"""nqmo.db — the engine's own SQLite (never the panel's traffic.db).

One long-lived connection owned by the main thread; every cycle's writes go in
one transaction. Schema = docs/nqmo/03-DATABASE-DESIGN.md, versioned with
PRAGMA user_version. A newer on-disk version than this code knows puts the
store in read-only mode (safe rollback). A failed quick_check renames the file
aside and starts empty — lost data is never back-filled with invented rows.
"""
import os
import sqlite3
import time

from . import SCHEMA_VERSION

PEER_MINUTE_COLS = (
    "peer_id", "ts", "rx_bytes", "tx_bytes", "c1_interval_s", "hs_age_max", "ep_ctx",
    "ep_changed", "ep_port_only_changed",
    "hs_init_in", "hs_resp_out", "hs_init_out", "hs_resp_in", "hs_cookie_out",
    "rtt_ms_min", "rtt_ms_med", "rtt_n", "rtt_missed",
    "frag_first", "frag_incomplete", "frag_first_len_min", "frag_first_len_max",
    "frag_orig_len",
    "s4_runs", "s4_expected", "s4_received", "s4_reorder", "s4_dup", "s4_late",
    "l_max_unfrag", "l_ceiling_share", "df_ratio", "s4_pkts",
    "mss_mode", "syn_n", "mss_exceeds",
    "tc_drops", "tc_overlimits", "rate_limit_mbit",
    "ctx_key", "t_config", "rtt_samples", "route_ok",
    "quality", "quality_why",
)

GLOBAL_MINUTE_COLS = (
    "ts", "frag_creates", "frag_fails", "reasm_reqds", "reasm_fails",
    "reasm_timeout", "icmp_out_unreach", "icmp_in_unreach",
    "udp_rcvbuf_err", "udp_sndbuf_err",
    "wg1_rx_frame_err", "wg1_tx_err", "wg1_tx_dropped",
    "eth0_rx_missed_fifo", "softnet_dropped", "softnet_squeeze",
    "hs_cookie_out", "cpu_softirq_pct", "cpu_total_pct", "conntrack_pct",
    "egress_json", "nqmo_cpu_pct", "nqmo_rss_mb",
    "c3_kernel_drops", "c3_user_drops", "quality", "frag_mem_pct",
)

_SCHEMA_V1 = """
CREATE TABLE peer (
  peer_id INTEGER PRIMARY KEY,
  iface TEXT NOT NULL, name TEXT NOT NULL, key_fp TEXT NOT NULL,
  first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  UNIQUE(iface, name, key_fp)
);
CREATE TABLE endpoint_ctx (
  ctx_id INTEGER PRIMARY KEY,
  ip_hmac TEXT NOT NULL, prefix24 TEXT NOT NULL,
  asn INTEGER, asn_name TEXT, country TEXT, asn_db_sha TEXT NOT NULL DEFAULT '',
  last_used REAL NOT NULL,
  UNIQUE(ip_hmac, asn_db_sha)
);
CREATE TABLE peer_minute (
  peer_id INTEGER NOT NULL, ts INTEGER NOT NULL,
  rx_bytes INTEGER, tx_bytes INTEGER, c1_interval_s REAL, hs_age_max INTEGER,
  ep_ctx INTEGER, ep_changed INTEGER NOT NULL DEFAULT 0,
  ep_port_only_changed INTEGER NOT NULL DEFAULT 0,
  hs_init_in INTEGER, hs_resp_out INTEGER, hs_init_out INTEGER,
  hs_resp_in INTEGER, hs_cookie_out INTEGER,
  rtt_ms_min REAL, rtt_ms_med REAL, rtt_n INTEGER, rtt_missed INTEGER,
  frag_first INTEGER, frag_incomplete INTEGER,
  frag_first_len_min INTEGER, frag_first_len_max INTEGER, frag_orig_len INTEGER,
  s4_runs INTEGER, s4_expected INTEGER, s4_received INTEGER,
  s4_reorder INTEGER, s4_dup INTEGER, s4_late INTEGER,
  l_max_unfrag INTEGER, l_ceiling_share REAL, df_ratio REAL, s4_pkts INTEGER,
  mss_mode INTEGER, syn_n INTEGER, mss_exceeds INTEGER,
  tc_drops INTEGER, tc_overlimits INTEGER, rate_limit_mbit INTEGER,
  ctx_key TEXT, t_config INTEGER, rtt_samples TEXT, route_ok INTEGER,
  quality TEXT NOT NULL, quality_why TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (peer_id, ts)
) WITHOUT ROWID;
CREATE INDEX idx_peer_minute_ts ON peer_minute(ts);
CREATE TABLE peer_hour (
  peer_id INTEGER NOT NULL, ts INTEGER NOT NULL,
  active_minutes INTEGER, rx_bytes INTEGER, tx_bytes INTEGER,
  rtt_ms_med REAL, rtt_n INTEGER,
  loss_expected INTEGER, loss_received INTEGER,
  frag_first INTEGER, frag_incomplete INTEGER,
  l_max_unfrag INTEGER, mss_mode INTEGER, df_ratio REAL,
  ctx_key TEXT NOT NULL, quality_good_minutes INTEGER,
  PRIMARY KEY (peer_id, ts)
) WITHOUT ROWID;
CREATE TABLE global_minute (
  ts INTEGER PRIMARY KEY,
  frag_creates INTEGER, frag_fails INTEGER, reasm_reqds INTEGER,
  reasm_fails INTEGER, reasm_timeout INTEGER,
  icmp_out_unreach INTEGER, icmp_in_unreach INTEGER,
  udp_rcvbuf_err INTEGER, udp_sndbuf_err INTEGER,
  wg1_rx_frame_err INTEGER, wg1_tx_err INTEGER, wg1_tx_dropped INTEGER,
  eth0_rx_missed_fifo INTEGER, softnet_dropped INTEGER, softnet_squeeze INTEGER,
  hs_cookie_out INTEGER, cpu_softirq_pct REAL, cpu_total_pct REAL,
  conntrack_pct REAL, egress_json TEXT,
  nqmo_cpu_pct REAL, nqmo_rss_mb REAL,
  c3_kernel_drops INTEGER, c3_user_drops INTEGER,
  quality TEXT NOT NULL
);
CREATE TABLE config_event (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, kind TEXT NOT NULL,
  subject TEXT NOT NULL, old TEXT, new TEXT
);
CREATE INDEX idx_config_event_ts ON config_event(ts);
CREATE TABLE diagnosis (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL,
  scope TEXT NOT NULL, subject TEXT NOT NULL, class TEXT NOT NULL,
  confidence TEXT NOT NULL,
  window_start INTEGER NOT NULL, window_end INTEGER NOT NULL,
  evidence_json TEXT NOT NULL, counter_evidence_json TEXT NOT NULL,
  alternatives_json TEXT NOT NULL, data_quality TEXT NOT NULL,
  baseline_ref TEXT, mode TEXT NOT NULL, state TEXT NOT NULL,
  cleared_ts REAL, ack_by TEXT, ack_ts REAL
);
CREATE INDEX idx_diag_subject ON diagnosis(scope, subject, ts);
CREATE TABLE recommendation (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, peer_id INTEGER, iface TEXT,
  target TEXT NOT NULL, current_value INTEGER, current_source TEXT NOT NULL,
  suggested_value INTEGER, status TEXT NOT NULL, direction_scope TEXT NOT NULL,
  rationale_json TEXT NOT NULL, limitations_json TEXT NOT NULL,
  diagnosis_ids TEXT NOT NULL, superseded_by INTEGER
);
CREATE TABLE correlation_event (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL,
  group_type TEXT NOT NULL, group_key TEXT NOT NULL,
  active_peers INTEGER NOT NULL, affected_peers INTEGER NOT NULL,
  confidence TEXT NOT NULL, suspected_cause TEXT NOT NULL,
  mtu_related_evidence INTEGER NOT NULL, requires_investigation INTEGER NOT NULL,
  evidence_json TEXT NOT NULL, state TEXT NOT NULL
);
CREATE TABLE probe_run (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, peer_id INTEGER NOT NULL,
  requested_by TEXT NOT NULL, sizes_json TEXT NOT NULL,
  results_json TEXT NOT NULL, packets_sent INTEGER NOT NULL,
  bytes_sent INTEGER NOT NULL, verdict TEXT NOT NULL, aborted_reason TEXT
);
CREATE TABLE collector_health (
  ts INTEGER NOT NULL, collector TEXT NOT NULL,
  runs INTEGER NOT NULL, failures INTEGER NOT NULL,
  max_duration_ms REAL, last_error TEXT,
  kernel_drops INTEGER, user_drops INTEGER,
  PRIMARY KEY (collector, ts)
) WITHOUT ROWID;
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE rule_state (
  scope TEXT NOT NULL, subject TEXT NOT NULL, class TEXT NOT NULL,
  history TEXT NOT NULL, open_id INTEGER, last_window INTEGER NOT NULL,
  notified_level TEXT, notified_ts REAL,
  PRIMARY KEY (scope, subject, class)
) WITHOUT ROWID;
CREATE TABLE notify_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
  severity TEXT NOT NULL, key TEXT NOT NULL,
  text_key TEXT NOT NULL, params_json TEXT NOT NULL
);
CREATE TABLE rec_followup (
  peer_id INTEGER PRIMARY KEY, rec_id INTEGER NOT NULL,
  t_old INTEGER, t_new INTEGER NOT NULL, changed_at REAL NOT NULL,
  active_minutes INTEGER NOT NULL DEFAULT 0, verdict TEXT
);
"""

# v2 (lab round, 28 Oct): IPv4 reassembly memory gauge for class 1
_SCHEMA_V2 = """
ALTER TABLE global_minute ADD COLUMN frag_mem_pct REAL;
"""

MIGRATIONS = {1: _SCHEMA_V1, 2: _SCHEMA_V2}


class StoreError(RuntimeError):
    pass


class Store:
    def __init__(self, path, now=time.time):
        self.path = path
        self.now = now
        self.read_only = False
        self.recreated = False
        self.closed = False
        self.conn = self._connect() if path == ":memory:" else None
        self._open()

    # ---- lifecycle -------------------------------------------------------
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=5000")
        if self.path != ":memory:":
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=OFF")
        return conn

    def _open(self):
        if self.path != ":memory:":
            d = os.path.dirname(self.path)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
            existed = os.path.exists(self.path)
        else:
            existed = False
        if existed and not self._healthy():
            ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime(self.now()))
            for suffix in ("", "-wal", "-shm"):
                if os.path.exists(self.path + suffix):
                    os.replace(self.path + suffix,
                               "%s.corrupt-%s%s" % (self.path, ts, suffix))
            self.recreated = True
        if self.conn is None:
            self.conn = self._connect()
        if self.path != ":memory:":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        self._migrate()

    def _healthy(self):
        """quick_check on a bare connection — no PRAGMA that could itself
        raise on a corrupt header before the check runs.

        Only real corruption returns False. A locked or unreadable file
        (e.g. root-owned -wal left by an operator's sqlite3) raises
        StoreError instead: renaming a healthy DB aside would destroy data.
        """
        try:
            c = sqlite3.connect(self.path, timeout=5.0)
            try:
                row = c.execute("PRAGMA quick_check").fetchone()
                return row is not None and row[0] == "ok"
            finally:
                c.close()
        except sqlite3.DatabaseError as e:
            code = getattr(e, "sqlite_errorcode", None)
            msg = str(e).lower()
            if code in (11, 26) or "not a database" in msg or "malformed" in msg:
                return False
            raise StoreError("cannot open %s: %s" % (self.path, e))

    def _migrate(self):
        cur = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if cur > SCHEMA_VERSION:
            self.read_only = True        # newer schema: never write
            return
        for v in range(cur + 1, SCHEMA_VERSION + 1):
            self.conn.execute("BEGIN")
            try:
                for stmt in _split(MIGRATIONS[v]):
                    self.conn.execute(stmt)
                self.conn.execute("PRAGMA user_version=%d" % v)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        if self.recreated:
            self.config_event("DB_RECREATED", "nqmo.db", None, "quick_check failed")

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if not self.read_only and self.path != ":memory:":
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            self.conn.close()

    # ---- write helpers ---------------------------------------------------
    def _w(self):
        if self.closed:
            raise StoreError("store is closed")
        if self.read_only:
            raise StoreError("store is read-only (newer schema on disk)")
        return self.conn

    def transaction(self):
        return _Tx(self)

    def get_meta(self, k, default=None):
        row = self.conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return row[0] if row else default

    def set_meta(self, k, v):
        self._w().execute("INSERT INTO meta(k,v) VALUES(?,?) "
                          "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    def peer_id(self, iface, name, key_fp):
        now = self.now()
        c = self._w()
        row = c.execute("SELECT peer_id FROM peer WHERE iface=? AND name=? AND key_fp=?",
                        (iface, name, key_fp)).fetchone()
        if row:
            c.execute("UPDATE peer SET last_seen=? WHERE peer_id=?", (now, row[0]))
            return row[0]
        cur = c.execute("INSERT INTO peer(iface,name,key_fp,first_seen,last_seen) "
                        "VALUES(?,?,?,?,?)", (iface, name, key_fp, now, now))
        return cur.lastrowid

    def endpoint_ctx(self, ip_hmac, prefix24, asn=None, asn_name=None,
                     country=None, asn_db_sha=""):
        now = self.now()
        c = self._w()
        row = c.execute("SELECT ctx_id FROM endpoint_ctx WHERE ip_hmac=? AND asn_db_sha=?",
                        (ip_hmac, asn_db_sha)).fetchone()
        if row:
            c.execute("UPDATE endpoint_ctx SET last_used=? WHERE ctx_id=?", (now, row[0]))
            return row[0]
        cur = c.execute(
            "INSERT INTO endpoint_ctx(ip_hmac,prefix24,asn,asn_name,country,asn_db_sha,last_used) "
            "VALUES(?,?,?,?,?,?,?)",
            (ip_hmac, prefix24, asn, asn_name, country, asn_db_sha, now))
        return cur.lastrowid

    def put_peer_minute(self, row):
        _put(self._w(), "peer_minute", PEER_MINUTE_COLS, row)

    def put_global_minute(self, row):
        _put(self._w(), "global_minute", GLOBAL_MINUTE_COLS, row)

    def put_collector_health(self, ts, collector, runs, failures, max_ms,
                             last_error, kernel_drops=None, user_drops=None):
        self._w().execute(
            "INSERT OR REPLACE INTO collector_health VALUES(?,?,?,?,?,?,?,?)",
            (int(ts), collector, runs, failures, max_ms, last_error or None,
             kernel_drops, user_drops))

    def config_event(self, kind, subject, old, new):
        self._w().execute("INSERT INTO config_event(ts,kind,subject,old,new) "
                          "VALUES(?,?,?,?,?)", (self.now(), kind, subject,
                                                None if old is None else str(old),
                                                None if new is None else str(new)))

    # ---- retention -------------------------------------------------------
    def prune(self, retention_days):
        """Delete rows older than their retention; returns rows deleted."""
        now = self.now()
        day = 86400.0
        plan = (
            ("peer_minute", "ts", retention_days["minute"]),
            ("global_minute", "ts", retention_days["minute"]),
            ("collector_health", "ts", retention_days["minute"]),
            ("peer_hour", "ts", retention_days["hour"]),
            ("diagnosis", "ts", retention_days["events"]),
            ("recommendation", "ts", retention_days["events"]),
            ("correlation_event", "ts", retention_days["events"]),
            ("probe_run", "ts", retention_days["events"]),
            ("config_event", "ts", retention_days["events"]),
            ("notify_outbox", "ts", retention_days["events"]),
        )
        n = 0
        c = self._w()
        c.execute("BEGIN")
        try:
            for table, col, days in plan:
                cur = c.execute("DELETE FROM %s WHERE %s < ?" % (table, col),
                                (now - days * day,))
                n += cur.rowcount
            cur = c.execute(
                "DELETE FROM endpoint_ctx WHERE last_used < ? AND ctx_id NOT IN "
                "(SELECT DISTINCT ep_ctx FROM peer_minute WHERE ep_ctx IS NOT NULL)",
                (now - retention_days["endpoint_ctx"] * day,))
            n += cur.rowcount
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        if self.path != ":memory:":
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return n

    def size_mb(self):
        if self.path == ":memory:":
            return 0.0
        total = 0
        for suffix in ("", "-wal"):
            try:
                total += os.path.getsize(self.path + suffix)
            except OSError:
                pass
        return total / (1024.0 * 1024.0)


class _Tx:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        self.store._w().execute("BEGIN")
        return self.store

    def __exit__(self, et, ev, tb):
        c = self.store.conn
        if et is None:
            try:
                c.execute("COMMIT")
            except sqlite3.Error:
                try:
                    c.execute("ROLLBACK")      # never leave a transaction open
                except sqlite3.Error:
                    pass
                raise
        else:
            try:
                c.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        return False


def _put(conn, table, cols, row):
    unknown = set(row) - set(cols)
    if unknown:
        raise StoreError("%s: unknown columns %s" % (table, sorted(unknown)))
    vals = [row.get(c) for c in cols]
    conn.execute("INSERT OR REPLACE INTO %s(%s) VALUES(%s)"
                 % (table, ",".join(cols), ",".join("?" * len(cols))), vals)


def _split(script):
    return [s.strip() for s in script.split(";") if s.strip()]
