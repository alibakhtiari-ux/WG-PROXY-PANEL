"""Window features with per-stream validity (design 04 §2–3, 02 «پنجره‌ها»).

A window is a tumbling, UTC-aligned interval of minute rows. Each metric is
computed only from minutes whose *own* stream was clean; the stream's window
quality is GOOD (all present minutes clean), DEGRADED (some), or INVALID
(fewer than MIN_VALID clean minutes). A rule never fires on an INVALID stream.
"""
from collections import Counter

from . import stats

MIN_VALID = 3                 # of the minutes present in a 5-minute window
STREAMS = ("C1", "S1", "S2", "S4", "S5")

_CAP_DOWN = ("C3:DISABLED", "STARTUP")
_BAD = {
    "S1": ("KERNEL_DROP:S1", "SOCK_ERR:S1", "NO_KERNEL_TS:S1", "LOWRATE_QUEUE_DROP",
           "C3:DOWN:nqmo-cap") + _CAP_DOWN,
    "S2": ("KERNEL_DROP:S2", "KERNEL_DROP:S3", "SOCK_ERR:S2", "SOCK_ERR:S3",
           "NO_KERNEL_TS:S2", "NO_KERNEL_TS:S3", "FRAG_TABLE_FULL", "FRAG_ID_REUSE",
           "LOWRATE_QUEUE_DROP", "C3:DOWN:nqmo-cap") + _CAP_DOWN,
    "S5": ("KERNEL_DROP:S5", "SOCK_ERR:S5", "NO_KERNEL_TS:S5", "LOWRATE_QUEUE_DROP",
           "C3:DOWN:nqmo-cap") + _CAP_DOWN,
    "S4": ("S4_COUNTER_JUMP", "C3:DOWN:nqmo-ring") + _CAP_DOWN,
}


def tokens(row):
    w = row.get("quality_why") or ""
    return set(t for t in w.split(";") if t)


def stream_ok(row, stream):
    if row.get("quality") == "INVALID":         # stale meta ⇒ attribution unsafe
        return False
    if stream == "C1":
        return True
    toks = tokens(row)
    if stream == "S4" and any(t.startswith("S4:") for t in toks):
        return False
    return not (toks & set(_BAD[stream]))


def window_quality(rows, stream, min_valid=MIN_VALID):
    """GOOD needs ≥min_valid minutes present and all of them clean; a window
    with fewer minutes is at best DEGRADED, so one active minute can never
    count as an independent HIGH-grade observation (review round 3)."""
    if not rows:
        return "INVALID", []
    ok = [r for r in rows if stream_ok(r, stream)]
    if not ok or len(ok) < min(min_valid, len(rows)):
        return "INVALID", ok
    if len(ok) == len(rows) and len(rows) >= min_valid:
        return "GOOD", ok
    return "DEGRADED", ok


def _sum(rows, k):
    return sum((r.get(k) or 0) for r in rows)


def peer_features(rows):
    """rows: minute-row dicts of ONE peer inside one window, any order."""
    rows = sorted(rows, key=lambda r: r["ts"])
    f = {"minutes": len(rows), "quality": {}}
    for s in STREAMS:
        f["quality"][s], valid = window_quality(rows, s)
        f["_" + s] = valid
    c1 = f["_C1"]
    last = rows[-1] if rows else {}
    f["t_config"] = last.get("t_config")
    f["ctx_key"] = last.get("ctx_key")
    f["rate_limit_mbit"] = last.get("rate_limit_mbit")
    f["rx"] = _sum(c1, "rx_bytes")
    f["tx"] = _sum(c1, "tx_bytes")
    f["c1_interval"] = _sum(c1, "c1_interval_s")
    f["c1_has_bytes"] = any(r.get("rx_bytes") is not None for r in c1)
    f["ep_ip_changes"] = _sum(c1, "ep_changed")
    f["ep_port_changes"] = _sum(c1, "ep_port_only_changed")
    f["hs_age_max"] = max([r.get("hs_age_max") or 0 for r in c1] or [0])
    f["route_bad"] = any(r.get("route_ok") == 0 for r in c1)
    f["tc_drops"] = _sum(c1, "tc_drops")
    f["tc_overlimits"] = _sum(c1, "tc_overlimits")
    s1 = f["_S1"]
    for k in ("hs_init_in", "hs_resp_out", "hs_init_out", "hs_resp_in", "hs_cookie_out"):
        f[k] = _sum(s1, k)
    samples = []
    for r in s1:
        if r.get("rtt_samples"):
            samples += [float(x) for x in r["rtt_samples"].split(",") if x]
    f["rtt_samples"] = samples
    s2 = f["_S2"]
    f["frag_first"] = _sum(s2, "frag_first")
    f["frag_incomplete"] = _sum(s2, "frag_incomplete")
    fmins = [r["frag_first_len_min"] for r in s2 if r.get("frag_first_len_min")]
    fmaxs = [r["frag_first_len_max"] for r in s2 if r.get("frag_first_len_max")]
    f["F_min"] = min(fmins) if fmins else None
    f["F_max"] = max(fmaxs) if fmaxs else None
    f["O_max"] = max([r.get("frag_orig_len") or 0 for r in s2] or [0]) or None
    s4 = f["_S4"]
    f["s4_expected"] = _sum(s4, "s4_expected")
    f["s4_received"] = _sum(s4, "s4_received")
    f["s4_lost"] = f["s4_expected"] - f["s4_received"]
    f["s4_reorder"] = _sum(s4, "s4_reorder")
    f["s4_dup"] = _sum(s4, "s4_dup")
    f["s4_pkts"] = _sum(s4, "s4_pkts")
    lmaxs = [r["l_max_unfrag"] for r in s4 if r.get("l_max_unfrag")]
    f["l_max"] = max(lmaxs) if lmaxs else None
    num = den = 0.0
    dfn = dfd = 0.0
    for r in s4:
        p = r.get("s4_pkts") or 0
        if f["l_max"] and r.get("l_max_unfrag") and r["l_max_unfrag"] >= f["l_max"] - 15 \
                and r.get("l_ceiling_share") is not None:
            num += r["l_ceiling_share"] * p
            den += p
        if r.get("df_ratio") is not None:
            dfn += r["df_ratio"] * p
            dfd += p
    f["ceiling_share"] = (num / den) if den else None
    f["df_ratio"] = (dfn / dfd) if dfd else None
    s5 = f["_S5"]
    mss = Counter()
    for r in s5:
        if r.get("mss_mode"):
            mss[r["mss_mode"]] += max(1, r.get("syn_n") or 1)
    f["mss_mode"] = mss.most_common(1)[0][0] if mss else None
    f["mss_exceeds"] = any(r.get("mss_exceeds") for r in s5)
    # Loss over judged counters; a datagram whose fragments never completed is
    # lost too. Its FIRST fragment carries the counter and passes the S4
    # filter, so it is already inside s4_expected as "received" — adding the
    # incomplete count to the denominator as well double-counts it. And the
    # two counts run on different clocks (counters are judged in batches as
    # they leave the replay window; fragments by arrival), so the incomplete
    # SHARE of arrived data packets is applied to the judged sample instead
    # (lab, 28 Oct: true ≈99% effective loss was reported as 45%).
    n = f["s4_expected"]
    k = f["s4_lost"]
    f["s4_loss_point"] = (k / n) if n else None      # counter gaps only
    if f["quality"]["S2"] != "INVALID" and f["frag_incomplete"] and f["s4_pkts"]:
        share = min(1.0, f["frag_incomplete"] / f["s4_pkts"])
        k = min(n, k + int(round((n - k) * share)))
    f["loss_n"], f["loss_k"] = n, k
    f["loss_lb"], f["loss_ub"] = stats.wilson(k, n) if n else (None, None)
    f["t_device"] = (min(f["mss_mode"] + 40, f["t_config"])
                     if f["mss_mode"] and f["t_config"] else f["t_config"])
    for s in STREAMS:
        del f["_" + s]
    return f


def global_features(rows):
    rows = sorted(rows, key=lambda r: r["ts"])
    ok = [r for r in rows if r.get("quality") == "GOOD"]
    f = {"minutes": len(rows), "valid_minutes": len(ok)}
    for k in ("softnet_dropped", "eth0_rx_missed_fifo", "udp_rcvbuf_err", "hs_cookie_out",
              "frag_creates", "reasm_fails", "reasm_timeout"):
        f[k] = sum((r.get(k) or 0) for r in ok)
    # ReasmFails counts timeouts too (ip_expire bumps both); the remainder is
    # fragments the server dropped without a queue — chiefly a full
    # reassembly memory. Only minutes that carry both counters count.
    f["reasm_drops"] = sum(max(0, r["reasm_fails"] - r["reasm_timeout"]) for r in ok
                           if r.get("reasm_fails") is not None
                           and r.get("reasm_timeout") is not None)
    f["conntrack_max"] = max([r.get("conntrack_pct") or 0 for r in ok] or [0])
    f["frag_mem_max"] = max([r.get("frag_mem_pct") or 0 for r in ok] or [0])
    f["softirq_max"] = max([r.get("cpu_softirq_pct") or 0 for r in ok] or [0])
    f["egress"] = rows[-1].get("egress") if rows else None
    return f
