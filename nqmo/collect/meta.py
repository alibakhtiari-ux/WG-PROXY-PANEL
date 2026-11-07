"""C1 + C5: the panel-written /run/wg-panel/nqmo-meta.json.

nqmo holds no CAP_NET_ADMIN, so everything `wg show` knows reaches it through
this file. Validation is fail-closed: a document that carries anything shaped
like a secret (a forbidden key name, or 32-byte-key-shaped base64 anywhere in
any string that is not exactly one of the listed public keys) is rejected
whole. Every failure surfaces as MetaError — never as another exception type.

Attribution maps are conservative: disabled peers are not mapped, and an
endpoint or tunnel IP claimed by two peers maps to nobody unless exactly one
of them handshook in the last 180 s.
"""
import ipaddress
import json
import math
import re
import time

FORBIDDEN_KEY_RE = re.compile(r"(psk|preshared|private|secret|token|passw)", re.I)
B64_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
B64_EMBEDDED_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=?(?![A-Za-z0-9+/=])")
NAME_RE = re.compile(r"^[^\x00-\x1f]{1,64}$")
MAX_FUTURE_S = 300
ACTIVE_HS_S = 180

INT = "int"
INT_OR_NONE = "int?"
NUM_OR_NONE = "num?"
BOOL = "bool"
BOOL_OR_NONE = "bool?"
STR = "str"
STR_OR_NONE = "str?"

PEER_FIELDS = {
    "iface": STR, "name": STR, "enabled": BOOL, "tunnel_ip": STR_OR_NONE,
    "c_mtu": INT_OR_NONE, "rate_mbit": INT_OR_NONE, "endpoint": STR_OR_NONE,
    "latest_handshake": INT, "rx_bytes": INT, "tx_bytes": INT,
}
PEER_RANGES = {"c_mtu": (576, 9000), "rate_mbit": (0, 100000),
               "latest_handshake": (0, 1 << 40), "rx_bytes": (0, 1 << 62),
               "tx_bytes": (0, 1 << 62)}
EGRESS_FIELDS = {
    "kind": STR, "mtu": INT_OR_NONE, "endpoint_dev": STR_OR_NONE,
    "awg_s4": INT_OR_NONE, "hs_age": INT_OR_NONE, "rx_delta": INT_OR_NONE,
    "health": STR_OR_NONE, "svc_ok": BOOL_OR_NONE, "svc_latency_ms": NUM_OR_NONE,
    "mtr_loss": NUM_OR_NONE, "mtr_rtt": NUM_OR_NONE, "warp_ms": NUM_OR_NONE,
    "ecmp_member": BOOL_OR_NONE, "ts": NUM_OR_NONE,
}


class MetaError(ValueError):
    pass


def _type_ok(v, t):
    if v is None:
        return t.endswith("?")
    base = t.rstrip("?")
    if base == BOOL:
        return isinstance(v, bool)
    if isinstance(v, bool):                 # bool is an int subclass: never a number here
        return False
    if base == INT:
        return isinstance(v, int)
    if base == "num":
        return isinstance(v, (int, float)) and math.isfinite(v)
    if base == STR:
        return isinstance(v, str)
    return False


def _scan_secrets(obj, allowed_b64, path="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise MetaError("%s: non-string key" % path)
            if FORBIDDEN_KEY_RE.search(k):
                raise MetaError("%s: forbidden key %r" % (path, k[:24]))
            if k not in allowed_b64 and B64_EMBEDDED_RE.search(k):
                raise MetaError("%s: key material in a key" % path)
            _scan_secrets(v, allowed_b64, path + "." + k[:12])
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_secrets(v, allowed_b64, "%s[%d]" % (path, i))
    elif isinstance(obj, str):
        if obj not in allowed_b64 and B64_EMBEDDED_RE.search(obj):
            raise MetaError("%s: key-shaped value" % path)


def _typed(obj, fields, where, ranges=None):
    if not isinstance(obj, dict):
        raise MetaError("%s: expected object" % where)
    for k, t in fields.items():
        if k not in obj:
            raise MetaError("%s: missing %s" % (where, k))
        if not _type_ok(obj[k], t):
            raise MetaError("%s.%s: bad type" % (where, k))
        if ranges and k in ranges and obj[k] is not None:
            lo, hi = ranges[k]
            if not lo <= obj[k] <= hi:
                raise MetaError("%s.%s: out of range" % (where, k))
    extra = set(obj) - set(fields)
    if extra:
        raise MetaError("%s: unknown fields %s" % (where, sorted(extra)[:5]))


def _endpoint(s):
    """'1.2.3.4:5678' → ('1.2.3.4', 5678); None for none/IPv6 (unmodelled).
    Returns (value, unmodelled_flag)."""
    if s in (None, "", "(none)"):
        return None, False
    if s.startswith("["):
        return None, True                       # IPv6: model not validated
    host, sep, port = s.rpartition(":")
    if not sep or not port.isdigit():
        raise MetaError("endpoint malformed")
    try:
        ip = ipaddress.IPv4Address(host)
    except ValueError:
        raise MetaError("endpoint address malformed")
    p = int(port)
    if not 0 < p < 65536:
        raise MetaError("endpoint port out of range")
    return (str(ip), p), False


def _unique_map(cands, now):
    """{key: [(pub, latest_handshake)]} → {key: pub}; ambiguity → nobody,
    unless exactly one claimant handshook within ACTIVE_HS_S."""
    out, ambiguous = {}, set()
    for key, owners in cands.items():
        if len(owners) == 1:
            out[key] = owners[0][0]
            continue
        active = [pub for pub, hs in owners if hs and now - hs < ACTIVE_HS_S]
        if len(active) == 1:
            out[key] = active[0]
        else:
            ambiguous.add(key)
    return out, ambiguous


class Meta:
    """Validated, immutable view of one meta document."""

    def __init__(self, doc, read_at):
        self.generated_at = float(doc["generated_at"])
        self.read_at = read_at
        self.client_mtu = doc["client_mtu"]
        w = doc["wg1udp"]
        self.wg1udp_mtu = w["mtu"]
        self.wg1udp_fwmark = w.get("fwmark")
        self.wg1udp_local_ip = w.get("local_ip")
        self.peers = {}
        self.unmodelled_endpoints = 0
        ep_c, tip_c = {}, {}
        for pub, p in doc["peers"].items():
            ep, unmodelled = _endpoint(p["endpoint"])
            self.unmodelled_endpoints += int(unmodelled)
            rec = dict(p)
            rec["endpoint"] = ep
            self.peers[pub] = rec
            if not p["enabled"]:
                continue
            if ep is not None:
                ep_c.setdefault(ep, []).append((pub, p["latest_handshake"]))
            if p["tunnel_ip"]:
                tip_c.setdefault(p["tunnel_ip"], []).append((pub, p["latest_handshake"]))
        self.by_endpoint, self.ambiguous_endpoints = _unique_map(ep_c, self.generated_at)
        self.by_tunnel_ip, self.ambiguous_tunnel_ips = _unique_map(tip_c, self.generated_at)
        self.endpoint_ips = {ep[0] for ep in ep_c}
        self.egress = dict(doc["egress"])

    def age(self, now=None):
        return (time.time() if now is None else now) - self.generated_at

    def effective_mtu(self, pub):
        p = self.peers.get(pub)
        if not p:
            return None
        return p["c_mtu"] or self.client_mtu


def _reject_constant(name):
    raise MetaError("non-finite number %s" % name)


def parse(text, read_at=None):
    read_at = time.time() if read_at is None else read_at
    try:
        return _parse(text, read_at)
    except MetaError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        raise MetaError("invalid meta: %s: %s" % (type(e).__name__, e))


def _parse(text, read_at):
    try:
        doc = json.loads(text, parse_constant=_reject_constant)
    except MetaError:
        raise
    except ValueError as e:
        raise MetaError("not JSON: %s" % e)
    if not isinstance(doc, dict):
        raise MetaError("root must be an object")
    for k in ("generated_at", "client_mtu", "wg1udp", "peers", "egress"):
        if k not in doc:
            raise MetaError("missing %s" % k)
    extra = set(doc) - {"generated_at", "client_mtu", "wg1udp", "peers", "egress", "schema"}
    if extra:
        raise MetaError("unknown top-level fields %s" % sorted(extra))
    if not isinstance(doc["peers"], dict) or not isinstance(doc["egress"], dict):
        raise MetaError("peers/egress must be objects")
    allowed = set()
    for pub in doc["peers"]:
        if not isinstance(pub, str) or not B64_KEY_RE.match(pub):
            raise MetaError("peer key is not a public key")
        allowed.add(pub)
    _scan_secrets(doc, allowed)
    g = doc["generated_at"]
    if not _type_ok(g, "num") or g <= 0:
        raise MetaError("generated_at must be a positive finite number")
    if g > read_at + MAX_FUTURE_S:
        raise MetaError("generated_at is in the future (clock or unit error)")
    if not _type_ok(doc["client_mtu"], INT) or not 576 <= doc["client_mtu"] <= 9000:
        raise MetaError("client_mtu out of range")
    w = doc["wg1udp"]
    if not isinstance(w, dict) or not _type_ok(w.get("mtu"), INT):
        raise MetaError("wg1udp.mtu required")
    if set(w) - {"mtu", "fwmark", "local_ip"}:
        raise MetaError("wg1udp: unknown fields")
    if not _type_ok(w.get("fwmark"), INT_OR_NONE) or (w.get("fwmark") or 0) < 0:
        raise MetaError("wg1udp.fwmark must be a non-negative integer or null")
    if w.get("local_ip") is not None:
        ipaddress.IPv4Address(w["local_ip"])
    for pub, p in doc["peers"].items():
        _typed(p, PEER_FIELDS, "peers[%s]" % pub[:8], PEER_RANGES)
        if not NAME_RE.match(p["name"]):
            raise MetaError("peer name invalid")
        if p["tunnel_ip"] is not None:
            ipaddress.IPv4Address(p["tunnel_ip"])
        _endpoint(p["endpoint"])
    for name, e in doc["egress"].items():
        _typed(e, EGRESS_FIELDS, "egress[%s]" % name[:15])
    return Meta(doc, read_at)


def read(path, read_at=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read(4 * 1024 * 1024 + 1)
    except FileNotFoundError:
        raise MetaError("meta file missing")
    except (OSError, UnicodeDecodeError) as e:
        raise MetaError("cannot read meta: %s" % e)
    if len(text) > 4 * 1024 * 1024:
        raise MetaError("meta file too large")
    return parse(text, read_at)
