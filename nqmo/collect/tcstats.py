"""C4: traffic-shaping statistics from `tc -s -j ... show` (read-only).

The class→IP map comes from the u32 filters actually installed, never from
re-deriving the panel's classid algorithm, so a drift between the two cannot
mis-attribute drops. Anything ambiguous maps to nobody.

NOT_VERIFIED: the exact JSON shape of `tc -j filter show` u32 output on the
server's iproute2; parse_filters() is tolerant and returns {} when unsure.
The lab phase pins it with a captured fixture.
"""
import ipaddress
import json

# u32 "match ip dst X/32" sits at offset 16; "match ip src X/32" at offset 12.
_OFF_DST = 16
_OFF_SRC = 12


def parse_classes(text):
    """→ {classid: {"bytes","packets","drops","overlimits","backlog"}}."""
    out = {}
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError:
        return {}
    for c in data if isinstance(data, list) else []:
        if not isinstance(c, dict) or c.get("class") != "htb":
            continue
        h = c.get("handle")
        st = c.get("stats") or {}
        if not isinstance(h, str):
            continue
        out[h] = {k: st.get(k) for k in ("bytes", "packets", "drops",
                                         "overlimits", "backlog")}
    return out


def _match_ip(m):
    """One u32 match dict → (offset, ip) for a full /32 match, else None."""
    if not isinstance(m, dict) or None in (m.get("value"), m.get("mask"), m.get("off")):
        return None
    try:
        val = int(str(m.get("value")), 16)
        mask = int(str(m.get("mask")), 16)
        off = int(m.get("off"))
    except (TypeError, ValueError):
        return None
    if mask != 0xFFFFFFFF:
        return None
    return off, str(ipaddress.IPv4Address(val))


def parse_filters(text, direction):
    """→ {classid: ip}. direction 'dst' (root of wg1udp) or 'src' (ifb)."""
    want = _OFF_DST if direction == "dst" else _OFF_SRC
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError:
        return {}
    seen = {}
    for f in data if isinstance(data, list) else []:
        opts = f.get("options") if isinstance(f, dict) else None
        if not isinstance(opts, dict):
            continue
        flow = opts.get("flowid")
        matches = opts.get("match")
        if isinstance(matches, dict):
            matches = [matches]
        if not isinstance(flow, str) or not isinstance(matches, list):
            continue
        ips = [r for r in (_match_ip(m) for m in matches) if r and r[0] == want]
        if len(ips) != 1:
            continue
        seen.setdefault(flow, set()).add(ips[0][1])
    # a class mapped to more than one IP is ambiguous → dropped
    return {cid: next(iter(v)) for cid, v in seen.items() if len(v) == 1}


def per_ip(classes, mapping):
    """Join classes with the filter map → {ip: stats}. Unmapped classes vanish."""
    out = {}
    for cid, ip in mapping.items():
        if cid in classes:
            if ip in out:              # two classes for one IP: ambiguous
                out[ip] = None
            else:
                out[ip] = classes[cid]
    return {ip: st for ip, st in out.items() if st is not None}
