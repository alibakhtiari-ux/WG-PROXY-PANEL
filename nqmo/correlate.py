"""Correlation of degradations across peers (design 04 §5).

A group event needs ALL of: ≥3 active peers in the group, ≥3 AND ≥50% of them
degraded in the same window, and no server/egress cause active (if one is,
the event names it instead). The default cause is UNKNOWN; MTU evidence is
claimed only when ≥2 peers show the same first-fragment size (±8 B), or ≥2
peers carry uncapped DIRECT blackhole evidence, in the same window — and even
then the wording is «a change in what the path delivers was observed», never
«the ISP changed the MTU». A /16 event that only repeats a /24 one (same
affected peers) is not emitted twice.
"""
DEGRADED_CLASSES = ("PACKET_LOSS", "NETWORK_CONGESTION", "SUSPECTED_MTU_PROBLEM",
                    "SUSPECTED_PMTU_BLACKHOLE", "UNKNOWN_DEGRADATION")
GROUP_MIN_ACTIVE = 3
GROUP_MIN_AFFECTED = 3
GROUP_MIN_SHARE = 0.5
ACTIVE_PKTS = 1000
ACTIVE_BYTES = 1000000


def _net(ctx_key):
    """ctx_key = '<AS…|a.b.c.0/24>|T|rate|mtu' → (group_type, key, prefix16|None)."""
    if not ctx_key:
        return None
    net = ctx_key.split("|", 1)[0]
    if net.startswith("AS"):
        return ("ASN", net, None)
    a, b = net.split(".")[:2]
    return ("PREFIX24", net, "%s.%s.0.0/16" % (a, b))


def correlate(result, server_bad, egress_bad_names):
    """result: Diagnoser.evaluate() output → list of event dicts."""
    groups = {}
    active_all = degraded_all = 0
    for pid, pr in result["peers"].items():
        f = pr["features"]
        active = f["s4_pkts"] >= ACTIVE_PKTS or (f["rx"] + f["tx"]) >= ACTIVE_BYTES
        if not active:
            continue
        deg = [o for o in pr["outcomes"] if o.cls in DEGRADED_CLASSES and o.positive]
        active_all += 1
        degraded_all += bool(deg)
        n = _net(f["ctx_key"])
        if n is None:
            continue
        keys = [(n[0], n[1])]
        if n[2]:
            keys.append(("PREFIX16", n[2]))          # PREFIX_ONLY fallback grouping
        for k in keys:
            g = groups.setdefault(k, {"active": 0, "affected": 0, "F": [], "bh_direct": 0})
            g["active"] += 1
            if deg:
                g["affected"] += 1
                if f["F_min"]:
                    g["F"].append(f["F_min"])
                if any(o.cls == "SUSPECTED_PMTU_BLACKHOLE" and o.strength == "DIRECT"
                       and o.cap is None for o in deg):
                    g["bh_direct"] += 1
    events = []
    cause = ("SERVER" if server_bad else
             ("EGRESS:" + ",".join(sorted(egress_bad_names)) if egress_bad_names else "UNKNOWN"))
    emitted24 = []
    for (gtype, gkey), g in sorted(groups.items(), key=lambda kv: kv[0][0] == "PREFIX16"):
        if g["active"] < GROUP_MIN_ACTIVE:
            continue
        if g["affected"] < GROUP_MIN_AFFECTED or g["affected"] / g["active"] < GROUP_MIN_SHARE:
            continue
        if gtype == "PREFIX24":
            emitted24.append((gkey, g["affected"]))
        if gtype == "PREFIX16":
            # the same incident already reported at /24: do not count it twice
            base = gkey.split(".")[:2]
            if any(k.split(".")[:2] == base and n == g["affected"] for k, n in emitted24):
                continue
        Fs = sorted(g["F"])
        same_F = any(Fs[i + 1] - Fs[i] <= 8 for i in range(len(Fs) - 1))
        events.append({
            "event_type": "CORRELATED_NETWORK_DEGRADATION",
            "group_type": gtype if gtype != "PREFIX16" else "PREFIX16 (PREFIX_ONLY)",
            "group_key": gkey, "active_peers": g["active"], "affected_peers": g["affected"],
            "confidence": "MEDIUM" if cause == "UNKNOWN" else "LOW",
            "suspected_cause": cause,
            "mtu_related_evidence": bool(same_F or g["bh_direct"] >= 2),
            "requires_investigation": True,
        })
    if active_all >= GROUP_MIN_ACTIVE and degraded_all >= GROUP_MIN_AFFECTED \
            and degraded_all / active_all >= GROUP_MIN_SHARE:
        events.append({"event_type": "GLOBAL_DEGRADATION", "group_type": "GLOBAL",
                       "group_key": "all", "active_peers": active_all,
                       "affected_peers": degraded_all,
                       "confidence": "MEDIUM", "suspected_cause": cause if cause != "UNKNOWN"
                       else "CHECK_SERVER_AND_EGRESS_FIRST",
                       "mtu_related_evidence": False, "requires_investigation": True})
    eligible = sum(1 for g in groups.values() if g["active"] >= GROUP_MIN_ACTIVE)
    return events, eligible
