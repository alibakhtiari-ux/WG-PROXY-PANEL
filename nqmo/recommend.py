"""MTU / MSS recommendation model (design 04 §4).

Every recommendation carries exactly one status:
    VERIFIED | ESTIMATED | CANDIDATE_FOR_TESTING | UNDETERMINED
and the default is UNDETERMINED. Wording never claims a "Path MTU": the
measured facts are «a packet of L bytes was delivered unfragmented» and
«F − 60 delivers a full packet unfragmented» (review round 1, finding 10).

A suggestion is never above the configured MTU, and anything below 1280 is
capped at CANDIDATE (inner IPv6 needs ≥1280; client AllowedIPs carry ::/0).
"""
from . import features as feat
from . import rules

LOOKBACK_WINDOWS = 6
MIN_WINDOWS = 3
IPV6_MIN = 1280
OVERHEAD = 60
FOLLOWUP_MAX_S = 24 * 3600


def _undetermined(t_config, why, mode_disabled=False):
    return {"target": "CLIENT_IFACE_MTU", "current_value": t_config,
            "current_source": "CONFIG", "suggested_value": None,
            "status": "UNDETERMINED", "direction_scope": "UPSTREAM",
            "rationale": ["DISABLED_BY_MODE"] if mode_disabled else [],
            "limitations": why}


def windows_features(rows_by_window):
    """[rows of window] (oldest first) → [features]."""
    return [feat.peer_features(rs) for rs in rows_by_window if rs]


def recommend(fs, diag, t_config, mode, probe=None):
    """fs: features of the last LOOKBACK windows (oldest first).
    diag: {class: (is_open, level)}. probe: latest probe verdict dict or None.
    Returns a list of recommendation dicts (first = client MTU)."""
    if mode != "RECOMMENDATIONS_ENABLED":
        return [_undetermined(t_config, ["recommendations disabled in this mode"],
                              mode_disabled=True)]
    if not t_config:
        return [_undetermined(t_config, ["client MTU unknown (no panel meta)"])]
    fs = fs[-LOOKBACK_WINDOWS:]
    s4_ok = [f for f in fs if f["quality"]["S4"] != "INVALID" and f["l_max"]]
    s2_ok = [f for f in fs if f["quality"]["S2"] != "INVALID"]
    frag = [f for f in s2_ok if f["frag_first"] > 0]
    open_lv = {k: v[1] for k, v in diag.items() if v[0]}
    mtu_pos = [f for f in s2_ok
               if rules.mtu_problem(f["frag_first"], f["F_min"], f["F_max"], f["l_max"],
                                    f["t_config"], f["quality"]["S2"],
                                    f["quality"]["S4"]).positive]
    df_pos = [f for f in s4_ok
              if rules.blackhole_df(f["df_ratio"], f["frag_first"], f["l_max"],
                                    f["ceiling_share"], f["t_device"], f["loss_lb"] or 0,
                                    f["loss_n"], f["quality"]["S4"]).positive]
    recs = []

    # 1) VERIFIED adequacy: the largest configured packet arrived unfragmented
    full = [f for f in s4_ok if f["l_max"] - OVERHEAD == t_config]
    if (len(full) >= MIN_WINDOWS and not frag and len(s2_ok) >= MIN_WINDOWS
            and "PACKET_LOSS" not in open_lv and "SUSPECTED_PMTU_BLACKHOLE" not in open_lv):
        recs.append({"target": "CLIENT_IFACE_MTU", "current_value": t_config,
                     "current_source": "CONFIG", "suggested_value": None,
                     "status": "VERIFIED", "direction_scope": "UPSTREAM",
                     "rationale": ["full-size packets (%d B) delivered unfragmented in %d "
                                   "separate windows" % (t_config + OVERHEAD, len(full))],
                     "limitations": ["downstream direction not verified"]})

    # 2) fragment-based (client without DF). Only windows in which the class-10
    #    rule itself was positive count — a stray fragment or a lone small one
    #    can never set the number (review round 3).
    elif "SUSPECTED_MTU_PROBLEM" in open_lv and len(mtu_pos) >= 2:
        F_min = min(f["F_min"] for f in mtu_pos)
        F_max = max(f["F_max"] for f in mtu_pos)
        stable = ((F_max - F_min) <= 8 and len(mtu_pos) >= MIN_WINDOWS
                  and sum(f["frag_first"] for f in mtu_pos)
                  >= rules.PARAMS["frag_min_total_high"])
        sug = F_min - OVERHEAD
        status = ("ESTIMATED" if open_lv["SUSPECTED_MTU_PROBLEM"] == "HIGH" and stable
                  else "CANDIDATE_FOR_TESTING")
        recs.append(_client(t_config, sug, status, "UPSTREAM",
                            ["first fragments of %d–%d B: a %d-byte tunnel packet is "
                             "delivered unfragmented" % (F_min, F_max, sug)],
                            ["downstream direction not verified",
                             "a reassembling middlebox would hide the true limit"]))

    # 3) DF-client ceiling (wireguard-go): only windows where the 11(b) rule
    #    fired — a quiet window of small packets says nothing about the ceiling
    elif open_lv.get("SUSPECTED_PMTU_BLACKHOLE") and len(df_pos) >= 2 and not frag:
        lmax = min(f["l_max"] for f in df_pos)
        sug = lmax - OVERHEAD
        recs.append(_client(t_config, sug, "CANDIDATE_FOR_TESTING", "UPSTREAM",
                            ["DF-marked packets cap at %d B with loss above it; %d B "
                             "packets are delivered" % (lmax, lmax)],
                            ["inferred from a ceiling effect, not a direct measurement",
                             "downstream direction not verified"]))

    # 4) manual round-trip probe
    if probe and probe.get("verdict") == "THRESHOLD" and probe.get("t_config") == t_config:
        sug = probe["s_star"] + 28
        lim = ["quantized to 16 B by WireGuard padding (±15 B)",
               "reply DF depends on the client implementation"]
        # a run with ANY server-side reassembly drop is already INCONCLUSIVE
        # (probe.py); one where they could not be read cannot exclude them
        measured = probe.get("server_reasm_drops") is not None
        if not measured:
            lim.append("server-side reassembly drops not measured during the probe")
        recs.append(_client(t_config, sug, "ESTIMATED" if measured else "CANDIDATE_FOR_TESTING",
                            "ROUNDTRIP",
                            ["largest inner packet answered in both directions: %d B" % sug],
                            lim))

    # 5) server-side MSS as an alternative when the client can't be changed
    client = [r for r in recs if r["suggested_value"]]
    if client and ("SUSPECTED_MTU_PROBLEM" in open_lv
                   or "SUSPECTED_PMTU_BLACKHOLE" in open_lv):
        best = min(r["suggested_value"] for r in client)
        recs.append({"target": "SERVER_PEER_TCP_MSS", "current_value": None,
                     "current_source": "KERNEL", "suggested_value": best - 40,
                     "status": "CANDIDATE_FOR_TESTING", "direction_scope": "UPSTREAM",
                     "rationale": ["alternative if the client config cannot be changed"],
                     "limitations": ["fixes TCP only, not UDP/QUIC",
                                     "apply manually via tunnel-ops; never automatic"]})
    if not recs:
        missing = []
        if len(s4_ok) < MIN_WINDOWS:
            missing.append("fewer than %d windows with valid S4 data" % MIN_WINDOWS)
        if len(s2_ok) < MIN_WINDOWS:
            missing.append("fewer than %d windows with valid fragment data" % MIN_WINDOWS)
        if not missing:
            missing.append("no measurement establishes adequacy or a safe smaller value")
        recs.append(_undetermined(t_config, missing))
    return recs


def _client(t_config, sug, status, scope, rationale, limitations):
    lim = list(limitations)
    if sug >= t_config:
        return _undetermined(t_config, ["evidence does not support a value below the "
                                        "configured MTU"])
    if sug < IPV6_MIN:
        status = "CANDIDATE_FOR_TESTING"
        lim.append("below 1280: inner IPv6 impossible (client AllowedIPs carry ::/0)")
    return {"target": "CLIENT_IFACE_MTU", "current_value": t_config,
            "current_source": "CONFIG", "suggested_value": sug, "status": status,
            "direction_scope": scope, "rationale": rationale, "limitations": lim}


def followup_verdict(fs, t_new, elapsed_s):
    """04 §4.5 — after the operator changed the client MTU.
    fs: features of windows since the change (oldest first).
    → "CONFIRMED" | "NOT_CONFIRMED" | "INCONCLUSIVE" | None (keep waiting).
    Fragments in one window can be the old session draining; NOT_CONFIRMED
    needs them in ≥2 separate windows."""
    s4_ok = [f for f in fs if f["quality"]["S4"] != "INVALID" and f["l_max"]]
    s2_ok = [f for f in fs if f["quality"]["S2"] != "INVALID"]
    frag_windows = sum(1 for f in s2_ok if f["frag_first"] > 0)
    if frag_windows >= 2:
        return "NOT_CONFIRMED"
    df_bad = [f for f in s4_ok
              if rules.blackhole_df(f["df_ratio"], f["frag_first"], f["l_max"],
                                    f["ceiling_share"], f["t_device"], f["loss_lb"] or 0,
                                    f["loss_n"], f["quality"]["S4"]).positive]
    if len(df_bad) >= 2:
        return "NOT_CONFIRMED"
    full = [f for f in s4_ok if f["l_max"] - OVERHEAD == t_new]
    if (len(full) >= MIN_WINDOWS and len(s2_ok) >= MIN_WINDOWS and frag_windows == 0
            and not df_bad):
        return "CONFIRMED"
    if elapsed_s >= FOLLOWUP_MAX_S:
        return "INCONCLUSIVE"
    return None
