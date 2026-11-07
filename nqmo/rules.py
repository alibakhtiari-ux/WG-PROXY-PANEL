"""Diagnostic rules (design 04 §2). Pure functions: features in, Outcome out.

Every rule states what it needs; a rule whose stream is INVALID returns
positive=None ("n/a"), which is neither evidence for nor against.

Hard rules enforced here and pinned by tests:
  R-MTU-1  MTU classes (10, 11) take no throughput/rate input at all — their
           signatures receive only the fragment/size/DF/loss features.
  R-FILTER-1  no rule names filtering as a cause.
"""
from . import stats

DIRECT, INDIRECT = "DIRECT", "INDIRECT"

PARAMS = {
    "rcvbuf_err_min": 10,          # per window
    # myserver, 32 days (read 28 Oct): ReasmFails − ReasmTimeout = 830 in total
    # (≈0.1 per window); the saturated lab: ≈12 000 per window
    "reasm_drop_min": 10,          # fragments dropped without a queue, per window
    "frag_mem_pct": 90.0,          # of net.ipv4.ipfrag_high_thresh
    "conntrack_pct": 90.0,
    "hs_init_min": 3,
    "nat_tx_min": 148,             # one server Initiation
    # §29.157: a NAT/firewall fault kills a session that was alive moments ago.
    # A peer whose last handshake is older than this is simply offline (myserver,
    # 4 Nov: the four shadow HIGHs had last handshakes 4 to 30 days old, and
    # 1269 of 1432 NAT-looking minutes in six hours were ≥ 2 h old); the server
    # retrying its Initiation at an absent device is not a symptom.
    "nat_offline_s": 1800,
    "roam_ip_per_hour": 4,
    "reorder_ratio": 0.01,
    "loss_min": 0.01,
    "loss_n_min": 1000,
    "frag_min": 4,                 # first fragments per window
    "frag_min_total_high": 20,     # 04 §2 class 10: ≥20 first fragments for HIGH
    "frag_stable": 8,              # bytes
    "blackhole_ratio": 0.5,
    "blackhole_loss_down": 0.05,
    "df_ratio_min": 0.9,
    "ceiling_share_min": 0.3,
    "rtt_min_samples": 5,
    "rtt_abs_ms": 50.0,
    "rtt_mad_k": 3.0,
    "shaping_frac": 0.9,
    "saturation_frac": 0.9,
    "unknown_loss_factor": 3.0,
    "unknown_loss_floor": 0.005,
}

ALT = {
    "SERVER_RESOURCE_BOTTLENECK": ["traffic burst on the server", "NIC/driver issue",
                                   "reassembly memory filled by fragments that never "
                                   "complete (a peer behind a fragment-dropping path)"],
    "HANDSHAKE_FLOOD": ["handshake flood from unknown sources"],
    "EGRESS_TUNNEL_DEGRADATION": ["upstream provider of the tunnel", "stale panel data"],
    "TRAFFIC_SHAPING_EFFECT": ["the user is simply at the configured limit"],
    "HANDSHAKE_FAILURE": ["client uses an old key or a removed config",
                          "client-side firewall", "path drops 148-byte packets"],
    "NAT_OR_FIREWALL_ISSUE": ["the cause cannot be separated from the server side: "
                              "client NAT mapping expiry, client offline, or a path "
                              "blocking server→client traffic"],
    "ROUTING_ANOMALY": ["policy routing change on the server"],
    "UDP_INSTABILITY": ["mobile client changing networks", "CGNAT rebinding"],
    "PACKET_LOSS": ["drops inside the client (queue, Wi-Fi, firewall, EMSGSIZE)",
                    "upstream saturation by the client itself", "path loss"],
    "NETWORK_CONGESTION": ["client-side processing delay (mobile sleep)",
                           "path congestion", "server load"],
    "SUSPECTED_MTU_PROBLEM": ["client MTU set larger than the path carries",
                              "client local link (e.g. PPPoE) fragments itself"],
    "SUSPECTED_PMTU_BLACKHOLE": ["fragment-dropping middlebox", "random loss hitting fragments",
                                 "application using fixed-size datagrams (ceiling effect)"],
    "UNKNOWN_DEGRADATION": ["cause not identifiable from the server side"],
}


class Outcome:
    __slots__ = ("cls", "positive", "strength", "evidence", "counter", "cap", "quality",
                 "scope", "subject", "n")

    def __init__(self, cls, positive, strength=None, evidence=None, counter=None,
                 cap=None, quality="GOOD", scope="PEER", subject=None, n=None):
        self.cls = cls
        self.positive = positive          # True / False / None (n/a)
        self.strength = strength
        self.evidence = evidence or []
        self.counter = counter or []
        self.cap = cap                    # max confidence level, or None
        self.quality = quality
        self.scope = scope
        self.subject = subject
        self.n = n                        # sample count behind a positive verdict

    def as_dict(self):
        return {"class": self.cls, "positive": self.positive, "strength": self.strength,
                "evidence": self.evidence, "counter": self.counter, "cap": self.cap,
                "quality": self.quality}


def ev(metric, value, source, point, direction, n=None):
    d = {"metric": metric, "value": value, "source": source, "point": point,
         "direction": direction}
    if n is not None:
        d["n"] = n
    return d


def _na(cls, quality="INVALID", **kw):
    return Outcome(cls, None, quality=quality, **kw)


def _worst(*qs):
    order = {"GOOD": 0, "DEGRADED": 1, "INVALID": 2}
    return max(qs, key=lambda q: order[q])


# ------------------------------------------------------------- global / server
def server_resource(g, p=PARAMS):
    if g["valid_minutes"] == 0:
        return _na("SERVER_RESOURCE_BOTTLENECK", scope="GLOBAL", subject="server")
    e = []
    if g["softnet_dropped"] > 0:
        e.append(ev("softnet_dropped", g["softnet_dropped"], "/proc/net/softnet_stat",
                    "server backlog", "in"))
    if g["eth0_rx_missed_fifo"] > 0:
        e.append(ev("nic_missed_fifo", g["eth0_rx_missed_fifo"], "/sys/class/net",
                    "eth0 NIC", "in"))
    if g["udp_rcvbuf_err"] >= p["rcvbuf_err_min"]:
        e.append(ev("UdpRcvbufErrors", g["udp_rcvbuf_err"], "/proc/net/snmp", "UDP sockets", "in"))
    if g.get("reasm_drops", 0) >= p["reasm_drop_min"]:
        e.append(ev("reasm_drops_without_queue", g["reasm_drops"],
                    "/proc/net/snmp ReasmFails−ReasmTimeout", "IPv4 reassembly", "in"))
    if g.get("frag_mem_max", 0) >= p["frag_mem_pct"]:
        e.append(ev("reassembly_memory_pct", g["frag_mem_max"],
                    "/proc/net/sockstat FRAG ÷ ipfrag_high_thresh", "IPv4 reassembly", "in"))
    if g["conntrack_max"] >= p["conntrack_pct"]:
        e.append(ev("conntrack_pct", g["conntrack_max"], "/proc/sys/net/netfilter",
                    "conntrack", "both"))
    q = "GOOD" if g["valid_minutes"] == g["minutes"] else "DEGRADED"
    return Outcome("SERVER_RESOURCE_BOTTLENECK", bool(e), DIRECT, e, quality=q,
                   scope="GLOBAL", subject="server")


def handshake_flood(g):
    if g["valid_minutes"] == 0:
        return _na("HANDSHAKE_FLOOD", scope="GLOBAL", subject="server")
    pos = g["hs_cookie_out"] > 0
    e = [ev("cookie_reply_out", g["hs_cookie_out"], "AF_PACKET S1", "eth0", "out")] if pos else []
    return Outcome("HANDSHAKE_FLOOD", pos, DIRECT, e, scope="GLOBAL", subject="server")


# The panel's tunnel_health() vocabulary (wgpanel/app.py). "chain" is a live,
# healthy tunnel whose endpoint deliberately routes through another tunnel
# (WARP), and was flagged as degradation until PHASE 4 compared the two lists.
# Every other value (loop, off, dead, noreturn) is a real fault: the panel
# exports only tunnels that are enabled or up, so "off" is never intentional.
EGRESS_HEALTH_OK = frozenset({None, "healthy", "idle", "chain"})


def egress(g, meta_fresh):
    """One Outcome per egress tunnel in the panel's meta."""
    out = []
    eg = g.get("egress") or {}
    for name, e in sorted(eg.items()):
        if not meta_fresh:
            out.append(_na("EGRESS_TUNNEL_DEGRADATION", scope="EGRESS", subject=name))
            continue
        bad = []
        if e.get("health") not in EGRESS_HEALTH_OK:
            bad.append(ev("health", e.get("health"), "panel TunnelCache", name, "both"))
        if e.get("svc_ok") is False:
            bad.append(ev("svc_ok", False, "panel SvcDiag", name, "out"))
        if (e.get("mtr_loss") or 0) > 5.0:
            bad.append(ev("mtr_loss_pct", e.get("mtr_loss"), "panel mtr_run", name, "out"))
        out.append(Outcome("EGRESS_TUNNEL_DEGRADATION", bool(bad), INDIRECT, bad,
                           scope="EGRESS", subject=name, cap="MEDIUM"))
    return out


# ------------------------------------------------------------- per peer
def traffic_shaping(f, p=PARAMS):
    lim = f["rate_limit_mbit"]
    if not lim:
        return Outcome("TRAFFIC_SHAPING_EFFECT", False, quality=f["quality"]["C1"])
    e = []
    if f["tc_drops"] or f["tc_overlimits"]:
        e.append(ev("tc_drops+overlimits", f["tc_drops"] + f["tc_overlimits"],
                    "tc -s class", "wg1udp htb class", "both"))
    if f["c1_interval"] > 0:
        mbit = max(f["rx"], f["tx"]) * 8 / f["c1_interval"] / 1e6
        if mbit >= p["shaping_frac"] * lim:
            e.append(ev("rate_mbit", round(mbit, 2), "wg show transfer (panel)", "wg1udp",
                        "both"))
    strength = DIRECT if (f["tc_drops"] or f["tc_overlimits"]) else INDIRECT
    return Outcome("TRAFFIC_SHAPING_EFFECT", bool(e), strength, e, quality=f["quality"]["C1"])


def handshake_failure(f, p=PARAMS):
    q = f["quality"]["S1"]
    if q == "INVALID":
        return _na("HANDSHAKE_FAILURE")
    pos = f["hs_init_in"] >= p["hs_init_min"] and f["hs_resp_out"] == 0
    e = [ev("init_in", f["hs_init_in"], "AF_PACKET S1", "eth0", "in"),
         ev("resp_out", f["hs_resp_out"], "AF_PACKET S1", "eth0", "out")] if pos else []
    return Outcome("HANDSHAKE_FAILURE", pos, DIRECT, e, quality=q)


def nat_or_firewall(f, p=PARAMS):
    q = _worst(f["quality"]["S1"], f["quality"]["C1"])
    if q == "INVALID" or not f["c1_has_bytes"]:
        return _na("NAT_OR_FIREWALL_ISSUE", quality=q)
    sig = (f["rx"] == 0 and f["tx"] >= p["nat_tx_min"] and f["hs_init_out"] >= 1
           and f["hs_resp_in"] == 0)
    counter = []
    offline = sig and f["hs_age_max"] >= p["nat_offline_s"]
    if offline:
        counter.append("last handshake %d s ago ⇒ client offline, not a NAT symptom"
                       % f["hs_age_max"])
    pos = sig and not offline
    if pos and f["ep_ip_changes"]:
        counter.append("endpoint changed in this window ⇒ roaming")
    e = [ev("rx_bytes", f["rx"], "wg show transfer (panel)", "wg1udp", "in"),
         ev("init_out", f["hs_init_out"], "AF_PACKET S1", "eth0", "out"),
         ev("resp_in", f["hs_resp_in"], "AF_PACKET S1", "eth0", "in")] if pos else []
    return Outcome("NAT_OR_FIREWALL_ISSUE", pos, DIRECT, e, counter, quality=q)


def routing_anomaly(f):
    pos = f["route_bad"]
    e = [ev("reply_route_dev", "not WAN", "ip route get", "server routing", "out")] if pos else []
    return Outcome("ROUTING_ANOMALY", pos, DIRECT, e, quality=f["quality"]["C1"])


def udp_instability(f, hour_ip_changes, p=PARAMS):
    e = []
    if hour_ip_changes >= p["roam_ip_per_hour"]:
        e.append(ev("endpoint_ip_changes_per_hour", hour_ip_changes, "panel meta", "wg1udp", "in"))
    q4 = f["quality"]["S4"]
    if q4 != "INVALID" and f["s4_expected"] >= PARAMS["loss_n_min"]:
        ratio = (f["s4_reorder"] + f["s4_dup"]) / f["s4_expected"]
        if ratio >= p["reorder_ratio"]:
            e.append(ev("reorder+dup_ratio", round(ratio, 4), "AF_PACKET S4", "eth0", "in",
                        f["s4_expected"]))
    # roaming alone (a mobile client changing networks) is weak evidence
    roam_only = bool(e) and all(x["metric"] == "endpoint_ip_changes_per_hour" for x in e)
    return Outcome("UDP_INSTABILITY", bool(e), INDIRECT, e, quality=f["quality"]["C1"],
                   cap="LOW" if roam_only else None)


def _upstream_mbit(f):
    return (f["rx"] * 8 / f["c1_interval"] / 1e6) if f["c1_interval"] > 0 else None


def packet_loss(f, base, global_res_positive, df_blackhole_positive,
                frag_blackhole_positive=False, p=PARAMS):
    q = f["quality"]["S4"]
    if q == "INVALID" or f["loss_n"] < p["loss_n_min"]:
        return _na("PACKET_LOSS", quality=q)
    if df_blackhole_positive:                 # routed to class 11(b) instead
        return Outcome("PACKET_LOSS", False, quality=q)
    if frag_blackhole_positive:
        # the incomplete fragments ARE class 11(a): judge class 8 on counter
        # gaps alone, so one cause never raises two diagnoses (lab, 28 Oct)
        k, n = f["s4_lost"], f["s4_expected"]
        if stats.wilson(k, n)[0] < p["loss_min"]:
            return Outcome("PACKET_LOSS", False, quality=q)
    pos = f["loss_lb"] >= p["loss_min"]
    e = [ev("upstream_loss_wilson_lb", round(f["loss_lb"], 5), "AF_PACKET S4 counters",
            "eth0", "in", f["loss_n"]),
         ev("upstream_loss_point", round(f["loss_k"] / f["loss_n"], 5), "AF_PACKET S4",
            "eth0", "in", f["loss_n"])] if pos else []
    counter, cap = [], None
    if pos and global_res_positive:
        counter.append("server-side drops in the same window (class 1a)")
    up = _upstream_mbit(f)
    if pos and up and base and base.get("max_up_mbit") and up >= p["saturation_frac"] * base["max_up_mbit"]:
        counter.append("upload at ≥90% of this peer's historical maximum ⇒ client saturation")
        cap = "LOW"
    return Outcome("PACKET_LOSS", pos, DIRECT, e, counter, cap, quality=q)


def congestion(rtt_samples, quality, base, p=PARAMS):
    """Evaluated on 15-minute windows only."""
    if quality == "INVALID" or len(rtt_samples) < p["rtt_min_samples"]:
        return _na("NETWORK_CONGESTION", quality=quality)
    if not base or base.get("rtt_med") is None:
        return _na("NETWORK_CONGESTION", quality=quality)       # NO_BASELINE
    med = stats.median(rtt_samples)
    thr = base["rtt_med"] + max(p["rtt_mad_k"] * (base["rtt_mad"] or 0), p["rtt_abs_ms"])
    pos = med > thr
    e = [ev("rtt_median_ms", round(med, 1), "AF_PACKET S1 handshake pairs", "eth0", "both",
            len(rtt_samples)),
         ev("baseline_threshold_ms", round(thr, 1), "nqmo baseline", "per peer", "both",
            base.get("rtt_n"))] if pos else []
    return Outcome("NETWORK_CONGESTION", pos, DIRECT, e, quality=quality)


# --- MTU classes: R-MTU-1 — signatures take no rate/throughput input -----------
def mtu_problem(frag_first, F_min, F_max, l_max, t_config, q_s2, q_s4, p=PARAMS):
    if q_s2 == "INVALID":
        return _na("SUSPECTED_MTU_PROBLEM", quality=q_s2)
    pos = (frag_first >= p["frag_min"] and F_min is not None
           and (F_max - F_min) <= p["frag_stable"])
    e = [ev("first_fragments", frag_first, "AF_PACKET S2", "eth0", "in"),
         ev("first_fragment_len", [F_min, F_max], "AF_PACKET S2", "eth0", "in")] if pos else []
    counter, cap = [], None
    if pos and q_s4 != "INVALID" and l_max and t_config and l_max >= t_config + 60:
        counter.append("full-size packets also arrived unfragmented ⇒ multi-path")
        cap = "LOW"
    return Outcome("SUSPECTED_MTU_PROBLEM", pos, DIRECT, e, counter, cap, quality=q_s2,
                   n=frag_first)


def blackhole_frag(frag_first, frag_incomplete, loss_point, q_s2, frags_per_datagram=2,
                   p=PARAMS):
    """11(a): upstream fragments that never complete (client without DF).

    loss_point must be the COUNTER-gap loss only — a loss figure that already
    folds in the incomplete fragments would make the symptom its own
    counter-evidence (lab, 28 Oct). Independent loss p leaves a k-fragment
    datagram incomplete with probability 1−(1−p)^(k−1); counter-evidence is
    claimed only when twice that can reach the observed ratio. (Correlated
    burst loss lowers the ratio: a lost first fragment is never counted.)"""
    if q_s2 == "INVALID" or frag_first < p["frag_min"]:
        return _na("SUSPECTED_PMTU_BLACKHOLE", quality=q_s2)
    ratio = frag_incomplete / frag_first
    pos = ratio >= p["blackhole_ratio"]
    e = [ev("incomplete_fragment_ratio", round(ratio, 3), "AF_PACKET S2+S3", "eth0", "in",
            frag_first)] if pos else []
    counter = []
    if pos and loss_point is not None and loss_point >= p["blackhole_loss_down"]:
        k = max(2, int(frags_per_datagram or 2))
        explained = 1.0 - (1.0 - min(loss_point, 1.0)) ** (k - 1)
        if ratio <= 2.0 * explained:
            counter.append("overall loss ≥5% also explains lost fragments")
    return Outcome("SUSPECTED_PMTU_BLACKHOLE", pos, DIRECT, e, counter, quality=q_s2)


def blackhole_df(df_ratio, frag_first, l_max, ceiling_share, t_device, loss_lb, loss_n,
                 q_s4, p=PARAMS):
    """11(b): DF-setting client (wireguard-go): big packets vanish, no fragments."""
    if (q_s4 == "INVALID" or df_ratio is None or l_max is None or t_device is None
            or loss_n < p["loss_n_min"]):
        return _na("SUSPECTED_PMTU_BLACKHOLE", quality=q_s4)
    pos = (df_ratio >= p["df_ratio_min"] and frag_first == 0
           and l_max <= t_device + 60 - 16
           and (ceiling_share or 0) >= p["ceiling_share_min"]
           and loss_lb >= p["loss_min"])
    e = [ev("df_ratio", round(df_ratio, 3), "AF_PACKET S4", "eth0", "in"),
         ev("l_max_unfrag", l_max, "AF_PACKET S4", "eth0", "in"),
         ev("ceiling_share", round(ceiling_share or 0, 3), "AF_PACKET S4", "eth0", "in"),
         ev("upstream_loss_wilson_lb", round(loss_lb, 5), "AF_PACKET S4", "eth0", "in",
            loss_n)] if pos else []
    return Outcome("SUSPECTED_PMTU_BLACKHOLE", pos, DIRECT, e, cap="MEDIUM", quality=q_s4)


def unknown_degradation(f, base, explained, p=PARAMS):
    q = f["quality"]["S4"]
    if explained or q == "INVALID" or f["loss_n"] < p["loss_n_min"] or not base \
            or base.get("loss_rate") is None:
        return _na("UNKNOWN_DEGRADATION", quality=q)
    thr = max(p["unknown_loss_factor"] * base["loss_rate"], p["unknown_loss_floor"])
    pos = f["loss_lb"] >= thr
    e = [ev("upstream_loss_wilson_lb", round(f["loss_lb"], 5), "AF_PACKET S4", "eth0", "in",
            f["loss_n"]),
         ev("baseline_loss", round(base["loss_rate"], 5), "nqmo baseline", "per peer", "in")] \
        if pos else []
    return Outcome("UNKNOWN_DEGRADATION", pos, INDIRECT, e, quality=q)
