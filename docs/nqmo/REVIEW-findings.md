# WG-NQMO Phase 1: adversarial review findings

Scope: docs 01–06. Evidence comes from the kernel v6.8 WireGuard copies in `scratchpad/ksrc/`, from `wgpanel/app.py`, `tests/test_wg_panel.py`, `ansible/roles/wg-panel/files/wg-panel.service`, and from upstream Linux and wireguard-go sources. Line numbers refer to those files. Nothing was run on the server.

Severity scale:
- **BLOCKER**: the design cannot work as written.
- **MAJOR**: it can produce wrong or fabricated output, or a stated guarantee is false.
- **MINOR**: a correctness or clarity problem.

---

## A. Findings

### 1. BLOCKER: a capture socket bound to `ETH_P_IP` never sees outgoing packets, so S1 and RTT are blind to half the exchange
- **Where:** 02 §C3 ("`socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))`"). The design relies on outgoing packets in several places: S1 ("Response ِ خروجی", "Cookie Reply ِ خروجی"), RTT case (الف) (`t(Response ِ خروجی)`) and case (ب) (`t(Initiation ِ خروجی)`), and class 4 (Initiation in vs Response out). Class 1 also uses the Cookie Reply out.
- **Why it is wrong:**
  - In `net/core/dev.c`, `dev_queue_xmit_nit()` delivers transmitted skbs only to `ptype_all` and `dev->ptype_all`.
  - `dev_add_pack()` puts a protocol-specific handler (`ETH_P_IP`) into `ptype_base`, not `ptype_all`.
  - So an `ETH_P_IP` packet socket receives inbound frames only. The server's Responses, server-initiated Initiations and Cookie Replies are never captured.
  - Two more consequences: `ptype_base` delivery happens after tc ingress and after the netdev-family netfilter ingress hook. The tap is therefore not "before everything", which matters if anything is ever attached to eth0 ingress.
- **Fix:**
  - Create the socket with `ETH_P_ALL`.
  - Check IPv4 in the filter, either with `SKF_AD_PROTOCOL` or with the DLT_RAW version-nibble check.
  - Get direction from `SKF_AD_PKTTYPE` or from `sll_pkttype` (`PACKET_OUTGOING` vs `PACKET_HOST`), which Python's `recvfrom` returns as the 3rd address element.
  - Use `PACKET_IGNORE_OUTGOING` on the sockets that only need inbound traffic (S2, S3, S4).

### 2. BLOCKER: `tcpdump -dd` on eth0 emits Ethernet (DLT_EN10MB) offsets, but a SOCK_DGRAM filter runs on data that starts at the IP header
- **Where:** 02 §C3 ("compiled in the lab with `tcpdump -dd`"), plus `NqmoBpfEquivalenceTests` in 06.
- **Why it is wrong:**
  - In `packet_rcv()` the skb for SOCK_DGRAM sockets is positioned at the network header. For outgoing frames the code even pulls the link header (`skb_pull(skb, skb_network_offset(skb))`) before `run_filter()`.
  - A program compiled for an eth0 capture starts with `ldh [12]` (ethertype) and puts every IP offset 14 bytes too far. It will match nothing, or garbage.
  - The equivalence test as described would not catch this. It replays lab pcaps of the same linktype, so it runs against Ethernet-framed pcaps, not against what the kernel actually hands a DGRAM filter.
  - On `wg1udp` (ARPHRD_NONE, no `header_ops`), `tcpdump -i wg1udp` already uses DLT_RAW, so S5 happens to be right. That makes the inconsistency easy to miss.
- **Fix:**
  - Compile every program for DLT_RAW: `tcpdump -y RAW -dd` against a raw-linktype source, or `pcap_compile_nopcap(snaplen, DLT_RAW, ...)`.
  - Store reference pcaps as LINKTYPE_RAW.
  - Add one lab test that runs the actual SOCK_DGRAM socket on a veth and asserts that real hits occur.
  - Also make sure the `ret #N` snaplen is in the program itself. `tcpdump -s 44 -dd` already emits it.

### 3. MAJOR: the claim "filter is attached before bind, so not one unfiltered packet surfaces" is false
- **Where:** 02 §C3, safety principles. It is also leaned on by 05 §5.6 ("no payload").
- **Why it is wrong:**
  - `packet_create()` with a non-zero protocol calls `register_prot_hook()` at once. The socket receives from all interfaces before `bind()` and before `SO_ATTACH_FILTER`.
  - Frames that arrive in that window are queued with no filter, so full payload is copied to userspace on the first `recv`. This holds for frames from any interface, including `wg1udp` plaintext.
- **Fix:**
  - Use `socket(AF_PACKET, SOCK_DGRAM, 0)` (protocol 0 registers no hook).
  - Then `SO_ATTACH_FILTER`, then `SO_LOCK_FILTER`, and only then `bind((ifname, ETH_P_ALL))`.
  - Optionally drain the queue once with `MSG_DONTWAIT` after bind, as defence in depth.
  - Add a test that asserts this call order on the socket.

### 4. MAJOR: the dynamic S1b socket has a structural race that biases RTT upward. A static stateless filter does the job.
- **Where:** 02 S1b and the RTT case (الف); 01 §0.
- **Why it is wrong:**
  - S1b can only be created after Python has received the outgoing Response, parsed it, patched the bytecode and built, attached and bound a new socket. Under `Nice=10` and `CPUQuota=20%`, that takes milliseconds to tens of milliseconds.
  - For in-country clients with RTT around 10–40 ms, the client's first data packet often arrives before the socket exists. Those samples become `MISSED`.
  - The samples that survive are therefore the slow ones, so the RTT median is systematically biased high.
  - Two side issues:
    - BPF loads are big-endian, while `sender_index` is `__le32` (messages.h:83–96). If Python unpacks the index with `'<I'` and patches the integer into `jeq`, the comparison is wrong. The fix is `int.from_bytes(raw, 'big')`.
    - The "one S1b at a time, otherwise SKIPPED" rule drops samples under concurrency.
- **Evidence for the replacement:** the first data message of every keypair has counter 0. Nonces are assigned as `atomic64_inc_return(&keypair->sending_counter) - 1` (send.c:379–380). That is true whichever side initiated. wireguard-go also starts its `sendNonce` at 0.
- **Fix:**
  - Drop S1b entirely.
  - Make S1 a static filter that also accepts `udp[8]=4 and udp[16:4]=0 and udp[20:4]=0` (data message with counter 0) on dst port 53953.
  - Pair that packet with the Response in userspace by comparing the raw 4 bytes at `udp[12:4]`.
  - This costs about one packet per handshake, has no race, and has no dynamic bytecode.

### 5. MAJOR: RTT timestamps are taken in userspace, under CPU throttling
- **Where:** 02 S1 and RTT.
- **Why it is wrong:**
  - `CPUQuota=20%` lets the cgroup be throttled for up to about 80 ms of every 100 ms period.
  - `Nice=10` adds scheduling delay on top.
  - With `time.time()` at `recv`, RTT error can reach tens of milliseconds, which is about the size of the quantity being measured.
- **Fix:**
  - Enable `SO_TIMESTAMPNS` on the AF_PACKET socket.
  - Read the kernel receive or transmit timestamp from the ancillary data of `recvmsg` (Python's `socket.recvmsg` supports this).
  - For outgoing frames the timestamp is taken in `dev_queue_xmit_nit`, which is good enough.

### 6. MAJOR: the RTT for a server-initiated handshake, case (ب), must be paired by index
- **Where:** 02 S1, case (ب).
- **Why it is wrong:**
  - The server retransmits Initiation every REKEY_TIMEOUT (5 s), and each retry carries a new `sender_index`.
  - A naive `t(Response in) − t(Initiation out)` can pair a Response with the wrong (latest) Initiation, which gives errors of about 5 s or negative values.
- **Fix:**
  - Pair the Response's `receiver_index` (WG offset 8, i.e. `udp[16:4]`) with the outgoing Initiation's `sender_index` (`udp[12:4]`).
  - Discard Initiations that have no match.

### 7. MAJOR: the outer DF assumption is wrong for wireguard-go on Linux and Android, so the "ICMP filter has no effect" claim and the MTU model are incomplete
- **Where:**
  - 01 §0 (DF never set): true for the server's own kernel sends (socket.c:84–86, `df=0`; `skb->ignore_df=1`).
  - 04 §7 ("بسته‌ی بیرونی DF ندارد").
  - 06 scenario 14 ("بی‌اثر (DF=0)").
- **Why it is wrong:**
  - The client-side behaviour depends on the implementation.
  - wireguard-go's Linux socket setup (`conn/controlfns_linux.go`, upstream master) sets SO_RCVBUF/SNDBUF, IP_PKTINFO and UDP_GRO but never `IP_MTU_DISCOVER`. The socket therefore keeps the default `IP_PMTUDISC_WANT`.
  - Under `IP_PMTUDISC_WANT`, Linux sets DF on every datagram that fits the cached PMTU. It fragments locally only after it has learned a smaller PMTU from an ICMP frag-needed message.
  - This covers wireguard-go on Linux and the Android app's Go backend, which most Android users run. On these clients:
    1. When ICMP is filtered upstream (likely on the target networks), large outer packets are silently dropped. That is a classic PMTU blackhole.
    2. The server then sees no fragments at all (`frag_first = 0`). It sees only counter gaps, which class 8 reads as `PACKET_LOSS`, and R-MTU-1 forbids calling that an MTU issue.
    3. When ICMP is not filtered, the client fragments locally at the learned PMTU. F is still meaningful in that case.
  - Kernel (Linux), wireguard-nt (Windows) and Apple clients behave differently. DF behaviour for wireguard-nt and Apple is not verified here and must be listed as NOT_VERIFIED rather than assumed.
- **Fix:**
  - Add a DF-client signature: S4 shows loss concentrated in bulk traffic while `L_max` is stuck below `T+60`, with `frag_first = 0`. This is evidence for a DF-client MTU blackhole (route it into class 11, not class 8).
  - Record `DF` per peer from S4 (`ip[6]&0x40`). That bit is the observation that tells the two client models apart.
  - Correct scenario 14's expected output, and add a wireguard-go Linux client with ICMP filtering to the lab matrix.

### 8. MAJOR: the `VERIFIED` rule compares `L_max` against a lower bound, which is the wrong direction
- **Where:** 04 §4.3 row 1 (`L_max ≥ T_device + 60`, with `T_device = MSS_max+40` labelled `OBSERVED_LOWER_BOUND`).
- **Why it is wrong:** to prove that the current MTU is sufficient, `L_max` has to reach the actual tunnel MTU plus 60. Comparing it against a lower bound of that MTU can return `VERIFIED` while full-size packets have never been seen.
- **Useful fact:** the outer size never exceeds `client_tunnel_MTU + 60`. Padding is capped at the MTU: `padded_size = min(mtu, ALIGN(len,16))` (send.c:157–158). So for a bulk-traffic peer, `L_max − 60` is itself a direct measurement of the client tunnel MTU.
- **Fix:**
  - Require `L_max ≥ max(T_config, T_device) + 60`.
  - Alternatively, define `T_observed = L_max − 60` and only report `VERIFIED` when `T_observed ≥ T_config`.

### 9. MAJOR: MSS is not a lower bound on the client's tunnel MTU
- **Where:** 02 S5 and 04 §4.1.
- **Why it is wrong:** a client that is a router (OpenWrt, MikroTik, Android tethering, a PC sharing its connection) forwards LAN hosts' SYNs without clamping, typically with MSS 1460. That gives `MSS+40 = 1500`, above the tunnel MTU, so the "lower bound" is violated in exactly the population that has MTU problems.
  - `MSS = MTU−40` also only holds for IPv4. Clients with inner IPv6 (`::/0` is allowed) advertise `MTU−60`. They are invisible because S5 filters IPv4 only, but this should be stated.
- **Fix:**
  - Use `T_device = min(MSS_mode + 40, T_config)`.
  - Emit a flag `MSS_EXCEEDS_TUNNEL_MTU` when `MSS+40 > T_config`. That is itself a useful finding: an unclamped LAN behind the client.
  - Use the mode rather than the max.

### 10. MAJOR: the fragment math holds as a safe lower bound, but "upstream PMTU ∈ [F, F+7]" and "L_max is a lower bound on PMTU" both need stated assumptions
- **Where:** 04 §4.2 and 02 S4 (`L_max`).
- **What is correct:**
  - With maximal-size fragmentation and no options, `F = 20 + 8⌊(M−20)/8⌋`.
  - Refragmentation can only shrink F.
  - Therefore `F ≤ every link MTU after the fragmentation point`.
  - `T = F−60` is safe for kernel-style padding: an inner packet of size T is padded to `min(ALIGN(T,16), T) = T`, so the outer size is exactly F.
- **What is assumption-dependent:**
  - The upper bound `F+7` requires the fragmenter to emit maximal first fragments. Equal-size or "small first fragment" fragmenters exist, and they make F smaller, so the result is still safe but the stated interval is wrong.
  - Middleboxes that reassemble fragments (CGNAT or firewall reassembly) break both claims:
    - The client's 1400-byte link fragments the packet, and a reassembler forwards it whole. The server sees an unfragmented 1452, so `L_max = 1452 > PMTU` of the client-side segment.
    - If the reassembler refragments at its own egress MTU, F reflects the segment after the reassembler only.
  - Operationally "delivered intact at size L" is still true, but "PMTU ≥ L" and "PMTU ≤ F+7" are not.
- **Fix:**
  - Rephrase as `delivered_size ≥ L_max` and `safe_T = F − 60`.
  - Treat the F+7 interval as a hypothesis that the lab checks.
  - Keep acceptance criterion 06 §6.3-3 (`[−7, 0]`) as a lab-only claim.
  - Additionally read `udp[4:2]` from the first fragment (it is captured within 28 bytes). It gives the original datagram size `O = udp_len + 20`, which tells you the client's actual outer size. Add a sanity check `O − 60 ≤ T_config`.

### 11. MAJOR: the dynamic S3 filter creates false `frag_incomplete` (a false PMTU-blackhole signal)
- **Where:** 02 S3 (`src host (E1 or E2 …)`, socket replaced on change).
- **Why it is wrong:**
  - Each time the endpoint set changes, which happens on every roam and CGNAT rebind, a socket is closed and a new one opened.
  - Trailing fragments that arrive in the gap are lost. For a newly roamed endpoint, trailing fragments are missed until the next C1 tick (up to 10 s), while S2, which is static, still counts the first fragments.
  - Both effects inflate `frag_incomplete/frag_first`, which is exactly class 11(a).
  - Smaller issue: completeness is judged only by seeing the MF=0 fragment. A lost middle fragment is counted as complete.
- **Fix:**
  - Make S3 static: `ip[9]=17 and ip[6:2]&0x1fff!=0` with snaplen 20. Non-first UDP fragments are rare on eth0.
  - If it must stay dynamic, open the new socket before closing the old one and dedupe.
  - Key fragments by `(src, dst, proto, id)` (RFC 791).
  - Track byte coverage (offset and length) rather than only MF=0.
  - Mark the window `DEGRADED` around any filter swap.

### 12. MAJOR: the S4 loss statistics can produce false HIGHs, and "counter gap = path loss" includes client-local drops
- **Where:** 02 S4 and 04 class 8.
- **Statistics:**
  - With n = 200 and `loss_min = 1%`, two lost packets is enough to cross the threshold.
  - At a true loss of 0.3%: P(≥2 lost | n=200) ≈ 1 − e^−0.6·1.6 ≈ 0.12.
  - With about 12 peers × 288 windows a day, multi-window false positives are expected. That violates 06 §6.3-1 (zero false HIGH).
- **Client-local drops:**
  - The sender consumes nonces before encryption and transmit (send.c:379).
  - Packets with assigned nonces are dropped by:
    - encryption failure;
    - a full encrypt or tx ring (`MAX_QUEUED_PACKETS = 1024`);
    - `wg_socket_send_skb_to_peer` errors;
    - the client's own qdisc or Wi-Fi driver;
    - the client's firewall;
    - wireguard-go's outbound-queue drops;
    - EMSGSIZE/ENOBUFS on a DF socket (see finding 7).
  - All of these show up as gaps. Saturated uploads therefore look like "path loss".
- **Fragment interplay:** S4 counts a counter when the first fragment arrives. If a trailing fragment is lost, the packet is lost but not counted, so loss is undercounted for fragmenting peers.
- **Fix:**
  - Decide on a confidence bound, for example the Wilson or Clopper-Pearson lower bound ≥ `loss_min`, rather than the point estimate.
  - Raise the minimum n.
  - Add "client-side egress saturation" to the alternatives: rate close to the peer's historical max, plus the upload direction.
  - Fold `frag_incomplete` into loss.

### 13. MAJOR: sliding windows are counted as independent repetitions
- **Where:** 02 "پنجره‌ها" (5- and 60-minute windows sliding over minute rows); 04 §3 HIGH (≥3 GOOD windows); R-HYST-1; class 8 (≥2 windows); class 10 and 11 (≥3 windows).
- **Why it is wrong:**
  - Five-minute windows that slide by one minute overlap by 80%. A single 3-minute burst satisfies "3 windows".
  - A single S4 sample, taken once per 5 minutes per peer, falls into up to five overlapping windows. So "2 valid windows" can be met by one 5-second measurement.
- **Fix:** count repetitions only over non-overlapping (tumbling) windows. For S4, count distinct sampling runs.

### 14. MAJOR: `NETWORK_CONGESTION` cannot fire in a 5-minute window
- **Where:** 04 class 9 (≥5 RTT samples); 01 §0 (one sample per handshake, about every 2 minutes).
- **Why it is wrong:**
  - Rekeying happens at REKEY_AFTER_TIME (120 s), giving at most about 2.5 samples per 5 minutes.
  - Five samples need about 10 minutes or more. Three repetitions for HIGH need 30 minutes or more of consistent activity.
- **Fix:**
  - State that class 9 runs only in the 60-minute window.
  - Say explicitly that RTT detection latency is at least 10 minutes.

### 15. MAJOR: `ALERTS.edge` stays silent the first time it sees a key, so the first OPEN never alerts
- **Where:** 05 P3 and 01 §1.
- **Why it is wrong:**
  - `AlertManager.edge` (app.py:7229–7245) emits only when `prev is not None and prev != now_state`.
  - A key like `nqmo:<scope>:<subject>:<class>` that has never been seen returns `prev = None` on its first call, which sends no message. That first call is the first OPEN.
  - A later CLEARED (False) then sends a "recovered" message for an alert that was never sent.
  - Keys are also pruned after `EDGE_TTL` (7 days, app.py:7180), so the problem recurs.
  - The existing `_check_tunnels` avoids this by calling `edge()` for every tunnel on every cycle. nqmo diagnoses are sparse, so the same trick does not apply automatically.
- **Fix:**
  - On every cycle, call `edge(key, False, …)` for every (peer × alertable class) once nqmo state is available.
  - Alternatively, use `ALERTS.event("nqmo", text)` for OPEN transitions that nqmo has already deduplicated (it has hysteresis and state).
  - Either way, add `("nqmo", …)` to `ALERT_EVENTS` and use `category="nqmo"`. `test_every_offered_alert_kind_has_an_emitter` (tests:2555) requires that literal.
  - ACK suppression needs explicit handling, because `edge` has no mute parameter.

### 16. MAJOR: the claim that "no secret enters the process" holds for nqmo's own code only. The residual-risk section understates what `CAP_NET_ADMIN` gives.
- **Where:** 01 §6 and 05 §5.6.
- **Why it is wrong:**
  - `WG_CMD_GET_DEVICE` returns the interface private key and every peer PSK to any caller with `CAP_NET_ADMIN`.
  - `wg show <if> endpoints` fetches the full device inside the `wg` child process. That child runs under the same uid and caps, so the secret is in the child's memory even though only endpoints are printed.
  - Any code execution in nqmo therefore yields the server private key, every PSK, and the ability to rewrite peers, routes and nft rules.
  - It also yields `CAP_NET_RAW` plus AF_PACKET, which allows full-payload sniffing and injection.
- **Fix:**
  - State this plainly in the residual risk.
  - Consider dropping `CAP_NET_ADMIN` altogether. The panel's Sampler already runs `wg show` as root every 2 s (`SAMPLE_INTERVAL = 2.0`, app.py:107). It could export endpoints, handshakes and transfer in `nqmo-meta.json`, leaving nqmo with only `CAP_NET_RAW`.
  - The trade-off is that nqmo loses independence while the panel is down. When meta is stale, nqmo can simply mark C1 `INVALID`.
  - Also grant `CAP_NET_RAW` only while `capture.enabled` is on, for example through a drop-in that is installed in step D4.

### 17. MAJOR: the privacy claims ("at most 16 bytes" / "only 44 bytes parsed") are false for S2, S3 and S5
- **Where:** 03 §حریم خصوصی, 05 §5.6, versus 02's own snaplen table.
- **Why it is wrong:**
  - A cBPF program can only truncate; the returned data always starts at the IP header.
  - S5 (80 bytes on `wg1udp`) therefore delivers the inner destination IP and port of every new TCP connection by every user to userspace. That is browsing metadata.
  - S2 and S3 deliver the outer source and destination IPs.
- **Fix:**
  - Correct the docs.
  - Parse into `(tunnel_src, mss)` and discard the buffer immediately.
  - Add a test that the inner destination fields are never stored or logged.
  - Separately, 400-day `peer_hour` rows with `ctx_key` (ASN or prefix) are a long-term location history per named user. Either justify that or shorten it.

### 18. MAJOR: the active probe can fabricate a threshold from a local `EMSGSIZE`, and its granularity breaks the [−7,0] criterion
- **Where:** 04 §7 and §4.3 ROUNDTRIP row.
- **Local error:**
  - The search range upper bound is `T_config − 28`.
  - If `T_config > mtu(wg1udp) = 1392`, `ping -M do -s S` with `S+28 > 1392` fails locally ("message too long, mtu=1392").
  - That failure is read as "no reply", producing `S* = 1364`, a "ROUNDTRIP ESTIMATED 1392" that is really the server's own interface MTU.
  - Fix: use an upper bound of `min(T_config, mtu(wg1udp)) − 28`, and treat ping's local-error exit or stderr as `PROBE_ERROR`, never as a size failure.
- **Padding quantization:**
  - The downstream outer size is `min(ALIGN(S+28,16), 1392) + 60`, so the threshold is quantized to 16 bytes.
  - Example: downstream PMTU 1450 gives `S* = 1348` and a suggestion of 1376, while the true safe value is 1390. That is an error of −14, which fails criterion 06 §6.3-3.
  - Fix: report ±15 for probe-derived values, or exempt ROUNDTRIP from criterion 3.
- **DF reply side:** the echo reply goes upstream with client-dependent DF (see finding 7), so success or failure can flip after the client's PMTU cache updates. Repeating the boundary only partly mitigates this.
- **Address family:** add `-4` to the argv. Without it, iputils also tries to open an AF_INET6 socket, which `RestrictAddressFamilies` denies. That is non-fatal but noisy.

### 19. MAJOR: `eth0 rx_dropped > 0` as counter-evidence (class 8 → class 1) will fire constantly
- **Where:** 04 class 8; 02 S4 limitation (1).
- **Why it is wrong:**
  - In `__netif_receive_skb_core`, `rx_dropped` counts frames with no protocol handler (LLDP, STP, unknown ethertypes from the hosting switch). It is incremented after the taps.
  - NIC ring overflow usually appears in `rx_missed_errors` or `rx_fifo_errors`, or in driver-specific counters, not in `rx_dropped`.
  - The rule as written can permanently suppress class 8 and push evidence toward class 1.
  - The drops that really happen before the tap are softnet backlog drops (`softnet_stat` column 2).
- **Fix:**
  - Use the `softnet_stat` dropped delta, plus `rx_missed_errors` and `rx_fifo_errors` deltas, relative to their baseline.
  - Do not use raw `rx_dropped`.

### 20. MINOR: the GRO claim cites the wrong knob
- **Where:** 01 §0 and 02 "GRO".
- **What is correct:**
  - In 6.8 `udp4_gro_receive()`, the socket lookup happens (`udp_encap_needed_key` is enabled by `setup_udp_tunnel_sock`).
  - The WireGuard socket has no `gro_receive` (socket.c:356 sets only `encap_rcv`) and does not set `UDP_GRO`.
  - So `udp_gro_receive()` merges only if `NETIF_F_GRO_FRAGLIST` (`rx-gro-list`) is on, through `is_flist = !GRO_ENABLED`.
- **What is wrong:** `rx-udp-gro-forwarding` (`NETIF_F_GRO_UDP_FWD`) applies only when `sk == NULL`, so it is irrelevant here.
- **Fix:**
  - Check `rx-gro-list` in the lab and in the passive phase.
  - Keep the runtime guard, but compute it from the captured IP `tot_len`, not from `recv`'s return value. The `recv` value is capped at the snaplen of 44, so as written the "frame > MTU" guard can never fire.
  - Alternatively use `MSG_TRUNC`.

### 21. MINOR: `SO_RCVBUF = 4 MB` is silently capped, and per-skb truesize makes the buffer small
- **Why:**
  - `SO_RCVBUF` is capped at `net.core.rmem_max` (default 212992, doubled internally).
  - Queued clones are charged their full truesize (about 2–4 KB each) even after trimming, so the buffer holds only about 100–200 packets.
  - At 20k pps, `tp_drops > 0` becomes near-certain. Because any drop invalidates the window, heavy users get no loss data at all.
- **Fix:**
  - Use `SO_RCVBUFFORCE` (requires the `CAP_NET_ADMIN` that is already held), or
  - use `PACKET_RX_RING` with TPACKET_V3 from the start. Frames there are snaplen-sized, and timestamps come for free.
  - Also note that `PACKET_STATISTICS` resets on read. Read it before closing any socket that is being swapped.

### 22. MINOR: integration details in app.py
- **Cadence:**
  - `AlertMonitor.INTERVAL = 30` (app.py:7277), not 60. P1 needs a `_due()`-style gate.
  - P1 and P3 must sit outside `if alert_cfg()["enabled"]:` (app.py:7306), or meta export stops whenever Telegram alerts are off, which is the default (`ALERT_DEFAULTS.enabled=False`).
  - A single `try` wraps all checks (app.py:7301–7313). Give the meta export its own `try`, so an exception in `_check_tunnels` does not stall it.
- **`ESCALATION_PERMS`:**
  - Its definition (app.py:1105–1114) means "permissions that let the holder gain more permissions", and `role_is_privileged` (app.py:1117, used at 10596) gates role assignment on it.
  - `nqmo.probe` and `nqmo.manage` do not escalate RBAC. Putting them there changes role-assignment semantics.
  - Use a separate `SENSITIVE_PERMS`, or justify the change.
- **`/run/wg-panel`:** nothing in the repository creates it. The panel unit has no `RuntimeDirectory`, and `/run` is tmpfs. Specify who runs `mkdir`, with which mode (0750 root:wg-nqmo), and what happens when the group does not exist (nqmo uninstalled).
- **Verified as present:** `PERM_CATALOG` at app.py:1039; `PERM_MAP` at 14984; `build_metrics` at 14199; `_check_report` at 7383; `ALERT_EVENTS` at 6087; tests at tests:761, 2170, 2514, 2555, 6537, 8860 (`HttpSmokeTests`), 10468.

### 23. MINOR: systemd unit
- `ReadOnlyPaths=/` is redundant with `ProtectSystem=strict`.
- `ReadWritePaths=` for StateDirectory and RuntimeDirectory is redundant. Neither conflicts.
- Missing hardening options that are cheap to add: `PrivateDevices=yes`, `ProtectKernelLogs=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `UMask=0077`, `SystemCallFilter=~@privileged @resources` (after a lab check), `ProtectProc=invisible`. Do **not** add `ProcSubset=pid`; it hides `/proc/net` and `/proc/stat`.
- `IOSchedulingClass=idle` can starve the per-minute SQLite commit under I/O pressure. Combined with `WatchdogSec=90`, that can cause watchdog restarts. Use `best-effort` with priority 7.
- §7 says `python3 -m nqmo --check`, while the unit runs the pyz. Unify on `python3 -I /opt/wg-nqmo/wg_nqmo.pyz --check`.

### 24. MINOR: other inconsistencies
- **Byte counters:**
  - `rx_bytes` and `tx_bytes` are WireGuard message bytes, not "inner decrypted bytes".
  - Evidence: receive.c `update_rx_stats(peer, message_data_len(len_before_trim))`, handshakes counted with `skb->len`; socket.c:183 `tx_bytes += skb_len` for all messages.
  - Fix the wording in 02 C1. Rate thresholds should account for the 32 bytes per packet plus handshakes.
- **Class 4 predicate:** "hs_age > 180 s with queued traffic" cannot be observed per peer (only `wg1udp tx_dropped` exists, at interface level). Remove it or redefine it.
- **Class 1:** "Cookie Reply out" means `handshake_queue_len ≥ 512` (receive.c:112–113). That is a handshake-flood signal, not general CPU pressure. Also the precedence of the "يا … و هم‌زمان softirq" condition is ambiguous; write it as explicit boolean logic.
- **Contradiction on server-tunnel severity:**
  - 04 §4.4 gives `SERVER_TUNNEL` HIGH from a calculation, but §3 says HIGH requires direct measurement.
  - The known wg21/22-over-awg1 finding would also raise a permanent 🔴 alert from the moment `DIAGNOSTICS_ENABLED` is on, even though df=0 fragmentation still delivers.
  - Use a separate config-audit severity that never pages.
  - The `ip route get` check must evaluate every nexthop of the ECMP group (910), not the single one it returns. It should also pass `from <local>` and the WG socket's `mark`, if any, so it matches how WireGuard actually routes replies.
- **`tp_drops`:** 01 says it "lowers data_quality" (→ DEGRADED), while 02 says any drop makes the window invalid (→ INVALID). Pick one.
- **UDP_INSTABILITY:** CGNAT port rebinding is normal for mobile clients. Count IP or prefix changes separately from port-only changes, or the class fires on healthy mobiles.
- **`collector_health`:** primary key `(collector, ts-minute)` collides with C1's 10-second runs. Aggregate per minute, or use `REAL` ts.
- **ASN memory:** two Python `list[int]` over about 600k ranges is about 40 MB, not 15 MB. Use `array('I')` from the start.
- **Probe range:** the range `[1232, T−28]` is empty when `T_config < 1260`. Handle it explicitly as UNDETERMINED.

---

## B. Claims checked and found correct

- **Message sizes:**
  - Initiation 148 = 4+4+32+48+28+32.
  - Response 92 = 4+4+4+32+16+32.
  - Cookie 64 = 4+4+24+32.
  - The matching UDP lengths 156, 100 and 72 in the S1 expression are right (messages.h:79–102).
- **Offsets:**
  - `udp[8]` is the type byte: `__le32 type` with values below 256, so the first byte is the type (messages.h:64–72).
  - `udp[12:4]` is `key_idx`, the receiver index of a data message, which equals the server's `sender_index` from its Response. That makes the S1b semantics right, apart from the endianness pitfall in finding 4.
  - The counter is at WireGuard offset 8 (`__le64`) and fits within the 44-byte snaplen.
- **`ip[6:2]&0x3fff = 0`** excludes all fragments (MF plus offset). The S2 first-fragment expression is right.
- **Keepalive after Response:** receive.c:181–186 calls `wg_packet_send_keepalive` after `begin_session`. It sends the staged packets, or else a keepalive, immediately. wireguard-go does the same. RTT case (الف) is sound in principle.
- **Server-side DF:** `udp_tunnel_xmit_skb(..., df=0, ...)` at socket.c:85–87 and `skb->ignore_df = 1`. Server→client outer packets never carry DF.
- **Padding:** `MESSAGE_PADDING_MULTIPLE = 16` (messages.h:116), with padding capped at the MTU (send.c:157). Overhead is 60 bytes on IPv4.
- **Interface counters:** `rx_frame_errors` means unallowed source or non-IP (receive.c:415–432). `tx_dropped` means staged-queue overflow beyond 128 (device.c:211–213). `tx_errors` covers no-peer or no-endpoint plus ICMP (device.c:224–231). Line numbers match.
- **Counters start at 0** and increase monotonically per keypair. Packets that fail after nonce assignment are re-staged on the old keypair, which is never reused, so they do not create gaps in an observed stream (send.c:383–413).
- **AF_PACKET versus defrag:** delivery happens in `__netif_receive_skb_core`, before `ip_rcv` and netfilter defrag, so fragments are visible. GRO runs before the tap. Fragments are never GRO-merged.
- **`wg1udp`** (ARPHRD_NONE, no `header_ops`): SOCK_DGRAM and SOCK_RAW both start at the IP header. Inner TCP GRO on the peer NAPI does not merge SYNs, so S5 is unaffected.
- **Snaplen enforcement:** `ret #N` truncates through `pskb_trim` in `packet_rcv`, which copies the clone's head, not the forwarded skb. Payload never reaches userspace once the filter is attached (finding 3 is about the window before that).
- **Python feasibility:** AF_PACKET in stdlib; `SO_ATTACH_FILTER` (26) and `SO_LOCK_FILTER` (44) as raw constants; `sock_fprog` as `struct.pack('HL', n, ctypes.addressof(buf))`. No ctypes callbacks are needed, so it is compatible with `MemoryDenyWriteExecute`.
- **Capabilities:**
  - `AmbientCapabilities` with `User=` and `NoNewPrivileges=yes` works.
  - `wg show` works as non-root with ambient `CAP_NET_ADMIN`, because `wg` has no file caps and WireGuard GET is `GENL_UNS_ADMIN_PERM`.
  - `ping` still gets `CAP_NET_RAW` under NNP: file caps ∩ old permitted. It also falls back to an ICMP datagram socket.
  - `tc -s -j ... show` needs no capability.
- **Tunnel overhead:** the `SERVER_TUNNEL` arithmetic for wg21/22 (1400+60 > 1420, so 1360 is suggested) is correct.
- **Volume estimate:** about 35k `peer_minute` rows per day at about 200 B is about 7 MB/day, and about 100 MB over 14 days.
- **Fragment lower bound:** `T_up_safe = F − 60` is never above the true safe value, given no reassembling middlebox. See finding 10 for the caveat.
- **Handshake staleness:** "a handshake proves only that small (92/148-byte) packets get through" is correct.
- **NAT-expiry signature:** the per-peer tx counter grows by 148 bytes per server Initiation (socket.c:183), as the docs say.
