"""WG-NQMO engine tests (PHASE 2: core, collectors, capture layer, storage).

Family guards (CLAUDE.md «قاعده‌ی گاردِ خانوادگی») — each pins a whole class of
mistake, not one instance:
  NqmoNoMutationTests      no process launch outside nqmo.runner; allowlist is show/get only
  NqmoDeployUnitTests      the shipped unit grants nothing, couples to nothing, and every key is live
  NqmoWorkerHealthTests    no worker sleeps longer than its heartbeat stays fresh
  NqmoCaptureSafetyTests   packet sockets: proto 0 → filter → lock → bind; never send
  NqmoBpfSemanticsTests    committed bytecode == intended predicate (cBPF VM)
  NqmoNoSecretTests        no key material reaches the DB or state.json
  NqmoNoInnerDestTests     S5's inner destination is never stored
  NqmoLossAccountingTests  window accounting == brute-force reference (random)
"""
import ast
import configparser
import json
import os
import queue
import random
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from nqmo import config, runner, sched, store as storemod, export  # noqa: E402
from nqmo import aggregate, ctl, engine  # noqa: E402
from nqmo.collect import bpf, capture, kernel, meta, ring, tcstats, wgparse  # noqa: E402

PKG = os.path.join(ROOT, "nqmo")
PORT = 53953

# Host-independent runner checks: runner._iface consults SYS_NET when it exists.
# Every test sees the same fake sysfs, so a result never depends on whether the
# host has /sys (macOS) or happens to lack wg1udp (a plain Linux box) — the
# OrbStack lab found four tests that passed on the Mac only by accident.
FAKE_IFACES = ("eth0", "wg1udp", "ib_wg1udp")
_SAVED_SYS_NET = None


def setUpModule():
    global _SAVED_SYS_NET
    d = tempfile.mkdtemp(prefix="nqmo-sysnet-")
    for name in FAKE_IFACES:
        os.mkdir(os.path.join(d, name))
    _SAVED_SYS_NET, runner.SYS_NET = runner.SYS_NET, d


def tearDownModule():
    d = runner.SYS_NET
    runner.SYS_NET = _SAVED_SYS_NET
    shutil.rmtree(d, ignore_errors=True)



def read(path, mode="r"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        return f.read()


def pkg_files():
    for dp, dn, fn in os.walk(PKG):
        dn[:] = [d for d in dn if d != "__pycache__"]
        for f in fn:
            if f.endswith(".py"):
                yield os.path.join(dp, f)


def pubkey(i):
    raw = bytes([i]) * 31 + b"\x00"
    import base64
    return base64.b64encode(raw).decode()


# ---------------------------------------------------------------- packet craft
def ipv4(payload, proto, src="198.51.100.7", dst="203.0.113.1", ident=1,
         df=False, mf=False, off=0, tot_len=None, ihl=5):
    flags = (0x4000 if df else 0) | (0x2000 if mf else 0) | (off // 8)
    tl = tot_len if tot_len is not None else 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, tl, ident, flags, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    if ihl > 5:
        hdr += b"\x00" * ((ihl - 5) * 4)
    return hdr + payload


def udp(sport, dport, payload, ulen=None):
    return struct.pack("!HHHH", sport, dport, ulen or 8 + len(payload), 0) + payload


def wg_init(sender=b"\x11\x22\x33\x44"):
    return b"\x01\x00\x00\x00" + sender + b"\x00" * 140          # 148 bytes


def wg_resp(sender=b"\xaa\xbb\xcc\xdd", receiver=b"\x11\x22\x33\x44"):
    return b"\x02\x00\x00\x00" + sender + receiver + b"\x00" * 80  # 92 bytes


def wg_cookie(receiver=b"\x11\x22\x33\x44"):
    return b"\x03\x00\x00\x00" + receiver + b"\x00" * 56           # 64 bytes


def wg_data(receiver=b"\xaa\xbb\xcc\xdd", counter=0, body=16):
    return b"\x04\x00\x00\x00" + receiver + struct.pack("<Q", counter) + b"\x00" * body


def wg_frame(msg, sport=51000, dport=PORT, src="198.51.100.7", dst="203.0.113.1", **kw):
    return ipv4(udp(sport, dport, msg), 17, src=src, dst=dst, **kw)


def syn(src="10.66.0.5", dst="203.0.113.77", dport=443, mss=1352, ack=False):
    opts = struct.pack("!BBH", 2, 4, mss) + b"\x01\x01\x04\x02"
    doff = (20 + len(opts)) // 4
    flags = 0x12 if ack else 0x02
    tcp = struct.pack("!HHIIBBHHH", 40000, dport, 1, 0, doff << 4, flags, 65535, 0, 0) + opts
    return ipv4(tcp, 6, src=src, dst=dst)


# ---------------------------------------------------------------- cBPF VM
def bpf_run(insns, pkt):
    """Minimal classic-BPF interpreter (the subset libpcap emits for these
    expressions). Out-of-bounds loads return 0 = drop, as in the kernel."""
    A = X = 0
    pc = 0
    n = len(insns)
    while pc < n:
        code, jt, jf, k = insns[pc]
        cls = code & 0x07
        if cls == 0x06:                                   # RET
            return k if (code & 0x18) == 0x00 else A
        if cls in (0x00, 0x01):                           # LD / LDX
            size = code & 0x18
            mode = code & 0xE0
            if cls == 0x01 and mode == 0xA0:              # LDX MSH
                if k >= len(pkt):
                    return 0
                X = (pkt[k] & 0x0F) * 4
                pc += 1
                continue
            if mode in (0x20, 0x40):
                off = k + (X if mode == 0x40 else 0)
                width = {0x00: 4, 0x08: 2, 0x10: 1}[size]
                if off + width > len(pkt):
                    return 0
                val = int.from_bytes(pkt[off:off + width], "big")
            elif mode == 0x00:
                val = k
            else:
                raise AssertionError("unsupported LD mode %#x" % code)
            if cls == 0x00:
                A = val
            else:
                X = val
            pc += 1
            continue
        if cls == 0x04:                                   # ALU
            op = code & 0xF0
            src = X if code & 0x08 else k
            if op == 0x50:
                A &= src
            elif op == 0x40:
                A |= src
            elif op == 0x00:
                A = (A + src) & 0xFFFFFFFF
            else:
                raise AssertionError("unsupported ALU %#x" % code)
            pc += 1
            continue
        if cls == 0x05:                                   # JMP
            op = code & 0xF0
            src = X if code & 0x08 else k
            if op == 0x00:
                pc += 1 + k
                continue
            cond = {0x10: A == src, 0x20: A > src, 0x30: A >= src,
                    0x40: bool(A & src)}[op]
            pc += 1 + (jt if cond else jf)
            continue
        if cls == 0x07:                                   # MISC
            if code & 0xF8 == 0x00:
                X = A
            else:
                A = X
            pc += 1
            continue
        raise AssertionError("unsupported class %#x" % code)
    return 0


class NqmoBpfSemanticsTests(unittest.TestCase):
    def accepts(self, prog, pkt):
        r = bpf_run(bpf.PROGRAMS[prog]["insns"], pkt)
        if r:
            self.assertEqual(r, bpf.PROGRAMS[prog]["snaplen"])
        return bool(r)

    def test_s1_handshake_family(self):
        p = "S1_HANDSHAKE"
        self.assertTrue(self.accepts(p, wg_frame(wg_init())))
        self.assertTrue(self.accepts(p, wg_frame(wg_resp(), sport=PORT, dport=51000)))
        self.assertTrue(self.accepts(p, wg_frame(wg_cookie(), sport=PORT, dport=51000)))
        self.assertTrue(self.accepts(p, wg_frame(wg_data(counter=0))))
        self.assertFalse(self.accepts(p, wg_frame(wg_data(counter=1))))
        self.assertFalse(self.accepts(p, wg_frame(wg_data(counter=1 << 32))))
        self.assertFalse(self.accepts(p, wg_frame(wg_init(), dport=53954)))
        self.assertFalse(self.accepts(p, wg_frame(wg_init()[:-4])))         # wrong length
        self.assertFalse(self.accepts(p, wg_frame(wg_init(), mf=True)))     # fragment
        self.assertFalse(self.accepts(p, wg_frame(wg_init(), ihl=6)))       # IP options

    def test_s2_s3_fragments(self):
        first = wg_frame(wg_data(counter=9, body=1300), mf=True)
        self.assertTrue(self.accepts("S2_FIRST_FRAG", first))
        self.assertFalse(self.accepts("S2_FIRST_FRAG", wg_frame(wg_data(counter=9))))
        tail = ipv4(b"\x00" * 100, 17, off=1400)
        self.assertTrue(self.accepts("S3_TAIL_FRAG", tail))
        self.assertFalse(self.accepts("S3_TAIL_FRAG", first))
        self.assertFalse(self.accepts("S3_TAIL_FRAG", ipv4(b"\x00" * 100, 6, off=1400)))

    def test_s4_data_only(self):
        self.assertTrue(self.accepts("S4_DATA", wg_frame(wg_data(counter=77))))
        self.assertTrue(self.accepts("S4_DATA", wg_frame(wg_data(counter=77, body=1300), mf=True)))
        self.assertFalse(self.accepts("S4_DATA", wg_frame(wg_init())))
        self.assertFalse(self.accepts("S4_DATA", wg_frame(wg_data(), sport=PORT, dport=51000)))

    def test_s5_syn_not_synack(self):
        self.assertTrue(self.accepts("S5_SYN", syn()))
        self.assertFalse(self.accepts("S5_SYN", syn(ack=True)))

    def test_every_accept_returns_snaplen(self):
        for name, p in bpf.PROGRAMS.items():
            rets = {k for code, _a, _b, k in p["insns"] if code == 0x06}
            self.assertEqual(rets, {0, p["snaplen"]}, name)
            self.assertLessEqual(p["snaplen"], 60, name)

    def test_programs_are_offset_for_raw_ip_not_ethernet(self):
        # A DLT_EN10MB program starts with "ldh [12]" (ethertype). Ours must
        # read the IP version nibble at byte 0.
        for name, p in bpf.PROGRAMS.items():
            self.assertEqual(p["insns"][0], (0x30, 0, 0, 0), name)

    @unittest.skipUnless(shutil.which("tcpdump"), "tcpdump not installed")
    def test_committed_bytecode_is_fresh(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "gen_nqmo_bpf.py"),
                            "--check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


# ---------------------------------------------------------------- mutation guards
MUTATING = ("set", "add", "del", "delete", "replace", "change", "flush", "up",
            "down", "append", "insert", "-A", "-I", "-D", "-F", "syncconf",
            "addconf", "setconf")


class NqmoNoMutationTests(unittest.TestCase):
    def test_subprocess_only_in_runner(self):
        for path in pkg_files():
            tree = ast.parse(read(path))
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names.add(node.module.split(".")[0])
                elif isinstance(node, ast.Attribute) and node.attr in (
                        "system", "popen", "execv", "execve", "spawnv", "fork"):
                    if isinstance(node.value, ast.Name) and node.value.id == "os":
                        self.fail("%s uses os.%s" % (path, node.attr))
            if os.path.basename(path) != "runner.py":
                self.assertNotIn("subprocess", names, path)

    def test_allowlist_has_only_show_get_verbs(self):
        for name, preds in runner.TEMPLATES.items():
            for word in MUTATING:
                if name == "ping_probe" and word in ("-I",):
                    continue                     # ping -I <iface> is bind, not insert
                ok = any(getattr(p, "__closure__", None) and
                         any(c.cell_contents == word or
                             (isinstance(c.cell_contents, tuple) and word in c.cell_contents)
                             for c in p.__closure__) for p in preds)
                self.assertFalse(ok, "%s template contains %r" % (name, word))

    def test_mutations_refused(self):
        bad = [
            ["wg", "show", "wg1udp", "dump"],                  # secrets — not allowed at all
            ["wg", "set", "wg1udp", "peer", "x", "remove"],
            ["awg", "show", "awg1"],
            ["tc", "qdisc", "del", "dev", "wg1udp", "root"],
            ["tc", "-s", "-j", "qdisc", "show", "dev", "wg1udp", "&&", "reboot"],
            ["ip", "link", "set", "wg1udp", "mtu", "1300"],
            ["ip", "-j", "route", "get", "1.2.3.4", "from", "5.6.7.8", "dev", "x"],
            ["ip", "-j", "route", "get", "1.2.3.4; rm -rf /"],
            ["iptables", "-A", "FORWARD"],
            ["nft", "add", "rule"],
            ["ping", "-4", "-n", "-q", "-M", "do", "-s", "1500", "-c", "1", "-W", "1",
             "-I", "wg1udp", "10.66.0.5"],                     # size out of range
            ["sh", "-c", "tc -s -j qdisc show dev wg1udp"],
            [], "tc -s -j qdisc show dev wg1udp",
        ]
        for argv in bad:
            with self.assertRaises(runner.NotAllowed, msg=repr(argv)):
                runner.match(argv)

    def test_ping_has_no_template_before_its_gates(self):
        with self.assertRaises(runner.NotAllowed):
            runner.match(["ping", "-4", "-n", "-q", "-M", "do", "-s", "1300", "-c", "1",
                          "-W", "1", "-I", "wg1udp", "10.66.0.5"])

    def test_reads_allowed(self):
        ok = [
            ["tc", "-s", "-j", "class", "show", "dev", "wg1udp"],
            ["ip", "-j", "-d", "link", "show"],
            ["ip", "-j", "nexthop", "show"],
            ["ip", "-j", "route", "get", "1.2.3.4"],
            ["ip", "-j", "route", "get", "1.2.3.4", "from", "5.6.7.8", "mark", "0x77"],
            ["ip", "-j", "route", "get", "1.2.3.4", "mark", "0x77", "from", "5.6.7.8"],
        ]
        for argv in ok:
            runner.match(argv)

    def test_runner_never_uses_shell(self):
        src = read(os.path.join(PKG, "runner.py"))
        self.assertIn("shell=False", src)
        self.assertNotIn("shell=True", src)


class NqmoDeployUnitTests(unittest.TestCase):
    """deploy/wg-nqmo.service: myserver is never rebooted, so its boot behaviour
    can only be right by construction. A key in the wrong section is not an
    error, systemd drops it with a warning nobody reads — the design doc's own
    StartLimitIntervalSec sat in [Service] until 4 Nov and would have left the
    restart loop unbounded."""
    UNIT = os.path.join(ROOT, "deploy", "wg-nqmo.service")
    CONFIG = os.path.join(ROOT, "deploy", "wg-nqmo.config.json")
    DROP_IN = os.path.join(ROOT, "deploy", "wg-nqmo-capture.conf")
    CAPTURE_CONFIG = os.path.join(ROOT, "deploy", "wg-nqmo.capture.config.json")
    DOC = os.path.join(ROOT, "docs", "nqmo", "01-TO-BE-ARCHITECTURE.md")
    # These are [Unit] keys on systemd ≥ 230; only the pre-230 spellings
    # (StartLimitInterval=) are still accepted under [Service].
    UNIT_ONLY = {"StartLimitIntervalSec", "StartLimitBurst", "StartLimitAction"}

    @staticmethod
    def parse(text):
        c = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
        c.optionxform = str
        c.read_string(text)
        return {sec: dict(c.items(sec)) for sec in c.sections()}

    def setUp(self):
        self.text = read(self.UNIT)
        self.unit = self.parse(self.text)
        self.svc = self.unit["Service"]

    def test_grants_no_capability_and_no_way_to_get_one(self):
        self.assertEqual(self.svc["CapabilityBoundingSet"], "")
        self.assertEqual(self.svc["AmbientCapabilities"], "")
        self.assertEqual(self.svc["NoNewPrivileges"], "yes")
        self.assertEqual((self.svc["User"], self.svc["Group"]), ("wg-nqmo", "wg-nqmo"))
        live = [ln for ln in self.text.splitlines() if not ln.startswith("#")]
        self.assertFalse([ln for ln in live if "CAP_" in ln], "capability in the base unit")
        self.assertFalse([ln for ln in live if "AF_PACKET" in ln], "AF_PACKET is D4's drop-in")

    def test_every_command_runs_inside_the_sandbox(self):
        # «+», «!» and «!!» run a command outside User= and the sandbox.
        for key, val in self.svc.items():
            if key.startswith("Exec"):
                self.assertFalse(val.lstrip("-@:").startswith(("+", "!")), key)
        self.assertFalse([k for k in self.svc if k in ("ExecStartPre", "ExecStartPost",
                                                       "ExecStopPost", "PermissionsStartOnly",
                                                       "ReadWritePaths", "BindPaths")])

    def test_couples_to_nothing(self):
        for key in ("Requires", "Requisite", "BindsTo", "PartOf", "Wants", "Before",
                    "OnFailure", "Conflicts"):
            self.assertNotIn(key, self.unit["Unit"], key)
        self.assertEqual(self.unit["Unit"]["After"], "network-online.target")
        self.assertEqual(self.unit["Install"], {"WantedBy": "multi-user.target"})

    def test_paths_agree_with_engine_and_panel(self):
        from nqmo.__main__ import DEFAULT_CONFIG
        self.assertEqual(self.svc["ExecStart"],
                         "/usr/bin/python3 -I /opt/wg-nqmo/wg_nqmo.pyz --run")
        self.assertEqual(os.path.dirname(DEFAULT_CONFIG),
                         "/etc/" + self.svc["ConfigurationDirectory"])
        state = "/var/lib/" + self.svc["StateDirectory"]
        paths = config.validate({})["paths"]
        for key in ("db", "state", "secret", "asn_dir"):
            self.assertEqual(os.path.dirname(paths[key]), state, key)
        self.assertEqual(os.path.dirname(paths["ctl"]), "/run/" + self.svc["RuntimeDirectory"])
        app = read(os.path.join(ROOT, "wgpanel", "app.py"))
        for const, want in (("NQMO_GROUP", self.svc["Group"]),
                            ("NQMO_STATE_PATH", paths["state"]),
                            ("NQMO_CTL_PATH", paths["ctl"])):
            self.assertIn('%s = "%s"' % (const, want), app)

    def test_shipped_config_is_read_only_observation(self):
        cfg = config.load(self.CONFIG)
        self.assertEqual(cfg["mode"], config.MODES[0])
        self.assertEqual(cfg["mode"], "OBSERVATION_ONLY")
        self.assertIs(cfg["active_probes"], False)
        self.assertIs(cfg["capture"]["enabled"], False)
        self.assertEqual({k: v for k, v in cfg.items() if k != "mode"},
                         {k: v for k, v in config.validate({}).items() if k != "mode"},
                         "the shipped file may only state defaults out loud")

    def test_capture_drop_in_grants_only_raw_sockets(self):
        drop = self.parse(read(self.DROP_IN))
        self.assertEqual(drop, {"Service": {
            "CapabilityBoundingSet": "CAP_NET_RAW",
            "AmbientCapabilities": "CAP_NET_RAW",
            "RestrictAddressFamilies": self.svc["RestrictAddressFamilies"] + " AF_PACKET"}})
        live = [ln for ln in read(self.DROP_IN).splitlines() if not ln.startswith("#")]
        self.assertFalse([ln for ln in live if "NET_ADMIN" in ln or "SYS_" in ln])

    def test_capture_config_changes_only_the_capture_settings(self):
        base, cap = config.load(self.CONFIG), config.load(self.CAPTURE_CONFIG)
        self.assertIs(cap["capture"]["enabled"], True)
        self.assertEqual(cap["mode"], "OBSERVATION_ONLY")
        self.assertIs(cap["active_probes"], False)
        cap["capture"]["enabled"] = False
        cap["capture"]["ring_blocks"] = base["capture"]["ring_blocks"]
        # §29.159: the S4 sampling threshold follows the raised CPUQuota (the
        # resources drop-in); it must stay below that quota or sampling never kicks in
        self.assertEqual(cap["capture"]["s4_cpu_pct_max"], 30.0)
        cap["capture"]["s4_cpu_pct_max"] = base["capture"]["s4_cpu_pct_max"]
        self.assertEqual(cap, base, "the D4 config may set capture.enabled, ring_blocks and "
                                    "s4_cpu_pct_max, nothing else")

    def test_resources_drop_in_only_raises_the_three_limits(self):
        """§29.159: deploy/wg-nqmo-resources.conf raises CPUQuota and the two memory
        limits and nothing else; the sampling threshold in the capture config stays
        below the quota, and MemoryHigh stays below MemoryMax."""
        drop = self.parse(read(os.path.join(ROOT, "deploy", "wg-nqmo-resources.conf")))
        self.assertEqual(set(drop), {"Service"})
        self.assertEqual(set(drop["Service"]), {"CPUQuota", "MemoryHigh", "MemoryMax"})
        quota = int(drop["Service"]["CPUQuota"].rstrip("%"))
        high = int(drop["Service"]["MemoryHigh"].rstrip("M"))
        mx = int(drop["Service"]["MemoryMax"].rstrip("M"))
        self.assertGreater(quota, int(self.svc["CPUQuota"].rstrip("%")))
        self.assertGreater(high, int(self.svc["MemoryHigh"].rstrip("M")))
        self.assertLess(high, mx)
        cap = config.load(self.CAPTURE_CONFIG)["capture"]
        self.assertLess(cap["s4_cpu_pct_max"], quota)
        # §29.162: a window close costs ~2 s of CPU; any quota under 150% throttles
        # the main thread for the whole flush (measured: 3.0 s of a 4.2 s flush at
        # 40%, and 25.8 s with S4 traffic), so it must never drift back down
        self.assertGreaterEqual(quota, 150, "a window flush must not be quota-bound")

    def test_capture_ring_fits_well_inside_the_memory_limit(self):
        cap = config.load(self.CAPTURE_CONFIG)["capture"]
        high = self.parse(read(self.UNIT))["Service"]["MemoryHigh"]
        self.assertTrue(high.endswith("M"), high)
        ring_mb = cap["ring_block_kb"] * cap["ring_blocks"] / 1024
        self.assertLessEqual(ring_mb * 4, int(high[:-1]),
                             "the ring may take at most a quarter of MemoryHigh")

    def test_design_doc_capture_block_is_this_drop_in(self):
        blocks = re.findall(r"```ini\n(\[Service\].*?)```", read(self.DOC), re.S)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(self.parse(blocks[0]), self.parse(read(self.DROP_IN)))

    def test_notify_and_watchdog_are_actually_sent(self):
        src = read(os.path.join(PKG, "engine.py"))
        self.assertEqual(self.svc["Type"], "notify")
        self.assertIn('sd_notify("READY=1")', src)
        self.assertIn('sd_notify("WATCHDOG=1")', src)
        self.assertGreater(int(self.svc["WatchdogSec"]), 60, "must outlive one export cycle")

    def test_design_doc_block_is_this_unit(self):
        block = re.search(r"```ini\n(\[Unit\].*?)```", read(self.DOC), re.S).group(1)
        doc = self.parse(block)
        self.assertEqual(doc, self.unit, "docs/nqmo/01 §۶ and deploy/wg-nqmo.service diverged")

    def test_no_unit_in_the_repo_has_a_dead_start_limit_key(self):
        units = [os.path.join(ROOT, "wg-panel.service"), self.DOC]
        d = os.path.join(ROOT, "deploy")
        units += [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.endswith(".service")]
        seen = 0
        for path in units:
            text = read(path)
            if path == self.DOC:
                text = re.search(r"```ini\n(\[Unit\].*?)```", text, re.S).group(1)
            for sec, keys in self.parse(text).items():
                if sec == "Unit":
                    seen += len(self.UNIT_ONLY & set(keys))
                else:
                    self.assertFalse(self.UNIT_ONLY & set(keys), "%s [%s]" % (path, sec))
        self.assertGreaterEqual(seen, 2, "scanner stopped seeing the keys it guards")

    def test_engine_install_files_are_published_together(self):
        """1.4.0 publishes the engine. The unit, both drop-ins, both configs and
        the review archive travel with it: a unit without its config (or a
        capture drop-in without the config that enables capture) is an install
        that fails on the first start."""
        path = os.path.join(ROOT, "publish", "filelist.txt")
        if not os.path.exists(path):
            self.skipTest("public tree")
        lines = read(path).splitlines()
        listed = {ln.split("#", 1)[0].strip() for ln in lines if ln and ln[0] not in "#-"}
        for need in ("nqmo/", "tools/build_nqmo_pyz.py", "tools/gen_nqmo_bpf.py",
                     "deploy/wg-nqmo.service", "deploy/wg-nqmo-capture.conf",
                     "deploy/wg-nqmo-resources.conf", "deploy/wg-nqmo.config.json",
                     "deploy/wg-nqmo.capture.config.json", "deploy/wg-nqmo-review.sh",
                     "deploy/wg-nqmo-review.service", "deploy/wg-nqmo-review.timer"):
            self.assertIn(need, listed, "engine file missing from the public filelist")
        dropped = [ln for ln in lines if ln.startswith("-") and "nqmo" in ln]
        self.assertEqual(dropped, ["-docs/nqmo/00-PHASE0-AUDIT.md"],
                         "only the phase-0 audit (a topology map) stays private")


class NqmoCaptureSafetyTests(unittest.TestCase):
    SEND = ("send", "sendto", "sendmsg", "sendall", "sendfile")

    def test_capture_modules_never_send(self):
        for fn in ("capture.py", "ring.py"):
            tree = ast.parse(read(os.path.join(PKG, "collect", fn)))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in self.SEND:
                    self.fail("%s calls .%s" % (fn, node.attr))

    class FakeSock:
        def __init__(self, log, *a):
            self.log = log
            log.append(("socket",) + a)

        def setsockopt(self, level, opt, val):
            self.log.append(("setsockopt", opt))

        def bind(self, addr):
            self.log.append(("bind", addr))

        def fileno(self):
            return 99

        def close(self):
            self.log.append(("close",))

    def fake_mod(self, log):
        test = self

        class M:
            AF_PACKET = 17
            SOCK_DGRAM = 2
            SOL_SOCKET = 1
            SO_RCVBUF = 8

            @staticmethod
            def socket(*a):
                return test.FakeSock(log, *a)
        return M

    def test_open_tap_order(self):
        log = []
        capture.open_tap("eth0", capture.ETH_P_ALL, "S1_HANDSHAKE", sock_mod=self.fake_mod(log))
        self.assertEqual(log[0], ("socket", 17, 2, 0))          # protocol 0
        ops = [e[1] if e[0] == "setsockopt" else e[0] for e in log[1:]]
        self.assertEqual(ops[:3], [capture.SO_ATTACH_FILTER, capture.SO_LOCK_FILTER,
                                   capture.SO_TIMESTAMPNS])
        self.assertEqual(log[-1], ("bind", ("eth0", capture.ETH_P_ALL)))

    def test_ring_order(self):
        log = []

        class FakeMmap:
            MAP_SHARED = 1
            PROT_READ = 1
            PROT_WRITE = 2

            @staticmethod
            def mmap(*a):
                log.append(("mmap",))
                return bytearray(16)
        ring.Ring("eth0", 16, 2, sock_mod=self.fake_mod(log), mmap_mod=FakeMmap)
        self.assertEqual(log[0], ("socket", 17, 2, 0))
        seq = [e[1] if e[0] == "setsockopt" else e[0] for e in log[1:]]
        self.assertEqual(seq, [capture.SO_ATTACH_FILTER, capture.SO_LOCK_FILTER,
                               ring.PACKET_VERSION, ring.PACKET_RX_RING, "mmap", "bind"])
        self.assertEqual(log[-1], ("bind", ("eth0", capture.ETH_P_IP)))

    def test_streams_bind_protocols(self):
        self.assertEqual(capture.STREAMS["S1"][1], capture.ETH_P_ALL)   # sees outgoing
        for s in ("S2", "S3", "S5"):
            self.assertEqual(capture.STREAMS[s][1], capture.ETH_P_IP)

    def test_port_mismatch_refuses(self):
        with self.assertRaises(capture.CaptureError):
            capture.check_port(PORT + 1)
        capture.check_port(PORT)

    def test_fprog_layout(self):
        import ctypes
        fp, keep = capture.fprog_bytes(bpf.PROGRAMS["S3_TAIL_FRAG"]["insns"])
        self.assertEqual(len(fp), 16)                        # x86_64 sock_fprog
        n, ptr = struct.unpack("HL", fp)
        self.assertEqual(n, len(bpf.PROGRAMS["S3_TAIL_FRAG"]["insns"]))
        self.assertEqual(ptr, ctypes.addressof(keep))
        self.assertEqual(len(keep), 8 * n)


# ---------------------------------------------------------------- parsers
class NqmoParserTests(unittest.TestCase):
    def test_wg_messages(self):
        m = wgparse.parse_wg(wg_frame(wg_init(b"ABCD")))
        self.assertEqual((m["type"], m["sender"]), (1, b"ABCD"))
        m = wgparse.parse_wg(wg_frame(wg_resp(b"SSSS", b"RRRR")))
        self.assertEqual((m["sender"], m["receiver"]), (b"SSSS", b"RRRR"))
        m = wgparse.parse_wg(wg_frame(wg_data(b"QQQQ", 2 ** 40 + 3)))
        self.assertEqual((m["receiver"], m["counter"]), (b"QQQQ", 2 ** 40 + 3))
        m = wgparse.parse_wg(wg_frame(wg_data(), df=True)[:44])         # snaplen-truncated
        self.assertTrue(m["ip"]["df"])

    def test_fragments(self):
        f = wgparse.parse_first_frag(wg_frame(wg_data(body=1400), mf=True, tot_len=1420)[:28])
        self.assertEqual(f["F"], 1420)
        self.assertEqual(f["O"], 20 + 8 + 16 + 1400)       # IP + UDP + data hdr + body
        t = wgparse.parse_tail_frag(ipv4(b"\x00" * 80, 17, off=1400, ident=7))
        self.assertEqual((t["off"], t["len"], t["mf"], t["id"]), (1400, 80, False, 7))

    def test_syn_returns_only_src_and_mss(self):
        r = wgparse.parse_syn(syn(mss=1300))
        self.assertEqual(r, ("10.66.0.5", 1300))
        self.assertIsNone(wgparse.parse_syn(syn(ack=True)))

    def test_fuzz_never_raises(self):
        rnd = random.Random(7)
        seeds = [wg_frame(wg_init()), wg_frame(wg_data()), syn(),
                 ipv4(b"\x00" * 30, 17, off=8)]
        for _ in range(4000):
            b = bytearray(rnd.choice(seeds)[:rnd.randint(0, 70)])
            for _j in range(rnd.randint(0, 4)):
                if b:
                    b[rnd.randrange(len(b))] = rnd.randrange(256)
            for fn in (wgparse.parse_wg, wgparse.parse_first_frag,
                       wgparse.parse_tail_frag, wgparse.parse_syn):
                fn(bytes(b))

    def test_snmp_softnet_cpu(self):
        snmp = ("Ip: Forwarding FragCreates ReasmFails\nIp: 1 59033728 38921\n"
                "Udp: InDatagrams RcvbufErrors\nUdp: 5 19378\n")
        c = kernel.parse_snmp(snmp)
        self.assertEqual(c["Ip.FragCreates"], 59033728)
        self.assertEqual(c["Udp.RcvbufErrors"], 19378)
        self.assertEqual(kernel.parse_softnet("0000a 0000000f 00000002 0\n1 00000001 0 0\n"),
                         (16, 2))
        a = kernel.parse_proc_stat_cpu("cpu  100 0 100 800 0 0 0 0\n")
        b = kernel.parse_proc_stat_cpu("cpu  150 0 150 850 0 0 50 0\n")
        self.assertEqual(kernel.cpu_pct(a, b), (75.0, 25.0))

    def test_nic_drop_stats_exclude_rx_dropped(self):
        self.assertNotIn("rx_dropped", kernel.NIC_DROP_STATS)

    def test_tc_parsing(self):
        classes = json.dumps([{"class": "htb", "handle": "1:3",
                               "stats": {"drops": 5, "overlimits": 9}}])
        filters = json.dumps([
            {"options": {"flowid": "1:3", "match": {"value": "0a420005",
                                                     "mask": "ffffffff", "off": 16}}},
            {"options": {"flowid": "1:4", "match": [
                {"value": "0a420006", "mask": "ffffffff", "off": 16},
                {"value": "0a420007", "mask": "ffffffff", "off": 16}]}},
        ])
        m = tcstats.parse_filters(filters, "dst")
        self.assertEqual(m, {"1:3": "10.66.0.5"})          # ambiguous 1:4 dropped
        self.assertEqual(tcstats.per_ip(tcstats.parse_classes(classes), m),
                         {"10.66.0.5": {"bytes": None, "packets": None, "drops": 5,
                                        "overlimits": 9, "backlog": None}})
        self.assertEqual(tcstats.parse_filters("garbage", "dst"), {})

    def test_ring_block_parse_bounded(self):
        mem = bytearray(4096)
        frame = wg_frame(wg_data(counter=5))[:44]
        hdr = ring._PKT.size + 4 + 8
        first = 48
        struct.pack_into("=IIIIIIQ", mem, 0, 3, 0, ring.TP_STATUS_USER, 1, first, 4096, 1)
        struct.pack_into("=IIIIIIHH", mem, first, 0, 10, 500000000, len(frame), 200, 0,
                         hdr, hdr)
        mem[first + hdr:first + hdr + len(frame)] = frame
        items = list(ring.iter_block(mem, 0))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][:2], (10.5, 200))
        self.assertEqual(items[0][2], frame)
        # claim far more packets than fit: must stop, not overrun
        struct.pack_into("=IIIIIIQ", mem, 0, 3, 0, ring.TP_STATUS_USER, 1000, first, 135, 1)
        struct.pack_into("=IIIIIIHH", mem, first, 64, 10, 0, len(frame), 200, 0, hdr, hdr)
        self.assertEqual(len(list(ring.iter_block(mem, 0))), 1)   # 2nd header would overrun blk_len
        ring.release_block(mem, 0)
        self.assertEqual(list(ring.iter_block(mem, 0)), [])


# ---------------------------------------------------------------- meta / secrets
def meta_doc(peers=None, **over):
    doc = {
        "generated_at": 1000.0, "client_mtu": 1392,
        "wg1udp": {"mtu": 1392, "fwmark": None, "local_ip": "203.0.113.1"},
        "peers": peers if peers is not None else {
            pubkey(1): {"iface": "wg1udp", "name": "alice", "enabled": True,
                        "tunnel_ip": "10.66.0.5", "c_mtu": None, "rate_mbit": None,
                        "endpoint": "198.51.100.7:51000", "latest_handshake": 990,
                        "rx_bytes": 1000, "tx_bytes": 2000}},
        "egress": {"awg1": {"kind": "awg", "mtu": 1420, "endpoint_dev": "eth0",
                            "awg_s4": 0, "hs_age": 10, "rx_delta": 5, "health": "healthy",
                            "svc_ok": True, "svc_latency_ms": 120.0, "mtr_loss": 0.0,
                            "mtr_rtt": 40.0, "warp_ms": None, "ecmp_member": True,
                            "ts": 990}},
    }
    doc.update(over)
    return doc


class NqmoMetaTests(unittest.TestCase):
    def test_valid(self):
        m = meta.parse(json.dumps(meta_doc()), read_at=1010)
        pub = pubkey(1)
        self.assertEqual(m.by_endpoint[("198.51.100.7", 51000)], pub)
        self.assertEqual(m.by_tunnel_ip["10.66.0.5"], pub)
        self.assertEqual(m.effective_mtu(pub), 1392)
        self.assertEqual(m.age(1010), 10)

    def test_secret_shaped_content_is_rejected_anywhere(self):
        for key in ("psk", "preshared_key", "private_key", "PrivateKey", "secret",
                    "bot_token", "password"):
            d = meta_doc()
            d["peers"][pubkey(1)][key] = "x"
            with self.assertRaises(meta.MetaError, msg=key):
                meta.parse(json.dumps(d))
            d = meta_doc()
            d["egress"]["awg1"][key] = "x"
            with self.assertRaises(meta.MetaError, msg=key):
                meta.parse(json.dumps(d))
        d = meta_doc()
        d["peers"][pubkey(1)]["name"] = pubkey(9)            # key-shaped value
        with self.assertRaises(meta.MetaError):
            meta.parse(json.dumps(d))

    def test_strict_shape(self):
        d = meta_doc()
        d["peers"][pubkey(1)]["extra"] = 1
        with self.assertRaises(meta.MetaError):
            meta.parse(json.dumps(d))
        d = meta_doc()
        d["peers"][pubkey(1)]["rx_bytes"] = True
        with self.assertRaises(meta.MetaError):
            meta.parse(json.dumps(d))
        with self.assertRaises(meta.MetaError):
            meta.parse(json.dumps(meta_doc(surprise=1)))
        d = meta_doc()
        d["peers"] = {"not-a-key": d["peers"][pubkey(1)]}
        with self.assertRaises(meta.MetaError):
            meta.parse(json.dumps(d))


# ---------------------------------------------------------------- loss accounting
def reference_loss(seq, B=aggregate.BITMAP):
    """Brute force with WireGuard's acceptance rule: a counter up to
    COUNTER_WINDOW (= B − 1) behind the highest is still accepted."""
    first = seq[0]
    got = set()
    highest = first
    late = dup = 0
    for c in seq:
        if c > highest:
            highest = c
            got.add(c)
        elif highest - c >= B or c < first:
            late += 1
        elif c in got:
            dup += 1
        else:
            got.add(c)
    ok = sum(1 for x in range(first, highest + 1) if x in got)
    return ok, (highest - first + 1) - ok, late, dup


class NqmoLossAccountingTests(unittest.TestCase):
    def run_track(self, seq):
        t = aggregate.KeypairTrack(seq[0], 0.0)
        for c in seq[1:]:
            self.assertTrue(t.add(c, 0.0))
        t.finalize()
        return t.ok, t.lost, t.late, t.dup

    def test_in_order(self):
        self.assertEqual(self.run_track(list(range(5000))), (5000, 0, 0, 0))

    def test_wireguard_acceptance_edge(self):
        W = aggregate.COUNTER_WINDOW
        t = aggregate.KeypairTrack(0, 0.0)
        t.add(W + 5, 0.0)
        t.add(5, 0.0)            # exactly W behind: WireGuard accepts it
        t.add(4, 0.0)            # W+1 behind: rejected ⇒ late
        self.assertEqual((t.reorder, t.late), (1, 1))

    def test_random_against_reference(self):
        rnd = random.Random(11)
        W = aggregate.COUNTER_WINDOW
        for trial in range(25):
            n = rnd.randint(50, 30000)
            seq = [c for c in range(n) if rnd.random() > rnd.choice((0, 0.001, 0.02, 0.2))]
            if not seq:
                continue
            for _ in range(rnd.randint(0, 50)):                  # reorder within W
                i = rnd.randrange(len(seq))
                j = min(len(seq) - 1, i + rnd.randint(1, 200))
                seq[i], seq[j] = seq[j], seq[i]
            for _ in range(rnd.randint(0, 5)):                   # duplicates / very late
                seq.insert(rnd.randrange(len(seq)), rnd.choice(seq))
            if trial % 5 == 0:
                seq.append(seq[-1] + rnd.randint(W, 5 * W))      # big jump
            self.assertEqual(self.run_track(seq), reference_loss(seq), "trial %d" % trial)

    def test_implausible_jump_discards(self):
        t = aggregate.KeypairTrack(0, 0.0)
        self.assertFalse(t.add(aggregate.MAX_COUNTER_JUMP + 5, 0.0))


class NqmoS4ReducerTests(unittest.TestCase):
    def frames(self, red, counters, ts=10.0, recv=b"KKKK", body=16, **kw):
        for c in counters:
            red.frame(ts, wg_frame(wg_data(recv, c, body=body), **kw)[:44])

    def test_loss_lmax_df_and_minute_bucket(self):
        red = aggregate.S4Reducer(wan_mtu=1500)
        for c in range(300):
            if c != 150:
                red.frame(10.0, wg_frame(wg_data(b"KKKK", c, body=1360 if c % 2 else 16),
                                         df=True)[:44])
        red.expire(10.0 + aggregate.KEYPAIR_IDLE + 1)       # idle ⇒ finalised now
        out = red.harvest(10 ** 9)
        by_min = {m: summ for m, summ, _t in out}
        s0 = by_min[0][("198.51.100.7", 51000, b"KKKK")]
        self.assertEqual((s0["pkts"], s0["df"], max(s0["lens"])), (299, 299, 20 + 8 + 16 + 1360))
        later = by_min[aggregate.minute_of(10.0 + aggregate.KEYPAIR_IDLE + 1)]
        s1 = later[("198.51.100.7", 51000, b"KKKK")]
        self.assertEqual((s1["ok"], s1["lost"]), (299, 1))   # judged at finalise time

    def test_gap_keeps_judged_counts_and_never_invents_loss(self):
        W = aggregate.COUNTER_WINDOW
        red = aggregate.S4Reducer()
        self.frames(red, range(0, W + 1000))                 # 1000 judged ok
        red.gap(11.0, "KERNEL_DROP")                          # ring overflow here
        self.frames(red, range(W + 50000, W + 50010), ts=12.0)   # a jump after the hole
        red.expire(10 ** 6)
        tot = {"ok": 0, "lost": 0}
        taints = set()
        for _m, summ, t in red.harvest(10 ** 9):
            taints |= t
            for st in summ.values():
                tot["ok"] += st["ok"]
                tot["lost"] += st["lost"]
        self.assertEqual(tot["lost"], 0)                      # the hole is not "loss"
        self.assertGreaterEqual(tot["ok"], 1000)              # judged work survived the gap
        self.assertIn("S4:GAP:KERNEL_DROP", taints)

    def test_rekey_finalises_old_keypair_soon(self):
        red = aggregate.S4Reducer()
        self.frames(red, range(0, 100), recv=b"OLD1", ts=5.0)
        self.frames(red, range(0, 10), recv=b"NEW2", ts=6.0)
        red.expire(6.0 + aggregate.REKEY_FINALIZE_AFTER + 1)
        self.assertNotIn(("198.51.100.7", 51000, b"OLD1"), red.tracks)

    def test_gro_guard(self):
        red = aggregate.S4Reducer(wan_mtu=1500)
        fr = bytearray(wg_frame(wg_data())[:44])
        struct.pack_into("!H", fr, 2, 9000)                   # merged super-frame
        red.frame(1.0, bytes(fr))
        self.assertIn("S4:INVALID_GRO", red.harvest(10 ** 9)[0][2])


class NqmoRingLosingTests(unittest.TestCase):
    def test_losing_block_yields_gap_before_its_frames(self):
        mem = bytearray(4096 * 2)
        frame = wg_frame(wg_data(counter=5))[:44]
        hdr = ring._PKT.size + 12
        first = 48
        struct.pack_into("=IIIIIIQ", mem, 0, 3, 0,
                         ring.TP_STATUS_USER | ring.TP_STATUS_LOSING, 1, first, 4096, 1)
        struct.pack_into("=IIIIIIHH", mem, first, 0, 10, 0, len(frame), 200, 0, hdr, hdr)
        mem[first + hdr:first + hdr + len(frame)] = frame
        r = object.__new__(ring.Ring)
        r.mem, r.block_size, r.blocks, r.cur = mem, 4096, 2, 0
        a, b = socket.socketpair()
        try:
            r.sock = a
            orig = capture.read_stats
            capture.read_stats = lambda s: (10, 7)
            try:
                out = list(r.poll(0.0))
            finally:
                capture.read_stats = orig
        finally:
            a.close()
            b.close()
        self.assertEqual([k for k, _ in out], ["gap", "frame"])
        self.assertEqual(out[0][1], 7)
        self.assertEqual(struct.unpack_from("=I", mem, 8)[0], ring.TP_STATUS_KERNEL)


# ---------------------------------------------------------------- aggregator
class FakeStore:
    def __init__(self):
        self.rows = []
        self.ctx = {}

    def peer_id(self, iface, name, fp):
        return hash((iface, name, fp)) & 0xFFFF

    def endpoint_ctx(self, h, p24, **kw):
        return self.ctx.setdefault(h, len(self.ctx) + 1)

    def put_peer_minute(self, row):
        unknown = set(row) - set(storemod.PEER_MINUTE_COLS)
        assert not unknown, unknown
        self.rows.append(row)


def agg_with_meta(doc=None, read_at=1000):
    a = aggregate.Aggregator(b"k" * 32)
    a.set_meta(meta.parse(json.dumps(doc or meta_doc()), read_at=read_at))
    return a


def flush(a, minute, now=None):
    fs = FakeStore()
    now = minute + 120 if now is None else now
    a.expire(now)
    a.flush(minute, fs, now=now, meta_stale_s=10 ** 9)
    return fs.rows


OUT = dict(src="203.0.113.1", dst="198.51.100.7", sport=PORT, dport=51000)


class NqmoAggregatorTests(unittest.TestCase):
    def test_rtt_client_initiated(self):
        a = agg_with_meta()
        a.on_s1(100.000, True, wgparse.parse_wg(wg_frame(wg_resp(b"SRVI", b"CLNI"), **OUT)))
        a.on_s1(100.030, False, wgparse.parse_wg(wg_frame(wg_data(b"SRVI", 0))))
        r = flush(a, 60)[0]
        self.assertEqual(r["rtt_n"], 1)
        self.assertAlmostEqual(r["rtt_ms_med"], 30.0, places=2)
        self.assertEqual(r["hs_resp_out"], 1)

    def test_rtt_server_initiated_pairs_by_index(self):
        a = agg_with_meta()
        a.on_s1(10.0, True, wgparse.parse_wg(wg_frame(wg_init(b"OLD1"), **OUT)))
        a.on_s1(15.0, True, wgparse.parse_wg(wg_frame(wg_init(b"NEW2"), **OUT)))
        a.on_s1(15.080, False, wgparse.parse_wg(wg_frame(wg_resp(b"CCCC", b"NEW2"))))
        r = flush(a, 0, now=30)[0]
        self.assertEqual(r["rtt_n"], 1)
        self.assertAlmostEqual(r["rtt_ms_med"], 80.0, places=2)   # not 5080
        self.assertEqual(r["rtt_missed"], 1)                      # OLD1 expired

    def test_wrong_index_no_sample(self):
        a = agg_with_meta()
        a.on_s1(1.0, True, wgparse.parse_wg(wg_frame(wg_resp(b"AAAA"), **OUT)))
        a.on_s1(1.02, False, wgparse.parse_wg(wg_frame(wg_data(b"BBBB", 0))))
        self.assertEqual(flush(a, 0, now=1.5)[0]["rtt_n"], 0)

    def test_events_bucket_by_kernel_timestamp(self):
        a = agg_with_meta()
        a.on_s5(59.9, "10.66.0.5", 1352)          # minute 0, drained late
        a.on_s5(60.1, "10.66.0.5", 1352)          # minute 60
        self.assertEqual(flush(a, 0)[0]["syn_n"], 1)
        self.assertEqual(flush(a, 60)[0]["syn_n"], 1)

    def test_fragments_complete_incomplete_and_orphans(self):
        a = agg_with_meta()
        src = "198.51.100.7"
        a.on_s3(1.0, {"src": src, "dst": "203.0.113.1", "id": 5, "off": 1400,
                      "len": 52, "mf": False})
        a.on_s2(1.01, {"src": src, "dst": "203.0.113.1", "id": 5, "F": 1420,
                       "O": 1472, "sport": 51000, "payload": 1400})
        a.on_s2(2.0, {"src": src, "dst": "203.0.113.1", "id": 6, "F": 1420,
                      "O": 1472, "sport": 51000, "payload": 1400})
        r = flush(a, 0, now=100)[0]
        self.assertEqual((r["frag_first"], r["frag_incomplete"]), (2, 1))
        self.assertEqual((r["frag_first_len_min"], r["frag_orig_len"]), (1420, 1472))

    def test_foreign_tail_fragments_are_not_stored(self):
        a = agg_with_meta()
        a.on_s3(1.0, {"src": "192.0.2.50", "dst": "203.0.113.1", "id": 9, "off": 8,
                      "len": 8, "mf": False})
        self.assertEqual(a.orphans, {})

    def test_s4_summary_mapped_by_index_over_endpoint(self):
        d = meta_doc()
        other = pubkey(2)
        d["peers"][other] = dict(d["peers"][pubkey(1)], name="bob", tunnel_ip="10.66.0.6",
                                 endpoint="192.0.2.9:4000")
        a = agg_with_meta(d)
        # bob's handshake taught us his server-side index; his data now comes
        # from alice's old ip:port (CGNAT reuse) — index must win
        a.on_s1(5.0, True, wgparse.parse_wg(wg_frame(wg_resp(b"BOBI"), src="203.0.113.1",
                                                     dst="192.0.2.9", sport=PORT,
                                                     dport=4000)))
        st = aggregate._new_s4()
        st.update(ok=10, pkts=10)
        a.on_s4_summary(0, {("198.51.100.7", 51000, b"BOBI"): st}, set())
        rows = {r["peer_id"]: r for r in flush(a, 0)}
        ids = {FakeStore().peer_id("wg1udp", n, aggregate.key_fp(k)): n
               for n, k in (("alice", pubkey(1)), ("bob", other))}
        got = {ids[pid]: r["s4_received"] for pid, r in rows.items()}
        self.assertEqual(got.get("bob"), 10)
        self.assertEqual(got.get("alice", 0), 0)

    def test_ambiguous_endpoint_maps_to_nobody(self):
        d = meta_doc()
        d["peers"][pubkey(2)] = dict(d["peers"][pubkey(1)], name="bob",
                                     tunnel_ip="10.66.0.6", latest_handshake=0)
        d["peers"][pubkey(1)]["latest_handshake"] = 0
        m = meta.parse(json.dumps(d), read_at=1000)
        self.assertNotIn(("198.51.100.7", 51000), m.by_endpoint)
        self.assertIn(("198.51.100.7", 51000), m.ambiguous_endpoints)
        d["peers"][pubkey(1)]["latest_handshake"] = 990     # only alice is active
        m = meta.parse(json.dumps(d), read_at=1000)
        self.assertEqual(m.by_endpoint[("198.51.100.7", 51000)], pubkey(1))

    def test_disabled_peer_is_not_mapped(self):
        d = meta_doc()
        d["peers"][pubkey(1)]["enabled"] = False
        m = meta.parse(json.dumps(d), read_at=1000)
        self.assertEqual(m.by_endpoint, {})
        self.assertEqual(m.by_tunnel_ip, {})

    def test_c1_deltas_counted_once_per_meta(self):
        a = agg_with_meta()                                    # meta @1000
        d = meta_doc(generated_at=1070.0)
        d["peers"][pubkey(1)].update(rx_bytes=10000, tx_bytes=2000,
                                     endpoint="198.51.100.7:52000")
        a.set_meta(meta.parse(json.dumps(d), read_at=1071))
        r1 = flush(a, 1020)                                    # minute holding 1070
        self.assertEqual((r1[0]["rx_bytes"], r1[0]["c1_interval_s"]), (9000, 70.0))
        self.assertEqual((r1[0]["ep_port_only_changed"], r1[0]["ep_changed"]), (1, 0))
        r2 = flush(a, 1080)                                    # no new meta
        self.assertTrue(not r2 or r2[0]["rx_bytes"] is None)   # never re-counted

    def test_mss_mode_and_exceeds(self):
        a = agg_with_meta()
        for mss in (1352, 1352, 1460):
            a.on_s5(1.0, "10.66.0.5", mss)
        r = flush(a, 0)[0]
        self.assertEqual((r["mss_mode"], r["mss_exceeds"]), (1352, 0))
        a.on_s5(61.0, "10.66.0.5", 1460)
        self.assertEqual(flush(a, 60)[0]["mss_exceeds"], 1)    # LAN behind client

    def test_stale_meta_marks_invalid(self):
        a = agg_with_meta()
        a.on_s5(4000.0, "10.66.0.5", 1352)
        fs = FakeStore()
        a.flush(3960, fs, now=4100, meta_stale_s=180)
        self.assertEqual(fs.rows[0]["quality"], "INVALID")

    def test_idle_peer_gets_no_row(self):
        d = meta_doc()
        d["peers"][pubkey(1)]["latest_handshake"] = 1
        a = agg_with_meta(d)
        self.assertEqual(flush(a, 600), [])

    def test_unmapped_and_cookie_are_global(self):
        a = agg_with_meta()
        a.on_s1(1.0, True, wgparse.parse_wg(wg_frame(wg_cookie(), src="203.0.113.1",
                                                     dst="192.0.2.77", sport=PORT,
                                                     dport=9999)))
        fs = FakeStore()
        a.expire(2)
        _n, glob = a.flush(0, fs, now=200, meta_stale_s=10 ** 9)
        self.assertEqual((glob["hs_cookie_out"], glob["unmapped_s1"]), (1, 1))


# ---------------------------------------------------------------- meta hardening
class NqmoMetaHardeningTests(unittest.TestCase):
    def test_non_meta_errors_become_meta_error(self):
        for mut in (lambda d: d["peers"][pubkey(1)].update(tunnel_ip="10.66.0.5/32"),
                    lambda d: d["peers"][pubkey(1)].update(endpoint="1.2.3.4:abc"),
                    lambda d: d["wg1udp"].update(local_ip="nope")):
            d = meta_doc()
            mut(d)
            with self.assertRaises(meta.MetaError):
                meta.parse(json.dumps(d), read_at=1000)

    def test_ipv6_endpoint_is_unmodelled_not_fatal(self):
        d = meta_doc()
        d["peers"][pubkey(1)]["endpoint"] = "[2001:db8::1]:51820"
        m = meta.parse(json.dumps(d), read_at=1000)
        self.assertEqual((m.unmodelled_endpoints, m.by_endpoint), (1, {}))

    def test_nonfinite_and_future_timestamps(self):
        for text in ('{"generated_at": NaN}', '{"generated_at": Infinity}'):
            with self.assertRaises(meta.MetaError):
                meta.parse(text, read_at=1000)
        with self.assertRaises(meta.MetaError):
            meta.parse(json.dumps(meta_doc(generated_at=1000 * 1000.0)), read_at=1000)

    def test_embedded_and_unpadded_keys_rejected(self):
        k = pubkey(9)
        for v in ("x " + k, k[:-1]):
            d = meta_doc()
            d["egress"]["awg1"]["health"] = v
            with self.assertRaises(meta.MetaError, msg=v):
                meta.parse(json.dumps(d), read_at=1000)

    def test_bool_never_passes_as_int(self):
        for field in ("c_mtu", "rate_mbit", "rx_bytes", "latest_handshake"):
            d = meta_doc()
            d["peers"][pubkey(1)][field] = True
            with self.assertRaises(meta.MetaError, msg=field):
                meta.parse(json.dumps(d), read_at=1000)
        d = meta_doc()
        d["peers"][pubkey(1)]["rx_bytes"] = -1
        with self.assertRaises(meta.MetaError):
            meta.parse(json.dumps(d), read_at=1000)


# ---------------------------------------------------------------- store / engine
class NqmoStoreTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "n.db")

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_migrate_and_mode(self):
        s = storemod.Store(self.p)
        from nqmo import SCHEMA_VERSION
        self.assertEqual(s.conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        self.assertEqual(oct(os.stat(self.p).st_mode & 0o777), "0o600")
        s.close()

    def test_v1_file_migrates_to_v2_keeping_rows(self):
        # a real v1 database with data, as PHASE 3 code would have written it
        c = sqlite3.connect(self.p)
        for stmt in storemod._split(storemod.MIGRATIONS[1]):
            c.execute(stmt)
        c.execute("PRAGMA user_version=1")
        c.execute("INSERT INTO global_minute(ts, reasm_fails, quality) VALUES(60, 7, 'GOOD')")
        c.commit()
        c.close()
        s = storemod.Store(self.p)
        self.assertFalse(s.read_only)
        self.assertEqual(s.conn.execute("PRAGMA user_version").fetchone()[0], 2)
        cols = [r[1] for r in s.conn.execute("PRAGMA table_info(global_minute)")]
        self.assertIn("frag_mem_pct", cols)
        self.assertEqual(s.conn.execute("SELECT reasm_fails FROM global_minute WHERE ts=60")
                         .fetchone()[0], 7)
        with s.transaction() as t:
            t.put_global_minute({"ts": 120, "frag_mem_pct": 99.5, "quality": "GOOD"})
        s.close()

    def test_every_store_column_tuple_matches_the_migrated_schema(self):
        # family guard: a column added to *_COLS without a migration (or the
        # reverse) must fail here, not as an INSERT error on the server
        s = storemod.Store(self.p)
        for table, cols in (("global_minute", storemod.GLOBAL_MINUTE_COLS),
                            ("peer_minute", storemod.PEER_MINUTE_COLS)):
            have = {r[1] for r in s.conn.execute("PRAGMA table_info(%s)" % table)}
            self.assertEqual(set(cols) - have, set(), table)
        s.close()

    def test_newer_schema_is_read_only(self):
        s = storemod.Store(self.p)
        s.conn.execute("PRAGMA user_version=99")
        s.close()
        s = storemod.Store(self.p)
        self.assertTrue(s.read_only)
        with self.assertRaises(storemod.StoreError):
            s.set_meta("x", 1)
        s.close()

    def test_corrupt_file_is_set_aside(self):
        with open(self.p, "wb") as f:
            f.write(b"SQLite format 3\x00" + b"\xff" * 4096)
        s = storemod.Store(self.p)
        self.assertTrue(s.recreated)
        self.assertTrue(any(n.startswith("n.db.corrupt-") for n in os.listdir(self.d)))
        ev = s.conn.execute("SELECT kind FROM config_event").fetchall()
        self.assertEqual(ev, [("DB_RECREATED",)])
        s.close()

    def test_unopenable_is_an_error_not_corruption(self):
        os.mkdir(self.p)                       # exists, but cannot be opened as a DB
        with self.assertRaises(storemod.StoreError):
            storemod.Store(self.p)
        self.assertEqual([n for n in os.listdir(self.d) if "corrupt" in n], [])

    def test_unknown_column_rejected_and_prune(self):
        s = storemod.Store(self.p, now=lambda: 100 * 86400.0)
        with self.assertRaises(storemod.StoreError):
            s.put_peer_minute({"peer_id": 1, "ts": 1, "quality": "GOOD", "bogus": 1})
        s.put_peer_minute({"peer_id": 1, "ts": 1, "quality": "GOOD"})
        s.put_peer_minute({"peer_id": 1, "ts": 99 * 86400, "quality": "GOOD"})
        n = s.prune(config.DEFAULTS["retention_days"])
        self.assertEqual(n, 1)
        s.close()


class NqmoWorkerHealthTests(unittest.TestCase):
    """myserver, 4 Nov: nqmo-net sleeps 60 s but its heartbeat went stale after
    30, so collector_health logged a failure every minute for a healthy thread.
    The lab never showed it: nobody read that table while the thread was idle."""

    @staticmethod
    def wakeups(cls_node, attrs):
        """Timeouts of every blocking call in run(): stop.wait, select, poll."""
        run = next(n for n in cls_node.body
                   if isinstance(n, ast.FunctionDef) and n.name == "run")
        out = []
        for node in ast.walk(run):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("wait", "select", "poll")):
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, (int, float)):
                    out.append(arg.value)
                elif (isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name)
                      and arg.value.id == "self"):
                    out.append(attrs[arg.attr])
        return out

    def test_every_worker_wakes_before_its_heartbeat_goes_stale(self):
        from nqmo import engine
        tree = ast.parse(read(os.path.join(PKG, "engine.py")))
        seen = set()
        for node in tree.body:
            if not (isinstance(node, ast.ClassDef)
                    and any(getattr(b, "id", "") == "_Worker" for b in node.bases)):
                continue
            cls = getattr(engine, node.name)
            attrs = {k: getattr(cls, k) for k in dir(cls) if k.isupper()}
            times = self.wakeups(node, attrs)
            self.assertTrue(times, "%s: no blocking call found in run()" % node.name)
            for t in times:
                self.assertLess(t, cls.STALE_S, node.name)
            seen.add(node.name)
        self.assertEqual(seen, {"LowRateCapture", "RingCapture", "NetThread"})

    def _running_net_thread(self):
        from nqmo import engine

        class Tc:
            def sample(self):
                return None

        cfg = config.validate({})
        w = engine.NetThread(cfg, engine.EventBus(8), lambda: None)
        w.tc = Tc()
        w.start()
        self.addCleanup(w.join, 5)
        self.addCleanup(w.stop.set)
        return w

    def test_idle_net_thread_stays_healthy_for_its_whole_sleep(self):
        w = self._running_net_thread()
        w.heartbeat = time.monotonic() - w.INTERVAL_S - 1
        self.assertTrue(w.healthy())

    def test_stuck_net_thread_is_still_reported(self):
        w = self._running_net_thread()
        self.assertLessEqual(w.STALE_S, 2 * w.INTERVAL_S, "a huge limit hides a stuck thread")
        w.heartbeat = time.monotonic() - w.STALE_S - 1
        self.assertFalse(w.healthy())

    def test_failing_net_thread_is_still_reported(self):
        w = self._running_net_thread()
        w.error = "OSError: boom"
        self.assertFalse(w.healthy())

    def test_capture_workers_keep_the_short_limit(self):
        from nqmo import engine
        self.assertEqual(engine.LowRateCapture.STALE_S, engine.THREAD_STALE_S)
        self.assertEqual(engine.RingCapture.STALE_S, engine.THREAD_STALE_S)


class NqmoEngineTests(unittest.TestCase):
    """Offline end-to-end: meta file → events → minute flush → DB + state.json."""

    def setUp(self):
        from nqmo import engine
        self.engine_mod = engine
        self.d = tempfile.mkdtemp()
        raw = {"paths": {k: os.path.join(self.d, k) for k in config.DEFAULTS["paths"]}}
        self.cfg = config.validate(raw)
        self.t = [1000.0]
        with open(self.cfg["paths"]["meta"], "w") as f:
            json.dump(meta_doc(), f)
        self.e = engine.Engine(self.cfg, clock=lambda: self.t[0])

    def tearDown(self):
        if not self.e.store.closed:
            self.e.store.close()
        shutil.rmtree(self.d)

    def test_minute_flow_without_secrets_or_inner_dest(self):
        e = self.e
        e.task_meta()
        self.assertEqual(e.meta_error, "")
        st4 = aggregate._new_s4()
        st4.update(ok=5, pkts=5)
        e.bus_s4.put(("S4SUM", 960, {("198.51.100.7", 51000, b"KKKK"): st4}, set()))
        e.bus.put(("S5", 1000.2, 0, syn(dst="203.0.113.77", dport=8443)[:60]))
        e.bus.put(("gap", 1000.5, "KERNEL_DROP:S1"))
        self.t[0] = 960 + 60 + aggregate.FLUSH_DELAY + 0.1
        e.step()
        e.task_export()
        rows = e.store.conn.execute(
            "SELECT quality, quality_why, syn_n, s4_received FROM peer_minute").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0][2], rows[0][3]), (1, 5))
        for tok in ("KERNEL_DROP:S1", "C3:DISABLED", "STARTUP"):
            self.assertIn(tok, rows[0][1])
        self.assertEqual(rows[0][0], "DEGRADED")
        st = json.loads(read(self.cfg["paths"]["state"]))
        self.assertEqual(st["mode"], "OBSERVATION_ONLY")
        self.assertIsNone(st["collectors"]["C3_capture"])     # disabled ≠ healthy
        e.store.close()
        blob = read(self.cfg["paths"]["db"], "rb")
        if os.path.exists(self.cfg["paths"]["db"] + "-wal"):
            blob += read(self.cfg["paths"]["db"] + "-wal", "rb")
        blob += read(self.cfg["paths"]["state"], "rb")
        self.assertNotIn(pubkey(1).encode(), blob)              # only key_fp
        self.assertNotIn(b"203.0.113.77", blob)                 # inner destination
        self.assertNotIn(b"198.51.100.7:51000", blob)           # raw endpoint

    def test_main_loop_phases_are_timed_and_a_slow_phase_is_named(self):
        """§29.161: four watchdog kills in three days with nothing in the journal.
        Family guard: every main-loop phase has a per-minute maximum in
        collector_health (loop:<phase>) and in state.json coverage.loop_ms, a
        phase over SLOW_PHASE_S becomes an engine error carrying its name, and the
        loop arms a stack dump before each step so the next stall prints itself."""
        e = self.e
        e.task_meta()
        self.t[0] = 960 + 60 + aggregate.FLUSH_DELAY + 0.1
        e.step()
        e.task_export()
        st = json.loads(read(self.cfg["paths"]["state"]))
        self.assertEqual(set(st["coverage"]["loop_ms"]) & set(engine.LOOP_PHASES),
                         set(st["coverage"]["loop_ms"]))
        self.assertTrue(st["coverage"]["loop_ms"], "phases must be timed")
        rows = {r[0]: r[1] for r in e.store.conn.execute(
            "SELECT collector, max_duration_ms FROM collector_health WHERE collector LIKE 'loop:%'")}
        self.assertEqual(set(rows), {"loop:" + p for p in st["coverage"]["loop_ms"]})
        self.assertTrue(all(isinstance(v, float) and v >= 0 for v in rows.values()), rows)
        # a slow phase: inject a task that sleeps past the threshold (clock is fake,
        # so advance it inside the task)
        old = engine.SLOW_PHASE_S
        engine.SLOW_PHASE_S = 0.0
        try:
            e.sched.add("slow", 1.0, 100.0, lambda: None, start_at=self.t[0])
            self.t[0] += 1
            e.step()
        finally:
            engine.SLOW_PHASE_S = old
        self.assertTrue(any(x["where"] == "loop:tasks" and "phase took" in x["error"]
                            for x in e.errors), e.errors)

    def test_window_close_sends_heartbeats_while_it_progresses(self):
        """§29.161: on myserver the window-close flush took 13.4 s of wall time for
        1.4 s of CPU; a progressing analysis must feed the watchdog from inside the
        phase. Guard: closing a 5-minute window emits several WATCHDOG=1 notifies."""
        e = self.e
        e.task_meta()
        beats = []
        real = engine.sd_notify
        engine.sd_notify = lambda msg, env=None: beats.append(msg)
        try:
            # walk five minutes so the window at 1200 closes inside maybe_flush
            for m in range(960, 960 + 6 * 60, 60):
                self.t[0] = m + 60 + aggregate.FLUSH_DELAY + 0.1
                e.step()
        finally:
            engine.sd_notify = real
        self.assertGreaterEqual(beats.count("WATCHDOG=1"), 6 + 4, beats)

    def test_run_forever_arms_a_stack_dump_around_every_step(self):
        calls = []
        fake = types.SimpleNamespace(
            enable=lambda all_threads=True: calls.append("enable"),
            register=lambda *a, **k: calls.append("register"),
            dump_traceback_later=lambda t, repeat=False: calls.append(("arm", t, repeat)),
            cancel_dump_traceback_later=lambda: calls.append("cancel"))
        e = self.e
        real = engine.faulthandler
        engine.faulthandler = fake
        steps = []

        def step():
            steps.append(1)
            if len(steps) == 2:
                e.stop.set()
        e.step = step
        e.start = lambda: None
        e.shutdown = lambda: None
        try:
            engine.sd_notify = lambda *a, **k: None
            e.run_forever()
        finally:
            engine.faulthandler = real
        self.assertEqual(calls[:2], ["enable", "register"])
        self.assertEqual(calls[2:], [("arm", engine.STALL_DUMP_S, False), "cancel"] * 2)
        self.assertLess(engine.STALL_DUMP_S, 90, "must fire before WatchdogSec=90")

    def test_export_carries_the_engines_own_cost(self):
        """§29.153: coverage.engine says what the engine costs and whether S4 is in
        sampling rotation (the one state that silently degrades data quality)."""
        e = self.e
        e.task_meta()
        self.t[0] = 960 + 60 + aggregate.FLUSH_DELAY + 0.1
        e.step()
        e.task_export()
        st = json.loads(read(self.cfg["paths"]["state"]))
        eng = st["coverage"]["engine"]
        self.assertEqual(set(eng), {"cpu_pct", "rss_mb", "cpu_pct_max", "sampling"})
        self.assertEqual(eng["cpu_pct_max"], self.cfg["capture"]["s4_cpu_pct_max"])
        self.assertIs(eng["sampling"], False)                 # capture off ⇒ no ring
        for k in ("cpu_pct", "rss_mb"):
            self.assertTrue(eng[k] is None or isinstance(eng[k], (int, float)), k)

    def test_backlog_minutes_flush_separately(self):
        e = self.e
        e.task_meta()
        e.bus.put(("S5", 970.0, 0, syn()[:60]))
        e.bus.put(("S5", 1030.0, 0, syn()[:60]))
        self.t[0] = 1200.0                                      # stalled ~3 minutes
        e.step()
        ts = [r[0] for r in e.store.conn.execute(
            "SELECT ts FROM peer_minute WHERE syn_n > 0 ORDER BY ts")]
        self.assertEqual(ts, [960, 1020])

    def test_ctl_runs_on_main_thread_via_queue(self):
        """The client lives in a side thread; requests are served HERE, on the
        thread that owns the store — exactly how run_forever does it."""
        import threading
        import time as _t
        e = self.e
        path = os.path.join(self.d, "c.sock")
        srv = ctl.Server(path, e.ctl_q, allowed_uid=os.getuid(), uid_fn=lambda c: os.getuid())
        srv.start()
        resp = {}

        def client():
            for _ in range(100):
                if os.path.exists(path):
                    break
                _t.sleep(0.02)
            c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            c.connect(path)
            c.sendall(b'{"v":1,"op":"mode.set","to":"DIAGNOSTICS_ENABLED","actor":"admin"}\n')
            resp.update(json.loads(c.recv(4096).decode()))
            c.close()
        th = threading.Thread(target=client)
        th.start()
        try:
            deadline = _t.time() + 5
            while th.is_alive() and _t.time() < deadline:
                ctl.serve_pending(e.ctl_q, e.handler)     # main thread = store owner
                _t.sleep(0.01)
        finally:
            th.join(3)
            srv.stop.set()
            srv.join(3)
        self.assertEqual(resp, {"ok": True, "mode": "DIAGNOSTICS_ENABLED"})
        self.assertEqual(srv.error, "")
        self.assertEqual(e.store.get_meta("mode_override"), "DIAGNOSTICS_ENABLED")

    def test_ctl_path_appears_only_once_it_accepts(self):
        """Family guard (lab, 28 Oct): a client that sees the socket file must
        never get ECONNREFUSED — bound in place, the bind→listen gap did."""
        import time as _t
        for i in range(25):
            path = os.path.join(self.d, "r%d.sock" % i)
            srv = ctl.Server(path, queue.Queue(), allowed_uid=os.getuid(),
                             uid_fn=lambda c: os.getuid())
            srv.start()
            try:
                for _ in range(500):
                    if os.path.exists(path):
                        break
                    _t.sleep(0.001)
                c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    c.connect(path)                 # raises if not yet listening
                finally:
                    c.close()
            finally:
                srv.stop.set()
                srv.join(3)
            # (a client closing unanswered may leave a BrokenPipe here — not this test)
            self.assertFalse(srv.error.startswith("bind"), srv.error)
            self.assertFalse(os.path.exists(path + ".new"))

    def test_ctl_removes_only_its_own_socket_on_stop(self):
        path = os.path.join(self.d, "own.sock")
        srv = ctl.Server(path, queue.Queue(), allowed_uid=os.getuid(),
                         uid_fn=lambda c: os.getuid())
        srv.start()
        for _ in range(500):
            if os.path.exists(path):
                break
            time.sleep(0.001)
        srv.stop.set()
        srv.join(3)
        self.assertFalse(os.path.exists(path), "a stopped engine left its socket behind")
        # a newer engine's socket at the same path survives an old one's exit
        a = ctl.Server(path, queue.Queue(), allowed_uid=os.getuid(),
                       uid_fn=lambda c: os.getuid())
        a.start()
        for _ in range(500):
            if os.path.exists(path):
                break
            time.sleep(0.001)
        os.unlink(path)
        other = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        other.bind(path)                          # "the next engine"
        try:
            a.stop.set()
            a.join(3)
            self.assertTrue(os.path.exists(path))
        finally:
            other.close()

    def test_engine_shutdown_joins_ctl(self):
        src = read(os.path.join(PKG, "engine.py"))
        body = src[src.index("    def shutdown("):src.index("    def reload(")]
        self.assertIn("self.ctl.join(", body)

    def test_ctl_never_binds_the_public_path_directly(self):
        tree = ast.parse(read(os.path.join(PKG, "ctl.py")))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "bind"):
                self.assertNotIn("self.path", ast.unparse(node.args[0]))

    def test_mode_override_and_cfg_wins_on_edit(self):
        e = self.e
        self.assertTrue(e.handler.handle(
            {"v": 1, "op": "mode.set", "to": "DIAGNOSTICS_ENABLED", "actor": "admin"})["ok"])
        e.store.close()
        e2 = self.engine_mod.Engine(self.cfg, clock=lambda: self.t[0])
        self.assertEqual(e2.mode, "DIAGNOSTICS_ENABLED")       # override persisted
        e2.store.close()
        cfg = dict(self.cfg, mode="RECOMMENDATIONS_ENABLED")
        e3 = self.engine_mod.Engine(cfg, clock=lambda: self.t[0])
        self.assertEqual(e3.mode, "RECOMMENDATIONS_ENABLED")   # operator edit wins
        self.e = e3

    def test_bad_meta_is_ignored_whole(self):
        with open(self.cfg["paths"]["meta"], "w") as f:
            d = meta_doc()
            d["peers"][pubkey(1)]["psk"] = "x"
            json.dump(d, f)
        self.e.task_meta()
        self.assertIn("forbidden", self.e.meta_error)
        self.assertIsNone(self.e.agg.meta)

    def test_secret_file_of_wrong_length_is_fatal(self):
        p = os.path.join(self.d, "bad-secret")
        with open(p, "wb") as f:
            f.write(b"short")
        with self.assertRaises(RuntimeError):
            self.engine_mod.load_secret(p)


class NqmoCaptureResilienceTests(unittest.TestCase):
    def test_socket_error_reopens_and_reports_gap(self):
        from nqmo import engine
        opened, pairs = [], []

        def fake_open(ifname, proto, prog):
            a, b = socket.socketpair()
            b.send(b"x")                          # readable at once
            pairs.append((a, b))
            opened.append(prog)
            return a

        def boom(s, snap):
            raise OSError(100, "Network is down")
        saved = (capture.open_tap, capture.recv_one, capture.read_stats, engine.REOPEN_BACKOFF)
        capture.open_tap, capture.recv_one = fake_open, boom
        capture.read_stats = lambda s: (0, 0)
        engine.REOPEN_BACKOFF = (0, 0, 0, 0)
        bus = engine.EventBus(1000)
        t = engine.LowRateCapture(config.validate({}), bus)
        try:
            t.start()
            import time as _t
            _t.sleep(0.6)
        finally:
            t.stop.set()
            t.join(3)
            (capture.open_tap, capture.recv_one, capture.read_stats,
             engine.REOPEN_BACKOFF) = saved
            for a, b in pairs:
                a.close()
                b.close()
        evs, _d = bus.drain()
        self.assertTrue(any(e[0] == "gap" and e[2].startswith("SOCK_ERR:") for e in evs))
        self.assertGreater(len(opened), len(capture.STREAMS))  # reopened after the error
        self.assertFalse(t.is_alive())


# ---------------------------------------------------------------- small units
class NqmoConfigCtlSchedTests(unittest.TestCase):
    def test_config_strict(self):
        config.validate({})
        for bad in ({"nope": 1}, {"capture": {"enabled": "yes"}},
                    {"capture": {"listen_port": 0}}, {"mode": "AUTO"},
                    {"active_probes": True}, {"paths": {"db": "relative.db"}},
                    {"capture": {"wan_iface": "eth0; rm"}},
                    {"intervals": {"meta_s": 1.5}},
                    {"capture": {"ring_block_kb": 18}}):
            with self.assertRaises(config.ConfigError, msg=repr(bad)):
                config.validate(bad)
        config.validate({"mode": "RECOMMENDATIONS_ENABLED", "active_probes": True})

    def test_adjacent(self):
        self.assertTrue(config.adjacent_mode("OBSERVATION_ONLY", "DIAGNOSTICS_ENABLED"))
        self.assertFalse(config.adjacent_mode("OBSERVATION_ONLY", "RECOMMENDATIONS_ENABLED"))

    def test_ctl_validation(self):
        h = ctl.Handler(lambda: "OBSERVATION_ONLY", lambda *a: None, lambda *a: False)
        q = __import__("queue").Queue()
        q.put(({"v": 1, "op": "mode.get"}, __import__("queue").Queue()))
        self.assertEqual(ctl.serve_pending(q, h), 1)
        self.assertEqual(h.handle({"v": 1, "op": "probe", "peer": "alice",
                                   "actor": "admin"})["refused"], "NOT_AVAILABLE")
        self.assertEqual(h.handle({"v": 1, "op": "mode.set", "to": "RECOMMENDATIONS_ENABLED",
                                   "actor": "admin"})["refused"], "NOT_ADJACENT")
        for bad in ({"v": 2, "op": "mode.get"}, {"v": 1, "op": "x"},
                    {"v": 1, "op": "mode.get", "extra": 1},
                    {"v": 1, "op": "ack", "id": True, "actor": "a"},
                    {"v": 1, "op": "ack", "id": 1, "actor": "a b"}):
            self.assertFalse(h.handle(bad)["ok"], bad)

    def test_sched_budget_and_isolation(self):
        t = [0.0]
        s = sched.Scheduler(clock=lambda: t[0])

        def slow():
            t[0] += 5.0

        def boom():
            raise RuntimeError("x")
        s.add("slow", 1.0, 1.0, slow, start_at=0)
        s.add("boom", 1.0, 1.0, boom, start_at=0)
        s.run_due()
        t[0] += 1.0
        s.run_due()
        h = s.health()
        self.assertEqual((h["slow"]["runs"], h["slow"]["gaps"]), (1, 1))
        self.assertEqual(h["boom"]["failures"], 2)

    def test_export_atomic_mode(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "s.json")
            export.write_atomic(p, {"a": 1})
            self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o640")
            self.assertEqual(json.loads(read(p)), {"a": 1})
            self.assertEqual([n for n in os.listdir(d) if n.startswith(".state.")], [])
        finally:
            shutil.rmtree(d)


class NqmoBuildTests(unittest.TestCase):
    def test_deterministic_and_self_check(self):
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import build_nqmo_pyz
        a = build_nqmo_pyz.build_bytes(allow_untracked=True)
        b = build_nqmo_pyz.build_bytes(allow_untracked=True)
        self.assertEqual(a, b)
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "wg_nqmo.pyz")
            with open(p, "wb") as f:
                f.write(a)
            r = subprocess.run([sys.executable, "-I", p, "--check", "--config",
                                os.path.join(d, "absent.json")],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("NQMO_CHECK_OK", r.stdout)
        finally:
            shutil.rmtree(d)


class NqmoReviewArchiveTests(unittest.TestCase):
    """deploy/wg-nqmo-review.{sh,service,timer} (§29.158): the seven-day shadow
    review must not depend on the Mac being on. Family guard: the hourly summary
    is JSON with numbers and closed vocabularies only (no peer name, IP or key
    reaches the review log), a run is idempotent within its hour, the dry run
    writes nothing, and the units follow the repo's oneshot-timer conventions
    without a misplaced StartLimit key."""
    SH = os.path.join(ROOT, "deploy", "wg-nqmo-review.sh")

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        db = storemod.Store(os.path.join(self.d, "nqmo.db"))
        pid = db.peer_id("wg1udp", "alice-secret-name", "fp")
        db.conn.execute(
            "INSERT INTO diagnosis(ts,scope,subject,class,confidence,window_start,window_end,"
            "evidence_json,counter_evidence_json,alternatives_json,data_quality,mode,state) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), "PEER", str(pid), "PACKET_LOSS", "HIGH", 0, 300,
             '[{"metric":"group","value":"198.51.100.0/24"}]', "[]", "[]", "GOOD", "SHADOW",
             "OPEN"))
        db.put_peer_minute({"peer_id": pid, "ts": int(time.time()) - 60, "quality": "DEGRADED",
                            "quality_why": "S4:GAP:KERNEL_DROP"})
        db.conn.commit()
        db.close()
        with open(os.path.join(self.d, "state.json"), "w") as f:
            json.dump({"generated_at": time.time() - 7, "mode": "OBSERVATION_ONLY",
                       "collectors": {"C1_meta": True, "C3_capture": None},
                       "coverage": {"engine": {"cpu_pct": 1.5, "rss_mb": 40.0,
                                               "sampling": False},
                                    "peers_total": 3, "peers_handshake_180s": 1},
                       "errors": [{"where": "x"}],
                       "promotion": {"data_days": 0.5,
                                     "shadow_high_by_peer_7d": {"1": 2, "9": 1}},
                       "peers": [{"name": "alice-secret-name"}]}, f)

    def run_sh(self, **env):
        e = dict(os.environ, NR_STATE_DIR=self.d, **env)
        return subprocess.run(["bash", self.SH], env=e, capture_output=True, text=True,
                              timeout=60)

    def test_dry_run_prints_a_clean_summary_and_writes_nothing(self):
        r = self.run_sh(NR_DRY_RUN="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["diagnoses"], {"OPEN/SHADOW/PACKET_LOSS/HIGH": 1})
        self.assertEqual(out["promotion"], {"data_days": 0.5, "shadow_high_7d": 3})
        self.assertEqual((out["errors"], out["peers_active"], out["notify_outbox"]), (1, 1, 0))
        self.assertEqual(out["minute_quality_1h"], {"S4:GAP:KERNEL_DROP": 1})
        self.assertEqual(out["engine"]["cpu_pct"], 1.5)
        self.assertNotIn("alice", r.stdout)
        self.assertNotIn("198.51.100", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.d, "review")))

    def test_hourly_archive_is_idempotent_and_the_log_only_appends(self):
        r1, r2 = self.run_sh(), self.run_sh()
        self.assertEqual((r1.returncode, r2.returncode), (0, 0), r1.stderr + r2.stderr)
        rev = os.path.join(self.d, "review")
        gz = [f for f in os.listdir(rev) if f.startswith("state-") and f.endswith(".json.gz")]
        self.assertEqual(len(gz), 1, gz)                       # same hour ⇒ one file
        with open(os.path.join(rev, "summary.jsonl")) as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 2)
        for ln in lines:
            json.loads(ln)
        import gzip
        with gzip.open(os.path.join(rev, gz[0]), "rt") as f:
            self.assertEqual(json.load(f)["mode"], "OBSERVATION_ONLY")
        self.assertNotIn("alice", "\n".join(lines))

    def test_missing_state_is_an_error_not_a_silent_success(self):
        os.unlink(os.path.join(self.d, "state.json"))
        self.assertEqual(self.run_sh().returncode, 1)

    def test_a_locked_or_missing_database_still_yields_a_summary(self):
        os.unlink(os.path.join(self.d, "nqmo.db"))
        r = self.run_sh(NR_DRY_RUN="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("db_error", json.loads(r.stdout))

    def test_units_follow_the_oneshot_timer_conventions(self):
        parse = NqmoDeployUnitTests.parse
        svc = parse(read(os.path.join(ROOT, "deploy", "wg-nqmo-review.service")))
        tim = parse(read(os.path.join(ROOT, "deploy", "wg-nqmo-review.timer")))
        self.assertEqual(svc["Service"]["Type"], "oneshot")
        self.assertEqual((svc["Service"]["User"], svc["Service"]["Group"]), ("wg-nqmo", "wg-nqmo"))
        self.assertEqual(svc["Service"]["ExecStart"], "/usr/local/sbin/wg-nqmo-review.sh")
        self.assertFalse(NqmoDeployUnitTests.UNIT_ONLY & set(svc["Service"]))
        for key in ("Requires", "BindsTo", "PartOf", "Wants"):
            self.assertNotIn(key, svc["Unit"])
        self.assertNotIn("Install", svc)                      # only the timer is enabled
        self.assertEqual(tim["Timer"]["Unit"], "wg-nqmo-review.service")
        self.assertEqual(tim["Install"], {"WantedBy": "timers.target"})
        self.assertGreaterEqual(int(tim["Timer"]["OnBootSec"].rstrip("s")), 45)
        self.assertEqual(tim["Timer"]["Persistent"], "true")
        # the script's own header names its install path (drift-check convention)
        self.assertIn("deploy/wg-nqmo-review.sh → /usr/local/sbin/wg-nqmo-review.sh",
                      read(self.SH))


if __name__ == "__main__":
    unittest.main()
