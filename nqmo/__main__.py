"""python3 -I /opt/wg-nqmo/wg_nqmo.pyz --check | --run [--config PATH]

--check is the pre-restart self-test (like wg_panel.py --check): it needs no
root, no Linux and touches nothing outside a temporary directory. It prints
NQMO_CHECK_OK only when every check passed.
"""
import argparse
import os
import sys
import tempfile

DEFAULT_CONFIG = "/etc/wg-nqmo/config.json"


def self_check(config_path):
    from . import VERSION, config, runner, store
    from .aggregate import Aggregator, KeypairTrack, COUNTER_WINDOW
    from .collect import bpf, wgparse, meta

    problems = []
    try:
        cfg = config.load(config_path) if config_path and os.path.exists(config_path) \
            else config.validate({})
    except config.ConfigError as e:
        problems.append("config: %s" % e)
        cfg = config.validate({})
    for name, p in bpf.PROGRAMS.items():
        ins = p["insns"]
        if not 0 < len(ins) <= 4096:
            problems.append("bpf %s: bad length" % name)
        if any(code == 0x06 and k not in (0, p["snaplen"]) for code, _a, _b, k in ins):
            problems.append("bpf %s: accept return != snaplen" % name)
    for bad in (["wg", "set", "wg1udp"], ["tc", "qdisc", "del"], ["sh", "-c", "x"]):
        try:
            runner.match(bad)
            problems.append("runner accepted %r" % bad)
        except runner.NotAllowed:
            pass
    with tempfile.TemporaryDirectory() as d:
        s = store.Store(os.path.join(d, "t.db"))
        if s.read_only:
            problems.append("store opened read-only")
        s.close()
    t = KeypairTrack(0, 0.0)
    for c in list(range(1, 100)) + [150]:
        t.add(c, 0.0)
    t.finalize()
    if (t.ok, t.lost) != (101, 50):
        problems.append("loss accounting self-test: %r" % ((t.ok, t.lost),))
    if wgparse.parse_wg(b"\x45" + b"\x00" * 10) is not None:
        problems.append("parser accepted a short frame")
    try:
        meta.parse('{"generated_at":1,"client_mtu":1392,"wg1udp":{"mtu":1392},'
                   '"peers":{},"egress":{},"private_key":"x"}')
        problems.append("meta accepted a secret-shaped key")
    except meta.MetaError:
        pass
    _ = Aggregator(b"\0" * 32), COUNTER_WINDOW
    for p in problems:
        print("NQMO_CHECK_FAIL", p)
    if problems:
        return 1
    print("NQMO_CHECK_OK", VERSION, "mode=%s" % cfg["mode"])
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wg-nqmo")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--run", action="store_true")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    a = ap.parse_args(argv)
    if a.check:
        return self_check(a.config)
    from . import config
    from .engine import Engine
    try:
        cfg = config.load(a.config)
    except config.ConfigError as e:
        print("config error:", e, file=sys.stderr)
        return 2
    lock = single_instance(cfg["paths"]["db"] + ".lock")
    if lock is None:
        print("another wg-nqmo engine already runs on %s" % cfg["paths"]["db"], file=sys.stderr)
        return 3
    Engine(cfg, a.config).run_forever()
    return 0


def single_instance(path):
    """Exclusive, non-blocking flock held for the life of the process (the fd
    is returned and must stay referenced). None if another engine holds it.

    Two engines on one DB double-capture, steal each other's ctl.sock and
    can open the same episode twice — two diagnoses, two notify messages
    (lab, 28 Oct: a manual --run beside a running one). The kernel drops the
    lock when the process dies, so a crash never leaves it stale."""
    import fcntl
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


if __name__ == "__main__":
    sys.exit(main())
