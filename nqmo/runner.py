"""The ONLY place nqmo launches a process.

Every argv is matched against a fixed allowlist of read-only templates before
exec; anything else raises NotAllowed. No shell, fixed PATH, C locale.
tests/test_nqmo.py (NqmoNoMutationTests) fails if subprocess is imported
anywhere else in the package, or if a template contains a mutating verb.
"""
import ipaddress
import os
import re
import subprocess

from .config import IFACE_RE

SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
SYS_NET = "/sys/class/net"

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]{1,8}$")
_INT_RE = re.compile(r"^[0-9]{1,5}$")


class NotAllowed(ValueError):
    pass


def _iface(tok):
    if not IFACE_RE.match(tok):
        return False
    # On the server the interface must exist; off-Linux (tests) the name
    # pattern alone is checked.
    if os.path.isdir(SYS_NET):
        return os.path.exists(os.path.join(SYS_NET, tok))
    return True


def _ipv4(tok):
    try:
        return str(ipaddress.IPv4Address(tok)) == tok
    except ValueError:
        return False


def _int_in(lo, hi):
    def check(tok):
        return bool(_INT_RE.match(tok)) and lo <= int(tok) <= hi
    return check


def _lit(word):
    return lambda tok: tok == word


def _one_of(*words):
    return lambda tok: tok in words


# Each template is a list of token predicates; OPTIONAL groups are tried as a
# unit at the tail. Verbs are only ever "show" / "get".
TEMPLATES = {
    "tc_show": [_lit("tc"), _lit("-s"), _lit("-j"),
                _one_of("qdisc", "class", "filter"), _lit("show"),
                _lit("dev"), _iface],
    "ip_link_show": [_lit("ip"), _lit("-j"), _lit("-d"), _lit("link"),
                     _lit("show")],
    "ip_nexthop_show": [_lit("ip"), _lit("-j"), _lit("nexthop"), _lit("show")],
    "ip_route_get": [_lit("ip"), _lit("-j"), _lit("route"), _lit("get"), _ipv4],
}

# The manual active probe (04 §7). It is matched ONLY when the caller passes
# allow_probe=True, and the only caller allowed to do so is nqmo/probe.py
# after every gate (mode, active_probes, RBAC via ctl, rate limits) passed —
# tests/test_nqmo.py fails if any other module passes allow_probe.
_SIZE = lambda t: t == "56" or (bool(_INT_RE.match(t)) and 1232 <= int(t) <= 1472)
PROBE_TEMPLATES = {
    "ping_probe": [_lit("ping"), _lit("-4"), _lit("-n"), _lit("-q"),
                   _lit("-M"), _lit("do"), _lit("-s"), _SIZE,
                   _lit("-c"), _int_in(1, 3), _lit("-W"), _lit("1"),
                   _lit("-I"), _iface, _ipv4],
}
# optional tails per template: list of [predicates...]
OPTIONAL_TAILS = {
    "ip_route_get": [[_lit("from"), _ipv4], [_lit("mark"),
                                             lambda t: bool(_HEX_RE.match(t))]],
}


def match(argv, allow_probe=False):
    """Return the template name argv matches, or raise NotAllowed."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise NotAllowed("argv must be a non-empty list")
    if not all(isinstance(t, str) for t in argv):
        raise NotAllowed("argv tokens must be strings")
    templates = dict(TEMPLATES)
    if allow_probe:
        templates.update(PROBE_TEMPLATES)
    for name, preds in templates.items():
        if len(argv) < len(preds):
            continue
        if not all(p(t) for p, t in zip(preds, argv)):
            continue
        rest = list(argv[len(preds):])
        tails = list(OPTIONAL_TAILS.get(name, []))
        ok = True
        while rest and ok:
            for i, tail in enumerate(tails):
                if (len(rest) >= len(tail)
                        and all(p(t) for p, t in zip(tail, rest))):
                    rest = rest[len(tail):]
                    tails.pop(i)
                    break
            else:
                ok = False
        if ok and not rest:
            return name
    raise NotAllowed("argv not in allowlist: %r" % (list(argv),))


def run_ro(argv, timeout=10, allow_probe=False):
    """Run an allowlisted read-only command. Returns (rc, stdout, stderr).

    rc == -1 with stderr "timeout" on timeout; never raises for process errors.
    """
    match(argv, allow_probe=allow_probe)
    try:
        p = subprocess.run(list(argv), capture_output=True, text=True,
                           timeout=timeout, env=SAFE_ENV, shell=False,
                           stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as e:
        return -1, "", str(e)
