"""Engine configuration: conservative defaults + strict validation.

Unknown keys, wrong types and out-of-range values are rejected — a typo must
never silently fall back to a default that changes behaviour. On SIGHUP the
caller keeps the previous config when validate() raises.
"""
import copy
import json
import re

MODES = ("OBSERVATION_ONLY", "DIAGNOSTICS_ENABLED", "RECOMMENDATIONS_ENABLED")

IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,14}$")

DEFAULTS = {
    "mode": "OBSERVATION_ONLY",
    "active_probes": False,
    "capture": {
        "enabled": False,
        "wan_iface": "eth0",
        "user_iface": "wg1udp",
        "listen_port": 53953,
        "ring_block_kb": 256,
        "ring_blocks": 16,
        "s4_cpu_pct_max": 15.0,
    },
    "paths": {
        "meta": "/run/wg-panel/nqmo-meta.json",
        "state": "/var/lib/wg-nqmo/state.json",
        "db": "/var/lib/wg-nqmo/nqmo.db",
        "secret": "/var/lib/wg-nqmo/secret",
        "asn_dir": "/var/lib/wg-nqmo/asn",
        "ctl": "/run/wg-nqmo/ctl.sock",
    },
    "intervals": {
        "meta_s": 10,
        "export_s": 60,
        "prune_s": 3600,
    },
    "limits": {
        "meta_stale_s": 180,
        "max_db_mb": 512,
        "queue_max": 20000,
        "frag_table_max": 10000,
        "pending_hs_max": 4096,
    },
    "retention_days": {
        "minute": 14,
        "hour": 400,
        "events": 183,
        "endpoint_ctx": 30,
        "hour_ctx_coarsen": 30,
    },
}

# (min, max) for numeric leaves; anything numeric not listed must be > 0.
RANGES = {
    ("capture", "listen_port"): (1, 65535),
    ("capture", "ring_block_kb"): (16, 4096),
    ("capture", "ring_blocks"): (2, 128),
    ("capture", "s4_cpu_pct_max"): (1.0, 100.0),
    ("intervals", "meta_s"): (5, 300),
    ("intervals", "export_s"): (10, 600),
    ("intervals", "prune_s"): (300, 86400),
    ("limits", "meta_stale_s"): (30, 3600),
    ("limits", "max_db_mb"): (16, 8192),
    ("limits", "queue_max"): (100, 1000000),
    ("limits", "frag_table_max"): (100, 1000000),
    ("limits", "pending_hs_max"): (16, 100000),
}


class ConfigError(ValueError):
    pass


def _merge(base, over, path):
    if not isinstance(over, dict):
        raise ConfigError("%s: expected object" % "/".join(path or ["<root>"]))
    out = copy.deepcopy(base)
    for k, v in over.items():
        if k not in base:
            raise ConfigError("unknown key: %s" % "/".join(path + [k]))
        if isinstance(base[k], dict):
            out[k] = _merge(base[k], v, path + [k])
        else:
            out[k] = v
    return out


def _check_leaf(path, default, value):
    name = "/".join(path)
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ConfigError("%s: expected boolean" % name)
        return
    if isinstance(default, (int, float)):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError("%s: expected number" % name)
        if isinstance(default, int) and not isinstance(value, int):
            raise ConfigError("%s: expected integer" % name)
        lo, hi = RANGES.get(tuple(path), (None, None))
        if lo is not None and not lo <= value <= hi:
            raise ConfigError("%s: out of range [%s, %s]" % (name, lo, hi))
        if lo is None and value <= 0:
            raise ConfigError("%s: must be > 0" % name)
        return
    if isinstance(default, str):
        if not isinstance(value, str) or not value:
            raise ConfigError("%s: expected non-empty string" % name)
        return
    raise ConfigError("%s: unsupported type" % name)


def _walk(default, value, path):
    for k, d in default.items():
        if isinstance(d, dict):
            _walk(d, value[k], path + [k])
        else:
            _check_leaf(path + [k], d, value[k])


def validate(raw):
    """Return a full, validated config dict built from DEFAULTS + raw."""
    cfg = _merge(DEFAULTS, raw if raw is not None else {}, [])
    _walk(DEFAULTS, cfg, [])
    if cfg["mode"] not in MODES:
        raise ConfigError("mode: must be one of %s" % ", ".join(MODES))
    for key in ("wan_iface", "user_iface"):
        if not IFACE_RE.match(cfg["capture"][key]):
            raise ConfigError("capture/%s: invalid interface name" % key)
    if cfg["capture"]["ring_block_kb"] % 4:
        raise ConfigError("capture/ring_block_kb: must be a multiple of 4 (page-aligned)")
    for key, p in cfg["paths"].items():
        if not p.startswith("/"):
            raise ConfigError("paths/%s: must be absolute" % key)
    if cfg["active_probes"] and cfg["mode"] != "RECOMMENDATIONS_ENABLED":
        raise ConfigError("active_probes requires mode RECOMMENDATIONS_ENABLED")
    return cfg


def load(path):
    """Read and validate a config file; a missing file means all defaults."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raw = {}
    except (OSError, ValueError) as e:
        raise ConfigError("cannot read %s: %s" % (path, e))
    return validate(raw)


def adjacent_mode(cur, to):
    """mode.set may move exactly one step, either direction."""
    if cur not in MODES or to not in MODES:
        return False
    return abs(MODES.index(cur) - MODES.index(to)) == 1
