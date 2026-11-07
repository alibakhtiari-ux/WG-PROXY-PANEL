"""state.json — the only thing the panel reads from nqmo (atomic replace).

It carries engine health, coverage, and the analysis snapshot (open
diagnoses, notify_outbox, recommendations, advisories, correlations).
"""
import json
import os
import tempfile

from . import STATE_SCHEMA, VERSION


ANALYSIS_KEYS = ("diagnoses", "notify_outbox", "recommendations", "advisories",
                 "correlations", "groups_eligible", "last_window", "probe", "promotion",
                 "peers")


def build_state(now, mode, collectors, coverage, errors, store_info, analysis=None):
    """Final state.json shape (the panel reader is built against this).
    No IP addresses, keys or endpoints appear here; peers are named by the
    panel's own peer name; groups by ASN or /24–/16 prefix."""
    analysis = analysis or {}
    st = {
        "schema": STATE_SCHEMA,
        "version": VERSION,
        "generated_at": round(now, 3),
        "mode": mode,
        "collectors": collectors,
        "coverage": coverage,
        "store": store_info,
        "errors": errors[-20:],
    }
    for k in ANALYSIS_KEYS:
        st[k] = analysis.get(k, [] if k in ("diagnoses", "notify_outbox", "advisories",
                                            "correlations", "peers") else None)
    return st


def write_atomic(path, obj, mode=0o640):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".state.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)                    # mode on tmp, before the rename
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
