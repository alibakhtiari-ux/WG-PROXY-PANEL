"""Confidence table + hysteresis (design 04 §2 R-HYST-1, §3).

History is a list of per-window outcome summaries, newest last:
    {"w": window_start, "p": True/False/None, "s": DIRECT/INDIRECT,
     "q": GOOD/DEGRADED/INVALID, "c": has_counter_evidence, "cap": level|None}
Only tumbling (non-overlapping) windows are ever appended, so "3 windows" is
three independent observations.
"""
LEVELS = ("INSUFFICIENT_EVIDENCE", "LOW", "MEDIUM", "HIGH")
LOOKBACK = 6            # windows considered for the level
OPEN_AFTER = 2          # consecutive positive windows
CLEAR_AFTER = 3         # consecutive negative windows
STALE_AFTER = 12        # consecutive n/a windows close an OPEN diagnosis
HISTORY_MAX = 24


def _rank(level):
    return LEVELS.index(level)


def cap_level(level, cap):
    if cap is None:
        return level
    return LEVELS[min(_rank(level), _rank(cap))]


def step_down(level):
    return LEVELS[max(1, _rank(level) - 1)] if _rank(level) > 0 else level


def level(history, min_total_high=None):
    """min_total_high: a class-specific floor on the summed sample count of
    the positive windows (e.g. ≥20 first fragments for class 10)."""
    recent = history[-LOOKBACK:]
    pos = [h for h in recent if h["p"] is True]
    if not pos:
        return "INSUFFICIENT_EVIDENCE"
    direct = [h for h in pos if h["s"] == "DIRECT"]
    direct_good = [h for h in direct if h["q"] == "GOOD"]
    indirect = [h for h in pos if h["s"] != "DIRECT"]
    if len(direct_good) >= 3:
        lv = "HIGH"
    elif len(direct) >= 3:
        lv = "MEDIUM"                       # HIGH evidence, but degraded data
    elif len(direct) >= 2 or len(indirect) >= 3:
        lv = "MEDIUM"
    else:
        lv = "LOW"
    latest = pos[-1]
    if lv == "HIGH" and min_total_high and sum(h.get("n") or 0 for h in pos) < min_total_high:
        lv = "MEDIUM"
    if any(h["c"] for h in pos[-3:]):
        lv = cap_level(lv, "LOW")           # active counter-evidence ⇒ LOW (04 §3)
    caps = [h["cap"] for h in pos if h["cap"]]
    for c in caps:
        lv = cap_level(lv, c)
    if latest["q"] != "GOOD" and lv == "HIGH":
        lv = "MEDIUM"
    return lv


def transition(history, is_open):
    """→ "OPEN" | "CLEAR" | "STALE" | None for the newest window."""
    if not is_open:
        tail = history[-OPEN_AFTER:]
        if len(tail) == OPEN_AFTER and all(h["p"] is True for h in tail):
            return "OPEN"
        return None
    # CLEAR: the last CLEAR_AFTER windows that carried a verdict were negative
    # (n/a windows in between are skipped, so a sparse peer can still clear);
    # STALE: no positive at all in the last STALE_AFTER windows (review round 4)
    judged = [h for h in history if h["p"] is not None]
    if len(judged) >= CLEAR_AFTER and all(h["p"] is False for h in judged[-CLEAR_AFTER:]):
        return "CLEAR"
    tail = history[-STALE_AFTER:]
    if len(tail) == STALE_AFTER and not any(h["p"] is True for h in tail):
        return "STALE"
    return None


def summarize(outcome, window):
    return {"w": window, "p": outcome.positive, "s": outcome.strength,
            "q": outcome.quality, "c": bool(outcome.counter), "cap": outcome.cap,
            "n": getattr(outcome, "n", None)}
