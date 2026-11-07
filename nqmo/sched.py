"""Single-threaded scheduler with per-task budgets, plus sd_notify.

Backpressure rule: a task whose run exceeded its budget skips its next slot
(recorded as a gap) instead of piling up. Exceptions are caught per task and
recorded; they never stop the loop.
"""
import os
import socket
import time


class Task:
    __slots__ = ("name", "period", "budget", "fn", "next_at", "skip_next",
                 "runs", "failures", "gaps", "max_ms", "last_error")

    def __init__(self, name, period, budget, fn, start_at=0.0):
        self.name = name
        self.period = float(period)
        self.budget = float(budget)
        self.fn = fn
        self.next_at = start_at
        self.skip_next = False
        self.reset_stats()

    def reset_stats(self):
        self.runs = 0
        self.failures = 0
        self.gaps = 0
        self.max_ms = 0.0
        self.last_error = ""


class Scheduler:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.tasks = []

    def add(self, name, period, budget, fn, start_at=None):
        t = Task(name, period, budget, fn,
                 self.clock() if start_at is None else start_at)
        self.tasks.append(t)
        return t

    def run_due(self):
        """Run every due task once. Returns the number of tasks run."""
        n = 0
        for t in self.tasks:
            now = self.clock()
            if now < t.next_at:
                continue
            t.next_at = now + t.period
            if t.skip_next:
                t.skip_next = False
                t.gaps += 1
                continue
            t0 = self.clock()
            try:
                t.fn()
            except Exception as e:          # isolate every task
                t.failures += 1
                t.last_error = "%s: %s" % (type(e).__name__, e)[:300]
            dt = self.clock() - t0
            t.runs += 1
            t.max_ms = max(t.max_ms, dt * 1000.0)
            if dt > t.budget:
                t.skip_next = True
            n += 1
        return n

    def sleep_hint(self, cap=1.0):
        now = self.clock()
        if not self.tasks:
            return cap
        return max(0.05, min(cap, min(t.next_at for t in self.tasks) - now))

    def health(self, reset=True):
        out = {}
        for t in self.tasks:
            out[t.name] = {"runs": t.runs, "failures": t.failures,
                           "gaps": t.gaps, "max_ms": round(t.max_ms, 1),
                           "last_error": t.last_error}
            if reset:
                t.reset_stats()
        return out


def sd_notify(msg, env=None):
    """Send a systemd notification; silently a no-op outside systemd."""
    addr = (env if env is not None else os.environ).get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.send(msg.encode("ascii"))
        return True
    except OSError:
        return False
