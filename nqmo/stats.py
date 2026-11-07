"""Small, dependency-free statistics used by the diagnostic rules."""
import math

Z95 = 1.959963984540054


def wilson(k, n, z=Z95):
    """Wilson score interval for k successes in n trials → (lo, hi).

    Used for loss: k = lost, n = judged. A rule fires on the LOWER bound, so
    a handful of losses in a small sample never crosses a threshold.
    """
    if n <= 0:
        return 0.0, 1.0
    if k <= 0:
        return 0.0, wilson_upper_zero(n, z)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - r) / d), min(1.0, (c + r) / d)


def wilson_upper_zero(n, z=Z95):
    """Upper bound for k = 0 (lower bound is exactly 0)."""
    return (z * z / n) / (1 + z * z / n)


def median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return None
    m = n // 2
    return float(s[m]) if n % 2 else (s[m - 1] + s[m]) / 2.0


def mad(xs, med=None):
    """Median absolute deviation (unscaled)."""
    if not xs:
        return None
    med = median(xs) if med is None else med
    return median([abs(x - med) for x in xs])
