import math


def normalize_score(raw: int) -> int:
    """Map a raw 0-100 style score to GTIC 1-10. Zero stays zero."""
    if raw <= 0:
        return 0
    return max(1, min(10, math.ceil(raw / 10.0)))


def normalize_cached_score(stored: int) -> int:
    """
    Normalize a value loaded from Redis/PostgreSQL that may be legacy 0-100 or already 1-10.
    Values greater than 10 are treated as legacy 0-100 and scaled down.
    """
    if stored <= 0:
        return 0
    if stored > 10:
        return max(1, min(10, math.ceil(stored / 10.0)))
    return max(1, min(10, stored))
