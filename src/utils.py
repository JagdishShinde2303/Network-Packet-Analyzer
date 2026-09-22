import hashlib
import math
import os
from typing import Any, Iterable


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    if denominator in (None, 0):
        return default
    try:
        return float(numerator) / float(denominator)
    except (TypeError, ValueError):
        return default


def normalize_ratio(value: float) -> float:
    return max(0.0, min(1.0, safe_float(value, 0.0)))


def project_hash(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def ensure_directory(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def clamp(value: float, lower: float = 0.0, upper: float = 100.0) -> float:
    if math.isnan(value):
        return lower
    return max(lower, min(upper, value))


def boolean_to_label(value: bool) -> str:
    return "ANOMALOUS" if value else "NORMAL"


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]
