from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd

from src.feature_engineering import compute_behavioral_features


def create_baseline(df: pd.DataFrame) -> Dict[str, Any]:
    if df is None or df.empty:
        return {"status": "insufficient_data", "baseline": {}, "message": "Unable to establish a baseline from the supplied traffic."}

    features = compute_behavioral_features(df)
    return {
        "status": "ok",
        "baseline": features,
        "message": "Baseline created successfully.",
    }


def compare_against_baseline(current_features: Dict[str, float], baseline: Dict[str, float]) -> Dict[str, Any]:
    if not baseline:
        return {"changes": {}, "significant": False, "summary": "No baseline available."}

    changes: Dict[str, Any] = {}
    for key in sorted(set(current_features) | set(baseline)):
        current_value = float(current_features.get(key, 0.0) or 0.0)
        baseline_value = float(baseline.get(key, 0.0) or 0.0)
        delta = current_value - baseline_value
        percentage = 0.0
        if baseline_value != 0:
            percentage = (delta / abs(baseline_value)) * 100
        changes[key] = {
            "baseline": baseline_value,
            "current": current_value,
            "absolute_change": delta,
            "percentage_change": percentage,
        }

    significant = any(abs(change["percentage_change"]) > 50 for change in changes.values())
    return {"changes": changes, "significant": significant, "summary": "Significant behavioral deviation detected." if significant else "Current traffic remains close to baseline."}
