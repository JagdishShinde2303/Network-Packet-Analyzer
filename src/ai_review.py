from __future__ import annotations

from typing import Any, Dict, List


def generate_ai_review(classification: str, anomaly_score: float, risk_score: float, deviation_summary: List[str]) -> Dict[str, Any]:
    observed = deviation_summary if deviation_summary else [
        "Current traffic differs from the established baseline.",
        "This behavioral deviation requires further investigation."
    ]

    review = {
        "classification": str(classification).upper(),
        "anomaly_score": float(anomaly_score),
        "risk_score": float(risk_score),
        "severity": "HIGH" if risk_score >= 75 else "MEDIUM" if risk_score >= 50 else "LOW" if risk_score >= 25 else "INFO",
        "observed_deviations": observed,
        "interpretation": "The observed communication behavior differs significantly from the established device fingerprint and requires further investigation.",
        "recommendation": "Review the destination addresses, ports and traffic timing to determine whether the behavior is expected.",
        "note": "An anomaly does not automatically prove malicious activity; it indicates a behavioral deviation that should be investigated.",
    }
    return review
