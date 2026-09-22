from __future__ import annotations

from typing import Dict

from src.utils import clamp


def calculate_risk_score(
    anomaly_score: float,
    packet_rate_deviation: float,
    byte_rate_deviation: float,
    destination_diversity: float,
    port_diversity: float,
    connection_frequency: float,
    protocol_deviation: float,
) -> float:
    anomaly_component = clamp(float(anomaly_score) * 25, 0.0, 30.0)
    packet_component = clamp(float(packet_rate_deviation) * 20, 0.0, 18.0)
    byte_component = clamp(float(byte_rate_deviation) * 20, 0.0, 18.0)
    destination_component = clamp(float(destination_diversity) * 15, 0.0, 12.0)
    port_component = clamp(float(port_diversity) * 15, 0.0, 12.0)
    connection_component = clamp(float(connection_frequency) * 10, 0.0, 8.0)
    protocol_component = clamp(float(protocol_deviation) * 10, 0.0, 10.0)

    total = anomaly_component + packet_component + byte_component + destination_component + port_component + connection_component + protocol_component
    return round(clamp(total, 0.0, 100.0), 2)


def severity_from_score(score: float) -> str:
    value = float(score)
    if value <= 24:
        return "INFO"
    if value <= 49:
        return "LOW"
    if value <= 74:
        return "MEDIUM"
    return "HIGH"


def network_health_score(risk_score: float) -> float:
    return round(clamp(100.0 - float(risk_score), 0.0, 100.0), 2)
