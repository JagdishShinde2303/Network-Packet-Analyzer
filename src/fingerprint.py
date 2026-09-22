from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from src.utils import safe_divide


def fingerprint_id(device: str) -> str:
    raw = hashlib.md5(device.encode("utf-8")).hexdigest()
    return f"{raw[:2]}-{raw[2:4]}-{raw[4:6]}".upper()


def _bar(percent: float, width: int = 10) -> str:
    filled = int(max(0, min(width, round(percent / 10.0))))
    return "█" * filled + " " * (width - filled)


def communication_fingerprint(device: str, metrics: Dict[str, Any]) -> Dict[str, Any]:
    device_name = str(device or "UNKNOWN DEVICE")

    overview = [
        {"label": "HTTPS usage", "percent": round(float(metrics.get("tcp_ratio", 0.0)) * 100, 1), "bar": _bar(float(metrics.get("tcp_ratio", 0.0)) * 100)},
        {"label": "DNS activity", "percent": round(float(metrics.get("dns_activity", 0.0)) * 100, 1), "bar": _bar(float(metrics.get("dns_activity", 0.0)) * 100)},
        {"label": "Destination diversity", "percent": round(float(metrics.get("destination_diversity", 0.0)) * 100, 1), "bar": _bar(float(metrics.get("destination_diversity", 0.0)) * 100)},
        {"label": "Port diversity", "percent": round(float(metrics.get("port_diversity", 0.0)) * 100, 1), "bar": _bar(float(metrics.get("port_diversity", 0.0)) * 100)},
        {"label": "Packet rate", "percent": round(safe_divide(float(metrics.get("packets_per_second", 0.0)), 50.0) * 100, 1), "bar": _bar(safe_divide(float(metrics.get("packets_per_second", 0.0)), 50.0) * 100)},
    ]

    return {
        "device": f"Device: {device_name}",
        "title": "Communication Fingerprint",
        "identifier": fingerprint_id(device_name),
        "overview": overview,
        "metrics": {
            "packets_per_second": float(metrics.get("packets_per_second", 0.0)),
            "bytes_per_second": float(metrics.get("bytes_per_second", 0.0)),
            "avg_packet_size": float(metrics.get("average_packet_size", 0.0)),
            "unique_destination_ips": float(metrics.get("unique_destination_ips", 0.0)),
            "unique_destination_ports": float(metrics.get("unique_destination_ports", 0.0)),
            "tcp_ratio": float(metrics.get("tcp_ratio", 0.0)),
            "udp_ratio": float(metrics.get("udp_ratio", 0.0)),
            "dns_activity": float(metrics.get("dns_activity", 0.0)),
        },
    }
