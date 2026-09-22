from __future__ import annotations

from typing import Any, Iterable, List
import pandas as pd

from src.utils import safe_float


def _extract_ip(packet: Any, field: str) -> str:
    if hasattr(packet, "src") and field == "src":
        return getattr(packet, "src")
    if hasattr(packet, "dst") and field == "dst":
        return getattr(packet, "dst")
    return ""


def _extract_ports(packet: Any) -> tuple[int | None, int | None]:
    src_port = None
    dst_port = None
    if hasattr(packet, "sport"):
        src_port = getattr(packet, "sport")
    if hasattr(packet, "dport"):
        dst_port = getattr(packet, "dport")
    return src_port, dst_port


def _extract_protocol(packet: Any) -> str:
    if hasattr(packet, "haslayer"):
        if packet.haslayer("TCP"):
            return "TCP"
        if packet.haslayer("UDP"):
            return "UDP"
        if packet.haslayer("ICMP"):
            return "ICMP"
        if packet.haslayer("DNS"):
            return "DNS"
    if isinstance(packet, dict):
        proto = packet.get("protocol")
        if proto:
            return str(proto).upper()
    return "UNKNOWN"


def parse_packets(packets: Iterable[Any]) -> List[dict]:
    records: List[dict] = []
    for packet in packets:
        if packet is None:
            continue

        record: dict[str, Any] = {
            "time": 0.0,
            "src_ip": "",
            "dst_ip": "",
            "src_port": None,
            "dst_port": None,
            "protocol": "UNKNOWN",
            "length": 0,
        }

        if isinstance(packet, dict):
            record["time"] = safe_float(packet.get("time"), 0.0)
            record["src_ip"] = str(packet.get("src_ip", ""))
            record["dst_ip"] = str(packet.get("dst_ip", ""))
            record["src_port"] = packet.get("src_port")
            record["dst_port"] = packet.get("dst_port")
            record["protocol"] = str(packet.get("protocol", "UNKNOWN")).upper() or "UNKNOWN"
            record["length"] = int(packet.get("length", 0) or 0)
            records.append(record)
            continue

        if hasattr(packet, "time"):
            record["time"] = safe_float(getattr(packet, "time"), 0.0)
        if hasattr(packet, "src"):
            record["src_ip"] = str(getattr(packet, "src"))
        if hasattr(packet, "dst"):
            record["dst_ip"] = str(getattr(packet, "dst"))

        src_port, dst_port = _extract_ports(packet)
        record["src_port"] = src_port
        record["dst_port"] = dst_port
        record["protocol"] = _extract_protocol(packet)

        try:
            record["length"] = len(bytes(packet)) if hasattr(packet, "__bytes__") else 0
        except Exception:
            record["length"] = 0

        if record["src_ip"] or record["dst_ip"] or record["protocol"] != "UNKNOWN":
            records.append(record)

    return records


def build_traffic_dataframe(records: Iterable[dict]) -> pd.DataFrame:
    if records is None:
        records = []

    df = pd.DataFrame(records)
    required_columns = [
        "time",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "length",
    ]

    for column in required_columns:
        if column not in df.columns:
            df[column] = None

    df = df[required_columns].copy()
    df["time"] = pd.to_numeric(df["time"], errors="coerce").fillna(0.0)
    df["src_ip"] = df["src_ip"].fillna("").astype(str)
    df["dst_ip"] = df["dst_ip"].fillna("").astype(str)
    df["protocol"] = df["protocol"].fillna("UNKNOWN").astype(str).str.upper()
    df["length"] = pd.to_numeric(df["length"], errors="coerce").fillna(0).astype(int)
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    return df
