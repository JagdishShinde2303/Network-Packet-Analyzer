from __future__ import annotations

from typing import Any, Dict

import pandas as pd

from src.utils import safe_divide, clamp


FEATURE_COLUMNS = [
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "unique_source_ips",
    "unique_destination_ips",
    "unique_destination_ports",
    "unique_source_ports",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "dns_activity",
    "connection_count",
    "protocol_diversity",
    "destination_diversity",
    "port_diversity",
]


def summarize_traffic(df: pd.DataFrame) -> Dict[str, Any]:
    if df is None or df.empty:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "duration_seconds": 0.0,
            "packets_per_second": 0.0,
            "bytes_per_second": 0.0,
            "top_source_ips": [],
            "top_destination_ips": [],
            "top_destination_ports": [],
            "protocol_distribution": {},
            "dns_observations": 0,
        }

    total_packets = int(len(df))
    total_bytes = int(df["length"].sum())
    duration = float(max(df["time"].max() - df["time"].min(), 0.0))
    if duration <= 0:
        duration = 1.0

    protocol_distribution = df["protocol"].fillna("UNKNOWN").astype(str).str.upper().value_counts().to_dict()
    top_source_ips = df["src_ip"].astype(str).value_counts().head(5).to_dict()
    top_destination_ips = df["dst_ip"].astype(str).value_counts().head(5).to_dict()
    top_destination_ports = df["dst_port"].dropna().astype(int).value_counts().head(5).to_dict()

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": duration,
        "packets_per_second": safe_divide(total_packets, duration),
        "bytes_per_second": safe_divide(total_bytes, duration),
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "top_destination_ports": top_destination_ports,
        "protocol_distribution": protocol_distribution,
        "dns_observations": int(((df["dst_port"] == 53) | (df["src_port"] == 53)).sum()),
    }


def compute_behavioral_features(df: pd.DataFrame) -> Dict[str, float]:
    if df is None or df.empty:
        return {
            feature: 0.0 for feature in FEATURE_COLUMNS
        }

    total_packets = len(df)
    total_bytes = float(df["length"].sum())
    duration = max(float(df["time"].max() - df["time"].min()), 1.0)
    if duration <= 0:
        duration = 1.0

    unique_source_ips = df["src_ip"].replace("", pd.NA).dropna().nunique()
    unique_destination_ips = df["dst_ip"].replace("", pd.NA).dropna().nunique()
    unique_destination_ports = df["dst_port"].dropna().nunique()
    unique_source_ports = df["src_port"].dropna().nunique()

    protocol_counts = df["protocol"].fillna("UNKNOWN").astype(str).str.upper().value_counts()
    tcp_count = int(protocol_counts.get("TCP", 0))
    udp_count = int(protocol_counts.get("UDP", 0))
    icmp_count = int(protocol_counts.get("ICMP", 0))
    dns_count = int(((df["dst_port"] == 53) | (df["src_port"] == 53)).sum())

    features = {
        "packets_per_second": safe_divide(total_packets, duration),
        "bytes_per_second": safe_divide(total_bytes, duration),
        "average_packet_size": safe_divide(total_bytes, total_packets),
        "unique_source_ips": float(unique_source_ips),
        "unique_destination_ips": float(unique_destination_ips),
        "unique_destination_ports": float(unique_destination_ports),
        "unique_source_ports": float(unique_source_ports),
        "tcp_ratio": safe_divide(tcp_count, total_packets),
        "udp_ratio": safe_divide(udp_count, total_packets),
        "icmp_ratio": safe_divide(icmp_count, total_packets),
        "dns_activity": safe_divide(dns_count, total_packets),
        "connection_count": float(total_packets),
        "protocol_diversity": float(protocol_counts.nunique()),
        "destination_diversity": safe_divide(unique_destination_ips, max(unique_source_ips, 1)),
        "port_diversity": safe_divide(unique_destination_ports, max(unique_source_ports, 1)),
    }

    for key, value in features.items():
        features[key] = clamp(float(value), 0.0, 1_000_000.0)

    return features


def feature_vector_from_df(df: pd.DataFrame) -> list[float]:
    features = compute_behavioral_features(df)
    return [
        features["packets_per_second"],
        features["bytes_per_second"],
        features["unique_source_ips"],
        features["unique_destination_ips"],
        features["unique_destination_ports"],
        features["tcp_ratio"],
        features["udp_ratio"],
        features["icmp_ratio"],
        features["average_packet_size"],
        features["connection_count"],
        features["protocol_diversity"],
        features["destination_diversity"],
        features["port_diversity"],
    ]
