import pandas as pd

from src.feature_engineering import compute_behavioral_features, summarize_traffic


def test_compute_behavioral_features_returns_expected_fields():
    df = pd.DataFrame(
        {
            "time": [1.0, 1.2, 2.0, 2.5],
            "src_ip": ["192.168.1.10"] * 4,
            "dst_ip": ["8.8.8.8", "1.1.1.1", "8.8.8.8", "4.4.4.4"],
            "dst_port": [53, 443, 53, 80],
            "src_port": [12345, 50000, 12346, 50001],
            "protocol": ["UDP", "TCP", "UDP", "TCP"],
            "length": [128, 256, 96, 512],
        }
    )

    features = compute_behavioral_features(df)
    expected = {
        "packets_per_second",
        "bytes_per_second",
        "average_packet_size",
        "unique_destination_ips",
        "unique_destination_ports",
        "unique_source_ports",
        "tcp_ratio",
        "udp_ratio",
        "icmp_ratio",
        "connection_count",
        "protocol_diversity",
        "destination_diversity",
        "port_diversity",
    }
    assert expected.issubset(features.keys())
    assert features["packets_per_second"] >= 0
    assert features["average_packet_size"] > 0


def test_summarize_traffic_handles_small_input():
    df = pd.DataFrame(
        {
            "time": [1.0, 2.0],
            "src_ip": ["192.168.1.10", "192.168.1.20"],
            "dst_ip": ["8.8.8.8", "8.8.8.8"],
            "dst_port": [53, 53],
            "src_port": [12345, 12346],
            "protocol": ["UDP", "UDP"],
            "length": [128, 256],
        }
    )
    summary = summarize_traffic(df)
    assert summary["total_packets"] == 2
    assert summary["total_bytes"] == 384
    assert summary["duration_seconds"] >= 1
