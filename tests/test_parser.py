import pandas as pd

from src.packet_parser import build_traffic_dataframe, parse_packets


def test_parse_packets_generates_metadata_for_supported_packets():
    packets = [
        {
            "time": 1.0,
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 12345,
            "dst_port": 53,
            "protocol": "UDP",
            "length": 128,
        },
        {
            "time": 1.5,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.1",
            "src_port": 443,
            "dst_port": 60000,
            "protocol": "TCP",
            "length": 256,
        },
    ]

    df = build_traffic_dataframe(parse_packets(packets))
    assert not df.empty
    assert {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length"}.issubset(df.columns)
    assert df["protocol"].isin(["UDP", "TCP"]).all()


def test_parse_packets_handles_empty_input():
    df = build_traffic_dataframe(parse_packets([]))
    assert isinstance(df, pd.DataFrame)
    assert df.empty
