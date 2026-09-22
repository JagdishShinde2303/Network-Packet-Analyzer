from src.fingerprint import communication_fingerprint, fingerprint_id


def test_fingerprint_id_is_generated_with_project_scope():
    fp = fingerprint_id("192.168.1.15")
    assert isinstance(fp, str)
    assert len(fp) >= 6


def test_communication_fingerprint_has_expected_sections():
    data = {
        "packets_per_second": 10,
        "bytes_per_second": 1000,
        "average_packet_size": 200,
        "unique_destination_ips": 4,
        "unique_destination_ports": 3,
        "unique_source_ports": 2,
        "tcp_ratio": 0.5,
        "udp_ratio": 0.4,
        "icmp_ratio": 0.1,
        "dns_activity": 0.2,
        "connection_count": 12,
        "protocol_diversity": 3,
        "destination_diversity": 0.4,
        "port_diversity": 0.5,
    }

    fingerprint = communication_fingerprint("192.168.1.15", data)
    assert "192.168.1.15" in fingerprint["device"]
    assert "Communication Fingerprint" in fingerprint["title"]
    assert "identifier" in fingerprint
    assert "overview" in fingerprint
    assert "metrics" in fingerprint
