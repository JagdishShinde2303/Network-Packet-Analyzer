from src.risk_scoring import calculate_risk_score, severity_from_score


def test_risk_score_is_normalized():
    score = calculate_risk_score(
        anomaly_score=0.9,
        packet_rate_deviation=1.4,
        byte_rate_deviation=1.2,
        destination_diversity=0.8,
        port_diversity=0.9,
        connection_frequency=0.7,
        protocol_deviation=0.6,
    )
    assert 0 <= score <= 100


def test_severity_from_score_matches_ranges():
    assert severity_from_score(10) == "INFO"
    assert severity_from_score(35) == "LOW"
    assert severity_from_score(60) == "MEDIUM"
    assert severity_from_score(85) == "HIGH"
