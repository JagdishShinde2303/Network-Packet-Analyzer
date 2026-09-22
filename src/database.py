from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List


DB_PATH = Path("data") / "network_analyzer.db"


def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_history (
                analysis_id TEXT PRIMARY KEY,
                timestamp TEXT,
                duration REAL,
                packet_count INTEGER,
                total_bytes INTEGER,
                device_count INTEGER,
                anomaly_count INTEGER,
                anomaly_rate REAL,
                risk_score REAL,
                severity TEXT,
                classification TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_fingerprints (
                fingerprint_id TEXT PRIMARY KEY,
                device TEXT,
                timestamp TEXT,
                tcp_ratio REAL,
                udp_ratio REAL,
                dns_activity REAL,
                destination_diversity REAL,
                port_diversity REAL,
                packets_per_second REAL,
                feature_payload TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS baselines (
                baseline_id TEXT PRIMARY KEY,
                timestamp TEXT,
                device TEXT,
                baseline_payload TEXT
            )
            """
        )
        conn.commit()


def save_analysis_record(record: Dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO analysis_history (
                analysis_id, timestamp, duration, packet_count, total_bytes,
                device_count, anomaly_count, anomaly_rate, risk_score, severity, classification
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                record.get("analysis_id"),
                record.get("timestamp"),
                record.get("duration"),
                record.get("packet_count"),
                record.get("total_bytes"),
                record.get("device_count"),
                record.get("anomaly_count"),
                record.get("anomaly_rate"),
                record.get("risk_score"),
                record.get("severity"),
                record.get("classification"),
            ],
        )
        conn.commit()


def load_analysis_history() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM analysis_history ORDER BY timestamp DESC LIMIT 20"
        ).fetchall()
    return [dict(row) for row in rows]


def save_fingerprint(record: Dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO device_fingerprints (
                fingerprint_id, device, timestamp, tcp_ratio, udp_ratio, dns_activity,
                destination_diversity, port_diversity, packets_per_second, feature_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                record.get("fingerprint_id"),
                record.get("device"),
                record.get("timestamp"),
                record.get("tcp_ratio"),
                record.get("udp_ratio"),
                record.get("dns_activity"),
                record.get("destination_diversity"),
                record.get("port_diversity"),
                record.get("packets_per_second"),
                record.get("feature_payload"),
            ],
        )
        conn.commit()


def save_baseline(record: Dict[str, Any]) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO baselines (baseline_id, timestamp, device, baseline_payload)
            VALUES (?, ?, ?, ?)
            """,
            [record.get("baseline_id"), record.get("timestamp"), record.get("device"), record.get("baseline_payload")],
        )
        conn.commit()
