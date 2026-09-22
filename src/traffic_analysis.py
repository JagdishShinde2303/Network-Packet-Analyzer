from __future__ import annotations

from typing import Any, Dict

import plotly.express as px


def build_protocol_chart(df):
    if df is None or df.empty:
        return px.bar(title="Protocol Distribution")
    protocols = df["protocol"].fillna("UNKNOWN").astype(str).str.upper().value_counts()
    fig = px.bar(x=protocols.index, y=protocols.values, labels={"x": "Protocol", "y": "Packets"}, title="Protocol Distribution")
    return fig


def build_top_ip_chart(series, title: str):
    if series is None or len(series) == 0:
        return px.bar(title=title)
    labels = list(series.keys())
    values = list(series.values())
    fig = px.bar(x=labels, y=values, title=title)
    return fig


def build_time_series(df):
    if df is None or df.empty:
        return px.line(title="Traffic Over Time")
    frame = df.copy()
    frame = frame.sort_values("time")
    fig = px.line(frame, x="time", y="length", title="Traffic Over Time")
    return fig


def build_summary_table(data: Dict[str, Any]) -> list[Dict[str, Any]]:
    details = [
        ("Total packets", data.get("total_packets", 0)),
        ("Total bytes", data.get("total_bytes", 0)),
        ("Capture duration", round(float(data.get("duration_seconds", 0.0)), 2)),
        ("Packets/sec", round(float(data.get("packets_per_second", 0.0)), 2)),
        ("Bytes/sec", round(float(data.get("bytes_per_second", 0.0)), 2)),
        ("DNS observations", data.get("dns_observations", 0)),
    ]
    return [{"Metric": label, "Value": value} for label, value in details]
