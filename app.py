from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

import pandas as pd
import streamlit as st
from scapy.all import PcapReader, rdpcap

from src.ai_review import generate_ai_review
from src.anomaly_model import calculate_anomaly_score, load_anomaly_model, predict_anomaly, train_anomaly_model
from src.baseline import compare_against_baseline, create_baseline
from src.capture import packets_to_dataframe, start_capture, stop_capture
from src.database import initialize_database, load_analysis_history, save_analysis_record, save_baseline, save_fingerprint
from src.feature_engineering import compute_behavioral_features, summarize_traffic
from src.fingerprint import communication_fingerprint
from src.risk_scoring import calculate_risk_score, network_health_score, severity_from_score
from src.traffic_analysis import build_protocol_chart, build_summary_table, build_time_series, build_top_ip_chart
from src.utils import safe_float

st.set_page_config(page_title="Network Analyzer with AI", page_icon="🛡️", layout="wide")

initialize_database()

NAV_ITEMS = [
    "Overview",
    "Live Analyzer",
    "PCAP Analyzer",
    "Communication Fingerprint",
    "AI Analysis",
    "What Changed?",
    "Traffic Statistics",
    "Analysis History",
]


def _model_vector(features: Dict[str, Any]) -> List[float]:
    return [
        safe_float(features.get("packets_per_second")),
        safe_float(features.get("bytes_per_second")),
        safe_float(features.get("unique_source_ips")),
        safe_float(features.get("unique_destination_ips")),
        safe_float(features.get("unique_destination_ports")),
        safe_float(features.get("tcp_ratio")),
        safe_float(features.get("udp_ratio")),
        safe_float(features.get("icmp_ratio")),
        safe_float(features.get("average_packet_size")),
        safe_float(features.get("connection_count")),
        safe_float(features.get("protocol_diversity")),
        safe_float(features.get("destination_diversity")),
        safe_float(features.get("port_diversity")),
    ]


def _safe_load_pcap(file_obj) -> pd.DataFrame:
    if file_obj is None:
        raise ValueError("Please upload a valid PCAP file.")

    name = str(getattr(file_obj, "name", "")).lower()
    if not (name.endswith(".pcap") or name.endswith(".pcapng")):
        raise ValueError("Please upload a valid PCAP file.")

    try:
        file_obj.seek(0)
        try:
            packets = rdpcap(file_obj.name)
        except Exception:
            packets = list(PcapReader(file_obj))
    except Exception:
        raise ValueError("Please upload a valid PCAP file.")

    if not packets:
        return pd.DataFrame()

    records = []
    for packet in packets:
        try:
            if not packet.haslayer("IP"):
                continue
            src_ip = packet["IP"].src if hasattr(packet, "IP") else ""
            dst_ip = packet["IP"].dst if hasattr(packet, "IP") else ""
            src_port = None
            dst_port = None
            if packet.haslayer("TCP"):
                protocol = "TCP"
                src_port = packet["TCP"].sport
                dst_port = packet["TCP"].dport
            elif packet.haslayer("UDP"):
                protocol = "UDP"
                src_port = packet["UDP"].sport
                dst_port = packet["UDP"].dport
            elif packet.haslayer("ICMP"):
                protocol = "ICMP"
            elif packet.haslayer("DNS"):
                protocol = "DNS"
            else:
                protocol = "UNKNOWN"

            records.append(
                {
                    "time": float(getattr(packet, "time", 0.0)),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "length": int(len(bytes(packet))),
                }
            )
        except Exception:
            continue

    return pd.DataFrame(records)


def _analyze_dataframe(df: pd.DataFrame, baseline: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if df is None or df.empty:
        return {
            "summary": summarize_traffic(pd.DataFrame()),
            "features": {key: 0.0 for key in [
                "packets_per_second", "bytes_per_second", "average_packet_size", "unique_source_ips",
                "unique_destination_ips", "unique_destination_ports", "unique_source_ports",
                "tcp_ratio", "udp_ratio", "icmp_ratio", "dns_activity", "connection_count",
                "protocol_diversity", "destination_diversity", "port_diversity"
            ]},
            "classification": "NORMAL",
            "anomaly_score": 0.0,
            "risk_score": 0.0,
            "severity": "INFO",
            "deviation_summary": ["Insufficient traffic data for anomaly analysis."],
            "review": generate_ai_review("NORMAL", 0.0, 0.0, ["Insufficient traffic data for anomaly analysis."]),
            "baseline_change": {"significant": False, "changes": {}},
        }

    summary = summarize_traffic(df)
    features = compute_behavioral_features(df)
    vector = _model_vector(features)
    model = load_anomaly_model()
    if model is None:
        training_result = train_anomaly_model([df])
        model = training_result.get("model") if training_result.get("status") == "ok" else None

    anomaly_pred = False
    anomaly_score = 0.0
    if model is not None:
        anomaly_pred = predict_anomaly(model, vector)
        anomaly_score = calculate_anomaly_score(model, vector)

    baseline_change = {"significant": False, "changes": {}}
    deviation_summary = ["Current traffic differs from the established baseline."]
    if baseline and baseline.get("baseline"):
        baseline_change = compare_against_baseline(features, baseline["baseline"])
        if baseline_change.get("changes"):
            deviation_summary = []
            for key, value in list(baseline_change["changes"].items())[:5]:
                pct = float(value.get("percentage_change", 0.0))
                if abs(pct) > 20:
                    deviation_summary.append(f"{key.replace('_', ' ').title()} deviated by {pct:.1f}% relative to baseline.")
            if not deviation_summary:
                deviation_summary = ["Current traffic remains broadly consistent with the established baseline."]

    packet_rate_dev = abs(features.get("packets_per_second", 0.0) - (baseline.get("baseline", {}).get("packets_per_second", 0.0) if baseline else 0.0))
    byte_rate_dev = abs(features.get("bytes_per_second", 0.0) - (baseline.get("baseline", {}).get("bytes_per_second", 0.0) if baseline else 0.0))
    risk_score = calculate_risk_score(
        anomaly_score=anomaly_score,
        packet_rate_deviation=packet_rate_dev,
        byte_rate_deviation=byte_rate_dev,
        destination_diversity=features.get("destination_diversity", 0.0),
        port_diversity=features.get("port_diversity", 0.0),
        connection_frequency=features.get("connection_count", 0.0),
        protocol_deviation=max(0.0, features.get("protocol_diversity", 0.0) / 10.0),
    )
    severity = severity_from_score(risk_score)
    classification = "ANOMALOUS" if anomaly_pred or risk_score >= 50 or baseline_change.get("significant") else "NORMAL"
    review = generate_ai_review(classification, anomaly_score, risk_score, deviation_summary)

    return {
        "summary": summary,
        "features": features,
        "classification": classification,
        "anomaly_score": anomaly_score,
        "risk_score": risk_score,
        "severity": severity,
        "deviation_summary": deviation_summary,
        "review": review,
        "baseline_change": baseline_change,
    }


def _build_fingerprints(df: pd.DataFrame) -> List[Dict[str, Any]]:
    if df is None or df.empty:
        return []

    results = []
    for source_ip, group in df.groupby("src_ip", dropna=False):
        if not str(source_ip).strip():
            continue
        metrics = compute_behavioral_features(group)
        fingerprint = communication_fingerprint(source_ip, metrics)
        save_fingerprint({
            "fingerprint_id": fingerprint["identifier"],
            "device": source_ip,
            "timestamp": datetime.utcnow().isoformat(),
            "tcp_ratio": metrics.get("tcp_ratio", 0.0),
            "udp_ratio": metrics.get("udp_ratio", 0.0),
            "dns_activity": metrics.get("dns_activity", 0.0),
            "destination_diversity": metrics.get("destination_diversity", 0.0),
            "port_diversity": metrics.get("port_diversity", 0.0),
            "packets_per_second": metrics.get("packets_per_second", 0.0),
            "feature_payload": json.dumps(metrics),
        })
        results.append(fingerprint)
    return results


def _render_metric_cards(keys, analysis):
    summary = analysis["summary"]
    cards = [
        ("Network Health", f"{network_health_score(analysis['risk_score']):.0f} / 100", "Project-defined behavioral health indicator."),
        ("Active Devices", len(set(summary.get("top_source_ips", {}).keys()) | set(summary.get("top_destination_ips", {}).keys())), "Distinct IPs observed."),
        ("Packets", f"{summary.get('total_packets', 0):,}", "Total packets analyzed."),
        ("Bytes", f"{summary.get('total_bytes', 0):,}", "Total bytes observed."),
        ("Anomalies", analysis["classification"], "Current classification."),
        ("Average Risk", f"{analysis['risk_score']:.0f} / 100", "Project-defined risk score."),
    ]
    for col, card in zip(keys, cards):
        col.metric(card[0], card[1], card[2])


def _show_overview():
    st.title("Network Analyzer with AI")
    st.caption("Educational network metadata analysis for authorized environments. Live capture is local-only; cloud deployments support PCAP upload and analysis.")

    if "last_analysis" not in st.session_state:
        st.info("No analysis has been run yet. Upload a PCAP or use the local analyzer to generate traffic data.")
        return

    analysis = st.session_state["last_analysis"]
    summary = analysis["summary"]
    cols = st.columns(6)
    _render_metric_cards(cols, analysis)

    st.subheader("Recent summary")
    st.dataframe(pd.DataFrame(build_summary_table(summary)))


def _show_live_analyzer():
    st.title("Live Analyzer")
    st.info("Live capture requires running the application locally on an authorized machine. Cloud deployments cannot monitor the visitor's local network interface.")

    interface = st.text_input("Interface name (optional)", value="", help="Leave blank to let Scapy detect an interface. On Windows, Npcap may be required for packet capture.")
    packet_limit = st.slider("Capture limit", min_value=50, max_value=5000, value=500, step=50)

    if st.button("START ANALYZER"):
        try:
            packets = start_capture(interface=interface, packet_limit=packet_limit)
            st.session_state["live_packets"] = packets
            st.success("Capture completed. The traffic has been processed and the results are ready for review.")
        except PermissionError as exc:
            st.error(str(exc))
        except OSError as exc:
            st.error(str(exc))
        except RuntimeError as exc:
            st.error(str(exc))
        except Exception:
            st.error("Live capture failed. Check the selected interface and confirm that Npcap is installed.")

    if st.button("STOP & ANALYZE"):
        packets = stop_capture()
        if not packets:
            st.warning("No packets were captured during the session.")
            return

        df = packets_to_dataframe(packets)
        if df.empty:
            st.warning("No valid network metadata was captured.")
            return

        baseline = create_baseline(df)
        analysis = _analyze_dataframe(df, baseline)
        st.session_state["last_analysis"] = analysis
        st.session_state["pcap_last_df"] = df
        st.success("Live analysis completed.")
        st.dataframe(pd.DataFrame(build_summary_table(analysis["summary"])))


def _show_pcap_analyzer():
    st.title("PCAP Analyzer")
    st.caption("PCAP upload works in cloud-hosted Streamlit deployments and is the recommended path for remote analysis.")

    uploaded = st.file_uploader("Upload a .pcap or .pcapng file", type=["pcap", "pcapng"])
    if uploaded is not None:
        try:
            df = _safe_load_pcap(uploaded)
            if df.empty:
                st.warning("Please upload a valid PCAP file with readable packet metadata.")
            else:
                baseline = create_baseline(df)
                analysis = _analyze_dataframe(df, baseline)
                st.session_state["last_analysis"] = analysis
                st.session_state["pcap_last_df"] = df
                st.success("PCAP analysis completed successfully.")
                st.dataframe(pd.DataFrame(build_summary_table(analysis["summary"])))
        except ValueError as exc:
            st.error(str(exc))
        except Exception:
            st.error("Unable to parse the supplied PCAP file. Please upload a valid capture.")


def _show_fingerprint_page():
    st.title("Communication Fingerprint")
    if "pcap_last_df" in st.session_state and not st.session_state["pcap_last_df"].empty:
        fps = _build_fingerprints(st.session_state["pcap_last_df"])
        if fps:
            for fp in fps:
                st.markdown(f"### {fp['device']}")
                st.write(f"Identifier: {fp['identifier']}")
                for item in fp["overview"]:
                    st.write(f"{item['label']}: {item['percent']}%")
                    st.progress(min(float(item['percent']), 100.0) / 100.0)
        else:
            st.info("No device-level fingerprint data was available from the current traffic.")
    else:
        st.info("Run a live capture or analyze a PCAP to generate communication fingerprints.")


def _show_ai_analysis():
    st.title("AI Analysis")
    if "last_analysis" not in st.session_state:
        st.info("No analysis results are available yet.")
        return

    analysis = st.session_state["last_analysis"]
    review = analysis["review"]
    st.subheader("Classification")
    st.markdown(f"### {review['classification']}")
    st.write(f"Anomaly score: {review['anomaly_score']:.2f}")
    st.write(f"Risk score: {review['risk_score']:.0f}/100")
    st.write(f"Severity: {review['severity']}")

    st.subheader("AI Traffic Review")
    st.write("Observed deviations:")
    for item in review["observed_deviations"]:
        st.write(f"• {item}")
    st.write(f"Interpretation: {review['interpretation']}")
    st.write(f"Recommendation: {review['recommendation']}")
    st.write(f"Note: {review['note']}")


def _show_what_changed():
    st.title("What Changed?")
    if "last_analysis" not in st.session_state:
        st.info("No historical baseline comparison is available yet.")
        return

    analysis = st.session_state["last_analysis"]
    changes = analysis["baseline_change"].get("changes", {})
    if not changes:
        st.info("The current traffic does not have a meaningful baseline comparison yet.")
        return

    rows = []
    for key, values in changes.items():
        rows.append({
            "Metric": key.replace("_", " ").title(),
            "Baseline": round(float(values.get("baseline", 0.0)), 2),
            "Current": round(float(values.get("current", 0.0)), 2),
            "Absolute change": round(float(values.get("absolute_change", 0.0)), 2),
            "Percentage change": round(float(values.get("percentage_change", 0.0)), 2),
        })

    st.dataframe(pd.DataFrame(rows))
    if analysis["baseline_change"].get("significant"):
        st.warning("Significant behavioral deviation detected. This does not automatically indicate malicious activity; it requires investigation.")
    else:
        st.success("Current behavior remains reasonably aligned with the established baseline.")


def _show_traffic_statistics():
    st.title("Traffic Statistics")
    if "last_analysis" not in st.session_state:
        st.info("Upload a PCAP or run the live analyzer to inspect traffic statistics.")
        return

    analysis = st.session_state["last_analysis"]
    summary = analysis["summary"]
    df = st.session_state.get("pcap_last_df") if "pcap_last_df" in st.session_state else pd.DataFrame()

    protocol_chart = build_protocol_chart(df)
    st.plotly_chart(protocol_chart, use_container_width=True)

    if summary.get("top_source_ips"):
        st.plotly_chart(build_top_ip_chart(summary.get("top_source_ips"), "Top Source IPs"), use_container_width=True)
    if summary.get("top_destination_ips"):
        st.plotly_chart(build_top_ip_chart(summary.get("top_destination_ips"), "Top Destination IPs"), use_container_width=True)
    if summary.get("top_destination_ports"):
        st.plotly_chart(build_top_ip_chart(summary.get("top_destination_ports"), "Top Destination Ports"), use_container_width=True)

    if not df.empty:
        st.plotly_chart(build_time_series(df), use_container_width=True)

    st.dataframe(pd.DataFrame(build_summary_table(summary)))


def _show_analysis_history():
    st.title("Analysis History")
    history = load_analysis_history()
    if not history:
        st.info("No previous analyses are stored yet.")
        return
    st.dataframe(pd.DataFrame(history))


def main():
    page = st.sidebar.radio("Navigation", NAV_ITEMS)

    if page == "Overview":
        _show_overview()
    elif page == "Live Analyzer":
        _show_live_analyzer()
    elif page == "PCAP Analyzer":
        _show_pcap_analyzer()
    elif page == "Communication Fingerprint":
        _show_fingerprint_page()
    elif page == "AI Analysis":
        _show_ai_analysis()
    elif page == "What Changed?":
        _show_what_changed()
    elif page == "Traffic Statistics":
        _show_traffic_statistics()
    elif page == "Analysis History":
        _show_analysis_history()

    st.sidebar.markdown("---")
    st.sidebar.caption("Privacy notice: This application focuses on packet metadata, protocol usage, timing, ports, sizes, and derived traffic statistics. It does not store packet payloads by default.")


if __name__ == "__main__":
    main()
