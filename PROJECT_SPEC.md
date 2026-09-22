# Project Specification

## Project goal
This project implements an educational, privacy-preserving network analysis dashboard that learns normal communication behavior, builds a behavioral fingerprint for each device, and uses lightweight machine learning to identify unusual communication patterns. The application is designed for authorized monitoring scenarios and avoids automatic attack claims.

## Functional requirements
- Capture authorized local live traffic using Scapy on a local machine.
- Support PCAP upload for .pcap and .pcapng files.
- Parse packet metadata without storing payload contents by default.
- Build a traffic dataframe from metadata.
- Compute traffic statistics and behavioral features.
- Generate communication fingerprints by source IP.
- Train and apply an Isolation Forest model using numerical traffic features.
- Compare current behavior to a baseline and explain changes.
- Produce an explainable AI review that clearly states anomalies require investigation.
- Calculate a project-defined risk score and network health score.
- Save analysis history and baseline metadata to SQLite.
- Present the results through a Streamlit dashboard with the required navigation.

## Non-functional requirements
- Python project with simple modules and minimal dependencies.
- No external AI API key needed.
- No offensive or exploit functionality.
- Graceful error handling to avoid exposing tracebacks to users.
- Streamlit Cloud-friendly PCAP-only mode in the cloud.
- Local live capture only runs on authorized local hosts.

## Architecture
The system is divided into focused modules for parsing, feature engineering, fingerprinting, anomaly detection, scoring, explanation, traffic analysis, database storage, live capture, and the Streamlit application. Each module is built to be small, testable, and easy to understand.

## Modules
- app.py: Streamlit front-end and dashboard orchestration.
- src/packet_parser.py: packet parsing and dataframe construction.
- src/feature_engineering.py: metadata feature extraction and comparison logic.
- src/fingerprint.py: communication fingerprint generation.
- src/baseline.py: baseline creation and change comparison.
- src/anomaly_model.py: Isolation Forest training and inference.
- src/risk_scoring.py: risk score and severity calculation.
- src/ai_review.py: explainable security review generation.
- src/traffic_analysis.py: metrics and Plotly charts.
- src/database.py: SQLite storage.
- src/capture.py: local packet capture logic.
- src/utils.py: helper utilities.

## Data flow
1. Packet intake from either a live local capture or uploaded PCAP.
2. Packet metadata extraction.
3. Feature engineering and summary computation.
4. Baseline generation or retrieval.
5. Communication fingerprint generation.
6. Isolation Forest training and anomaly scoring.
7. Risk scoring and AI review generation.
8. Dashboard rendering and history storage.

## AI pipeline
The AI pipeline uses numerical traffic features rather than payload content. Features are vectorized and passed to an Isolation Forest model. The model identifies unusual points relative to the known baseline, and the system translates model output into explainable language that describes behavioral deviations without asserting malicious activity.

## Feature engineering
The feature set includes packet rate, byte rate, average packet size, unique destination IPs, unique destination ports, unique source ports, protocol ratios, DNS activity, connection count, protocol diversity, destination diversity, and port diversity. The features are computed from metadata and normalized where needed.

## Fingerprint generation
A communication fingerprint is created for each source device or IP address. It summarizes communication behavior in a human-readable format and includes a project-level fingerprint identifier derived from the IP and hashing logic. This identifier is not a global device identity.

## Anomaly detection
The project uses scikit-learn Isolation Forest, with robust handling for empty captures, missing data, insufficient variation, and model errors. Predictions are framed as anomaly indicators and not automatic attack verdicts.

## Risk calculation
Risk is a project-defined score from 0 to 100 based on measurable behavior, including anomaly score, rate deviation, destination diversity, port diversity, and protocol shifts. Thresholds are project-defined and clearly described as such.

## What Changed
This section compares current traffic with the baseline and reports changes in packet rate, byte rate, destination diversity, port diversity, protocol ratios, and connection counts. It emphasizes behavioral deviation as a reason for investigation rather than direct malicious activity.

## Dashboard
The Streamlit interface presents overview metrics, live capture controls, PCAP upload analysis, communication fingerprint sections, AI analysis, what changed views, traffic statistics, and analysis history.

## Database
The application uses SQLite to store analysis history, fingerprints, and baselines. It stores metadata only and intentionally avoids packet payloads.

## Privacy
The application is designed for privacy-preserving metadata analysis. It does not store packet payloads, credentials, or cookies. It focuses on IP metadata, ports, protocols, packet sizes, timestamps, and derived statistics.

## Deployment
The project is prepared for Streamlit Community Cloud deployment, with the cloud version focused on PCAP upload and analysis. Live capture remains a local-only capability because cloud platforms cannot access the visitor's local network interface.

## Limitations
- Live capture is only feasible on an authorized local machine.
- The model is behavior-oriented and not a universal cyberattack detector.
- Traffic characteristics can vary by environment, so baseline quality matters.
- Network metadata analysis cannot infer application-layer content without explicit authorization.

## Implementation order
The implementation follows the required phased order: specification, project structure, dependencies, parsing, feature engineering, fingerprinting, baseline, anomaly model, risk scoring, AI review, traffic analysis, database, capture, dashboard, tests, README, deployment config, and verification.
