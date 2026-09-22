# Network Analyzer with AI

AI-Based Network Communication Fingerprinting and Anomaly Detection

## Overview

Network Analyzer with AI is an educational cybersecurity analytics application designed to monitor authorized network traffic, learn normal communication behavior, and identify unusual activity through lightweight machine learning. The project focuses on network metadata instead of payload inspection to keep the workflow privacy-conscious and suitable for learning environments.

This system combines:

- local live traffic capture for authorized environments
- PCAP file upload and analysis for cloud-friendly workflows
- communication fingerprint generation per device or source IP
- behavioral anomaly detection using Isolation Forest
- baseline comparison via the "What Changed?" analysis
- explainable AI review that clearly states anomalies require investigation
- project-defined risk scoring and health metrics
- SQLite-based analysis history and fingerprint storage

The application is intentionally designed not to label traffic as malicious automatically. Instead, it flags unusual behavioral deviations and emphasizes that they should be investigated further.

---

## Project Objective

The central goal is to learn the normal communication behavior of network devices, create a behavioral communication fingerprint, compare current activity to a baseline, and identify significant deviations using AI. The output is meant to support education, authorized review, and defensive monitoring—not to claim that an anomaly is definitively malicious.

---

## Problem Statement

Traditional network monitoring tools are often focused on packet payload analysis, deep learning systems, or attack detection without contextual explanation. For cybersecurity education and authorized monitoring, there is a clear need for a simple, explainable, metadata-first analyzer that:

- understands normal traffic patterns
- describes how a device behaves in communication terms
- highlights unusual deviations
- explains what changed compared to baseline behavior
- avoids false claims of malicious activity

---

## Solution Summary

This project provides a Streamlit-based dashboard that can:

1. Capture authorized live traffic on a local machine
2. Analyze uploaded .pcap and .pcapng files
3. Extract metadata such as IPs, ports, packet lengths, protocols, and timing
4. Build behavioral features from that metadata
5. Create a communication fingerprint for each source IP/device
6. Train and run a scikit-learn Isolation Forest model
7. Compare current traffic with a baseline
8. Produce a risk score and explainable review
9. Persist analysis history in SQLite

---

## Key Features

### 1. Network Traffic Analyzer

- local live capture using Scapy
- start and stop controls
- capture status display
- elapsed time tracking
- packet count and byte count display
- metadata-first analysis only
- no payload inspection by default

### 2. PCAP Analyzer

- supports .pcap and .pcapng files
- parses packet metadata
- builds a traffic dataframe
- calculates traffic statistics
- generates fingerprints and anomaly results
- designed for cloud deployment use

### 3. Communication Fingerprint

- generates a behavioral fingerprint for each source device/IP
- summarizes traffic characteristics such as:
  - packets per second
  - bytes per second
  - average packet size
  - unique destination IPs
  - unique destination ports
  - unique source ports
  - TCP/UDP/ICMP ratios
  - DNS activity when available
  - connection count
  - protocol diversity
  - destination diversity
  - port diversity
- provides a simple visual fingerprint representation
- uses a project-level fingerprint identifier such as 7A-F2-91

### 4. AI Anomaly Detection

- isolation forest model from scikit-learn
- no deep learning or external AI API required
- no OpenAI API or keys required
- model saved using joblib
- robust handling for small or empty datasets and model failures

### 5. What Changed?

- compares current traffic against baseline
- shows baseline and current values
- reports absolute and percentage change
- highlights significant behavioral deviations
- frames results as investigation-worthy rather than malicious

### 6. Explainable AI Traffic Review

- combines anomaly model output, risk score, and behavioral observations
- produces plain-language review
- emphasizes that the anomaly is not automatic proof of malicious behavior
- recommends review of destinations, timing, and ports

### 7. Dashboard Statistics and History

- overview cards for health, packet totals, active devices, anomaly states, and average risk
- traffic charts for protocol distribution and time-series activity
- top source/destination IP summaries
- analysis history in SQLite

---

## Product Characteristics

- beginner-friendly
- privacy-preserving
- metadata-focused
- explainable output
- educational and authorized monitoring oriented
- lightweight machine learning only
- no offensive or exploit functionality
- cloud-friendly for PCAP workflows
- local-only live capture for actual interface monitoring

---

## Architecture

The project is organized into modular Python components:

- app.py: Streamlit dashboard and orchestration
- src/packet_parser.py: packet parsing and metadata extraction
- src/feature_engineering.py: traffic feature generation
- src/fingerprint.py: communication fingerprint logic
- src/baseline.py: baseline creation and deviation comparison
- src/anomaly_model.py: Isolation Forest training and prediction
- src/risk_scoring.py: risk score and health score calculation
- src/ai_review.py: explainable review generation
- src/traffic_analysis.py: summary tables and Plotly charts
- src/database.py: SQLite storage for analysis history and fingerprints
- src/capture.py: local packet capture handling
- src/utils.py: generic helpers and safety utilities

---

## Technology Stack

- Python 3.10+
- Streamlit
- Scapy
- pandas
- numpy
- scikit-learn
- Plotly
- joblib
- SQLite
- pytest

---

## AI Methodology

The anomaly detection pipeline is based on observational traffic metadata rather than payload content.

The model uses numerical behavioral features including:

- packets_per_second
- bytes_per_second
- unique_destination_ips
- unique_destination_ports
- tcp_ratio
- udp_ratio
- icmp_ratio
- average_packet_size
- connection_count
- protocol_diversity
- destination_diversity
- port_diversity

This is an unsupervised anomaly detection workflow using Isolation Forest and is designed to identify unusual communication patterns rather than classify every possible cyberattack.

---

## Communication Fingerprint Details

For each device or source IP, the system calculates a fingerprint that summarizes communication behavior, including:

- packet rate
- byte rate
- service mix
- destination spreads
- port diversity
- protocol behavior
- DNS activity when it is detectable

The output is presented in a human-readable format with a project-defined identifier, such as:

- Device: 192.168.1.15
- Communication Fingerprint
- Identifier: 7A-F2-91

This identifier is not a global device identity. It is only a project-level behavioral identifier.

---

## What Changed? Details

The What Changed dashboard compares current traffic with the established baseline.

It reports metrics such as:

- packets per second
- bytes per second
- unique destinations
- unique ports
- connection count
- TCP ratio
- UDP ratio
- DNS activity where available
- protocol distribution

Example interpretation:

- significant behavioral deviation detected
- current traffic differs meaningfully from the baseline
- observed deviation requires investigation

---

## Risk Scoring

The application calculates a project-defined risk score on a 0 to 100 scale based on measurable behavioral conditions.

Risk inputs may include:

- anomaly score
- packet rate deviation
- byte rate deviation
- destination diversity
- port diversity
- connection frequency
- protocol deviation

Severity bands are defined as:

- 0-24: INFO
- 25-49: LOW
- 50-74: MEDIUM
- 75-100: HIGH

These thresholds are project-defined analytical thresholds and are not presented as universal cybersecurity standards.

---

## Network Health Score

The dashboard also displays a simple network health metric from 0 to 100.

This score is described as a project metric and is not an industry-standard security rating.

---

## Explainable AI Review

The AI review combines the model result, risk score, baseline difference, and deviation summary into a human-readable assessment.

Example output style:

- Classification: ANOMALOUS
- Risk Score: 74/100
- Severity: MEDIUM
- Observed deviations: connection frequency increased, destination diversity increased, port diversity increased
- Interpretation: observed communication behavior differs significantly from the device fingerprint and requires investigation
- Recommendation: review destination addresses, ports, and traffic timing
- Note: anomaly does not automatically prove malicious activity

---

## Privacy and Security Design

The application is designed for privacy-preserving analysis and authorized monitoring.

It does not by default:

- store packet payloads
- store credentials or passwords
- store cookies or authentication tokens
- inspect application message contents

It focuses on:

- IP metadata
- destination/source ports
- traffic timing
- packet sizes
- protocols
- aggregate statistics

A privacy notice is shown in the dashboard.

---

## Security and Ethics

This project is strictly for authorized network monitoring and educational analysis.

It does not implement:

- packet injection
- credential interception
- malware behavior
- exploit execution
- offensive scanning
- attack automation
- vulnerability exploitation

The tool analyzes metadata and derived behaviors only.

---

## Project Structure

```text
Network-Packet-Analyzer/
├── app.py
├── requirements.txt
├── README.md
├── PROJECT_SPEC.md
├── .gitignore
├── .streamlit/
│   └── config.toml
├── src/
│   ├── __init__.py
│   ├── capture.py
│   ├── packet_parser.py
│   ├── feature_engineering.py
│   ├── fingerprint.py
│   ├── anomaly_model.py
│   ├── risk_scoring.py
│   ├── ai_review.py
│   ├── baseline.py
│   ├── traffic_analysis.py
│   ├── database.py
│   └── utils.py
├── models/
│   └── .gitkeep
├── data/
│   └── .gitkeep
├── tests/
│   ├── test_parser.py
│   ├── test_features.py
│   ├── test_fingerprint.py
│   └── test_risk.py
└── .venv/   (optional local virtual environment)
```

---

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd Network-Packet-Analyzer
```

### 2. Create a virtual environment

#### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

#### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

---

## Local Run Commands

### Windows

```powershell
cd C:\path\to\Network-Packet-Analyzer
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

### Linux/macOS

```bash
cd /path/to/Network-Packet-Analyzer
source .venv/bin/activate
streamlit run app.py
```

Then open the local URL shown by Streamlit, typically:

```text
http://localhost:8501
```

---

## Live Capture Instructions

Live capture is intended for local authorized use.

### Important limitation

Cloud-hosted Streamlit deployments cannot access the visitor's local network interface. Therefore:

- live capture works on a local machine
- cloud deployment is for PCAP upload and analysis only

### Windows live capture note

For Windows, Scapy may require Npcap for packet capture support. If live capture does not work, install Npcap and ensure the app is run with proper local permissions.

### Example workflow

1. Open the Live Analyzer page
2. Optionally specify an interface name
3. Click START ANALYZER
4. Allow the application to capture authorized traffic
5. Stop analysis when enough traffic is collected
6. Review results, fingerprints, risk score, and AI traffic review

---

## PCAP Analysis Instructions

### Upload flow

1. Open the PCAP Analyzer page
2. Upload a .pcap or .pcapng file
3. The app parses the file and builds a traffic dataframe
4. It calculates behavioral metrics
5. It generates fingerprints and baseline comparisons
6. It produces anomaly and risk scores
7. It renders summary tables and charts

### Supported file types

- .pcap
- .pcapng

---

## Streamlit Cloud Deployment Guide

This project is designed for Streamlit Community Cloud compatibility.

### Deployment guidance

1. Push the repository to GitHub
2. Create a new app in Streamlit Community Cloud
3. Choose this repository
4. Set the app entry point to: app.py
5. Use the repository's requirements.txt for dependencies
6. In the hosted cloud environment, use the PCAP Analyzer only

### Cloud limitation

The cloud-hosted application cannot automatically capture the local network interface of the visitor's machine. It can only analyze uploaded files.

---

## Testing

Automated tests cover the key project functions:

- packet parsing
- feature extraction
- fingerprint generation
- risk scoring

Run tests with:

```bash
python -m pytest -q
```

---

## Example Commands Summary

```bash
# install dependencies
python -m pip install -r requirements.txt

# start the dashboard
streamlit run app.py

# run tests
python -m pytest -q
```

---

## Deployment Notes

### Local deployment

- works on a local device with proper capture permissions
- suitable for research, labs, and educational monitoring

### Cloud deployment

- supports PCAP analysis and static app functions
- does not provide live device-level capture in the browser

---

## Limitations

- live packet capture is only possible on authorized local machines
- network metadata cannot reveal full payload content without explicit authorization
- baseline quality materially affects anomaly quality
- model results should be interpreted as behavioral deviations, not definitive attack labels
- no universal security standard is implied by the project-defined risk thresholds

---

## Future Enhancements

Possible next-step extensions include:

- time-windowed baseline analysis
- richer per-device trend detection
- expanded explanation modules
- improved adaptive baselines
- advanced dashboard filtering

---

## Ethical and Legal Usage

This project is intended exclusively for:

- authorized network monitoring
- educational analysis
- defensive and research-oriented workflows

It must not be used for:

- unauthorized traffic interception
- credential theft
- exploitation testing
- malicious packet manipulation
- evasion or persistence techniques

Any deployment must comply with local laws, institutional policy, and organizational authorization.

---

## Author and Project Context

This repository contains a complete implementation of a cybersecurity education project focused on behavioral communication fingerprinting and anomaly detection using lightweight machine learning.

The project is designed to be understandable, practical, and aligned with privacy-conscious metadata analysis.

---

## Final Notes

This application is a network behavior analysis tool intended to support investigation, not automatic accusation. It demonstrates a practical way to:

- identify unusual communication patterns
- compare behavior against a baseline
- explain deviations in clear language
- produce a project-defined risk assessment

This README is intended to serve as a complete project handoff document for developers, users, and deployment stakeholders.
