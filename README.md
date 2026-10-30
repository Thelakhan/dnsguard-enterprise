# 🛡️ DNSGuard Enterprise SOC & DNS Tunneling Detection Platform (v6.0)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)](https://flask.palletsprojects.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-CSS-38bdf8.svg)](https://tailwindcss.com/)
[![Chart.js](https://img.shields.io/badge/Chart.js-4.0-orange.svg)](https://www.chartjs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**DNSGuard Enterprise** is a production-grade Security Operations Center (SOC) web application engineered for real-time DNS traffic monitoring, multi-file log ingestion, heuristic anomaly detection, and automated threat risk scoring. Built to identify hidden data exfiltration, C2 beaconing, and DNS tunneling campaigns.

---

## 🚀 Key Features & Capabilities

### 1. Multi-File Ingestion & Normalization
* **Concurrent Ingestion:** Simultaneously upload and parse multiple `.csv`, `.pcap`, and `.pcapng` datasets.
* **Unified Telemetry:** Merges multiple logs into a single correlative timeline to track multi-host activity.
* **Binary Sanitization:** Automatically strips non-printable binary characters and garbage formatting from raw query streams.

### 2. Advanced Feature Extraction & Heuristics
* **Shannon Entropy Calculation:** Measures randomness in subdomains to flag Base64-encoded, encrypted, or algorithmically generated (DGA) traffic.
* **Subdomain Length & Label Analysis:** Tracks excessive label lengths and deep subdomain nesting designed to smuggle exfiltrated data.
* **Beaconing & Frequency Tracking:** Monitors query polling rates within configurable time windows to detect automated C2 heartbeats.
* **TXT Record Activity:** Isolates heavy `TXT` record transactions frequently abused by tunneling tools like Iodine and DNScat2.

### 3. Automated Risk Scoring & Alert Management
* **0–100 Weighted Risk Scoring:** Automatically evaluates threats based on entropy, label length, and frequency thresholds.
* **Severity Classification:** Dynamically categorizes incidents into **Critical**, **High**, **Medium**, and **Low** severities.
* **Interactive SOC Filtering:** Filter alerts in real-time by source IP, target domain, or severity level.

### 4. Visual Analytics & Dashboard (v6.0)
* **Threat Activity Timeline:** Dual-area line chart distinguishing normal baseline traffic from anomalous spikes.
* **Query Type Distribution:** Doughnut chart mapping protocol breakdown (`A`, `AAAA`, `TXT`, `CNAME`, etc.).
* **Severity Breakdown Bar Chart:** Visualizes incident distribution across threat levels.
* **Dynamic Rule Engine:** Configure detection thresholds and allowlists directly through the UI; updates apply instantly to the backend engine without restarting.

---

## 📂 Project Architecture

```text
DNSGuard_Enterprise_v6/
├── app.py                  # Main Flask application & API route controllers
├── vercel.json             # Serverless cloud deployment configuration
├── rules.yaml              # Configurable detection thresholds & allowlists
├── requirements.txt        # Python dependency manifest
├── dnstd/                  # Core Detection & Parsing Package
│   ├── __init__.py
│   ├── parser.py           # Multi-format log parser (PCAP/CSV)
│   ├── extractor.py        # Cryptographic & statistical feature extraction
│   ├── enrichment.py       # 0–100 risk scoring & severity mapping
│   └── detector.py         # Multi-heuristic detection engine & timeline correlator
└── templates/              # Frontend Assets
    └── index.html          # Tailwind CSS + Chart.js SOC Dashboard
