# Network Intrusion Detection System (NIDS)

## 📌 Overview

This project is a **feature-rich, Python-based Network Intrusion Detection System (NIDS)** that monitors live network traffic, detects malicious behavior, and flags anomalous patterns in real time. It combines **rule-based intrusion detection**, **statistical traffic analysis**, and **machine learning–based anomaly detection** to closely resemble modern IDS architectures used in real-world environments.

The system captures packets using **Scapy**, extracts **time-based and flow-based features**, applies **traffic-class–specific ML models**, and logs alerts and packets for forensic analysis.

This project was developed incrementally in multiple phases, with strong emphasis on clean architecture, modular design, and realistic cybersecurity practices.

---

## 🧠 Core Capabilities

### 1. Live Packet Capture

* Real-time packet sniffing using Scapy
* Supports TCP, UDP, ICMP, and generic IP traffic
* Designed to run continuously like a background IDS sensor

---

### 2. Rule-Based Intrusion Detection

Implements classical signature-based detections with configurable thresholds:

* **Port Scan Detection**
  Detects multiple unique destination ports accessed by a single source IP within a sliding time window.

* **SYN Flood (DoS) Detection**
  Identifies excessive TCP SYN packets indicating denial-of-service attempts.

* **ICMP Flood Detection (DDoS Indicator)**
  Detects abnormal ICMP request rates per source IP.

* **Brute Force Login Detection**
  Monitors repeated access attempts to sensitive service ports (e.g., SSH, FTP).

All detection thresholds, time windows, and sensitive ports are centrally configurable in `rules.py`.

---

### 3. Advanced Feature Engineering

The system extracts **behavioral features** from live traffic, enabling deeper detection than packet-level inspection.

#### 🔹 Time-Based Features (per source IP)

* Packet rate (packets/sec)
* Average packet size
* Number of unique destination ports
* SYN packet rate
* ICMP packet rate

Maintained using sliding time windows for real-time accuracy.

#### 🔹 Flow-Based Features (per 5-tuple flow)

* Flow duration
* Packet count
* Byte count
* Packet rate
* Byte rate
* TCP SYN count
* TCP FIN count

Flows are tracked using configurable timeouts to mimic real IDS flow tracking.

---

### 4. Machine Learning–Based Anomaly Detection

#### 🔸 Isolation Forest Models

* Uses **Isolation Forest** for unsupervised anomaly detection
* Learns normal traffic behavior dynamically during runtime
* Detects previously unseen or zero-day–style anomalies

#### 🔸 Feature Normalization & Scaling

* Applies **StandardScaler** to normalize features
* Prevents dominance of large-magnitude features
* Mirrors production ML pipelines used in security analytics

#### 🔸 Traffic-Class–Specific Models

Separate ML models are trained per traffic class:

* ICMP
* Web (HTTP/HTTPS)
* Login services
* Generic TCP
* UDP

This improves detection accuracy by learning **class-specific baselines** instead of a single global model.

---

### 5. Alerting, Logging & Forensics

#### 📄 Alert Logging

* Alerts are written to a structured **CSV log file**
* Each alert contains:

  * Timestamp
  * Attack type
  * Severity level
  * Source & destination IPs
  * Protocol
  * Additional contextual information

#### 📦 Packet Capture (PCAP)

* Raw packets are stored in `.pcap` format using `PcapWriter`
* Enables offline forensic analysis in Wireshark
* Useful for post-incident investigation and learning

#### 📊 Attack Statistics

* Tracks cumulative counts per attack type
* Useful for dashboards and reporting

---

## 🧩 Project Structure

```
NIDS/
│
├── main.py                 # Entry point
├── sniffing.py             # Packet capture loop
├── analysis.py             # Rule-based + ML detection logic
├── ml_detector.py          # ML pipeline (scaling + Isolation Forest)
├── rules.py                # Thresholds and detection parameters
├── logger.py               # CSV logging + PCAP export
│
├── features/
│   ├── time_features.py   # Time-based feature extraction
│   └── flow_features.py   # Flow-based feature extraction
│
├── traffic_log.csv         # Alert logs
├── captured_traffic.pcap   # Packet capture for analysis
└── README.md
```

The architecture is intentionally modular and extensible.

---

## ⚙️ Technologies Used

* **Python 3**
* **Scapy** – packet capture and protocol analysis
* **Scikit-learn** – Isolation Forest, feature scaling
* **NumPy** – numerical processing
* **PCAP** – network forensics

---

## 🧪 What This Project Demonstrates

* Deep understanding of network protocols
* Real-time traffic analysis
* Sliding window and flow-based detection
* Practical ML deployment in cybersecurity
* Modular defensive security engineering

---

## ⚠️ Disclaimer

This project is intended **strictly for educational and defensive purposes**.

---

## 👤 Author

Developed as a comprehensive hands-on cybersecurity project showcasing modern intrusion detection techniques and ML-driven traffic analysis.
