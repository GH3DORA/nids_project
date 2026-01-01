# Network Intrusion Detection System (NIDS)

## 📌 Overview

This project is a **Python-based Network Intrusion Detection System (NIDS)** designed to monitor live network traffic, detect malicious patterns, and flag anomalous behavior in real time. It combines **signature-based detection** (rule-based attacks) with **machine learning–based anomaly detection**, closely resembling how real-world IDS solutions operate.

The system captures packets using **Scapy**, analyzes them across multiple detection modules, logs alerts in structured formats, and optionally stores raw packets in **PCAP** format for forensic analysis.

This project is built incrementally in phases, emphasizing clean architecture, modularity, and practical cybersecurity concepts.

---

## 🧠 Key Features

### 1. Live Packet Sniffing

* Captures real-time packets from the network interface
* Supports TCP, UDP, ICMP, and generic IP traffic
* Designed to run continuously like a daemon

### 2. Rule-Based Attack Detection

Implements multiple classical intrusion detection techniques:

* **Port Scan Detection**
  Detects multiple unique destination ports accessed by the same source IP within a short time window.

* **SYN Flood (DoS) Detection**
  Flags excessive TCP SYN packets indicating a possible denial-of-service attempt.

* **ICMP Flood Detection (DDoS Indicator)**
  Detects high-frequency ICMP echo requests.

* **Brute Force Login Detection**
  Monitors repeated access attempts to sensitive ports (e.g., SSH, FTP).

All thresholds and time windows are configurable via a central `rules.py` file.

---

### 3. Machine Learning–Based Anomaly Detection

* Uses **Isolation Forest** for unsupervised anomaly detection
* Learns normal traffic patterns dynamically during runtime
* Extracted features include:

  * Packet size
  * Protocol number
  * Source port
  * Destination port
* Automatically switches from training mode to detection mode
* Flags packets with abnormal statistical behavior

This allows detection of **previously unseen or zero-day–style attacks**.

---

### 4. Logging & Forensics

#### Alert Logging

* Alerts are stored in a structured **CSV log file**
* Each alert contains:

  * Timestamp
  * Attack type
  * Severity level
  * Source & destination IPs
  * Protocol
  * Additional contextual information

#### Packet Capture (PCAP)

* Raw packets are saved to a `.pcap` file using `PcapWriter`
* Enables offline analysis using tools like Wireshark
* Useful for incident response and post-attack investigation

---

## 🧩 Project Architecture

```
NIDS/
│
├── main.py          # Entry point, packet capture loop
├── sniffing.py       # Packet sniffing logic
├── analysis.py      # Rule-based attack detection
├── ml_detector.py   # ML anomaly detection (Isolation Forest)
├── rules.py         # Thresholds and detection parameters
├── logger.py        # Alert logging + PCAP export
├── traffic_log.csv  # Alert log output
├── captured_traffic.pcap
└── README.md
```

The system is intentionally modular to reflect production-grade security tools.

---

## ⚙️ Technologies Used

* **Python 3**
* **Scapy** – packet capture and analysis
* **Scikit-learn** – machine learning (Isolation Forest)
* **NumPy** – numerical feature handling
* **PCAP format** – network forensics

---

## 🚀 How It Works (High Level)

1. `sniffer.py` captures live packets
2. Packets are passed to `analysis.py` for rule-based checks
3. Packets are used to train and simultaneously analyzed by `ml_detector.py`
4. Detected attacks or anomalies trigger alerts
5. Alerts are logged and packets are optionally stored

The system operates fully in **real time**.

---

## 🧪 Learning Outcomes

Through this project, the following cybersecurity concepts are demonstrated:

* Network protocol analysis
* Traffic behavior modeling
* Intrusion detection logic
* Threshold-based vs anomaly-based detection
* Practical ML usage in cybersecurity
* Defensive security engineering mindset

---

## 🔮 Future Enhancements

* Feature-rich ML models (time-based and flow-based features)
* Visualization dashboard (Grafana / Flask)

---


## 👤 Author

Developed as a hands-on cybersecurity and systems project to demonstrate real-world IDS design and implementation.
