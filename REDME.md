# 🛡️ Threat-Intel-Pipeline: Automated SOC Assistant 🚀

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![SQLite](https://img.shields.io/badge/SQLite-Database-lightgrey?style=for-the-badge&logo=sqlite)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)

> **"Turning Raw Data into Actionable Intelligence."**
This project is a fully automated **Cyber Threat Intelligence (CTI)** pipeline that monitors, enriches, and reports malicious indicators (IOCs) to stay ahead of cyber threats.

---

## 🏗️ System Architecture
The pipeline operates in three core stages, simulating a real-world **Security Operations Center (SOC)** workflow:

1.  **📥 Ingestion:** Fetches live pulses from **AlienVault OTX**.
2.  **🔍 Enrichment:** Queries **VirusTotal API v3** to determine severity (IPs & Hashes).
3.  **📊 Reporting:** Generates instant **CSV Alerts** for High/Critical threats.



---

## 🚀 Key Features
- **Smart Deduplication:** Never stores the same IOC twice (Optimized SQLite Logic).
- **Rate-Limit Handling:** Intelligent `time.sleep` and backoff strategies to respect API constraints.
- **Multimodal Support:** Handles **IPv4**, **MD5**, **SHA1**, and **SHA256** seamlessly.
- **Hierarchical Logging:** Detailed traceability of every API call and database transaction.

---

## 🛠️ Tech Stack
* **Core:** Python (OOP Architecture)
* **Intelligence:** AlienVault OTX, VirusTotal API.
* **Storage:** SQLite3.
* **Environment:** Dotenv for secure API Key management.

---

## 📂 Project Tree
```text
├── src/
│   ├── collectors/   # API Data Fetching
│   ├── enrichment/   # VirusTotal Logic (The Brain)
│   └── utils/        # DB, Logger, & Reporter
├── reports/          # 🚩 Critical Threat CSVs
├── logs/             # 📜 System History
└── main.py           # ⚡ Entry Point