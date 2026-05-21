# ThreatDock 🛡️
**Centralized Threat Intelligence & Security Alert Dashboard**

ThreatDock is a professional-grade security alert aggregator and threat intelligence platform. It seamlessly integrates multiple OSINT sources, CVE databases, and private intelligence feeds into a unified, actionable dashboard. Designed for security researchers and SOC analysts, it enables rapid identification, tracking, and response to emerging threats.

---

## 🚀 Key Features
- **Intelligent Aggregation**: Unified feed from GitHub Security Advisories, NVD CVEs, Red Hat Security, AlienVault OTX, and ThreatFox.
- **Advanced Ingestion**: Built-in RSS collectors for SANS ISC, CISA (US-CERT), BleepingComputer, Dark Reading, and more.
- **Actionable UI**: React-based dashboard featuring real-time statistics, severity filtering, and MITRE ATT&CK phase tracking.
- **Extensible Backend**: Modular service-based architecture (Node.js/Express) for easy integration of new TI sources.
- **Automated Notifications**: Slack integration with customizable severity thresholds.
- **SOC-Ready**: Supports alert status management (Open/In Progress/Closed) and manual enrichment.

---

## 🛠️ Tech Stack
- **Frontend**: React.js, Lucide Icons, Tailwind CSS (Visual Design).
- **Backend**: Node.js, Express.js.
- **Storage**: SQLite (Lightweight & Portable).
- **Deployment**: Docker, Docker Compose.

---

## 🏁 Quick Start

### 1. Prerequisites
- Docker & Docker Compose installed.
- API Keys for various services (GitHub, OTX, etc. — Optional but recommended).

### 2. Configuration
Clone the repository and prepare your environment variables:
```bash
git clone https://github.com/wahidhendrawan/ThreatDock.git
cd ThreatDock/backend
cp .env.example .env
```
Edit `.env` and add your API keys to enable full intelligence enrichment.

### 3. Deployment
Run the entire stack using Docker:
```bash
docker-compose up --build
```

### 4. Access
- **Dashboard**: `http://localhost:3000`
- **API Backend**: `http://localhost:5000`

---

## 📊 Supported Integrations
| Source | Type | Description |
| :--- | :--- | :--- |
| **AlienVault OTX** | IOC / Pulses | Subscription-based threat pulses. |
| **ThreatFox** | IOCs | Real-time malware indicators. |
| **MISP** | Threat Intel | Community-driven threat sharing. |
| **NVD / GitHub** | CVEs | Vulnerability data and security advisories. |
| **IntelOwl** | Analysis | Comprehensive malware & file analysis. |

---

## 🛡️ Detection & Defensive Context
ThreatDock is designed to facilitate the **Blue Team** workflow. By aggregating various feeds, it provides:
1. **Early Warning**: Automated tracking of new CVEs relevant to your tech stack.
2. **Detection Enrichment**: Export IOCs for ingestion into SIEM (Wazuh/ELK) or EDR.
3. **SOAR Integration**: Built-in webhooks allow easy connection to tools like **n8n** for automated incident response.

---

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License
This project is licensed under the MIT License.