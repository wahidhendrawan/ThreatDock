[![CI](https://github.com/wahidhendrawan/ThreatDock/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/ThreatDock/actions/workflows/ci.yml)

# ThreatDock 🛡️

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL-3.0-blue.svg)](https://github.com/wahidhendrawan/ThreatDock/blob/main/LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0-green.svg)](https://github.com/wahidhendrawan/ThreatDock/releases)
[![CI](https://github.com/wahidhendrawan/ThreatDock/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/ThreatDock/actions)
[![Pages](https://img.shields.io/badge/docs-🌐-orange.svg)](https://wahidhendrawan.github.io/ThreatDock/)
**Centralized Threat Intelligence & Security Alert Dashboard**

ThreatDock is a professional-grade security alert aggregator and threat intelligence platform. It seamlessly integrates multiple OSINT sources, CVE databases, and private intelligence feeds into a unified, actionable dashboard. Designed for security researchers and SOC analysts, it enables rapid identification, tracking, and response to emerging threats.

---

## ℹ️ About

ThreatDock is designed to centralize and automate the workflow of Security Operations Centers (SOC) and threat hunters. By aggregating external attack surface management (EASM) data, digital risk protection (DRP), and threat intelligence (TI) into a single pane of glass, ThreatDock drastically reduces the mean time to detect (MTTD) and mean time to respond (MTTR) to emerging threats and active exposures.

---

## 🚀 Key Features
- **Intelligent Aggregation**: Unified feed from GitHub Security Advisories, NVD CVEs, Red Hat Security, AlienVault OTX, and ThreatFox.
- **Advanced Ingestion**: Built-in RSS collectors for SANS ISC, CISA (US-CERT), BleepingComputer, Dark Reading, and more.
- **Contextual Asset Intelligence**: Deeply enriches assets with mapped CVEs, active IOCs, vendor risks, and OSINT findings.
- **Unified Risk Prioritization**: Single scoring system across External Assets, Digital Risk, Brand Exposure, and Third-Party Risk Management.
- **Case Management Workflow**: Alert ownership, priority, SLA dates, tags, summaries, comments, and audit history for SOC triage.
- **Operational Intel Health**: Collector health, ingestion history, IOC registry, CISA KEV/FIRST EPSS enrichment, and cross-source correlations.
- **Context-Rich Threat Analysis**: Visual MITRE ATT&CK distribution and deep correlation mapping.
- **Automated Notifications**: Slack, Microsoft Teams, Telegram, and n8n webhooks with customizable severity thresholds and JSON-based routing rules.
- **Enterprise Architecture**: Built-in Nginx Reverse Proxy handles API routing (`/api` and `/auth`) transparently without cross-origin issues or SSL mixed-content errors.
- **Dynamic Configuration**: UI-driven API key management with active validation status.

---

## 🛠️ Tech Stack
- **Frontend**: React.js, Lucide Icons, Vanilla CSS (Premium Dark/Light Themes), Nginx Reverse Proxy.
- **Backend**: Node.js, Express.js.
- **Storage**: PostgreSQL 16 with host bind-mounted data under `./data/postgres`.
- **Deployment**: Docker, Docker Compose.

---

## 🏁 Quick Start

### 1. Prerequisites
- Docker & Docker Compose installed.

### 2. Configuration
Clone the repository and prepare your environment variables:
```bash
git clone https://github.com/wahidhendrawan/ThreatDock.git
cd ThreatDock/backend
cp .env.example .env
```
Edit `.env` and add your API keys to enable full intelligence enrichment. The default local administrator will be seeded using `AUTH_USER` and `AUTH_PASSWORD`.

### 3. Deployment
Run the entire stack using Docker:
```bash
docker-compose build --no-cache
docker-compose up -d
```

PostgreSQL data is persisted on the host at `./data/postgres`, not inside the backend container. To override the default database credentials, set `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` in the shell or a root-level Compose `.env` before starting the stack.

### Migrating Existing SQLite Data
If you are upgrading from the older SQLite deployment, stop the old backend, copy `/app/alerts.db` from the backend container to a host backup directory, start PostgreSQL, then run:
```bash
docker compose run --rm -v /opt/ThreatDock/data/sqlite-backup:/sqlite-backup:ro -e SQLITE_DB_PATH=/sqlite-backup/alerts.db backend npm run migrate:postgres
```

### 4. Access
- **Unified Dashboard & API**: `http://localhost:3000` (Routed by Nginx)
- The frontend proxy will automatically route `/api/*` and `/auth/*` requests internally to the backend.

---

## 📊 Supported Integrations
| Source | Type | Description |
| :--- | :--- | :--- |
| **AlienVault OTX** | IOC / Pulses | Subscription-based threat pulses. |
| **ThreatFox** | IOCs | Real-time malware indicators. |
| **MISP** | Threat Intel | Community-driven threat sharing. |
| **NVD / GitHub** | CVEs | Vulnerability data and security advisories. |
| **CISA KEV / FIRST EPSS** | Exploit Prioritization | Known exploited vulnerability and exploit-probability enrichment. |
| **BreachDirectory (RapidAPI)** | Credential Exposure | Credential breach lookup for Digital Risk workflows. |
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
This project is licensed under the GNU General Public License v3.0.
