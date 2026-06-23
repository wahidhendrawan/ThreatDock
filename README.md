[![CI](https://github.com/wahidhendrawan/ThreatDock/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/ThreatDock/actions/workflows/ci.yml)

# ThreatDock 🛡️

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL-3.0-blue.svg)](https://github.com/wahidhendrawan/ThreatDock/blob/main/LICENSE)
[![Release](https://img.shields.io/badge/release-v1.2.0-green.svg)](https://github.com/wahidhendrawan/ThreatDock/releases)
[![CI](https://github.com/wahidhendrawan/ThreatDock/actions/workflows/ci.yml/badge.svg)](https://github.com/wahidhendrawan/ThreatDock/actions)
[![Pages](https://img.shields.io/badge/docs-🌐-orange.svg)](https://wahidhendrawan.github.io/ThreatDock/)

**Centralized Threat Intelligence & Security Alert Dashboard**

ThreatDock is a professional-grade security alert aggregator and threat intelligence platform. It seamlessly integrates multiple OSINT sources, CVE databases, and private intelligence feeds into a unified, actionable dashboard. Designed for security researchers and SOC analysts, it enables rapid identification, tracking, and response to emerging threats.

---

## ℹ️ About

ThreatDock is designed to centralize and automate the workflow of Security Operations Centers (SOC) and threat hunters. By aggregating external attack surface management (EASM) data, digital risk protection (DRP), and threat intelligence (TI) into a single pane of glass, ThreatDock drastically reduces the mean time to detect (MTTD) and mean time to respond (MTTR) to emerging threats and active exposures.

---

## 🚀 Key Features

### Intelligence & Ingestion
- **Intelligent Aggregation**: Unified feed from GitHub Security Advisories, NVD CVEs, Red Hat Security, AlienVault OTX, ThreatFox, and RSS feeds.
- **Advanced Ingestion**: Built-in collectors for SANS ISC, CISA (US-CERT), BleepingComputer, Dark Reading, and more.
- **IOC Registry**: Automatic extraction and correlation of CVEs, IPs, domains, hashes from all ingested sources.
- **CISA KEV / FIRST EPSS**: Automatic enrichment of CVEs with Known Exploited Vulnerability and Exploit Prediction scoring.
- **Cross-Source Correlations**: AI-free correlation engine linking alerts, indicators, assets, and vendors into unified findings.
- **Resilient Fetch**: Exponential backoff retry (per-source config) for NVD, OTX, and other external sources.

### Performance & Architecture (v1.2)
- **Batch Database Operations**: Bulk INSERT (1000 rows) for alerts, indicators, and CVE enrichment — 10-50x faster ingestion.
- **Worker Thread Processing**: CPU-intensive correlation rebuild runs in a dedicated worker thread — no event loop blocking.
- **Real-Time WebSocket Updates**: Dashboard, alerts, and IntelOperations auto-refresh via Socket.IO — no manual refresh needed.
- **Server-Side Pagination**: Scalable `{data, total, page, limit}` response format for alerts, assets, indicators, and correlations.
- **In-Memory Job Queue**: Lightweight queue with optional Redis/Bull backing for parallel source fetching.
- **Settings Cache**: 5-minute TTL cache on runtime settings reduces redundant DB queries per fetch cycle.
- **Redis Service**: Optional Redis 7 service for production-grade queue persistence and caching.
- **N+1 Query Elimination**: Word-index-based asset matching replaces O(n*m) nested loops in correlation engine.
- **Data Retention**: Weekly automatic pruning of alerts older than 90 days (configurable).
- **In-Memory Rate Limiter**: Per-IP sliding window — auth 120/min, API 600/min.
- **Decoupled Scheduler**: Cron jobs run via `process.nextTick` to prevent "missed execution" during long fetch cycles.

### Platform & UX
- **Real-Time Live Indicators**: IntelOperations shows live source-health pulse with animated dot indicators.
- **PWA Support**: Service worker with network-first caching, manifest.json, and push notification support.
- **Swagger/OpenAPI Docs**: Self-hosted interactive API documentation at `/api/docs` (no CDN dependencies).
- **Manual Fetch Trigger**: "Fetch Sources" button in IntelOperations triggers immediate ingestion cycle.
- **Timeout Safety**: 30-minute automatic lock reset for stuck ingestion runs.
- **Parallel Notifications**: Slack, Teams, Telegram, and n8n webhooks sent concurrently via `Promise.allSettled`.
- **Dark/Light Theme Toggle**: Built-in theme switcher with localStorage persistence.

### Detection & Response
- **Contextual Asset Intelligence**: Deeply enriches assets with mapped CVEs, active IOCs, vendor risks, and OSINT findings.
- **Unified Risk Prioritization**: Single scoring system across External Assets, Digital Risk, Brand Exposure, and Third-Party Risk Management.
- **Case Management Workflow**: Alert ownership, priority, SLA dates, tags, summaries, comments, and audit history for SOC triage.
- **Operational Intel Health**: Collector health dashboard, ingestion history, IOC registry, and cross-source correlations.
- **Context-Rich Threat Analysis**: Visual MITRE ATT&CK distribution and deep correlation mapping.
- **Dynamic Configuration**: UI-driven API key management with active validation status.
- **IOC Export**: Export indicators in JSON, CSV, or STIX 2.1 format for SIEM ingestion (`GET /api/intelligence/indicators/export`).

### Infrastructure
- **Enterprise Architecture**: Built-in Nginx Reverse Proxy handles API routing transparently.
- **PostgreSQL 16**: With composite indexes for time-series query performance.
- **Docker Compose**: Single-command deployment with 5 services (postgres, redis, backend, frontend, db-backup).
- **Automated DB Backups**: `db-backup` service runs `pg_dump` every 6 hours with 30-day retention.
- **Error Monitoring**: Global unhandled rejection/exception capture with rotating log files and optional webhook alerts.
- **Automated Notifications**: Slack, Microsoft Teams, Telegram, and n8n webhooks with customizable severity thresholds.
- **NVD Optimization**: Payload stripping reduces CVE response size by 90%+, AbortController timeout, 24h polling window.

---

## 🛠️ Tech Stack
- **Frontend**: React 18, React Router, Recharts, Lucide Icons, Vanilla CSS (Premium Dark/Light Themes), Socket.IO Client
- **Backend**: Node.js, Express.js, Socket.IO, Worker Threads, node-cron
- **Database**: PostgreSQL 16, optional Redis 7 for queue
- **Infrastructure**: Docker, Docker Compose, Nginx Reverse Proxy

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
docker compose up -d --build
```

PostgreSQL data is persisted on the host at `./data/postgres`. To override the default database credentials, set `POSTGRES_DB`, `POSTGRES_USER`, and `POSTGRES_PASSWORD` before starting.

### 4. Access
- **Dashboard**: `http://localhost:3000` / `https://frontend.threatdock.orb.local`
- **Default login**: As configured in `.env` (`AUTH_USER` / `AUTH_PASSWORD`)
- **API Documentation**: `http://localhost:3000/api/docs`
- **Backend Health**: `http://localhost:5002/`

---

## 📊 Supported Integrations
| Source | Type | Description |
| :--- | :--- | :--- |
| **AlienVault OTX** | IOC / Pulses | Subscription-based threat pulses. |
| **ThreatFox** | IOCs | Real-time malware indicators. |
| **MISP** | Threat Intel | Community-driven threat sharing. |
| **NVD / GitHub** | CVEs | Vulnerability data and security advisories. |
| **Red Hat Security** | CVEs | Red Hat product vulnerability data. |
| **CISA KEV / FIRST EPSS** | Exploit Prioritization | Known exploited vulnerability and exploit-probability enrichment. |
| **BreachDirectory (RapidAPI)** | Credential Exposure | Credential breach lookup for Digital Risk workflows. |
| **IntelOwl** | Analysis | Comprehensive malware & file analysis. |
| **URLScan.io** | Brand Exposure | Domain and brand monitoring. |
| **RSS Feeds** | News | Customizable RSS intelligence feeds. |

---

## 📡 API Documentation

Interactive API documentation is available at `/api/docs` when the backend is running:

```bash
# OpenAPI 3.0 spec
curl http://localhost:5002/api/docs.json

# Swagger UI
open http://localhost:3000/api/docs
```

### Key Endpoints
| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/alerts?page=&limit=` | Paginated alerts with filters |
| `GET` | `/api/assets?page=&limit=` | Paginated asset inventory |
| `GET` | `/api/intelligence/indicators` | IOC registry |
| `GET` | `/api/intelligence/indicators/export?format=csv` | IOC export (json, csv, stix) |
| `GET` | `/api/intelligence/correlations` | Correlated findings |
| `GET` | `/api/ingestion/health` | Source health status |
| `POST` | `/api/ingestion/fetch` | Manual source fetch trigger |
| `POST` | `/auth/local-login` | Authentication |

---

## 🧪 Testing

```bash
cd backend
npm test
```

Unit tests cover intelligence service (severity normalization, CVE extraction, domain parsing, indicator type detection), in-memory cache module (set/get/TTL/del/flush), and job queue (buffered processing).

---

## 🗂️ Deployment Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Nginx:3000  │────▶│  Backend:5002 │────▶│ PostgreSQL   │
│  (Frontend)  │     │  (Express)   │     │  (Postgres)  │
└─────────────┘     │  + Socket.IO │     └──────────────┘
                    │  + Worker    │     ┌──────────────┐
                    │  + Scheduler │────▶│  Redis:6379  │
                    └──────────────┘     │  (Optional)  │
                    ┌──────────────┐     └──────────────┘
                    │  db-backup   │
                    │  (pg_dump    │
                    │   6h cron)   │
                    └──────────────┘
```

---

## 🛡️ Detection & Defensive Context
ThreatDock is designed to facilitate the **Blue Team** workflow. By aggregating various feeds, it provides:
1. **Early Warning**: Automated tracking of new CVEs relevant to your tech stack.
2. **Detection Enrichment**: Export IOCs in CSV/STIX format for ingestion into SIEM (Wazuh/ELK) or EDR.
3. **SOAR Integration**: Built-in webhooks allow easy connection to tools like **n8n** for automated incident response.

---

## 🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License
This project is licensed under the GNU General Public License v3.0.
