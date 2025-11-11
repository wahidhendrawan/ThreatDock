# ThreatDock

**ThreatDock** is a full-stack security alert and threat intelligence dashboard.  It aggregates vulnerability advisories from the National Vulnerability Database (NVD), GitHub Security Advisories, and Red Hat security data, then enriches this information with open‑source threat intelligence.  The dashboard runs entirely in Docker and exposes a simple REST API and responsive web interface for filtering and prioritising alerts.

## Features

- **Data aggregation from multiple sources**
  - **GitHub Advisories** – queries GitHub’s public Security Advisories API to collect CVEs and security notices from the open‑source ecosystem.  A GitHub token is optional but increases API rate limits.
  - **NVD CVEs** – pulls newly published CVEs from the US National Vulnerability Database via its JSON API and derives severity from CVSS scores.
  - **Red Hat Security Data** – downloads recent CVEs and advisories from Red Hat’s public security feed, mapping Red Hat severities to standard Critical/High/Medium/Low values.
  - **OTX Pulses** – integrates with the AlienVault Open Threat Exchange API.  When you provide an API key, the backend queries your subscribed pulses (`/api/v1/pulses/subscribed`) and converts each pulse into a dashboard alert【603937255844768†L49-L52】.  OTX pulses are treated as medium‑severity items since the API does not include explicit severity ratings.
  - **ThreatFox IOCs** – integrates with the threat intelligence platform from abuse.ch.  Using a free Auth‑Key, the backend calls the ThreatFox API (`/api/v1` with `query=get_iocs`) to retrieve indicators of compromise (IOCs) for the last seven days【916006223225416†L44-L52】.  Each IOC is shown as a high‑severity alert with a link back to the ThreatFox portal.

  - **MISP events** – ThreatDock can ingest events from your own MISP instance.  The backend uses the `/events/index` endpoint of the MISP Automation API to fetch recent events and maps the numeric `threat_level_id` field (1 = High, 2 = Medium, 3 = Low) to a corresponding severity【380436334720828†L240-L319】.  Provide `MISP_URL` and `MISP_API_KEY` in your environment to enable this feature.

  - **IntelOwl analysis** – A placeholder integration exists for IntelOwl, an OSINT analysis platform.  To activate, supply `INTELO_OWL_API_KEY` and implement calls in `backend/services/intelowl.js`.  By default this integration is disabled.

  - **YARA/Sigma rules** – ThreatDock includes a stub to match alerts against YARA and Sigma rules.  You can integrate with an existing YARA/Sigma service (for example, your `yara-sigma-webui` project) by implementing `backend/services/yaraSigma.js`.  Matched alerts are returned as a separate source.

  - **RSS Feeds** – ThreatDock can also ingest news and analysis from curated cybersecurity RSS feeds.  The backend parses several well‑known feeds drawn from the *awesome-threat-intel-rss* project, including:

    - **SANS Internet Storm Center** (feed: `https://isc.sans.edu/rssfeed_full.xml`)【36635210653818†L361-L366】 – a global cooperative monitor for cyber threats and internet security.
    - **US‑CERT National Cyber Awareness System – Alerts** (feed: `https://us-cert.cisa.gov/ncas/alerts.xml`)【36635210653818†L375-L378】 – providing timely information on current security issues and vulnerabilities.
    - **BleepingComputer** (feed: `https://www.bleepingcomputer.com/feed`)【36635210653818†L417-L423】 – a popular technology news site focusing on cybersecurity threats and advice.
    - **Dark Reading** (feed: `https://www.darkreading.com/rss/all.xml`)【36635210653818†L433-L438】 – a trusted online community for security professionals.
    - **Krebs on Security** (feed: `http://krebsonsecurity.com/feed`)【36635210653818†L487-L493】 – investigative reporting on cybercrime by journalist Brian Krebs.

    You can extend or customise the RSS feed list by editing `backend/services/rss.js` and adding more feed URLs.  Articles from these feeds are treated as low‑severity alerts by default, and their titles and publication dates are displayed in the dashboard.

- **REST API** – all alerts are stored in a local SQLite database and exposed via `/alerts`.  Query parameters allow filtering by severity, source, and date range.  Results are ordered by severity and recency.

- **Interactive dashboard** – a React frontend displays alerts in a sortable table.  Users can filter by severity (Critical, High, Medium, Low), data source (GitHub, NVD, Red Hat, OTX, ThreatFox), and date range.  Clicking an alert opens the original advisory or IOC page in a new tab.
  - The table now includes columns for **Attack Phase** and **Status**.  Attack phase corresponds to the MITRE ATT&CK stage (currently defaulting to “Unknown” until future classification is implemented).  Status can be changed via a dropdown to “Open”, “In Progress” or “Resolved”.
  - An “Alert Statistics” section visualises the distribution of alerts by severity and shows the number of alerts over time using simple bar and line charts (powered by the Recharts library).

- **Containerised deployment** – the application is divided into backend and frontend services.  A single `docker‑compose.yml` spins up both containers.  Environment variables are defined in `backend/.env` to configure API keys without modifying code.

## Requirements

- Docker and Docker Compose.
- Node.js and npm (only if you plan to run the services outside of Docker).

## Setup

1. **Clone or extract the repository.**
2. Navigate to the project directory and copy the environment template:

   ```bash
   cp backend/.env.example backend/.env
   ```

3. Edit `backend/.env` and provide any API credentials you want to use:

   - `GITHUB_TOKEN` – personal access token to raise GitHub API rate limits.
   - `NVD_API_KEY` – optional API key from NVD for higher request quotas.
   - `OTX_API_KEY` – your AlienVault OTX API key; required to fetch subscribed pulses【603937255844768†L49-L52】.
   - `THREATFOX_AUTH_KEY` – your ThreatFox Auth‑Key from abuse.ch; required to retrieve IOCs【916006223225416†L44-L52】.
   - `MISP_URL` and `MISP_API_KEY` – placeholders for future integration with a MISP instance.
   - `INTELO_OWL_API_KEY` – reserved for additional OSINT sources.

   - `SLACK_WEBHOOK_URL` – optional Slack Incoming Webhook URL.  If provided, ThreatDock will send notifications for alerts whose severity is equal to or above the value of `NOTIFY_THRESHOLD`.
   - `NOTIFY_THRESHOLD` – severity threshold for Slack notifications (e.g. Critical, High, Medium).  Defaults to High.
   - `AUTH_USER` and `AUTH_PASSWORD` – set these to enable HTTP basic authentication for the backend API.  Leave blank to disable auth.

4. **Build and run the containers**:

   ```bash
   docker‑compose up --build
   ```

   The backend listens on port 5000, and the frontend is served on port 3000.  Navigate to `http://localhost:3000` to view the dashboard.

## Usage

- **Filtering alerts:** Use the dropdowns at the top of the page to select a severity level and source.  Date pickers allow you to restrict results to a start and end date.  The table updates automatically when filters are changed.
  - Additional filters let you select a **status** (Open, In Progress, Resolved) and an **attack phase**.  Attack phase values correspond to MITRE ATT&CK tactic categories; at present they default to “Unknown”.

- **API queries:** The backend API supports the same filters via query parameters.  For example, to retrieve only high‑severity ThreatFox IOCs:

  ```bash
  curl 'http://localhost:5000/alerts?severity=High&source=ThreatFox'
  ```

  To update the status of an alert (e.g. mark alert ID 123 as “Resolved”), send a PATCH request:

  ```bash
  curl -X PATCH 'http://localhost:5000/alerts/123' \
       -H 'Content-Type: application/json' \
       -d '{"status":"Resolved"}'
  ```

## Extending the project

ThreatDock is designed to be extensible.  To add another threat intelligence source:

1. Create a new module under `backend/services/` that uses `axios` to call the external API and returns an array of objects.
2. Normalise the data into the common alert schema (`source`, `externalId`, `title`, `severity`, `date`, `url`) in `fetchAllSources()` within `backend/app.js`.
3. Add an entry in the frontend filter component to expose the new source.

In addition, the backend exposes a stub for Slack notifications and basic HTTP authentication.  To enable Slack notifications, set `SLACK_WEBHOOK_URL` and optionally `NOTIFY_THRESHOLD` in your environment.  To protect the API with simple credentials, set `AUTH_USER` and `AUTH_PASSWORD`.

## Licensing and fair use

All integrated APIs are used according to their respective terms of service.  The ThreatFox API requires a free Auth‑Key and requests must include this key in an `Auth-Key` header【916006223225416†L44-L52】.  The OTX API similarly requires an `X‑OTX‑API‑KEY` header【603937255844768†L49-L52】.  Please respect rate limits and usage policies when running ThreatDock in production.