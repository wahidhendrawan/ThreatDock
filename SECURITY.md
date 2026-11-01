# Security Policy

## Supported versions

Only the latest release of ThreatDock gets security fixes. Please check that the problem still exists there before reporting.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository ([direct link](https://github.com/wahidhendrawan/ThreatDock/security/advisories/new)). Do not open a public issue, discussion or pull request, and do not post exploit details or credentials anywhere public.

Please include:

- the version or commit you tested, and how you deployed it (Docker Compose, bare metal)
- the smallest steps or input that reproduce the problem
- what an attacker gains (data exposure, code execution, privilege escalation, denial of service, …)

Remove real credentials, customer data and sensitive logs from any evidence you share.

You should get a first reply within 7 days. Fixed issues are credited in the release notes unless you ask otherwise.

## In scope

- Authentication, MFA, role or tenant isolation bypass (HTTP API and WebSocket)
- Exposure of tokens, API keys or settings to users who should not see them
- Server-side request forgery through feed fetchers or enrichment adapters
- Injection (SQL, command, template) and stored XSS through ingested feed data

## Out of scope

- Behaviour, rate limits or data quality of third-party feeds and APIs (OTX, ThreatFox, NVD, …)
- Testing third-party APIs beyond the keys you own

## Safe harbor

Good-faith research that follows this policy will not be treated as a violation of the license or of this policy. Only test against your own deployment, access no more data than needed to show the issue, and do not degrade services for other people.
