# SOCAI Architecture Overview

## System Overview

SOCAI (Security Operations Case AI) is a security alert triage and enrichment platform built with:

- **FastAPI** — async Python web framework serving REST API and WebSocket feeds
- **PostgreSQL** — primary data store for cases, incidents, audit logs, and configuration
- **Docker Compose** — single-command deployment of API + database
- **Optional Redis** — caching layer for threat intel lookups and rate limiting

## Request Flow

```
Alert Ingestion (JSON/CSV upload, webhook push, or API call)
    │
    ▼
Alert Mapper ──► Normalizes vendor-specific formats (Chronicle, Sentinel, etc.)
    │
    ▼
Enrichment Pipeline ──► Threat intel lookups (VirusTotal, AbuseIPDB)
    │                    Entity extraction (identity, device, IP, app, file, mailbox)
    │                    Geo-IP resolution
    ▼
Confidence Scoring ──► Multi-signal weighted scoring engine
    │                   Severity mapping, historical calibration
    ▼
Case Creation ──► One case per normalized alert with full enrichment context
    │
    ▼
Alert Grouping ──► Deduplicates and groups cases by alert type + entity
    │                within configurable time window (default 60 min)
    ▼
Incident Correlation ──► Links related cases across kill-chain stages
    │                      Time-windowed entity matching (default 24 hours)
    ▼
Webhook Delivery ──► Pushes enriched cases to SOAR / ticketing systems
```

## Key Components

### Threat Intelligence Providers
- **VirusTotal** — file hash, domain, and IP reputation lookups
- **AbuseIPDB** — IP abuse confidence scoring
- **Built-in heuristics** — impossible travel, password spray detection, MFA fatigue patterns

### Confidence Scoring Engine
- Weighted signal aggregation (threat intel hits, entity risk, behavioral anomalies)
- Labels: critical (85+), high (60-84), medium (30-59), low (0-29)
- Calibration feedback loop for analyst-driven score tuning

### Kill-Chain Analyzer
- Maps alert types to MITRE-aligned kill-chain stages
- Stages: Initial Access, Credential Access, Execution, Privilege Escalation, Lateral Movement, Exfiltration
- Incident correlation uses kill-chain progression as a grouping signal

### Job Queue
- In-process background job runner for long-running batch operations
- Status tracking: pending, running, completed, failed
- Progress reporting with percentage and message updates

### Suppression Rules
- Analyst-defined rules to auto-close known benign patterns
- Reduces alert fatigue by filtering recurring false positives

## Database Schema

| Table | Purpose |
|-------|---------|
| `tenants` | Multi-tenant isolation |
| `cases` | Core alert cases with enrichment, scoring, entities |
| `case_sources` | Source alert references and vendor metadata |
| `case_confidence_signals` | Individual scoring signals per case |
| `case_disposition_events` | Disposition change history |
| `case_notes` | Analyst notes and annotations |
| `incidents` | Correlated incident groups |
| `incident_case_links` | Many-to-many case-incident mapping |
| `webhook_deliveries` | Outbound webhook delivery log |
| `api_keys` | Hashed API keys with RBAC roles |
| `suppression_rules` | Auto-suppression pattern definitions |
| `calibration_feedback` | Analyst feedback for score tuning |
| `signal_telemetry` | Enrichment provider response telemetry |
| `audit_events` | Security audit trail for all admin actions |

## Ingestion Methods

| Method | Status | Description |
|--------|--------|-------------|
| File Upload | Available | JSON or CSV via `/api/v1/demo/upload` |
| Webhook Push | Available | POST to `/api/v1/ingest/batch` |
| API Pull | Planned | Scheduled polling from SIEM APIs |

## Authentication and Multi-Tenancy

- API key authentication via `X-API-Key` header
- Keys are SHA-256 hashed at rest; only prefix is stored in plaintext
- RBAC roles: `analyst` (read/write cases), `admin` (key management, audit log)
- Tenant isolation on all data queries
