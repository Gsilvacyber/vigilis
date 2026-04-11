# Vigilis

**Security alert-to-case enrichment platform with behavioral entity graph, threat intelligence, and learning-loop detection.**

Vigilis ingests raw security alerts from any source, normalizes them into a common schema, enriches them with 5 threat intelligence providers, tracks entity relationships in a behavioral graph, and scores them with a transparent tier-aware confidence model.

---

## What makes Vigilis different

| Capability | What it does |
|---|---|
| **Entity Graph** | Tracks relationships between users, hosts, processes, IPs, and domains across all cases. Flags novel or rare entity pairs as verified behavioral signals. |
| **Signal Tier System** | Every signal is classified as `verified` (DB-backed), `observed` (structured field from source tool), or `inferred` (keyword match). Scoring applies tier multipliers so keyword-only cases can't reach critical. |
| **5 Threat Intel Providers** | OTX AlienVault, GreyNoise, WHOIS/RDAP, ip-api.com IP identity, plus local Postgres database of 11,628+ IOCs from abuse.ch feeds (Feodo Tracker, URLhaus, ThreatFox). |
| **Learning Loop** | `calibration.py` reads analyst dispositions and adjusts signal weights based on false-positive rates. The system gets smarter from analyst feedback. |
| **SOAR Framework** | Integration stubs for CrowdStrike (isolate host), Okta (suspend user), ServiceNow (create ticket). |
| **30 Alert Types** | Across 6 domains (identity, endpoint, email, cloud, network, DLP) with MITRE ATT&CK mapping and kill-chain stages. |
| **Sysmon Pipeline** | PowerShell exporter that feeds real endpoint telemetry (process create, network connect, DNS, file create, registry) from any Windows host into Vigilis every 5 minutes. |

---

## Architecture

```
+------------------------------------------------------------------+
|                     Alert Sources                                |
|  Sysmon * SIEM * EDR * IdP * Email Gateway * Cloud * Custom     |
+-------------------------------+----------------------------------+
                                | POST /api/v1/cases
                                v
+------------------------------------------------------------------+
|                    Vigilis Backend (FastAPI)                     |
|  +--------------+  +-----------------+  +------------------+    |
|  |  Normalize   |->|    Enrich       |->|  Entity Graph    |    |
|  |  alert_mapper|  |  (8 phases)     |  |  (detection      |    |
|  |              |  |                 |  |   brain)         |    |
|  +--------------+  +-----------------+  +------------------+    |
|                             |                                    |
|         +-------------------+-------------------+                |
|         v                   v                   v                |
|  +----------+       +--------------+    +-------------+         |
|  | Threat   |       |   Scoring    |    |   Case      |         |
|  | Intel    |       | (tier-aware) |    |  Grouping   |         |
|  | (5 prov) |       +--------------+    | & Incidents |         |
|  +----------+                           +-------------+         |
+-----------------------------+------------------------------------+
                              |
                 +------------+------------+
                 v            v            v
          +----------+ +----------+ +----------+
          | Webhook  | |  SOAR    | | Postgres |
          | Delivery | | Actions  | |  Store   |
          +----------+ +----------+ +----------+
```

---

## Quick start

### Prerequisites
- Docker + Docker Compose
- (Optional) Python 3.11+ for running tests locally

### Run with Docker
```bash
git clone <your-repo> vigilis
cd vigilis
cp .env.example .env
# Edit .env and add your OTX_API_KEY (free at otx.alienvault.com)
docker compose up --build -d
```

Verify it's running:
```bash
curl http://localhost:8000/health
# -> {"status":"ok", "providers":{...}, "entity_graph":{...}}
```

### Open the UI
Open your browser to:
```
http://localhost:8000/
```

Available views: `/cases`, `/incidents`, `/admin`, `/metrics`, `/rules`, `/upload`, `/enrich`.

### Upload sample data
```bash
# CSV uploads (Sentinel, Splunk, or generic format)
curl -X POST http://localhost:8000/api/v1/upload \
  -H "X-API-Key: socai-demo-key-do-not-use-in-production" \
  -F "file=@sample_data/sentinel_export.csv"
```

Or send a JSON alert directly:
```bash
curl -X POST http://localhost:8000/api/v1/cases \
  -H "X-API-Key: socai-demo-key-do-not-use-in-production" \
  -H "Content-Type: application/json" \
  -d '{
    "tenantId": "demo",
    "customer": {"name": "Demo Corp", "environment": "prod"},
    "source": {
      "sourceSystem": "idp", "sourceName": "Azure AD",
      "sourceAlertId": "test-001", "sourceSeverity": "high"
    },
    "alertType": "identity.suspiciousSignIn",
    "title": "Test alert",
    "severity": "high",
    "eventTime": "2026-04-10T00:00:00Z",
    "rawAlert": {
      "identity": {"upn": "user@demo.com"},
      "device": {"hostname": "WS-01"},
      "ips": [{"ipAddress": "198.51.100.10", "role": "anomalous"}]
    }
  }'
```

---

## Live endpoint telemetry (Sysmon)

To feed real endpoint events into Vigilis from a Windows host:

1. Install Sysmon with the SwiftOnSecurity config
2. Copy `scripts/export_sysmon.ps1` to `C:\Tools\SysmonExport\` on the target host
3. Schedule it via Task Scheduler to run every 5 minutes
4. Events flow into Vigilis automatically, building the entity graph baseline

See `scripts/export_sysmon.ps1` for the full exporter.

---

## Project structure

```
vigilis/
|-- backend/
|   |-- app/
|   |   |-- api/              # FastAPI routes
|   |   |-- core/             # Config, auth, metrics, DB session
|   |   |-- db/               # SQLModel models
|   |   |-- schemas/          # Pydantic request/response schemas
|   |   |-- services/
|   |   |   |-- enrichment/   # The core enrichment engine
|   |   |   |   |-- mappers/       # Per-domain extractors
|   |   |   |   |-- providers/     # Threat intel providers
|   |   |   |   |-- entity_graph.py  # Detection brain
|   |   |   |   |-- scoring.py       # Tier-aware confidence scoring
|   |   |   |   `-- weights.py       # Signal weight registry
|   |   |   |-- case_service.py      # Case CRUD
|   |   |   |-- incident_service.py  # Case correlation -> incidents
|   |   |   |-- calibration.py       # Learning loop
|   |   |   `-- integrations/soar.py # SOAR action framework
|   `-- tests/                # 445 tests
|-- scripts/
|   `-- export_sysmon.ps1     # Sysmon -> Vigilis pipeline
|-- sample_data/              # Example alerts for each alert type
|-- docs/                     # Architecture, API, deployment docs
|-- docker-compose.yml
`-- Dockerfile
```

---

## Running tests

```bash
python -m pytest backend/tests/ -q
# 445 passed, 19 skipped
```

---

## Threat intel providers

| Provider | What it does | Setup |
|---|---|---|
| **LocalDBProvider** | Postgres lookup of 11,628+ IOCs from abuse.ch feeds | Auto-loaded on first startup |
| **OTXProvider** | AlienVault OTX pulse lookup | Free API key at [otx.alienvault.com](https://otx.alienvault.com) |
| **GreyNoiseProvider** | Background noise / internet scanner identification | Free community tier (25 req/week) |
| **WHOISProvider** | Domain age and registration details | No API key needed (RDAP) |
| **ip-api.com** | IP organization / proxy / VPN identification | Free tier, 45 req/min |
| **AbuseIPDB** (optional) | IP reputation lookup | Free tier, 1000 req/day |

---

## Signal tier system

Not all signals carry equal evidential weight. Vigilis classifies every signal into one of three tiers:

- **`verified`** (1.0x multiplier): DB query or external API confirms the indicator. E.g., OTX confirms the IP is in 50+ threat pulses.
- **`observed`** (0.4x multiplier): A pre-populated structured field from the source tool. E.g., `_isAdminGroupMember: true` from Azure AD.
- **`inferred`** (0.6x multiplier): Keyword match on alert text. E.g., "lateral movement" appears in the description.

**Scoring rule:** A case with no verified signals is capped at 65/100. A case with only keyword matches cannot reach "critical" severity. This prevents theatrical scoring from keyword lookups.

---

## Entity graph

The entity graph tracks relationships between entities across all cases:

- `user <-> host` — Who logs into what
- `user <-> ip` — Who connects from where
- `host <-> process` — What runs on each machine
- `host <-> ip` — What each host connects to
- `process <-> ip` — Which processes make which network connections
- `ip <-> domain` — IP/domain correlations

When a new case arrives, the graph fires verified signals:
- `new_entity_relationship` (weight 20) — Entity pair never seen before
- `rare_entity_relationship` (weight 15) — Pair seen <= 2 times previously
- `entity_graph_anomaly` (weight 18) — 3+ new relationships in a single case
- `process_on_new_host` (weight 18) — Process never seen on this host
- `rare_process_on_server` (weight 20) — Rare process on server infrastructure
- `known_tool_on_dc` (weight 25) — Attack tool on a domain controller

Cold-start suppression prevents false positives on fresh deployments (signals require >= 20 baseline relationships before firing).

---

## License

TBD — project currently private.

---

## Status

- Done: 30 alert types across 6 domains
- Done: 5 threat intel providers + local IOC database
- Done: Entity graph (detection brain) with cold-start suppression
- Done: Tier-aware signal scoring
- Done: Learning loop for signal calibration
- Done: SOAR integration framework
- Done: Sysmon live endpoint pipeline
- Done: 445 tests passing
- In progress: Windows Security Event Log, M365, Azure AD integration
- In progress: SOC 2 readiness, SSO, load testing
