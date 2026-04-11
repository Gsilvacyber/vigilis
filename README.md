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

## Live endpoint telemetry

Vigilis ships with six PowerShell exporters that feed real Windows endpoint
events into the pipeline. Each exporter is a separate script with its own
state file — failures in one don't cascade.

| Exporter | Source | Cadence | What it captures |
|---|---|---|---|
| `export_sysmon.ps1` | Sysmon Operational log | every 5 min | Process create, network, file create, registry, DNS, LSASS access, named pipes, WMI persistence (EIDs 1, 3, 10, 11, 12, 13, 17, 18, 19, 20, 21, 22) |
| `export_secevt.ps1` | Windows Security Event Log | every 5 min | Logon (4624/4625), privilege (4672), process (4688), service install (4697), scheduled task (4698), account create (4720), group add (4728/4732), log clear (1102) |
| `export_psbl.ps1` | PowerShell Operational log | every 5 min | Script Block Logging (EventID 4104) — captures decoded PowerShell source code matched against 62 MITRE patterns |
| `export_state.ps1` | Host state snapshots | hourly | Services, scheduled tasks, local users, autoruns (~15 registry keys), installed programs — diffed against previous snapshot to emit only drift events |

### Setup

1. **Install Sysmon** with the SwiftOnSecurity config:
   ```powershell
   C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml
   ```
2. **Enable PowerShell Script Block Logging** (for `export_psbl.ps1`):
   ```powershell
   New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force
   New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord -Force
   ```
3. **Copy exporters** to `C:\Tools\SysmonExport\` on the target host
4. **Register scheduled tasks** (one per exporter) to run every 5 minutes
   (hourly for `export_state.ps1`) with `SYSTEM` account, `Highest` run level
5. Events flow into Vigilis automatically, building the entity graph baseline

### Noise reduction (Phase 1)

`export_sysmon.ps1` applies aggressive filtering to keep signal-to-noise high:
- EventID 11 file-create events from `C:\Windows\WinSxS\`, Microsoft Store,
  Windows Update, Defender definitions, and Microsoft Edge user data are dropped
- Benign writer processes (`svchost`, `TiWorker`, `TrustedInstaller`, `MsMpEng`,
  `MoUsoCoreWorker`, `OneDrive`, `msedge`) are excluded
- File-create events from the same `(process, directory, user)` within a 5-minute
  window are aggregated into a single `endpoint.massFileCreate` alert
- Repeated process-create events with identical command lines are deduplicated

### Threat intel providers

Vigilis ships with 5 active providers + 2 optional (require API keys):

| Provider | Setup | Free tier limit |
|---|---|---|
| **LocalDBProvider** | Always active | Zero API calls — queries local IOC database |
| **OTXProvider** | Set `OTX_API_KEY` in `.env` | Free — get key at [otx.alienvault.com](https://otx.alienvault.com) |
| **GreyNoiseProvider** | Optional `GREYNOISE_API_KEY` | Community: 25 req/week; free API: 500 req/day |
| **WHOISProvider** | Always active | RDAP (no key) |
| **ip-api.com** | Always active | 45 req/min |
| **VirusTotalProvider** | Set `VIRUSTOTAL_API_KEY` in `.env` | Free: 4 req/min, 500 req/day |
| **AbuseIPDBProvider** | Set `ABUSEIPDB_API_KEY` in `.env` | Free: 1000 req/day |

### Local IOC database

On startup, Vigilis downloads 5 free IOC feeds from abuse.ch into a local
Postgres table. Every IP/domain/hash in an incoming alert is checked against
this table — zero API calls, sub-millisecond lookups:

| Feed | IOC type | Count |
|---|---|---|
| Feodo Tracker | Botnet C2 IPs | ~300 |
| URLhaus | Malicious domains | ~1000 |
| ThreatFox | Mixed IOCs (IPs, domains, hashes) | ~2000 |
| MalwareBazaar | Malware SHA256 hashes | ~5000 |
| URLhaus hashes | Hosted payload SHA256 hashes | ~5000 |

Feeds auto-update every 24 hours via a background task.

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
