# Vigilis

**A detection engine that refuses to call a keyword match a critical alert.**

Send Vigilis an alert whose title is `"Suspected lateral movement via mimikatz"` and whose description name-drops every red-team term in the book — but with no IP, no hash, no domain, nothing the engine can corroborate. It scores **22/100, label "low"**, and explains why in plain text on the case page.

Add one outbound IP to the same alert. The engine checks it against six threat-intel providers and a local IOC database. If any of them flags the IP, a `verified`-tier signal fires, the score climbs into the medium-to-high band, and the case becomes a real ticket. If none of them flag it, the score stays low.

That asymmetry — between *evidence* and *vibes* — is the whole point of this project.

Most detection tools weight a regex hit on `"mimikatz"` in a process name about the same as a confirmed SHA256 match against a malware database. Both fire the same red banner, both wake up the same Tier 1 analyst at 2 a.m. Vigilis doesn't. Every signal carries a **tier** that captures *what kind of evidence it actually is*, and the tier limits how high the case is allowed to score:

```python
# backend/app/services/enrichment/scoring.py — the cap
if not has_verified and score > 65:
    score = 65
```

A second cap fires earlier: if no positive signals fire at all, the score is forced to ≤20. Free-text keyword matches don't count as positive signals — they're not part of the structured pattern library. The engine has to find concrete structural or external evidence, or it stays low.

The breakdown — every signal that fired, its tier, its weight contribution — is exposed in the case detail response and rendered in the UI. No black box.

---

## Why this exists

I've watched detection tools accumulate signals the way old code accumulates `if` statements: each addition makes the score climb, none of them subtract, and a string match in an alert title eventually weighs as much as a confirmed C2 connection. The result is alert theatre — high-confidence-looking output that an analyst can't trust without re-doing the investigation by hand.

Vigilis takes the opposite default. It treats keyword matches as suggestive, not conclusive, and forces the engine to find at least one verified piece of evidence before a case is allowed to look critical. The cap is small, blunt, and deterministic — exactly the kind of rule a SOC analyst can reason about under load.

---

## How scoring works

Every signal in the engine carries a **tier**:

| Tier | Multiplier | Examples |
|---|---|---|
| `verified` (1.0×) | DB or external API confirms the indicator. | OTX has the IP in 50+ pulses. Local IOC DB matches the hash. Entity graph: this user has never logged into this host before. |
| `observed` (0.4×) | Pre-populated structured field from the source tool. | `_isAdminGroupMember=true` from Azure AD. Sysmon EID 11 `TargetFilename` = a sensitive path. |
| `inferred` (0.6×) | Keyword or pattern match on alert text. | `"lateral movement"` appears in description. PowerShell script block contains `Invoke-Mimikatz`. |

The final score is:

```
score = base_severity + Σ(signal_weight × tier_multiplier)
        + asset_criticality + user_risk
        capped at 100
```

Then the cap fires:

- **No verified signal anywhere → score capped at 65.**
- IR response (host already isolated) → capped at 40.
- Geo-anomaly with no corroboration → capped at 45.
- Zero positive signals → capped at 20.

Weights live in **one** registry — [`backend/app/services/enrichment/weights.py`](backend/app/services/enrichment/weights.py). One signal name = one weight everywhere in the codebase. Tuning is a single-file operation, not a scavenger hunt.

The full score breakdown — every signal that fired, its tier, its weight contribution — is part of the case detail response. It exists because an analyst who can't ask "why did this score 78?" and get a concrete answer will go back to grepping the SIEM.

---

## What this is, and what it isn't

**It is:**
- An open-source detection-scoring engine you can run locally in 60 seconds.
- A reference implementation of tier-aware confidence scoring with auditable output.
- ~870 tests across the scoring pipeline, signal registry, entity graph, and provider integrations.

**It isn't:**
- A SIEM. It doesn't index logs. It expects normalized alerts in.
- A SOAR. It can call out to playbooks (CrowdStrike, Okta, ServiceNow stubs are in the repo) but case action is not its job.
- A startup pitch. There is no SaaS, no SSO, no billing, no hosted offering.

If you want a turnkey product, you want something else. If you want an engine you can read end-to-end and bend to your environment, this is for you.

---

## Honest limitations

The 30-day target on a cold install is roughly **17% of fired signals reach the `verified` tier**. That number is a function of how much external corroboration the engine can pull (threat intel feed coverage, entity graph baseline, asset CMDB, identity context) — not a scoring bug. Free feeds give you ~13K IOCs of coverage; richer integrations push the rate higher.

**Why the cap doesn't move with the verified rate**: the cap is a property of an individual case. Either the engine found verified evidence for *this* alert or it didn't. A higher fleet-average verified rate just means more cases clear the cap, not that the cap is lowered for the cases that don't.

If you're running this on a quiet network with no threat intel, expect most cases to land in the 50–65 band. That's the engine being honest. It is not a feature gap to fix with stronger keyword rules.

---

## Quick start

### Run with Docker
```bash
git clone <repo> vigilis
cd vigilis
cp .env.example .env
# Optional: add OTX_API_KEY, ABUSEIPDB_API_KEY for richer threat intel
docker compose up --build -d
```

### Run with Python (no Docker)
```bash
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# SQLite mode — zero infra
DATABASE_URL=sqlite:///local.db SKIP_INITIAL_FEEDS=true \
  uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

`SKIP_INITIAL_FEEDS=true` defers the IOC feed download to the background scheduler so the server is ready in <100 ms instead of waiting on 7 outbound HTTP calls. Useful for demos and CI.

### Verify
```bash
curl http://localhost:8000/health
# {"status":"ok","providers":{...}}

curl -s "http://localhost:8000/api/v1/metrics/enrichment-quality" \
  -H "X-API-Key: socai-demo-key-do-not-use-in-production"
# {"totalCases":0,"qualityScore":null}  on a fresh DB
```

### See it in action

Send two alerts whose titles and descriptions look identical to a SIEM. The difference is whether the alert contains anything the engine can verify.

```bash
# Alert A — title screams "mimikatz / lateral movement / pass-the-hash"
#           but has no IP, no hash, no domain. Pure free-text bait.
curl -X POST http://localhost:8000/api/v1/cases \
  -H "X-API-Key: socai-demo-key-do-not-use-in-production" \
  -H "Content-Type: application/json" \
  -d @sample_data/keyword_only_alert.json
# -> confidence.score = 22, label = "low"
# -> explanation contains zero positive signals

# Alert B — same text content, plus one outbound IP the engine can check
curl -X POST http://localhost:8000/api/v1/cases \
  -H "X-API-Key: socai-demo-key-do-not-use-in-production" \
  -H "Content-Type: application/json" \
  -d @sample_data/verified_ioc_alert.json
# -> confidence.score = 56, label = "medium"
# -> explanation includes known_proxy_vpn (verified), tor_exit_node,
#    _multiVectorAttack, network_activity. Re-send the same alert
#    after a few seconds and watch _rapidEscalation fire on top.
```

Pull each case back and look at `confidence.explanation`. Alert A has no positive-tier signals — the engine has nothing to grade. Alert B fires real signals, with `tier` annotations on each line.

Same words, different scores, because evidence matters and vibes don't.

The UI surfaces this directly at `http://localhost:8000/cases/<id>`.

---

## Tested on public data

The two-alert demo above is hand-crafted. The fairer question is: *what happens when you point this at data the engine has never seen?*

I ran it against 200 alerts from a public HuggingFace SIEM dataset (Chronicle UDM-formatted, mix of login, process, network, and cloud events from a synthetic but unfamiliar fleet). A 30-line adapter — [`test_data/public_datasets/map_udm_to_csv.py`](test_data/public_datasets/map_udm_to_csv.py) — flattens the nested UDM schema into the flat columns the upload endpoint expects. No per-record tuning, no signal weight changes, no IOC pre-loading.

200 alerts in, 200 cases out. Score histogram:

```
00-20 |   0
21-40 |  38  ######################################
41-60 | 157  ##################################################################
61-65 |   5  #####    <- cap zone
66-80 |   0
81-100|   0
```

**Zero records crossed 65.** The engine didn't have access to threat intel that could verify any of these alerts (no OTX, no AbuseIPDB — just the local IOC DB and GreyNoise community), so the cap held on every one of 200 cases. Five pressed up against the cap zone — the engine wanted to score them higher, structurally, and the cap stopped it.

That's the cap doing exactly what the headline says: refusing to grade alerts as critical without verifiable evidence, even when the alert text *looks* dramatic. The cap is not a unit test fixture. It's a property of the engine on real data.

To reproduce:
```bash
python test_data/public_datasets/map_udm_to_csv.py
curl -X POST "http://localhost:8000/api/v1/demo/upload?persist=true&grouping=true" \
  -H "X-API-Key: socai-demo-key-do-not-use-in-production" \
  -F "file=@test_data/public_datasets/hf_siem_mapped.csv"
```

The dataset itself (`hf_siem_200_curated.json`, ~124KB) is in [`test_data/public_datasets/`](test_data/public_datasets/) and is the curated 200-row slice of a larger HuggingFace SIEM dataset. The CSV the mapper produces is gitignored — regenerate it with the script.

---

## Architecture

```
+------------------------------------------------------------------+
|                     Alert sources                                |
|  Sysmon * SIEM * EDR * IdP * Email gateway * Cloud * Custom      |
+-------------------------------+----------------------------------+
                                | POST /api/v1/cases
                                v
+------------------------------------------------------------------+
|                    Vigilis backend (FastAPI)                     |
|  +--------------+  +-----------------+  +------------------+    |
|  |  Normalize   |->|    Enrich       |->|  Entity graph    |    |
|  |  alert_mapper|  |  (8 phases)     |  |  (verified-tier  |    |
|  |              |  |                 |  |   signals)       |    |
|  +--------------+  +-----------------+  +------------------+    |
|                             |                                    |
|         +-------------------+-------------------+                |
|         v                   v                   v                |
|  +----------+       +--------------+    +-------------+         |
|  | Threat   |       |  Scoring     |    |   Case      |         |
|  | intel    |       |  (tier-aware,|    |  grouping   |         |
|  | (6 prov) |       |   capped)    |    | & incidents |         |
|  +----------+       +--------------+    +-------------+         |
+-----------------------------+------------------------------------+
                              |
                 +------------+------------+
                 v            v            v
          +----------+ +----------+ +----------+
          | Webhook  | |  SOAR    | |  Store   |
          | delivery | |  stubs   | | (PG/SQLi)|
          +----------+ +----------+ +----------+
```

The frontend is static HTML served by FastAPI — no Node toolchain, no build step. If you want to read what the UI does, it's in [`backend/app/static/`](backend/app/static/) and [`backend/app/api/demo_ui.py`](backend/app/api/demo_ui.py).

---

## Threat intel providers

| Provider | Always on? | Free tier | What it provides |
|---|---|---|---|
| **LocalDBProvider** | Yes | Unlimited (local) | ~13K IOCs from abuse.ch feeds (Feodo, URLhaus, ThreatFox, MalwareBazaar, OpenPhish, SSLBL) ingested on startup |
| **GreyNoiseProvider** | Yes | Community tier (no key) | Internet-scanner / background-noise classification for IPs |
| **WHOISProvider** | Yes | RDAP, no key | Domain age and registration metadata |
| **OTXProvider** | If `OTX_API_KEY` set | Free key | AlienVault OTX pulse lookups |
| **AbuseIPDBProvider** | If `ABUSEIPDB_API_KEY` set | 1000 req/day | IP reputation |
| **VirusTotalProvider** | If `VIRUSTOTAL_API_KEY` set | 4 req/min, 500/day | File / IP / domain reports |

All providers implement a single Protocol — adding a new one is one file plus an entry in `lifespan()`.

---

## Live endpoint telemetry

Vigilis ships PowerShell exporters that feed real Windows endpoint events into the pipeline. Each exporter is independent — failures in one don't cascade.

| Exporter | Source | Cadence | What it captures |
|---|---|---|---|
| `export_sysmon.ps1` | Sysmon Operational log | every 5 min | EIDs 1, 3, 10, 11, 12, 13, 17, 18, 19, 20, 21, 22 (process, network, file, registry, DNS, LSASS access, named pipes, WMI persistence) |
| `export_secevt.ps1` | Windows Security Event Log | every 5 min | Logon (4624/4625), privilege (4672), process (4688), service install (4697), scheduled task (4698), account create (4720), group add (4728/4732), log clear (1102) |
| `export_psbl.ps1` | PowerShell Operational log | every 5 min | Script Block Logging (4104) — decoded source matched against MITRE patterns |
| `export_state.ps1` | Host snapshots | hourly | Services, scheduled tasks, local users, autoruns, installed programs — diffed across snapshots, only drift events are emitted |

Setup notes are in [`scripts/`](scripts/).

---

## Project structure

```
vigilis/
├── backend/
│   ├── app/
│   │   ├── api/              # FastAPI routes
│   │   ├── core/             # Config, auth, metrics, DB session
│   │   ├── db/               # SQLModel models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── services/
│   │   │   ├── enrichment/
│   │   │   │   ├── mappers/        # Per-domain extractors
│   │   │   │   ├── providers/      # Threat intel providers
│   │   │   │   ├── entity_graph.py # Cross-case entity relationships
│   │   │   │   ├── scoring.py      # Tier-aware scoring + cap
│   │   │   │   └── weights.py      # Single signal-weight registry
│   │   │   ├── case_service.py
│   │   │   ├── incident_service.py
│   │   │   ├── calibration.py      # Analyst-disposition feedback loop
│   │   │   └── integrations/soar.py
│   │   └── static/                 # UI (vanilla HTML/JS, no build)
│   └── tests/                      # ~870 tests
├── sample_data/                    # Example alerts per type / format
├── scripts/                        # PowerShell endpoint exporters
├── docs/                           # Reference docs
└── docker-compose.yml
```

---

## Running tests

```bash
python -m pytest backend/tests/ -q
# 867 passed, 19 skipped
```

The skipped tests are integration tests that require live external feeds.

---

## What's in scope, what isn't

In scope for this repo:
- The scoring engine and signal registry.
- The entity graph (cross-case relationship tracking).
- The threat intel provider protocol and the 6 default providers.
- The MITRE ATT&CK pattern library used by `export_psbl.ps1`.
- The static UI showing case detail with score breakdown.
- The PowerShell endpoint exporters.

Deliberately out of scope:
- SSO / SAML / OIDC. There's a single API-key model. You're expected to put this behind your own auth gateway if you deploy it.
- Multi-tenant admin UI. Tenants exist at the data layer; the UI assumes one operator.
- Hosted SaaS. There isn't one.
- LLM-driven alert classification or narrative generation. The deterministic engine works without it. Adding LLM enrichment as a non-load-bearing layer is straightforward; making it the source of truth is not the goal of this project.

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

## Contributing

This started as a solo project; PRs are welcome. The most useful contributions are:

1. **New threat intel providers** — implement `ThreatIntelProvider` and register in `lifespan()`. Tests in `backend/tests/test_threat_intel.py`.
2. **New extractors / signals** — add to a domain mapper, register the weight in `W` (one place, please don't hardcode), add a tier annotation. Tests live alongside.
3. **Calibration data** — if you run this on real telemetry, the disposition feedback the engine collects is the most useful artifact you can share back. (Anonymize first.)

Style: keep it deterministic, keep it auditable, write the test before the regex.
