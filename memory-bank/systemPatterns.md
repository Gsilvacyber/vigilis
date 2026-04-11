# SOCAI — System Patterns

## Architecture

```
FastAPI app (main.py)
├── /health
├── /  → redirect → /demo/ui/
├── /debug/webhook-echo
├── /api/v1/
│   ├── /cases (CRUD + list)
│   ├── /cases/{id}/disposition (PATCH → TTFD calc)
│   ├── /cases/{id}/deliver-webhook
│   ├── /cases/{id}/export
│   ├── /calibration/feedback (POST — analyst TP/FP verdict)
│   ├── /calibration/stats (GET — precision, FP rate, per-signal stats)
│   ├── /telemetry/dashboard (GET — signal frequency, weight impact, score distribution)
│   ├── /demo/ (load-fixtures, enrich-raw, sample-raw-alerts, reset, simulate-pilot)
│   ├── /demo/upload (file upload → preview + process)
│   ├── /demo/batch-enrich (JSON array batch enrichment)
│   ├── /demo/calibration/ (legacy feedback/stats endpoints)
│   ├── /incidents/ (list, detail, correlate — multi-step attack chains)
│   ├── /metrics/ (summary, ttfd, by-alert-type, by-tenant)
│   ├── /webhooks/logs
│   ├── /config/ (webhook targets, mode — tenant-scoped)
│   └── /admin/ (API key CRUD)
└── /demo/ui/ (landing, enrich, cases, incidents, case-detail, metrics, upload)
```

## Enrichment Pipeline
```
raw alert → mapper → signals → asset/user risk → cross-alert intel → threat intel → scoring → playbooks → actions → telemetry → CaseV0_2
```

1. **Mapper** (`enrichment/mappers/`) — extracts domain-specific signals from raw alert data
2. **Weight Registry** (`enrichment/weights.py`) — central `W` dict, one signal name = one weight everywhere
3. **Asset Criticality** (`enrichment/asset_criticality.py`) — detects tier from hostname/device patterns (+20 to -5)
4. **User Risk** (`enrichment/asset_criticality.py`) — detects risk from UPN/title/privilege tier (+15 to -5)
5. **Cross-Alert Intelligence** (`enrichment/cross_alert.py`) — sliding window scanner for multi-vector attacks, corroboration, rapid escalation
6. **Threat Intel** (`enrichment/threat_intel.py`) — pluggable providers (static lists default, supports VirusTotal/AbuseIPDB/GreyNoise)
7. **Scoring** (`enrichment/scoring.py`) — base score from severity + signal weights + asset/user weights, capped at 100
8. **Playbooks** (`enrichment/playbooks.py`) — static per-type ordered step lists
9. **Actions** (`enrichment/actions.py`) — signal-aware actions + cross-alert cascades (e.g., "revoke ALL tokens" on identity+cloud multi-vector)
10. **Telemetry** (`enrichment/telemetry.py`) — DB-persisted enrichment run recording + analytics (frequency, effectiveness, FP rate)
11. **Normalizer** (`services/normalizer.py`) — orchestrates entity extraction, enrichment, impact summary, case readiness, and builds final CaseV0_2

## Calibration Feedback Loop
```
analyst verdict (TP/FP/BTP) → CalibrationFeedback DB → per-signal precision → weight tuning data
```
- POST `/api/v1/calibration/feedback` — records analyst verdict per case
- GET `/api/v1/calibration/stats` — precision/FP rate per alert type and per signal
- GET `/api/v1/telemetry/dashboard` — signal frequency, weight impact, score distribution

## Alert Mapper Pipeline (upload/batch ingestion)
```
arbitrary SIEM row → flatten_row() → guess_alert_type() → map_row_to_raw_alert() → enrich pipeline
```

### Field Extraction Layers (priority ordered)
1. **Tier 1**: UDM dot-notation fields (principal.*, target.*, metadata.*)
2. **Tier 2**: Top-level fields (user, ip, hostname, severity)
3. **Tier 3**: additional.* / raw_log.* fields (lowest priority)

### Alert Type Classification
- **Fast-path**: `_EVENT_TYPE_MAP` — direct event_type value → alert type mapping (30+ entries)
- **Fallback**: Keyword scoring with value-weighted approach (value match = 3x, key match = 1x)

### Context Enrichment Miners
Each miner populates structured fields from arbitrary SIEM rows:
- `_enrich_identity_context` — mfaStatus, riskLevel, privilegeTier, failedAttempts
- `_enrich_bulk_target` — target count, success count (password spray)
- `_enrich_app_context` — app name, publisher, scopes, firstSeen, **apiOperation**
- `_enrich_file_context` — signer, prevalence, file path, **process name**, **command line**
- `_enrich_mailbox_context` — mailbox, forwarding address, rule name
- `_enrich_actor_context` — actor type, target user
- `_enrich_geo_context` — country on IP geo (uses `_find_field` with `_GEO_FIELDS`)
- `_enrich_network_context` — **bytesSent**, protocol

### Supported Event Type Mappings
| Source Event Type | SOCAI Alert Type |
|---|---|
| login_failure, login_success, account_lockout | identity.suspiciousSignIn |
| password_spray, credential_stuffing | identity.passwordSpray |
| mfa_fatigue, mfa_push_denied | identity.mfaFatigue |
| oauth_consent | identity.oauthConsentRisk |
| privilege_escalation | identity.privilegeElevation |
| malware_download, malware_detected, threat_list_hit | endpoint.malwareDetection |
| process_creation, process_execution, registry_modification | endpoint.suspiciousProcess |
| phishing_detected | email.forwardingRule |
| anomalous_api_call, data_exfiltration, large_upload | cloud.secretStoreAccessAnomaly |
| impossible_travel, suspicious_domain, network_connection | network.impossibleGeoAccess |

## Data Flow Patterns
- **Case creation**: POST raw case → normalize → enrich → persist CaseRow + TenantRow → return case.v0.2
- **Disposition**: PATCH status → create CaseDispositionEvent → calculate TTFD on first decision → attach ttfdComparison to outputs
- **Webhook**: POST deliver → httpx.post to target → log WebhookDelivery row
- **Metrics**: Query CaseRow + CaseDispositionEvent + WebhookDelivery → aggregate in Python
  - Summary includes: totalTimeSavedMinutes, avgTimeSavedMinutes, totalManualStepsReplaced, casesReadyForAction, casesNeedingReview
- **Upload/Batch**: File upload → flatten → preview/validate → map to rawAlert → enrich pipeline
- **Incident correlation**: Cases → cluster by entity overlap (user + IP) within 24h window → detect multi-stage kill chains → generate narrative → persist Incident + IncidentCaseLink rows

## Incident Correlation Pipeline
```
cases (per tenant) → entity extraction (UPN + IP + device)
  → weighted clustering (user=3, public IP=1, private IP=0, threshold≥2, 24h window)
  → kill chain stage mapping (alert_type → stage) → filter clusters with 2+ stages
  → confidence scoring (stages + cases + entity consistency + time proximity + chain coherence)
  → linkage reason audit trail (shared_user, shared_ip, time_proximity, kill_chain_progression)
  → kill chain gap analysis (present vs expected intermediate stages)
  → descriptive title generation (pattern-matched attack descriptions)
  → narrative generation (evidence + gaps + timeline)
  → severity computation (boosted for multi-stage) → persist Incident
```

### Kill Chain Stage Mapping
| Alert Type | Kill Chain Stage |
|---|---|
| email.forwardingRule | initial_access |
| identity.suspiciousSignIn | initial_access |
| identity.passwordSpray | credential_access |
| identity.mfaFatigue | credential_access |
| identity.oauthConsentRisk | credential_access |
| identity.privilegeElevation | privilege_escalation |
| endpoint.malwareDetection | execution |
| endpoint.suspiciousProcess | execution |
| network.impossibleGeoAccess | lateral_movement |
| cloud.secretStoreAccessAnomaly | exfiltration |

## Metrics Page Sections
1. **ROI Summary** — triage %, median TTFD, speed improvement, total time saved, manual steps automated
2. **Summary Cards** — total cases, avg confidence, triaged, open, webhooks, avg time saved/case
3. **Distributions** — severity, confidence level, disposition breakdown, cases by alert type (bar charts)
4. **Case Readiness** — ready for action vs needs review
5. **TTFD** — avg/median/min/max + per-alert-type breakdown table
6. **By Alert Type** — detailed table with counts, confidence, dispositions, TTFD, webhooks
7. **Recent Webhooks** — last 10 deliveries
8. **Date Range Filter** — start/end date pickers using backend start/end query params

## UI Pattern
- 7 static HTML pages (no template engine, no build step)
- Each page has identical nav bar with brand link, page links, Simulate/Reset buttons, API docs link
- Pages cross-link: alert types link to enrich page, enrich persists and redirects to cases
- Inline disposition dropdown triggers PATCH and refreshes case list
- Case detail page with raw/enriched JSON, playbook, actions, timeline

## Auth Pattern
- API key-based authentication (X-API-Key header)
- Tenant isolation: API key determines tenant_id, all data scoped
- Rate limiting: 100 req/min per key, in-memory counter
- Demo key auto-seeded at startup

## Testing Pattern
- `conftest.py` provides `test_client` fixture with isolated SQLite test DB
- Tests use `TestClient` from FastAPI for integration testing
- Reset endpoint used for test isolation
- Cross-alert scanner and threat intel reset in `autouse` fixture to prevent test bleed
- 410 tests passing (~90s), 19 skipped
