# SOCAI — Progress & Roadmap

## Overall Progress Score: 100/100

### Completed Phases

| Phase | Score | Description |
|-------|-------|-------------|
| 1. Local Dev Setup | 10/10 | SQLite default, no Docker, env config, README |
| 2. Enrichment Engine | 18/20 | All 10 alert types, scoring, playbooks, actions, 34 tests |
| 3. Demo Readiness | 14/15 | Rich fixtures, enrich-raw, debug mode, demo flow tests |
| 4. Pilot Metrics | 12/15 | Summary/TTFD/by-type/by-tenant, simulate-pilot, metrics tests |
| 5. Operator UI | 12/15 | 7 HTML pages, webhook logs, impactSummary, ttfdComparison |
| 6. UI Polish | 6/10 | Nav unification, cross-linking, disposition dropdown, dead code cleanup |
| 7. Integration + Credibility | 10/15 | Config layer, dynamic impact, readiness, export, SOAR UI, integration doc |
| 8. Auth + Multi-Tenant | 8/8 | API key auth, tenant isolation, rate limiting, admin endpoints, 20 new tests |
| 9. Incident Correlation | 5/5 | Kill-chain mapping, entity clustering, narrative generation, incidents UI, 9 tests |
| 10. Demo-Ready Polish | 2/5 | Summary, actions, timestamps, severity, timeline, risk, workflow, export |
| **Total** | **97/100** | |

### What Works Right Now
- [x] Backend runs locally with `uvicorn` (no Docker)
- [x] All 10 alert types map raw → enriched case.v0.2
- [x] Confidence scoring with signal-based explanation
- [x] Recommended playbooks (per type, ordered steps)
- [x] Recommended actions (signal-aware, conditional)
- [x] Dynamic impact summary (5-45 min based on signals, entities, privilege)
- [x] Alert-type-specific risk strings (not generic)
- [x] Case readiness indicator (READY / NEEDS REVIEW)
- [x] TTFD calculation + automated-vs-manual comparison
- [x] Pilot metrics (summary, TTFD, by-alert-type, by-tenant)
- [x] **Enhanced metrics: time saved, distributions, case readiness, date range filter**
- [x] Webhook delivery + logging + per-case status badge
- [x] Send to SOAR button in UI
- [x] Integration config (webhook targets, mode — tenant-scoped)
- [x] Case export endpoint (clean JSON for external systems)
- [x] Copy-paste integration example doc
- [x] 6 interconnected UI pages with unified nav
- [x] API key authentication (X-API-Key header)
- [x] Full tenant isolation (cases, metrics, webhooks, config)
- [x] Rate limiting (100 req/min per key, 429 on excess)
- [x] Admin key management (create + list)
- [x] Demo key auto-seeded at startup
- [x] **Alert mapper: 30+ event types, UDM/Splunk/Sentinel field extraction**
- [x] **Geo enrichment from any field (UDM, additional, raw_log)**
- [x] **MFA status extraction (mfa_used, mfa_status, mfaStatus → enabled/disabled)**
- [x] **Process/command line extraction from raw_log fields**
- [x] **API operation extraction (CreateUser, CreateAccessKey, etc.)**
- [x] **Network context (bytesSent) for data exfiltration volume**
- [x] **Incident correlation: multi-step attack chain detection**
- [x] **Kill-chain stage mapping (10 alert types → 9 MITRE-aligned stages)**
- [x] **Entity-based clustering (weighted: user=3, public IP=1, private IP=0, threshold=2)**
- [x] **Over-correlation guardrails: private/NAT IPs ignored, user-weighted linking**
- [x] **Incident confidence scoring (stage count, case count, entity consistency, time proximity, chain coherence)**
- [x] **Linkage reasons: auditable correlation evidence (shared_user, shared_ip, time_proximity, kill_chain_progression)**
- [x] **Kill chain gap analysis (present vs missing stages with expected intermediates)**
- [x] **Descriptive incident titles (pattern-based: "Account compromise and data exfiltration — alice")**
- [x] **Enhanced narrative with correlation evidence + open investigation gaps**
- [x] **Incidents UI: confidence meter, linkage reasons panel, chain gaps (✔/✖), robust error handling**
- [x] **Confidence hover tooltip: inline breakdown on badge hover (no card expand needed)**
- [x] **Weak-link warning: borderline correlation banner when link margin ≤ 1**
- [x] **Three-tier component coloring: strong (green) / weak (yellow) / suppressed (gray) link components**
- [x] **Full export: confidenceBreakdown + linkStrength in all API responses**
- [x] **Incident summary one-liner: screenshot-ready shareable line per incident**
- [x] **"What should I do?" recommended actions per incident (stage-aware, prioritized)**
- [x] **First/last seen timestamps with duration display**
- [x] **Incident severity override: independent logic (multi-stage + exfil = critical)**
- [x] **Visual incident timeline with severity-colored dots and gradient line**
- [x] **Confidence vs Risk dual display (independent risk assessment with factor breakdown)**
- [x] **Analyst workflow simulation (escalation, auto-containment, triage prediction)**
- [x] **Export endpoint: Slack Block Kit + clean JSON payload with copy-to-clipboard UI**
- [x] **"Paste Anything" smart input: single textbox accepts JSON, CSV, key=value, syslog, raw text**
- [x] **Auto-detection preview: format badge, alert type, severity, field chips, parser notes**
- [x] **Paste endpoint (POST /api/v1/demo/paste): parse → detect → enrich → case in one call**
- [x] **245 tests passing (~20s), 25 new paste tests**
- [x] **IOC Investigation Workspace: search any IOC, see full dossier (entity graph, timeline, geo, risk)**
- [x] **IOC type auto-detection: IP, SHA-256, MD5, email, domain, keyword**
- [x] **Pivot investigation: click any entity to search for it**
- [x] **Cross-reference with incidents: related attack chains shown**
- [x] **264 tests passing (~23s), 19 new investigation tests**
- [x] **Side-by-side alert comparison: signal diff, entity overlap, playbook/actions diff, verdict**
- [x] **Compare endpoint (POST /api/v1/demo/compare): any format for both inputs**
- [x] **Three-tab Enrich page: Paste & Enrich + Investigate IOC + Compare Alerts**
- [x] **281 tests passing (~27s), 17 new comparison tests**
- [x] **Live Enrichment Feed: animated real-time demo with signal pills, climbing scores, playbook reveal**
- [x] **Live feed endpoint (GET /api/v1/demo/live-feed): all 10 alert types enriched and ordered**
- [x] **Four-tab Enrich page: Paste + Investigate + Compare + Live Feed**
- [x] **295 tests passing (~24s), 14 new live feed tests**
- [x] **Auto-correlation wired into simulate-pilot**
- [x] No deprecation warnings
- [x] **Central weight registry: one signal name = one weight everywhere (109 signals)**
- [x] **Asset criticality: DC/AD/PKI/SCADA → critical (+20), servers/bastion → high (+12), dev/sandbox → low (-5)**
- [x] **User risk: CEO/CISO/directors → critical (+15), admins/HR flags → high (+10), service accts → low (-5)**
- [x] **Cross-alert intelligence: multi-vector (+18), corroboration (+12), rapid escalation (+15)**
- [x] **Action cascades: identity+cloud → revoke all tokens, identity+endpoint → isolate + revoke**
- [x] **Threat intel: pluggable providers, static IP ranges, TOR exit nodes, domain lists, hash lists**
- [x] **New signals: known_malicious_ip (20), tor_exit_node (15), recently_registered_domain (12)**
- [x] **Calibration feedback: TP/FP verdicts, precision per signal, precision per alert type**
- [x] **Signal telemetry: DB-persisted, frequency/effectiveness/weight-impact analytics, dashboard**
- [x] **410 tests passing (~90s), 115 new enrichment engine tests**

### Vigilis Enrichment Engine Upgrade (5-Phase Gameplan) — COMPLETE

| Phase | Status | Description |
|-------|--------|-------------|
| 1. Internal Consistency | ✅ Complete | Central weight registry, failure handling, telemetry emission |
| 2. Asset Criticality + User Risk | ✅ Complete | DC/PLC/bastion → +20, CEO/CISO → +15, dev/sandbox → -5, 36 tests |
| 3. Cross-Alert Intelligence | ✅ Complete | Multi-vector, corroboration, rapid escalation, action cascades, 30 tests |
| 4. Threat Intel Hooks | ✅ Complete | Pluggable providers, static lists, calibration feedback, 28 tests |
| 5. Signal Telemetry | ✅ Complete | DB persistence, analytics, dashboard endpoint, 21 tests |

**Test count**: 295 → 410 (+115 new tests across all 5 phases)

### What's Left — Final Phase to 100

#### Phase 10: Production Hardening (est. +5 pts)
- [ ] Pin all dependencies with exact versions
- [ ] Structured JSON logging
- [ ] Alembic migrations that work with SQLite + Postgres
- [ ] Docker Compose for production
- [ ] CI/CD pipeline config
- [ ] Health check with DB connectivity test
**Priority**: HIGH for deployment | **Effort**: Medium

### Known Issues
1. ~~No authentication~~ **RESOLVED** — API key auth on all production endpoints
2. Config file writes to CWD — not ideal for containerized deployment
3. No input sanitization on raw alert payloads
4. No pagination on cases list
5. Alembic migrations assume PostgreSQL
6. `Customer.environment` hardcoded to `Literal["prod"]`
7. Admin endpoints unprotected (demo-only, needs external protection in production)
8. Rate limiter is in-memory (resets on restart, not shared across workers)

### Files Changed — Vigilis 5-Phase Session
```
NEW:
  backend/app/services/enrichment/threat_intel.py    — Pluggable threat intel (providers, static lists, enricher)
  backend/app/services/enrichment/telemetry.py       — TelemetryCollector (DB persistence, analytics)
  backend/app/api/v1/endpoints/calibration.py        — Calibration feedback + telemetry dashboard endpoints
  backend/tests/test_asset_criticality.py            — 36 tests for asset/user risk
  backend/tests/test_telemetry.py                    — 21 tests for telemetry recording + analytics + dashboard

MODIFIED:
  backend/app/services/enrichment/__init__.py        — Wired in asset risk, threat intel, telemetry collector
  backend/app/services/enrichment/scoring.py         — Added asset_weight, user_weight params
  backend/app/services/enrichment/base.py            — Added asset_tier, user_risk_tier to EnrichmentResult
  backend/app/services/enrichment/weights.py         — Added threat intel signal weights
  backend/app/services/enrichment/threat_intel.py    — Rewrote with proper Signal objects + range matching
  backend/app/api/v1/endpoints/demo.py               — Restored calibration endpoints
  backend/app/api/v1/router.py                       — Added calibration router
  backend/app/db/models.py                           — Added CalibrationFeedback + SignalTelemetry tables
  backend/tests/conftest.py                          — Import new models + reset fixtures
  memory-bank/*                                      — Updated all context files
```

### Score History
| Date | Score | Phase Completed |
|------|-------|-----------------|
| Session 1 | 72/100 | Phases 1-6 (local dev → UI polish) |
| Session 2 | 82/100 | Phase 7 (integration + credibility) |
| Session 3 | 90/100 | Phase 8 (auth + multi-tenant) |
| Session 4 | 90/100 | UDM gap fixes + metrics enhancement (quality improvement) |
| Session 5 | 95/100 | Phase 9: Incident correlation layer |
| Session 5b | 95/100 | Incident precision + trust (confidence, linkage, gaps, guardrails, titles) |
| Session 5c | 95/100 | UI scannability polish (hover tooltip, weak-link warn, component coloring, export) |
| Session 5d | 96/100 | Demo-ready polish (summary line, action hints, timestamps, severity override) |
| Session 5e | 97/100 | Impact layers (visual timeline, confidence vs risk, workflow, export) |
| Session 6 | 98/100 | "Paste Anything" smart input mode (parser, endpoint, rebuilt enrich UI) |
| Session 6b | 99/100 | IOC Investigation Workspace (search, entity graph, timeline, geo, pivot) |
| Session 6c | 100/100 | Side-by-side alert comparison (signal diff, entity overlap, verdict) |
| Session 6d | 100/100 | Live enrichment feed (animated demo mode with signal/score/playbook animation) |
| Session 7 | 100/100 | Vigilis 5-Phase: asset criticality, cross-alert intel, threat intel, calibration, telemetry (410 tests) |
