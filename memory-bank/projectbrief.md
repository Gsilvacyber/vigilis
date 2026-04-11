# Vigilis — Project Brief

## What
Alert-to-Case Enrichment Pack — a deterministic, rule-based engine that ingests raw security alerts (10 types), enriches them into canonical `case.v0.2` payloads with confidence scoring, recommended playbooks, recommended actions, and impact summaries. Designed for SOC/MDR pilot demonstrations.

## Core Alert Types
1. `identity.suspiciousSignIn`
2. `identity.passwordSpray`
3. `identity.mfaFatigue`
4. `identity.oauthConsentRisk`
5. `identity.privilegeElevation`
6. `endpoint.malwareDetection`
7. `endpoint.suspiciousProcess`
8. `email.forwardingRule`
9. `cloud.secretStoreAccessAnomaly`
10. `network.impossibleGeoAccess`

## Key Capabilities
- Raw alert → enriched case normalization with entity extraction
- Confidence scoring (base severity + signal boost, 0-100, labeled low/medium/high/critical)
- Recommended playbooks (per alert type)
- Recommended actions (signal-aware, per alert type)
- Impact summary (risk label, time saved, manual steps replaced)
- TTFD tracking (time-to-first-decision, automated vs manual comparison)
- Pilot metrics (summary, TTFD, per-alert-type, per-tenant)
- Webhook delivery logging
- Demo simulation (simulate-pilot endpoint)
- Minimal web UI (landing, enrich, cases, metrics)

## Non-Goals (Current Phase)
- No LLMs / no external AI calls
- No authentication / authorization
- No production database migrations
- No React or build-step frontend
- No Docker (local dev only)
