# Vigilis — Active Context

## Last Completed: Vigilis 5-Phase Enrichment Engine Upgrade
**Date**: April 2, 2026

### What was done — The 5-Phase Gameplan

**Phase 1: Internal Consistency (completed in prior session)**
- Central weight registry in `weights.py` — all 5 mappers import `W`
- Failure handling in enrichment orchestrator — 2-attempt retry + `ENRICHMENT_FAILED` flag
- In-memory telemetry emission via `_emit_telemetry()`

**Phase 2: Asset Criticality + User Risk**
- Wired existing `asset_criticality.py` into the live pipeline
- `compute_asset_criticality()` and `compute_user_risk()` called in `_run_enrichment()`
- `compute_confidence()` now accepts `asset_weight` and `user_weight` params
- `EnrichmentResult` has `asset_tier` and `user_risk_tier` fields
- Notes include tier info when non-standard (e.g., "Asset tier: critical (+20)")
- 36 new tests (hostname patterns, device types, C-suite detection, end-to-end scoring)

**Phase 3: Cross-Alert Intelligence (completed in prior session)**
- `cross_alert.py` with `CrossAlertScanner` — thread-safe sliding window
- Multi-vector attack, corroboration, rapid escalation detection
- Action cascades: identity+cloud → revoke tokens, identity+endpoint → isolate
- 30 tests (entity extraction, pattern detection, window expiry, thread safety)

**Phase 4: Threat Intel Hooks**
- `threat_intel.py` with pluggable `ThreatIntelProvider` protocol
- `StaticListProvider`: IP ranges, TOR exit nodes, domain lists, suspicious TLD patterns, hash lists
- `ThreatIntelEnricher` orchestrates providers and generates `Signal` objects
- New signal weights: `known_malicious_ip` (20), `tor_exit_node` (15), `recently_registered_domain` (12)
- Calibration feedback: `POST /api/v1/calibration/feedback` + `GET /api/v1/calibration/stats`
- `CalibrationFeedback` DB model for TP/FP verdicts with per-signal/per-alert-type precision
- 28 tests (static lookups, protocol compliance, signal generation, calibration flow)

**Phase 5: Signal Telemetry Analytics**
- `telemetry.py` with `TelemetryCollector` singleton — DB persistence + in-memory buffer
- `SignalTelemetry` DB model records every enrichment run
- Analytics: `signal_frequency()`, `signal_effectiveness()`, `weight_impact_analysis()`, `false_positive_rate()`
- Telemetry dashboard: `GET /api/v1/telemetry/dashboard` — full analytics in one call
- Backward-compatible: `_TELEMETRY` buffer and `get_telemetry()` still work
- 21 tests (recording, DB persistence, analytics, dashboard endpoint)

### Current State
- **Tests**: 410 passing (~90s), 19 skipped (dataset validation)
- **Enrichment pipeline**: `raw alert → mapper → signals → asset/user risk → cross-alert → threat intel → scoring → playbooks → actions → telemetry → CaseV0_2`
- **New endpoints**: `/api/v1/calibration/feedback`, `/api/v1/calibration/stats`, `/api/v1/telemetry/dashboard`
- **New DB tables**: `calibration_feedback`, `signal_telemetry`
- **New modules**: `asset_criticality.py`, `cross_alert.py`, `threat_intel.py`, `telemetry.py`

## Next Steps
See `progress.md` for the full roadmap with scoring.
