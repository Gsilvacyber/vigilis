# Vigilis — Product Context

## Why This Exists
SOC/MDR teams spend excessive time on manual alert triage — correlating logs, checking threat intel, assessing severity, and documenting decisions. Vigilis demonstrates measurable reduction in time-to-first-decision (TTFD) through automated enrichment.

## Target Audience
- SOC managers evaluating automation tooling
- MDR providers wanting to prove pilot ROI
- Security engineers assessing enrichment quality

## Demo Story
1. **Ingest** — raw alert arrives (any of 10 types)
2. **Enrich** — rule-based engine extracts signals, scores confidence, generates playbook + actions
3. **Triage** — analyst views enriched case, sets disposition with one click
4. **Measure** — TTFD, confidence, triage rates, webhook deliveries quantify the value

## User Experience Goals
- Zero-config local startup (`pip install` + `uvicorn`)
- Single-click pilot simulation populates all metrics
- Side-by-side raw → enriched comparison
- Inline disposition dropdown for live TTFD demonstration
- Cross-page navigation (alert type links between pages)
- All demo features accessible from one unified nav bar
