"""Validation engine: run Vigilis enrichment against dataset rows and measure accuracy."""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from backend.app.services.enrichment import enrich_debug
from backend.app.services.normalizer import normalize_case_from_request
from backend.app.services.dataset_validation.dataset_adapter import row_to_raw_alert


@dataclass
class CaseResult:
    event_id: str
    dataset_event_type: str
    dataset_action: str | None
    mapped_alert_type: str
    dataset_risk_score: float
    dataset_confidence: float
    vigilis_score: int
    vigilis_label: str
    vigilis_severity: str
    signals_fired: list[str]
    signals_total: int
    playbook_count: int
    action_count: int
    explanation_count: int
    ready_for_action: bool
    missing_context: list[str]
    error: str | None = None


@dataclass
class ValidationReport:
    total_dataset_rows: int = 0
    mapped_rows: int = 0
    skipped_rows: int = 0
    errors: int = 0
    results: list[CaseResult] = field(default_factory=list)

    # Aggregates (computed after run)
    score_correlation: float = 0.0
    mean_absolute_error: float = 0.0
    vigilis_mean_score: float = 0.0
    dataset_mean_risk: float = 0.0
    by_alert_type: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_severity: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_signal_count: dict[str, dict[str, Any]] = field(default_factory=dict)
    by_readiness: dict[str, dict[str, Any]] = field(default_factory=dict)
    high_score_cases: list[CaseResult] = field(default_factory=list)
    disagreements: list[CaseResult] = field(default_factory=list)

    def compute_aggregates(self) -> None:
        if not self.results:
            return

        vigilis_scores = [r.vigilis_score for r in self.results]
        ds_scores = [r.dataset_risk_score for r in self.results]

        self.vigilis_mean_score = statistics.mean(vigilis_scores)
        self.dataset_mean_risk = statistics.mean(ds_scores)

        diffs = [abs(s - d) for s, d in zip(vigilis_scores, ds_scores)]
        self.mean_absolute_error = statistics.mean(diffs)

        if len(vigilis_scores) >= 2:
            try:
                self.score_correlation = statistics.correlation(vigilis_scores, ds_scores)
            except statistics.StatisticsError:
                self.score_correlation = 0.0
        else:
            self.score_correlation = 0.0

        # By alert type
        by_type: dict[str, list[CaseResult]] = defaultdict(list)
        for r in self.results:
            by_type[r.mapped_alert_type].append(r)

        for atype, cases in by_type.items():
            ss = [c.vigilis_score for c in cases]
            ds = [c.dataset_risk_score for c in cases]
            self.by_alert_type[atype] = {
                "count": len(cases),
                "vigilisMean": round(statistics.mean(ss), 1),
                "datasetMean": round(statistics.mean(ds), 1),
                "mae": round(statistics.mean([abs(a - b) for a, b in zip(ss, ds)]), 1),
                "signalsFiredAvg": round(statistics.mean([len(c.signals_fired) for c in cases]), 1),
                "playbookAvg": round(statistics.mean([c.playbook_count for c in cases]), 1),
                "actionsAvg": round(statistics.mean([c.action_count for c in cases]), 1),
            }

        # By severity
        by_sev: dict[str, list[CaseResult]] = defaultdict(list)
        for r in self.results:
            by_sev[r.vigilis_severity].append(r)

        for sev, cases in by_sev.items():
            ss = [c.vigilis_score for c in cases]
            self.by_severity[sev] = {
                "count": len(cases),
                "vigilisMean": round(statistics.mean(ss), 1),
                "expectedRange": _expected_range(sev),
                "inRange": sum(1 for s in ss if _in_expected_range(s, sev)),
            }

        # By fired signal count
        buckets = {"0": [], "1": [], "2": [], "3+": []}
        for r in self.results:
            n = len(r.signals_fired)
            key = str(n) if n <= 2 else "3+"
            buckets[key].append(r)
        for bucket, cases in buckets.items():
            if not cases:
                self.by_signal_count[bucket] = {"count": 0, "vigilisMean": 0, "readyPct": 0}
                continue
            ss = [c.vigilis_score for c in cases]
            ready = sum(1 for c in cases if c.ready_for_action)
            self.by_signal_count[bucket] = {
                "count": len(cases),
                "vigilisMean": round(statistics.mean(ss), 1),
                "readyPct": round(100 * ready / len(cases), 1),
            }

        # By readiness
        for label, pred in [("ready", True), ("needsReview", False)]:
            cases = [r for r in self.results if r.ready_for_action == pred]
            if not cases:
                self.by_readiness[label] = {"count": 0, "vigilisMean": 0, "signalAvg": 0}
                continue
            ss = [c.vigilis_score for c in cases]
            sigs = [len(c.signals_fired) for c in cases]
            self.by_readiness[label] = {
                "count": len(cases),
                "vigilisMean": round(statistics.mean(ss), 1),
                "signalAvg": round(statistics.mean(sigs), 1),
            }

        # Enhance by_alert_type with readiness and zero-signal pct
        for atype, stats in self.by_alert_type.items():
            cases = by_type[atype]
            ready = sum(1 for c in cases if c.ready_for_action)
            zero_sig = sum(1 for c in cases if len(c.signals_fired) == 0)
            stats["readyPct"] = round(100 * ready / len(cases), 1)
            stats["zeroSignalPct"] = round(100 * zero_sig / len(cases), 1)

        # Enhance by_severity with readiness pct
        for sev, stats in self.by_severity.items():
            cases = by_sev[sev]
            ready = sum(1 for c in cases if c.ready_for_action)
            stats["readyPct"] = round(100 * ready / len(cases), 1)

        # High-score cases needing manual review
        self.high_score_cases = sorted(
            [r for r in self.results if r.vigilis_score >= 75],
            key=lambda r: r.vigilis_score,
            reverse=True,
        )

        # Significant disagreements (Vigilis vs dataset differ by >30 points)
        self.disagreements = sorted(
            [r for r in self.results if abs(r.vigilis_score - r.dataset_risk_score) > 30],
            key=lambda r: abs(r.vigilis_score - r.dataset_risk_score),
            reverse=True,
        )


def _expected_range(sev: str) -> str:
    return {
        "critical": "75-100",
        "high": "55-85",
        "medium": "30-65",
        "low": "10-45",
    }.get(sev, "0-100")


def _in_expected_range(score: int, sev: str) -> bool:
    ranges = {"critical": (75, 100), "high": (55, 85), "medium": (30, 65), "low": (10, 45)}
    lo, hi = ranges.get(sev, (0, 100))
    return lo <= score <= hi


def validate_row(adapted: dict[str, Any]) -> CaseResult:
    """Run a single adapted row through Vigilis enrichment and return the result."""
    alert_type = adapted["alertType"]
    severity = adapted["severity"]
    raw_alert = adapted["rawAlert"]
    ds = adapted["datasetMeta"]

    try:
        from datetime import datetime, timezone
        event_time = datetime.now(timezone.utc)

        debug = enrich_debug(alert_type, severity, raw_alert, event_time)
        fired = [s.name for s in debug.all_signals if s.fired]

        case = normalize_case_from_request(
            tenant={"tenantId": "validation", "name": "Validation", "environment": "prod"},
            source={"sourceSystem": "custom", "sourceName": "Advanced_SIEM_Dataset", "sourceAlertId": ds["eventId"] or "unknown", "sourceSeverity": severity},
            alert_type=alert_type,
            title=f"Validation: {ds['description'][:80]}" if ds.get("description") else f"Validation: {alert_type}",
            description=ds.get("description") or alert_type,
            severity=severity,
            event_time=event_time,
            raw_alert=raw_alert,
        )

        enrichment = case.enrichment
        readiness = enrichment.caseReadiness if enrichment else None

        return CaseResult(
            event_id=ds["eventId"],
            dataset_event_type=ds["eventType"],
            dataset_action=ds.get("action"),
            mapped_alert_type=alert_type,
            dataset_risk_score=ds.get("datasetRiskScore") or 0,
            dataset_confidence=ds.get("datasetConfidence") or 0,
            vigilis_score=debug.result.confidence_score,
            vigilis_label=debug.result.confidence_label,
            vigilis_severity=severity,
            signals_fired=fired,
            signals_total=len(debug.all_signals),
            playbook_count=len(debug.result.recommended_playbook),
            action_count=len(debug.result.recommended_actions),
            explanation_count=len(debug.result.confidence_explanation),
            ready_for_action=readiness.readyForAction if readiness else False,
            missing_context=readiness.missingContext if readiness else [],
        )
    except Exception as e:
        return CaseResult(
            event_id=ds.get("eventId", "?"),
            dataset_event_type=ds.get("eventType", "?"),
            dataset_action=ds.get("action"),
            mapped_alert_type=alert_type,
            dataset_risk_score=ds.get("datasetRiskScore") or 0,
            dataset_confidence=ds.get("datasetConfidence") or 0,
            vigilis_score=0,
            vigilis_label="error",
            vigilis_severity=severity,
            signals_fired=[],
            signals_total=0,
            playbook_count=0,
            action_count=0,
            explanation_count=0,
            ready_for_action=False,
            missing_context=[],
            error=str(e),
        )


def run_validation(rows: list[dict[str, Any]], sample_size: int = 500) -> ValidationReport:
    """Run validation across a sample of dataset rows."""
    import random
    report = ValidationReport()

    if len(rows) > sample_size:
        rows = random.sample(rows, sample_size)

    report.total_dataset_rows = len(rows)

    for row in rows:
        adapted = row_to_raw_alert(row)
        if adapted is None:
            report.skipped_rows += 1
            continue

        report.mapped_rows += 1
        result = validate_row(adapted)
        if result.error:
            report.errors += 1
        report.results.append(result)

    report.compute_aggregates()
    return report
