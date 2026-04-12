"""Signal Calibration Engine — learns from analyst feedback.

THE LEARNING LOOP:
  1. Analyst dispositions cases as benign/true_positive/false_positive
  2. This service queries all dispositioned cases from the last 30 days
  3. For each signal, it calculates the false positive rate
  4. Signals with high FP rates get weight adjustments stored in DB
  5. Next enrichment run uses adjusted weights instead of hardcoded defaults

WHY THIS MATTERS:
  Without this, signal weights are static guesses. "after_hours = 18" might be
  perfect for a 9-5 office but terrible for a 24/7 SOC. The learning loop makes
  weights adapt to each customer's environment automatically.

  This is the DATA FLYWHEEL that creates the moat — the more analysts triage,
  the better the scoring becomes, the more value they get, the more they triage.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlmodel import Session, select

from backend.app.db.models import (
    Case as CaseRow,
    CaseConfidenceSignal,
    Tenant as TenantRow,
)

_log = logging.getLogger(__name__)

# Disposition categories
_POSITIVE = {"true_positive", "escalated", "confirmed"}
_NEGATIVE = {"benign", "false_positive", "auto_closed"}
_ALL_DECIDED = _POSITIVE | _NEGATIVE

# Calibration thresholds
_MIN_SAMPLES = 10         # Need 10+ dispositioned cases with this signal to calibrate
_HIGH_FP_THRESHOLD = 0.70  # 70%+ FP rate = significant weight reduction
_MED_FP_THRESHOLD = 0.50   # 50-70% = moderate reduction
_LOW_FP_THRESHOLD = 0.30   # 30-50% = slight reduction
_HIGH_TP_THRESHOLD = 0.85  # 85%+ TP rate = weight boost

# Weight adjustment bounds
_MIN_WEIGHT = 2     # Never reduce below 2 (signal still shows but barely contributes)
_MAX_BOOST = 1.3    # Never increase more than 30% above original


class SignalEffectiveness:
    """Tracks how effective a signal is at predicting real threats."""

    def __init__(self, signal_name: str):
        self.signal_name = signal_name
        self.total_cases = 0
        self.true_positives = 0
        self.false_positives = 0
        self.undecided = 0

    @property
    def fp_rate(self) -> float:
        decided = self.true_positives + self.false_positives
        if decided == 0:
            return 0.0
        return self.false_positives / decided

    @property
    def tp_rate(self) -> float:
        decided = self.true_positives + self.false_positives
        if decided == 0:
            return 0.0
        return self.true_positives / decided

    @property
    def decided_count(self) -> int:
        return self.true_positives + self.false_positives

    def weight_multiplier(self, original_weight: int) -> float:
        """Calculate the weight adjustment multiplier.

        Returns a float between 0.1 and 1.3 that should multiply the
        original weight.  >1.0 means the signal is more effective than
        expected (boost it).  <1.0 means too many false positives (reduce).
        """
        if self.decided_count < _MIN_SAMPLES:
            return 1.0  # Not enough data to calibrate

        if self.fp_rate >= _HIGH_FP_THRESHOLD:
            # 70%+ FP rate: severe reduction
            return max(0.3, _MIN_WEIGHT / max(original_weight, 1))
        elif self.fp_rate >= _MED_FP_THRESHOLD:
            # 50-70% FP: moderate reduction
            return 0.5
        elif self.fp_rate >= _LOW_FP_THRESHOLD:
            # 30-50% FP: slight reduction
            return 0.75
        elif self.tp_rate >= _HIGH_TP_THRESHOLD:
            # 85%+ TP rate: boost (capped at 30%)
            return _MAX_BOOST
        else:
            # Normal range — no adjustment
            return 1.0


def compute_signal_effectiveness(
    session: Session,
    tenant_id: str,
    window_days: int = 30,
) -> dict[str, SignalEffectiveness]:
    """Calculate false positive / true positive rates per signal.

    Queries all cases dispositioned in the last `window_days` days,
    joins with their fired signals, and computes effectiveness metrics.
    """
    tenant = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == tenant_id)
    ).first()
    if not tenant:
        return {}

    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

    # Get all cases with dispositions in the window
    cases = session.exec(
        select(CaseRow).where(
            CaseRow.tenant_id == tenant.id,
            CaseRow.created_at >= cutoff,
            CaseRow.disposition_status.in_(list(_ALL_DECIDED)),  # type: ignore[attr-defined]
        )
    ).all()

    if not cases:
        return {}

    effectiveness: dict[str, SignalEffectiveness] = {}

    for case in cases:
        # Get signals that fired for this case
        signals = session.exec(
            select(CaseConfidenceSignal).where(
                CaseConfidenceSignal.case_id == case.id,
            )
        ).all()

        is_tp = case.disposition_status in _POSITIVE
        is_fp = case.disposition_status in _NEGATIVE

        for sig in signals:
            if sig.signal.startswith("_"):
                continue  # Skip internal signals (_score_breakdown, etc.)
            if sig.signal in ("noise_flag", "ir_response", "action_status"):
                continue  # Skip meta-signals

            if sig.signal not in effectiveness:
                effectiveness[sig.signal] = SignalEffectiveness(sig.signal)

            eff = effectiveness[sig.signal]
            eff.total_cases += 1
            if is_tp:
                eff.true_positives += 1
            elif is_fp:
                eff.false_positives += 1
            else:
                eff.undecided += 1

    return effectiveness


def get_weight_adjustments(
    session: Session,
    tenant_id: str,
    window_days: int = 30,
) -> dict[str, float]:
    """Get weight multipliers based on analyst feedback.

    Returns a dict of signal_name -> multiplier (0.3 to 1.3).
    Signals not in the dict should use their default weight (1.0x).
    """
    from backend.app.core.metrics import (
        calibration_adjusted_signals,
        calibration_runs_total,
    )
    from backend.app.services.enrichment.weights import W

    calibration_runs_total.inc()
    effectiveness = compute_signal_effectiveness(session, tenant_id, window_days)

    adjustments: dict[str, float] = {}
    for signal_name, eff in effectiveness.items():
        original_weight = W.get(signal_name, 10)
        multiplier = eff.weight_multiplier(original_weight)
        if multiplier != 1.0:
            adjustments[signal_name] = multiplier
            _log.info(
                "Signal calibration: %s multiplier=%.2f (TP=%d FP=%d rate=%.0f%%)",
                signal_name, multiplier, eff.true_positives,
                eff.false_positives, eff.fp_rate * 100,
            )

    calibration_adjusted_signals.set(len(adjustments))
    return adjustments


def get_calibration_report(
    session: Session,
    tenant_id: str,
    window_days: int = 30,
) -> list[dict[str, Any]]:
    """Generate a human-readable calibration report.

    Returns a list of signal effectiveness records for the API/UI.
    """
    from backend.app.services.enrichment.weights import W

    effectiveness = compute_signal_effectiveness(session, tenant_id, window_days)

    report = []
    for signal_name, eff in sorted(effectiveness.items(), key=lambda x: -x[1].fp_rate):
        original_weight = W.get(signal_name, 10)
        multiplier = eff.weight_multiplier(original_weight)
        adjusted_weight = int(original_weight * multiplier)

        report.append({
            "signal": signal_name,
            "originalWeight": original_weight,
            "adjustedWeight": adjusted_weight,
            "multiplier": round(multiplier, 2),
            "totalCases": eff.total_cases,
            "truePositives": eff.true_positives,
            "falsePositives": eff.false_positives,
            "undecided": eff.undecided,
            "fpRate": round(eff.fp_rate * 100, 1),
            "tpRate": round(eff.tp_rate * 100, 1),
            "status": (
                "reduce" if multiplier < 0.9 else
                "boost" if multiplier > 1.1 else
                "stable"
            ),
        })

    return report
