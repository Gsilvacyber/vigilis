"""Tests for backend/app/services/calibration.py — the learning-loop math.

Covers:
- TestSignalEffectivenessMath — pure math tests on SignalEffectiveness class
  (fp_rate, tp_rate, weight_multiplier across all threshold tiers)
- TestColdStart — signals with < 10 decided samples return multiplier 1.0
- TestWeightMultiplierBounds — reduction floor at _MIN_WEIGHT / original,
  boost ceiling at _MAX_BOOST (1.3)
- TestComputeSignalEffectiveness — integration test with seeded DB:
  tenant + cases + dispositions + CaseConfidenceSignal rows
- TestGetWeightAdjustments — returns only signals with non-1.0 multipliers
- TestGetCalibrationReport — report structure + sorting + status label
- TestMetaSignalSkipped — internal signals (_*, noise_flag, etc.) skipped
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlmodel import Session, SQLModel, select

from backend.app.core.db import engine
from backend.app.db.models import (
    Case as CaseRow,
    CaseConfidenceSignal,
    Tenant as TenantRow,
)
from backend.app.services.calibration import (
    SignalEffectiveness,
    compute_signal_effectiveness,
    get_calibration_report,
    get_weight_adjustments,
)


@pytest.fixture(autouse=True)
def _reset_tables():
    """Wipe tenant/case tables before each test for repeatable state."""
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        for row in s.exec(select(CaseConfidenceSignal)).all():
            s.delete(row)
        for row in s.exec(select(CaseRow)).all():
            s.delete(row)
        for row in s.exec(select(TenantRow)).all():
            s.delete(row)
        s.commit()
    yield


def _make_tenant(session: Session, tenant_id: str = "t-calib") -> TenantRow:
    t = TenantRow(tenant_id=tenant_id, customer_name="Calib Co",
                  customer_environment="prod")
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


def _make_case(
    session: Session,
    tenant: TenantRow,
    disposition: str,
    signals: list[tuple[str, int]],
    days_ago: int = 1,
) -> CaseRow:
    now = datetime.now(timezone.utc)
    ts = now - timedelta(days=days_ago)
    case = CaseRow(
        tenant_id=tenant.id,
        alert_type="endpoint.suspiciousProcess",
        title="test",
        description="test",
        severity="medium",
        event_time=ts,
        ingested_time=ts,
        enriched_time=ts,
        created_at=ts,
        confidence_score=50,
        confidence_label="medium",
        disposition_status=disposition,
    )
    session.add(case)
    session.flush()
    for signal_name, weight in signals:
        session.add(CaseConfidenceSignal(
            case_id=case.id,
            signal=signal_name,
            weight=weight,
        ))
    session.commit()
    session.refresh(case)
    return case


# ─── SignalEffectiveness math ──────────────────────────────────────────────

class TestSignalEffectivenessMath:

    def test_zero_decided_rates_are_zero(self):
        eff = SignalEffectiveness("test_signal")
        assert eff.fp_rate == 0.0
        assert eff.tp_rate == 0.0
        assert eff.decided_count == 0

    def test_fp_rate_calculation(self):
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 3
        eff.false_positives = 7
        assert eff.fp_rate == 0.7
        assert eff.tp_rate == 0.3
        assert eff.decided_count == 10

    def test_cold_start_returns_1_0(self):
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 2
        eff.false_positives = 3  # only 5 decided, below _MIN_SAMPLES=10
        assert eff.weight_multiplier(15) == 1.0

    def test_high_fp_severe_reduction(self):
        # 80% FP, 20% TP, 10+ samples
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 2
        eff.false_positives = 8
        # At weight 15, min weight 2 / 15 = 0.133, floor is 0.3
        assert eff.weight_multiplier(15) == 0.3

    def test_medium_fp_moderate_reduction(self):
        # 60% FP
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 4
        eff.false_positives = 6
        assert eff.weight_multiplier(15) == 0.5

    def test_low_fp_slight_reduction(self):
        # 40% FP
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 6
        eff.false_positives = 4
        assert eff.weight_multiplier(15) == 0.75

    def test_high_tp_boost(self):
        # 90% TP — boost
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 9
        eff.false_positives = 1
        assert eff.weight_multiplier(15) == 1.3  # _MAX_BOOST

    def test_normal_range_no_adjustment(self):
        # 80% TP, 20% FP — stable zone
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 8
        eff.false_positives = 2
        assert eff.weight_multiplier(15) == 1.0

    def test_severe_reduction_floor_protects_low_weight_signal(self):
        # If original weight is very low (say 3), min_weight/original = 2/3 = 0.67
        # but we floor at 0.3 for severe FP. max(0.3, 0.67) = 0.67
        eff = SignalEffectiveness("test_signal")
        eff.true_positives = 1
        eff.false_positives = 9
        assert eff.weight_multiplier(3) == pytest.approx(0.667, abs=0.01)


# ─── Database integration ─────────────────────────────────────────────────

class TestComputeSignalEffectiveness:

    def test_aggregates_tp_and_fp_across_cases(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # 5 TP cases where "signal_a" fired
            for _ in range(5):
                _make_case(s, tenant, "true_positive", [("signal_a", 10)])
            # 3 FP cases where "signal_a" fired
            for _ in range(3):
                _make_case(s, tenant, "false_positive", [("signal_a", 10)])
            eff = compute_signal_effectiveness(s, "t-calib")
            assert "signal_a" in eff
            assert eff["signal_a"].true_positives == 5
            assert eff["signal_a"].false_positives == 3
            assert eff["signal_a"].decided_count == 8

    def test_missing_tenant_returns_empty_dict(self):
        with Session(engine) as s:
            eff = compute_signal_effectiveness(s, "nonexistent")
            assert eff == {}

    def test_multiple_signals_tracked_independently(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            _make_case(s, tenant, "true_positive",
                       [("signal_a", 10), ("signal_b", 15)])
            _make_case(s, tenant, "false_positive", [("signal_a", 10)])
            eff = compute_signal_effectiveness(s, "t-calib")
            assert eff["signal_a"].true_positives == 1
            assert eff["signal_a"].false_positives == 1
            assert eff["signal_b"].true_positives == 1
            assert eff["signal_b"].false_positives == 0

    def test_events_outside_window_are_excluded(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # This case is 60 days old — outside the default 30-day window
            _make_case(s, tenant, "true_positive",
                       [("signal_a", 10)], days_ago=60)
            eff = compute_signal_effectiveness(s, "t-calib", window_days=30)
            assert eff == {}


# ─── get_weight_adjustments ────────────────────────────────────────────────

class TestGetWeightAdjustments:

    def test_stable_signals_omitted_from_adjustments(self):
        """Signals with multiplier=1.0 should NOT appear in the adjustments dict."""
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # signal_good: 8 TP / 2 FP → 80% TP → stable → no adjustment
            for _ in range(8):
                _make_case(s, tenant, "true_positive", [("signal_good", 10)])
            for _ in range(2):
                _make_case(s, tenant, "false_positive", [("signal_good", 10)])
            adj = get_weight_adjustments(s, "t-calib")
            assert "signal_good" not in adj

    def test_high_fp_signal_reduction_in_adjustments(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # signal_noisy: 2 TP / 8 FP → 80% FP → severe reduction
            for _ in range(2):
                _make_case(s, tenant, "true_positive", [("signal_noisy", 10)])
            for _ in range(8):
                _make_case(s, tenant, "false_positive", [("signal_noisy", 10)])
            adj = get_weight_adjustments(s, "t-calib")
            assert "signal_noisy" in adj
            assert adj["signal_noisy"] < 1.0

    def test_high_tp_signal_boost_in_adjustments(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # signal_strong: 9 TP / 1 FP → 90% TP → boost
            for _ in range(9):
                _make_case(s, tenant, "true_positive", [("signal_strong", 10)])
            _make_case(s, tenant, "false_positive", [("signal_strong", 10)])
            adj = get_weight_adjustments(s, "t-calib")
            assert "signal_strong" in adj
            assert adj["signal_strong"] == 1.3  # _MAX_BOOST


# ─── get_calibration_report ────────────────────────────────────────────────

class TestGetCalibrationReport:

    def test_report_structure_and_fields(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            for _ in range(5):
                _make_case(s, tenant, "true_positive", [("signal_a", 10)])
            for _ in range(5):
                _make_case(s, tenant, "false_positive", [("signal_a", 10)])
            report = get_calibration_report(s, "t-calib")
            assert len(report) == 1
            row = report[0]
            assert row["signal"] == "signal_a"
            assert "originalWeight" in row
            assert "adjustedWeight" in row
            assert "multiplier" in row
            assert "fpRate" in row
            assert "tpRate" in row
            assert "status" in row
            assert row["status"] in ("reduce", "boost", "stable")

    def test_report_sorted_by_fp_rate_desc(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # signal_bad: 100% FP
            for _ in range(10):
                _make_case(s, tenant, "false_positive", [("signal_bad", 10)])
            # signal_meh: 50% FP
            for _ in range(5):
                _make_case(s, tenant, "true_positive", [("signal_meh", 10)])
            for _ in range(5):
                _make_case(s, tenant, "false_positive", [("signal_meh", 10)])
            # signal_good: 100% TP
            for _ in range(10):
                _make_case(s, tenant, "true_positive", [("signal_good", 10)])

            report = get_calibration_report(s, "t-calib")
            # sorted by -fp_rate → bad first, meh second, good last
            assert report[0]["signal"] == "signal_bad"
            assert report[-1]["signal"] == "signal_good"


# ─── Meta-signal exclusion ────────────────────────────────────────────────

class TestMetaSignalSkipped:
    """Signals prefixed `_` or meta-signals should not appear in calibration."""

    def test_underscore_signals_skipped(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            _make_case(s, tenant, "true_positive",
                       [("_score_breakdown", 0), ("real_signal", 10)])
            eff = compute_signal_effectiveness(s, "t-calib")
            assert "_score_breakdown" not in eff
            assert "real_signal" in eff

    def test_action_status_skipped(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            _make_case(s, tenant, "true_positive",
                       [("action_status", 5), ("real_signal", 10)])
            eff = compute_signal_effectiveness(s, "t-calib")
            assert "action_status" not in eff

    def test_noise_flag_skipped(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            _make_case(s, tenant, "true_positive",
                       [("noise_flag", 0), ("real_signal", 10)])
            eff = compute_signal_effectiveness(s, "t-calib")
            assert "noise_flag" not in eff

    def test_ir_response_skipped(self):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            _make_case(s, tenant, "true_positive",
                       [("ir_response", 0), ("real_signal", 10)])
            eff = compute_signal_effectiveness(s, "t-calib")
            assert "ir_response" not in eff
