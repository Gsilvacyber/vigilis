"""Tests for Attack-Aware Detection Engine v2 fixes.

Covers: spray detection, dedup, stage-aware actions, scoring spread,
cross-alert-type grouping, and DB-level dedup.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import pytest

from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.scoring import compute_confidence
from backend.app.services.enrichment.actions import (
    get_actions, _STAGE_TO_ACTION, _ALERT_TYPE_TO_STAGE,
    _score_to_action_override,
)
from backend.app.services.grouping import (
    EnrichedAlert, _detect_batch_spray, _alert_fingerprint,
    _dedup_within_group, _extract_group_upn, _merge_same_user_groups,
    group_enriched_alerts, AlertGroup,
)
from backend.app.schemas.case_v0_2 import CaseV0_2


# ── Helpers ───────────────────────────────────────────────────────────────

def _make_alert(
    index: int,
    upn: str = "user@contoso.com",
    ip: str = "203.0.113.1",
    alert_type: str = "identity.suspiciousSignIn",
    severity: str = "high",
    score: int = 70,
    event_time: datetime | None = None,
) -> EnrichedAlert:
    row = {
        "identity": {"upn": upn},
        "ips": [{"ipAddress": ip}],
    }
    case = MagicMock(spec=CaseV0_2)
    return EnrichedAlert(
        index=index,
        row=row,
        alert_type=alert_type,
        severity=severity,
        case_data=case,
        score=score,
        event_time=event_time or datetime(2026, 3, 26, 2, 0, 0, tzinfo=timezone.utc),
    )


# ── Fix 2: Spray Detection ───────────────────────────────────────────────

class TestSprayDetection:
    def test_spray_3_users_same_ip(self):
        base = datetime(2026, 3, 26, 2, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _make_alert(0, upn="alice@c.com", ip="8.8.8.8", event_time=base),
            _make_alert(1, upn="bob@c.com", ip="8.8.8.8",
                        event_time=base + timedelta(minutes=1)),
            _make_alert(2, upn="charlie@c.com", ip="8.8.8.8",
                        event_time=base + timedelta(minutes=2)),
        ]
        groups, consumed = _detect_batch_spray(alerts, 60)
        assert len(groups) == 1
        assert len(consumed) == 3
        assert groups[0].primary_alert_type == "identity.passwordSpray"
        assert "spray" in groups[0].grouping_reason.lower()

    def test_spray_private_ip_ignored(self):
        alerts = [
            _make_alert(0, upn="a@c.com", ip="192.168.1.1"),
            _make_alert(1, upn="b@c.com", ip="192.168.1.1"),
            _make_alert(2, upn="c@c.com", ip="192.168.1.1"),
        ]
        groups, consumed = _detect_batch_spray(alerts, 60)
        assert len(groups) == 0

    def test_spray_2_users_not_enough(self):
        alerts = [
            _make_alert(0, upn="a@c.com", ip="203.0.113.50"),
            _make_alert(1, upn="b@c.com", ip="203.0.113.50"),
        ]
        groups, consumed = _detect_batch_spray(alerts, 60)
        assert len(groups) == 0

    def test_spray_reclassifies_alert_type(self):
        alerts = [
            _make_alert(0, upn="a@c.com", ip="1.2.3.4"),
            _make_alert(1, upn="b@c.com", ip="1.2.3.4"),
            _make_alert(2, upn="c@c.com", ip="1.2.3.4"),
        ]
        _detect_batch_spray(alerts, 60)
        for a in alerts:
            assert a.alert_type == "identity.passwordSpray"


# ── Fix 5: Dedup ─────────────────────────────────────────────────────────

class TestDedup:
    def test_fingerprint_10min_bucket(self):
        base = datetime(2026, 3, 26, 2, 0, 0, tzinfo=timezone.utc)
        a1 = _make_alert(0, event_time=base)
        a2 = _make_alert(1, event_time=base + timedelta(minutes=5))
        assert _alert_fingerprint(a1) == _alert_fingerprint(a2)

    def test_fingerprint_different_bucket(self):
        base = datetime(2026, 3, 26, 2, 0, 0, tzinfo=timezone.utc)
        a1 = _make_alert(0, event_time=base)
        a2 = _make_alert(1, event_time=base + timedelta(minutes=15))
        assert _alert_fingerprint(a1) != _alert_fingerprint(a2)

    def test_dedup_within_group_keeps_highest_score(self):
        base = datetime(2026, 3, 26, 2, 0, 0, tzinfo=timezone.utc)
        alerts = [
            _make_alert(0, score=50, event_time=base),
            _make_alert(1, score=80, event_time=base + timedelta(minutes=3)),
        ]
        result = _dedup_within_group(alerts)
        assert len(result) == 1
        assert result[0].score == 80


# ── Fix 3: Cross-Alert-Type Grouping ─────────────────────────────────────

class TestCrossAlertGrouping:
    def test_extract_upn_from_identity(self):
        group = AlertGroup(key="test", grouping_reason="test")
        group.entity_anchor = "cfo@contoso.com"
        assert _extract_group_upn(group) == "cfo@contoso.com"

    def test_extract_upn_from_mailbox(self):
        group = AlertGroup(key="test", grouping_reason="test")
        group.entity_anchor = "some-device"
        alert = _make_alert(0)
        alert.row = {"mailbox": {"primaryAddress": "cfo@contoso.com"}}
        group.alerts = [alert]
        assert _extract_group_upn(group) == "cfo@contoso.com"

    def test_extract_upn_no_user(self):
        group = AlertGroup(key="test", grouping_reason="test")
        group.entity_anchor = "some-device"
        alert = _make_alert(0)
        alert.row = {"device": {"hostname": "srv01"}}
        group.alerts = [alert]
        assert _extract_group_upn(group) == ""


# ── Fix 6: Stage-Aware Actions ───────────────────────────────────────────

class TestStageAwareActions:
    def test_stage_map_covers_all_stages(self):
        for stage in ("initial_access", "credential_access", "privilege_escalation",
                       "execution", "persistence", "lateral_movement",
                       "collection", "exfiltration", "reconnaissance"):
            assert stage in _STAGE_TO_ACTION

    def test_execution_maps_to_contain(self):
        assert _STAGE_TO_ACTION["execution"] == "CONTAIN"

    def test_privilege_escalation_maps_to_escalate(self):
        assert _STAGE_TO_ACTION["privilege_escalation"] == "ESCALATE"

    def test_persistence_maps_to_investigate(self):
        assert _STAGE_TO_ACTION["persistence"] == "INVESTIGATE"

    def test_alert_type_to_stage_consistent_with_incident_service(self):
        from backend.app.services.incident_service import (
            _ALERT_TYPE_TO_STAGE as incident_stages,
        )
        for at, stage in _ALERT_TYPE_TO_STAGE.items():
            if at in incident_stages:
                assert stage == incident_stages[at], (
                    f"Stage mismatch for {at}: actions={stage}, "
                    f"incidents={incident_stages[at]}"
                )

    def test_score_override_high_exfil_contain(self):
        assert _score_to_action_override(90, "exfiltration") == "CONTAIN"

    def test_score_override_high_priv_esc_escalate(self):
        assert _score_to_action_override(90, "privilege_escalation") == "ESCALATE"

    def test_score_override_low_suppress(self):
        assert _score_to_action_override(20, "initial_access") == "SUPPRESS"

    def test_score_override_mid_review(self):
        assert _score_to_action_override(45, "initial_access") == "REVIEW"

    def test_score_override_normal_none(self):
        assert _score_to_action_override(70, "initial_access") is None

    def test_get_actions_passes_score(self):
        signals = [Signal("anomalous_ip", 12, True, "Anomalous IP")]
        actions = get_actions("identity.suspiciousSignIn", signals, score=30)
        labels = {a.get("primaryLabel") for a in actions}
        assert "SUPPRESS" in labels

    def test_get_actions_signal_override_beats_score(self):
        signals = [
            Signal("anomalous_ip", 12, True, "Anomalous IP"),
            Signal("data_exfiltration", 15, True, "Exfil detected"),
        ]
        actions = get_actions("identity.suspiciousSignIn", signals, score=30)
        labels = {a.get("primaryLabel") for a in actions}
        assert "CONTAIN" in labels


# ── Fix 7: Scoring Spread ────────────────────────────────────────────────

class TestScoringSpread:
    def test_diminishing_returns_top3_full(self):
        """Top 3 signals at tier-adjusted weight (inferred=0.6x by default)."""
        s1 = Signal("s1", 15, True, "Signal 1")
        s2 = Signal("s2", 12, True, "Signal 2")
        score_2, _, _ = compute_confidence("medium", [s1, s2])
        # medium(15) + int(15*0.6)=9 + int(12*0.6)=7 = 31
        assert score_2 == 31

    def test_diminishing_returns_3rd_at_full(self):
        """3rd inferred signal still in top-3 band (full tier-adjusted weight)."""
        s1 = Signal("s1", 15, True, "Signal 1")
        s2 = Signal("s2", 12, True, "Signal 2")
        s3 = Signal("s3", 10, True, "Signal 3")
        score_3, _, _ = compute_confidence("medium", [s1, s2, s3])
        # medium(15) + int(15*0.6) + int(12*0.6) + int(10*0.6) + 3(corroboration) = 40
        assert score_3 == 40

    def test_diminishing_returns_4th_at_80pct(self):
        """4th signal at 80% of tier-adjusted weight."""
        s1 = Signal("s1", 15, True, "Signal 1")
        s2 = Signal("s2", 12, True, "Signal 2")
        s3 = Signal("s3", 10, True, "Signal 3")
        s4 = Signal("s4", 8, True, "Signal 4")
        score_4, _, _ = compute_confidence("medium", [s1, s2, s3, s4])
        # 15 + 9+7+6 + int(int(8*0.6)*0.8)=3 + 5(corroboration for 4) = 45
        assert score_4 == 45

    def test_corroboration_graduated(self):
        s1 = Signal("s1", 15, True, "a")
        s2 = Signal("s2", 12, True, "b")
        s3 = Signal("s3", 10, True, "c")
        score_3, _, _ = compute_confidence("medium", [s1, s2, s3])

        s4 = Signal("s4", 8, True, "d")
        s5 = Signal("s5", 6, True, "e")
        score_5, _, _ = compute_confidence("medium", [s1, s2, s3, s4, s5])

        # 5 signals get +8 corroboration, 3 get +3, diff includes 4th+5th signal weights
        diff = score_5 - score_3
        assert diff == 10  # verified by running compute_confidence

    def test_combined_asset_user_weight_reduced(self):
        signals = [Signal("s1", 12, True, "a")]
        score_both, _, _ = compute_confidence(
            "medium", signals, asset_weight=20, user_weight=15)
        score_asset, _, _ = compute_confidence(
            "medium", signals, asset_weight=20, user_weight=0)
        score_user, _, _ = compute_confidence(
            "medium", signals, asset_weight=0, user_weight=15)
        score_plain, _, _ = compute_confidence("medium", signals)

        # When only one fires: full weight
        assert score_asset - score_plain == 20
        assert score_user - score_plain == 15
        # When both fire: 70% of sum = int(35*0.7) = 24
        assert score_both - score_plain == 24

    def test_score_spread_realistic(self):
        """Verify score spread: high-severity alert with tier-multiplied
        inferred/observed signals should produce moderate scores."""
        signals = [
            Signal("anomalous_ip", 15, True, "a"),   # observed: 0.4x
            Signal("after_hours", 8, True, "b"),      # inferred: 0.6x
            Signal("external_geo", 10, True, "c"),    # observed: 0.4x
        ]
        score, _, _ = compute_confidence("high", signals)
        # Tier multipliers significantly reduce these non-verified signals
        assert score < 65, f"Expected < 65 for observed/inferred signals, got {score}"
        assert score > 30, f"Expected > 30 for high + 3 signals, got {score}"

    def test_explanation_excludes_negative_weights(self):
        signals = [Signal("anomalous_ip", 12, True, "a")]
        _, _, expl = compute_confidence(
            "medium", signals, asset_weight=-5, user_weight=-3)
        asset_entries = [e for e in expl if e["signal"] == "asset_criticality"]
        user_entries = [e for e in expl if e["signal"] == "user_risk"]
        assert len(asset_entries) == 0
        assert len(user_entries) == 0
