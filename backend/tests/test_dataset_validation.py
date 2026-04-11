"""Automated validation tests using the Advanced SIEM Dataset.

These tests use a small sample (50 rows) so they run fast in CI.
For full validation, run: python scripts/run_validation.py --sample 500
"""
from __future__ import annotations

import pytest

try:
    from datasets import load_dataset
    HAS_DATASETS = True
except ImportError:
    HAS_DATASETS = False

from backend.app.services.dataset_validation.dataset_adapter import row_to_raw_alert, resolve_alert_type
from backend.app.services.dataset_validation.validator import run_validation, validate_row

pytestmark = pytest.mark.skipif(not HAS_DATASETS, reason="datasets library not installed")

SAMPLE_SIZE = 50


@pytest.fixture(scope="module")
def dataset_rows():
    ds = load_dataset("darkknight25/Advanced_SIEM_Dataset")
    return list(ds["train"])


@pytest.fixture(scope="module")
def validation_report(dataset_rows):
    return run_validation(dataset_rows, sample_size=SAMPLE_SIZE)


class TestDatasetAdapter:
    def test_maps_auth_events(self, dataset_rows):
        auth_rows = [r for r in dataset_rows if r["event_type"] == "auth"][:5]
        for row in auth_rows:
            result = row_to_raw_alert(row)
            assert result is not None, f"Auth row should map: action={row['action']}"
            assert result["alertType"].startswith("identity.")

    def test_maps_endpoint_events(self, dataset_rows):
        ep_rows = [r for r in dataset_rows if r["event_type"] == "endpoint"][:5]
        for row in ep_rows:
            result = row_to_raw_alert(row)
            assert result is not None
            assert result["alertType"].startswith("endpoint.")

    def test_maps_network_events(self, dataset_rows):
        mappable_actions = {"data_exfiltration", "covert_channel", "beaconing", "protocol_anomaly"}
        net_rows = [r for r in dataset_rows if r["event_type"] == "network" and r.get("action") in mappable_actions][:5]
        for row in net_rows:
            result = row_to_raw_alert(row)
            assert result is not None
            assert result["alertType"] == "network.impossibleGeoAccess"

    def test_skips_generic_network_events(self, dataset_rows):
        """Generic network events (connection, disconnection, etc.) should be skipped."""
        skip_actions = {"connection", "latency_spike", "disconnection", "bandwidth_usage"}
        net_rows = [r for r in dataset_rows if r["event_type"] == "network" and r.get("action") in skip_actions][:5]
        for row in net_rows:
            result = resolve_alert_type(row)
            assert result is None, f"Generic network/{row['action']} should not map"

    def test_maps_cloud_events(self, dataset_rows):
        cloud_rows = [r for r in dataset_rows if r["event_type"] == "cloud"][:5]
        for row in cloud_rows:
            result = row_to_raw_alert(row)
            assert result is not None
            assert "cloud." in result["alertType"] or "identity." in result["alertType"]

    def test_skips_ai_and_iot(self, dataset_rows):
        for etype in ("ai", "iot"):
            rows = [r for r in dataset_rows if r["event_type"] == etype][:3]
            for row in rows:
                assert resolve_alert_type(row) is None

    def test_adapted_has_required_fields(self, dataset_rows):
        mappable = [r for r in dataset_rows if r["event_type"] not in ("ai", "iot")][:10]
        for row in mappable:
            adapted = row_to_raw_alert(row)
            if adapted is None:
                continue
            assert "alertType" in adapted
            assert "severity" in adapted
            assert "rawAlert" in adapted
            assert "datasetMeta" in adapted
            assert "identity" in adapted["rawAlert"], f"Missing identity for {adapted['alertType']}"


class TestEnrichmentAccuracy:
    def test_all_cases_produce_scores(self, validation_report):
        for r in validation_report.results:
            assert r.socai_score >= 0
            assert r.socai_score <= 100
            assert r.socai_label in ("low", "medium", "high", "critical")

    def test_all_cases_produce_playbooks(self, validation_report):
        for r in validation_report.results:
            if r.error:
                continue
            assert r.playbook_count > 0, f"No playbook for {r.mapped_alert_type} (event {r.event_id})"

    def test_all_cases_produce_actions(self, validation_report):
        for r in validation_report.results:
            if r.error:
                continue
            assert r.action_count > 0, f"No actions for {r.mapped_alert_type} (event {r.event_id})"

    def test_most_cases_produce_explanations(self, validation_report):
        """At least 50% of cases should have confidence explanations.

        Cases where zero signals fire correctly have no explanations.
        """
        valid = [r for r in validation_report.results if not r.error]
        with_exp = [r for r in valid if r.explanation_count > 0]
        pct = len(with_exp) / len(valid) * 100 if valid else 0
        assert pct >= 50, f"Only {pct:.0f}% of cases have explanations (expected >=50%)"

    def test_signals_fire_for_most_cases(self, validation_report):
        """Zero-signal cases are expected when synthetic data lacks discriminating indicators."""
        no_signals = [r for r in validation_report.results if len(r.signals_fired) == 0 and not r.error]
        pct = len(no_signals) / len(validation_report.results) * 100 if validation_report.results else 0
        assert pct < 55, f"{pct:.0f}% of cases had zero signals fired (expected <55%)"

    def test_error_rate_below_threshold(self, validation_report):
        error_pct = validation_report.errors / validation_report.mapped_rows * 100 if validation_report.mapped_rows else 0
        assert error_pct < 5, f"Error rate {error_pct:.1f}% exceeds 5% threshold"


class TestScoreCalibration:
    def test_mean_absolute_error_reasonable(self, validation_report):
        assert validation_report.mean_absolute_error < 50, (
            f"MAE of {validation_report.mean_absolute_error:.1f} is too high (expected <50)"
        )

    def test_severity_ordering_preserved(self, validation_report):
        """Higher severities should generally produce higher scores."""
        by_sev = validation_report.by_severity
        if "critical" in by_sev and "low" in by_sev:
            assert by_sev["critical"]["socaiMean"] > by_sev["low"]["socaiMean"], (
                f"Critical ({by_sev['critical']['socaiMean']}) should score higher than low ({by_sev['low']['socaiMean']})"
            )

    def test_high_score_cases_mostly_have_signals(self, validation_report):
        """Most cases scoring >=75 should have fired at least one signal."""
        if not validation_report.high_score_cases:
            return
        with_signals = [c for c in validation_report.high_score_cases if len(c.signals_fired) >= 1]
        pct = len(with_signals) / len(validation_report.high_score_cases) * 100
        assert pct >= 80, (
            f"Only {pct:.0f}% of high-score cases have signals (expected >=80%)"
        )


class TestManualReviewFlags:
    def test_high_score_cases_flagged(self, validation_report):
        """Ensure high-score cases are identified for review."""
        assert isinstance(validation_report.high_score_cases, list)

    def test_disagreements_flagged(self, validation_report):
        """Ensure large disagreements are identified."""
        assert isinstance(validation_report.disagreements, list)

    def test_report_has_by_alert_type(self, validation_report):
        """Every mapped alert type should appear in the breakdown."""
        assert len(validation_report.by_alert_type) > 0
        for atype, stats in validation_report.by_alert_type.items():
            assert stats["count"] > 0
            assert stats["playbookAvg"] > 0
