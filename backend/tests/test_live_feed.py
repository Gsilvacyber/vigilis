"""Tests for the Live Enrichment Feed feature."""
from __future__ import annotations

import pytest

from backend.app.services.live_feed import generate_feed

pytestmark = pytest.mark.usefixtures("_reset_shared_state")


@pytest.fixture()
def client(fresh_client):
    return fresh_client


# ── Service-level tests ──────────────────────────────────────────────

class TestGenerateFeed:
    def test_returns_list(self):
        items = generate_feed()
        assert isinstance(items, list)
        assert len(items) > 0

    def test_all_alert_types_present(self):
        items = generate_feed()
        types = {item["alertType"] for item in items}
        assert "identity.suspiciousSignIn" in types
        assert "endpoint.malwareDetection" in types
        assert "email.forwardingRule" in types

    def test_items_sorted_by_offset(self):
        items = generate_feed()
        offsets = [item["offsetSeconds"] for item in items]
        assert offsets == sorted(offsets)

    def test_item_has_required_fields(self):
        items = generate_feed()
        item = items[0]
        assert "alertType" in item
        assert "category" in item
        assert "severity" in item
        assert "signals" in item
        assert "signalsFired" in item
        assert "signalsTotal" in item
        assert "scoreBreakdown" in item
        assert "identity" in item
        assert "recommendedPlaybook" in item

    def test_signals_have_structure(self):
        items = generate_feed()
        for item in items:
            for sig in item["signals"]:
                assert "signal" in sig
                assert "weight" in sig
                assert "fired" in sig
                assert "label" in sig

    def test_score_breakdown_valid(self):
        items = generate_feed()
        for item in items:
            sb = item["scoreBreakdown"]
            assert 0 <= sb["finalScore"] <= 100
            assert sb["label"] in ("low", "medium", "high", "critical")
            assert isinstance(sb["severityBase"], int)
            assert isinstance(sb["signalBoost"], int)

    def test_signals_fired_count_matches(self):
        items = generate_feed()
        for item in items:
            fired = sum(1 for s in item["signals"] if s["fired"])
            assert item["signalsFired"] == fired

    def test_category_matches_alert_type(self):
        items = generate_feed()
        for item in items:
            expected_cat = item["alertType"].split(".")[0]
            assert item["category"] == expected_cat

    def test_identity_info_present(self):
        items = generate_feed()
        upn_count = sum(1 for item in items if item["identity"]["upn"])
        assert upn_count > 0

    def test_covers_all_ten_alert_types(self):
        items = generate_feed()
        assert len(items) == 10


# ── API endpoint tests ──────────────────────────────────────────────

def test_live_feed_endpoint(client):
    resp = client.get("/api/v1/demo/live-feed")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 10


def test_live_feed_items_enriched(client):
    resp = client.get("/api/v1/demo/live-feed")
    data = resp.json()
    for item in data:
        assert item["signalsTotal"] > 0
        assert item["scoreBreakdown"]["finalScore"] > 0


def test_live_feed_no_auth_required(raw_client):
    resp = raw_client.get("/api/v1/demo/live-feed")
    assert resp.status_code == 200


def test_live_feed_tab_in_ui(client):
    resp = client.get("/demo/ui/enrich")
    assert resp.status_code == 200
    assert "Live Feed" in resp.text
    assert "feedContainer" in resp.text
    assert "startFeed" in resp.text
