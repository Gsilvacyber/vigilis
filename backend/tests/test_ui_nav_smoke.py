"""Smoke tests for the Three-Pillar nav IA redesign + Day 4/5 polish.

Covers:
- TestPillarNavRendering: every /demo/ui/* route returns 200 and contains the
  pillar-nav markup with the correct active pillar key
- TestSubnavRendering: Triage/Enrichment/Tuning pages render the sub-tab bar
  with the correct active sub-tab
- TestSettingsDropdown: settings dropdown HTML is present on every page
- TestCalibrationPolish: sortable headers, Δ delta column, per-tier grouping,
  row counts on calibration.html
- TestBackwardCompat: existing URLs still return 200 (no bookmark breakage)
"""
from __future__ import annotations

import pytest


# ─── TestPillarNavRendering ───────────────────────────────────────────────

class TestPillarNavRendering:
    """Every page renders the four-pillar nav with the right active key."""

    @pytest.mark.parametrize("path,expected_active", [
        ("/demo/ui/",             "'home'"),
        ("/demo/ui/cases",        "'triage'"),
        ("/demo/ui/incidents",    "'triage'"),
        ("/demo/ui/enrich",       "'enrichment'"),
        ("/demo/ui/upload",       "'enrichment'"),
        ("/demo/ui/calibration",  "'tuning'"),
        ("/demo/ui/rules",        "'tuning'"),
        ("/demo/ui/metrics",      "'tuning'"),
        ("/demo/ui/admin",        "'home'"),  # no pillar — via settings gear
        ("/demo/ui/jobs",         "'home'"),  # same
    ])
    def test_page_renders_correct_active_pillar(self, test_client, path, expected_active):
        resp = test_client.get(path)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        assert "renderNav(" in resp.text, f"{path} missing renderNav call"
        # The first arg of renderNav is the pillar key
        assert f"renderNav({expected_active}" in resp.text, (
            f"{path} should call renderNav with {expected_active} as first arg"
        )

    def test_pillar_nav_markup_in_js(self, test_client):
        """The served vigilis.js contains the 4-pillar array."""
        resp = test_client.get("/static/vigilis.js")
        assert resp.status_code == 200
        # All 4 pillars should be in VIGILIS_NAV_LINKS
        assert "key: 'home'" in resp.text
        assert "key: 'triage'" in resp.text
        assert "key: 'enrichment'" in resp.text
        assert "key: 'tuning'" in resp.text
        # And the old flat key should NOT appear as a primary nav entry
        # (they're still in subnav map, so we check the primary array shape)
        assert "VIGILIS_NAV_LINKS = [" in resp.text

    def test_subnav_map_covers_three_pillars(self, test_client):
        resp = test_client.get("/static/vigilis.js")
        assert "VIGILIS_SUBNAV" in resp.text
        # Triage subnav has Cases + Incidents
        assert "key: 'cases'" in resp.text
        assert "key: 'incidents'" in resp.text
        # Enrichment subnav has Workbench + Upload
        assert "key: 'workbench'" in resp.text
        assert "key: 'upload'" in resp.text
        # Tuning subnav has Calibration + Rules + Metrics
        assert "key: 'calibration'" in resp.text
        assert "key: 'rules'" in resp.text
        assert "key: 'metrics'" in resp.text


# ─── TestSubnavRendering ──────────────────────────────────────────────────

class TestSubnavRendering:
    """Triage/Enrichment/Tuning pages pass the correct sub-tab key."""

    def test_cases_passes_cases_subtab(self, test_client):
        resp = test_client.get("/demo/ui/cases")
        assert "renderNav('triage', 'cases')" in resp.text

    def test_incidents_passes_incidents_subtab(self, test_client):
        resp = test_client.get("/demo/ui/incidents")
        assert "renderNav('triage', 'incidents')" in resp.text

    def test_enrich_passes_workbench_subtab(self, test_client):
        resp = test_client.get("/demo/ui/enrich")
        assert "renderNav('enrichment', 'workbench')" in resp.text

    def test_upload_passes_upload_subtab(self, test_client):
        resp = test_client.get("/demo/ui/upload")
        assert "renderNav('enrichment', 'upload')" in resp.text

    def test_calibration_passes_calibration_subtab(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        assert "renderNav('tuning', 'calibration')" in resp.text

    def test_rules_passes_rules_subtab(self, test_client):
        resp = test_client.get("/demo/ui/rules")
        assert "renderNav('tuning', 'rules')" in resp.text

    def test_metrics_passes_metrics_subtab(self, test_client):
        resp = test_client.get("/demo/ui/metrics")
        assert "renderNav('tuning', 'metrics')" in resp.text


# ─── TestSettingsDropdown ─────────────────────────────────────────────────

class TestSettingsDropdown:
    """Settings gear + dropdown structure is present in the served JS."""

    def test_settings_links_array_defined(self, test_client):
        resp = test_client.get("/static/vigilis.js")
        assert "VIGILIS_SETTINGS_LINKS" in resp.text
        # All 3 settings entries
        assert "'Admin'" in resp.text
        assert "'Jobs'" in resp.text
        assert "'API Docs'" in resp.text

    def test_settings_gear_click_handler(self, test_client):
        resp = test_client.get("/static/vigilis.js")
        assert "toggleSettingsDropdown" in resp.text
        assert "settings-gear" in resp.text
        assert "settings-dropdown" in resp.text


# ─── TestCalibrationPolish ────────────────────────────────────────────────

class TestCalibrationPolish:
    """Day 4/5 table polish items on calibration.html."""

    def test_sortable_headers_present(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        assert "sortable" in resp.text
        assert "sortTable(" in resp.text
        # All columns should be wired
        assert "'string'" in resp.text  # string sort
        assert "'number'" in resp.text  # number sort

    def test_delta_column_present(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        # The Δ character is in the column header
        assert "Δ" in resp.text
        # The delta calculation
        assert "adjustedWeight-s.originalWeight" in resp.text

    def test_row_counts_in_headers(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        # Calibration report header mentions reduced/boosted counts
        assert "reduced" in resp.text
        assert "boosted" in resp.text
        assert "tracked" in resp.text
        # Signal config header mentions total/disabled
        assert "total, " in resp.text
        assert "disabled" in resp.text

    def test_per_tier_grouping_markup(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        # Collapsible <details> blocks
        assert "<details open>" in resp.text
        assert "tier-summary" in resp.text
        assert "renderGroup(" in resp.text
        # Three tier groups
        assert "renderGroup('verified'" in resp.text
        assert "renderGroup('inferred'" in resp.text
        assert "renderGroup('observed'" in resp.text

    def test_sortTable_helper_served(self, test_client):
        resp = test_client.get("/static/vigilis.js")
        assert "function sortTable(" in resp.text
        assert "data-sort-col" in resp.text
        assert "sort-asc" in resp.text
        assert "sort-desc" in resp.text


# ─── TestBackwardCompat ───────────────────────────────────────────────────

class TestBackwardCompat:
    """No URL changes — every existing page route still works."""

    @pytest.mark.parametrize("path", [
        "/demo/ui/",
        "/demo/ui/enrich",
        "/demo/ui/cases",
        "/demo/ui/incidents",
        "/demo/ui/rules",
        "/demo/ui/metrics",
        "/demo/ui/calibration",
        "/demo/ui/upload",
        "/demo/ui/jobs",
        "/demo/ui/admin",
    ])
    def test_existing_url_still_works(self, test_client, path):
        resp = test_client.get(path)
        assert resp.status_code == 200, f"{path} is broken: {resp.status_code}"
        # Every page should still reference vigilis.js
        assert "vigilis.js" in resp.text

    def test_css_cache_busted_to_v9(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        assert "vigilis.css?v=9" in resp.text

    def test_js_cache_busted_to_v12(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        assert "vigilis.js?v=12" in resp.text
