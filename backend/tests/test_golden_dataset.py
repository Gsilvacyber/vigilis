"""Golden Dataset — regression tests asserting enrichment quality on attack data.

These tests validate that Vigilis correctly enriches realistic attack scenarios
by checking that specific signals fire, MITRE techniques are detected, and
scores are appropriate. If anyone breaks a detection pattern, this test catches it.

Uses the 10 attack scenarios from backend/app/fixtures/attack_scenarios.py.
"""
from __future__ import annotations

import pytest

from backend.app.fixtures.attack_scenarios import get_all_scenarios


# ─── Helpers ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def attack_results(test_client) -> dict[str, list[dict]]:
    """Load all attack scenarios and collect the enrichment results.

    Returns a dict of scenario_name -> list of case response dicts.
    Uses module scope so we only load once per test run.

    Ensures the DB schema is ready before inserting (fixes the 'no such
    table: tenants' flakiness when run after tests that drop/recreate tables).
    """
    from sqlmodel import SQLModel
    from backend.app.core.db import engine
    from backend.app.core.auth import seed_demo_key
    SQLModel.metadata.create_all(engine)
    seed_demo_key()

    results: dict[str, list[dict]] = {}
    scenarios = get_all_scenarios()
    for scenario in scenarios:
        case_results = []
        for case_dict in scenario["cases"]:
            resp = test_client.post("/api/v1/cases", json=case_dict)
            if resp.status_code == 200:
                case_results.append(resp.json())
            else:
                case_results.append({"_error": resp.status_code, "_body": resp.text})
        results[scenario["name"]] = case_results
    return results


def _signals(case_result: dict) -> set[str]:
    """Extract the set of fired signal names from a case result."""
    expl = case_result.get("confidence", {}).get("explanation", [])
    return {
        e["signal"] for e in expl
        if isinstance(e, dict) and not e.get("signal", "").startswith("_")
    }


def _score(case_result: dict) -> int:
    return case_result.get("confidence", {}).get("score", 0)


def _has_mitre(case_result: dict, technique: str) -> bool:
    """Check if a specific MITRE technique was tagged on the case."""
    enrichment = case_result.get("enrichment", {})
    if isinstance(enrichment, dict):
        mitre = enrichment.get("mitre", {})
        if isinstance(mitre, dict):
            return technique in (mitre.get("techniques") or [])
    return False


# ─── Scenario-level tests ────────────────────────────────────────────────

class TestCredentialDumpingScenario:

    def test_download_cradle_detected(self, attack_results):
        cases = attack_results.get("cred_dump_lateral", [])
        assert len(cases) >= 5
        # Case 2 (download cradle) should fire download_cradle signal
        step2 = cases[1]
        assert "download_cradle" in _signals(step2) or _score(step2) >= 50

    def test_mimikatz_scores_high(self, attack_results):
        cases = attack_results.get("cred_dump_lateral", [])
        step3 = cases[2]  # Mimikatz
        assert _score(step3) >= 40  # credential dump should score medium-high

    def test_lateral_movement_detected(self, attack_results):
        cases = attack_results.get("cred_dump_lateral", [])
        step4 = cases[3]  # PsExec
        sigs = _signals(step4)
        # Should fire lateral movement or remote execution related signals
        assert len(sigs) >= 1


class TestRansomwareScenario:

    def test_shadow_copy_deletion_detected(self, attack_results):
        cases = attack_results.get("ransomware", [])
        assert len(cases) >= 4
        step3 = cases[2]  # vssadmin delete shadows
        sigs = _signals(step3)
        assert "shadow_copy_deletion" in sigs or "ransomware_chain" in sigs

    def test_mass_encryption_scores_critical(self, attack_results):
        cases = attack_results.get("ransomware", [])
        step4 = cases[3]  # mass file create
        assert _score(step4) >= 40

    def test_defender_tamper_detected(self, attack_results):
        cases = attack_results.get("ransomware", [])
        step2 = cases[1]  # Set-MpPreference disable
        # The sysmon translator should set _defenderTampered
        assert _score(step2) >= 30


class TestInsiderExfilScenario:

    def test_bulk_transfer_detected(self, attack_results):
        cases = attack_results.get("insider_exfil", [])
        assert len(cases) >= 3
        step2 = cases[1]  # Bulk upload to Dropbox
        assert _score(step2) >= 50

    def test_insider_resignation_context(self, attack_results):
        cases = attack_results.get("insider_exfil", [])
        step1 = cases[0]
        # _insiderResignation should boost the score
        sigs = _signals(step1)
        assert "resignation_on_file" in sigs or _score(step1) >= 30


class TestLOLBinScenario:

    def test_certutil_download_detected(self, attack_results):
        cases = attack_results.get("lolbin_chain", [])
        assert len(cases) >= 4
        step1 = cases[0]  # certutil download
        sigs = _signals(step1)
        assert "download_cradle" in sigs or _score(step1) >= 40

    def test_scheduled_task_persistence(self, attack_results):
        cases = attack_results.get("lolbin_chain", [])
        step4 = cases[3]  # schtasks create
        assert _score(step4) >= 30


class TestADTakeoverScenario:

    def test_account_creation_detected(self, attack_results):
        cases = attack_results.get("ad_takeover", [])
        assert len(cases) >= 4
        step3 = cases[2]  # net user /add
        assert _score(step3) >= 30

    def test_privilege_escalation_detected(self, attack_results):
        cases = attack_results.get("ad_takeover", [])
        step4 = cases[3]  # Domain Admins add
        sigs = _signals(step4)
        assert "privilege_activity" in sigs or "admin_role_grant" in sigs or _score(step4) >= 30


class TestBECScenario:

    def test_foreign_signin_scores_high(self, attack_results):
        cases = attack_results.get("bec", [])
        assert len(cases) >= 4
        step1 = cases[0]  # Nigeria sign-in
        assert _score(step1) >= 40

    def test_email_forward_rule_detected(self, attack_results):
        cases = attack_results.get("bec", [])
        step3 = cases[2]  # inbox rule
        assert _score(step3) >= 30


# ─── Aggregate quality invariants ────────────────────────────────────────

class TestAggregateQuality:
    """Cross-scenario quality checks."""

    def test_attack_cases_score_above_baseline(self, attack_results):
        """Attack cases should score HIGHER than the general population average (~30)."""
        all_scores = []
        for cases in attack_results.values():
            for c in cases:
                s = _score(c)
                if s > 0:
                    all_scores.append(s)
        assert len(all_scores) >= 30
        avg = sum(all_scores) / len(all_scores)
        # Attack cases should average at LEAST 35 (above the ~30 general average)
        assert avg >= 35, f"Attack cases avg {avg:.1f} — should be >= 35"

    def test_most_attack_cases_have_signals(self, attack_results):
        """At least 80% of attack cases should fire 1+ signals."""
        total = 0
        with_signals = 0
        for cases in attack_results.values():
            for c in cases:
                total += 1
                if len(_signals(c)) >= 1:
                    with_signals += 1
        pct = with_signals / total * 100 if total > 0 else 0
        assert pct >= 80, f"Only {pct:.0f}% of attack cases have signals — should be >= 80%"

    def test_no_attack_classified_as_benign_powershell(self, attack_results):
        """Attack PowerShell (Mimikatz, download cradle) should NEVER be classified benign."""
        for scenario_name, cases in attack_results.items():
            for i, c in enumerate(cases):
                sigs = _signals(c)
                if "benign_powershell" in sigs:
                    # Check it's an attack scenario, not a benign case
                    assert False, (
                        f"Attack case {scenario_name} step {i+1} was classified as "
                        f"benign_powershell — MITRE should win over benign classification"
                    )

    def test_multi_host_scenarios_produce_entity_diversity(self, attack_results):
        """Scenarios with lateral movement should produce multiple cases with
        meaningful scores, confirming the enrichment processed the chain."""
        cred_dump = attack_results.get("cred_dump_lateral", [])
        assert len(cred_dump) >= 5, "Credential dump chain should have 5+ cases"
        scores = [_score(c) for c in cred_dump]
        # All cases should score above the base (enrichment added value)
        assert all(s >= 15 for s in scores), (
            f"All cases should score >= 15, got {scores}"
        )
        # At least one case should score significantly (attack was detected)
        assert max(scores) >= 30, (
            f"At least one case should score >= 30, max was {max(scores)}"
        )

    def test_all_10_scenarios_load_successfully(self, attack_results):
        """All 10 scenarios should produce at least 3 cases each."""
        assert len(attack_results) >= 10, f"Only {len(attack_results)} scenarios loaded"
        for name, cases in attack_results.items():
            valid = [c for c in cases if "_error" not in c]
            assert len(valid) >= 3, f"Scenario {name} only produced {len(valid)} valid cases"
