"""Tests for the Day 6+ entity graph tuning (expanded process field coverage
+ lowered cold-start thresholds + widened rare threshold).

Covers:
- TestExtractPairsFieldCoverage: `_extract_pairs` reads all 15+ process fields
- TestColdStartThresholds: global 10 + process 5 thresholds fire correctly
- TestRareThresholdWidened: pairs seen 1-5 times still count as rare
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
    EntityRelationship,
    Tenant as TenantRow,
)
from backend.app.services.enrichment.entity_graph import (
    _extract_pairs,
    check_entity_relationships,
    check_process_relationships,
)


@pytest.fixture
def fresh_eg_db():
    """Wipe entity graph + cases between tests for isolation."""
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        for row in s.exec(select(EntityRelationship)).all():
            s.delete(row)
        for row in s.exec(select(CaseConfidenceSignal)).all():
            s.delete(row)
        for row in s.exec(select(CaseRow)).all():
            s.delete(row)
        for row in s.exec(select(TenantRow)).all():
            s.delete(row)
        s.commit()
    yield


def _seed_relationships(session: Session, count: int, rel_type: str = "host_process"):
    """Seed N distinct entity relationships so cold-start thresholds pass."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for i in range(count):
        session.add(EntityRelationship(
            entity_a_type="host",
            entity_a_value=f"seed-host-{i}",
            entity_b_type="process",
            entity_b_value=f"seed-proc-{i}.exe",
            relationship_type=rel_type,
            count=1,
            first_seen=now,
            last_seen=now,
        ))
    session.commit()


# ─── TestExtractPairsFieldCoverage ────────────────────────────────────────

class TestExtractPairsFieldCoverage:
    """_extract_pairs must read process name from many field variants."""

    def _get_host_process(self, pairs):
        """Return the (host_value, proc_value) from the first host_process pair, or None."""
        for rel_type, a_type, a_val, b_type, b_val in pairs:
            if rel_type == "host_process":
                return (a_val, b_val)
        return None

    def test_reads_original_process_field(self):
        raw = {"device": {"hostname": "HOST01"}, "process": "cmd.exe"}
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "cmd.exe"

    def test_reads_sysmon_Image_field(self):
        """Sysmon events use `Image` (PascalCase) not `process`."""
        raw = {
            "device": {"hostname": "HOST01"},
            "Image": r"C:\Windows\System32\powershell.exe",
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "powershell.exe"

    def test_reads_ParentImage_field(self):
        raw = {
            "device": {"hostname": "HOST01"},
            "ParentImage": r"C:\Windows\System32\services.exe",
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "services.exe"

    def test_reads_parentProcess_field(self):
        raw = {
            "device": {"hostname": "HOST01"},
            "parentProcess": r"C:\Program Files\Vendor\wrapper.exe",
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "wrapper.exe"

    def test_reads_executablePath_field(self):
        raw = {
            "device": {"hostname": "HOST01"},
            "executablePath": r"C:\Tools\mimikatz.exe",
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "mimikatz.exe"

    def test_reads_processName_camelCase(self):
        raw = {"device": {"hostname": "HOST01"}, "processName": "evil.exe"}
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "evil.exe"

    def test_reads_CommandLine_PascalCase(self):
        raw = {
            "device": {"hostname": "HOST01"},
            "CommandLine": r"C:\Windows\System32\cmd.exe /c calc.exe",
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        # First token of the command line after path stripping
        assert hp[1] == "cmd.exe"

    def test_reads_file_entity_fallback(self):
        """When no process-style field exists, fall back to file.fileName."""
        raw = {
            "device": {"hostname": "HOST01"},
            "file": {"fileName": "suspicious.bin"},
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "suspicious.bin"

    def test_normalizes_case_lowercase(self):
        """Process name should be lowercased for stable pair-keying."""
        raw = {"device": {"hostname": "HOST01"}, "process": "POWERSHELL.EXE"}
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "powershell.exe"

    def test_strips_path_windows_backslash(self):
        raw = {
            "device": {"hostname": "HOST01"},
            "process": r"C:\Windows\System32\cmd.exe",
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "cmd.exe"

    def test_strips_path_unix_slash(self):
        raw = {
            "device": {"hostname": "HOST01"},
            "process": "/usr/bin/bash",
        }
        pairs = _extract_pairs(raw)
        hp = self._get_host_process(pairs)
        assert hp is not None
        assert hp[1] == "bash"


# ─── TestColdStartThresholds ─────────────────────────────────────────────

class TestColdStartThresholds:
    """The cold-start thresholds should be 10 (global) and 5 (process)."""

    def test_global_cold_start_suppresses_at_9(self, fresh_eg_db):
        """With 9 relationships, check_entity_relationships returns []."""
        with Session(engine) as s:
            _seed_relationships(s, count=9)
        # Call with a payload that would normally fire (pristine pair)
        raw = {
            "identity": {"upn": "alice@example.com"},
            "device": {"hostname": "fresh-host"},
            "ips": [{"ipAddress": "203.0.113.50"}],
        }
        signals = check_entity_relationships(
            raw, datetime.now(timezone.utc), tenant_id="demo-tenant",
        )
        # Should be empty because 9 < 10 threshold
        assert signals == []

    def test_global_cold_start_allows_at_10(self, fresh_eg_db):
        """With 10 relationships, novelty signals are allowed to fire."""
        with Session(engine) as s:
            _seed_relationships(s, count=10)
        raw = {
            "identity": {"upn": "alice@example.com"},
            "device": {"hostname": "fresh-host"},
            "ips": [{"ipAddress": "203.0.113.99"}],
        }
        signals = check_entity_relationships(
            raw, datetime.now(timezone.utc), tenant_id="demo-tenant",
        )
        # Should fire at least new_entity_relationship (pristine pairs)
        names = {s.name for s in signals}
        assert "new_entity_relationship" in names

    def test_process_cold_start_suppresses_at_4(self, fresh_eg_db):
        """process_on_new_host is suppressed when < 5 total relationships."""
        with Session(engine) as s:
            _seed_relationships(s, count=4, rel_type="user_host")
        raw = {
            "device": {"hostname": "new-host"},
            "process": "evil.exe",
        }
        signals = check_process_relationships(
            raw, datetime.now(timezone.utc), tenant_id="demo-tenant",
        )
        names = {s.name for s in signals}
        # process_on_new_host should NOT fire (still in cold-start)
        assert "process_on_new_host" not in names

    def test_process_cold_start_allows_at_5(self, fresh_eg_db):
        """process_on_new_host fires when >= 5 total relationships exist."""
        with Session(engine) as s:
            _seed_relationships(s, count=5, rel_type="user_host")
        raw = {
            "device": {"hostname": "new-host"},
            "process": "evil.exe",
        }
        signals = check_process_relationships(
            raw, datetime.now(timezone.utc), tenant_id="demo-tenant",
        )
        names = {s.name for s in signals}
        assert "process_on_new_host" in names


# ─── TestRareThresholdWidened ─────────────────────────────────────────────

class TestRareThresholdWidened:
    """Pairs seen 1-5 times fire rare_entity_relationship (was 1-2)."""

    def test_rare_fires_on_count_3(self, fresh_eg_db):
        """A pair seen exactly 3 times should still fire as rare."""
        with Session(engine) as s:
            # Seed enough background relationships to pass cold-start
            _seed_relationships(s, count=10)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            s.add(EntityRelationship(
                entity_a_type="user",
                entity_a_value="alice@example.com",
                entity_b_type="host",
                entity_b_value="target-host",
                relationship_type="user_host",
                count=3,
                first_seen=now - timedelta(days=5),
                last_seen=now,
            ))
            s.commit()

        raw = {
            "identity": {"upn": "alice@example.com"},
            "device": {"hostname": "target-host"},
        }
        signals = check_entity_relationships(
            raw, datetime.now(timezone.utc), tenant_id="demo-tenant",
        )
        names = {s.name for s in signals}
        assert "rare_entity_relationship" in names

    def test_rare_fires_on_count_5(self, fresh_eg_db):
        """A pair seen exactly 5 times should fire as rare (boundary)."""
        with Session(engine) as s:
            _seed_relationships(s, count=10)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            s.add(EntityRelationship(
                entity_a_type="user",
                entity_a_value="alice@example.com",
                entity_b_type="host",
                entity_b_value="target-host",
                relationship_type="user_host",
                count=5,
                first_seen=now - timedelta(days=5),
                last_seen=now,
            ))
            s.commit()

        raw = {
            "identity": {"upn": "alice@example.com"},
            "device": {"hostname": "target-host"},
        }
        signals = check_entity_relationships(
            raw, datetime.now(timezone.utc), tenant_id="demo-tenant",
        )
        names = {s.name for s in signals}
        assert "rare_entity_relationship" in names

    def test_rare_does_not_fire_on_count_6(self, fresh_eg_db):
        """A pair seen 6 times is now considered 'established' — no rare signal."""
        with Session(engine) as s:
            _seed_relationships(s, count=10)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            s.add(EntityRelationship(
                entity_a_type="user",
                entity_a_value="alice@example.com",
                entity_b_type="host",
                entity_b_value="target-host",
                relationship_type="user_host",
                count=6,
                first_seen=now - timedelta(days=5),
                last_seen=now,
            ))
            s.commit()

        raw = {
            "identity": {"upn": "alice@example.com"},
            "device": {"hostname": "target-host"},
        }
        signals = check_entity_relationships(
            raw, datetime.now(timezone.utc), tenant_id="demo-tenant",
        )
        names = {s.name for s in signals}
        assert "rare_entity_relationship" not in names
