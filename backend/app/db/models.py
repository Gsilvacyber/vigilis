from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID, uuid4

from sqlalchemy import Column, Index, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

_JSON = JSON().with_variant(JSONB(), "postgresql")


class Tenant(SQLModel, table=True):
    __tablename__ = "tenants"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: str = Field(index=True, unique=True)
    customer_name: str
    customer_environment: str = Field(default="prod")
    customer_industry: Optional[str] = None


class Case(SQLModel, table=True):
    __tablename__ = "cases"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(foreign_key="tenants.id", index=True)

    schema_version: str = Field(default="case.v0.2", index=True)
    alert_type: str = Field(index=True)
    title: str
    description: str

    severity: str

    event_time: datetime
    ingested_time: datetime
    enriched_time: datetime

    confidence_score: int
    confidence_label: str

    entities: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    enrichment: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    recommended_playbook: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    recommended_actions: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    outputs: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    audit: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    bulk_target: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))

    disposition_status: str
    disposition_set_by: Optional[str] = None
    disposition_set_at: Optional[datetime] = None
    disposition_notes: Optional[str] = None

    retention_store_mode: str = "cached"
    retention_ttl_days: int = 14
    retention_redacted: bool = True

    time_to_first_decision_ms: Optional[int] = Field(default=None, index=True)

    # Grouping metadata
    alert_count: int = Field(default=1)
    grouping_key: Optional[str] = Field(default=None, index=True)
    member_alert_ids: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class CaseSource(SQLModel, table=True):
    __tablename__ = "case_sources"
    __table_args__ = (
        Index("ix_case_sources_dedup", "source_system", "source_alert_id"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: UUID = Field(foreign_key="cases.id", index=True)

    source_system: str
    source_name: str
    source_alert_id: str
    source_severity: str
    source_url: Optional[str] = None


class CaseConfidenceSignal(SQLModel, table=True):
    __tablename__ = "case_confidence_signals"

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: UUID = Field(foreign_key="cases.id", index=True)

    signal: str
    weight: int
    label: Optional[str] = None
    tier: Optional[str] = None


class ThreatIntelIOC(SQLModel, table=True):
    """Local threat intel indicators from free public feeds (abuse.ch, etc.)."""
    __tablename__ = "threat_intel_iocs"
    __table_args__ = (
        Index("ix_threat_intel_iocs_lookup", "ioc_type", "ioc_value"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    ioc_type: str = Field(index=True)       # "ip", "domain", "hash"
    ioc_value: str = Field(index=True)       # the actual indicator value
    source: str = Field(index=True)          # "feodo_tracker", "urlhaus", "threatfox"
    threat_type: str = Field(default="")     # "botnet_cc", "malware_distribution", etc.
    malware: str = Field(default="")         # "Emotet", "QakBot", etc.
    confidence: float = Field(default=0.85)
    details: str = Field(default="")
    first_seen: Optional[datetime] = None
    last_seen: datetime = Field(default_factory=_utcnow)
    created_at: datetime = Field(default_factory=_utcnow)


class EntityRelationship(SQLModel, table=True):
    """Entity graph — tracks relationships between entities across cases.

    This is the DETECTION BRAIN. Every case creates relationships like:
      user ↔ host     ("admin logged into DC-01")
      host ↔ process  ("DC-01 ran psexec.exe")
      process ↔ ip    ("psexec.exe connected to 10.10.50.20")
      ip ↔ domain     ("162.125.1.1 is dropbox.com")

    During enrichment, we query: "Has this relationship been seen before?"
      first_seen = never → VERIFIED signal: new/anomalous behavior
      count = 1 vs count = 500 → rarity signal
    """
    __tablename__ = "entity_relationships"
    __table_args__ = (
        Index("ix_entity_rel_lookup", "entity_a_type", "entity_a_value",
              "entity_b_type", "entity_b_value"),
        Index("ix_entity_rel_type", "relationship_type"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)

    entity_a_type: str      # "user", "host", "process", "ip", "domain"
    entity_a_value: str     # "admin@test.com", "DC-01", "psexec.exe"
    entity_b_type: str      # "host", "process", "ip", "domain"
    entity_b_value: str     # "DC-01", "psexec.exe", "10.10.50.20"

    relationship_type: str  # "user_host", "host_process", "process_ip", "ip_domain"

    count: int = Field(default=1)
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)

    # Context
    tenant_id: Optional[str] = Field(default=None, index=True)
    last_case_id: Optional[UUID] = None


class WebhookDelivery(SQLModel, table=True):
    __tablename__ = "webhook_deliveries"

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: UUID = Field(foreign_key="cases.id", index=True)

    webhook_url: str
    attempt_no: int = Field(default=1)
    delivered: bool = Field(default=False)
    status_code: Optional[int] = None
    error: Optional[str] = None
    delivered_at: Optional[datetime] = None

    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))

    created_at: datetime = Field(default_factory=_utcnow)


class ApiKey(SQLModel, table=True):
    __tablename__ = "api_keys"

    id: Optional[int] = Field(default=None, primary_key=True)
    key_hash: str = Field(index=True)
    key_prefix: str = Field(index=True, max_length=12)
    tenant_id: str = Field(index=True)
    name: str = Field(default="")
    role: str = Field(default="analyst")  # admin | analyst | viewer
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=_utcnow)


class CaseDispositionEvent(SQLModel, table=True):
    __tablename__ = "case_disposition_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: UUID = Field(foreign_key="cases.id", index=True)

    status: str
    set_by: Optional[str] = None
    set_at: datetime
    notes: Optional[str] = None

    ttfd_ms: Optional[int] = None


class SuppressionRule(SQLModel, table=True):
    __tablename__ = "suppression_rules"

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)

    name: str
    description: str = Field(default="")
    conditions: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    # conditions schema: { alertType?: str, severity?: [str], confidenceMax?: int, entityPatterns?: { user?: str, ip?: str } }
    action: str = Field(default="auto_close")  # auto_close | auto_tag | reduce_priority
    action_value: Optional[str] = Field(default=None)  # e.g. tag name or target priority

    enabled: bool = Field(default=True)
    hits_count: int = Field(default=0)

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class CaseNote(SQLModel, table=True):
    __tablename__ = "case_notes"

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: UUID = Field(foreign_key="cases.id", index=True)

    author: str = Field(default="analyst")
    content: str
    created_at: datetime = Field(default_factory=_utcnow)


class Incident(SQLModel, table=True):
    __tablename__ = "incidents"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    tenant_id: UUID = Field(foreign_key="tenants.id", index=True)

    title: str
    summary: str = Field(default="")
    severity: str
    status: str = Field(default="open")

    confidence_score: int = Field(default=0)
    confidence_label: str = Field(default="low")
    confidence_breakdown: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))

    kill_chain_stages: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    kill_chain_gaps: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    entities: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    linkage_reasons: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    link_strength: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    recommended_actions: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    risk_level: str = Field(default="medium")
    risk_factors: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    workflow: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))
    narrative: str = Field(default="")
    case_count: int = Field(default=0)
    alert_type_count: int = Field(default=0)
    time_span_seconds: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class CalibrationFeedback(SQLModel, table=True):
    __tablename__ = "calibration_feedback"

    id: Optional[int] = Field(default=None, primary_key=True)
    case_id: str = Field(index=True)

    analyst_verdict: str  # true_positive | false_positive | benign_true_positive
    analyst: Optional[str] = None
    notes: Optional[str] = None
    submitted_by: Optional[str] = None

    alert_type: str = Field(default="", index=True)
    confidence_score: int = Field(default=0)
    signals_fired: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))

    created_at: datetime = Field(default_factory=_utcnow)


class SignalTelemetry(SQLModel, table=True):
    __tablename__ = "signal_telemetry"

    id: Optional[int] = Field(default=None, primary_key=True)

    alert_type: str = Field(index=True)
    severity: str
    signals_fired: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))
    signal_count: int = Field(default=0)
    confidence_score: int = Field(default=0)
    source_tool: str = Field(default="unknown")
    asset_tier: str = Field(default="standard")
    user_risk_tier: str = Field(default="standard_user")
    cross_alert_flags: list[Any] = Field(default_factory=list, sa_column=Column(_JSON))

    created_at: datetime = Field(default_factory=_utcnow)


class IncidentCaseLink(SQLModel, table=True):
    __tablename__ = "incident_case_links"

    id: Optional[int] = Field(default=None, primary_key=True)
    incident_id: UUID = Field(foreign_key="incidents.id", index=True)
    case_id: UUID = Field(foreign_key="cases.id", index=True)

    kill_chain_stage: str
    stage_order: int = Field(default=0)
    added_at: datetime = Field(default_factory=_utcnow)


class AuditEvent(SQLModel, table=True):
    __tablename__ = "audit_events"

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    timestamp: datetime = Field(default_factory=_utcnow)
    actor: str  # key prefix or "system"
    action: str = Field(index=True)  # "case.created", "key.created", etc.
    resource_type: str  # "case", "api_key", "incident", "rule"
    resource_id: str = Field(default="")
    details: dict[str, Any] = Field(default_factory=dict, sa_column=Column(_JSON))


