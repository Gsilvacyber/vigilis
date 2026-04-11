from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

CaseSchemaVersion = Literal["case.v0.2"]

Severity = Literal["informational", "low", "medium", "high", "critical"]
DispositionStatus = Literal["open", "investigating", "benign", "true_positive", "escalated", "closed"]
IdentityType = Literal["user", "service_principal", "managed_identity", "unknown"]
PrivilegeTier = Literal["standard", "privileged", "admin", "service_account"]
MfaStatus = Literal["enabled", "disabled", "not_registered", "not_applicable"]
RiskLevel = Literal["low", "medium", "high", "critical"]
DeviceIdentificationStatus = Literal["identified", "unknown", "not_applicable"]
IpRole = Literal["observed", "anomalous", "legitimate", "prior_known"]
ComplianceStatus = Literal["compliant", "non_compliant", "unknown"]

SourceSystem = Literal["idp", "edr", "email", "cloud", "network", "custom"]
ConfidenceLabel = Literal["low", "medium", "high", "critical"]
EntityAppScopes = list[str]


class Customer(BaseModel):
    name: str
    environment: Literal["prod"] = "prod"
    industry: Optional[str] = None


class Source(BaseModel):
    sourceSystem: SourceSystem
    sourceName: str
    sourceAlertId: str
    sourceSeverity: Severity
    sourceUrl: Optional[str] = None


class ConfidenceSignal(BaseModel):
    signal: str
    weight: int = Field(ge=-30, le=100)
    label: Optional[str] = None
    tier: Optional[str] = None


class Confidence(BaseModel):
    score: int = Field(ge=0, le=100)
    label: ConfidenceLabel
    explanation: list[ConfidenceSignal] = Field(default_factory=list)


class Disposition(BaseModel):
    status: DispositionStatus
    setBy: Optional[str] = None
    setAt: Optional[datetime] = None
    notes: Optional[str] = None


class BulkTarget(BaseModel):
    count: int = 0
    successCount: int = 0
    succeededAccounts: list[str] = Field(default_factory=list)
    sampleTargets: list[str] = Field(default_factory=list)


class Geo(BaseModel):
    country: Optional[str] = None
    city: Optional[str] = None
    isKnownVpn: Optional[bool] = None
    isKnownProxy: Optional[bool] = None
    isTorExit: Optional[bool] = None


class IPAddressEntity(BaseModel):
    role: IpRole
    ipAddress: str
    geo: Geo = Field(default_factory=Geo)


class Device(BaseModel):
    deviceId: Optional[str] = None
    hostname: Optional[str] = None
    managed: bool = True
    os: Optional[str] = None
    compliance: Optional[ComplianceStatus] = None
    identificationStatus: DeviceIdentificationStatus = "unknown"


class App(BaseModel):
    name: Optional[str] = None
    clientApp: Optional[str] = None
    appId: Optional[str] = None
    publisher: Optional[str] = None
    scopes: list[str] = Field(default_factory=list)
    firstSeenInTenantAt: Optional[datetime] = None


class Mailbox(BaseModel):
    primaryAddress: Optional[str] = None
    displayName: Optional[str] = None
    forwardingAddress: Optional[str] = None
    ruleName: Optional[str] = None


class FileEntity(BaseModel):
    fileName: Optional[str] = None
    filePath: Optional[str] = None
    sha256: Optional[str] = None
    signer: Optional[str] = None
    prevalence: Optional[Literal["rare", "common", "unknown"]] = None


class Identity(BaseModel):
    identityType: IdentityType = "unknown"
    userId: Optional[str] = None
    upn: Optional[str] = None
    displayName: Optional[str] = None
    servicePrincipalId: Optional[str] = None
    privilegeTier: Optional[PrivilegeTier] = None
    newPrivilegeTier: Optional[PrivilegeTier] = None
    mfaStatus: Optional[MfaStatus] = None
    riskLevel: Optional[RiskLevel] = None


class Actor(Identity):
    pass


class Entities(BaseModel):
    identity: Identity = Field(default_factory=Identity)
    actor: Actor = Field(default_factory=Actor)
    device: Device = Field(default_factory=Device)
    ips: list[IPAddressEntity] = Field(default_factory=list)
    app: App = Field(default_factory=App)
    mailbox: Mailbox = Field(default_factory=Mailbox)
    file: FileEntity = Field(default_factory=FileEntity)


class Timestamps(BaseModel):
    eventTime: datetime
    ingestedTime: datetime
    enrichedTime: datetime


class ImpactSummary(BaseModel):
    risk: str = ""
    timeSavedMinutes: int = 0
    manualStepsReplaced: list[str] = Field(default_factory=list)


class CaseReadiness(BaseModel):
    readyForAction: bool = True
    missingContext: list[str] = Field(default_factory=list)
    confidenceLevel: str = "medium"


class Enrichment(BaseModel):
    recentActivity: list[Any] = Field(default_factory=list)
    relatedAlerts: list[Any] = Field(default_factory=list)
    riskScore: int = 0
    enrichmentNotes: list[str] = Field(default_factory=list)
    impactSummary: Optional[ImpactSummary] = None
    caseReadiness: Optional[CaseReadiness] = None
    qualityFlags: list[str] = Field(default_factory=list)


class Retention(BaseModel):
    storeMode: Literal["metadata-only", "cached", "vault"] = "cached"
    ttlDays: int = 14
    redacted: bool = True


class Audit(BaseModel):
    rulesetVersion: Literal["rules.v0.2"] = "rules.v0.2"
    enrichmentLatencyMs: int = 0
    enrichmentSources: list[str] = Field(default_factory=list)
    operatorOverrides: list[str] = Field(default_factory=list)
    processingErrors: list[str] = Field(default_factory=list)


class TtfdComparison(BaseModel):
    automatedSeconds: float = 0
    estimatedManualSeconds: int = 900
    improvement: str = ""


class Outputs(BaseModel):
    webhooks: list[str] = Field(default_factory=list)
    soarConnectors: list[str] = Field(default_factory=list)
    ttfdComparison: Optional[TtfdComparison] = None
    mitre: Optional[dict[str, Any]] = None


class CaseV0_2(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schemaVersion: CaseSchemaVersion = "case.v0.2"
    caseId: UUID = Field(default_factory=uuid4)
    tenantId: str
    customer: Customer
    sources: list[Source] = Field(default_factory=list)

    alertType: str
    title: str
    description: str

    timestamps: Timestamps
    severity: Severity
    confidence: Confidence

    disposition: Disposition
    bulkTarget: BulkTarget

    entities: Entities

    enrichment: Enrichment = Field(default_factory=Enrichment)
    recommendedPlaybook: list[Any] = Field(default_factory=list)
    recommendedActions: list[Any] = Field(default_factory=list)

    outputs: Outputs = Field(default_factory=Outputs)

    audit: Audit = Field(default_factory=Audit)
    retention: Retention = Field(default_factory=Retention)

    # Grouping metadata (populated when grouping=True)
    alertCount: int = Field(default=1)
    groupingKey: Optional[str] = None
    groupingReason: Optional[str] = None
    memberAlertIndices: list[int] = Field(default_factory=list)

