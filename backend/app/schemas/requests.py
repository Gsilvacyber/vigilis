from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from backend.app.schemas.case_v0_2 import Customer, DispositionStatus, Severity, Source


class CreateCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenantId: str
    customer: Customer
    alertType: str

    source: Source
    rawAlert: dict[str, Any]

    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[Severity] = None
    eventTime: Optional[datetime] = None


class PatchDispositionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: DispositionStatus
    setBy: Optional[str] = None
    setAt: Optional[datetime] = None
    notes: Optional[str] = None


class DeliverWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    webhookUrl: Optional[str] = None
    # If set, include an override of delivery attempt number (useful for retries)
    attemptNo: Optional[int] = None


class EnrichRawRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alertType: str
    rawAlert: dict[str, Any]
    tenantId: str = "demo-tenant"
    customer: Customer = Field(default_factory=lambda: Customer(name="Demo Customer"))
    source: Optional[Source] = None
    severity: Optional[Severity] = None
    eventTime: Optional[datetime] = None
    title: Optional[str] = None
    description: Optional[str] = None
    persist: bool = False


class ProcessUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fileContent: str
    filename: str
    alertType: str | None = None
    columnOverrides: dict[str, str] | None = None
    persist: bool = False
    grouping: bool = False


class BulkDispositionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    caseIds: list[UUID]
    status: DispositionStatus
    setBy: Optional[str] = None


class CreateNoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    author: str = "demo-analyst"
    content: str


class CaseQueryParams(BaseModel):
    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)

