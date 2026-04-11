import os

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session


def _configure_test_env() -> None:
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        url = "sqlite:///test.db"
    os.environ["DATABASE_URL"] = url


_configure_test_env()

from backend.app.main import app  # noqa: E402
from backend.app.db.models import (  # noqa: E402,F401
    ApiKey,
    AuditEvent,
    CalibrationFeedback,
    Case,
    CaseConfidenceSignal,
    CaseDispositionEvent,
    CaseSource,
    SignalTelemetry,
    Tenant,
    WebhookDelivery,
)
from backend.app.core.db import engine  # noqa: E402
from backend.app.core.auth import DEMO_API_KEY, seed_demo_key, _rate_counts  # noqa: E402
from backend.app.services.enrichment.cross_alert import reset_scanner  # noqa: E402
from backend.app.services.enrichment.threat_intel import reset_threat_intel  # noqa: E402
from backend.app.services.enrichment.telemetry import get_collector as _get_telemetry_collector  # noqa: E402


@pytest.fixture(scope="session")
def test_client() -> TestClient:
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    seed_demo_key()
    return TestClient(app, headers={"X-API-Key": DEMO_API_KEY})


@pytest.fixture(autouse=True)
def _reset_shared_state():
    """Clear rate-limit counters, cross-alert scanner, threat intel, and telemetry buffer before each test."""
    _rate_counts.clear()
    reset_scanner()
    reset_threat_intel()
    _get_telemetry_collector().clear_buffer()


@pytest.fixture()
def raw_client() -> TestClient:
    """Client with NO API key header - for testing auth rejection."""
    return TestClient(app)


@pytest.fixture()
def fresh_client() -> TestClient:
    """Function-scoped client with a freshly reset database.

    Use this for tests that need isolated DB state (e.g. paste, IOC,
    comparison, live-feed tests).
    """
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    seed_demo_key()
    return TestClient(app, headers={"X-API-Key": DEMO_API_KEY})


@pytest.fixture()
def populated_fresh_client(fresh_client) -> TestClient:
    """Fresh client with simulated pilot data pre-loaded."""
    fresh_client.post("/api/v1/demo/simulate-pilot")
    return fresh_client


@pytest.fixture()
def db_session():
    with Session(engine) as session:
        yield session
