# SOCAI — Tech Context

## Stack
- **Python 3.11+**
- **FastAPI** — API framework + HTML serving (no Jinja, raw HTMLResponse)
- **SQLModel** — ORM (SQLAlchemy + Pydantic hybrid)
- **SQLite** (dev default) / **PostgreSQL** (production)
- **Pydantic v2** — request/response schemas with `ConfigDict(extra="forbid")`
- **pytest** — 410 tests, ~90s runtime
- **httpx** — webhook delivery client
- **uvicorn** — ASGI server

## Database
- `DATABASE_URL=sqlite:///local.db` for local dev
- JSON columns use `JSON().with_variant(JSONB(), "postgresql")` for cross-DB compatibility
- `connect_args={"check_same_thread": False}` for SQLite
- `pool_pre_ping=True` for PostgreSQL
- Tables: `Tenant`, `Case`, `CaseSource`, `CaseConfidenceSignal`, `CaseDispositionEvent`, `CaseNote`, `WebhookDelivery`, `ApiKey`, `SuppressionRule`, `Incident`, `IncidentCaseLink`, `CalibrationFeedback`, `SignalTelemetry`

## Environment
- `.env` / `.env.example` for config
- `APP_CREATE_TABLES=1` auto-creates tables on startup
- `WEBHOOK_DEFAULT_URL=http://localhost:8000/debug/webhook-echo` for local testing

## Key Patterns
- Enrichment engine: `app/services/enrichment/` with per-domain mappers
- All scoring is deterministic: severity base + signal weights, capped at 100
- UI: static HTML files in `app/static/`, served via `app/api/demo_ui.py`
- Lifespan handler (not deprecated `on_event`)

## Running Locally
```powershell
cd backend
pip install -r requirements.txt
uvicorn backend.app.main:app --reload
# Open http://localhost:8000/
```

## Running Tests
```powershell
python -m pytest backend/tests/ -v
```
