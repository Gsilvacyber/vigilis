from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.responses import Response
from fastapi.staticfiles import StaticFiles

from backend.app.api.v1.router import api_router_v1
from backend.app.api.demo_ui import ui_router
from backend.app.core.config import settings
from backend.app.core.db import init_db

_STATIC_DIR = Path(__file__).resolve().parent / "static"


import logging

_log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    from backend.app.core.auth import seed_demo_key
    seed_demo_key()

    # Register external threat intel providers if API keys are configured
    from backend.app.services.enrichment.threat_intel import set_threat_intel_providers
    from backend.app.services.enrichment.providers.virustotal import VirusTotalProvider
    from backend.app.services.enrichment.providers.abuseipdb import AbuseIPDBProvider
    from backend.app.services.enrichment.providers.otx import OTXProvider

    from backend.app.services.enrichment.providers.greynoise import GreyNoiseProvider
    from backend.app.services.enrichment.providers.whois_lookup import WHOISProvider
    from backend.app.services.enrichment.providers.local_db import LocalDBProvider

    providers = []
    # Local threat intel DB — queries Postgres, zero API calls, no rate limits
    providers.append(LocalDBProvider())
    _log.info("Local threat intel DB provider registered")
    # OTX (AlienVault) — free, commercial-use allowed
    if settings.otx_api_key:
        providers.append(OTXProvider(settings.otx_api_key))
        _log.info("OTX (AlienVault) provider registered")
    # GreyNoise — free community API, NO key required
    providers.append(GreyNoiseProvider(api_key=getattr(settings, 'greynoise_api_key', None)))
    _log.info("GreyNoise provider registered (community tier)")
    # WHOIS/RDAP — free domain age lookup, NO key required
    providers.append(WHOISProvider())
    _log.info("WHOIS/RDAP provider registered (domain age lookup)")
    # AbuseIPDB — free tier, commercial-use allowed
    if settings.abuseipdb_api_key:
        providers.append(AbuseIPDBProvider(settings.abuseipdb_api_key))
        _log.info("AbuseIPDB provider registered")
    # VirusTotal — PREMIUM ONLY for commercial use
    if settings.virustotal_api_key:
        providers.append(VirusTotalProvider(settings.virustotal_api_key))
        _log.info("VirusTotal provider registered (requires Premium for commercial)")
    if providers:
        set_threat_intel_providers(providers)

    # Start background loops
    import asyncio
    from backend.app.services.retention import retention_cleanup_loop
    from backend.app.services.webhook_service import retry_failed_webhooks_loop
    from backend.app.services.feed_ingestion import update_feeds_loop

    retention_task = asyncio.create_task(retention_cleanup_loop())
    webhook_retry_task = asyncio.create_task(retry_failed_webhooks_loop())
    feed_task = asyncio.create_task(update_feeds_loop(
        interval_hours=getattr(settings, 'feed_update_hours', 24)
    ))

    yield

    # Shutdown background tasks
    retention_task.cancel()
    webhook_retry_task.cancel()
    feed_task.cancel()


def create_app() -> FastAPI:
    application = FastAPI(
        title="Alert-to-Case Enrichment Pack",
        version="0.1.0",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    import os
    from fastapi.middleware.cors import CORSMiddleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:8000").split(","),
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["X-API-Key", "Content-Type"],
        allow_credentials=False,
    )

    @application.get("/", include_in_schema=False)
    def root_redirect() -> RedirectResponse:
        return RedirectResponse(url="/demo/ui/")

    @application.get("/health")
    def health() -> dict:
        result = {"status": "ok"}
        try:
            from backend.app.services.enrichment.threat_intel import get_provider_health
            providers = get_provider_health()
            if providers:
                result["providers"] = providers
                if any(p.get("status") == "error" for p in providers.values()):
                    result["status"] = "degraded"
        except Exception:
            pass  # Don't fail health check if provider tracking not available
        try:
            from backend.app.services.enrichment.entity_graph import get_entity_graph_stats
            graph_stats = get_entity_graph_stats()
            if graph_stats.get("total_relationships", 0) > 0:
                result["entity_graph"] = graph_stats
        except Exception:
            pass
        # Exporter heartbeat summary (Days 1-3 observability)
        try:
            from datetime import datetime as _dt, timedelta as _td, timezone as _tz
            from sqlmodel import select as _select
            from backend.app.core.db import get_session as _get_session
            from backend.app.db.models import AuditEvent as _Audit
            now = _dt.now(_tz.utc)
            cutoff = now - _td(days=1)
            with _get_session() as _s:
                rows = _s.exec(
                    _select(_Audit)
                    .where(_Audit.action == "exporter_heartbeat")
                    .where(_Audit.timestamp >= cutoff)
                ).all()
            latest: dict[tuple[str, str], _Audit] = {}
            for row in rows:
                det = row.details or {}
                k = (str(det.get("exporter") or ""), str(det.get("hostname") or ""))
                if not k[0] or not k[1]:
                    continue
                prev = latest.get(k)
                if prev is None or row.timestamp > prev.timestamp:
                    latest[k] = row
            if latest:
                fresh = stale = 0
                for row in latest.values():
                    ts = row.timestamp
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=_tz.utc)
                    age = int((now - ts).total_seconds())
                    if age < 600:
                        fresh += 1
                    else:
                        stale += 1
                result["exporters"] = {
                    "total": len(latest),
                    "fresh": fresh,
                    "stale": stale,
                }
                if stale > 0:
                    result["status"] = "degraded"
        except Exception:
            pass  # Heartbeat tracking is optional
        return result

    @application.get("/metrics", include_in_schema=False)
    def prometheus_metrics() -> Response:
        """Prometheus metrics in text exposition format."""
        from backend.app.core.metrics import is_enabled, generate_latest, CONTENT_TYPE_LATEST
        if not is_enabled():
            return PlainTextResponse(
                "prometheus_client not installed. pip install prometheus_client",
                status_code=501,
            )
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    if settings.app_env != "prod":
        @application.post("/debug/webhook-echo")
        async def webhook_echo(request: Request) -> JSONResponse:
            body = await request.json()
            return JSONResponse(content={"received": True, "caseId": body.get("caseId")})

    application.include_router(api_router_v1)
    application.include_router(ui_router)
    application.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    return application


app = create_app()
