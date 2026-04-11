from fastapi import APIRouter

from backend.app.api.v1.endpoints.admin import router as admin_router
from backend.app.api.v1.endpoints.calibration import router as calibration_router
from backend.app.api.v1.endpoints.calibration_report import router as calibration_report_router
from backend.app.api.v1.endpoints.cases import router as cases_router
from backend.app.api.v1.endpoints.config import router as config_router
from backend.app.api.v1.endpoints.demo import router as demo_router
from backend.app.api.v1.endpoints.incidents import router as incidents_router
from backend.app.api.v1.endpoints.jobs import router as jobs_router
from backend.app.api.v1.endpoints.ingest import router as ingest_router
from backend.app.api.v1.endpoints.metrics import router as metrics_router
from backend.app.api.v1.endpoints.rules import router as rules_router
from backend.app.api.v1.endpoints.soar import router as soar_router
from backend.app.api.v1.endpoints.webhooks import router as webhooks_router
from backend.app.api.v1.endpoints.ws import router as ws_router

api_router_v1 = APIRouter(prefix="/api/v1")
api_router_v1.include_router(admin_router, tags=["admin"])
api_router_v1.include_router(calibration_router, tags=["calibration"])
api_router_v1.include_router(calibration_report_router, tags=["calibration"])
api_router_v1.include_router(cases_router, tags=["cases"])
api_router_v1.include_router(config_router, tags=["config"])
api_router_v1.include_router(demo_router, tags=["demo"])
api_router_v1.include_router(incidents_router, tags=["incidents"])
api_router_v1.include_router(jobs_router, tags=["jobs"])
api_router_v1.include_router(ingest_router, tags=["ingest"])
api_router_v1.include_router(metrics_router, tags=["metrics"])
api_router_v1.include_router(rules_router, tags=["rules"])
api_router_v1.include_router(soar_router, tags=["soar"])
api_router_v1.include_router(webhooks_router, tags=["webhooks"])
api_router_v1.include_router(ws_router, tags=["websocket"])
