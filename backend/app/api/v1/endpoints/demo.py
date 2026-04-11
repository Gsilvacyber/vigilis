"""Demo API — thin re-export of focused sub-routers.

All routes are served under /api/v1/demo/ via the parent router in router.py.
"""
from fastapi import APIRouter

from backend.app.api.v1.endpoints.demo_fixtures import router as fixtures_router
from backend.app.api.v1.endpoints.demo_enrichment import router as enrichment_router
from backend.app.api.v1.endpoints.demo_ingestion import router as ingestion_router

router = APIRouter(prefix="/demo")
router.include_router(fixtures_router)
router.include_router(enrichment_router)
router.include_router(ingestion_router)
