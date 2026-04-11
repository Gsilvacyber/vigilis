from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

_STATIC = Path(__file__).resolve().parent.parent / "static"

ui_router = APIRouter(prefix="/demo/ui", tags=["demo-ui"])


@ui_router.get("/", response_class=HTMLResponse)
def ui_landing() -> HTMLResponse:
    return HTMLResponse((_STATIC / "landing.html").read_text(encoding="utf-8"))


@ui_router.get("/enrich", response_class=HTMLResponse)
def ui_enrich() -> HTMLResponse:
    return HTMLResponse((_STATIC / "enrich.html").read_text(encoding="utf-8"))


@ui_router.get("/cases", response_class=HTMLResponse)
def ui_cases() -> HTMLResponse:
    return HTMLResponse((_STATIC / "cases.html").read_text(encoding="utf-8"))


@ui_router.get("/cases/{case_id}", response_class=HTMLResponse)
def ui_case_detail(case_id: str) -> HTMLResponse:
    return HTMLResponse((_STATIC / "case_detail.html").read_text(encoding="utf-8"))


@ui_router.get("/metrics", response_class=HTMLResponse)
def ui_metrics() -> HTMLResponse:
    return HTMLResponse((_STATIC / "metrics.html").read_text(encoding="utf-8"))


@ui_router.get("/incidents", response_class=HTMLResponse)
def ui_incidents() -> HTMLResponse:
    return HTMLResponse((_STATIC / "incidents.html").read_text(encoding="utf-8"))


@ui_router.get("/upload", response_class=HTMLResponse)
def ui_upload() -> HTMLResponse:
    return HTMLResponse((_STATIC / "upload.html").read_text(encoding="utf-8"))


@ui_router.get("/rules", response_class=HTMLResponse)
def ui_rules() -> HTMLResponse:
    return HTMLResponse((_STATIC / "rules.html").read_text(encoding="utf-8"))


@ui_router.get("/jobs", response_class=HTMLResponse)
def ui_jobs() -> HTMLResponse:
    return HTMLResponse((_STATIC / "jobs.html").read_text(encoding="utf-8"))


@ui_router.get("/admin", response_class=HTMLResponse)
def ui_admin() -> HTMLResponse:
    return HTMLResponse((_STATIC / "admin.html").read_text(encoding="utf-8"))
