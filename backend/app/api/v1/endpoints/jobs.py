"""Background job status endpoints."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from backend.app.core.auth import require_tenant
from backend.app.services.job_manager import get_job_manager

router = APIRouter()


@router.get("/jobs/{job_id}")
def api_get_job(
    job_id: str,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    job = get_job_manager().get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.tenant_id != auth_tenant:
        raise HTTPException(status_code=403, detail="Access denied")
    return {
        "jobId": job.job_id,
        "status": job.status.value,
        "progress": job.progress,
        "message": job.message,
        "result": job.result if job.status.value == "completed" else None,
        "error": job.error,
        "createdAt": job.created_at.isoformat(),
        "completedAt": job.completed_at.isoformat() if job.completed_at else None,
    }


@router.get("/jobs")
def api_list_jobs(
    auth_tenant: str = Depends(require_tenant),
) -> list[dict[str, Any]]:
    jobs = get_job_manager().list_jobs(auth_tenant)
    return [
        {
            "jobId": j.job_id,
            "status": j.status.value,
            "progress": j.progress,
            "message": j.message,
            "createdAt": j.created_at.isoformat(),
        }
        for j in jobs
    ]
