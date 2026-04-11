"""Simple background job manager using ThreadPoolExecutor."""
import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

_log = logging.getLogger(__name__)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class JobRecord:
    job_id: str
    tenant_id: str
    status: JobStatus = JobStatus.PENDING
    progress: int = 0  # 0-100
    message: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None


class JobManager:
    def __init__(self, max_workers: int = 2):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._jobs: dict[str, JobRecord] = {}
        self._lock = threading.Lock()

    def submit(self, tenant_id: str, fn: Callable, *args: Any, **kwargs: Any) -> str:
        job_id = str(uuid.uuid4())
        record = JobRecord(job_id=job_id, tenant_id=tenant_id)
        with self._lock:
            self._jobs[job_id] = record
            # Auto-prune old jobs (keep last 100)
            if len(self._jobs) > 100:
                sorted_jobs = sorted(self._jobs.values(), key=lambda j: j.created_at)
                for old in sorted_jobs[: len(self._jobs) - 100]:
                    del self._jobs[old.job_id]

        def _wrapper() -> None:
            record.status = JobStatus.RUNNING
            try:
                result = fn(*args, job_record=record, **kwargs)
                record.result = result if isinstance(result, dict) else {"data": result}
                record.status = JobStatus.COMPLETED
                record.progress = 100
            except Exception as e:
                record.status = JobStatus.FAILED
                record.error = str(e)
                _log.exception("Job %s failed", job_id)
            finally:
                record.completed_at = datetime.now(timezone.utc)

        self._executor.submit(_wrapper)
        return job_id

    def get_job(self, job_id: str) -> JobRecord | None:
        return self._jobs.get(job_id)

    def list_jobs(self, tenant_id: str, limit: int = 20) -> list[JobRecord]:
        with self._lock:
            tenant_jobs = [j for j in self._jobs.values() if j.tenant_id == tenant_id]
            return sorted(tenant_jobs, key=lambda j: j.created_at, reverse=True)[:limit]


# Module-level singleton
_manager = JobManager()


def get_job_manager() -> JobManager:
    return _manager
