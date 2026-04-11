"""Background task for enforcing case retention TTL."""
import asyncio
import logging
from datetime import datetime, timezone

from sqlmodel import select

_log = logging.getLogger(__name__)


async def retention_cleanup_loop(interval_seconds: int = 3600):
    """Run retention cleanup every hour. Started in app lifespan."""
    _log.info("Retention cleanup task started (interval=%ds)", interval_seconds)
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            _run_cleanup()
        except Exception:
            _log.exception("Retention cleanup failed")


def _run_cleanup():
    from backend.app.api.v1.endpoints.cases import _cascade_delete_cases
    from backend.app.core.db import get_session
    from backend.app.db.models import Case as CaseRow

    now = datetime.now(timezone.utc)
    with get_session() as session:
        # Find cases past their retention TTL
        all_cases = session.exec(select(CaseRow)).all()
        expired_ids = []
        for case in all_cases:
            ttl = getattr(case, "retention_ttl_days", 14) or 14
            if case.created_at and (now - case.created_at).days > ttl:
                expired_ids.append(case.id)

        if not expired_ids:
            return

        _log.info("Retention cleanup: deleting %d expired cases", len(expired_ids))
        _cascade_delete_cases(session, expired_ids)
        session.commit()
        _log.info("Retention cleanup complete: %d cases removed", len(expired_ids))
