from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlmodel import Session, select

from backend.app.core.config import settings
from backend.app.db.models import Case as CaseRow
from backend.app.db.models import WebhookDelivery
from backend.app.schemas.case_v0_2 import CaseV0_2
from backend.app.services.case_service import get_case

_log = logging.getLogger(__name__)

# Retry schedule: [30s, 2min, 10min, 1hr]
_RETRY_DELAYS = [30, 120, 600, 3600]
MAX_RETRIES = 4


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _next_attempt_no(session: Session, case_id: Any) -> int:
    latest = session.exec(
        select(WebhookDelivery).where(WebhookDelivery.case_id == case_id).order_by(WebhookDelivery.attempt_no.desc())
    ).first()
    if latest is None:
        return 1
    return (latest.attempt_no or 0) + 1


def deliver_case_payload(
    *,
    session: Session,
    case_id: Any,
    webhook_url: str,
    attempt_no: Optional[int] = None,
    client: Optional[httpx.Client] = None,
) -> WebhookDelivery:
    case = get_case(session, case_id)
    if case is None:
        raise ValueError("Case not found")

    # Determine attempt number for the delivery
    attempt = attempt_no if attempt_no is not None else _next_attempt_no(session, case_id)

    delivery = WebhookDelivery(case_id=case_id, webhook_url=webhook_url, attempt_no=attempt, delivered=False)
    delivery.payload = case.model_dump(mode="json")  # store canonical JSON
    delivery.delivered_at = None
    delivery.status_code = None
    delivery.error = None

    session.add(delivery)
    session.commit()
    session.refresh(delivery)

    # Send
    http_client = client or httpx.Client(timeout=10)
    try:
        resp = http_client.post(webhook_url, json=delivery.payload)
        delivery.status_code = resp.status_code
        delivery.delivered = resp.is_success
        delivery.error = None if resp.is_success else resp.text[:2000]
    except Exception as e:  # noqa: BLE001 - MVP: capture and log error
        delivery.delivered = False
        delivery.error = str(e)[:2000]
        delivery.status_code = None
    finally:
        if client is None:
            http_client.close()

    delivery.delivered_at = _utc_now()
    session.add(delivery)
    session.commit()
    session.refresh(delivery)
    return delivery


def schedule_webhook_delivery(
    *,
    session: Session,
    case_id: Any,
    webhook_url: Optional[str],
    attempt_no: Optional[int] = None,
) -> WebhookDelivery:
    target_url = webhook_url or settings.webhook_default_url
    return deliver_case_payload(session=session, case_id=case_id, webhook_url=target_url, attempt_no=attempt_no)


async def retry_failed_webhooks_loop(interval_seconds: int = 60):
    """Periodically check for failed webhooks and retry them."""
    _log.info("Webhook retry task started")
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            _retry_pending()
        except Exception:
            _log.exception("Webhook retry failed")


def _retry_pending() -> None:
    from backend.app.core.db import get_session

    now = datetime.now(timezone.utc)
    with get_session() as session:
        # Find failed deliveries that haven't exceeded max retries
        failed = session.exec(
            select(WebhookDelivery)
            .where(WebhookDelivery.delivered == False)  # noqa: E712
            .where(WebhookDelivery.attempt_no < MAX_RETRIES)
        ).all()

        for delivery in failed:
            # Check if enough time has passed for the next retry
            delay = _RETRY_DELAYS[min(delivery.attempt_no, len(_RETRY_DELAYS) - 1)]
            last_attempt = delivery.delivered_at or delivery.created_at
            if last_attempt and (now - last_attempt).total_seconds() < delay:
                continue  # Not time yet

            # Retry
            try:
                with httpx.Client(timeout=10) as client:
                    resp = client.post(delivery.webhook_url, json=delivery.payload)
                    delivery.delivered = resp.is_success
                    delivery.status_code = resp.status_code
                    delivery.attempt_no += 1
                    delivery.delivered_at = now
                    if resp.is_success:
                        _log.info(
                            "Webhook retry succeeded for case %s (attempt %d)",
                            delivery.case_id,
                            delivery.attempt_no,
                        )
                    else:
                        delivery.error = f"HTTP {resp.status_code}"
            except Exception as e:
                delivery.attempt_no += 1
                delivery.error = str(e)
                delivery.delivered_at = now

            session.add(delivery)
        session.commit()

