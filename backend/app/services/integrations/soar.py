"""SOAR Action Executor — takes response actions via external APIs.

This is what separates an enrichment engine from a real security platform.
Instead of just scoring alerts, we can RESPOND to them:
  - Isolate a compromised endpoint via CrowdStrike
  - Suspend a compromised user via Okta
  - Create a ticket in ServiceNow for investigation tracking

Each action is:
  1. Triggered by an analyst clicking a button OR by auto-response rules
  2. Executed via the vendor's REST API with customer's credentials
  3. Logged as an audit event on the case
  4. Shown in the case timeline
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx

_log = logging.getLogger(__name__)


class ActionResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAUTHORIZED = "unauthorized"


@dataclass
class SOARAction:
    """Result of a SOAR action execution."""
    action: str
    target: str
    result: ActionResult
    details: str
    vendor: str
    timestamp: datetime
    raw_response: dict[str, Any] | None = None


class CrowdStrikeIntegration:
    """CrowdStrike Falcon — endpoint isolation and containment.

    Requires: client_id + client_secret (API client credentials)
    Docs: https://falcon.crowdstrike.com/documentation/page/api-authentication
    """

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url
        self._token: str | None = None
        self._token_expires: datetime | None = None

    def _authenticate(self) -> str | None:
        """Get OAuth2 bearer token."""
        if self._token and self._token_expires and datetime.now(timezone.utc) < self._token_expires:
            return self._token
        try:
            with httpx.Client(timeout=10) as c:
                resp = c.post(f"{self._base_url}/oauth2/token",
                    data={"client_id": self._client_id, "client_secret": self._client_secret})
            if resp.status_code == 201:
                data = resp.json()
                self._token = data.get("access_token")
                expires_in = data.get("expires_in", 1800)
                from datetime import timedelta
                self._token_expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)
                return self._token
        except Exception as e:
            _log.error("CrowdStrike auth failed: %s", e)
        return None

    def isolate_host(self, hostname: str, reason: str = "") -> SOARAction:
        """Isolate/contain an endpoint — blocks all network except CrowdStrike."""
        token = self._authenticate()
        if not token:
            return SOARAction("isolate_host", hostname, ActionResult.UNAUTHORIZED,
                "Failed to authenticate with CrowdStrike", "crowdstrike",
                datetime.now(timezone.utc))
        try:
            # Step 1: Find device ID by hostname
            with httpx.Client(timeout=15) as c:
                search = c.get(f"{self._base_url}/devices/queries/devices/v1",
                    params={"filter": f"hostname:'{hostname}'"},
                    headers={"Authorization": f"Bearer {token}"})
            device_ids = search.json().get("resources", [])
            if not device_ids:
                return SOARAction("isolate_host", hostname, ActionResult.FAILED,
                    f"Host '{hostname}' not found in CrowdStrike", "crowdstrike",
                    datetime.now(timezone.utc))

            # Step 2: Contain the device
            with httpx.Client(timeout=15) as c:
                contain = c.post(f"{self._base_url}/devices/entities/devices-actions/v2",
                    params={"action_name": "contain"},
                    json={"ids": device_ids},
                    headers={"Authorization": f"Bearer {token}"})

            if contain.status_code in (200, 202):
                return SOARAction("isolate_host", hostname, ActionResult.SUCCESS,
                    f"Host {hostname} isolated via CrowdStrike Falcon",
                    "crowdstrike", datetime.now(timezone.utc),
                    raw_response=contain.json())
            else:
                return SOARAction("isolate_host", hostname, ActionResult.FAILED,
                    f"CrowdStrike contain failed: {contain.status_code}",
                    "crowdstrike", datetime.now(timezone.utc))
        except Exception as e:
            return SOARAction("isolate_host", hostname, ActionResult.FAILED,
                f"CrowdStrike error: {e}", "crowdstrike", datetime.now(timezone.utc))


class OktaIntegration:
    """Okta — user suspension and session clearing.

    Requires: API token (SSWS) + Okta domain
    Docs: https://developer.okta.com/docs/reference/api/users/
    """

    def __init__(self, domain: str, api_token: str):
        self._domain = domain.rstrip("/")
        self._token = api_token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"SSWS {self._token}",
                "Accept": "application/json", "Content-Type": "application/json"}

    def suspend_user(self, user_email: str, reason: str = "") -> SOARAction:
        """Suspend an Okta user — blocks all logins."""
        try:
            with httpx.Client(timeout=10) as c:
                # Find user by email
                search = c.get(f"{self._domain}/api/v1/users/{user_email}",
                    headers=self._headers())
            if search.status_code != 200:
                return SOARAction("suspend_user", user_email, ActionResult.FAILED,
                    f"User '{user_email}' not found in Okta", "okta",
                    datetime.now(timezone.utc))

            user_id = search.json().get("id")
            with httpx.Client(timeout=10) as c:
                suspend = c.post(f"{self._domain}/api/v1/users/{user_id}/lifecycle/suspend",
                    headers=self._headers())

            if suspend.status_code == 200:
                return SOARAction("suspend_user", user_email, ActionResult.SUCCESS,
                    f"User {user_email} suspended in Okta", "okta",
                    datetime.now(timezone.utc))
            else:
                return SOARAction("suspend_user", user_email, ActionResult.FAILED,
                    f"Okta suspend failed: {suspend.status_code}", "okta",
                    datetime.now(timezone.utc))
        except Exception as e:
            return SOARAction("suspend_user", user_email, ActionResult.FAILED,
                f"Okta error: {e}", "okta", datetime.now(timezone.utc))

    def clear_sessions(self, user_email: str) -> SOARAction:
        """Clear all active sessions for a user."""
        try:
            with httpx.Client(timeout=10) as c:
                resp = c.delete(f"{self._domain}/api/v1/users/{user_email}/sessions",
                    headers=self._headers())
            if resp.status_code == 204:
                return SOARAction("clear_sessions", user_email, ActionResult.SUCCESS,
                    f"All sessions cleared for {user_email}", "okta",
                    datetime.now(timezone.utc))
            return SOARAction("clear_sessions", user_email, ActionResult.FAILED,
                f"Session clear failed: {resp.status_code}", "okta",
                datetime.now(timezone.utc))
        except Exception as e:
            return SOARAction("clear_sessions", user_email, ActionResult.FAILED,
                f"Okta error: {e}", "okta", datetime.now(timezone.utc))


class ServiceNowIntegration:
    """ServiceNow — incident ticket creation.

    Requires: instance URL + username + password (or OAuth)
    Docs: https://developer.servicenow.com/dev.do#!/reference/api/
    """

    def __init__(self, instance_url: str, username: str, password: str):
        self._url = instance_url.rstrip("/")
        self._auth = (username, password)

    def create_incident(self, short_description: str, description: str,
                        urgency: int = 2, impact: int = 2,
                        assignment_group: str = "Security Operations") -> SOARAction:
        """Create a ServiceNow incident ticket."""
        try:
            payload = {
                "short_description": short_description,
                "description": description,
                "urgency": str(urgency),
                "impact": str(impact),
                "assignment_group": assignment_group,
                "category": "Security",
            }
            with httpx.Client(timeout=15) as c:
                resp = c.post(f"{self._url}/api/now/table/incident",
                    json=payload, auth=self._auth,
                    headers={"Accept": "application/json", "Content-Type": "application/json"})

            if resp.status_code in (200, 201):
                ticket = resp.json().get("result", {})
                number = ticket.get("number", "?")
                sys_id = ticket.get("sys_id", "?")
                return SOARAction("create_incident", number, ActionResult.SUCCESS,
                    f"ServiceNow incident {number} created (sys_id: {sys_id})",
                    "servicenow", datetime.now(timezone.utc),
                    raw_response=ticket)
            return SOARAction("create_incident", "?", ActionResult.FAILED,
                f"ServiceNow create failed: {resp.status_code}", "servicenow",
                datetime.now(timezone.utc))
        except Exception as e:
            return SOARAction("create_incident", "?", ActionResult.FAILED,
                f"ServiceNow error: {e}", "servicenow", datetime.now(timezone.utc))


# ── Registry ────────────────────────────────────────────────────────────

_integrations: dict[str, Any] = {}


def register_integration(name: str, instance: Any) -> None:
    """Register a SOAR integration for use by case actions."""
    _integrations[name] = instance
    _log.info("SOAR integration registered: %s (%s)", name, type(instance).__name__)


def get_integration(name: str) -> Any | None:
    """Get a registered SOAR integration by name."""
    return _integrations.get(name)


def list_integrations() -> list[dict[str, str]]:
    """List all registered SOAR integrations."""
    return [
        {"name": name, "vendor": type(inst).__name__, "status": "active"}
        for name, inst in _integrations.items()
    ]


def execute_action(integration_name: str, action: str, target: str, **kwargs) -> SOARAction:
    """Execute a SOAR action by integration name.

    Example:
        execute_action("crowdstrike", "isolate_host", "FILE-SVR-03")
        execute_action("okta", "suspend_user", "admin@acme.com")
        execute_action("servicenow", "create_incident", "Security Alert",
                       description="...", urgency=1)
    """
    inst = get_integration(integration_name)
    if inst is None:
        return SOARAction(action, target, ActionResult.FAILED,
            f"Integration '{integration_name}' not configured",
            integration_name, datetime.now(timezone.utc))

    method = getattr(inst, action, None)
    if method is None:
        return SOARAction(action, target, ActionResult.FAILED,
            f"Action '{action}' not supported by {integration_name}",
            integration_name, datetime.now(timezone.utc))

    return method(target, **kwargs)
