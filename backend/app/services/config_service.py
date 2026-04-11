"""Lightweight JSON-file-backed integration config for MVP.  Tenant-scoped."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_CONFIG_PATH = Path("socai_config.json")

_TENANT_DEFAULT: dict[str, Any] = {
    "mode": "automated",
    "webhookTargets": [
        {
            "name": "Local Echo",
            "url": "http://localhost:8000/debug/webhook-echo",
            "enabled": True,
        },
    ],
}


def _load_all() -> dict[str, Any]:
    if _CONFIG_PATH.exists():
        return json.loads(_CONFIG_PATH.read_text())
    return {}


def _save_all(data: dict[str, Any]) -> None:
    _CONFIG_PATH.write_text(json.dumps(data, indent=2))


def get_config(tenant_id: str = "demo-tenant") -> dict[str, Any]:
    all_cfg = _load_all()
    tenant_cfg = all_cfg.get(tenant_id)
    if tenant_cfg is None:
        return {k: (list(v) if isinstance(v, list) else v) for k, v in _TENANT_DEFAULT.items()}
    return tenant_cfg


def save_config(tenant_id: str, config: dict[str, Any]) -> None:
    all_cfg = _load_all()
    all_cfg[tenant_id] = config
    _save_all(all_cfg)


def get_webhook_targets(tenant_id: str = "demo-tenant") -> list[dict[str, Any]]:
    return get_config(tenant_id).get("webhookTargets", [])


def add_webhook_target(tenant_id: str, name: str, url: str, enabled: bool = True) -> list[dict[str, Any]]:
    config = get_config(tenant_id)
    targets = config.get("webhookTargets", [])
    targets.append({"name": name, "url": url, "enabled": enabled})
    config["webhookTargets"] = targets
    save_config(tenant_id, config)
    return targets


def update_config(tenant_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    config = get_config(tenant_id)
    if "mode" in patch:
        config["mode"] = patch["mode"]
    save_config(tenant_id, config)
    return config
