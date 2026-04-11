"""WebSocket endpoint for real-time case feed."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.app.services.ws_manager import ws_manager

router = APIRouter()


@router.websocket("/ws/feed")
async def ws_feed(ws: WebSocket) -> None:
    api_key = ws.query_params.get("api_key")
    if not api_key:
        await ws.close(code=1008, reason="API key required")
        return
    from backend.app.core.auth import _resolve_key
    key, tenant_id = _resolve_key(api_key)
    if tenant_id is None:
        await ws.close(code=1008, reason="Invalid API key")
        return
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep connection alive — client can send pings
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)
