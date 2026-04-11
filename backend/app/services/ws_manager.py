"""WebSocket connection manager for real-time case feed."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts events."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws)

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def broadcast(self, message: dict[str, Any]) -> None:
        payload = json.dumps(message)
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.discard(ws)

    def broadcast_sync(self, message: dict[str, Any]) -> None:
        """Fire-and-forget broadcast from sync code (e.g. service layer)."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.broadcast(message))
        except RuntimeError:
            pass  # No running loop — skip broadcast


# Singleton instance
ws_manager = ConnectionManager()
