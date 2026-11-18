"""WebSocket connection manager.

Messages are NOTIFICATIONS ONLY, published after a successful database commit. Clients
must re-read state from the REST API; the database remains the source of truth.

Message shape::

    {"type": "<topic>", "data": {...}, "timestamp": "<UTC ISO 8601>"}
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import WebSocket
from pydantic import TypeAdapter

from app.core.time import utcnow

logger = logging.getLogger("hospitra.ws")
# Same JSON serialisation as REST responses (UTC datetimes rendered with a trailing "Z").
_JSON = TypeAdapter(Any)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._connections.discard(websocket)

    async def broadcast(self, message_type: str, data: dict[str, Any] | None = None) -> int:
        payload = _JSON.dump_python({"type": message_type, "data": data or {}, "timestamp": utcnow()}, mode="json")
        delivered = 0
        for ws in list(self._connections):
            try:
                await ws.send_json(payload)
                delivered += 1
            except Exception:  # client went away; drop it silently
                logger.info("Dropping closed WebSocket client")
                self.disconnect(ws)
        return delivered


manager = ConnectionManager()
