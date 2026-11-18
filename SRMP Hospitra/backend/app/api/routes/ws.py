from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.dependencies import DbSession
from app.core.config import settings
from app.services import user_service
from app.websocket.manager import manager

router = APIRouter()

# Application-defined close code (4000–4999 range): authentication required.
WS_UNAUTHENTICATED = 4401


@router.websocket("/ws/events")
async def events_socket(websocket: WebSocket, db: DbSession) -> None:
    """Notification channel for signed-in users. Clients may send "ping" and receive "pong"."""
    resolved = user_service.resolve_session(db, websocket.cookies.get(settings.session_cookie_name))
    db.close()  # release the connection; the socket may stay open for hours
    if resolved is None:
        # Accept first, then close: a close *before* accept becomes an HTTP 403 handshake
        # rejection, and the browser would only see code 1006 and keep retrying forever.
        await websocket.accept()
        await websocket.close(code=WS_UNAUTHENTICATED)
        return

    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "data": {"clients": manager.connection_count}})
        while True:
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_json({"type": "pong", "data": {}})
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)
