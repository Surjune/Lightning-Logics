"""FastAPI app: REST for alerts/metrics/schema, a WebSocket live feed, and the dashboard."""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from enclave.core.constants import API_ALERTS_DEFAULT_LIMIT, API_ALERTS_MAX_LIMIT
from enclave.metrics import Metrics
from enclave.schema.alert import Alert
from enclave.sinks.store import AlertStore

STATIC_DIR = Path(__file__).parent / "static"


def create_app(store: AlertStore, metrics: Metrics) -> FastAPI:
    app = FastAPI(title="Enclave Threat Console", version="0.1.0")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/metrics")
    def get_metrics() -> JSONResponse:
        return JSONResponse(metrics.snapshot())

    @app.get("/api/alerts")
    def list_alerts(
        limit: Annotated[int, Query(ge=1, le=API_ALERTS_MAX_LIMIT)] = API_ALERTS_DEFAULT_LIMIT,
        severity: str | None = None,
        threat_class: str | None = None,
    ) -> list[dict[str, object]]:
        return [a.model_dump(mode="json") for a in store.recent(limit, severity, threat_class)]

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: str) -> JSONResponse:
        alert = store.get(alert_id)
        if alert is None:
            return JSONResponse({"error": {"code": "not_found", "message": alert_id}}, status_code=404)
        return JSONResponse(alert.model_dump(mode="json"))

    @app.get("/api/schema/alert")
    def alert_schema() -> dict[str, object]:
        return Alert.model_json_schema()

    @app.websocket("/ws/alerts")
    async def ws_alerts(websocket: WebSocket) -> None:
        await websocket.accept()
        for alert in store.recent(API_ALERTS_DEFAULT_LIMIT):
            await websocket.send_json({"type": "snapshot", "alert": alert.model_dump(mode="json")})
        queue = store.subscribe()
        try:
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15.0)
                    await websocket.send_json(message)
                except TimeoutError:
                    await websocket.send_json({"type": "metrics", "metrics": metrics.snapshot()})
        except WebSocketDisconnect:
            pass
        finally:
            store.unsubscribe(queue)

    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    else:
        @app.get("/", response_class=HTMLResponse)
        def index() -> str:
            return "<h1>Enclave Threat Console</h1><p>Dashboard assets not found.</p>"

    return app


async def serve(app: FastAPI, host: str, port: int) -> None:
    import uvicorn

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    with contextlib.suppress(asyncio.CancelledError):
        await server.serve()
