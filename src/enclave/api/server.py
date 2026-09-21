"""FastAPI app: REST for alerts/metrics/schema, a WebSocket live feed, and the dashboard.

When ``settings`` and ``intel`` are supplied (the ``enclave serve`` command), two extra routes are
registered so an evaluator can try the system without cloning it: ``POST /api/analyze`` runs an
uploaded capture through the pipeline, and ``GET /api/sample`` hands back a labelled sample capture.
"""

from __future__ import annotations

import asyncio
import contextlib
import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from enclave.core.config import Settings
from enclave.core.constants import (
    API_ALERTS_DEFAULT_LIMIT,
    API_ALERTS_MAX_LIMIT,
    UPLOAD_ALLOWED_SUFFIXES,
    UPLOAD_MAX_BYTES,
    UPLOAD_READ_CHUNK,
)
from enclave.intel import Intel
from enclave.metrics import Metrics
from enclave.schema.alert import Alert
from enclave.sinks.store import AlertStore

STATIC_DIR = Path(__file__).parent / "static"


def create_app(store: AlertStore, metrics: Metrics, settings: Settings | None = None,
               intel: Intel | None = None) -> FastAPI:
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

    if settings is not None and intel is not None:
        _register_analysis(app, store, metrics, settings, intel)

    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
    else:
        @app.get("/", response_class=HTMLResponse)
        def index() -> str:
            return "<h1>Enclave Threat Console</h1><p>Dashboard assets not found.</p>"

    return app


def _register_analysis(app: FastAPI, store: AlertStore, metrics: Metrics, settings: Settings,
                       intel: Intel) -> None:
    from enclave.api.analyze import analyze_to_store

    lock = asyncio.Lock()

    def _error(code: str, message: str, status: int) -> JSONResponse:
        return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)

    @app.post("/api/analyze")
    async def analyze(file: Annotated[UploadFile, File()]) -> JSONResponse:
        name = file.filename or "upload"
        suffix = Path(name).suffix.lower()
        if suffix not in UPLOAD_ALLOWED_SUFFIXES:
            return _error("unsupported_type",
                          f"{suffix or 'file'} not accepted; upload {', '.join(sorted(UPLOAD_ALLOWED_SUFFIXES))}",
                          415)
        before = sum(metrics.alerts_by_class.values())
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
            tmp_path = Path(handle.name)
            written = 0
            while chunk := await file.read(UPLOAD_READ_CHUNK):
                written += len(chunk)
                if written > UPLOAD_MAX_BYTES:
                    handle.close()
                    tmp_path.unlink(missing_ok=True)
                    return _error("too_large", f"capture exceeds {UPLOAD_MAX_BYTES // (1024 * 1024)} MiB", 413)
                handle.write(chunk)
        try:
            async with lock:
                await analyze_to_store(tmp_path, settings, intel, store, metrics)
        except Exception as exc:
            return _error("analysis_failed", str(exc), 422)
        finally:
            tmp_path.unlink(missing_ok=True)
        new_alerts = sum(metrics.alerts_by_class.values()) - before
        recent = [a.model_dump(mode="json") for a in store.recent(API_ALERTS_DEFAULT_LIMIT)]
        return JSONResponse({"filename": name, "bytes": written, "new_alerts": new_alerts,
                             "alerts_by_class": dict(metrics.alerts_by_class), "alerts": recent})

    @app.get("/api/sample")
    def sample() -> FileResponse:
        from enclave.synth import generate

        out_dir = Path(tempfile.mkdtemp(prefix="enclave-sample-"))
        pcap_path = out_dir / "enclave-sample.pcap"
        generate(pcap_path, None)
        return FileResponse(pcap_path, media_type="application/vnd.tcpdump.pcap",
                            filename="enclave-sample.pcap")


async def serve(app: FastAPI, host: str, port: int) -> None:
    import uvicorn

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    with contextlib.suppress(asyncio.CancelledError):
        await server.serve()
