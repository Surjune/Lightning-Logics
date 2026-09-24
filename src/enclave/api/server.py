"""FastAPI app: REST for alerts/metrics/schema, a WebSocket live feed, and the dashboard.

When ``settings`` and ``intel`` are supplied (the ``enclave serve`` command), two extra routes are
registered so an evaluator can try the system without cloning it: ``POST /api/analyze`` runs an
uploaded capture through the pipeline, and ``GET /api/sample`` hands back a labelled sample capture.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
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
    DEMO_BUS_MAXSIZE,
    DEMO_REPLAY_SPEED,
    UPLOAD_ALLOWED_SUFFIXES,
    UPLOAD_MAX_BYTES,
    UPLOAD_READ_CHUNK,
)
from enclave.core.logging import get_logger
from enclave.intel import Intel
from enclave.metrics import Metrics
from enclave.schema.alert import Alert
from enclave.sinks.store import AlertStore, HashChainLog

STATIC_DIR = Path(__file__).parent / "static"
log = get_logger(__name__)


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
    sample_cache: dict[str, Path] = {}  # generated once, then served instantly
    demo_state: dict[str, asyncio.Task[None] | None] = {"task": None}

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
        tmp_dir = Path(tempfile.mkdtemp(prefix="enclave-analyze-"))
        tmp_path = tmp_dir / f"upload{suffix}"
        written = 0
        with tmp_path.open("wb") as handle:
            while chunk := await file.read(UPLOAD_READ_CHUNK):
                written += len(chunk)
                if written > UPLOAD_MAX_BYTES:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    return _error("too_large", f"capture exceeds {UPLOAD_MAX_BYTES // (1024 * 1024)} MiB", 413)
                handle.write(chunk)
        try:
            async with lock:
                # Analyse the uploaded capture in ISOLATION so the report is this file alone,
                # never mixed into the shared live feed.
                file_store = AlertStore(HashChainLog(tmp_dir / "alerts.jsonl"), f"upload:{name}")
                file_metrics = Metrics()
                await analyze_to_store(tmp_path, settings, intel, file_store, file_metrics)
                alerts = [a.model_dump(mode="json") for a in file_store.all()]
                snap = file_metrics.snapshot()
        except Exception as exc:  # surface any parse/analysis failure as a typed error
            return _error("analysis_failed", str(exc), 422)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return JSONResponse({
            "filename": name, "bytes": written,
            "alerts": alerts,
            "summary": {"total": len(alerts), "by_class": snap["alerts_by_class"],
                        "by_severity": snap["alerts_by_severity"]},
            "stats": {"events": snap["events"], "flows_per_s": snap["flows_per_s"],
                      "latency_ms": snap["latency_ms"], "dropped": snap["dropped"],
                      "detectors_active": [d["name"] for d in snap["detectors"] if d["active"]]},
        })

    @app.get("/api/sample")
    def sample() -> FileResponse:
        return FileResponse(_demo_capture(), media_type="application/vnd.tcpdump.pcap",
                            filename="enclave-sample.pcap")

    def _demo_capture() -> Path:
        """The labelled demo capture, reused if present and generated once otherwise."""
        path = sample_cache.get("path")
        if path is None or not path.is_file():
            demo = Path("data/demo.pcap")
            if demo.is_file():
                path = demo  # reuse the already-generated demo capture — instant
            else:
                from enclave.synth import generate

                path = Path(tempfile.mkdtemp(prefix="enclave-sample-")) / "enclave-sample.pcap"
                generate(path, None)  # generate once; cached for every later use
            sample_cache["path"] = path
        return path

    async def _replay_demo(path: Path) -> None:
        # Replay the demo capture into the SHARED store/metrics so the live feed fills up, the same
        # way `enclave replay --serve` does from the CLI — only triggered from the dashboard button.
        from enclave.ingest.pcap_source import PcapSource
        from enclave.pipeline import Pipeline

        try:
            source = PcapSource(path, speed=DEMO_REPLAY_SPEED)
            await Pipeline(settings, source, store, metrics, intel).run(bus_maxsize=DEMO_BUS_MAXSIZE)
        except Exception:  # a demo replay must never take the server down
            log.exception("demo replay failed")

    @app.post("/api/demo/replay")
    async def demo_replay() -> JSONResponse:
        task = demo_state["task"]
        if task is not None and not task.done():
            return JSONResponse({"status": "running"})
        demo_state["task"] = asyncio.create_task(_replay_demo(_demo_capture()))
        return JSONResponse({"status": "started"})

    @app.get("/api/demo/status")
    def demo_status() -> JSONResponse:
        task = demo_state["task"]
        return JSONResponse({"running": task is not None and not task.done()})


async def serve(app: FastAPI, host: str, port: int) -> None:
    import uvicorn

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    with contextlib.suppress(asyncio.CancelledError):
        await server.serve()
