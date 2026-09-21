"""Command-line entry point: synth | replay | netflow | verify-log | intel-manifest | schema."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import sys
from pathlib import Path

from enclave.core.config import Settings
from enclave.core.logging import configure_logging, get_logger, new_run_id
from enclave.egress_guard import blocked_attempts, install
from enclave.intel import Intel, write_manifest
from enclave.metrics import Metrics
from enclave.pipeline import Pipeline
from enclave.schema.alert import Alert
from enclave.sinks.store import AlertStore, HashChainLog, verify_chain

log = get_logger("enclave.cli")


def _load(settings_path: Path | None) -> tuple[Settings, Intel]:
    settings = Settings.load(settings_path)
    configure_logging(settings.log_level)
    return settings, Intel.load(settings.intel_dir)


def _run_pipeline(settings: Settings, intel: Intel, source: object, serve: bool, host: str,
                  port: int) -> Metrics:
    store = AlertStore(HashChainLog(settings.alert_log), source.source_ref)  # type: ignore[attr-defined]
    metrics = Metrics()
    pipeline = Pipeline(settings, source, store, metrics, intel)  # type: ignore[arg-type]

    async def main() -> None:
        if serve:
            from enclave.api.server import create_app
            from enclave.api.server import serve as serve_api
            app = create_app(store, metrics, settings, intel)
            api_task = asyncio.create_task(serve_api(app, host, port))
            log.info("dashboard serving", extra={"url": f"http://{host}:{port}"})
            await pipeline.run()
            log.info("replay complete; dashboard still serving (Ctrl+C to stop)")
            await api_task
        else:
            await pipeline.run()

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
    metrics.egress_blocked = blocked_attempts()
    return metrics


def _summary(metrics: Metrics) -> None:
    snap = metrics.snapshot()
    print(json.dumps({
        "events": snap["events"],
        "alerts_by_class": snap["alerts_by_class"],
        "alerts_by_severity": snap["alerts_by_severity"],
        "latency_ms": snap["latency_ms"],
        "dropped": snap["dropped"],
        "egress_blocked": snap["egress_blocked"],
        "detectors_active": [d["name"] for d in snap["detectors"] if d["active"]],
    }, indent=2))


def cmd_synth(args: argparse.Namespace) -> int:
    from enclave.synth import generate
    configure_logging()
    result = generate(Path(args.out), Path(args.intel) if args.intel else None)
    print(json.dumps(result, indent=2))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from enclave.ingest.pcap_source import PcapSource
    new_run_id()
    settings, intel = _load(Path(args.config) if args.config else None)
    install(settings.internal_networks)
    source = PcapSource(Path(args.pcap), speed=args.speed)
    metrics = _run_pipeline(settings, intel, source, args.serve, args.host, args.port)
    _summary(metrics)
    return 0


def cmd_netflow(args: argparse.Namespace) -> int:
    from enclave.ingest.netflow_source import NetflowSource
    new_run_id()
    settings, intel = _load(Path(args.config) if args.config else None)
    host, _, port = args.listen.rpartition(":")
    install(settings.internal_networks)
    source = NetflowSource(host or "0.0.0.0", int(port))
    metrics = _run_pipeline(settings, intel, source, args.serve, args.host, args.port)
    _summary(metrics)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Serve the dashboard with the upload endpoint and no pre-loaded capture (public demo)."""
    import asyncio as _asyncio

    from enclave.api.server import create_app
    from enclave.api.server import serve as serve_api

    new_run_id()
    settings, intel = _load(Path(args.config) if args.config else None)
    install(settings.internal_networks)
    store = AlertStore(HashChainLog(settings.alert_log), "upload")
    metrics = Metrics()
    metrics.input_mode = "pcap"
    app = create_app(store, metrics, settings, intel)
    log.info("dashboard serving", extra={"url": f"http://{args.host}:{args.port}", "mode": "upload"})
    with contextlib.suppress(KeyboardInterrupt):
        _asyncio.run(serve_api(app, args.host, args.port))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.log)
    if not path.is_file():
        print(f"no log at {path}")
        return 1
    intact, count = verify_chain(path)
    print(json.dumps({"log": str(path), "records": count, "chain_intact": intact}, indent=2))
    return 0 if intact else 2


def cmd_manifest(args: argparse.Namespace) -> int:
    path = write_manifest(Path(args.dir))
    print(f"wrote {path}")
    return 0


def cmd_schema(_: argparse.Namespace) -> int:
    print(json.dumps(Alert.model_json_schema(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="enclave", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("synth", help="generate the labelled demo capture and intel")
    p.add_argument("--out", default="data/demo.pcap")
    p.add_argument("--intel", default="intel")
    p.set_defaults(func=cmd_synth)

    p = sub.add_parser("replay", help="replay a pcap/pcapng as a live stream")
    p.add_argument("pcap")
    p.add_argument("--speed", type=float, default=1.0, help="0 = as fast as possible")
    p.add_argument("--config")
    p.add_argument("--serve", action="store_true")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("netflow", help="collect NetFlow v5 (listen-only)")
    p.add_argument("--listen", default="127.0.0.1:2055")
    p.add_argument("--config")
    p.add_argument("--serve", action="store_true")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_netflow)

    p = sub.add_parser("serve", help="serve the dashboard + upload endpoint (no pre-loaded capture)")
    p.add_argument("--config")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("verify-log", help="verify the hash-chained evidence log")
    p.add_argument("log", default="var/alerts.jsonl", nargs="?")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("intel-manifest", help="write manifest.json (SHA-256) for an intel dir")
    p.add_argument("dir", default="intel", nargs="?")
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("schema", help="print the alert JSON schema")
    p.set_defaults(func=cmd_schema)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
