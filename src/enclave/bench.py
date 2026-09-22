"""Throughput benchmark for the detection engine (PS constraint d).

Feeds pre-generated flow records straight into the pipeline and times it, so the number reflects
the *detection* engine's ceiling in isolation from packet parsing (dpkt) and disk I/O — the parser
is a separate, replaceable front end. Reports sustained flows/s plus processing latency.
"""

from __future__ import annotations

import random
import tempfile
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from enclave.core.config import Settings
from enclave.core.constants import PROTO_TCP, TARGET_FLOWS_PER_S
from enclave.intel import Intel
from enclave.metrics import Metrics
from enclave.pipeline import Pipeline
from enclave.schema.events import Event, FlowRecord, InputMode
from enclave.sinks.store import AlertStore, HashChainLog

_SCAN_FRACTION = 0.03
_DDOS_FRACTION = 0.05  # cumulative: 0.03..0.05 of flows are a spoofed flood toward one target
_EVENT_TIME_STEP_S = 0.001  # ~1000 flows per second of event time, so windows roll realistically


class _StubSource:
    """A source that never streams — the benchmark drives `pipeline.process` directly."""

    mode = InputMode.PCAP
    live = False
    source_ref = "benchmark"

    def events(self) -> AsyncIterator[Event]:
        raise NotImplementedError


def _generate(n_flows: int, seed: int) -> list[FlowRecord]:
    rng = random.Random(seed)
    flows: list[FlowRecord] = []
    ts = 0.0
    for i in range(n_flows):
        ts += rng.uniform(0.0, _EVENT_TIME_STEP_S)
        roll = rng.random()
        src = f"10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        dst = f"203.0.113.{rng.randint(1, 254)}"
        if roll < _SCAN_FRACTION:  # one source fanning out across ports (scan)
            src, dport, fwd, bwd, synack = "10.0.9.9", rng.randint(1, 65535), 1, 0, False
        elif roll < _DDOS_FRACTION:  # many sources onto one target (flood)
            dst, dport, fwd, bwd, synack = "10.10.0.5", 443, 1, 0, False
        else:  # benign request/response
            dport = rng.choice([80, 443, 53, 22])
            fwd, bwd, synack = rng.randint(2, 20), rng.randint(2, 30), True
        flows.append(FlowRecord(
            flow_id=f"1:{i}", src_ip=src, dst_ip=dst, src_port=rng.randint(1024, 65535), dst_port=dport,
            proto=PROTO_TCP, first_ts=ts, last_ts=ts + rng.uniform(0.0, 0.5),
            bytes_fwd=fwd * rng.randint(60, 500), bytes_bwd=bwd * rng.randint(60, 900),
            pkts_fwd=fwd, pkts_bwd=bwd, syn_seen=True, synack_seen=synack, rst_seen=False,
            export_index=0, is_final=True, mode=InputMode.PCAP))
    return flows


def _worker(args: tuple[int, int]) -> dict[str, Any]:
    return run(args[0], args[1])


def run_parallel(n_flows: int, workers: int, seed: int = 20260917) -> dict[str, Any]:
    """Run `workers` independent pipelines in parallel (sharded by entity, as a real sensor would).

    Detectors keep per-entity state, so traffic can be partitioned across workers by target/source
    with no shared state. Aggregate throughput is the sum of the per-worker rates measured
    concurrently — the honest way the engine scales past a single core toward the target.
    """
    from concurrent.futures import ProcessPoolExecutor

    per_worker = n_flows // workers
    payload = [(per_worker, seed + w) for w in range(workers)]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_worker, payload))
    aggregate = sum(int(r["flows_per_s"]) for r in results)
    return {
        "workers": workers,
        "flows_per_worker": per_worker,
        "per_worker_flows_per_s": [r["flows_per_s"] for r in results],
        "aggregate_flows_per_s": aggregate,
        "target_flows_per_s": TARGET_FLOWS_PER_S,
        "met_target": aggregate >= TARGET_FLOWS_PER_S,
    }


def run(n_flows: int, seed: int = 20260917) -> dict[str, Any]:
    settings = Settings()
    intel = Intel()
    flows = _generate(n_flows, seed)  # pre-generated so generation cost is excluded from timing
    with tempfile.TemporaryDirectory() as tmp:
        store = AlertStore(HashChainLog(Path(tmp) / "alerts.jsonl"), "benchmark")
        metrics = Metrics()
        pipeline = Pipeline(settings, _StubSource(), store, metrics, intel)
        start = time.perf_counter()
        for flow in flows:
            pipeline.process(flow, time.perf_counter())
        pipeline.finish()
        elapsed = time.perf_counter() - start
    per_s = round(n_flows / elapsed) if elapsed else 0
    snap = metrics.snapshot()
    return {
        "flows": n_flows,
        "elapsed_s": round(elapsed, 3),
        "flows_per_s": per_s,
        "target_flows_per_s": TARGET_FLOWS_PER_S,
        "met_target": per_s >= TARGET_FLOWS_PER_S,
        "alerts_raised": sum(metrics.alerts_by_class.values()),
        "latency_ms": snap["latency_ms"],
    }
