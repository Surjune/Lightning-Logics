"""Throughput, latency and coverage counters exposed on the dashboard."""

from __future__ import annotations

import random
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from enclave.core.constants import (
    LATENCY_BUDGET_P95_S,
    LATENCY_RESERVOIR_SIZE,
    METRICS_EWMA_ALPHA,
    TARGET_FLOWS_PER_S,
)
from enclave.detectors.registry import DetectorStatus

MS_PER_S = 1000.0
P50 = 0.5
P95 = 0.95
RESERVOIR_SEED = 7


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


@dataclass
class Metrics:
    source_ref: str = ""
    input_mode: str = ""
    started_wall: float = field(default_factory=time.time)
    events: Counter[str] = field(default_factory=Counter)
    alerts_by_class: Counter[str] = field(default_factory=Counter)
    alerts_by_severity: Counter[str] = field(default_factory=Counter)
    detectors: list[DetectorStatus] = field(default_factory=list)
    dropped: int = 0
    egress_blocked: int = 0
    watermark: float = 0.0
    finished: bool = False
    flows_per_s: float = 0.0
    _second: int = 0
    _flows_this_second: int = 0
    _latencies_ms: list[float] = field(default_factory=list)
    _latency_seen: int = 0
    _rng: random.Random = field(default_factory=lambda: random.Random(RESERVOIR_SEED))

    def count_event(self, kind: str) -> None:
        self.events[kind] += 1
        if kind != "flow":
            return
        now = int(time.monotonic())
        if now != self._second:
            elapsed = max(now - self._second, 1)
            instant = self._flows_this_second / elapsed if self._second else 0.0
            self.flows_per_s += METRICS_EWMA_ALPHA * (instant - self.flows_per_s)
            self._second = now
            self._flows_this_second = 0
        self._flows_this_second += 1

    def observe_latency(self, ms: float) -> None:
        """Reservoir sample so percentiles stay cheap on long runs."""
        self._latency_seen += 1
        if len(self._latencies_ms) < LATENCY_RESERVOIR_SIZE:
            self._latencies_ms.append(ms)
            return
        slot = self._rng.randrange(self._latency_seen)
        if slot < LATENCY_RESERVOIR_SIZE:
            self._latencies_ms[slot] = ms

    def snapshot(self) -> dict[str, Any]:
        p95_ms = percentile(self._latencies_ms, P95)
        return {
            "source": self.source_ref,
            "input_mode": self.input_mode,
            "uptime_s": round(time.time() - self.started_wall, 1),
            "finished": self.finished,
            "events": dict(self.events),
            "flows_per_s": round(self.flows_per_s, 1),
            "target_flows_per_s": TARGET_FLOWS_PER_S,
            "latency_ms": {"p50": round(percentile(self._latencies_ms, P50), 3), "p95": round(p95_ms, 3),
                           "samples": self._latency_seen},
            "latency_budget_ms": LATENCY_BUDGET_P95_S * MS_PER_S,
            "within_budget": p95_ms <= LATENCY_BUDGET_P95_S * MS_PER_S,
            "dropped": self.dropped,
            "egress_blocked": self.egress_blocked,
            "event_time": self.watermark,
            "alerts_by_class": dict(self.alerts_by_class),
            "alerts_by_severity": dict(self.alerts_by_severity),
            "detectors": [d.__dict__ for d in self.detectors],
        }
