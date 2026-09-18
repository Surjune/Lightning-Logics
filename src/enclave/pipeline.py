"""Wires source -> bounded bus -> detectors -> fusion -> store, incrementally."""

from __future__ import annotations

import asyncio
import time

from enclave.core.config import NetworkContext, Settings
from enclave.core.constants import (
    BUS_MAX_EVENTS,
    DDOS_WINDOW_S,
    DNS_WINDOW_S,
    EXFIL_WINDOW_S,
    PIPELINE_TICK_S,
    SCAN_WINDOW_S,
)
from enclave.core.logging import get_logger
from enclave.detectors.base import DetectorContext
from enclave.detectors.registry import build_detectors
from enclave.fusion.engine import AlertUpdate, FusionEngine
from enclave.ingest.base import Source
from enclave.intel import Intel
from enclave.metrics import Metrics
from enclave.schema.alert import Detection
from enclave.schema.events import Event
from enclave.sinks.store import AlertStore

log = get_logger(__name__)

MS_PER_S = 1000.0
END_OF_INPUT_S = max(DDOS_WINDOW_S, DNS_WINDOW_S, EXFIL_WINDOW_S, SCAN_WINDOW_S)

BusItem = tuple[float, Event] | None


class Pipeline:
    def __init__(self, settings: Settings, source: Source, store: AlertStore, metrics: Metrics,
                 intel: Intel) -> None:
        self.source = source
        self.store = store
        self.metrics = metrics
        network = NetworkContext(settings)
        self.detectors, statuses = build_detectors(source.mode, DetectorContext(network, intel))
        self.fusion = FusionEngine(network, settings.sensor_id, source.mode.value)
        metrics.detectors = statuses
        metrics.source_ref = source.source_ref
        metrics.input_mode = source.mode.value
        self._next_tick: float | None = None

    def process(self, event: Event, ingest_wall: float) -> list[AlertUpdate]:
        ts = event.ts
        detections: list[Detection] = []
        if self._next_tick is None:
            self._next_tick = ts + PIPELINE_TICK_S
        elif ts >= self._next_tick:
            for det in self.detectors:
                detections.extend(det.flush(ts))
            self._next_tick = ts + PIPELINE_TICK_S
        self.metrics.watermark = max(self.metrics.watermark, ts)
        self.metrics.count_event(event.kind.value)
        for det in self.detectors:
            if event.kind in det.consumes:
                detections.extend(det.observe(event))
        return self._fuse(detections, ingest_wall)

    def finish(self) -> list[AlertUpdate]:
        """End of input: close every open window as if time had moved past it."""
        now = self.metrics.watermark + END_OF_INPUT_S
        detections: list[Detection] = []
        for det in self.detectors:
            detections.extend(det.flush(now))
        updates = self._fuse(detections, time.perf_counter())
        self.metrics.finished = True
        return updates

    def _fuse(self, detections: list[Detection], ingest_wall: float) -> list[AlertUpdate]:
        updates: list[AlertUpdate] = []
        for det in detections:
            latency_ms = (time.perf_counter() - ingest_wall) * MS_PER_S
            for update in self.fusion.ingest(det, latency_ms):
                self.store.publish(update.alert, update.is_new)
                if update.is_new:
                    self.metrics.alerts_by_class[update.alert.threat_class.value] += 1
                    self.metrics.alerts_by_severity[update.alert.severity.value] += 1
                    self.metrics.observe_latency(latency_ms)
                updates.append(update)
        return updates

    async def run(self) -> None:
        bus: asyncio.Queue[BusItem] = asyncio.Queue(maxsize=BUS_MAX_EVENTS)
        live = self.source.live

        async def produce() -> None:
            try:
                async for event in self.source.events():
                    item = (time.perf_counter(), event)
                    if live:
                        try:
                            bus.put_nowait(item)
                        except asyncio.QueueFull:
                            self.metrics.dropped += 1
                    else:
                        await bus.put(item)
            finally:
                await bus.put(None)

        async def consume() -> None:
            while (item := await bus.get()) is not None:
                self.process(item[1], item[0])
            self.finish()

        log.info("pipeline started", extra={"source": self.source.source_ref,
                                            "detectors": [d.name for d in self.detectors]})
        await asyncio.gather(produce(), consume())
        log.info("pipeline finished", extra={"alerts": sum(self.metrics.alerts_by_class.values()),
                                             "merged": self.fusion.merged,
                                             "allowlisted": self.fusion.allowlisted})
