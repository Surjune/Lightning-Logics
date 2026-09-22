"""Live packet capture: consumes a streaming pcap from stdin, a FIFO, or a file being appended.

The real diode feed is a live one-way copy of traffic. Rather than embed a raw-socket sniffer (which
is platform-specific and needs privileges), this source consumes a **streaming pcap**, so the capture
is done by the OS tool that is best at it and we keep our single, tested decode path:

    tcpdump -i eth1 -U -w - | enclave sniff --serve          # Linux/macOS
    dumpcap -i 5 -w - | enclave sniff --serve                # Windows (Npcap/Wireshark)

The sensor interface has no IP and no route out, so this stays strictly read-only. The blocking read
runs on a worker thread and feeds an asyncio queue; when the queue is full the source drops and counts,
exactly as a live sensor must under load.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, BinaryIO

import dpkt

from enclave.core.constants import BUS_MAX_EVENTS
from enclave.core.logging import get_logger
from enclave.ingest.flowmeter import FlowMeter
from enclave.ingest.pcap_source import decode_packet
from enclave.schema.events import Event, InputMode

log = get_logger(__name__)

_STDIN = "-"


class LiveSource:
    """A read-only live source. `spec` is '-' for stdin, or a path to a FIFO/streaming pcap."""

    mode = InputMode.PCAP
    live = True  # drop-and-count under load, never block the capture

    def __init__(self, spec: str = _STDIN) -> None:
        self.spec = spec
        self.meter = FlowMeter()
        self.packets = 0
        self.skipped = 0
        self.dropped = 0

    @property
    def source_ref(self) -> str:
        return f"live:{self.spec}"

    def _open(self) -> BinaryIO:
        if self.spec == _STDIN:
            return sys.stdin.buffer
        path = Path(self.spec)
        if not path.exists():
            raise FileNotFoundError(f"live source not found: {path}")
        return path.open("rb")

    def _read_into(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue[Any],
                   sentinel: object) -> None:
        """Blocking reader, run on a worker thread; hands packets to the loop, drops when full."""
        def offer(item: object) -> None:
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                self.dropped += 1

        try:
            reader = dpkt.pcap.Reader(self._open())
            datalink = reader.datalink()
            for ts, buf in reader:
                meta = decode_packet(ts, buf, datalink)
                if meta is None:
                    self.skipped += 1
                    continue
                loop.call_soon_threadsafe(offer, meta)
        except (dpkt.UnpackError, ValueError, OSError) as exc:
            log.warning("live capture ended", extra={"error": str(exc)})
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, sentinel)

    async def events(self) -> AsyncIterator[Event]:
        log.info("live capture started", extra={"source": self.source_ref})
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=BUS_MAX_EVENTS)
        sentinel = object()
        reader = loop.run_in_executor(None, self._read_into, loop, queue, sentinel)
        try:
            while True:
                meta = await queue.get()
                if meta is sentinel:
                    break
                self.packets += 1
                for event in self.meter.observe(meta):
                    yield event
        finally:
            await reader
        for event in self.meter.flush():
            yield event
        log.info("live capture stopped", extra={"packets": self.packets, "skipped": self.skipped,
                                                "dropped": self.dropped})
