"""Flow ingestion for NetFlow v9 / IPFIX / sFlow via goflow2 JSON.

Rather than re-implement each template-based protocol, we consume the newline-delimited JSON that
`goflow2` emits — it already decodes NetFlow v5/v9, IPFIX and sFlow into one normalised record.
This is the documented ingestion path for every flow-export format beyond the built-in v5 collector:

    goflow2 -transport.file /dev/stdout -format json | enclave flow-json --stream -

Field names are matched case-insensitively across goflow2 versions (PascalCase and snake_case).
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, BinaryIO

import dpkt

from enclave.core.constants import BUS_MAX_EVENTS
from enclave.core.logging import get_logger
from enclave.ingest.community_id import community_id
from enclave.schema.events import Event, FlowRecord, InputMode

log = get_logger(__name__)

_STDIN = "-"
_NS_PER_S = 1e9


def _get(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in record:
            return record[key]
    return default


def flow_from_json(record: dict[str, Any]) -> FlowRecord | None:
    """Map one goflow2 JSON record to a FlowRecord, or None if it lacks the essentials."""
    src_ip = _get(record, "SrcAddr", "src_addr")
    dst_ip = _get(record, "DstAddr", "dst_addr")
    if not src_ip or not dst_ip:
        return None
    proto = int(_get(record, "Proto", "proto", default=0))
    sport = int(_get(record, "SrcPort", "src_port", default=0))
    dport = int(_get(record, "DstPort", "dst_port", default=0))
    flags = int(_get(record, "TcpFlags", "tcp_flags", default=0))
    start_ns = _get(record, "TimeFlowStartNs", "time_flow_start_ns")
    end_ns = _get(record, "TimeFlowEndNs", "time_flow_end_ns")
    first_ts = float(start_ns) / _NS_PER_S if start_ns is not None \
        else float(_get(record, "TimeFlowStart", "time_flow_start", default=0))
    last_ts = float(end_ns) / _NS_PER_S if end_ns is not None \
        else float(_get(record, "TimeFlowEnd", "time_flow_end", default=first_ts))
    syn = bool(flags & dpkt.tcp.TH_SYN)
    return FlowRecord(
        flow_id=community_id(str(src_ip), str(dst_ip), sport, dport, proto),
        src_ip=str(src_ip), dst_ip=str(dst_ip), src_port=sport, dst_port=dport, proto=proto,
        first_ts=first_ts, last_ts=max(last_ts, first_ts),
        bytes_fwd=int(_get(record, "Bytes", "bytes", default=0)), bytes_bwd=0,
        pkts_fwd=int(_get(record, "Packets", "packets", default=0)), pkts_bwd=0,
        syn_seen=syn, synack_seen=syn and bool(flags & dpkt.tcp.TH_ACK),
        rst_seen=bool(flags & dpkt.tcp.TH_RST),
        export_index=0, is_final=True, mode=InputMode.FLOW,
    )


class JsonFlowSource:
    """Reads newline-delimited goflow2 JSON from stdin ('-') or a file/FIFO."""

    mode = InputMode.FLOW
    live = True

    def __init__(self, spec: str = _STDIN) -> None:
        self.spec = spec
        self.records = 0
        self.errors = 0
        self.dropped = 0

    @property
    def source_ref(self) -> str:
        return f"goflow2-json:{self.spec}"

    def _open(self) -> BinaryIO:
        if self.spec == _STDIN:
            return sys.stdin.buffer
        path = Path(self.spec)
        if not path.exists():
            raise FileNotFoundError(f"flow-json source not found: {path}")
        return path.open("rb")

    def _read_into(self, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue[Any],
                   sentinel: object) -> None:
        def offer(item: object) -> None:
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                self.dropped += 1

        try:
            stream = self._open()
            for raw in stream:
                line = raw.strip()
                if not line:
                    continue
                try:
                    flow = flow_from_json(json.loads(line))
                except (ValueError, TypeError):
                    self.errors += 1
                    continue
                if flow is not None:
                    loop.call_soon_threadsafe(offer, flow)
        except OSError as exc:
            log.warning("flow-json stream ended", extra={"error": str(exc)})
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, sentinel)

    async def events(self) -> AsyncIterator[Event]:
        log.info("flow-json ingestion started", extra={"source": self.source_ref})
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[Any] = asyncio.Queue(maxsize=BUS_MAX_EVENTS)
        sentinel = object()
        reader = loop.run_in_executor(None, self._read_into, loop, queue, sentinel)
        try:
            while True:
                item = await queue.get()
                if item is sentinel:
                    break
                self.records += 1
                yield item
        finally:
            await reader
        log.info("flow-json ingestion stopped", extra={"records": self.records,
                                                       "errors": self.errors, "dropped": self.dropped})
