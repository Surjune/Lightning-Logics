"""NetFlow v5 collector (listen-only UDP). Records become flow events in FLOW mode.

NetFlow records are unidirectional, so `bytes_bwd` is 0 and host-level detectors
aggregate both directions themselves.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from collections.abc import AsyncIterator

import dpkt

from enclave.core.constants import BUS_MAX_EVENTS
from enclave.core.exceptions import ParseError
from enclave.core.logging import get_logger
from enclave.ingest.community_id import community_id
from enclave.schema.events import Event, FlowRecord, InputMode

log = get_logger(__name__)

NETFLOW_V5 = 5
HEADER = struct.Struct("!HHIIIIBBH")
RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
MS_PER_S = 1000.0
NS_PER_S = 1e9


def parse_netflow_v5(datagram: bytes) -> list[FlowRecord]:
    if len(datagram) < HEADER.size:
        raise ParseError("NetFlow datagram shorter than header")
    version, count, uptime_ms, unix_secs, unix_nsecs, _seq, _etype, _eid, _sampling = (
        HEADER.unpack_from(datagram)
    )
    if version != NETFLOW_V5:
        raise ParseError(f"Unsupported NetFlow version {version}")
    if len(datagram) < HEADER.size + count * RECORD.size:
        raise ParseError("NetFlow datagram truncated")
    export_ts = unix_secs + unix_nsecs / NS_PER_S
    records: list[FlowRecord] = []
    for i in range(count):
        (src, dst, _nh, _in, _out, pkts, octets, first, last, sport, dport, _p1, flags, proto,
         _tos, _sas, _das, _sm, _dm, _p2) = RECORD.unpack_from(datagram, HEADER.size + i * RECORD.size)
        src_ip, dst_ip = socket.inet_ntoa(src), socket.inet_ntoa(dst)
        syn = bool(flags & dpkt.tcp.TH_SYN)
        records.append(FlowRecord(
            flow_id=community_id(src_ip, dst_ip, sport, dport, proto),
            src_ip=src_ip, dst_ip=dst_ip, src_port=sport, dst_port=dport, proto=proto,
            first_ts=export_ts - (uptime_ms - first) / MS_PER_S,
            last_ts=export_ts - (uptime_ms - last) / MS_PER_S,
            bytes_fwd=octets, bytes_bwd=0, pkts_fwd=pkts, pkts_bwd=0,
            # The initiator only sends ACK after receiving SYN-ACK.
            syn_seen=syn, synack_seen=syn and bool(flags & dpkt.tcp.TH_ACK),
            rst_seen=bool(flags & dpkt.tcp.TH_RST),
            export_index=0, is_final=True, mode=InputMode.FLOW,
        ))
    return records


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[bytes], stats: dict[str, int]) -> None:
        self.queue = queue
        self.stats = stats

    def datagram_received(self, data: bytes, addr: tuple[str | bytes, int]) -> None:
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            self.stats["dropped"] += 1


class NetflowSource:
    mode = InputMode.FLOW
    live = True

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.stats = {"datagrams": 0, "dropped": 0, "errors": 0}

    @property
    def source_ref(self) -> str:
        return f"netflow5:{self.host}:{self.port}"

    async def events(self) -> AsyncIterator[Event]:
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=BUS_MAX_EVENTS)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _Protocol(queue, self.stats), local_addr=(self.host, self.port)
        )
        log.info("netflow collector listening", extra={"source": self.source_ref})
        try:
            while True:
                datagram = await queue.get()
                self.stats["datagrams"] += 1
                try:
                    records = parse_netflow_v5(datagram)
                except ParseError as exc:
                    self.stats["errors"] += 1
                    log.warning("netflow datagram rejected", extra={"reason": exc.message})
                    continue
                for rec in records:
                    yield rec
        finally:
            transport.close()
