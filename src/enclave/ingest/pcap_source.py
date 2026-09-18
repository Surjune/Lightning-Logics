"""Replays a pcap/pcapng file as a live stream at a chosen speed (read-only)."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any, BinaryIO

import dpkt

from enclave.core.constants import PROTO_TCP, PROTO_UDP
from enclave.core.exceptions import IngestError, UnsupportedCaptureError
from enclave.core.logging import get_logger
from enclave.ingest.flowmeter import FlowMeter, PacketMeta
from enclave.schema.events import Event, InputMode

log = get_logger(__name__)

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
DLT_RAW_VALUES = frozenset({12, 14, 101})
DLT_LINUX_SLL = 113
YIELD_EVERY_PACKETS = 2_000
MIN_SLEEP_S = 0.005
HASH_CHUNK_BYTES = 1 << 20


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _open_reader(fh: BinaryIO) -> Any:
    magic = fh.read(4)
    fh.seek(0)
    try:
        return dpkt.pcapng.Reader(fh) if magic == PCAPNG_MAGIC else dpkt.pcap.Reader(fh)
    except (ValueError, dpkt.UnpackError) as exc:
        raise UnsupportedCaptureError(f"Not a readable pcap/pcapng file: {exc}") from exc


def _ip_layer(buf: bytes, datalink: int) -> Any:
    if datalink == dpkt.pcap.DLT_EN10MB:
        frame = dpkt.ethernet.Ethernet(buf)
        return frame.data
    if datalink == DLT_LINUX_SLL:
        return dpkt.sll.SLL(buf).data
    if datalink in DLT_RAW_VALUES:
        version = buf[0] >> 4 if buf else 0
        return dpkt.ip6.IP6(buf) if version == 6 else dpkt.ip.IP(buf)
    raise UnsupportedCaptureError(f"Unsupported link type {datalink}")


def decode_packet(ts: float, buf: bytes, datalink: int) -> PacketMeta | None:
    """Header fields only. Returns None for non-IP or unparseable frames."""
    try:
        ip = _ip_layer(buf, datalink)
    except (dpkt.UnpackError, IndexError, ValueError):
        return None
    if isinstance(ip, dpkt.ip.IP):
        src, dst = socket.inet_ntop(socket.AF_INET, ip.src), socket.inet_ntop(socket.AF_INET, ip.dst)
        proto, ip_len, ttl = ip.p, ip.len, ip.ttl
    elif isinstance(ip, dpkt.ip6.IP6):
        src, dst = socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst)
        proto, ip_len, ttl = ip.nxt, ip.plen + len(ip.pack_hdr()), ip.hlim
    else:
        return None
    l4 = ip.data
    sport = dport = flags = 0
    payload = b""
    if proto == PROTO_TCP and isinstance(l4, dpkt.tcp.TCP):
        sport, dport, flags, payload = l4.sport, l4.dport, l4.flags, bytes(l4.data)
    elif proto == PROTO_UDP and isinstance(l4, dpkt.udp.UDP):
        sport, dport, payload = l4.sport, l4.dport, bytes(l4.data)
    return PacketMeta(ts=float(ts), src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, proto=proto,
                      ip_len=ip_len, ttl=ttl, tcp_flags=flags, payload=payload)


class PcapSource:
    """`speed` = replay speed multiplier; 0 replays as fast as possible."""

    mode = InputMode.PCAP
    live = False

    def __init__(self, path: Path, speed: float = 1.0) -> None:
        if speed < 0:
            raise IngestError("speed must be >= 0")
        if not path.is_file():
            raise IngestError(f"Capture file not found: {path}")
        self.path = path
        self.speed = speed
        self.meter = FlowMeter()
        self.packets = 0
        self.skipped = 0
        self._sha256 = sha256_file(path)

    @property
    def source_ref(self) -> str:
        return f"pcap:{self.path.name}:sha256:{self._sha256}"

    def _packets(self, fh: BinaryIO) -> Iterator[PacketMeta]:
        reader = _open_reader(fh)
        datalink = reader.datalink()
        for ts, buf in reader:
            meta = decode_packet(ts, buf, datalink)
            if meta is None:
                self.skipped += 1
                continue
            yield meta

    async def events(self) -> AsyncIterator[Event]:
        log.info("replay started", extra={"source": self.source_ref, "speed": self.speed})
        first_ts: float | None = None
        wall_start = time.monotonic()
        last_ts = 0.0
        with self.path.open("rb") as fh:
            for meta in self._packets(fh):
                self.packets += 1
                last_ts = meta.ts
                if first_ts is None:
                    first_ts = meta.ts
                if self.speed > 0:
                    delay = (meta.ts - first_ts) / self.speed - (time.monotonic() - wall_start)
                    if delay > MIN_SLEEP_S:
                        await asyncio.sleep(delay)
                elif self.packets % YIELD_EVERY_PACKETS == 0:
                    await asyncio.sleep(0)
                for event in self.meter.observe(meta):
                    yield event
        for event in self.meter.sweep(last_ts + 1.0):
            yield event
        for event in self.meter.flush():
            yield event
        log.info("replay finished", extra={"packets": self.packets, "skipped": self.skipped,
                                           "parse_errors": self.meter.parse_errors})
