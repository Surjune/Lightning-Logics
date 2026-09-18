"""Packets -> bidirectional flow records, plus DNS and TLS metadata events.

Flows are exported incrementally (active timeout) so detection never waits for a
conversation to end, and closed early when they never got a reply.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

import dpkt

from enclave.core.constants import (
    FLOW_ACTIVE_TIMEOUT_S,
    FLOW_IDLE_TIMEOUT_S,
    FLOW_SWEEP_INTERVAL_S,
    FLOW_TABLE_MAX,
    FLOW_UNANSWERED_IDLE_TIMEOUT_S,
    PORT_DNS,
    PROTO_TCP,
    PROTO_UDP,
    SPLT_LENGTH,
)
from enclave.core.exceptions import ParseError
from enclave.core.logging import get_logger
from enclave.ingest.community_id import community_id
from enclave.ingest.parsers.dns import parse_dns
from enclave.ingest.parsers.tls import ja3, ja4, looks_like_client_hello, parse_client_hello
from enclave.schema.events import DnsEvent, Event, FlowRecord, InputMode, TlsEvent

log = get_logger(__name__)

FlowKey = tuple[int, str, int, str, int]


@dataclass(slots=True)
class _FlowState:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    first_ts: float
    last_ts: float
    last_export_ts: float
    bytes_fwd: int = 0
    bytes_bwd: int = 0
    pkts_fwd: int = 0
    pkts_bwd: int = 0
    total_pkts_bwd: int = 0
    syn_seen: bool = False
    synack_seen: bool = False
    rst_seen: bool = False
    fin_fwd: bool = False
    fin_bwd: bool = False
    min_ttl: int = 255
    max_ttl: int = 0
    export_index: int = 0
    client_payload_seen: bool = False
    splt: list[int] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class PacketMeta:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    ip_len: int
    ttl: int
    tcp_flags: int
    payload: bytes


class FlowMeter:
    def __init__(self) -> None:
        self._flows: OrderedDict[FlowKey, _FlowState] = OrderedDict()
        self._last_sweep = 0.0
        self.parse_errors = 0
        self.forced_exports = 0

    def __len__(self) -> int:
        return len(self._flows)

    @staticmethod
    def _key(p: PacketMeta) -> FlowKey:
        a = (p.src_ip, p.src_port)
        b = (p.dst_ip, p.dst_port)
        lo, hi = (a, b) if a <= b else (b, a)
        return (p.proto, lo[0], lo[1], hi[0], hi[1])

    def observe(self, p: PacketMeta) -> list[Event]:
        out: list[Event] = []
        if p.ts - self._last_sweep >= FLOW_SWEEP_INTERVAL_S:
            out.extend(self.sweep(p.ts))
            self._last_sweep = p.ts

        key = self._key(p)
        st = self._flows.get(key)
        if st is None:
            st = _FlowState(
                flow_id=community_id(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.proto),
                src_ip=p.src_ip, dst_ip=p.dst_ip, src_port=p.src_port, dst_port=p.dst_port,
                proto=p.proto, first_ts=p.ts, last_ts=p.ts, last_export_ts=p.ts,
            )
            self._flows[key] = st
            if len(self._flows) > FLOW_TABLE_MAX:
                _, oldest = self._flows.popitem(last=False)
                out.append(self._export(oldest, final=True))
                self.forced_exports += 1
        else:
            self._flows.move_to_end(key)

        forward = p.src_ip == st.src_ip and p.src_port == st.src_port
        st.last_ts = p.ts
        st.min_ttl = min(st.min_ttl, p.ttl)
        st.max_ttl = max(st.max_ttl, p.ttl)
        if forward:
            st.bytes_fwd += p.ip_len
            st.pkts_fwd += 1
        else:
            st.bytes_bwd += p.ip_len
            st.pkts_bwd += 1
            st.total_pkts_bwd += 1

        if p.proto == PROTO_TCP:
            if p.tcp_flags & dpkt.tcp.TH_SYN:
                if p.tcp_flags & dpkt.tcp.TH_ACK:
                    if not forward:
                        st.synack_seen = True
                elif forward:
                    st.syn_seen = True
            if p.tcp_flags & dpkt.tcp.TH_RST:
                st.rst_seen = True
            if p.tcp_flags & dpkt.tcp.TH_FIN:
                if forward:
                    st.fin_fwd = True
                else:
                    st.fin_bwd = True

        if p.payload:
            if len(st.splt) < SPLT_LENGTH:
                st.splt.append(len(p.payload) if forward else -len(p.payload))
            out.extend(self._metadata(st, p, forward))

        if p.ts - st.last_export_ts >= FLOW_ACTIVE_TIMEOUT_S:
            out.append(self._export(st, final=False))
        return out

    def _metadata(self, st: _FlowState, p: PacketMeta, forward: bool) -> list[Event]:
        events: list[Event] = []
        if PORT_DNS in (p.src_port, p.dst_port) and p.proto == PROTO_UDP:
            try:
                msg = parse_dns(p.payload)
            except ParseError:
                self.parse_errors += 1
            else:
                client, resolver = (p.dst_ip, p.src_ip) if msg.is_response else (p.src_ip, p.dst_ip)
                events.append(DnsEvent(
                    ts=p.ts, flow_id=st.flow_id, client_ip=client, resolver_ip=resolver,
                    query=msg.query, qtype=msg.qtype, is_response=msg.is_response, rcode=msg.rcode,
                    answer_bytes=msg.size if msg.is_response else 0,
                ))
        elif p.proto == PROTO_TCP and forward and not st.client_payload_seen:
            st.client_payload_seen = True
            if looks_like_client_hello(p.payload):
                try:
                    hello = parse_client_hello(p.payload)
                except ParseError:
                    self.parse_errors += 1
                else:
                    events.append(TlsEvent(
                        ts=p.ts, flow_id=st.flow_id, client_ip=st.src_ip, server_ip=st.dst_ip,
                        server_port=st.dst_port, version=hello.version_label, sni=hello.sni,
                        ja3=ja3(hello), ja4=ja4(hello), alpn=hello.alpn[0] if hello.alpn else None,
                    ))
        return events

    def _export(self, st: _FlowState, final: bool) -> FlowRecord:
        rec = FlowRecord(
            flow_id=st.flow_id, src_ip=st.src_ip, dst_ip=st.dst_ip, src_port=st.src_port,
            dst_port=st.dst_port, proto=st.proto, first_ts=st.first_ts, last_ts=st.last_ts,
            bytes_fwd=st.bytes_fwd, bytes_bwd=st.bytes_bwd, pkts_fwd=st.pkts_fwd, pkts_bwd=st.pkts_bwd,
            syn_seen=st.syn_seen, synack_seen=st.synack_seen, rst_seen=st.rst_seen,
            export_index=st.export_index, is_final=final, min_ttl=st.min_ttl, max_ttl=st.max_ttl,
            splt=tuple(st.splt), mode=InputMode.PCAP,
        )
        st.bytes_fwd = st.bytes_bwd = st.pkts_fwd = st.pkts_bwd = 0
        st.export_index += 1
        st.last_export_ts = st.last_ts
        return rec

    def sweep(self, now: float) -> list[FlowRecord]:
        """Export flows that went idle. Oldest-first; stops at the first recently active flow."""
        out: list[FlowRecord] = []
        expired: list[FlowKey] = []
        for key, st in self._flows.items():
            idle = now - st.last_ts
            if idle < FLOW_UNANSWERED_IDLE_TIMEOUT_S:
                break
            closing = st.rst_seen or (st.fin_fwd and st.fin_bwd)
            short = st.total_pkts_bwd == 0 or closing
            timeout = FLOW_UNANSWERED_IDLE_TIMEOUT_S if short else FLOW_IDLE_TIMEOUT_S
            if idle >= timeout:
                expired.append(key)
        for key in expired:
            out.append(self._export(self._flows.pop(key), final=True))
        return out

    def flush(self) -> list[FlowRecord]:
        out = [self._export(st, final=True) for st in self._flows.values()]
        self._flows.clear()
        return out
