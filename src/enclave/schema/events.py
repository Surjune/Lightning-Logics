"""Normalised events that every input format is converted into.

Hot-path records are slotted dataclasses (validated by construction in the ingest layer);
the output alert schema in `schema.alert` uses Pydantic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class InputMode(StrEnum):
    PCAP = "pcap"          # full packets: every detector can run
    FLOW = "flow"          # NetFlow / IPFIX / sFlow: no DNS names, no TLS handshakes


class EventKind(StrEnum):
    FLOW = "flow"
    DNS = "dns"
    TLS = "tls"


@dataclass(frozen=True, slots=True)
class FlowRecord:
    """One export of a (possibly still running) conversation.

    Byte and packet counters are deltas since the previous export of the same flow;
    `export_index` is 0 on the first export. "fwd" is the direction of the first packet.
    """

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int
    first_ts: float
    last_ts: float
    bytes_fwd: int
    bytes_bwd: int
    pkts_fwd: int
    pkts_bwd: int
    syn_seen: bool
    synack_seen: bool
    rst_seen: bool
    export_index: int
    is_final: bool
    min_ttl: int = 0
    max_ttl: int = 0
    splt: tuple[int, ...] = field(default_factory=tuple)
    mode: InputMode = InputMode.PCAP
    kind: EventKind = EventKind.FLOW

    @property
    def ts(self) -> float:
        return self.last_ts

    @property
    def handshake_failed(self) -> bool:
        """Initiator sent SYN and the responder never answered with SYN-ACK."""
        return self.syn_seen and not self.synack_seen

    @property
    def answered(self) -> bool:
        return self.pkts_bwd > 0 and not (self.rst_seen and not self.synack_seen)


@dataclass(frozen=True, slots=True)
class DnsEvent:
    ts: float
    flow_id: str
    client_ip: str
    resolver_ip: str
    query: str
    qtype: int
    is_response: bool
    rcode: int | None = None
    answer_bytes: int = 0
    kind: EventKind = EventKind.DNS


@dataclass(frozen=True, slots=True)
class TlsEvent:
    ts: float
    flow_id: str
    client_ip: str
    server_ip: str
    server_port: int
    version: str
    sni: str | None
    ja3: str
    ja4: str
    alpn: str | None = None
    kind: EventKind = EventKind.TLS


Event = FlowRecord | DnsEvent | TlsEvent
