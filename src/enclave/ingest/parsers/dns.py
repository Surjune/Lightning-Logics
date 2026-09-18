"""Cleartext DNS (UDP/TCP 53) parsing. Encrypted DNS (DoH/DoT) is only seen as flows."""

from __future__ import annotations

from dataclasses import dataclass

import dpkt

from enclave.core.exceptions import ParseError


@dataclass(frozen=True, slots=True)
class DnsMessage:
    query: str
    qtype: int
    is_response: bool
    rcode: int | None
    size: int


def parse_dns(payload: bytes) -> DnsMessage:
    try:
        msg = dpkt.dns.DNS(payload)
    except (dpkt.UnpackError, IndexError, ValueError) as exc:
        raise ParseError(f"DNS message malformed: {exc}") from exc
    if not msg.qd:
        raise ParseError("DNS message has no question")
    question = msg.qd[0]
    is_response = msg.qr == dpkt.dns.DNS_R
    return DnsMessage(
        query=str(question.name).lower().rstrip("."),
        qtype=int(question.type),
        is_response=is_response,
        rcode=int(msg.rcode) if is_response else None,
        size=len(payload),
    )
