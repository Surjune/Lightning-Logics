"""Parsers, fingerprints and the Community ID."""

from __future__ import annotations

import struct

import dpkt
import pytest

from enclave.core.exceptions import ParseError
from enclave.ingest.community_id import community_id
from enclave.ingest.parsers.dns import parse_dns
from enclave.ingest.parsers.tls import is_grease, ja3, ja4, looks_like_client_hello, parse_client_hello


def _client_hello(sni: str | None = "example.test", extra_cipher: bool = False) -> bytes:
    ciphers = [0x1301, 0xC02F] + ([0x00FF] if extra_cipher else [])
    body = bytearray(struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00")
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"
    exts = bytearray()
    if sni is not None:
        name = sni.encode()
        server = struct.pack("!BH", 0, len(name)) + name
        exts += struct.pack("!HH", 0x0000, len(server) + 2) + struct.pack("!H", len(server)) + server
    exts += struct.pack("!HH", 0x000A, 2) + b"\x00\x00"
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + bytes(body)
    return struct.pack("!BHH", 22, 0x0301, len(handshake)) + handshake


def test_community_id_is_symmetric() -> None:
    a = community_id("10.0.0.1", "10.0.0.2", 1234, 443, 6)
    b = community_id("10.0.0.2", "10.0.0.1", 443, 1234, 6)
    assert a == b == a.split()[0] or a == b
    assert a.startswith("1:")


def test_grease_detection() -> None:
    assert is_grease(0x0A0A)
    assert is_grease(0x1A1A)
    assert not is_grease(0x1301)


def test_client_hello_and_fingerprints() -> None:
    payload = _client_hello()
    assert looks_like_client_hello(payload)
    hello = parse_client_hello(payload)
    assert hello.sni == "example.test"
    assert len(ja3(hello)) == 32                     # md5 hex
    j4 = ja4(hello)
    assert j4.startswith("t") and j4.count("_") == 2
    assert "d" in j4[:4]                              # SNI present -> 'd'


def test_ja4_changes_with_ciphers() -> None:
    assert ja4(parse_client_hello(_client_hello())) != ja4(parse_client_hello(_client_hello(extra_cipher=True)))


def test_dns_query_and_nxdomain() -> None:
    query = dpkt.dns.DNS(id=1, qd=[dpkt.dns.DNS.Q(name="bad.test", type=16, cls=1)])
    parsed = parse_dns(bytes(query))
    assert parsed.query == "bad.test" and parsed.qtype == 16 and not parsed.is_response
    query.qr = dpkt.dns.DNS_R
    query.rcode = dpkt.dns.DNS_RCODE_NXDOMAIN
    resp = parse_dns(bytes(query))
    assert resp.is_response and resp.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN


def test_dns_rejects_garbage() -> None:
    with pytest.raises(ParseError):
        parse_dns(b"\xff\xff")
