"""TLS ClientHello parsing and JA3 / JA4 client fingerprints.

Only the cleartext handshake is read. Nothing after the handshake is touched, and
QUIC Initial packets are never unprotected (that would be decryption).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

from enclave.core.exceptions import ParseError

# Wire-format identifiers (RFC 8446 / RFC 5246 / IANA TLS registries).
RECORD_HANDSHAKE = 22
HANDSHAKE_CLIENT_HELLO = 1
RECORD_HEADER_LEN = 5
HANDSHAKE_HEADER_LEN = 4
RANDOM_LEN = 32
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
SNI_HOST_NAME = 0
JA4_MAX_COUNT = 99
JA4_HASH_LEN = 12
JA4_EMPTY_HASH = "0" * JA4_HASH_LEN

_JA4_VERSIONS = {
    0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
    0xFEFF: "d1", 0xFEFD: "d2", 0xFEFC: "d3",
}


def is_grease(value: int) -> bool:
    """GREASE values (RFC 8701): 0x0a0a, 0x1a1a ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


@dataclass(slots=True)
class ClientHello:
    legacy_version: int
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    sni: str | None = None
    alpn: list[str] = field(default_factory=list)

    @property
    def version(self) -> int:
        real = [v for v in self.supported_versions if not is_grease(v)]
        return max(real) if real else self.legacy_version

    @property
    def version_label(self) -> str:
        return _JA4_VERSIONS.get(self.version, "00")


class _Reader:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes) -> None:
        self.buf = buf
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ParseError("TLS ClientHello truncated")
        chunk = self.buf[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        value: int = struct.unpack("!H", self.take(2))[0]
        return value

    def u24(self) -> int:
        b = self.take(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def remaining(self) -> int:
        return len(self.buf) - self.pos


def _u16_list(data: bytes) -> list[int]:
    return [v for (v,) in struct.iter_unpack("!H", data[: len(data) - len(data) % 2])]


def looks_like_client_hello(payload: bytes) -> bool:
    return (
        len(payload) > RECORD_HEADER_LEN
        and payload[0] == RECORD_HANDSHAKE
        and payload[RECORD_HEADER_LEN] == HANDSHAKE_CLIENT_HELLO
    )


def parse_client_hello(payload: bytes) -> ClientHello:
    if not looks_like_client_hello(payload):
        raise ParseError("not a TLS ClientHello")
    r = _Reader(payload)
    r.take(RECORD_HEADER_LEN)
    r.u8()   # handshake type
    r.u24()  # handshake length
    hello = ClientHello(legacy_version=r.u16())
    r.take(RANDOM_LEN)
    r.take(r.u8())                              # session id
    hello.ciphers = _u16_list(r.take(r.u16()))
    r.take(r.u8())                              # compression methods
    if r.remaining() < 2:
        return hello
    ext_reader = _Reader(r.take(r.u16()))
    while ext_reader.remaining() >= 4:
        ext_type = ext_reader.u16()
        data = ext_reader.take(ext_reader.u16())
        hello.extensions.append(ext_type)
        _parse_extension(hello, ext_type, data)
    return hello


def _parse_extension(hello: ClientHello, ext_type: int, data: bytes) -> None:
    if ext_type == EXT_SERVER_NAME and len(data) >= 5:
        er = _Reader(data)
        er.u16()
        if er.u8() == SNI_HOST_NAME:
            hello.sni = er.take(er.u16()).decode("ascii", errors="replace")
    elif ext_type == EXT_SUPPORTED_GROUPS and len(data) >= 2:
        hello.groups = _u16_list(data[2:])
    elif ext_type == EXT_EC_POINT_FORMATS and len(data) >= 1:
        hello.point_formats = list(data[1:1 + data[0]])
    elif ext_type == EXT_SIGNATURE_ALGORITHMS and len(data) >= 2:
        hello.sig_algs = _u16_list(data[2:])
    elif ext_type == EXT_SUPPORTED_VERSIONS and len(data) >= 1:
        hello.supported_versions = _u16_list(data[1:1 + data[0]])
    elif ext_type == EXT_ALPN and len(data) >= 2:
        er = _Reader(data[2:])
        while er.remaining() > 0:
            hello.alpn.append(er.take(er.u8()).decode("ascii", errors="replace"))


def ja3_string(hello: ClientHello) -> str:
    def join(values: list[int]) -> str:
        return "-".join(str(v) for v in values if not is_grease(v))

    return ",".join([
        str(hello.legacy_version),
        join(hello.ciphers),
        join(hello.extensions),
        join(hello.groups),
        "-".join(str(v) for v in hello.point_formats),
    ])


def ja3(hello: ClientHello) -> str:
    return hashlib.md5(ja3_string(hello).encode("ascii"), usedforsecurity=False).hexdigest()


def _hash12(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:JA4_HASH_LEN]


def _alpn_chars(hello: ClientHello) -> str:
    if not hello.alpn or not hello.alpn[0]:
        return "00"
    value = hello.alpn[0]
    first, last = value[0], value[-1]
    if first.isascii() and first.isalnum() and last.isascii() and last.isalnum():
        return first + last
    hexed = value.encode("utf-8").hex()
    return hexed[0] + hexed[-1]


def ja4(hello: ClientHello, transport: str = "t") -> str:
    ciphers = [c for c in hello.ciphers if not is_grease(c)]
    extensions = [e for e in hello.extensions if not is_grease(e)]
    part_a = (
        f"{transport}{hello.version_label}{'d' if hello.sni else 'i'}"
        f"{min(len(ciphers), JA4_MAX_COUNT):02d}{min(len(extensions), JA4_MAX_COUNT):02d}"
        f"{_alpn_chars(hello)}"
    )
    part_b = _hash12(",".join(sorted(f"{c:04x}" for c in ciphers))) if ciphers else JA4_EMPTY_HASH
    hashed_ext = sorted(f"{e:04x}" for e in extensions if e not in (EXT_SERVER_NAME, EXT_ALPN))
    if hashed_ext:
        text = ",".join(hashed_ext)
        sigs = [s for s in hello.sig_algs if not is_grease(s)]
        if sigs:
            text += "_" + ",".join(f"{s:04x}" for s in sigs)
        part_c = _hash12(text)
    else:
        part_c = JA4_EMPTY_HASH
    return f"{part_a}_{part_b}_{part_c}"
