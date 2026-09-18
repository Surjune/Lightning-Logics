"""Community ID v1 flow hashing (corelight/community-id-spec).

The same flow gets the same ID in Zeek, Suricata and this pipeline, so analysts can
pivot between tools.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct
from functools import lru_cache

from enclave.core.constants import COMMUNITY_ID_SEED, PROTO_TCP, PROTO_UDP

_PORTED = {PROTO_TCP, PROTO_UDP}


@lru_cache(maxsize=262_144)
def community_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> str:
    src = ipaddress.ip_address(src_ip).packed
    dst = ipaddress.ip_address(dst_ip).packed
    if proto not in _PORTED:
        src_port = dst_port = 0
    if (src, src_port) > (dst, dst_port):
        src, dst = dst, src
        src_port, dst_port = dst_port, src_port
    blob = (
        struct.pack("!H", COMMUNITY_ID_SEED)
        + src
        + dst
        + struct.pack("!BB", proto, 0)
        + struct.pack("!HH", src_port, dst_port)
    )
    return "1:" + base64.b64encode(hashlib.sha1(blob).digest()).decode("ascii")
