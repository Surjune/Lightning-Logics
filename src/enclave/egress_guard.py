"""Process-level enforcement of the read-only rule.

Once installed, any attempt by this process to connect or send to an address outside
the allowed networks raises `EgressAttemptError`. Listening sockets (the dashboard, the
NetFlow collector) are unaffected because they accept rather than connect.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from typing import Any

from enclave.core.exceptions import EgressAttemptError
from enclave.core.logging import get_logger

log = get_logger(__name__)

LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
LOOPBACK_V6 = ipaddress.ip_network("::1/128")

_state: dict[str, Any] = {"installed": False, "blocked": 0}


def blocked_attempts() -> int:
    return int(_state["blocked"])


def _host_of(address: Any) -> str | None:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return None


def install(allowed: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] = ()) -> None:
    if _state["installed"]:
        return
    networks = [LOOPBACK_V4, LOOPBACK_V6, *allowed]

    def permitted(address: Any) -> bool:
        host = _host_of(address)
        if host is None:  # AF_UNIX and friends stay local by definition
            return True
        try:
            ip = ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            return False  # hostnames would need a DNS lookup, which is itself egress
        return any(ip.version == net.version and ip in net for net in networks)

    def guard(original: Callable[..., Any], address_index: int) -> Callable[..., Any]:
        def wrapper(self: socket.socket, *args: Any) -> Any:
            address = args[address_index] if len(args) > address_index else None
            if not permitted(address):
                _state["blocked"] += 1
                log.error("egress blocked", extra={"destination": str(address)})
                raise EgressAttemptError(f"Outbound connection to {address} is not permitted in the enclave")
            return original(self, *args)
        return wrapper

    socket.socket.connect = guard(socket.socket.connect, 0)  # type: ignore[method-assign]
    socket.socket.connect_ex = guard(socket.socket.connect_ex, 0)  # type: ignore[method-assign]
    socket.socket.sendto = guard(socket.socket.sendto, -1)  # type: ignore[method-assign]
    _state["installed"] = True
    log.info("egress guard installed", extra={"allowed": [str(n) for n in networks]})
