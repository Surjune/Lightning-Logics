"""Read-only proof: with the egress guard installed, the enclave cannot connect out.

The guard is a process-wide monkeypatch that installs once and cannot be uninstalled, so it
runs in a subprocess to prove the behaviour without patching the sockets of the test process.
No real network is used: the guard raises before any packet leaves, and the loopback send goes
nowhere it can reach out from.
"""

from __future__ import annotations

import subprocess
import sys

_PROOF = r"""
import ipaddress, socket, sys
from enclave.egress_guard import install, blocked_attempts
from enclave.core.exceptions import EgressAttemptError

install([ipaddress.ip_network("10.0.0.0/8")])

# 1) TCP connect to a public address is refused before it leaves the host.
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
    print("FAIL: public connect was not blocked"); sys.exit(1)
except EgressAttemptError:
    pass

# 2) UDP sendto to a public address is likewise refused.
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("8.8.8.8", 53))
    print("FAIL: public sendto was not blocked"); sys.exit(1)
except EgressAttemptError:
    pass

# 3) Loopback stays permitted (the dashboard/collector must keep working).
try:
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))
except EgressAttemptError:
    print("FAIL: loopback was wrongly blocked"); sys.exit(1)

if blocked_attempts() != 2:
    print(f"FAIL: expected 2 blocked attempts, got {blocked_attempts()}"); sys.exit(1)

print("OK"); sys.exit(0)
"""


def test_outbound_connections_are_blocked() -> None:
    proc = subprocess.run(
        [sys.executable, "-c", _PROOF],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"egress proof failed: {proc.stdout}\n{proc.stderr}"
    assert "OK" in proc.stdout
