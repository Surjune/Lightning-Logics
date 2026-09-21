"""Which detectors run for which input mode, and why the others do not."""

from __future__ import annotations

from dataclasses import dataclass

from enclave.detectors.base import Detector, DetectorContext
from enclave.detectors.beacon import BeaconDetector
from enclave.detectors.ddos import DdosDetector
from enclave.detectors.dns import DnsDetector
from enclave.detectors.exfil import ExfilDetector
from enclave.detectors.ml_flow import MlFlowDetector
from enclave.detectors.scan import ScanDetector
from enclave.detectors.tls import TlsDetector
from enclave.schema.events import EventKind, InputMode

ALL_DETECTORS: tuple[type[Detector], ...] = (
    DdosDetector, BeaconDetector, DnsDetector, TlsDetector, ScanDetector, ExfilDetector,
    MlFlowDetector,
)

KINDS_BY_MODE: dict[InputMode, frozenset[EventKind]] = {
    InputMode.PCAP: frozenset({EventKind.FLOW, EventKind.DNS, EventKind.TLS}),
    InputMode.FLOW: frozenset({EventKind.FLOW}),
}


@dataclass(frozen=True)
class DetectorStatus:
    name: str
    purpose: str
    active: bool
    reason: str


def build_detectors(mode: InputMode, ctx: DetectorContext) -> tuple[list[Detector], list[DetectorStatus]]:
    available = KINDS_BY_MODE[mode]
    active: list[Detector] = []
    statuses: list[DetectorStatus] = []
    for cls in ALL_DETECTORS:
        missing = cls.consumes - available
        if missing:
            statuses.append(DetectorStatus(cls.name, cls.purpose, False,
                                           f"needs {', '.join(sorted(missing))} events, which {mode} input lacks"))
            continue
        detector = cls(ctx)
        blocked = detector.unavailable_reason()
        if blocked is not None:
            statuses.append(DetectorStatus(cls.name, cls.purpose, False, blocked))
            continue
        active.append(detector)
        statuses.append(DetectorStatus(cls.name, cls.purpose, True, "running"))
    return active, statuses
