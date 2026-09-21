"""Detector contract and the shared context every detector receives."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from enclave.core.config import NetworkContext
from enclave.core.constants import EPHEMERAL_PORT_MIN, PROTO_TCP, PROTO_UDP
from enclave.intel import Intel
from enclave.schema.alert import Detection, EvidenceItem
from enclave.schema.events import Event, EventKind, FlowRecord, InputMode


@dataclass(frozen=True)
class DetectorContext:
    network: NetworkContext
    intel: Intel
    ml_model_dir: Path | None = None


class Detector(ABC):
    name: ClassVar[str]
    version: ClassVar[str] = "1.0"
    consumes: ClassVar[frozenset[EventKind]]
    purpose: ClassVar[str]

    def unavailable_reason(self) -> str | None:
        """Why this detector cannot run even though its event kinds are present (e.g. no model).

        Returns None when the detector is ready. The registry uses this to disable a detector
        gracefully and report the reason on the dashboard.
        """
        return None

    def __init__(self, ctx: DetectorContext) -> None:
        self.ctx = ctx
        self.suppressed = 0

    @property
    def model_ref(self) -> str:
        return f"{self.name}-{self.version}"

    @abstractmethod
    def observe(self, event: Event) -> list[Detection]:
        """Consume one event; return detections that are already conclusive."""

    def flush(self, now: float) -> list[Detection]:
        """Close any event-time windows that ended before `now`."""
        return []


def ev(observed: float | int | str, reference: str | None = None) -> EvidenceItem:
    if isinstance(observed, float):
        observed = round(observed, 4)
    return EvidenceItem(observed=observed, reference=reference)


def proto_name(proto: int) -> str:
    return {PROTO_TCP: "TCP", PROTO_UDP: "UDP"}.get(proto, str(proto))


def is_probable_reply(flow: FlowRecord) -> bool:
    """Unidirectional flow records include server->client halves; skip them for fan-out logic."""
    return (
        flow.mode is InputMode.FLOW
        and flow.src_port < EPHEMERAL_PORT_MIN <= flow.dst_port
    )
