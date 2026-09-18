"""The contract every input source fulfils: a read-only async stream of events."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from enclave.schema.events import Event, InputMode


class Source(Protocol):
    mode: InputMode
    live: bool  # live sources drop when the bus is full; file replays apply backpressure

    @property
    def source_ref(self) -> str:
        """Identifies the evidence origin (file + SHA-256, or listener address)."""
        ...

    def events(self) -> AsyncIterator[Event]:
        ...
