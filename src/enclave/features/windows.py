"""Event-time window helpers shared by the detectors."""

from __future__ import annotations

import math


class WindowClock:
    """Tumbling windows aligned to multiples of `size` seconds (event time)."""

    __slots__ = ("size", "start")

    def __init__(self, size: float) -> None:
        self.size = size
        self.start: float | None = None

    def touch(self, ts: float) -> None:
        if self.start is None:
            self.start = math.floor(ts / self.size) * self.size

    def due(self, now: float) -> bool:
        return self.start is not None and now >= self.start + self.size

    def roll(self, now: float) -> None:
        self.start = math.floor(now / self.size) * self.size

    @property
    def end(self) -> float:
        return (self.start or 0.0) + self.size


class DoublingTrigger:
    """Fires when a count first reaches `threshold`, then again each time it doubles.

    Lets count-based detectors alert as soon as evidence is sufficient without
    re-emitting on every additional event.
    """

    __slots__ = ("next_at",)

    def __init__(self, threshold: float) -> None:
        self.next_at = threshold

    def check(self, value: float) -> bool:
        if value >= self.next_at:
            self.next_at = value * 2
            return True
        return False
