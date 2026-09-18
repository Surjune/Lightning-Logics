"""Shared statistics. Every detector uses these; none re-derives them."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Sequence

from enclave.core.constants import (
    BASELINE_EWMA_ALPHA,
    BASELINE_MIN_SAMPLES,
    BASELINE_MIN_STD_FRACTION,
    TRW_ALPHA,
    TRW_BETA,
    TRW_THETA_BENIGN,
    TRW_THETA_SCANNER,
)


def shannon_entropy(counts: Iterable[int]) -> float:
    """Entropy in bits of a discrete distribution given as occurrence counts."""
    values = [c for c in counts if c > 0]
    total = sum(values)
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in values)


def string_entropy(text: str) -> float:
    """Per-character entropy in bits."""
    return shannon_entropy(Counter(text).values())


def mean(values: Sequence[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def std(values: Sequence[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))


def coefficient_of_variation(values: Sequence[float]) -> float:
    """std / mean; 0 for perfectly regular series. Infinite when the mean is 0."""
    m = mean(values)
    if m == 0:
        return math.inf
    return std(values) / m


def producer_consumer_ratio(bytes_out: float, bytes_in: float) -> float:
    """(out - in) / (out + in): +1 pure upload, -1 pure download, 0 balanced."""
    total = bytes_out + bytes_in
    if total == 0:
        return 0.0
    return (bytes_out - bytes_in) / total


class Ewma:
    """Exponentially weighted mean and variance used as a per-entity baseline."""

    __slots__ = ("alpha", "mean", "samples", "var")

    def __init__(self, alpha: float = BASELINE_EWMA_ALPHA) -> None:
        self.alpha = alpha
        self.mean = 0.0
        self.var = 0.0
        self.samples = 0

    def update(self, value: float) -> None:
        if self.samples == 0:
            self.mean = value
        else:
            diff = value - self.mean
            incr = self.alpha * diff
            self.mean += incr
            self.var = (1 - self.alpha) * (self.var + diff * incr)
        self.samples += 1

    @property
    def ready(self) -> bool:
        return self.samples >= BASELINE_MIN_SAMPLES

    def zscore(self, value: float) -> float:
        """Distance from the baseline in standard deviations (floored std, see constants)."""
        floor = abs(self.mean) * BASELINE_MIN_STD_FRACTION
        sd = max(math.sqrt(self.var), floor, 1.0)
        return (value - self.mean) / sd


class ThresholdRandomWalk:
    """Sequential hypothesis test on first-contact outcomes (Jung et al., 2004)."""

    STEP_SUCCESS = math.log(TRW_THETA_SCANNER / TRW_THETA_BENIGN)
    STEP_FAILURE = math.log((1 - TRW_THETA_SCANNER) / (1 - TRW_THETA_BENIGN))
    UPPER = math.log(TRW_BETA / TRW_ALPHA)
    LOWER = math.log((1 - TRW_BETA) / (1 - TRW_ALPHA))

    __slots__ = ("score",)

    def __init__(self) -> None:
        self.score = 0.0

    def observe(self, success: bool) -> None:
        self.score += self.STEP_SUCCESS if success else self.STEP_FAILURE
        if self.score <= self.LOWER:
            self.score = 0.0

    @property
    def is_scanner(self) -> bool:
        return self.score >= self.UPPER
