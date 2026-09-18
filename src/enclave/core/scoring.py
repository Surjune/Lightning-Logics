"""Turns named feature values into one explainable confidence.

Each feature is scored with a logistic curve centred on its threshold (exactly at the
threshold -> 0.5), then combined with fixed weights. The per-feature contributions are
reported as the alert's "top factors", so every statistical alert explains itself the
same way an ML alert does with SHAP values.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from enclave.core.constants import SIGNAL_STEEPNESS


@dataclass(frozen=True, slots=True)
class Signal:
    value: float
    threshold: float
    weight: float
    higher_is_worse: bool = True


def signal_strength(value: float, threshold: float, higher_is_worse: bool = True) -> float:
    """0..1 score; 0.5 at the threshold. Uses the ratio so scale-free features compare fairly."""
    if threshold <= 0:
        raise ValueError("threshold must be positive")
    if math.isinf(value):
        return 1.0 if higher_is_worse else 0.0
    ratio = value / threshold
    if not higher_is_worse:
        ratio = threshold / value if value > 0 else math.inf
        if math.isinf(ratio):
            return 1.0
    return 1.0 / (1.0 + math.exp(-SIGNAL_STEEPNESS * (ratio - 1.0)))


def combine(signals: dict[str, Signal]) -> tuple[float, list[tuple[str, float]]]:
    """Weighted confidence plus contributions sorted by size."""
    total_weight = sum(s.weight for s in signals.values())
    if total_weight <= 0:
        raise ValueError("signals need a positive total weight")
    contributions = {
        name: s.weight * signal_strength(s.value, s.threshold, s.higher_is_worse) / total_weight
        for name, s in signals.items()
    }
    confidence = sum(contributions.values())
    ranked = sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)
    return round(confidence, 4), [(k, round(v, 4)) for k, v in ranked]
