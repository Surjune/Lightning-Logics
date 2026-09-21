"""Core statistics at their edges."""

from __future__ import annotations

import math

from enclave.core.stats import (
    ThresholdRandomWalk,
    coefficient_of_variation,
    producer_consumer_ratio,
    shannon_entropy,
    string_entropy,
)


def test_entropy_extremes() -> None:
    assert shannon_entropy([]) == 0.0
    assert shannon_entropy([5]) == 0.0                       # one source -> no uncertainty
    assert math.isclose(shannon_entropy([1, 1]), 1.0)        # two equal -> 1 bit
    assert math.isclose(shannon_entropy([1] * 1024), 10.0)   # 1024 equal -> 10 bits


def test_string_entropy() -> None:
    assert string_entropy("aaaa") == 0.0
    assert string_entropy("google") < string_entropy("xj7qk9zvwp2h")


def test_cv_regular_vs_jittered() -> None:
    assert coefficient_of_variation([60, 60, 60, 60]) == 0.0
    assert coefficient_of_variation([60, 61, 59, 60]) < 0.2
    assert coefficient_of_variation([1, 90, 5, 200]) > 0.6
    assert math.isinf(coefficient_of_variation([0, 0]))


def test_pcr_direction() -> None:
    assert producer_consumer_ratio(100, 0) == 1.0
    assert producer_consumer_ratio(0, 100) == -1.0
    assert producer_consumer_ratio(50, 50) == 0.0
    assert producer_consumer_ratio(0, 0) == 0.0


def test_trw_declares_scanner_on_failures() -> None:
    trw = ThresholdRandomWalk()
    for _ in range(5):
        trw.observe(success=False)
    assert trw.is_scanner
    benign = ThresholdRandomWalk()
    for _ in range(20):
        benign.observe(success=True)
    assert not benign.is_scanner
