"""The dataset generator must be deterministic and produce the documented shape and labels."""

from __future__ import annotations

import sys
from pathlib import Path

from enclave.ml.features import FEATURE_NAMES

# generate_dataset lives at the repository root under ml/ (offline tooling, not a package).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml"))

import generate_dataset as gd


def test_flow_dataset_shape_and_determinism() -> None:
    header, rows = gd.generate_flows(40, seed=7)
    again = gd.generate_flows(40, seed=7)[1]
    assert header == [*FEATURE_NAMES, "label"]
    assert len(rows) == 40 * len(gd.FLOW_CLASSES)
    assert rows == again, "same seed must reproduce the dataset byte-for-byte"
    assert {row[-1] for row in rows} == set(gd.FLOW_CLASSES)
    assert all(isinstance(cell, float | int) for row in rows for cell in row[:-1])


def test_dns_dataset_shape_and_labels() -> None:
    header, rows = gd.generate_dns(40, seed=7)
    assert header[0] == "query" and header[-1] == "label"
    assert len(rows) == 40 * len(gd.DNS_CLASSES)
    assert {row[-1] for row in rows} == set(gd.DNS_CLASSES)


def test_dga_names_score_higher_than_benign() -> None:
    score_idx = 1 + gd.DNS_FEATURES.index("dga_score")  # +1 for the leading "query" column
    _, rows = gd.generate_dns(300, seed=7)
    dga = [row[score_idx] for row in rows if row[-1] == "dga"]
    benign = [row[score_idx] for row in rows if row[-1] == "benign"]
    assert sum(dga) / len(dga) > sum(benign) / len(benign)
