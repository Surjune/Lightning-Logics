"""The dataset generator must be deterministic and produce the documented shape and labels."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

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


def test_loader_features_match_derive_features() -> None:
    """The vectorised CIC loader must produce the same features as the scalar derive_features."""
    pd = pytest.importorskip("pandas")
    import datasets as ds

    from enclave.ml.features import FlowCounts, derive_features

    raw = pd.DataFrame({
        "duration_us": [1_000_000, 0, 5_500_000, 250],
        "fwd_packets": [10, 1, 2000, 0],
        "bwd_packets": [5, 0, 20, 3],
        "fwd_bytes": [2000, 40, 2_000_000, 0],
        "bwd_bytes": [500, 0, 3000, 120],
        "proto": [6, 6, 6, 17],
        "syn": [1, 1, 0, 0],
        "rst": [0, 1, 0, 0],
        "label": ["benign", "ddos", "exfiltration", "benign"],
    })
    got = ds._feature_frame(raw)
    for i, row in enumerate(raw.itertuples(index=False)):
        want = derive_features(FlowCounts(
            duration_s=row.duration_us / 1_000_000.0, fwd_packets=row.fwd_packets,
            bwd_packets=row.bwd_packets, fwd_bytes=row.fwd_bytes, bwd_bytes=row.bwd_bytes,
            proto=int(row.proto), syn=bool(row.syn), rst=bool(row.rst)))
        for name in FEATURE_NAMES:
            assert got.iloc[i][name] == pytest.approx(want[name]), (name, i)
