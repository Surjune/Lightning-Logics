"""Tests for the supervised flow-classifier layer: features, model loading and the detector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from enclave.core.config import NetworkContext, Settings
from enclave.detectors.base import DetectorContext
from enclave.intel import Intel
from enclave.ml.features import FEATURE_NAMES, FlowCounts, derive_features, features_from_flow
from enclave.ml.model import load_classifier
from enclave.schema.events import InputMode


def _flow(**kw: object):
    from enclave.schema.events import FlowRecord
    base = dict(flow_id="1:x", src_ip="10.0.0.5", dst_ip="203.0.113.9", src_port=40000, dst_port=443,
                proto=6, first_ts=0.0, last_ts=10.0, bytes_fwd=1000, bytes_bwd=1000, pkts_fwd=10,
                pkts_bwd=10, syn_seen=True, synack_seen=True, rst_seen=False, export_index=0,
                is_final=True, mode=InputMode.PCAP)
    base.update(kw)
    return FlowRecord(**base)  # type: ignore[arg-type]


def test_feature_vector_shape_and_order() -> None:
    vec = features_from_flow(_flow())
    assert len(vec) == len(FEATURE_NAMES)
    assert all(isinstance(v, float) for v in vec)


def test_derive_features_is_deterministic_and_leakage_free() -> None:
    counts = FlowCounts(duration_s=2.0, fwd_packets=10, bwd_packets=5, fwd_bytes=2000,
                        bwd_bytes=500, proto=6, syn=True, rst=False)
    a = derive_features(counts)
    b = derive_features(counts)
    assert a == b
    # No identifier features (ip/port/timestamp) leak into the model input.
    assert not ({"src_ip", "dst_ip", "src_port", "dst_port", "timestamp"} & set(a))
    assert a["down_up_ratio"] == pytest.approx(0.25)
    assert a["bytes_per_s"] == pytest.approx(1250.0)


def test_missing_model_is_graceful(tmp_path: Path) -> None:
    clf = load_classifier(tmp_path)  # empty dir: no artifact
    assert clf.available is False
    assert "flow_classifier" in clf.reason and "run the trainer" in clf.reason
    assert clf.predict([0.0] * len(FEATURE_NAMES)) is None


def _train_tmp_model(tmp_path: Path) -> Path:
    """Train a tiny benign-vs-exfil model into tmp_path and write its meta card."""
    joblib = pytest.importorskip("joblib")
    pytest.importorskip("sklearn")
    from sklearn.ensemble import HistGradientBoostingClassifier

    rows: list[list[float]] = []
    labels: list[str] = []
    for _ in range(60):
        rows.append([derive_features(FlowCounts(5.0, 10, 10, 1000, 1000, 6, True, False))[n]
                     for n in FEATURE_NAMES])
        labels.append("benign")
        rows.append([derive_features(FlowCounts(120.0, 2000, 20, 2_000_000, 2000, 6, True, False))[n]
                     for n in FEATURE_NAMES])
        labels.append("exfiltration")
    model = HistGradientBoostingClassifier(random_state=1, max_iter=50)
    model.fit(rows, labels)
    model_path = tmp_path / "flow_classifier.joblib"
    joblib.dump(model, model_path)
    sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
    meta = {
        "model_version": "test", "feature_names": list(FEATURE_NAMES),
        "classes": ["benign", "exfiltration"], "class_to_threat": {"exfiltration": "exfiltration"},
        "feature_importances": {n: 1.0 / len(FEATURE_NAMES) for n in FEATURE_NAMES},
        "benign_means": {n: 0.0 for n in FEATURE_NAMES}, "sha256": sha,
    }
    (tmp_path / "flow_classifier.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return tmp_path


def test_classifier_roundtrip_predicts_malicious(tmp_path: Path) -> None:
    _train_tmp_model(tmp_path)
    clf = load_classifier(tmp_path)
    assert clf.available is True
    exfil = [derive_features(FlowCounts(120.0, 2000, 20, 2_000_000, 2000, 6, True, False))[n]
             for n in FEATURE_NAMES]
    pred = clf.predict(exfil)
    assert pred is not None
    assert pred.label == "exfiltration"
    assert pred.is_malicious is True
    assert clf.threat_for(pred.label) == "exfiltration"
    assert clf.threat_for("benign") is None


def test_hash_mismatch_refuses_to_load(tmp_path: Path) -> None:
    _train_tmp_model(tmp_path)
    meta_path = tmp_path / "flow_classifier.meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["sha256"] = "0" * 64
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    clf = load_classifier(tmp_path)
    assert clf.available is False
    assert "hash mismatch" in clf.reason


def test_ml_detector_emits_detection(tmp_path: Path) -> None:
    _train_tmp_model(tmp_path)
    from enclave.detectors.ml_flow import MlFlowDetector

    ctx = DetectorContext(NetworkContext(Settings()), Intel.load(Path("intel")), ml_model_dir=tmp_path)
    detector = MlFlowDetector(ctx)
    flow = _flow(bytes_fwd=2_000_000, bytes_bwd=2000, pkts_fwd=2000, pkts_bwd=20, last_ts=120.0)
    detections = detector.observe(flow)
    assert len(detections) == 1
    assert detections[0].threat_class.value == "exfiltration"
    assert detections[0].confidence >= 0.6
