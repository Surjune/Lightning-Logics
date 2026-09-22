"""DNS lexical features and the supervised DGA / DNS-tunnel detector."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

import pytest

from enclave.core.config import NetworkContext, Settings
from enclave.detectors.base import DetectorContext
from enclave.intel import Intel
from enclave.ml.dns_features import DNS_FEATURE_NAMES, features_from_query
from enclave.schema.events import DnsEvent


def test_dns_features_shape_and_signal() -> None:
    vec = features_from_query("kj3xq9zvm2lppqr7.com", 1)
    assert len(vec) == len(DNS_FEATURE_NAMES)
    entropy_idx = DNS_FEATURE_NAMES.index("label_entropy")
    assert features_from_query("random9x8q7zk2mv.com", 1)[entropy_idx] > \
        features_from_query("cloud.com", 1)[entropy_idx]


def _rand_label(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("bcdfghjklmnpqrstvwxyz0123456789") for _ in range(n))


def _train_tmp_dga(tmp_path: Path) -> Path:
    joblib = pytest.importorskip("joblib")
    pytest.importorskip("sklearn")
    from sklearn.ensemble import HistGradientBoostingClassifier

    rng = random.Random(1)
    words = ["cloud", "secure", "portal", "mail", "shop", "bank", "news", "drive"]
    rows: list[list[float]] = []
    labels: list[str] = []
    for _ in range(80):
        rows.append(features_from_query(f"{rng.choice(words)}.com", 1))
        labels.append("benign")
        rows.append(features_from_query(f"{_rand_label(rng, rng.randint(14, 22))}.com", 1))
        labels.append("dga")
    model = HistGradientBoostingClassifier(random_state=1, max_iter=60).fit(rows, labels)
    model_path = tmp_path / "dga_classifier.joblib"
    joblib.dump(model, model_path)
    sha = hashlib.sha256(model_path.read_bytes()).hexdigest()
    meta = {"model_version": "test", "feature_names": list(DNS_FEATURE_NAMES),
            "classes": ["benign", "dga"], "class_to_threat": {"dga": "dga"},
            "feature_importances": {n: 1.0 / len(DNS_FEATURE_NAMES) for n in DNS_FEATURE_NAMES},
            "benign_means": {}, "sha256": sha}
    (tmp_path / "dga_classifier.meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return tmp_path


def test_dga_detector_disabled_without_model() -> None:
    from enclave.detectors.dga_ml import DgaMlDetector

    ctx = DetectorContext(NetworkContext(Settings()), Intel(), ml_model_dir=None)
    assert DgaMlDetector(ctx).unavailable_reason() is not None


def test_dga_detector_flags_generated_domain(tmp_path: Path) -> None:
    _train_tmp_dga(tmp_path)
    from enclave.detectors.dga_ml import DgaMlDetector

    ctx = DetectorContext(NetworkContext(Settings()), Intel.load(Path("intel")), ml_model_dir=tmp_path)
    detector = DgaMlDetector(ctx)
    assert detector.unavailable_reason() is None

    dga = DnsEvent(ts=1.0, flow_id="1:x", client_ip="10.0.0.5", resolver_ip="10.10.0.8",
                   query="kj3xq9zvm2lppqr7wd.com", qtype=1, is_response=False)
    detections = detector.observe(dga)
    assert detections and detections[0].threat_class.value == "dga"

    benign = DnsEvent(ts=2.0, flow_id="1:y", client_ip="10.0.0.5", resolver_ip="10.10.0.8",
                      query="cloud.com", qtype=1, is_response=False)
    assert detector.observe(benign) == []
