"""Loads the trained flow classifier once and wraps inference.

Kept deliberately thin and dependency-tolerant: if scikit-learn/joblib are not installed, or
no artifact is present, the classifier reports ``available = False`` and the pipeline runs on
the statistical detectors alone. The model file is hash-verified before it is trusted, the same
way the offline intel bundle is.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from enclave.core.constants import (
    ML_BENIGN_LABEL,
    ML_DGA_META_FILE,
    ML_DGA_MODEL_FILE,
    ML_META_FILE,
    ML_MIN_CONFIDENCE,
    ML_MODEL_DIR,
    ML_MODEL_FILE,
    ML_VERIFY_HASH,
    TOP_FACTORS,
)
from enclave.core.logging import get_logger

log = get_logger(__name__)

_CHUNK = 1 << 16


@dataclass(frozen=True, slots=True)
class Prediction:
    label: str
    confidence: float
    is_malicious: bool
    proba_by_class: dict[str, float]
    top_features: list[tuple[str, float]]


@dataclass(slots=True)
class FlowClassifier:
    """A loaded model, or a placeholder that explains why no model is active."""

    available: bool
    reason: str
    model: Any = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def version(self) -> str:
        return str(self.meta.get("model_version", "untrained"))

    @property
    def feature_names(self) -> list[str]:
        return list(self.meta.get("feature_names", []))

    @property
    def benign_means(self) -> dict[str, float]:
        return dict(self.meta.get("benign_means", {}))

    def threat_for(self, label: str) -> str | None:
        """Map a model label to a schema threat-class value, or None for the benign class."""
        if label == ML_BENIGN_LABEL:
            return None
        mapping: dict[str, str] = self.meta.get("class_to_threat", {})
        return mapping.get(label)

    def predict(self, features: list[float]) -> Prediction | None:
        if not self.available or self.model is None:
            return None
        proba = self.model.predict_proba([features])[0]
        classes: list[str] = list(self.model.classes_)
        proba_by_class = {cls: float(p) for cls, p in zip(classes, proba, strict=True)}
        label = max(proba_by_class, key=lambda k: proba_by_class[k])
        confidence = proba_by_class[label]
        importances: dict[str, float] = self.meta.get("feature_importances", {})
        top = sorted(importances.items(), key=lambda kv: kv[1], reverse=True)[:TOP_FACTORS]
        is_malicious = label != ML_BENIGN_LABEL and confidence >= ML_MIN_CONFIDENCE
        return Prediction(label, round(confidence, 4), is_malicious, proba_by_class, top)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load(model_dir: Path, model_file: str, meta_file: str) -> FlowClassifier:
    model_path = model_dir / model_file
    meta_path = model_dir / meta_file
    if not model_path.is_file() or not meta_path.is_file():
        return FlowClassifier(False, f"no {model_file} in {model_dir} (run the trainer)")
    try:
        import joblib  # optional dependency, imported only when a model exists
    except ImportError:
        return FlowClassifier(False, "scikit-learn/joblib not installed (pip install -e '.[ml]')")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if ML_VERIFY_HASH:
        expected = meta.get("sha256")
        actual = _sha256(model_path)
        if expected and expected != actual:
            return FlowClassifier(False, f"model hash mismatch for {model_path}; refusing to load")
    model = joblib.load(model_path)
    log.info("classifier loaded", extra={"file": model_file, "version": meta.get("model_version"),
                                         "classes": meta.get("classes")})
    return FlowClassifier(True, "loaded", model, meta)


_CACHE: dict[tuple[Path, str], FlowClassifier] = {}


def _cached(model_dir: str | Path, model_file: str, meta_file: str) -> FlowClassifier:
    key = (Path(model_dir), model_file)
    cached = _CACHE.get(key)
    if cached is None:
        cached = _load(key[0], model_file, meta_file)
        _CACHE[key] = cached
    return cached


def load_classifier(model_dir: str | Path = ML_MODEL_DIR) -> FlowClassifier:
    """Load (and memoise) the flow classifier. Safe to call when no model exists."""
    return _cached(model_dir, ML_MODEL_FILE, ML_META_FILE)


def load_dga_classifier(model_dir: str | Path = ML_MODEL_DIR) -> FlowClassifier:
    """Load (and memoise) the DGA / DNS-tunnel classifier. Safe to call when no model exists."""
    return _cached(model_dir, ML_DGA_MODEL_FILE, ML_DGA_META_FILE)
