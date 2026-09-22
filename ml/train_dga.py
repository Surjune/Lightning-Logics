"""Train a DGA / DNS-tunnelling classifier on the generated DNS-name dataset.

Usage:
    python ml/generate_dataset.py           # writes data/generated/dns.csv
    python ml/train_dga.py --csv data/generated/dns.csv

Uses only lexical features of the query name (length, entropy, rare-bigram ratio, digit ratio,
subdomain shape, record type) - never the raw query string, so the model cannot memorise domains.
The live pipeline detects DGA/tunnelling with the statistical `dns-lexical` detector; this model
validates the same features with a supervised learner and is available to wire in as a second
opinion (roadmap).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from enclave.ml.dns_features import DNS_FEATURE_NAMES

FEATURES = list(DNS_FEATURE_NAMES)
DEFAULT_SEED = 20260917


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", default="data/generated/dns.csv")
    parser.add_argument("--test-frac", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", default="ml/artifacts")
    args = parser.parse_args()

    frame = pd.read_csv(args.csv).dropna(subset=[*FEATURES, "label"])
    print(f"loaded {len(frame):,} names: {frame['label'].value_counts().to_dict()}")

    x, y = frame[FEATURES], frame["label"]
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=args.test_frac,
                                                        random_state=args.seed, stratify=y)
    model = HistGradientBoostingClassifier(random_state=args.seed, max_iter=200, early_stopping=True)
    model.fit(x_train.to_numpy(), y_train)

    y_pred = model.predict(x_test.to_numpy())
    report: dict[str, Any] = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"macro F1: {macro_f1:.4f}")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "dga_classifier.joblib"
    meta_path = out_dir / "dga_classifier.meta.json"
    joblib.dump(model, model_path)
    classes = [str(c) for c in model.classes_]
    perm = permutation_importance(model, x_test.to_numpy(), y_test, n_repeats=5,
                                  random_state=args.seed, scoring="f1_macro")
    raw = np.clip(perm.importances_mean, 0.0, None)
    total = float(raw.sum()) or 1.0
    importances = {name: round(float(v) / total, 4) for name, v in zip(FEATURES, raw, strict=True)}
    meta = {
        "schema_version": "1.0", "model_version": "1.0-generated-dns",
        "model_type": type(model).__name__, "dataset": "generated-dns",
        "feature_names": FEATURES, "classes": classes,
        "class_to_threat": {"dga": "dga", "dns_tunnel": "dns_tunnel"},
        "feature_importances": importances,
        "metrics": {"macro_f1": round(macro_f1, 4),
                    "per_class": {k: v for k, v in report.items() if k in classes}},
        "train_rows": len(x_train), "test_rows": len(x_test),
        "trained_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "sha256": _sha256(model_path),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"\nwrote {model_path} and {meta_path}\nmacro_f1={macro_f1:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
