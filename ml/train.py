"""Train the supervised flow classifier and write a hash-verified artifact + model card.

Usage:
    python ml/train.py --csv-dir data/cicids2017        # real: CIC-IDS2017 flow CSVs
    python ml/train.py --synthetic                       # demo: fabricated labelled flows

Both paths share the training, evaluation and save code, so the artifact the live detector loads
is produced identically. Metrics are reported per class (precision / recall / F1) on a held-out
split (temporal for the real dataset, to avoid leaking future flows into training).
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

from datasets import BENIGN, load_cicids2017, make_synthetic

from enclave.ml.features import FEATURE_NAMES

DEFAULT_SEED = 20260917
PERMUTATION_REPEATS = 5


def _split(frame: pd.DataFrame, test_frac: float, temporal: bool, seed: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    if temporal:
        # Rows arrive in capture order; the tail becomes the test set so the model is never
        # evaluated on flows that preceded its training data.
        cut = int(len(frame) * (1.0 - test_frac))
        return frame.iloc[:cut], frame.iloc[cut:]
    train_df, test_df = train_test_split(frame, test_size=test_frac, random_state=seed,
                                         stratify=frame["label"])
    return train_df, test_df


def _importances(model: HistGradientBoostingClassifier, x_test: pd.DataFrame, y_test: pd.Series,
                 seed: int) -> dict[str, float]:
    result = permutation_importance(model, x_test.to_numpy(), y_test, n_repeats=PERMUTATION_REPEATS,
                                    random_state=seed, scoring="f1_macro")
    raw = np.clip(result.importances_mean, 0.0, None)
    total = float(raw.sum()) or 1.0
    return {name: round(float(v) / total, 4) for name, v in zip(FEATURE_NAMES, raw, strict=True)}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--csv-dir", help="directory of CIC-IDS2017 flow CSVs")
    src.add_argument("--synthetic", action="store_true", help="use fabricated demo flows")
    parser.add_argument("--rows", type=int, default=6000, help="synthetic rows per class")
    parser.add_argument("--test-frac", type=float, default=0.3)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", default="ml/artifacts")
    args = parser.parse_args()

    if args.synthetic:
        frame = make_synthetic(args.rows, args.seed)
        dataset, temporal = "synthetic-demo", False
    else:
        frame = load_cicids2017(Path(args.csv_dir))
        dataset, temporal = "CIC-IDS2017", True
    print(f"loaded {len(frame):,} flows from {dataset}: "
          f"{frame['label'].value_counts().to_dict()}")

    train_df, test_df = _split(frame, args.test_frac, temporal, args.seed)
    x_train, y_train = train_df[list(FEATURE_NAMES)], train_df["label"]
    x_test, y_test = test_df[list(FEATURE_NAMES)], test_df["label"]

    model = HistGradientBoostingClassifier(random_state=args.seed, max_iter=200,
                                           learning_rate=0.1, early_stopping=True)
    model.fit(x_train.to_numpy(), y_train)

    y_pred = model.predict(x_test.to_numpy())
    report: dict[str, Any] = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    print(classification_report(y_test, y_pred, zero_division=0))
    print(f"macro F1: {macro_f1:.4f}")

    classes = [str(c) for c in model.classes_]
    malicious = [c for c in classes if c != BENIGN]
    benign_rows = x_test[y_test == BENIGN]
    benign_means = {name: round(float(benign_rows[name].mean()), 4) for name in FEATURE_NAMES} \
        if len(benign_rows) else {}

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    model_path = out_dir / "flow_classifier.joblib"
    meta_path = out_dir / "flow_classifier.meta.json"
    joblib.dump(model, model_path)

    meta = {
        "schema_version": "1.0",
        "model_version": f"1.0-{dataset.lower().replace(' ', '')}",
        "model_type": type(model).__name__,
        "dataset": dataset,
        "feature_names": list(FEATURE_NAMES),
        "classes": classes,
        "class_to_threat": {c: c for c in malicious},  # model labels already equal ThreatClass values
        "feature_importances": _importances(model, x_test, y_test, args.seed),
        "benign_means": benign_means,
        "metrics": {"macro_f1": round(macro_f1, 4),
                    "per_class": {k: v for k, v in report.items() if k in classes}},
        "train_rows": len(train_df),
        "test_rows": len(test_df),
        "split": "temporal" if temporal else "stratified",
        "trained_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "sha256": _sha256(model_path),
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"\nwrote {model_path} and {meta_path}")
    print(f"model_version={meta['model_version']}  macro_f1={macro_f1:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
