"""Load labelled flows into the canonical feature vectors the model trains on.

Two sources, one output shape (``FEATURE_NAMES`` columns + a ``label`` column):

* :func:`load_cicids2017` reads the published CIC-IDS2017 flow CSVs and maps their raw counters
  through :func:`enclave.ml.features.derive_features`, the exact function the live detector uses.
* :func:`make_synthetic` fabricates a labelled set with plausible per-class distributions, so the
  pipeline is runnable and the model is live before the multi-GB dataset is downloaded.

Identifiers (IP, port, timestamp) are never turned into features, to prevent label leakage.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from enclave.core.constants import ML_RATE_EPSILON_S
from enclave.ml.features import FEATURE_NAMES, FlowCounts, derive_features

PROTO_TCP = 6
PROTO_UDP = 17
BENIGN = "benign"

# CIC-IDS2017 'Label' text -> our model label. Rows that map to None are dropped (web-attack and
# brute-force families are out of scope for a flow-only classifier; DNS/TLS classes need payload).
_CIC_LABELS: dict[str, str] = {
    "BENIGN": BENIGN,
    "DDOS": "ddos",
    "DOS HULK": "ddos",
    "DOS GOLDENEYE": "ddos",
    "DOS SLOWLORIS": "ddos",
    "DOS SLOWHTTPTEST": "ddos",
    "PORTSCAN": "recon_scan",
    "BOT": "c2_beacon",
    "INFILTRATION": "exfiltration",
}

# CIC-IDS2017 column -> our raw counter. Alternate spellings across CICFlowMeter versions included.
_COL_ALIASES: dict[str, tuple[str, ...]] = {
    "duration_us": ("Flow Duration",),
    "fwd_packets": ("Total Fwd Packets", "Total Fwd Packet"),
    "bwd_packets": ("Total Backward Packets", "Total Bwd Packets"),
    "fwd_bytes": ("Total Length of Fwd Packets", "Fwd Packets Length Total", "TotLen Fwd Pkts"),
    "bwd_bytes": ("Total Length of Bwd Packets", "Bwd Packets Length Total", "TotLen Bwd Pkts"),
    "proto": ("Protocol",),
    "syn": ("SYN Flag Count", "SYN Flag Cnt"),
    "rst": ("RST Flag Count", "RST Flag Cnt"),
    "label": ("Label",),
}


def _resolve(columns: list[str], wanted: str) -> str:
    lookup = {c.strip().lower(): c for c in columns}
    for alias in _COL_ALIASES[wanted]:
        hit = lookup.get(alias.lower())
        if hit is not None:
            return hit
    raise KeyError(f"CIC-IDS2017 CSV is missing a column for {wanted!r} (tried {_COL_ALIASES[wanted]})")


def _read_flow_file(path: Path) -> pd.DataFrame:
    raw = pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_csv(
        path, low_memory=False, encoding="latin-1")
    raw.columns = [c.strip() for c in raw.columns]
    return raw


def _feature_frame(merged: pd.DataFrame) -> pd.DataFrame:
    """Vectorised twin of enclave.ml.features.derive_features (kept in lock-step by test_ml)."""
    raw_dur = merged["duration_us"].to_numpy(dtype=float) / 1_000_000.0  # CIC duration is microseconds
    dur = np.maximum(raw_dur, ML_RATE_EPSILON_S)
    fp = merged["fwd_packets"].to_numpy(dtype=float)
    bp = merged["bwd_packets"].to_numpy(dtype=float)
    fb = merged["fwd_bytes"].to_numpy(dtype=float)
    bb = merged["bwd_bytes"].to_numpy(dtype=float)
    proto = merged["proto"].to_numpy(dtype=float)
    total_packets = fp + bp
    total_bytes = fb + bb
    out = pd.DataFrame({
        "duration_s": raw_dur,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "fwd_packets": fp,
        "bwd_packets": bp,
        "fwd_bytes": fb,
        "bwd_bytes": bb,
        "bytes_per_s": total_bytes / dur,
        "packets_per_s": total_packets / dur,
        "fwd_pkt_len_mean": fb / np.maximum(fp, 1.0),
        "bwd_pkt_len_mean": bb / np.maximum(bp, 1.0),
        "down_up_ratio": bb / np.maximum(fb, 1.0),
        "fwd_bwd_pkt_ratio": fp / np.maximum(bp, 1.0),
        "syn_flag": (merged["syn"].to_numpy(dtype=float) > 0).astype(float),
        "rst_flag": (merged["rst"].to_numpy(dtype=float) > 0).astype(float),
        "is_tcp": (proto == PROTO_TCP).astype(float),
        "is_udp": (proto == PROTO_UDP).astype(float),
    })
    out["label"] = merged["label"].to_numpy()
    return out[[*FEATURE_NAMES, "label"]]


def _flow_files(data_dir: Path) -> list[Path]:
    # A single .csv file, or a .parquet file/dataset-directory, is used as-is; a plain directory is
    # globbed for both formats (so a folder of CIC-IDS2017 day files just works).
    if data_dir.suffix in {".csv", ".parquet"}:
        return [data_dir]
    return sorted(data_dir.glob("*.csv")) + sorted(data_dir.glob("*.parquet"))


def load_cicids2017(data_dir: Path) -> pd.DataFrame:
    """Load CIC-IDS2017 flow files (.csv or .parquet) and map them to the model feature frame."""
    files = _flow_files(data_dir)
    if not files:
        raise FileNotFoundError(f"no .csv or .parquet files in {data_dir}")
    frames: list[pd.DataFrame] = []
    for path in files:
        raw = _read_flow_file(path)
        cols = list(raw.columns)
        resolved = {key: _resolve(cols, key) for key in _COL_ALIASES}
        frames.append(pd.DataFrame({
            "duration_us": pd.to_numeric(raw[resolved["duration_us"]], errors="coerce"),
            "fwd_packets": pd.to_numeric(raw[resolved["fwd_packets"]], errors="coerce"),
            "bwd_packets": pd.to_numeric(raw[resolved["bwd_packets"]], errors="coerce"),
            "fwd_bytes": pd.to_numeric(raw[resolved["fwd_bytes"]], errors="coerce"),
            "bwd_bytes": pd.to_numeric(raw[resolved["bwd_bytes"]], errors="coerce"),
            "proto": pd.to_numeric(raw[resolved["proto"]], errors="coerce"),
            "syn": pd.to_numeric(raw[resolved["syn"]], errors="coerce"),
            "rst": pd.to_numeric(raw[resolved["rst"]], errors="coerce"),
            "label_raw": raw[resolved["label"]].astype(str).str.strip().str.upper(),
        }))
    merged = pd.concat(frames, ignore_index=True).replace([np.inf, -np.inf], np.nan).dropna()
    merged["label"] = merged["label_raw"].map(_CIC_LABELS)
    merged = merged.dropna(subset=["label"])
    return _feature_frame(merged)


def _counts(rng: np.random.Generator, label: str) -> FlowCounts:
    if label == BENIGN:
        fwd_p = rng.integers(4, 40)
        bwd_p = rng.integers(4, 40)
        return FlowCounts(rng.uniform(0.2, 30.0), fwd_p, bwd_p,
                          fwd_p * rng.uniform(60, 600), bwd_p * rng.uniform(60, 900),
                          rng.choice([PROTO_TCP, PROTO_UDP]), bool(rng.integers(0, 2)), False)
    if label == "ddos":  # many small SYN-heavy packets, very short, one-sided
        fwd_p = rng.integers(1, 4)
        return FlowCounts(rng.uniform(0.0, 0.05), fwd_p, 0, fwd_p * rng.uniform(40, 60), 0,
                          PROTO_TCP, True, bool(rng.integers(0, 2)))
    if label == "recon_scan":  # 1-2 packet probes, no reply
        return FlowCounts(rng.uniform(0.0, 0.02), rng.integers(1, 3), 0, rng.uniform(40, 120), 0,
                          PROTO_TCP, True, bool(rng.integers(0, 2)))
    if label == "c2_beacon":  # small, regular, balanced check-ins
        fwd_p = rng.integers(3, 10)
        bwd_p = rng.integers(3, 10)
        return FlowCounts(rng.uniform(0.1, 2.0), fwd_p, bwd_p,
                          fwd_p * rng.uniform(80, 200), bwd_p * rng.uniform(80, 300),
                          PROTO_TCP, True, False)
    # exfiltration: large sustained upload, tiny download
    fwd_p = rng.integers(400, 3000)
    bwd_p = rng.integers(5, 60)
    return FlowCounts(rng.uniform(20.0, 300.0), fwd_p, bwd_p,
                      fwd_p * rng.uniform(1000, 1460), bwd_p * rng.uniform(40, 120),
                      PROTO_TCP, True, False)


def make_synthetic(rows_per_class: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    labels = [BENIGN, "ddos", "recon_scan", "c2_beacon", "exfiltration"]
    records = [
        derive_features(_counts(rng, label)) | {"label": label}
        for label in labels
        for _ in range(rows_per_class)
    ]
    rng.shuffle(records)
    return pd.DataFrame(records, columns=[*FEATURE_NAMES, "label"])


def load_feature_csv(path: Path) -> pd.DataFrame:
    """Load a CSV whose columns are exactly FEATURE_NAMES + 'label' (what generate_dataset.py writes)."""
    frame = pd.read_csv(path)
    missing = ({*FEATURE_NAMES, "label"}) - set(frame.columns)
    if missing:
        raise KeyError(f"{path} is missing columns: {sorted(missing)}")
    return frame[[*FEATURE_NAMES, "label"]].dropna()
