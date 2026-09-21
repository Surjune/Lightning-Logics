"""The canonical flow feature vector, derived identically at training and inference time.

The supervised model must see the *same* features when it is trained on labelled CIC-IDS2017
flow rows and when it scores a live :class:`~enclave.schema.events.FlowRecord`. To guarantee
that, both paths build a :class:`FlowCounts` of raw, format-independent counters and pass it
through the single :func:`derive_features` function below. The repository-root training script
imports this module for exactly that reason.

Identifiers that would leak the label (IP addresses, port numbers, absolute timestamps) are
deliberately excluded, so the model generalises to hosts and ports it never saw in training.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from enclave.core.constants import ML_RATE_EPSILON_S, PROTO_TCP, PROTO_UDP
from enclave.schema.events import FlowRecord

# The feature order is frozen: the model's coefficients are positional, so this tuple is the
# contract between the trainer and the loader. Never reorder; append only, and retrain.
FEATURE_NAMES: Final[tuple[str, ...]] = (
    "duration_s",
    "total_packets",
    "total_bytes",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "bytes_per_s",
    "packets_per_s",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "down_up_ratio",
    "fwd_bwd_pkt_ratio",
    "syn_flag",
    "rst_flag",
    "is_tcp",
    "is_udp",
)


@dataclass(frozen=True, slots=True)
class FlowCounts:
    """Raw, format-independent counters. Both a FlowRecord and a CIC-IDS2017 CSV row reduce to this."""

    duration_s: float
    fwd_packets: float
    bwd_packets: float
    fwd_bytes: float
    bwd_bytes: float
    proto: int
    syn: bool
    rst: bool


def derive_features(c: FlowCounts) -> dict[str, float]:
    """The one place the 17 model features are computed. Used by the trainer and the detector."""
    duration = max(c.duration_s, ML_RATE_EPSILON_S)
    total_packets = c.fwd_packets + c.bwd_packets
    total_bytes = c.fwd_bytes + c.bwd_bytes
    return {
        "duration_s": c.duration_s,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "fwd_packets": c.fwd_packets,
        "bwd_packets": c.bwd_packets,
        "fwd_bytes": c.fwd_bytes,
        "bwd_bytes": c.bwd_bytes,
        "bytes_per_s": total_bytes / duration,
        "packets_per_s": total_packets / duration,
        "fwd_pkt_len_mean": c.fwd_bytes / max(c.fwd_packets, 1.0),
        "bwd_pkt_len_mean": c.bwd_bytes / max(c.bwd_packets, 1.0),
        "down_up_ratio": c.bwd_bytes / max(c.fwd_bytes, 1.0),
        "fwd_bwd_pkt_ratio": c.fwd_packets / max(c.bwd_packets, 1.0),
        "syn_flag": 1.0 if c.syn else 0.0,
        "rst_flag": 1.0 if c.rst else 0.0,
        "is_tcp": 1.0 if c.proto == PROTO_TCP else 0.0,
        "is_udp": 1.0 if c.proto == PROTO_UDP else 0.0,
    }


def feature_row(counts: FlowCounts) -> list[float]:
    """Derived features in the frozen :data:`FEATURE_NAMES` order (the model's input vector)."""
    derived = derive_features(counts)
    return [derived[name] for name in FEATURE_NAMES]


def counts_from_flow(flow: FlowRecord) -> FlowCounts:
    return FlowCounts(
        duration_s=max(flow.last_ts - flow.first_ts, 0.0),
        fwd_packets=float(flow.pkts_fwd),
        bwd_packets=float(flow.pkts_bwd),
        fwd_bytes=float(flow.bytes_fwd),
        bwd_bytes=float(flow.bytes_bwd),
        proto=flow.proto,
        syn=flow.syn_seen,
        rst=flow.rst_seen,
    )


def features_from_flow(flow: FlowRecord) -> list[float]:
    """The inference entry point: one FlowRecord to one model input vector."""
    return feature_row(counts_from_flow(flow))
