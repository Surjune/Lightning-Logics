"""Lexical feature vector for a DNS query, derived identically at training and inference time.

Mirrors :mod:`enclave.ml.features` for the flow model: the DGA/tunnel dataset generator and the live
`dga-ml` detector both build their features here, from the same functions the statistical
`dns-lexical` detector uses, so the model can never see a feature the detector cannot reproduce.
"""

from __future__ import annotations

from typing import Final

from enclave.core.stats import string_entropy
from enclave.features.lexical import dga_name_score, max_label_length, name_features, split_name

# Frozen feature order — the model's input contract. Append only, then retrain.
DNS_FEATURE_NAMES: Final[tuple[str, ...]] = (
    "label_length",
    "label_entropy",
    "digit_ratio",
    "rare_bigram_ratio",
    "dga_score",
    "subdomain_max_label_len",
    "subdomain_entropy",
    "num_labels",
    "qtype",
    "is_txt_or_null",
)

QTYPE_TXT: Final = 16
QTYPE_NULL: Final = 10


def features_from_query(query: str, qtype: int) -> list[float]:
    """One DNS query (name + record type) to the model input vector, in DNS_FEATURE_NAMES order."""
    parts = split_name(query)
    feats = name_features(parts.label)
    labels = [p for p in query.rstrip(".").split(".") if p]
    return [
        feats["length"],
        feats["char_entropy"],
        feats["digit_ratio"],
        feats["rare_bigram_ratio"],
        dga_name_score(parts.label)[0],
        float(max_label_length(parts.subdomain)),
        string_entropy(parts.subdomain.replace(".", "")),
        float(len(labels)),
        float(qtype),
        1.0 if qtype in (QTYPE_TXT, QTYPE_NULL) else 0.0,
    ]
