"""Lexical features of domain names (shared by the DGA detector and model training)."""

from __future__ import annotations

from dataclasses import dataclass

from enclave.core.constants import (
    DGA_DIGIT_RATIO,
    DGA_ENTROPY_BITS,
    DGA_LONG_LABEL,
    DGA_MIN_LABEL_LEN,
    DGA_NAME_WEIGHTS,
    DGA_RARE_BIGRAM_RATIO,
    MULTI_LABEL_SUFFIXES,
)
from enclave.core.scoring import Signal, combine
from enclave.core.stats import string_entropy

# Frequent English letter pairs (after Norvig's Google-corpus bigram counts). Pronounceable
# brand names mostly stay inside this set; algorithmically generated names mostly do not.
COMMON_BIGRAMS: frozenset[str] = frozenset(["th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le", "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea", "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur", "ca", "el", "ta", "la", "ns", "di", "fo", "ho", "pe", "ec", "pr", "no", "ct", "us", "ac", "ot", "il", "tr", "ly", "nc", "et", "ut", "ss", "so", "rs", "un", "lo", "wa", "ge", "ie", "wh", "ee", "wi", "em", "ad", "ol", "rt", "po", "we", "na", "ul", "ni", "ts", "mo", "ow", "pa", "im", "mi", "ai", "sh", "ir", "su", "id", "os", "iv", "ia", "am", "fi", "ci", "vi", "pl", "ig", "tu", "ev", "ld", "ry", "mp", "fe", "bl", "ab", "gh", "ty", "op", "wo", "sa", "ay", "ex", "ke", "fr", "oo", "av", "ag", "if", "ap", "gr", "od", "bo", "sp", "rd", "do", "uc", "bu", "ei", "ov", "by", "rm", "ep", "tt", "oc", "fa", "ef", "cu", "rn", "sc", "gi", "da", "yo", "cr", "cl", "du", "ga", "qu", "ue", "ff", "ba", "ey", "ls", "va", "um", "pp", "ua", "up", "lu", "go", "ht", "ru", "ug", "ds", "lt", "pi", "rc", "rr", "eg", "au", "ck", "ew", "mu", "br", "bi", "pt", "ak", "pu", "ui", "rg", "ib", "tl", "ny", "ki", "rk", "ys", "ob", "mm", "fu", "ph", "og", "ms", "ye", "ud", "mb", "ip", "ub", "oi", "rl", "gu", "dr", "hr", "cc", "tw", "ft", "wn", "nu", "af", "hu", "nn", "eo", "vo", "rv", "nf", "xp", "gn", "sm", "fl", "iz", "ok", "nl", "my", "gl", "aw", "ju", "oa", "sy", "sl", "ps", "jo", "lf", "nk", "kn", "gs", "dy", "hy", "ze", "ks", "xt", "bs", "ik", "dd", "cy", "rp", "sk", "ws", "oe", "oy", "eu", "ya"])


@dataclass(frozen=True, slots=True)
class NameParts:
    registered: str     # e.g. "example.co.in"
    label: str          # registrable label without suffix, e.g. "example"
    subdomain: str      # everything left of the registered domain


def split_name(query: str) -> NameParts:
    labels = [part for part in query.lower().rstrip(".").split(".") if part]
    if not labels:
        return NameParts("", "", "")
    suffix_len = 2 if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES else 1
    reg_len = min(len(labels), suffix_len + 1)
    registered = labels[-reg_len:]
    return NameParts(
        registered=".".join(registered),
        label=registered[0] if len(registered) > suffix_len else "",
        subdomain=".".join(labels[:-reg_len]),
    )


def rare_bigram_ratio(label: str) -> float:
    pairs = [label[i:i + 2] for i in range(len(label) - 1)]
    letter_pairs = [p for p in pairs if p.isalpha()]
    if not letter_pairs:
        return 1.0 if pairs else 0.0
    return sum(1 for p in letter_pairs if p not in COMMON_BIGRAMS) / len(letter_pairs)


def name_features(label: str) -> dict[str, float]:
    length = len(label)
    return {
        "length": float(length),
        "char_entropy": string_entropy(label),
        "digit_ratio": sum(c.isdigit() for c in label) / length if length else 0.0,
        "rare_bigram_ratio": rare_bigram_ratio(label),
    }


def dga_name_score(label: str) -> tuple[float, dict[str, float]]:
    """0..1 likelihood that a registrable label was machine-generated."""
    feats = name_features(label)
    if feats["length"] < DGA_MIN_LABEL_LEN:
        return 0.0, feats
    thresholds = {
        "char_entropy": DGA_ENTROPY_BITS,
        "rare_bigram_ratio": DGA_RARE_BIGRAM_RATIO,
        "digit_ratio": DGA_DIGIT_RATIO,
        "length": float(DGA_LONG_LABEL),
    }
    signals = {
        name: Signal(value=feats[name], threshold=thresholds[name], weight=weight)
        for name, weight in DGA_NAME_WEIGHTS.items()
    }
    score, _ = combine(signals)
    return score, feats


def max_label_length(subdomain: str) -> int:
    return max((len(part) for part in subdomain.split(".")), default=0) if subdomain else 0
