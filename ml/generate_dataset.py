"""Generate a labelled, feature-extracted dataset (PS dataset option a: synthetic / lab-generated).

This never sends a single packet. It models the *flow-level statistical signature* each tool named in
the problem statement would produce, and extracts flow / lexical features from those models. Two
datasets are written:

* ``flows.csv``  - flow features + label, for the supervised ``ml-flow`` classifier.
* ``dns.csv``    - DNS-name lexical features + label, for the DGA / DNS-tunnelling side.

Provenance (which tool each class models) is written to ``DATASET.md``. Everything is seeded, so the
dataset is reproducible.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections.abc import Callable
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from enclave.ml.dns_features import DNS_FEATURE_NAMES, features_from_query
from enclave.ml.features import FEATURE_NAMES, FlowCounts, derive_features

TCP, UDP = 6, 17
DEFAULT_SEED = 20260917

# --- Flow signatures per PS-named tool --------------------------------------------------------
# Each returns raw FlowCounts; label groups several tools into one threat class.


def iperf3_bulk(r: np.random.Generator) -> FlowCounts:  # benign throughput test / large transfer
    fwd_p = int(r.integers(2000, 40000))
    bwd_p = int(fwd_p * r.uniform(0.02, 0.5))
    return FlowCounts(r.uniform(5, 90), fwd_p, bwd_p, fwd_p * r.uniform(1200, 1460),
                      bwd_p * r.uniform(40, 200), TCP, True, False)


def web_browse(r: np.random.Generator) -> FlowCounts:  # benign HTTP(S) request/response
    fwd_p = int(r.integers(4, 40))
    bwd_p = int(r.integers(6, 120))
    return FlowCounts(r.uniform(0.1, 6.0), fwd_p, bwd_p, fwd_p * r.uniform(120, 500),
                      bwd_p * r.uniform(300, 1400), TCP, True, bool(r.integers(0, 2)))


def dns_lookup(r: np.random.Generator) -> FlowCounts:  # benign small UDP request/response
    return FlowCounts(r.uniform(0.001, 0.2), 1, 1, r.uniform(40, 90), r.uniform(60, 300), UDP, False, False)


def keepalive(r: np.random.Generator) -> FlowCounts:  # benign small periodic TCP
    p = int(r.integers(2, 8))
    return FlowCounts(r.uniform(0.5, 20), p, p, p * r.uniform(60, 200), p * r.uniform(60, 200), TCP, True, False)


def hping3_syn_flood(r: np.random.Generator) -> FlowCounts:  # attack: SYN flood (half-open)
    return FlowCounts(r.uniform(0.0, 0.03), int(r.integers(1, 3)), 0, r.uniform(40, 60), 0, TCP, True,
                      bool(r.integers(0, 2)))


def hping3_udp_flood(r: np.random.Generator) -> FlowCounts:  # attack: UDP flood
    p = int(r.integers(1, 5))
    return FlowCounts(r.uniform(0.0, 0.05), p, 0, p * r.uniform(60, 1400), 0, UDP, False, False)


def slowloris(r: np.random.Generator) -> FlowCounts:  # attack: slow HTTP exhaustion (long, starved)
    p = int(r.integers(3, 20))
    return FlowCounts(r.uniform(30, 300), p, int(p * r.uniform(0.1, 0.5)), p * r.uniform(20, 120),
                      r.uniform(0, 200), TCP, True, False)


def port_scan(r: np.random.Generator) -> FlowCounts:  # recon: 1-2 packet probes, no reply
    return FlowCounts(r.uniform(0.0, 0.02), int(r.integers(1, 3)), 0, r.uniform(40, 120), 0, TCP, True,
                      bool(r.integers(0, 2)))


def c2_beacon(r: np.random.Generator) -> FlowCounts:  # C2 emulator: small regular check-ins
    fwd_p = int(r.integers(3, 12))
    bwd_p = int(r.integers(3, 12))
    return FlowCounts(r.uniform(0.05, 3.0), fwd_p, bwd_p, fwd_p * r.uniform(80, 260),
                      bwd_p * r.uniform(80, 400), TCP, True, False)


def exfiltration(r: np.random.Generator) -> FlowCounts:  # attack: bulk upload, tiny download
    fwd_p = int(r.integers(400, 8000))
    bwd_p = int(r.integers(5, 80))
    return FlowCounts(r.uniform(20, 600), fwd_p, bwd_p, fwd_p * r.uniform(1000, 1460),
                      bwd_p * r.uniform(40, 140), TCP, True, False)


# label -> (list of signature generators, provenance note)
FLOW_CLASSES: dict[str, tuple[list[Callable[[np.random.Generator], FlowCounts]], str]] = {
    "benign": ([iperf3_bulk, web_browse, dns_lookup, keepalive],
               "iperf3 bulk transfer, HTTP(S) browsing, DNS lookups, keepalives"),
    "ddos": ([hping3_syn_flood, hping3_udp_flood, slowloris],
             "hping3 SYN flood, hping3 UDP flood, Slowloris slow-HTTP exhaustion"),
    "recon_scan": ([port_scan], "port / host scanning (nmap-style fan-out)"),
    "c2_beacon": ([c2_beacon], "sandboxed C2 emulator: regular beacon check-ins"),
    "exfiltration": ([exfiltration], "bulk outbound upload with asymmetric byte ratio"),
}


def generate_flows(rows_per_class: int, seed: int) -> tuple[list[str], list[list[object]]]:
    r = np.random.default_rng(seed)
    header = [*FEATURE_NAMES, "label"]
    rows: list[list[object]] = []
    for label, (generators, _) in FLOW_CLASSES.items():
        for _ in range(rows_per_class):
            gen = generators[int(r.integers(0, len(generators)))]
            feats = derive_features(gen(r))
            rows.append([round(feats[n], 6) for n in FEATURE_NAMES] + [label])
    r.shuffle(rows)
    return header, rows


# --- DNS-name signatures ----------------------------------------------------------------------
_WORDS = ("cloud secure portal login mail news shop store bank pay account update service api cdn "
          "media video music photo drive docs office team meet chat forum blog help support status "
          "market data health power grid energy metro transport finance ledger token node relay "
          "gateway sensor device edge core central north south east west plant unit line zone").split()
_CONS, _VOW = "bcdfghjklmnpqrstvwxyz", "aeiou"
_TLDS = (".com", ".net", ".org", ".io", ".co", ".in", ".gov.in", ".co.in")
QTYPE_A, QTYPE_TXT, QTYPE_NULL = 1, 16, 10


def benign_domain(r: np.random.Generator) -> tuple[str, int]:
    label = _WORDS[int(r.integers(0, len(_WORDS)))]
    if r.random() < 0.4:
        label += _WORDS[int(r.integers(0, len(_WORDS)))]
    sub = "www." if r.random() < 0.3 else ""
    return f"{sub}{label}{_TLDS[int(r.integers(0, len(_TLDS)))]}", QTYPE_A


def dga_arithmetic(r: np.random.Generator) -> tuple[str, int]:  # high-entropy pseudo-random DGA
    alphabet = _CONS + _VOW + "0123456789"
    n = int(r.integers(12, 25))
    label = "".join(alphabet[int(r.integers(0, len(alphabet)))] for _ in range(n))
    return f"{label}{_TLDS[int(r.integers(0, len(_TLDS)))]}", QTYPE_A


def dga_dictionary(r: np.random.Generator) -> tuple[str, int]:  # concatenated words + digits (harder DGA)
    parts = [_WORDS[int(r.integers(0, len(_WORDS)))] for _ in range(int(r.integers(2, 4)))]
    label = "".join(parts) + str(int(r.integers(10, 9999)))
    return f"{label}{_TLDS[int(r.integers(0, len(_TLDS)))]}", QTYPE_A


def dns_tunnel(r: np.random.Generator) -> tuple[str, int]:  # long high-entropy subdomain (iodine / dnscat2)
    alphabet = _CONS + _VOW + "0123456789"
    chunks = [
        "".join(alphabet[int(r.integers(0, len(alphabet)))] for _ in range(int(r.integers(20, 50))))
        for _ in range(int(r.integers(1, 3)))
    ]
    base = _WORDS[int(r.integers(0, len(_WORDS)))] + _TLDS[int(r.integers(0, len(_TLDS)))]
    qtype = QTYPE_TXT if r.random() < 0.6 else QTYPE_NULL
    return f"{'.'.join(chunks)}.{base}", qtype


DNS_CLASSES: dict[str, tuple[list[Callable[[np.random.Generator], tuple[str, int]]], str]] = {
    "benign": ([benign_domain], "pronounceable brand/service names, common TLDs"),
    "dga": ([dga_arithmetic, dga_dictionary], "published-style DGA: arithmetic and dictionary algorithms"),
    "dns_tunnel": ([dns_tunnel], "iodine / dnscat2 style long high-entropy subdomains, TXT/NULL records"),
}

DNS_FEATURES = DNS_FEATURE_NAMES




def generate_dns(rows_per_class: int, seed: int) -> tuple[list[str], list[list[object]]]:
    r = np.random.default_rng(seed + 1)
    header = ["query", *DNS_FEATURES, "label"]
    rows: list[list[object]] = []
    for label, (generators, _) in DNS_CLASSES.items():
        for _ in range(rows_per_class):
            gen = generators[int(r.integers(0, len(generators)))]
            query, qtype = gen(r)
            rows.append([query, *[round(v, 6) for v in features_from_query(query, qtype)], label])
    r.shuffle(rows)
    return header, rows


def _write_csv(path: Path, header: list[str], rows: list[list[object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def _write_provenance(path: Path, flow_rows: int, dns_rows: int, seed: int) -> None:
    lines = ["# Generated dataset - provenance",
             "",
             f"Reproduce exactly: `python ml/generate_dataset.py --seed {seed}`. No packets are sent;",
             "each class models the flow-level signature of the tool named in the problem statement.",
             "",
             "## flows.csv (flow-feature dataset for the `ml-flow` classifier)",
             "",
             "| Class | Rows | Models |", "| --- | --- | --- |"]
    for label, (_, note) in FLOW_CLASSES.items():
        lines.append(f"| {label} | {flow_rows:,} | {note} |")
    lines += ["", f"Features ({len(FEATURE_NAMES)}): " + ", ".join(FEATURE_NAMES) + ".", "",
              "## dns.csv (DNS-name dataset for DGA / tunnelling)", "",
              "| Class | Rows | Models |", "| --- | --- | --- |"]
    for label, (_, note) in DNS_CLASSES.items():
        lines.append(f"| {label} | {dns_rows:,} | {note} |")
    lines += ["", "Features: " + ", ".join(DNS_FEATURES) + " (the `query` column is kept for "
              "inspection and is not a feature).", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="data/generated")
    parser.add_argument("--flow-rows", type=int, default=8000, help="rows per flow class")
    parser.add_argument("--dns-rows", type=int, default=8000, help="rows per DNS class")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    flow_header, flow_rows = generate_flows(args.flow_rows, args.seed)
    _write_csv(out / "flows.csv", flow_header, flow_rows)
    dns_header, dns_rows = generate_dns(args.dns_rows, args.seed)
    _write_csv(out / "dns.csv", dns_header, dns_rows)
    _write_provenance(out / "DATASET.md", args.flow_rows, args.dns_rows, args.seed)

    print(f"flows.csv: {len(flow_rows):,} rows, {len(FLOW_CLASSES)} classes")
    print(f"dns.csv:   {len(dns_rows):,} rows, {len(DNS_CLASSES)} classes")
    print(f"wrote {out}/flows.csv, {out}/dns.csv, {out}/DATASET.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
