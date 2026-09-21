# Supervised flow classifier — model card & training

This directory holds the **offline** training pipeline for the supervised detector `ml-flow`. It is
never imported at request time; the live pipeline loads only the trained artifact through
`enclave.ml.model`.

## What the model is

| Field | Value |
| --- | --- |
| Task | Multiclass flow classification (benign vs. threat class) |
| Algorithm | Gradient-boosted decision trees (`HistGradientBoostingClassifier`, scikit-learn) |
| Classes | `benign`, `ddos`, `recon_scan`, `c2_beacon`, `exfiltration` |
| Input | 17 behavioural flow features (see below) — **no IP, port or timestamp** (leakage-safe) |
| Output | Class + calibrated probability; an alert is raised only above `ML_MIN_CONFIDENCE` (0.6) |
| Covers | The flow-observable classes. DGA/DNS-tunnel/encrypted-malware stay with the metadata detectors, which need payload fields a flow record cannot carry. |

The classifier is a **second, dataset-trained opinion** on top of the always-on statistical
detectors — not a replacement. Fusion merges or corroborates the two.

## Features (identical at train and inference time)

Both the CSV loader and the live detector build a `FlowCounts` and pass it through the single
`derive_features()` function in [`src/enclave/ml/features.py`](../src/enclave/ml/features.py), so the
model can never see a feature at training that the detector cannot reproduce live:

`duration_s`, `total_packets`, `total_bytes`, `fwd_packets`, `bwd_packets`, `fwd_bytes`,
`bwd_bytes`, `bytes_per_s`, `packets_per_s`, `fwd_pkt_len_mean`, `bwd_pkt_len_mean`,
`down_up_ratio`, `fwd_bwd_pkt_ratio`, `syn_flag`, `rst_flag`, `is_tcp`, `is_udp`.

Identifiers (IP, port, timestamp) are deliberately excluded so the model generalises to hosts and
ports unseen in training, rather than memorising them.

## Dataset — CIC-IDS2017

Primary training set: **CIC-IDS2017** (Canadian Institute for Cybersecurity, University of New
Brunswick). It ships labelled flow-feature CSVs whose labels map onto our classes.

1. Download the "MachineLearningCVE" CSVs from
   <https://www.unb.ca/cic/datasets/ids-2017.html> (free; no signup for the CSVs).
2. Put the `.csv` files in `data/cicids2017/`.
3. Train:

   ```bash
   pip install -e ".[train]"
   python ml/train.py --csv-dir data/cicids2017
   ```

Label mapping (`ml/datasets.py`): `BENIGN -> benign`; `DDoS`/`DoS *` -> `ddos`; `PortScan` ->
`recon_scan`; `Bot` -> `c2_beacon`; `Infiltration` -> `exfiltration`. Web-attack and brute-force
families are dropped — they are out of scope for a flow-only classifier.

Complementary sets for future work: **CIC-DDoS2019** (DDoS subtypes), **CTU-13 / Stratosphere**
(real botnet C2), **CIC-Bell-DNS-EXF-2021** (exfil). See [`../docs/VALIDATION.md`](../docs/VALIDATION.md).

## Generate a dataset without downloading anything (PS option a)

The problem statement's dataset section lists synthetic / lab-generated traffic (iperf3, hping3,
Slowloris, dnscat2/iodine, DGA). `ml/generate_dataset.py` produces a labelled, feature-extracted
dataset that models each of those tools' **flow-level signatures** — it never sends a packet:

```bash
python ml/generate_dataset.py                          # data/generated/{flows.csv, dns.csv, DATASET.md}
python ml/train.py --csv data/generated/flows.csv      # trains ml-flow on the flow dataset
python ml/train_dga.py --csv data/generated/dns.csv    # trains a DGA / tunnel classifier
```

- `flows.csv` — 5 classes (benign, ddos, recon_scan, c2_beacon, exfiltration); benign models
  iperf3/HTTP/DNS/keepalive, ddos models hping3 SYN+UDP floods and Slowloris.
- `dns.csv` — 3 classes (benign, dga, dns_tunnel); DGA uses arithmetic and dictionary algorithms,
  tunnelling models iodine/dnscat2 long high-entropy subdomains with TXT/NULL records.
- `DATASET.md` — provenance (which tool each class models) and exact row counts; fully reproducible
  from the seed.

Results are in [../docs/VALIDATION.md](../docs/VALIDATION.md). This is the fastest path to a live AI
model; CIC-IDS2017 remains the independent public cross-check.

## Training / validation approach

- **Split:** temporal for CIC-IDS2017 (`--csv-dir`) — the tail of the capture is the test set, so the
  model is never evaluated on flows that preceded its training data. Stratified for the synthetic
  demo. Set with the data source; see `ml/train.py`.
- **Model selection:** gradient boosting needs no feature scaling, handles skewed counts, trains in
  seconds and exposes permutation importances for explanation.
- **Metrics:** per-class precision / recall / F1 and macro-F1 on the held-out split, written into the
  model card JSON and printed by the trainer.
- **Explainability:** permutation feature importances are stored and surfaced as each alert's
  `top_factors`; per-alert evidence compares the flow's values against benign means.

## Demo model (runnable before the dataset is downloaded)

`python ml/train.py --synthetic` (or the richer `--csv data/generated/flows.csv`) trains on
fabricated flows to prove the end-to-end wiring and give a live model with no download. **Synthetic
metrics are not evidence of real-world accuracy** — CIC-IDS2017 is the independent cross-check.
Current model: `HistGradientBoostingClassifier`, macro-F1 ≈ 0.95 (ddos/recon_scan overlap because
both are small SYN flows at the flow level).

## Artifacts

`train.py` writes two files into `ml/artifacts/` (git-ignored; regenerate any time):

- `flow_classifier.joblib` — the fitted model.
- `flow_classifier.meta.json` — the model card: feature order, classes, importances, benign means,
  metrics, split, timestamp and the model's SHA-256 (verified on load).
