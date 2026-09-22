# Validation — methodology and metrics

This documents how detection quality is measured and where the numbers come from. **Fill the
CIC-IDS2017 table from your own training run** (`python ml/train.py --csv-dir data/cicids2017` writes
the metrics into `ml/artifacts/flow_classifier.meta.json`); the synthetic-demo numbers below are real
but only prove the wiring.

## Datasets

| Dataset | Role | Classes it validates |
| --- | --- | --- |
| **CIC-IDS2017** | Primary training + validation for `ml-flow` | DDoS/DoS, PortScan, Bot, Infiltration |
| CIC-DDoS2019 | Cross-dataset DDoS test | DDoS subtypes |
| CTU-13 / Stratosphere | Real botnet C2 | beaconing |
| CIC-Bell-DNS-EXF-2021 | DNS exfiltration | tunnelling / exfil |
| Tranco top-1M | Benign domain baseline | DGA false-positive rate |
| abuse.ch SSLBL | JA3 blocklist (offline import) | encrypted-malware fingerprints |
| **Generated (`ml/generate_dataset.py`)** | Trainable dataset with no download (PS option a) | flow classes + DGA/tunnel |
| `enclave synth` | Reproducible end-to-end demo | all six + campaign correlation |

Get CIC-IDS2017 from <https://www.unb.ca/cic/datasets/ids-2017.html> (see [`../ml/README.md`](../ml/README.md)).

## Methodology (avoiding the usual traps)

- **Temporal split, not random.** For CIC-IDS2017 the test set is the tail of the capture, so the
  model is never scored on flows that preceded its training data. Random splits leak time-correlated
  flows and inflate scores.
- **No identifier features.** IPs, ports and timestamps are excluded from model input, so accuracy
  cannot come from memorising addresses.
- **Cross-dataset check (recommended).** Train on CIC-IDS2017, test on a different capture
  (CIC-DDoS2019 or your own lab pcap) to measure real generalisation.
- **Metrics reported:** per-class **precision, recall, F1**, plus macro-F1; false positives per hour
  on benign-only replay; detection latency (p50/p95). Calibration (ECE) is a roadmap item.

## Metric definitions

- **Precision** = TP / (TP + FP): of the alerts raised for a class, how many were correct. Drives
  analyst trust.
- **Recall** = TP / (TP + FN): of the real events of a class, how many we caught.
- **F1** = harmonic mean of precision and recall. **Macro-F1** averages F1 across classes equally, so
  a rare class cannot be ignored.

## Results — supervised `ml-flow`

### Real-data false-positive validation (CIC-IDS2017 Monday, benign-only)

The single most important result. We scored **real** CIC-IDS2017 benign flows (the Monday capture,
458,831 benign flows, IP/port/timestamp stripped) with the flow classifier, and measured how often it
wrongly flags benign traffic:

| Model trained on… | False positives on 20,000 real benign flows |
| --- | --- |
| synthetic benign | 7,205 = **36.0%** |
| **real benign** (this capture) + synthetic attacks | 6 = **0.03%** |

Real benign traffic is exactly what a synthetic generator gets wrong, so training the benign class on
a genuine capture collapses the false-positive rate by three orders of magnitude while attack recall
stays at 1.00 (synthetic). This is the shipped model. Reproduce:

```bash
python ml/train.py --real-benign "Benign-Monday-no-metadata.parquet"   # .parquet or .csv, file or dir
```

**Shipped model** (`real-benign+synthetic-attacks`, stratified split, 30,000 test rows):

| Class | Precision | Recall | F1 |
| --- | --- | --- | --- |
| benign | 1.00 | 1.00 | 1.00 |
| c2_beacon | 1.00 | 1.00 | 1.00 |
| ddos | 0.89 | 0.88 | 0.88 |
| exfiltration | 1.00 | 1.00 | 1.00 |
| recon_scan | 0.88 | 0.89 | 0.88 |
| **macro avg** | **0.95** | **0.95** | **0.95** |

> Attack recall here is still validated on *synthetic* attacks. To validate it on **real** attacks,
> add the CIC-IDS2017 attack-day files (Tuesday–Friday: DoS, DDoS, PortScan, Bot, Infiltration) to a
> folder and run `python ml/train.py --csv-dir <folder>` for full real-data multiclass metrics.


### CIC-IDS2017 (fill after training)

| Class | Precision | Recall | F1 | Support |
| --- | --- | --- | --- | --- |
| benign | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| ddos | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| recon_scan | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| c2_beacon | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| exfiltration | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| **macro avg** | _tbd_ | _tbd_ | _tbd_ | |

> After `python ml/train.py --csv-dir data/cicids2017`, copy the per-class numbers from
> `ml/artifacts/flow_classifier.meta.json` (`metrics.per_class`) into this table.

### Generated dataset (PS option a — no download required)

`ml/generate_dataset.py` writes a 40,000-row flow dataset (5 classes, modelling iperf3/hping3/
Slowloris/scan/C2/exfil signatures) and a 24,000-row DNS dataset (DGA + tunnelling). Train with:

```bash
python ml/generate_dataset.py
python ml/train.py --csv data/generated/flows.csv     # flow classifier
python ml/train_dga.py --csv data/generated/dns.csv   # DGA / tunnel classifier
```

**Flow classifier** (`HistGradientBoostingClassifier`, held-out stratified split, 12,000 test flows):

| Class | Precision | Recall | F1 |
| --- | --- | --- | --- |
| benign | 0.99 | 0.99 | 0.99 |
| c2_beacon | 0.99 | 0.99 | 0.99 |
| ddos | 0.89 | 0.86 | 0.87 |
| exfiltration | 1.00 | 1.00 | 1.00 |
| recon_scan | 0.86 | 0.89 | 0.88 |
| **macro avg** | **0.95** | **0.95** | **0.95** |

The ddos/recon_scan overlap is expected — both are small SYN flows at the flow level; rate and
fan-out (which the statistical `ddos-stat`/`scan-trw` detectors use across flows) separate them.

**DGA / DNS-tunnel classifier** (10 lexical features, 7,200 test names): precision/recall/F1 = **1.00**
for all of benign / dga / dns_tunnel. This near-perfect score reflects the clean separation of
*synthetic* names (random DGA vs. dictionary words); real dictionary-DGA families are harder, so treat
this as a wiring/feature validation, and cross-check on DGArchive samples.

> These numbers come from a self-consistent synthetic dataset. CIC-IDS2017 (above) is the
> independent, public cross-check — fill its table from your own run.

## End-to-end system validation (statistical layer)

The automated end-to-end test (`tests/test_pipeline_e2e.py`) replays the labelled synthetic capture
and asserts that **all six threat classes plus campaign correlation fire**, every alert carries
evidence and an explanation, the tamper-evident chain verifies, and flow-only mode disables the
DNS/TLS detectors. Run `pytest -q` (27 tests, no network calls).

## Throughput & latency (state your measured numbers)

Target: 20,000 flows/s sustained, p95 processing latency ≤ 5 s. Measure on your hardware:

```bash
enclave replay data/demo.pcap --speed 0 --config config/enclave.example.json
```

The summary reports events/s, latency p50/p95 and dropped records. Record the measured figures in the
README — a stated, demonstrated number is required by PS constraint (d).
