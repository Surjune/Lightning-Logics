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

### Synthetic demo (wiring proof only — not real-world accuracy)

`HistGradientBoostingClassifier`, held-out stratified split, 9,000 test flows:

| Class | Precision | Recall | F1 |
| --- | --- | --- | --- |
| benign | 1.00 | 1.00 | 1.00 |
| c2_beacon | 1.00 | 1.00 | 1.00 |
| ddos | 0.89 | 0.85 | 0.87 |
| exfiltration | 1.00 | 1.00 | 1.00 |
| recon_scan | 0.86 | 0.89 | 0.87 |
| **macro avg** | **0.95** | **0.95** | **0.95** |

The ddos/recon_scan overlap is expected: in the synthetic generator both are small SYN flows. Real
CIC-IDS2017 separates them on rate and fan-out.

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
