# Models — the detection layer

Detection is a **hybrid**: always-on statistical detectors provide the floor, and a supervised model
adds a dataset-trained opinion on the flow-observable classes. Every detector — statistical or ML —
emits the same explainable `Detection` object, so fusion, the alert schema and the dashboard treat
them identically.

## Why hybrid, not ML-only

- The enclave is **offline and air-gapped**; a purely-ML system that needs constant retraining or
  cloud inference does not fit. The statistical detectors work on day one, with zero training, and
  degrade gracefully to flow-only input.
- Explainability is a hard requirement for a SOC analyst. Both layers explain themselves: statistical
  detectors via weighted per-feature contributions, the model via permutation importances.
- ML refines, it does not gate: if the model is absent or unsure, the statistical layer still fires.

## Statistical detectors (always on)

| Detector | Class | Method |
| --- | --- | --- |
| `ddos-stat` | Volumetric / protocol DDoS | EWMA baseline + robust z-score on flow rate; source-IP entropy; SYN-without-handshake ratio; amplification byte ratio |
| `beacon-score` | Botnet C2 beaconing | Inter-arrival coefficient of variation; repetition count; destination prevalence |
| `dns-lexical` | DGA + DNS tunnelling | Name entropy; rare-bigram ratio; NXDOMAIN rate; subdomain length/uniqueness; TXT/NULL share |
| `tls-meta` | Malware in encrypted sessions | JA3/JA4 fingerprint rarity; missing SNI; offline blocklist match; SPLT — no decryption |
| `scan-trw` | Reconnaissance / scanning | Threshold Random Walk (Jung et al., 2004) on first-contact failures; fan-out shape |
| `exfil-baseline` | Data exfiltration | Upload volume vs. per-host EWMA baseline; out/in ratio; PCR; first-contact destination |

Each combines its features with a **logistic signal model** (`core/scoring.py`): a feature exactly at
its threshold scores 0.5; contributions are weighted into one confidence and ranked as `top_factors`.

## Supervised model — `ml-flow` (opt-in)

- **Algorithm:** gradient-boosted trees (`HistGradientBoostingClassifier`).
- **Trained on:** CIC-IDS2017 labelled flows (see [`../ml/README.md`](../ml/README.md)).
- **Covers:** DDoS, scanning, botnet C2, exfiltration — the classes a flow record can express. It is
  exactly the flow-only degradation set, so it is the "brain" when no packet payload is available.
- **Config-driven:** switched on by `ml_model_dir` in the config. Off by default, so the reproducible
  demo runs on the statistical detectors alone.
- **Roadmap models** (interfaces ready): a character-CNN for DGA and an Isolation Forest for
  unsupervised exfil/anomaly — both plug into the same `Detection` interface.

## Fusion

Detections become alerts in `fusion/`:

- **Asset-weighted severity** = confidence × class impact × asset criticality, bucketed low→critical.
- **De-duplication** within a suppression window per (class, entity), incrementing `events_merged`.
- **Campaign correlation:** distinct stages on one host within 15 minutes are linked into a single
  incident with growing confidence.
- Every alert is appended to a **hash-chained, tamper-evident** evidence log (SHA-256 chain).
