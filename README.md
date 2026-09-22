# Enclave Threat Console

**Passive, one-way AI/ML detection of cyber threats in unidirectional IP traffic.**
Reference prototype for a Smart India Hackathon problem statement.

Critical-infrastructure links are copied one way into a monitoring enclave through a passive TAP or a
hardware data diode — nothing can travel back. This pipeline turns that one-way stream into real-time,
scored, **explainable** alerts for six threat classes, using only passively observed metadata. It
never decrypts, never probes, and never blocks. Detection is a **hybrid**: always-on statistical
detectors plus two supervised ML models trained on real CIC-IDS2017 traffic.

---

## What it detects

| Class | Statistical detector | ML |
| --- | --- | --- |
| Volumetric / protocol DDoS | `ddos-stat` — flow-rate z-score, source-IP entropy, SYN-without-handshake, amplification ratio | `ml-flow` |
| Botnet C2 beaconing | `beacon-score` — inter-arrival regularity (CV), repetitions, destination prevalence | `ml-flow` |
| DGA + DNS tunnelling | `dns-lexical` — name entropy, rare-bigram ratio, NXDOMAIN rate, subdomain shape, TXT/NULL share | `dga-ml` |
| Malware in encrypted sessions | `tls-meta` — JA3/JA4 fingerprint, rarity, missing SNI, offline blocklist (no decryption) | — |
| Reconnaissance / scanning | `scan-trw` — Threshold Random Walk on failed first contacts, fan-out shape | `ml-flow` |
| Data exfiltration | `exfil-baseline` — upload vs per-host baseline, out/in ratio, producer-consumer ratio | `ml-flow` |

Plus **campaign correlation** — stages on one host within 15 minutes are linked into one incident.

The two supervised models are the **AI/ML layer**: `ml-flow` (gradient-boosted flow classifier) and
`dga-ml` (gradient-boosted DNS-name classifier). Both run live beside the statistical detectors and
are opt-in via `ml_model_dir`, so the reproducible demo runs on the statistical layer alone.
See [docs/MODELS.md](docs/MODELS.md) · [docs/FEATURES.md](docs/FEATURES.md) · [ml/README.md](ml/README.md).

## Results (measured)

- **Throughput** ~12,000 flows/s (detection engine, single process), **p95 latency ~2 ms** — `enclave bench`
- **`ml-flow`** on real CIC-IDS2017: **0.03% false positives** on real benign, **DDoS F1 0.99**, **C2 F1 0.98**, macro-F1 0.99
- **Quality gates**: 38 tests pass · `ruff` clean · `mypy --strict` clean

Full methodology and per-class tables in [docs/VALIDATION.md](docs/VALIDATION.md).

## The five architectural constraints

| Constraint | How it is met |
| --- | --- |
| **Read-only ingest** | Listen-only sources; `egress_guard` blocks any outbound `connect`/`sendto` at process level (test raises `EgressAttemptError`) |
| **No payload decryption** | Only the cleartext TLS ClientHello, packet sizes and timing are parsed; QUIC Initial packets stay sealed |
| **Streaming, not batch** | Event-time windows, 5 s flow active timeout, per-second flush, alerts emitted mid-flow; p50/p95 latency reported |
| **Defined throughput** | ~12,000 flows/s demonstrated (`enclave bench`); `--workers N` shards across cores |
| **Standard alert schema** | Pydantic `Alert` → JSON Schema; Community ID flow id; evidence, factors, MITRE, custody hashes (`enclave schema`) |

## Quick start

Requires Python 3.11+ (developed on 3.12).

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate      Linux/macOS:  source .venv/bin/activate
pip install -e ".[dev]"

# 1  generate the labelled demo capture + offline intel
enclave synth --out data/demo.pcap --intel intel

# 2  replay it and open the dashboard at http://127.0.0.1:8000
enclave replay data/demo.pcap --speed 6 --config config/enclave.example.json --serve

# 3  demo server with a file-upload endpoint (drop in a pcap, watch alerts)
enclave serve --config config/enclave.example.json --port 8000

# 4  live capture off an interface (the real diode feed), via a streaming pcap
tcpdump -i eth1 -U -w - | enclave sniff --serve            # Windows: dumpcap -i 5 -w - | enclave sniff --serve

# 5  flow-only: NetFlow v5 collector, or v9 / IPFIX / sFlow through goflow2
enclave netflow  --listen 127.0.0.1:2055 --config config/enclave.example.json --serve
goflow2 -format json | enclave flow-json --config config/enclave.example.json --serve

# utilities
enclave bench --flows 200000        # throughput of the detection engine
enclave verify-log var/alerts.jsonl # verify the tamper-evident evidence chain
enclave schema                      # print the standardised alert JSON Schema
```

`--speed 0` means "as fast as possible"; any positive number is a real-time multiplier. Omit `--serve`
to just process and print a summary.

## Train the ML layer

```bash
pip install -e ".[train]"

python ml/generate_dataset.py                            # data/generated/{flows,dns}.csv (no download)
python ml/train.py --csv-dir data/cicids2017 --augment   # flow model on real CIC-IDS2017 (.csv/.parquet)
python ml/train_dga.py --csv data/generated/dns.csv      # DGA / DNS-tunnel model

# enable ML on REAL / live traffic (not the synthetic demo — see limitations)
tcpdump -i eth1 -U -w - | enclave sniff --config config/enclave.ml.example.json --serve
```

Get CIC-IDS2017 from the [dhoogla mirror](https://www.kaggle.com/datasets/dhoogla/cicids2017); details
in [ml/README.md](ml/README.md).

## Alert schema & chain of custody

Every alert carries `alert_id`, timestamps, `flow_id` (Community ID v1), 5-tuple, `sensor_id`,
`threat_class` / `sub_type`, `confidence`, `severity` (+ score), `asset`, `model`, `mitre_attack`, a
human `summary` + `suggested_action`, an `evidence` map (observed vs reference), `top_factors` (the
weighted contributions that explain the decision), and a `custody` block.

Each alert is appended to `var/alerts.jsonl` as `SHA-256(prev_hash + record)`. Editing any past line
breaks every hash after it; `enclave verify-log` recomputes the chain. This is the **Blockchain &
Cybersecurity** theme as a lightweight, tamper-evident evidence ledger.

## Architecture

```
replay / live capture / NetFlow / goflow2   (one-way; the enclave has no route out)
  → ingest (read-only; SHA-256 of every capture)
  → flow meter + DNS/TLS metadata (JA3, JA4, SPLT)      active 5s / idle 15s / unanswered 2s
  → bounded bus (files backpressure; live drop-and-count)
  → 8 detectors (6 statistical + ml-flow + dga-ml, one Detection interface)
  → fusion (allowlist, asset-weighted severity, de-dup, campaign correlation)
  → hash-chained evidence log + REST/WebSocket API + dashboard
```

Dependencies flow one way: `cli/api → pipeline → detectors → features/fusion → ingest/sinks → core`.
`core/` imports nothing above it; every threshold lives in `core/constants.py` with its reasoning.

**Graceful degradation** — packet input runs all detectors; flow-only input (NetFlow/IPFIX/sFlow)
runs DDoS, beaconing, scanning and exfiltration, and the DNS/TLS detectors switch off and say why.

## Repository layout

```
src/enclave/
  core/       constants, config, logging, exceptions, stats, scoring, lru
  schema/     events (FlowRecord, DnsEvent, TlsEvent), alert (JSON Schema)
  ingest/     pcap_source, live_source, netflow_source, json_flow_source, flowmeter, parsers/{dns,tls}
  features/   windows, lexical (DGA features)
  ml/         features (flow), dns_features, model (hash-verified inference loaders)
  detectors/  ddos, beacon, dns, tls, scan, exfil, ml_flow, dga_ml, registry, base
  fusion/     engine (severity, de-dup), correlator (campaigns)
  sinks/      store (alert store, WebSocket fan-out, hash-chained log, verifier)
  api/        FastAPI REST + WebSocket + dashboard + upload/analyze
  intel.py · egress_guard.py · metrics.py · pipeline.py · bench.py · synth.py · cli.py
ml/           offline training: generate_dataset, datasets, train, train_dga, model card
deploy/       systemd unit · docs/ (MODELS, FEATURES, VALIDATION, DEPLOYMENT) · tests/
```

## Deployment

Runs on-premises / offline by design. A host-agnostic Docker image also serves the dashboard + upload
endpoint for a public try-it link, and `docker compose` / systemd run it 24/7. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

```bash
docker compose up -d                 # continuous, restarts on crash/reboot
# or a one-off container:
docker build -t enclave-console . && docker run -p 8000:8000 enclave-console
```

## Development

```bash
pytest -q             # 38 tests, no network calls
ruff check src tests ml
mypy                  # strict type checking
```

## Known limitations (deliberately deferred)

- **Run ML on real traffic, not the synthetic demo.** `ml-flow` is validated on real CIC-IDS2017
  (0.03% false positives on real benign), but the demo pcap's *synthetic* benign flows differ, so it
  over-flags there; the demo showcases the statistical detectors. `dga-ml` is distribution-robust and
  runs cleanly on either.
- **Exfiltration metrics are synthetic** — CIC-IDS2017's Infiltration class is only ~36 rows.
- **Throughput** ~12,000 flows/s single-process; the 20,000 flows/s stretch target needs multi-core
  sharding (`--workers`) or hot-path optimisation.
- **Roadmap models** (interfaces ready): a character-CNN for DGA and an Isolation Forest for
  unsupervised anomaly, both plugging into the same `Detection` interface.
- Payload-level attacks inside encrypted sessions and very slow-and-low exfiltration are out of scope
  for a metadata-only system — this is one layer within defence in depth.

Re-measure throughput and accuracy on your own hardware.

## Authorisation

Generate attack traffic only inside an isolated lab you own, with approval. The built-in
`enclave synth` fabricates a labelled capture directly on disk and never sends anything on a network,
so it is safe to run anywhere.
