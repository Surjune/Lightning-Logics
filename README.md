# Enclave Threat Console

**Passive, one-way AI/ML detection of cyber threats in unidirectional IP traffic.**
Reference prototype for SIH Problem Statement **26145** (NTRO).

Traffic is copied one way into a monitoring enclave through a passive TAP or a hardware
data diode. Nothing can travel back. This pipeline turns that one-way stream into
real-time, scored, explainable alerts for six threat classes, using only passively
observed metadata — it never decrypts, never probes, and never blocks.

---

## What it detects

| Class | Detector | Signal |
| --- | --- | --- |
| Volumetric / protocol DDoS | `ddos-stat` | flow-rate z-score, source-IP entropy, SYN-without-handshake ratio, amplification byte ratio, TTL spread |
| Botnet C2 beaconing | `beacon-score` | inter-arrival regularity (CV), session-size regularity, repetitions, destination prevalence |
| DGA + DNS tunnelling | `dns-lexical` | name entropy, rare-bigram ratio, NXDOMAIN rate; subdomain length, uniqueness, TXT/NULL share |
| Malware in encrypted sessions | `tls-meta` | JA3/JA4 fingerprint, local rarity, missing SNI, offline blocklist match (no decryption) |
| Reconnaissance / scanning | `scan-trw` | Threshold Random Walk on failed first contacts, fan-out shape (vertical/horizontal/block) |
| Data exfiltration | `exfil-baseline` | upload volume vs per-host baseline, out/in ratio, producer-consumer ratio, first-contact destination |

Plus **campaign correlation**: stages on one host within 15 minutes are linked into a single incident.

## Architecture

```
replay / live mirror / NetFlow   (simulated diode: one-way, enclave has no route out)
   -> ingest (pcap reader | NetFlow v5 collector)         read-only; SHA-256 of every capture
   -> flow meter + DNS/TLS metadata (JA3, JA4, SPLT)      active 5s / idle 15s / unanswered 2s
   -> bounded bus (files backpressure, live drop-and-count)
   -> 6 detectors (statistics now; ML plugs into the same interface)
   -> fusion (allowlist, asset-weighted severity, de-dup, campaign correlation)
   -> hash-chained evidence log + REST/WebSocket API + dashboard
```

Layering (dependencies flow one way): `cli/api -> pipeline -> detectors -> features ->
fusion -> ingest/sinks -> core`. `core/` imports nothing above it. Every threshold lives
in `core/constants.py` with its reasoning.

## Quick start

Requires Python 3.11+ (developed on 3.12).

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate      Linux/macOS:  source .venv/bin/activate
pip install -e ".[dev]"

# 1. generate the labelled synthetic demo capture + matching offline intel
enclave synth --out data/demo.pcap --intel intel

# 2. replay it and open the dashboard at http://127.0.0.1:8000
enclave replay data/demo.pcap --speed 6 --config config/enclave.example.json --serve

# 3. replay as fast as possible, print a summary (throughput check)
enclave replay data/demo.pcap --speed 0 --config config/enclave.example.json

# 4. flow-only mode: listen for NetFlow v5 (feed with softflowd or a router)
enclave netflow --listen 127.0.0.1:2055 --config config/enclave.example.json --serve

# 5. verify the tamper-evident evidence chain
enclave verify-log var/alerts.jsonl

# 6. print the standardised alert JSON schema
enclave schema
```

Run without `--serve` to just process and print a summary. `--speed 0` means "as fast as
possible"; any positive number is a real-time multiplier.

## The five architectural constraints, and how each is met

| Constraint | How | Proof |
| --- | --- | --- |
| **Read-only ingest** | Listen-only sources; no active modules; `egress_guard` blocks any outbound `connect`/`sendto` at process level | Test raises `EgressAttemptError`; dashboard shows blocked-attempt count |
| **No payload decryption** | Only the cleartext TLS ClientHello, packet sizes and timing are parsed; QUIC Initial packets are left sealed by design | The TLS parser stops after the handshake; no key material anywhere |
| **Streaming, not batch** | Event-time windows, 5 s flow active timeout, per-second detector flush, alerts emitted mid-flow | Per-alert processing latency reported as p50/p95 |
| **Defined throughput target** | Target: 20,000 flows/s sustained on a 4-core laptop | Replay with `--speed 0` reports events/s, latency and drops (fill in measured numbers) |
| **Standard alert schema** | Pydantic `Alert` exported as JSON Schema; Community ID flow id; evidence, factors, MITRE, custody hashes | `GET /api/schema/alert` / `enclave schema` |

## Alert schema

Every alert carries: `alert_id`, `detected_at`, `event_start/end`, `flow_id` (Community ID
v1), `src`, `dst`, `dst_port`, `proto`, `sensor_id`, `input_mode`, `host`, `threat_class`,
`sub_type`, `confidence` (0–1), `severity` + `severity_score`, `asset`, `model`,
`mitre_attack`, a human `summary` and `suggested_action`, an `evidence` map (observed vs
reference for each feature), `top_factors` (the weighted contributions that explain the
decision), `events_merged`, `related_alert_ids`, `processing_latency_ms`, and a `custody`
block (capture source ref + previous/this alert hash).

### Chain of custody

Each new alert is appended to `var/alerts.jsonl`, where every line stores the previous
line's hash and `SHA-256(prev_hash + canonical_record)`. Editing any past line breaks every
hash after it. `enclave verify-log` recomputes the chain. This is the "Blockchain &
Cybersecurity" theme applied as a lightweight, tamper-evident evidence ledger.

## Graceful degradation

| Input | Detectors that run |
| --- | --- |
| Packets (pcap / mirror) | all six |
| NetFlow / IPFIX / sFlow only | DDoS, beaconing, scanning, exfiltration (DNS + TLS detectors switch off, and say why) |

## Offline intelligence

The enclave never fetches intelligence. Blocklists (JA3/JA4/domains) live in `intel/` with a
`manifest.json` of SHA-256 hashes; a mismatch refuses to load. Regenerate the manifest with
`enclave intel-manifest intel`.

## Repository layout

```
src/enclave/
  core/      constants, config, logging, exceptions, stats, scoring, lru
  schema/    events (FlowRecord, DnsEvent, TlsEvent), alert (Alert JSON schema)
  ingest/    pcap_source, netflow_source, flowmeter, community_id, parsers/{dns,tls}
  features/  windows, lexical (DGA features)
  detectors/ ddos, beacon, dns, tls, scan, exfil, registry, base
  fusion/    engine (severity, de-dup), correlator (campaigns)
  sinks/     store (alert store, WebSocket fan-out, hash-chained log, verifier)
  intel.py   offline intelligence loader with hash verification
  egress_guard.py  process-level outbound block
  metrics.py, pipeline.py, synth.py, cli.py
  api/       FastAPI REST + WebSocket + static dashboard
tests/       mirrors src/enclave; unit tests + end-to-end scenario
```

## Development

```bash
pytest -q            # 21 tests, no network calls
ruff check src tests # lint
mypy                 # strict type checking
```

## Known limitations (deliberately deferred)

- **ML layer** (LightGBM / Isolation Forest / character-CNN) is designed and interfaced but
  not yet trained in this prototype; the statistical layer runs today and ML refines it.
- **IPFIX / NetFlow v9 / sFlow**: only NetFlow v5 is decoded here; the intended path is a
  `goflow2` front end whose JSON the pipeline consumes.
- **Benchmark harness** for fixed-rate throughput runs is not yet included; `--speed 0`
  gives a first measurement.
- **Docker Compose** with a simulated diode and an internal-only network is on the roadmap;
  the `egress_guard` already enforces the one-way rule at process level.
- Payload-level attacks inside encrypted sessions and very slow-and-low exfiltration are out
  of scope for a metadata-only system; this is a monitoring layer within defence in depth.

Throughput and accuracy figures must come from your own measured runs; targets in this repo
are goals to verify, not results.

## Authorisation note

Generate attack traffic only inside an isolated lab network you own, with approval. The
built-in `enclave synth` generator fabricates a labelled capture directly on disk and never
sends anything on a network, so it is safe to run anywhere.
