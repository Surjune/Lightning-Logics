# Feature engineering — what we measure and why

Every feature is computed from **passively observed metadata only**: no decryption, no probes, no
handshake completion. Features are grouped by the signal they expose. Thresholds referenced here
live in [`src/enclave/core/constants.py`](../src/enclave/core/constants.py), each with its reasoning.

## Flow metrics (the backbone)

A flow is one conversation, keyed by the 5-tuple and identified across tools by **Community ID v1**
(a hash of the canonicalised 5-tuple, so both directions share one ID). From each flow we derive:

| Feature | Why it matters |
| --- | --- |
| duration, packets, bytes (per direction) | Raw shape of the conversation; the basis of every rate. |
| bytes/s, packets/s | Volumetric floods and amplification show up as rate outliers vs. an EWMA baseline. |
| forward/backward byte & packet ratios | Scans and floods are one-sided; exfiltration is upload-heavy. |
| `down_up_ratio`, **PCR** = (out−in)/(out+in) | Producer–Consumer Ratio cleanly separates a client (consumes) from a host that is *sending* data out (exfiltration). |
| SYN-without-SYN/ACK ratio | A handshake that never completes is the signature of SYN floods and half-open scans — visible without us answering. |
| source-IP Shannon **entropy** | Spoofed floods draw from a huge random source range (high entropy); a flash crowd does not. |
| TTL spread | Many different TTLs toward one target suggest spoofed or widely distributed sources. |

Flows are exported every 5 s (active timeout) so long flows raise alerts incrementally rather than
only at the end — this is what makes the pipeline *streaming*, not batch.

## SPLT — Sequence of Packet Lengths and Times

For each flow we keep the signed sizes and inter-arrival gaps of the first ~20 packets (Cisco ETA and
the SPLT literature use 10–20). This captures the **rhythm and shape** of a session — request/response
sizing, burstiness — which survives encryption because sizes and timings are visible even when the
payload is not. It is a primary feature for distinguishing malware channels from normal TLS without
ever decrypting anything.

## TLS fingerprints — JA3 and JA4 (no decryption)

TLS negotiates in the clear before it encrypts. We parse **only the ClientHello** and stop:

- **JA3** hashes the ordered list of TLS version, cipher suites, extensions, curves and formats — a
  fingerprint of the *client library*, not the user or the content.
- **JA4** is the modern successor: more structured (protocol, SNI presence, cipher/extension counts,
  ALPN) and **GREASE-aware**, so randomised GREASE values don't change the fingerprint. It is more
  robust to the churn that made JA3 noisy.

A rare JA3/JA4 on a host that normally shows a handful of them, or one matching an offline blocklist,
flags a suspicious client stack — malware often ships a distinctive TLS library. **QUIC** Initial
packets are left sealed by design: unprotecting them is decryption, which the constraints forbid, so
we use only cleartext long-header fields, sizes and timing.

Why fingerprints and not payload: the PS forbids decryption, and JA3/JA4 give strong client identity
from the one part of the session that is legitimately in the clear.

## DNS lexical features (DGA & tunnelling)

DNS queries are cleartext, so we read the query names directly:

- **Character entropy** and **rare-bigram ratio** — algorithmically generated domains (DGA) look
  random and score high; real domains use common letter pairs.
- **NXDOMAIN rate per host** — DGA malware tries many non-existent domains before one resolves.
- **Subdomain length, uniqueness, and TXT/NULL record share** — DNS tunnelling smuggles data in long,
  unique, high-entropy subdomains and unusual record types.

## Detection statistics built on these features

- **EWMA baseline + robust z-score / MAD** — per-entity "normal", so alerts are relative to each
  target, not a global constant.
- **Threshold Random Walk** (Jung et al., 2004) — sequential hypothesis test on first-contact
  successes vs. failures; the rigorous way to call a scanner from fan-out with few false positives.
- **Interval coefficient of variation** — near-constant inter-arrival gaps toward a small set of
  destinations is the signature of C2 beaconing.
- **Logistic signal combination** — each feature is scored on a logistic curve centred on its
  threshold, then weighted into one confidence, with per-feature contributions exposed as the alert's
  explanation (the statistical analogue of SHAP values).

## Supervised model features

The `ml-flow` classifier uses the 17 leakage-safe flow features in
[`ml/README.md`](../ml/README.md), trained on CIC-IDS2017. It reuses the flow metrics above; the same
`derive_features()` function computes them at training and inference time.
