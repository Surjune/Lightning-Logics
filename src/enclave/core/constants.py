"""Every threshold, weight and physical constant used by the pipeline.

Each value carries the reasoning behind it. Detectors import from here; a bare
numeric literal in detector or fusion code is a review failure.
"""

from __future__ import annotations

from typing import Final

SCHEMA_VERSION: Final = "1.0"

# --- Protocol numbers (IANA "Assigned Internet Protocol Numbers") -------------------------------
PROTO_ICMP: Final = 1
PROTO_TCP: Final = 6
PROTO_UDP: Final = 17
PROTO_ICMPV6: Final = 58

# --- Well-known ports --------------------------------------------------------------------------
PORT_DNS: Final = 53
PORT_HTTPS: Final = 443
PORT_MODBUS: Final = 502

# UDP services abused for reflection/amplification (US-CERT TA14-017A amplification table).
AMPLIFICATION_PORTS: Final[frozenset[int]] = frozenset({19, 53, 123, 161, 389, 1900, 11211})

# --- Flow metering ----------------------------------------------------------------------------
# Long flows are exported every ACTIVE timeout so alerts never wait for a flow to end.
# 5 s keeps time-to-detect well inside the latency budget; NetFlow defaults are 60-1800 s.
FLOW_ACTIVE_TIMEOUT_S: Final = 5.0
# A flow with no packets for this long is finished (Linux conntrack uses 30-120 s for UDP;
# shorter here because the enclave only needs statistics, not session state).
FLOW_IDLE_TIMEOUT_S: Final = 15.0
# A flow that never got a reply (SYN-only TCP, one-way UDP) is closed quickly so floods and
# scans surface within seconds (mirrors conntrack's short SYN_SENT handling).
FLOW_UNANSWERED_IDLE_TIMEOUT_S: Final = 2.0
# Ports at or above this are ephemeral client ports (IANA dynamic range starts at 49152;
# most stacks hand out anything above 1023, so 1024 is the practical split).
EPHEMERAL_PORT_MIN: Final = 1024
# Hard memory bound for the flow table; the oldest flows are force-exported beyond this.
FLOW_TABLE_MAX: Final = 500_000
# Packet-size/timing sequence length kept per flow (Cisco ETA and most SPLT papers use 10-20).
SPLT_LENGTH: Final = 20
# Timeout sweeps run at most this often (event time) to keep per-packet cost flat.
FLOW_SWEEP_INTERVAL_S: Final = 1.0

# --- Stream processing ------------------------------------------------------------------------
# Detectors are flushed each time event time advances by this much.
PIPELINE_TICK_S: Final = 1.0
# Bounded queue between ingest and analysis. Live sources drop (and count) when full;
# file replays apply backpressure instead.
BUS_MAX_EVENTS: Final = 200_000
# Stated targets, shown on the dashboard and checked by the benchmark harness.
TARGET_FLOWS_PER_S: Final = 20_000
LATENCY_BUDGET_P95_S: Final = 5.0
LATENCY_RESERVOIR_SIZE: Final = 2_000
METRICS_EWMA_ALPHA: Final = 0.2

# --- Shared statistics ------------------------------------------------------------------------
# Baseline smoothing: alpha 0.1 ~ an effective memory of ~19 windows.
BASELINE_EWMA_ALPHA: Final = 0.1
# Windows needed before a baseline is trusted for z-scores.
BASELINE_MIN_SAMPLES: Final = 5
# Floor on baseline standard deviation so near-constant traffic cannot yield infinite z-scores.
BASELINE_MIN_STD_FRACTION: Final = 0.1
# Bounded LRU sizes for per-entity state (memory safety under spoofed-source floods).
ENTITY_STATE_MAX: Final = 100_000

# --- Signal combination (core.scoring) --------------------------------------------------------
# A feature exactly at its threshold scores 0.5; SIGNAL_STEEPNESS sets how fast it saturates.
SIGNAL_STEEPNESS: Final = 4.0

# Detections below this combined confidence are counted but not raised.
DETECTION_MIN_CONFIDENCE: Final = 0.5

# --- DDoS -------------------------------------------------------------------------------------
DDOS_WINDOW_S: Final = 5.0
# Reflection floods have few flows but many bytes: 10 Mbit/s of unsolicited answers.
DDOS_AMP_MIN_BYTES_PER_S: Final = 1_250_000
# Absolute floor: below this many new flows/s toward one target nothing is a flood.
DDOS_MIN_FLOWS_PER_S: Final = 500.0
DDOS_RATE_ZSCORE: Final = 6.0
# Share of new TCP flows that never completed a handshake.
DDOS_SYN_ONLY_RATIO: Final = 0.8
# 10 bits ~ 1,000 equally active sources; normal busy servers sit around 5-8 bits.
DDOS_SRC_ENTROPY_BITS: Final = 10.0
# Response bytes / request bytes toward a victim on amplification ports (DNS ANY ~ 50x).
DDOS_AMPLIFICATION_RATIO: Final = 10.0
DDOS_WEIGHTS: Final = {"flow_rate_z": 0.35, "syn_only_ratio": 0.25, "src_ip_entropy": 0.25, "amp_ratio": 0.15}

# --- Reconnaissance (Threshold Random Walk, Jung et al., IEEE S&P 2004) ------------------------
TRW_THETA_BENIGN: Final = 0.8      # P(connection succeeds | benign host)
TRW_THETA_SCANNER: Final = 0.2     # P(connection succeeds | scanner)
TRW_ALPHA: Final = 0.01            # tolerated false-positive probability
TRW_BETA: Final = 0.99             # required detection probability
SCAN_WINDOW_S: Final = 60.0
SCAN_MIN_DISTINCT_TARGETS: Final = 20
SCAN_FAILED_RATIO: Final = 0.5
# A scan is "vertical" when ports outnumber hosts by this factor, "horizontal" the reverse.
SCAN_SHAPE_RATIO: Final = 5.0
SCAN_WEIGHTS: Final = {"trw_score": 0.4, "distinct_targets": 0.35, "failed_ratio": 0.25}

# --- C2 beaconing -----------------------------------------------------------------------------
BEACON_MIN_CONNECTIONS: Final = 6
BEACON_HISTORY: Final = 64
# Sub-5 s repetition is normal application chatter, not a check-in schedule.
BEACON_MIN_INTERVAL_S: Final = 5.0
# Interval coefficient of variation: human traffic is > 0.6; 0.2 tolerates ~20 % jitter.
BEACON_MAX_INTERVAL_CV: Final = 0.2
BEACON_MAX_BYTES_CV: Final = 0.5
# A destination polled by many internal hosts is more likely a shared service.
BEACON_SHARED_DST_HOSTS: Final = 3
BEACON_WEIGHTS: Final = {"interval_regularity": 0.45, "size_regularity": 0.25, "repetitions": 0.2,
                         "dst_prevalence": 0.1}

# --- DNS: DGA + tunnelling --------------------------------------------------------------------
DNS_WINDOW_S: Final = 60.0
DGA_MIN_LABEL_LEN: Final = 8
# Real registered names average ~2.5-3.0 bits/char; random 12+ char strings exceed 3.3.
DGA_ENTROPY_BITS: Final = 3.3
# Share of letter pairs not in the common-English bigram set.
DGA_RARE_BIGRAM_RATIO: Final = 0.5
DGA_NAME_SCORE: Final = 0.6
DGA_MIN_NAMES_PER_WINDOW: Final = 20
DGA_NXDOMAIN_RATIO: Final = 0.5
DGA_WEIGHTS: Final = {"dga_like_names": 0.35, "nxdomain_ratio": 0.35, "mean_name_score": 0.3}
DGA_NAME_WEIGHTS: Final = {"char_entropy": 0.35, "rare_bigram_ratio": 0.35, "digit_ratio": 0.15,
                           "length": 0.15}
DGA_DIGIT_RATIO: Final = 0.2
DGA_LONG_LABEL: Final = 12
TUNNEL_WINDOW_S: Final = 300.0
# base32/base64 chunks used by iodine and dnscat2 are 40-63 characters; normal labels < 20.
TUNNEL_MIN_LABEL_LEN: Final = 40
TUNNEL_MIN_UNIQUE_SUBDOMAINS: Final = 100
TUNNEL_TXT_RATIO: Final = 0.5
TUNNEL_MAX_TRACKED_SUBDOMAINS: Final = 5_000
TUNNEL_WEIGHTS: Final = {"unique_subdomains": 0.35, "label_length": 0.35, "txt_null_ratio": 0.3}
DNS_TXT_LIKE_QTYPES: Final[frozenset[int]] = frozenset({10, 16})  # NULL, TXT
# Two-label public suffixes treated as one TLD when extracting the registered domain.
MULTI_LABEL_SUFFIXES: Final[frozenset[str]] = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "gov.in", "ac.in", "nic.in",
    "res.in", "com.au", "net.au", "co.jp", "com.cn", "com.br", "co.za",
})

# --- Encrypted sessions (TLS metadata only) ---------------------------------------------------
# Fingerprint rarity is meaningless until the sensor has seen normal traffic.
TLS_WARMUP_HANDSHAKES: Final = 200
TLS_RARE_MAX_HOSTS: Final = 1
TLS_MIN_CONFIDENCE: Final = 0.6
TLS_WEIGHTS: Final = {"blocklist_match": 0.5, "fingerprint_rarity": 0.3, "sni_absent": 0.2}

# --- Exfiltration -----------------------------------------------------------------------------
EXFIL_WINDOW_S: Final = 60.0
EXFIL_MIN_BYTES_OUT: Final = 50 * 1024 * 1024  # 50 MiB in one minute from one host
# Producer-consumer ratio (Chris Gerritz, 2015): +1 pure upload, -1 pure download.
EXFIL_PCR: Final = 0.8
EXFIL_ZSCORE: Final = 4.0
EXFIL_WEIGHTS: Final = {"upload_volume": 0.35, "pcr": 0.35, "upload_zscore": 0.3}
EXFIL_MAX_KNOWN_DESTINATIONS: Final = 1_000

# --- Fusion -----------------------------------------------------------------------------------
# Impact of each class before asset criticality; floods and theft rank highest.
CLASS_IMPACT: Final = {
    "ddos": 1.0, "c2_beacon": 0.9, "dga": 0.85, "dns_tunnel": 0.9, "encrypted_malware": 0.95,
    "recon_scan": 0.7, "exfiltration": 1.0, "campaign": 1.0,
}
# Asset weight = BASE + STEP * criticality(1..5) -> 0.7 .. 1.1
ASSET_WEIGHT_BASE: Final = 0.6
ASSET_WEIGHT_STEP: Final = 0.1
ASSET_DEFAULT_CRITICALITY: Final = 3
ASSET_MIN_CRITICALITY: Final = 1
ASSET_MAX_CRITICALITY: Final = 5
SEVERITY_SCORE_MAX: Final = 100
SEVERITY_CRITICAL: Final = 80
SEVERITY_HIGH: Final = 60
SEVERITY_MEDIUM: Final = 40
# Repeat detections for the same (class, entity) inside this window update one alert.
DEDUP_WINDOW_S: Final = 300.0
# Stages on one host inside this window are linked into a campaign.
CORRELATION_WINDOW_S: Final = 900.0
CORRELATION_MIN_STAGES: Final = 2
CORRELATION_CONFIDENCE: Final = 0.9
# Each extra linked stage adds this much confidence, capped below certainty.
CORRELATION_STAGE_BONUS: Final = 0.03
CORRELATION_MAX_CONFIDENCE: Final = 0.99
ALERT_STORE_MAX: Final = 5_000
TOP_FACTORS: Final = 5

# --- Community ID v1 (corelight/community-id-spec) --------------------------------------------
COMMUNITY_ID_SEED: Final = 0

# --- API --------------------------------------------------------------------------------------
API_DEFAULT_HOST: Final = "127.0.0.1"
API_DEFAULT_PORT: Final = 8000
API_ALERTS_DEFAULT_LIMIT: Final = 100
API_ALERTS_MAX_LIMIT: Final = 1_000

# --- Machine learning (supervised flow classifier) --------------------------------------------
# The ML flow-classifier covers the flow-observable classes (DDoS, scanning, botnet C2,
# exfiltration). DNS/TLS classes stay with their metadata detectors, which need packet payload
# fields a flow record does not carry. This mirrors the flow-only graceful-degradation set.
ML_MODEL_DIR: Final = "ml/artifacts"
ML_MODEL_FILE: Final = "flow_classifier.joblib"
ML_META_FILE: Final = "flow_classifier.meta.json"
# A flow is only turned into an alert when the model is at least this confident it is malicious.
# 0.6 keeps the supervised layer conservative; the statistical detectors are the always-on floor.
ML_MIN_CONFIDENCE: Final = 0.6
# Small constant added to denominators when deriving rate features, so a zero-duration flow
# (single packet) does not divide by zero. 1 ms is below the resolution of any real flow.
ML_RATE_EPSILON_S: Final = 1e-3
# Model artifacts are verified against this hash on load; a mismatch refuses to load the model
# rather than trust an unverified binary (same posture as the offline intel bundle).
ML_VERIFY_HASH: Final = True
# Benign is the negative class; predicting it emits no alert.
ML_BENIGN_LABEL: Final = "benign"

# --- Upload / analysis endpoint (demo convenience) --------------------------------------------
# Cap on an uploaded capture. 64 MiB comfortably holds a few minutes of a mirrored link while
# bounding memory and analysis time for a shared public demo.
UPLOAD_MAX_BYTES: Final = 64 * 1024 * 1024
UPLOAD_ALLOWED_SUFFIXES: Final[frozenset[str]] = frozenset({".pcap", ".pcapng", ".cap"})
UPLOAD_READ_CHUNK: Final = 1 << 20
