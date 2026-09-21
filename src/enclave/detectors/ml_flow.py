"""Supervised flow classifier: the AI/ML detector for the flow-observable threat classes.

A gradient-boosted model trained on labelled CIC-IDS2017 flows (see ``ml/train.py``) scores each
completed flow. It covers exactly the classes a flow record can carry — DDoS, scanning, botnet
C2 and exfiltration — while the DNS and TLS classes stay with their metadata detectors. The
statistical detectors remain the always-on floor; this layer adds a second, dataset-trained
opinion and, through fusion, corroborates or extends them.

Flow counters arrive as per-export deltas, so a flow is accumulated by its Community ID (which is
identical in both directions) and classified once, when it closes. That reproduces the whole-flow
feature semantics the model was trained on.
"""

from __future__ import annotations

from dataclasses import dataclass

from enclave.core.constants import ASSET_DEFAULT_CRITICALITY, ENTITY_STATE_MAX
from enclave.core.lru import BoundedDict
from enclave.detectors.base import Detector, DetectorContext, ev
from enclave.ml.features import FlowCounts, derive_features, feature_row
from enclave.ml.model import FlowClassifier, Prediction, load_classifier
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import Event, EventKind, FlowRecord

# Friendly sub-type and ATT&CK technique per model label. Keys are the model's class labels.
_LABEL_META: dict[str, tuple[ThreatClass, str, list[str]]] = {
    "ddos": (ThreatClass.DDOS, "Volumetric flood (ML)", ["T1498"]),
    "recon_scan": (ThreatClass.RECON_SCAN, "Reconnaissance / scan (ML)", ["T1046"]),
    "c2_beacon": (ThreatClass.C2_BEACON, "Botnet C2 (ML)", ["T1071"]),
    "exfiltration": (ThreatClass.EXFILTRATION, "Data exfiltration (ML)", ["T1041"]),
}
_ACTIONS: dict[ThreatClass, str] = {
    ThreatClass.DDOS: "Ask the upstream provider for scrubbing toward the target.",
    ThreatClass.RECON_SCAN: "Identify the scanning host and restrict it at the zone firewall.",
    ThreatClass.C2_BEACON: "Isolate the host and hunt for the malware maintaining the channel.",
    ThreatClass.EXFILTRATION: "Freeze outbound transfers from the host and review what left.",
}


@dataclass(slots=True)
class _FlowAcc:
    """Whole-flow totals accumulated across per-export deltas of one Community ID."""

    src_ip: str
    dst_ip: str
    dst_port: int
    proto: int
    first_ts: float
    last_ts: float
    fwd_bytes: float = 0.0
    bwd_bytes: float = 0.0
    fwd_pkts: float = 0.0
    bwd_pkts: float = 0.0
    syn: bool = False
    rst: bool = False


class MlFlowDetector(Detector):
    name = "ml-flow"
    version = "1.0"
    consumes = frozenset({EventKind.FLOW})
    purpose = "supervised classifier for DDoS, scanning, botnet C2 and exfiltration"

    def unavailable_reason(self) -> str | None:
        return None if self.clf.available else self.clf.reason

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        if ctx.ml_model_dir is None:
            self.clf = FlowClassifier(False, "ML disabled (set ml_model_dir in config to enable)")
        else:
            self.clf = load_classifier(ctx.ml_model_dir)
        self.model_version = self.clf.version
        self._acc: BoundedDict[str, _FlowAcc] = BoundedDict(ENTITY_STATE_MAX, self._empty_acc)

    @staticmethod
    def _empty_acc() -> _FlowAcc:
        return _FlowAcc("", "", 0, 0, 0.0, 0.0)

    def observe(self, event: Event) -> list[Detection]:
        if not self.clf.available or not isinstance(event, FlowRecord):
            return []
        flow = event
        acc = self._acc.get(flow.flow_id)
        if acc is None:
            acc = _FlowAcc(flow.src_ip, flow.dst_ip, flow.dst_port, flow.proto, flow.first_ts, flow.last_ts)
            self._acc.set(flow.flow_id, acc)
        acc.last_ts = max(acc.last_ts, flow.last_ts)
        acc.first_ts = min(acc.first_ts, flow.first_ts)
        acc.fwd_bytes += flow.bytes_fwd
        acc.bwd_bytes += flow.bytes_bwd
        acc.fwd_pkts += flow.pkts_fwd
        acc.bwd_pkts += flow.pkts_bwd
        acc.syn = acc.syn or flow.syn_seen
        acc.rst = acc.rst or flow.rst_seen
        if not flow.is_final:
            return []
        self._acc.pop(flow.flow_id)
        return self._classify(flow.flow_id, acc)

    def _classify(self, flow_id: str, acc: _FlowAcc) -> list[Detection]:
        counts = FlowCounts(
            duration_s=max(acc.last_ts - acc.first_ts, 0.0),
            fwd_packets=acc.fwd_pkts, bwd_packets=acc.bwd_pkts,
            fwd_bytes=acc.fwd_bytes, bwd_bytes=acc.bwd_bytes,
            proto=acc.proto, syn=acc.syn, rst=acc.rst,
        )
        prediction = self.clf.predict(feature_row(counts))
        if prediction is None or not prediction.is_malicious:
            return []
        threat = self.clf.threat_for(prediction.label)
        if threat is None or prediction.label not in _LABEL_META:
            return []
        detection = self._to_detection(flow_id, acc, counts, prediction)
        return [detection] if detection is not None else []

    def _to_detection(self, flow_id: str, acc: _FlowAcc, counts: FlowCounts,
                      prediction: Prediction) -> Detection | None:
        threat_class, sub_type, mitre = _LABEL_META[prediction.label]
        # The victim is the target for DDoS; for the others the actor is the internal host.
        host = acc.dst_ip if threat_class is ThreatClass.DDOS else acc.src_ip
        asset = host if self.ctx.network.is_internal(host) else (
            acc.src_ip if self.ctx.network.is_internal(acc.src_ip) else acc.dst_ip)
        derived = derive_features(counts)
        benign = self.clf.benign_means
        evidence = {
            "model_label": ev(prediction.label, f"p={prediction.confidence:.2f}"),
            "duration_s": ev(derived["duration_s"]),
            "total_bytes": ev(derived["total_bytes"]),
            "bytes_per_s": ev(derived["bytes_per_s"]),
            "down_up_ratio": ev(derived["down_up_ratio"],
                                f"benign avg {benign.get('down_up_ratio', 0.0):.2f}" if benign else None),
            "fwd_bwd_pkt_ratio": ev(derived["fwd_bwd_pkt_ratio"]),
        }
        criticality = self.ctx.network.criticality(asset) if self.ctx.network.is_internal(asset) \
            else ASSET_DEFAULT_CRITICALITY
        summary = (
            f"Supervised model flagged a flow {acc.src_ip} -> {acc.dst_ip}:{acc.dst_port} as "
            f"{prediction.label} (p={prediction.confidence:.2f}, criticality {criticality}). "
            f"{derived['total_bytes']:,.0f} bytes over {derived['duration_s']:.1f}s, "
            f"down/up ratio {derived['down_up_ratio']:.2f}."
        )
        return Detection(
            threat_class=threat_class, sub_type=sub_type, entity=host, host=host,
            src=acc.src_ip, dst=acc.dst_ip, dst_port=str(acc.dst_port),
            proto="TCP" if counts.proto == 6 else "UDP" if counts.proto == 17 else str(counts.proto),
            flow_id=flow_id, event_start=acc.first_ts, event_end=acc.last_ts,
            confidence=prediction.confidence, evidence=evidence,
            factors=[(name, round(imp, 4)) for name, imp in prediction.top_features],
            summary=summary, action=_ACTIONS[threat_class], mitre=mitre,
            model=f"{self.name}-{self.model_version}", asset_ip=asset,
        )
