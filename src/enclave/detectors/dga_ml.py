"""Supervised DGA / DNS-tunnelling detector — the second AI/ML model, running live on DNS names.

A gradient-boosted classifier (trained by ``ml/train_dga.py``) scores each DNS query from its lexical
features alone, alongside the statistical ``dns-lexical`` detector. DNS is high-volume, so it only
alerts above a high confidence, and only on queries (not responses). Opt-in via ``ml_model_dir``.
"""

from __future__ import annotations

from enclave.core.constants import ASSET_DEFAULT_CRITICALITY, ML_DGA_MIN_CONFIDENCE, PORT_DNS
from enclave.detectors.base import Detector, DetectorContext, ev
from enclave.ml.dns_features import features_from_query
from enclave.ml.model import FlowClassifier, load_dga_classifier
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import DnsEvent, Event, EventKind

_LABEL_META: dict[str, tuple[ThreatClass, str, list[str]]] = {
    "dga": (ThreatClass.DGA, "Algorithmically generated domain (ML)", ["T1568.002"]),
    "dns_tunnel": (ThreatClass.DNS_TUNNEL, "DNS tunnelling (ML)", ["T1071.004"]),
}
_ACTIONS: dict[ThreatClass, str] = {
    ThreatClass.DGA: "Block the domain and hunt the host for DGA-driven malware.",
    ThreatClass.DNS_TUNNEL: "Inspect the host's DNS: a covert channel may be tunnelling data out.",
}


class DgaMlDetector(Detector):
    name = "dga-ml"
    version = "1.0"
    consumes = frozenset({EventKind.DNS})
    purpose = "supervised classifier for DGA domains and DNS tunnelling"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        if ctx.ml_model_dir is None:
            self.clf = FlowClassifier(False, "ML disabled (set ml_model_dir in config to enable)")
        else:
            self.clf = load_dga_classifier(ctx.ml_model_dir)
        self.model_version = self.clf.version

    def unavailable_reason(self) -> str | None:
        return None if self.clf.available else self.clf.reason

    def observe(self, event: Event) -> list[Detection]:
        if not self.clf.available or not isinstance(event, DnsEvent) or event.is_response:
            return []
        prediction = self.clf.predict(features_from_query(event.query, event.qtype))
        if prediction is None or prediction.label not in _LABEL_META:
            return []
        if prediction.confidence < ML_DGA_MIN_CONFIDENCE:
            self.suppressed += 1
            return []
        threat_class, sub_type, mitre = _LABEL_META[prediction.label]
        host = event.client_ip
        criticality = self.ctx.network.criticality(host) if self.ctx.network.is_internal(host) \
            else ASSET_DEFAULT_CRITICALITY
        evidence = {
            "query": ev(event.query),
            "model_label": ev(prediction.label, f"p={prediction.confidence:.2f}"),
            "record_type": ev(event.qtype),
        }
        return [Detection(
            threat_class=threat_class, sub_type=sub_type, entity=host, host=host,
            src=host, dst=event.query[:120], dst_port=str(PORT_DNS), proto="UDP",
            flow_id=event.flow_id, event_start=event.ts, event_end=event.ts,
            confidence=prediction.confidence, evidence=evidence,
            factors=[(name, round(imp, 4)) for name, imp in prediction.top_features],
            summary=(f"Supervised model flagged DNS query '{event.query}' from {host} as "
                     f"{prediction.label} (p={prediction.confidence:.2f}, criticality {criticality})."),
            action=_ACTIONS[threat_class], mitre=mitre,
            model=f"{self.name}-{self.model_version}", asset_ip=host,
        )]
