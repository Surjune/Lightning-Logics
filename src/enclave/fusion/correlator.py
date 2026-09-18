"""Links alerts on the same host into one multi-stage campaign."""

from __future__ import annotations

from dataclasses import dataclass, field

from enclave.core.constants import (
    CORRELATION_CONFIDENCE,
    CORRELATION_MAX_CONFIDENCE,
    CORRELATION_MIN_STAGES,
    CORRELATION_STAGE_BONUS,
    CORRELATION_WINDOW_S,
    ENTITY_STATE_MAX,
)
from enclave.core.lru import BoundedDict
from enclave.schema.alert import Alert, Detection, EvidenceItem, ThreatClass

STAGE_ORDER: tuple[ThreatClass, ...] = (
    ThreatClass.RECON_SCAN, ThreatClass.DGA, ThreatClass.ENCRYPTED_MALWARE, ThreatClass.C2_BEACON,
    ThreatClass.DNS_TUNNEL, ThreatClass.EXFILTRATION,
)
STAGE_LABEL = {
    ThreatClass.RECON_SCAN: "reconnaissance", ThreatClass.DGA: "DGA lookups",
    ThreatClass.ENCRYPTED_MALWARE: "malicious TLS", ThreatClass.C2_BEACON: "C2 beaconing",
    ThreatClass.DNS_TUNNEL: "DNS tunnelling", ThreatClass.EXFILTRATION: "exfiltration",
}


@dataclass(slots=True)
class _HostStages:
    stages: dict[ThreatClass, tuple[float, str]] = field(default_factory=dict)
    reported_stages: int = 0


class Correlator:
    def __init__(self) -> None:
        self._hosts: BoundedDict[str, _HostStages] = BoundedDict(ENTITY_STATE_MAX, _HostStages)

    def observe(self, alert: Alert) -> Detection | None:
        if alert.threat_class not in STAGE_LABEL:
            return None
        now = alert.event_end.timestamp()
        st = self._hosts.get_or_create(alert.host)
        st.stages[alert.threat_class] = (now, alert.alert_id)
        recent = {cls: v for cls, v in st.stages.items() if now - v[0] <= CORRELATION_WINDOW_S}
        st.stages = recent
        st.reported_stages = min(st.reported_stages, len(recent))
        if len(recent) < CORRELATION_MIN_STAGES or len(recent) <= st.reported_stages:
            return None
        st.reported_stages = len(recent)
        confidence = min(CORRELATION_MAX_CONFIDENCE,
                         CORRELATION_CONFIDENCE + CORRELATION_STAGE_BONUS * (len(recent) - CORRELATION_MIN_STAGES))
        ordered = sorted(recent.items(), key=lambda kv: (kv[1][0], STAGE_ORDER.index(kv[0])))
        chain = " -> ".join(STAGE_LABEL[cls] for cls, _ in ordered)
        start = ordered[0][1][0]
        return Detection(
            threat_class=ThreatClass.CAMPAIGN, sub_type=f"Multi-stage activity: {chain}",
            entity=alert.host, host=alert.host, src=alert.host, dst="multiple", dst_port="-",
            proto="mixed", flow_id=alert.flow_id, event_start=start, event_end=now,
            confidence=confidence,
            evidence={
                "linked_stages": EvidenceItem(observed=len(ordered), reference=f"alert at {CORRELATION_MIN_STAGES}"),
                "stage_chain": EvidenceItem(observed=chain),
                "time_span_s": EvidenceItem(observed=round(now - start, 1),
                                            reference=f"window {CORRELATION_WINDOW_S:.0f} s"),
            },
            factors=[("linked_stages", confidence)],
            summary=f"{alert.host} shows {len(ordered)} linked attack stages: {chain}. Treat as one incident.",
            action=f"Open an incident for {alert.host}; contain it on the production side and preserve evidence.",
            mitre=["TA0011", "TA0010"], model="correlator-1.0", asset_ip=alert.host,
            related=[aid for _, (_, aid) in ordered],
        )
