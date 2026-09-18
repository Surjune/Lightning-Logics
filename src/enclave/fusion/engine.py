"""Detections -> alerts: allowlist, severity, de-duplication and campaign correlation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from enclave.core.config import NetworkContext
from enclave.core.constants import (
    ASSET_WEIGHT_BASE,
    ASSET_WEIGHT_STEP,
    CLASS_IMPACT,
    DEDUP_WINDOW_S,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_SCORE_MAX,
    TOP_FACTORS,
)
from enclave.core.logging import get_logger
from enclave.fusion.correlator import Correlator
from enclave.schema.alert import Alert, Detection, Factor, ModelRef, Severity

log = get_logger(__name__)


def severity_for(confidence: float, threat_class: str, criticality: int) -> tuple[int, Severity]:
    weight = ASSET_WEIGHT_BASE + ASSET_WEIGHT_STEP * criticality
    score = min(SEVERITY_SCORE_MAX, round(SEVERITY_SCORE_MAX * confidence * CLASS_IMPACT[threat_class] * weight))
    if score >= SEVERITY_CRITICAL:
        return score, Severity.CRITICAL
    if score >= SEVERITY_HIGH:
        return score, Severity.HIGH
    if score >= SEVERITY_MEDIUM:
        return score, Severity.MEDIUM
    return score, Severity.LOW


def to_datetime(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, UTC)


@dataclass(frozen=True)
class AlertUpdate:
    alert: Alert
    is_new: bool


class FusionEngine:
    def __init__(self, network: NetworkContext, sensor_id: str, input_mode: str) -> None:
        self.network = network
        self.sensor_id = sensor_id
        self.input_mode = input_mode
        self.correlator = Correlator()
        self._open: dict[tuple[str, str], Alert] = {}
        self._seq = 0
        self.allowlisted = 0
        self.merged = 0

    def _next_id(self) -> str:
        self._seq += 1
        return f"{self.sensor_id}-{self._seq:07d}"

    def ingest(self, det: Detection, latency_ms: float) -> list[AlertUpdate]:
        if self.network.is_allowlisted(det.src, det.dst):
            self.allowlisted += 1
            return []
        key = (det.threat_class.value, det.entity)
        existing = self._open.get(key)
        if existing and det.event_start - existing.event_end.timestamp() <= DEDUP_WINDOW_S:
            existing.events_merged += 1
            existing.event_end = max(existing.event_end, to_datetime(det.event_end))
            if det.confidence >= existing.confidence:
                existing.confidence = round(det.confidence, 3)
                existing.sub_type = det.sub_type
                existing.related_alert_ids = det.related or existing.related_alert_ids
                existing.severity_score, existing.severity = severity_for(
                    det.confidence, det.threat_class.value, self.network.criticality(det.asset_ip))
                existing.evidence = det.evidence
                existing.top_factors = [Factor(feature=f, contribution=c) for f, c in det.factors[:TOP_FACTORS]]
                existing.summary = det.summary
            self.merged += 1
            return [AlertUpdate(existing, is_new=False)]

        alert = self._build(det, latency_ms)
        self._open[key] = alert
        log.info("alert raised", extra={"alert_id": alert.alert_id, "class": alert.threat_class.value,
                                        "severity": alert.severity.value, "host": alert.host})
        updates = [AlertUpdate(alert, is_new=True)]
        campaign = self.correlator.observe(alert)
        if campaign is not None:
            updates.extend(self.ingest(campaign, latency_ms))
        return updates

    def _build(self, det: Detection, latency_ms: float) -> Alert:
        criticality = self.network.criticality(det.asset_ip)
        score, severity = severity_for(det.confidence, det.threat_class.value, criticality)
        asset = self.network.asset(det.asset_ip)
        name, version = det.model.rsplit("-", 1) if "-" in det.model else (det.model, "1.0")
        return Alert(
            alert_id=self._next_id(),
            detected_at=to_datetime(det.event_end),
            event_start=to_datetime(det.event_start),
            event_end=to_datetime(det.event_end),
            flow_id=det.flow_id, src=det.src, dst=det.dst, dst_port=det.dst_port, proto=det.proto,
            sensor_id=self.sensor_id, input_mode=self.input_mode, host=det.host,
            threat_class=det.threat_class, sub_type=det.sub_type,
            confidence=round(det.confidence, 3), severity=severity, severity_score=score,
            asset={"address": det.asset_ip, "name": asset.name if asset else "unregistered",
                   "zone": asset.zone if asset else "unknown", "criticality": criticality},
            model=ModelRef(name=name, version=version), mitre_attack=det.mitre,
            summary=det.summary, suggested_action=det.action, evidence=det.evidence,
            top_factors=[Factor(feature=f, contribution=c) for f, c in det.factors[:TOP_FACTORS]],
            related_alert_ids=det.related, processing_latency_ms=round(latency_ms, 3),
        )
