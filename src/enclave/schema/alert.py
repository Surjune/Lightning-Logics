"""The standardised alert record (PS constraint e) and the internal detection it comes from."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field

from enclave.core.constants import SCHEMA_VERSION, SEVERITY_SCORE_MAX


class ThreatClass(StrEnum):
    DDOS = "ddos"
    C2_BEACON = "c2_beacon"
    DGA = "dga"
    DNS_TUNNEL = "dns_tunnel"
    ENCRYPTED_MALWARE = "encrypted_malware"
    RECON_SCAN = "recon_scan"
    EXFILTRATION = "exfiltration"
    CAMPAIGN = "campaign"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Detection:
    """What a detector emits. Fusion turns it into an `Alert`."""

    threat_class: ThreatClass
    sub_type: str
    entity: str                      # dedup key within the class (host, target, pair...)
    host: str                        # the internal host the finding is about
    src: str
    dst: str
    dst_port: str
    proto: str
    flow_id: str
    event_start: float
    event_end: float
    confidence: float
    evidence: dict[str, EvidenceItem]
    factors: list[tuple[str, float]]
    summary: str
    action: str
    mitre: list[str]
    model: str
    asset_ip: str
    related: list[str] = field(default_factory=list)


class EvidenceItem(BaseModel):
    observed: float | int | str
    reference: str | None = None


class Factor(BaseModel):
    feature: str
    contribution: float


class ModelRef(BaseModel):
    name: str
    version: str


class Custody(BaseModel):
    source_ref: str
    prev_alert_hash: str
    alert_hash: str


class Alert(BaseModel):
    schema_version: str = SCHEMA_VERSION
    alert_id: str
    detected_at: datetime
    event_start: datetime
    event_end: datetime
    flow_id: str
    src: str
    dst: str
    dst_port: str
    proto: str
    sensor_id: str
    input_mode: str
    host: str
    threat_class: ThreatClass
    sub_type: str
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    severity: Severity
    severity_score: Annotated[int, Field(ge=0, le=SEVERITY_SCORE_MAX)]
    asset: dict[str, str | int]
    model: ModelRef
    mitre_attack: list[str]
    summary: str
    suggested_action: str
    evidence: dict[str, EvidenceItem]
    top_factors: list[Factor]
    events_merged: int = 1
    related_alert_ids: list[str] = Field(default_factory=list)
    processing_latency_ms: float = 0.0
    custody: Custody | None = None
