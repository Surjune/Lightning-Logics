"""Reconnaissance: first-contact failures (Threshold Random Walk) plus fan-out shape."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from enclave.core.constants import (
    DETECTION_MIN_CONFIDENCE,
    ENTITY_STATE_MAX,
    PORT_MODBUS,
    PROTO_TCP,
    SCAN_FAILED_RATIO,
    SCAN_MIN_DISTINCT_TARGETS,
    SCAN_SHAPE_RATIO,
    SCAN_WEIGHTS,
    SCAN_WINDOW_S,
)
from enclave.core.lru import BoundedDict
from enclave.core.scoring import Signal, combine
from enclave.core.stats import ThresholdRandomWalk
from enclave.detectors.base import Detector, DetectorContext, ev, is_probable_reply
from enclave.features.windows import DoublingTrigger
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import Event, EventKind, FlowRecord


@dataclass(slots=True)
class _SourceState:
    first_ts: float = 0.0
    last_ts: float = 0.0
    attempts: int = 0
    failures: int = 0
    trw: ThresholdRandomWalk = field(default_factory=ThresholdRandomWalk)
    targets: set[tuple[str, int]] = field(default_factory=set)
    hosts: Counter[str] = field(default_factory=Counter)
    ports: Counter[int] = field(default_factory=Counter)
    sample_flow: str = ""
    trigger: DoublingTrigger = field(default_factory=lambda: DoublingTrigger(SCAN_MIN_DISTINCT_TARGETS))


class ScanDetector(Detector):
    name = "scan-trw"
    consumes = frozenset({EventKind.FLOW})
    purpose = "Port scans and host sweeps from a single source"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._sources: BoundedDict[str, _SourceState] = BoundedDict(ENTITY_STATE_MAX, _SourceState)

    def observe(self, event: Event) -> list[Detection]:
        if not isinstance(event, FlowRecord):
            return []
        flow = event
        if flow.proto != PROTO_TCP or flow.export_index != 0 or is_probable_reply(flow):
            return []
        st = self._sources.get_or_create(flow.src_ip)
        if st.attempts and flow.first_ts - st.last_ts > SCAN_WINDOW_S:
            st = _SourceState()
            self._sources.set(flow.src_ip, st)
        if not st.attempts:
            st.first_ts = flow.first_ts
            st.sample_flow = flow.flow_id
        st.last_ts = max(st.last_ts, flow.last_ts)
        target = (flow.dst_ip, flow.dst_port)
        if target in st.targets:
            return []
        if len(st.targets) < ENTITY_STATE_MAX:
            st.targets.add(target)
        success = flow.synack_seen
        st.attempts += 1
        st.failures += 0 if success else 1
        st.trw.observe(success)
        st.hosts[flow.dst_ip] += 1
        st.ports[flow.dst_port] += 1
        if st.trw.is_scanner and st.trigger.check(len(st.targets)):
            detection = self._detect(flow.src_ip, st)
            return [detection] if detection else []
        return []

    def _detect(self, src: str, st: _SourceState) -> Detection | None:
        distinct = len(st.targets)
        failed_ratio = st.failures / st.attempts
        confidence, factors = combine({
            "trw_score": Signal(st.trw.score, ThresholdRandomWalk.UPPER, SCAN_WEIGHTS["trw_score"]),
            "distinct_targets": Signal(distinct, SCAN_MIN_DISTINCT_TARGETS, SCAN_WEIGHTS["distinct_targets"]),
            "failed_ratio": Signal(failed_ratio, SCAN_FAILED_RATIO, SCAN_WEIGHTS["failed_ratio"]),
        })
        if confidence < DETECTION_MIN_CONFIDENCE:
            self.suppressed += 1
            return None
        n_hosts, n_ports = len(st.hosts), len(st.ports)
        top_host = st.hosts.most_common(1)[0][0]
        top_port = st.ports.most_common(1)[0][0]
        if n_ports >= SCAN_SHAPE_RATIO * n_hosts:
            sub, dst, dport, asset = "Vertical port scan", top_host, f"{n_ports} ports", top_host
        elif n_hosts >= SCAN_SHAPE_RATIO * n_ports:
            sub, dst, dport = "Horizontal host sweep", f"{n_hosts} hosts", str(top_port)
            asset = top_host
        else:
            sub, dst, dport, asset = "Block scan", f"{n_hosts} hosts", f"{n_ports} ports", top_host
        mitre = ["T1046"] + (["T0846"] if top_port == PORT_MODBUS else [])
        return Detection(
            threat_class=ThreatClass.RECON_SCAN, sub_type=sub, entity=src, host=src,
            src=src, dst=dst, dst_port=dport, proto="TCP", flow_id=st.sample_flow,
            event_start=st.first_ts, event_end=st.last_ts, confidence=confidence,
            evidence={
                "distinct_targets": ev(distinct, f"alert at {SCAN_MIN_DISTINCT_TARGETS}"),
                "distinct_hosts": ev(n_hosts),
                "distinct_ports": ev(n_ports),
                "failed_connection_ratio": ev(failed_ratio, f"alert at {SCAN_FAILED_RATIO}"),
                "trw_log_likelihood": ev(st.trw.score, f"alert at {ThresholdRandomWalk.UPPER:.2f}"),
                "most_probed_port": ev(top_port),
            },
            factors=factors,
            summary=(f"{src} probed {distinct:,} targets ({n_hosts} hosts, {n_ports} ports) in "
                     f"{st.last_ts - st.first_ts:.0f} s; {failed_ratio:.0%} got no handshake."),
            action=f"Identify the owner of {src} and restrict its reach at the zone firewall.",
            mitre=mitre, model=self.model_ref, asset_ip=asset,
        )
