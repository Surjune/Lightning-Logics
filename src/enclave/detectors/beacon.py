"""Botnet C2 beaconing: connections that repeat on a schedule toward few destinations."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from enclave.core.constants import (
    BEACON_HISTORY,
    BEACON_MAX_BYTES_CV,
    BEACON_MAX_INTERVAL_CV,
    BEACON_MIN_CONNECTIONS,
    BEACON_MIN_INTERVAL_S,
    BEACON_SHARED_DST_HOSTS,
    BEACON_WEIGHTS,
    DETECTION_MIN_CONFIDENCE,
    ENTITY_STATE_MAX,
    PORT_HTTPS,
)
from enclave.core.lru import BoundedDict
from enclave.core.scoring import Signal, combine
from enclave.core.stats import coefficient_of_variation, mean
from enclave.detectors.base import Detector, DetectorContext, ev, is_probable_reply, proto_name
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import Event, EventKind, FlowRecord

PairKey = tuple[str, str, int, int]


@dataclass(slots=True)
class _PairState:
    starts: deque[float] = field(default_factory=lambda: deque(maxlen=BEACON_HISTORY))
    sizes: deque[int] = field(default_factory=lambda: deque(maxlen=BEACON_HISTORY))
    sample_flow: str = ""


class BeaconDetector(Detector):
    name = "beacon-score"
    consumes = frozenset({EventKind.FLOW})
    purpose = "Periodic check-ins toward a small set of destinations"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._pairs: BoundedDict[PairKey, _PairState] = BoundedDict(ENTITY_STATE_MAX, _PairState)
        self._dst_hosts: BoundedDict[str, set[str]] = BoundedDict(ENTITY_STATE_MAX, set)

    def observe(self, event: Event) -> list[Detection]:
        if not isinstance(event, FlowRecord):
            return []
        flow = event
        if flow.export_index != 0 or is_probable_reply(flow):
            return []
        callers = self._dst_hosts.get_or_create(flow.dst_ip)
        if len(callers) <= BEACON_SHARED_DST_HOSTS:
            callers.add(flow.src_ip)
        key = (flow.src_ip, flow.dst_ip, flow.dst_port, flow.proto)
        st = self._pairs.get_or_create(key)
        st.starts.append(flow.first_ts)
        st.sizes.append(flow.bytes_fwd + flow.bytes_bwd)
        st.sample_flow = flow.flow_id
        if len(st.starts) < BEACON_MIN_CONNECTIONS:
            return []
        starts = sorted(st.starts)
        intervals = [b - a for a, b in zip(starts, starts[1:], strict=False)]
        mean_interval = mean(intervals)
        if mean_interval < BEACON_MIN_INTERVAL_S:
            return []
        interval_cv = coefficient_of_variation(intervals)
        if interval_cv > BEACON_MAX_INTERVAL_CV:
            return []
        sizes = [float(s) for s in st.sizes]
        size_cv = coefficient_of_variation(sizes)
        confidence, factors = combine({
            "interval_regularity": Signal(interval_cv, BEACON_MAX_INTERVAL_CV,
                                          BEACON_WEIGHTS["interval_regularity"], higher_is_worse=False),
            "size_regularity": Signal(size_cv, BEACON_MAX_BYTES_CV, BEACON_WEIGHTS["size_regularity"],
                                      higher_is_worse=False),
            "repetitions": Signal(len(starts), BEACON_MIN_CONNECTIONS, BEACON_WEIGHTS["repetitions"]),
            "dst_prevalence": Signal(len(callers), BEACON_SHARED_DST_HOSTS, BEACON_WEIGHTS["dst_prevalence"],
                                     higher_is_worse=False),
        })
        if confidence < DETECTION_MIN_CONFIDENCE:
            self.suppressed += 1
            return []
        src, dst, dport, proto = key
        mitre = ["T1071.001", "T1573"] if dport == PORT_HTTPS else ["T1071"]
        return [Detection(
            threat_class=ThreatClass.C2_BEACON, sub_type="Periodic check-in", entity=f"{src}>{dst}:{dport}",
            host=src, src=src, dst=dst, dst_port=str(dport), proto=proto_name(proto),
            flow_id=st.sample_flow, event_start=starts[0], event_end=flow.last_ts, confidence=confidence,
            evidence={
                "connections": ev(len(starts), f"alert from {BEACON_MIN_CONNECTIONS}"),
                "mean_interval_s": ev(mean_interval),
                "interval_cv": ev(interval_cv, f"human traffic > 0.6; alert below {BEACON_MAX_INTERVAL_CV}"),
                "bytes_per_session_cv": ev(size_cv, f"alert below {BEACON_MAX_BYTES_CV}"),
                "mean_bytes_per_session": ev(mean(sizes)),
                "internal_hosts_calling_dst": ev(len(callers), f"shared service at {BEACON_SHARED_DST_HOSTS}+"),
            },
            factors=factors,
            summary=(f"{src} contacts {dst}:{dport} every {mean_interval:.1f} s "
                     f"(variation {interval_cv:.3f}) with near-identical sessions, {len(starts)} times so far."),
            action=f"Block {dst} at the perimeter and examine {src} before cleaning it.",
            mitre=mitre, model=self.model_ref, asset_ip=src,
        )]
