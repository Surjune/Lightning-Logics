"""Data exfiltration: one internal host suddenly sends far more than it receives."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from enclave.core.constants import (
    DETECTION_MIN_CONFIDENCE,
    ENTITY_STATE_MAX,
    EXFIL_MAX_KNOWN_DESTINATIONS,
    EXFIL_MIN_BYTES_OUT,
    EXFIL_PCR,
    EXFIL_WEIGHTS,
    EXFIL_WINDOW_S,
    EXFIL_ZSCORE,
)
from enclave.core.lru import BoundedDict
from enclave.core.scoring import Signal, combine
from enclave.core.stats import Ewma, producer_consumer_ratio
from enclave.detectors.base import Detector, DetectorContext, ev, proto_name
from enclave.features.windows import DoublingTrigger, WindowClock
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import Event, EventKind, FlowRecord

BYTES_PER_MIB = 1024 * 1024


@dataclass(slots=True)
class _HostWindow:
    first_ts: float
    last_ts: float = 0.0
    bytes_out: int = 0
    bytes_in: int = 0
    by_dst: Counter[str] = field(default_factory=Counter)
    dst_port: dict[str, int] = field(default_factory=dict)
    proto: int = 0
    sample_flow: str = ""
    trigger: DoublingTrigger = field(default_factory=lambda: DoublingTrigger(EXFIL_MIN_BYTES_OUT))


class ExfilDetector(Detector):
    name = "exfil-baseline"
    consumes = frozenset({EventKind.FLOW})
    purpose = "Asymmetric upload volume toward new or rare destinations"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._clock = WindowClock(EXFIL_WINDOW_S)
        self._hosts: dict[str, _HostWindow] = {}
        self._baselines: BoundedDict[str, Ewma] = BoundedDict(ENTITY_STATE_MAX, Ewma)
        self._known: BoundedDict[str, set[str]] = BoundedDict(ENTITY_STATE_MAX, set)

    def observe(self, event: Event) -> list[Detection]:
        if not isinstance(event, FlowRecord):
            return []
        flow = event
        internal = self.ctx.network.is_internal
        src_in, dst_in = internal(flow.src_ip), internal(flow.dst_ip)
        if src_in == dst_in:
            return []
        self._clock.touch(flow.ts)
        if src_in:
            host, remote, out_b, in_b, rport = flow.src_ip, flow.dst_ip, flow.bytes_fwd, flow.bytes_bwd, flow.dst_port
        else:
            host, remote, out_b, in_b, rport = flow.dst_ip, flow.src_ip, flow.bytes_bwd, flow.bytes_fwd, flow.src_port
        win = self._hosts.get(host)
        if win is None:
            win = _HostWindow(first_ts=flow.first_ts)
            self._hosts[host] = win
        win.last_ts = max(win.last_ts, flow.last_ts)
        win.bytes_out += out_b
        win.bytes_in += in_b
        if out_b:
            win.by_dst[remote] += out_b
            win.dst_port.setdefault(remote, rport)
            win.proto = flow.proto
            win.sample_flow = flow.flow_id
        if win.trigger.check(win.bytes_out):
            detection = self._evaluate(host, win)
            return [detection] if detection else []
        return []

    def flush(self, now: float) -> list[Detection]:
        if not self._clock.due(now):
            return []
        for host, win in self._hosts.items():
            baseline = self._baselines.get_or_create(host)
            if win.bytes_out < EXFIL_MIN_BYTES_OUT:
                baseline.update(float(win.bytes_out))
            known = self._known.get_or_create(host)
            for dst in win.by_dst:
                if len(known) < EXFIL_MAX_KNOWN_DESTINATIONS:
                    known.add(dst)
        self._hosts.clear()
        self._clock.roll(now)
        return []

    def _evaluate(self, host: str, win: _HostWindow) -> Detection | None:
        pcr = producer_consumer_ratio(win.bytes_out, win.bytes_in)
        if pcr <= 0:
            return None
        baseline = self._baselines.get_or_create(host)
        signals = {
            "upload_volume": Signal(win.bytes_out, EXFIL_MIN_BYTES_OUT, EXFIL_WEIGHTS["upload_volume"]),
            "pcr": Signal(pcr, EXFIL_PCR, EXFIL_WEIGHTS["pcr"]),
        }
        zscore = baseline.zscore(win.bytes_out) if baseline.ready else None
        if zscore is not None:
            signals["upload_zscore"] = Signal(max(zscore, 0.0), EXFIL_ZSCORE, EXFIL_WEIGHTS["upload_zscore"])
        confidence, factors = combine(signals)
        if confidence < DETECTION_MIN_CONFIDENCE:
            self.suppressed += 1
            return None
        top_dst, top_bytes = win.by_dst.most_common(1)[0]
        first_contact = top_dst not in (self._known.get(host) or set())
        sub = "Bulk upload to a new destination" if first_contact else "Bulk upload"
        ratio = win.bytes_out / max(win.bytes_in, 1)
        # bytes -> MiB for display
        out_mib = win.bytes_out / BYTES_PER_MIB
        return Detection(
            threat_class=ThreatClass.EXFILTRATION, sub_type=sub,
            entity=f"{host}>{top_dst}", host=host, src=host, dst=top_dst,
            dst_port=str(win.dst_port.get(top_dst, 0)), proto=proto_name(win.proto), flow_id=win.sample_flow,
            event_start=win.first_ts, event_end=win.last_ts, confidence=confidence,
            evidence={
                "bytes_out_mib": ev(out_mib, f"alert at {EXFIL_MIN_BYTES_OUT / BYTES_PER_MIB:.0f} MiB per window"),
                "bytes_in_mib": ev(win.bytes_in / BYTES_PER_MIB),
                "out_in_ratio": ev(ratio),
                "producer_consumer_ratio": ev(pcr, f"alert at {EXFIL_PCR}; +1 = pure upload"),
                "upload_zscore": ev(zscore if zscore is not None else "no baseline yet", f"alert at {EXFIL_ZSCORE}"),
                "top_destination": ev(top_dst),
                "top_destination_share": ev(top_bytes / win.bytes_out),
                "destination_first_contact": ev("yes" if first_contact else "no"),
            },
            factors=factors,
            summary=(f"{host} sent {out_mib:,.1f} MiB, mostly to {top_dst}, receiving only "
                     f"{win.bytes_in / BYTES_PER_MIB:,.2f} MiB back (ratio {ratio:,.0f}:1)."),
            action=f"Block {top_dst} and check what {host} uploaded; preserve the capture segment.",
            mitre=["T1041", "T1048"], model=self.model_ref, asset_ip=host,
        )
