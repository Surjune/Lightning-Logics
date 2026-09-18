"""Volumetric / protocol DDoS from per-target flow rate, source entropy and byte asymmetry."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from enclave.core.constants import (
    AMPLIFICATION_PORTS,
    DDOS_AMP_MIN_BYTES_PER_S,
    DDOS_AMPLIFICATION_RATIO,
    DDOS_MIN_FLOWS_PER_S,
    DDOS_RATE_ZSCORE,
    DDOS_SRC_ENTROPY_BITS,
    DDOS_SYN_ONLY_RATIO,
    DDOS_WEIGHTS,
    DDOS_WINDOW_S,
    DETECTION_MIN_CONFIDENCE,
    ENTITY_STATE_MAX,
    PROTO_TCP,
)
from enclave.core.lru import BoundedDict
from enclave.core.scoring import Signal, combine
from enclave.core.stats import Ewma, shannon_entropy
from enclave.detectors.base import Detector, DetectorContext, ev, is_probable_reply
from enclave.features.windows import WindowClock
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import Event, EventKind, FlowRecord

BITS_PER_BYTE = 8
BITS_PER_MBIT = 1_000_000
OVERFLOW_SOURCE = "(other sources)"


@dataclass(slots=True)
class _TargetWindow:
    new_flows: int = 0
    tcp_new: int = 0
    syn_only: int = 0
    amp_bytes_in: int = 0
    amp_bytes_out: int = 0
    min_ttl: int = 255
    max_ttl: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    dst_port: int = 0
    proto: int = 0
    sample_flow: str = ""
    sources: Counter[str] = field(default_factory=Counter)


class DdosDetector(Detector):
    name = "ddos-stat"
    consumes = frozenset({EventKind.FLOW})
    purpose = "SYN floods, UDP reflection/amplification and spoofed-source floods"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._clock = WindowClock(DDOS_WINDOW_S)
        self._windows: dict[str, _TargetWindow] = {}
        self._baselines: BoundedDict[str, Ewma] = BoundedDict(ENTITY_STATE_MAX, Ewma)

    def _window(self, target: str, flow: FlowRecord) -> _TargetWindow:
        win = self._windows.get(target)
        if win is None:
            if len(self._windows) >= ENTITY_STATE_MAX:
                self.suppressed += 1
            win = _TargetWindow(first_ts=flow.first_ts, dst_port=flow.dst_port, proto=flow.proto,
                                sample_flow=flow.flow_id)
            self._windows[target] = win
        win.last_ts = max(win.last_ts, flow.last_ts)
        return win

    def observe(self, event: Event) -> list[Detection]:
        if not isinstance(event, FlowRecord):
            return []
        flow = event
        self._clock.touch(flow.ts)
        if flow.src_port in AMPLIFICATION_PORTS:
            win = self._window(flow.dst_ip, flow)
            win.amp_bytes_in += flow.bytes_fwd
            win.amp_bytes_out += flow.bytes_bwd
        if flow.dst_port in AMPLIFICATION_PORTS:
            win = self._window(flow.src_ip, flow)
            win.amp_bytes_out += flow.bytes_fwd
            win.amp_bytes_in += flow.bytes_bwd
        if flow.export_index != 0 or is_probable_reply(flow):
            return []
        win = self._window(flow.dst_ip, flow)
        win.new_flows += 1
        if len(win.sources) < ENTITY_STATE_MAX:
            win.sources[flow.src_ip] += 1
        else:
            win.sources[OVERFLOW_SOURCE] += 1
        if flow.min_ttl:
            win.min_ttl = min(win.min_ttl, flow.min_ttl)
            win.max_ttl = max(win.max_ttl, flow.max_ttl)
        if flow.proto == PROTO_TCP:
            win.tcp_new += 1
            if flow.handshake_failed:
                win.syn_only += 1
        return []

    def flush(self, now: float) -> list[Detection]:
        if not self._clock.due(now):
            return []
        out = [d for target, win in self._windows.items() if (d := self._evaluate(target, win))]
        self._windows.clear()
        self._clock.roll(now)
        return out

    def _evaluate(self, target: str, win: _TargetWindow) -> Detection | None:
        rate = win.new_flows / DDOS_WINDOW_S
        amp_in_rate = win.amp_bytes_in / DDOS_WINDOW_S
        baseline = self._baselines.get_or_create(target)
        flood_by_flows = rate >= DDOS_MIN_FLOWS_PER_S
        flood_by_bytes = amp_in_rate >= DDOS_AMP_MIN_BYTES_PER_S
        if not (flood_by_flows or flood_by_bytes):
            baseline.update(rate)
            return None
        # Without a trusted baseline, express the rate as multiples of the absolute floor
        # on the z-score scale so the same threshold applies.
        rate_z = baseline.zscore(rate) if baseline.ready else DDOS_RATE_ZSCORE * rate / DDOS_MIN_FLOWS_PER_S
        entropy = shannon_entropy(win.sources.values())
        syn_ratio = win.syn_only / win.tcp_new if win.tcp_new else 0.0
        amp_ratio = win.amp_bytes_in / max(win.amp_bytes_out, 1)

        signals = {"flow_rate_z": Signal(max(rate_z, 0.0), DDOS_RATE_ZSCORE, DDOS_WEIGHTS["flow_rate_z"]),
                   "src_ip_entropy": Signal(entropy, DDOS_SRC_ENTROPY_BITS, DDOS_WEIGHTS["src_ip_entropy"])}
        if win.tcp_new:
            signals["syn_only_ratio"] = Signal(syn_ratio, DDOS_SYN_ONLY_RATIO, DDOS_WEIGHTS["syn_only_ratio"])
        if flood_by_bytes:
            signals["amp_ratio"] = Signal(amp_ratio, DDOS_AMPLIFICATION_RATIO, DDOS_WEIGHTS["amp_ratio"])
            signals["flow_rate_z"] = Signal(amp_in_rate, DDOS_AMP_MIN_BYTES_PER_S, DDOS_WEIGHTS["flow_rate_z"])
        confidence, factors = combine(signals)
        if confidence < DETECTION_MIN_CONFIDENCE:
            self.suppressed += 1
            baseline.update(rate)
            return None

        if flood_by_bytes and amp_ratio >= DDOS_AMPLIFICATION_RATIO:
            sub, mitre = "UDP reflection / amplification", ["T1498.002"]
        elif win.tcp_new and syn_ratio >= DDOS_SYN_ONLY_RATIO:
            spoofed = entropy >= DDOS_SRC_ENTROPY_BITS
            sub, mitre = ("Spoofed SYN flood" if spoofed else "SYN flood"), ["T1498.001"]
        else:
            sub, mitre = "Volumetric flood", ["T1498.001"]
        unique = len(win.sources)
        evidence = {
            "new_flows_per_s": ev(rate, f"baseline {baseline.mean:.1f}/s" if baseline.ready else "no baseline yet"),
            "unique_sources": ev(unique),
            "src_ip_entropy_bits": ev(entropy, f"alert at {DDOS_SRC_ENTROPY_BITS}"),
            "syn_only_ratio": ev(syn_ratio, f"alert at {DDOS_SYN_ONLY_RATIO}"),
            "amplification_ratio": ev(amp_ratio, f"alert at {DDOS_AMPLIFICATION_RATIO}x"),
            # bytes/s -> Mbit/s
            "unsolicited_mbps": ev(amp_in_rate * BITS_PER_BYTE / BITS_PER_MBIT),
            "ttl_spread": ev(max(win.max_ttl - win.min_ttl, 0)),
        }
        return Detection(
            threat_class=ThreatClass.DDOS, sub_type=sub, entity=target, host=target,
            src=f"{unique} sources", dst=target, dst_port=str(win.dst_port), proto="TCP" if win.tcp_new else "UDP",
            flow_id=win.sample_flow, event_start=win.first_ts, event_end=win.last_ts,
            confidence=confidence, evidence=evidence, factors=factors,
            summary=(
                f"{sub} toward {target}: {amp_in_rate * BITS_PER_BYTE / BITS_PER_MBIT:,.1f} Mbit/s of "
                f"unsolicited answers from {unique:,} reflectors, {amp_ratio:,.0f}x the bytes it sent."
                if flood_by_bytes else
                f"{sub} toward {target}: {rate:,.0f} new flows/s from {unique:,} sources "
                f"(entropy {entropy:.1f} bits, {syn_ratio:.0%} never completed a handshake)."
            ),
            action=f"Ask the upstream provider for scrubbing or rate-limiting toward {target}.",
            mitre=mitre, model=self.model_ref, asset_ip=target,
        )
