"""DGA lookups and DNS tunnelling from cleartext DNS metadata."""

from __future__ import annotations

from dataclasses import dataclass, field

import dpkt

from enclave.core.constants import (
    DETECTION_MIN_CONFIDENCE,
    DGA_MIN_NAMES_PER_WINDOW,
    DGA_NAME_SCORE,
    DGA_NXDOMAIN_RATIO,
    DGA_WEIGHTS,
    DNS_TXT_LIKE_QTYPES,
    DNS_WINDOW_S,
    ENTITY_STATE_MAX,
    PORT_DNS,
    TUNNEL_MAX_TRACKED_SUBDOMAINS,
    TUNNEL_MIN_LABEL_LEN,
    TUNNEL_MIN_UNIQUE_SUBDOMAINS,
    TUNNEL_TXT_RATIO,
    TUNNEL_WEIGHTS,
    TUNNEL_WINDOW_S,
)
from enclave.core.lru import BoundedDict
from enclave.core.scoring import Signal, combine
from enclave.detectors.base import Detector, DetectorContext, ev
from enclave.features.lexical import dga_name_score, max_label_length, split_name
from enclave.features.windows import DoublingTrigger
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import DnsEvent, Event, EventKind

SAMPLE_NAMES = 5


@dataclass(slots=True)
class _ClientWindow:
    start: float
    last_ts: float = 0.0
    responses: int = 0
    nxdomain: int = 0
    dga_names: set[str] = field(default_factory=set)
    score_sum: float = 0.0
    resolver: str = ""
    sample_flow: str = ""
    trigger: DoublingTrigger = field(default_factory=lambda: DoublingTrigger(DGA_MIN_NAMES_PER_WINDOW))


@dataclass(slots=True)
class _TunnelWindow:
    start: float
    last_ts: float = 0.0
    queries: int = 0
    txt_like: int = 0
    label_len_sum: int = 0
    subdomains: set[str] = field(default_factory=set)
    resolver: str = ""
    sample_flow: str = ""
    trigger: DoublingTrigger = field(default_factory=lambda: DoublingTrigger(TUNNEL_MIN_UNIQUE_SUBDOMAINS))


class DnsDetector(Detector):
    name = "dns-lexical"
    consumes = frozenset({EventKind.DNS})
    purpose = "Algorithmically generated domains and DNS tunnelling"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._clients: dict[str, _ClientWindow] = {}
        self._tunnels: BoundedDict[tuple[str, str], _TunnelWindow] = BoundedDict(
            ENTITY_STATE_MAX, lambda: _TunnelWindow(start=0.0)
        )

    def _client(self, ip: str, ts: float) -> _ClientWindow:
        win = self._clients.get(ip)
        if win is None or ts - win.start > DNS_WINDOW_S:
            if win is None and len(self._clients) >= ENTITY_STATE_MAX:
                self._clients.pop(next(iter(self._clients)))
            win = _ClientWindow(start=ts)
            self._clients[ip] = win
        win.last_ts = ts
        return win

    def observe(self, event: Event) -> list[Detection]:
        if not isinstance(event, DnsEvent):
            return []
        client = self._client(event.client_ip, event.ts)
        client.resolver = event.resolver_ip
        if event.is_response:
            client.responses += 1
            if event.rcode == dpkt.dns.DNS_RCODE_NXDOMAIN:
                client.nxdomain += 1
            return []
        parts = split_name(event.query)
        out: list[Detection] = []
        score, _ = dga_name_score(parts.label)
        if score >= DGA_NAME_SCORE and parts.registered not in client.dga_names:
            client.dga_names.add(parts.registered)
            client.score_sum += score
            client.sample_flow = event.flow_id
            if client.trigger.check(len(client.dga_names)):
                detection = self._dga(event.client_ip, client)
                if detection:
                    out.append(detection)
        if parts.subdomain:
            detection = self._tunnel_observe(event, parts.registered, parts.subdomain)
            if detection:
                out.append(detection)
        return out

    def _dga(self, ip: str, win: _ClientWindow) -> Detection | None:
        names = len(win.dga_names)
        nx_ratio = win.nxdomain / win.responses if win.responses else 0.0
        mean_score = win.score_sum / names
        confidence, factors = combine({
            "dga_like_names": Signal(names, DGA_MIN_NAMES_PER_WINDOW, DGA_WEIGHTS["dga_like_names"]),
            "nxdomain_ratio": Signal(nx_ratio, DGA_NXDOMAIN_RATIO, DGA_WEIGHTS["nxdomain_ratio"]),
            "mean_name_score": Signal(mean_score, DGA_NAME_SCORE, DGA_WEIGHTS["mean_name_score"]),
        })
        if confidence < DETECTION_MIN_CONFIDENCE:
            self.suppressed += 1
            return None
        samples = sorted(win.dga_names)[:SAMPLE_NAMES]
        return Detection(
            threat_class=ThreatClass.DGA, sub_type="Algorithmically generated domains", entity=ip, host=ip,
            src=ip, dst=win.resolver, dst_port=str(PORT_DNS), proto="UDP", flow_id=win.sample_flow,
            event_start=win.start, event_end=win.last_ts, confidence=confidence,
            evidence={
                "dga_like_domains": ev(names, f"alert at {DGA_MIN_NAMES_PER_WINDOW} per {DNS_WINDOW_S:.0f} s"),
                "nxdomain_ratio": ev(nx_ratio, f"alert at {DGA_NXDOMAIN_RATIO}"),
                "mean_name_score": ev(mean_score, f"alert at {DGA_NAME_SCORE}"),
                "sample_domains": ev(", ".join(samples)),
            },
            factors=factors,
            summary=(f"{ip} looked up {names} random-looking domains in {win.last_ts - win.start:.0f} s; "
                     f"{nx_ratio:.0%} of answers were NXDOMAIN."),
            action=f"Inspect {ip}; sinkhole the listed domains at the production resolver.",
            mitre=["T1568.002"], model=self.model_ref, asset_ip=ip,
        )

    def _tunnel_observe(self, event: DnsEvent, registered: str, subdomain: str) -> Detection | None:
        key = (event.client_ip, registered)
        win = self._tunnels.get(key)
        if win is None or event.ts - win.start > TUNNEL_WINDOW_S:
            win = _TunnelWindow(start=event.ts)
            self._tunnels.set(key, win)
        win.last_ts = event.ts
        win.queries += 1
        win.resolver = event.resolver_ip
        win.sample_flow = event.flow_id
        win.label_len_sum += max_label_length(subdomain)
        if event.qtype in DNS_TXT_LIKE_QTYPES:
            win.txt_like += 1
        if len(win.subdomains) < TUNNEL_MAX_TRACKED_SUBDOMAINS:
            win.subdomains.add(subdomain)
        if not win.trigger.check(len(win.subdomains)):
            return None
        unique = len(win.subdomains)
        mean_len = win.label_len_sum / win.queries
        txt_ratio = win.txt_like / win.queries
        confidence, factors = combine({
            "unique_subdomains": Signal(unique, TUNNEL_MIN_UNIQUE_SUBDOMAINS, TUNNEL_WEIGHTS["unique_subdomains"]),
            "label_length": Signal(mean_len, TUNNEL_MIN_LABEL_LEN, TUNNEL_WEIGHTS["label_length"]),
            "txt_null_ratio": Signal(txt_ratio, TUNNEL_TXT_RATIO, TUNNEL_WEIGHTS["txt_null_ratio"]),
        })
        if confidence < DETECTION_MIN_CONFIDENCE:
            self.suppressed += 1
            return None
        ip = event.client_ip
        return Detection(
            threat_class=ThreatClass.DNS_TUNNEL, sub_type="DNS tunnelling", entity=f"{ip}>{registered}",
            host=ip, src=ip, dst=registered, dst_port=str(PORT_DNS), proto="UDP", flow_id=win.sample_flow,
            event_start=win.start, event_end=win.last_ts, confidence=confidence,
            evidence={
                "base_domain": ev(registered),
                "unique_subdomains": ev(unique, f"alert at {TUNNEL_MIN_UNIQUE_SUBDOMAINS}"),
                "mean_longest_label": ev(mean_len, f"alert at {TUNNEL_MIN_LABEL_LEN}; normal < 20"),
                "txt_null_ratio": ev(txt_ratio, f"alert at {TUNNEL_TXT_RATIO}"),
                "queries": ev(win.queries),
            },
            factors=factors,
            summary=(f"{ip} sent {win.queries} lookups with {unique} unique encoded subdomains under "
                     f"{registered} ({txt_ratio:.0%} TXT/NULL); data is likely moving inside DNS."),
            action=f"Block {registered} at the production resolver and review {ip}'s egress rules.",
            mitre=["T1071.004", "T1572"], model=self.model_ref, asset_ip=ip,
        )
