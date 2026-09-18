"""Malware inside encrypted sessions, judged from TLS handshake metadata only."""

from __future__ import annotations

from enclave.core.constants import (
    ENTITY_STATE_MAX,
    TLS_MIN_CONFIDENCE,
    TLS_RARE_MAX_HOSTS,
    TLS_WARMUP_HANDSHAKES,
    TLS_WEIGHTS,
)
from enclave.core.lru import BoundedDict
from enclave.core.scoring import Signal, combine
from enclave.detectors.base import Detector, DetectorContext, ev
from enclave.schema.alert import Detection, ThreatClass
from enclave.schema.events import Event, EventKind, TlsEvent

PRESENT = 1.0
ABSENT = 0.0
BINARY_THRESHOLD = 0.5


class TlsDetector(Detector):
    name = "tls-meta"
    consumes = frozenset({EventKind.TLS})
    purpose = "Malware in TLS sessions from JA3/JA4 fingerprints and handshake traits (no decryption)"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._hosts_by_fp: BoundedDict[str, set[str]] = BoundedDict(ENTITY_STATE_MAX, set)
        self.handshakes = 0

    def observe(self, event: Event) -> list[Detection]:
        if not isinstance(event, TlsEvent):
            return []
        self.handshakes += 1
        hosts = self._hosts_by_fp.get_or_create(event.ja4)
        prior_hosts = len(hosts - {event.client_ip})
        if len(hosts) <= TLS_RARE_MAX_HOSTS + 1:
            hosts.add(event.client_ip)
        blocklisted = event.ja3 in self.ctx.intel.ja3 or event.ja4 in self.ctx.intel.ja4
        warmed_up = self.handshakes > TLS_WARMUP_HANDSHAKES

        signals = {
            "blocklist_match": Signal(PRESENT if blocklisted else ABSENT, BINARY_THRESHOLD,
                                      TLS_WEIGHTS["blocklist_match"]),
            "sni_absent": Signal(ABSENT if event.sni else PRESENT, BINARY_THRESHOLD, TLS_WEIGHTS["sni_absent"]),
        }
        if warmed_up:
            # Hosts that already used this fingerprint; 0 means first sighting on this network.
            signals["fingerprint_rarity"] = Signal(prior_hosts, TLS_RARE_MAX_HOSTS,
                                                   TLS_WEIGHTS["fingerprint_rarity"], higher_is_worse=False)
        confidence, factors = combine(signals)
        if not blocklisted and confidence < TLS_MIN_CONFIDENCE:
            return []
        rare_text = "first time on this network" if prior_hosts == 0 else f"seen from {prior_hosts} other hosts"
        return [Detection(
            threat_class=ThreatClass.ENCRYPTED_MALWARE,
            sub_type="Known-bad TLS fingerprint" if blocklisted else "Anomalous TLS client",
            entity=f"{event.client_ip}>{event.ja4}", host=event.client_ip, src=event.client_ip,
            dst=event.server_ip, dst_port=str(event.server_port), proto="TCP", flow_id=event.flow_id,
            event_start=event.ts, event_end=event.ts, confidence=confidence,
            evidence={
                "ja3": ev(event.ja3),
                "ja4": ev(event.ja4),
                "offline_blocklist_match": ev("yes" if blocklisted else "no", self.ctx.intel.source),
                "fingerprint_prevalence": ev(prior_hosts, rare_text if warmed_up else "still learning"),
                "sni": ev(event.sni or "(absent)", "present in most legitimate sessions"),
                "tls_version": ev(event.version),
                "alpn": ev(event.alpn or "(none)"),
            },
            factors=factors,
            summary=(f"{event.client_ip} opened a TLS session to {event.server_ip}:{event.server_port} with "
                     f"client fingerprint {event.ja4} ({'on the offline blocklist' if blocklisted else rare_text}"
                     f"{', no server name' if not event.sni else ''}). Nothing was decrypted."),
            action=f"Isolate {event.client_ip} and search the flow archive for the same fingerprint.",
            mitre=["T1573.002", "T1071.001"], model=self.model_ref, asset_ip=event.client_ip,
        )]
