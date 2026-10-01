"""Each per-threat capture must raise exactly its own threat class; the benign control raises none."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from enclave.core.config import Settings
from enclave.ingest.pcap_source import PcapSource
from enclave.intel import Intel
from enclave.metrics import Metrics
from enclave.pipeline import Pipeline
from enclave.schema.alert import ThreatClass
from enclave.sinks.store import AlertStore, HashChainLog
from enclave.synth import THREAT_SCENARIOS, generate, generate_threat

EXPECTED: dict[str, set[ThreatClass]] = {
    "benign_only": set(),
    "ddos_syn_flood": {ThreatClass.DDOS},
    "ddos_udp_amplification": {ThreatClass.DDOS},
    "c2_beacon": {ThreatClass.C2_BEACON},
    "dga_domains": {ThreatClass.DGA},
    "dns_tunnel": {ThreatClass.DNS_TUNNEL},
    "encrypted_malware": {ThreatClass.ENCRYPTED_MALWARE},
    "recon_port_scan": {ThreatClass.RECON_SCAN},
    "recon_host_sweep": {ThreatClass.RECON_SCAN},
    "exfiltration": {ThreatClass.EXFILTRATION},
}


@pytest.fixture(scope="module")
def intel_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("intel")
    generate(base / "demo.pcap", base / "intel")  # writes the matching offline intel bundle
    return base / "intel"


def test_every_scenario_has_an_expectation() -> None:
    assert set(EXPECTED) == set(THREAT_SCENARIOS)


@pytest.mark.parametrize("threat", sorted(EXPECTED))
def test_capture_raises_only_its_own_threat(threat: str, intel_dir: Path, tmp_path: Path) -> None:
    pcap, log = tmp_path / f"{threat}.pcap", tmp_path / "alerts.jsonl"
    generate_threat(pcap, threat)
    source = PcapSource(pcap, speed=0.0)
    store = AlertStore(HashChainLog(log), source.source_ref)
    settings = Settings(intel_dir=intel_dir, alert_log=log)
    asyncio.run(Pipeline(settings, source, store, Metrics(), Intel.load(intel_dir)).run())
    assert {a.threat_class for a in store.all()} == EXPECTED[threat]


def test_unknown_threat_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown threat"):
        generate_threat(tmp_path / "x.pcap", "not-a-threat")
