"""End-to-end: the synthetic scenario must raise every threat class, and the chain must verify."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from enclave.core.config import Settings
from enclave.ingest.pcap_source import PcapSource
from enclave.intel import Intel
from enclave.metrics import Metrics
from enclave.pipeline import Pipeline
from enclave.schema.alert import Alert, ThreatClass
from enclave.sinks.store import AlertStore, HashChainLog, verify_chain
from enclave.synth import generate


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, Path]:
    base = tmp_path_factory.mktemp("demo")
    pcap, intel_dir, log = base / "demo.pcap", base / "intel", base / "alerts.jsonl"
    generate(pcap, intel_dir)
    return pcap, intel_dir, log


def _run(pcap: Path, intel_dir: Path, log: Path) -> tuple[AlertStore, Metrics]:
    settings = Settings(intel_dir=intel_dir, alert_log=log)
    source = PcapSource(pcap, speed=0.0)
    store = AlertStore(HashChainLog(log), source.source_ref)
    metrics = Metrics()
    pipeline = Pipeline(settings, source, store, metrics, Intel.load(intel_dir))
    asyncio.run(pipeline.run())
    return store, metrics


def test_all_threat_classes_detected(demo: tuple[Path, Path, Path]) -> None:
    store, metrics = _run(*demo)
    seen = {a.threat_class for a in store.all()}
    expected = {
        ThreatClass.DDOS, ThreatClass.RECON_SCAN, ThreatClass.C2_BEACON, ThreatClass.DGA,
        ThreatClass.DNS_TUNNEL, ThreatClass.ENCRYPTED_MALWARE, ThreatClass.EXFILTRATION,
    }
    missing = expected - seen
    assert not missing, f"missing detections: {missing}"
    assert ThreatClass.CAMPAIGN in seen, "campaign correlation did not fire"
    assert metrics.dropped == 0


def test_alerts_validate_and_carry_evidence(demo: tuple[Path, Path, Path]) -> None:
    store, _ = _run(*demo)
    for alert in store.all():
        Alert.model_validate(alert.model_dump())
        assert alert.evidence, f"{alert.alert_id} has no evidence"
        assert alert.top_factors, f"{alert.alert_id} has no explanation"
        assert 0.0 <= alert.confidence <= 1.0


def test_flow_only_mode_disables_dns_and_tls(demo: tuple[Path, Path, Path]) -> None:
    from enclave.core.config import NetworkContext
    from enclave.detectors.base import DetectorContext
    from enclave.detectors.registry import build_detectors
    from enclave.schema.events import InputMode

    ctx = DetectorContext(NetworkContext(Settings()), Intel())
    _, statuses = build_detectors(InputMode.FLOW, ctx)
    active = {s.name for s in statuses if s.active}
    inactive = {s.name for s in statuses if not s.active}
    assert "dns-lexical" in inactive and "tls-meta" in inactive
    assert {"ddos-stat", "scan-trw", "exfil-baseline", "beacon-score"} <= active


def test_evidence_chain_verifies(demo: tuple[Path, Path, Path]) -> None:
    pcap, intel_dir, log = demo
    _run(pcap, intel_dir, log)
    intact, count = verify_chain(log)
    assert intact and count > 0
