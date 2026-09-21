"""Detector unit tests on hand-built event sequences."""

from __future__ import annotations

from enclave.core.config import NetworkContext, Settings
from enclave.detectors.base import DetectorContext
from enclave.detectors.beacon import BeaconDetector
from enclave.detectors.ddos import DdosDetector
from enclave.detectors.scan import ScanDetector
from enclave.intel import Intel
from enclave.schema.alert import ThreatClass
from enclave.schema.events import FlowRecord, InputMode


def _ctx() -> DetectorContext:
    return DetectorContext(NetworkContext(Settings()), Intel())


def _flow(src: str, dst: str, sp: int, dp: int, ts: float, *, syn: bool = True, synack: bool = False,
          bwd: int = 0, mode: InputMode = InputMode.PCAP) -> FlowRecord:
    return FlowRecord(
        flow_id=f"{src}:{sp}>{dst}:{dp}", src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp, proto=6,
        first_ts=ts, last_ts=ts, bytes_fwd=200, bytes_bwd=bwd, pkts_fwd=1, pkts_bwd=1 if bwd else 0,
        syn_seen=syn, synack_seen=synack, rst_seen=False, export_index=0, is_final=True, mode=mode,
    )


def test_scan_detects_vertical_sweep() -> None:
    det = ScanDetector(_ctx())
    hits = []
    for port in range(1, 60):
        hits += det.observe(_flow("10.20.4.9", "10.10.1.15", 40000 + port, port, port * 0.01, synack=False))
    assert any(h.threat_class is ThreatClass.RECON_SCAN for h in hits)
    hit = next(h for h in hits if h.threat_class is ThreatClass.RECON_SCAN)
    assert "scan" in hit.sub_type.lower()
    assert hit.host == "10.20.4.9"


def test_scan_ignores_successful_connections() -> None:
    det = ScanDetector(_ctx())
    hits = []
    for port in (80, 443, 22):
        for _ in range(30):
            hits += det.observe(_flow("10.30.1.5", f"10.10.0.{port}", 5000, port, 1.0, synack=True))
    assert not hits


def test_ddos_flags_spoofed_syn_flood() -> None:
    det = DdosDetector(_ctx())
    for i in range(4000):
        det.observe(_flow(f"9.{i % 254}.{(i // 254) % 254}.{i % 200 + 1}", "10.10.0.5",
                          1024 + i % 4000, 443, i * 0.001, synack=False))
    out = det.flush(6.0)
    assert out and out[0].threat_class is ThreatClass.DDOS
    assert "flood" in out[0].sub_type.lower()
    assert float(out[0].evidence["src_ip_entropy_bits"].observed) > 10


def test_ddos_ignores_legitimate_burst() -> None:
    det = DdosDetector(_ctx())
    for i in range(4000):
        det.observe(_flow("10.30.1.10", "10.10.0.5", 1024 + i, 443, i * 0.001, synack=True, bwd=1500))
    assert not det.flush(6.0)


def test_beacon_detects_regular_checkins() -> None:
    det = BeaconDetector(_ctx())
    hits = []
    for i in range(8):
        hits += det.observe(_flow("10.30.2.41", "203.0.113.66", 40000 + i, 443, i * 60.0, synack=True, bwd=1200))
    assert any(h.threat_class is ThreatClass.C2_BEACON for h in hits)


def test_beacon_ignores_irregular_traffic() -> None:
    det = BeaconDetector(_ctx())
    hits = []
    for i, gap in enumerate([0, 3, 30, 32, 200, 205, 400, 800]):
        hits += det.observe(_flow("10.30.2.41", "203.0.113.66", 40000 + i, 443, float(gap), synack=True, bwd=i * 500))
    assert not hits
