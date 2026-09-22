"""The live source must stream a pcap through the tested decode path and emit flow records."""

from __future__ import annotations

import asyncio
from pathlib import Path

from enclave.ingest.live_source import LiveSource
from enclave.schema.events import Event, FlowRecord
from enclave.synth import generate


def test_live_source_streams_flow_records(tmp_path: Path) -> None:
    pcap = tmp_path / "live.pcap"
    generate(pcap, tmp_path / "intel")

    async def collect() -> list[Event]:
        return [event async for event in LiveSource(str(pcap)).events()]

    events = asyncio.run(collect())
    assert any(isinstance(e, FlowRecord) for e in events), "no flow records from live source"
