"""goflow2 JSON ingestion: field mapping (both casings) and streaming from a file."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from enclave.ingest.json_flow_source import JsonFlowSource, flow_from_json
from enclave.schema.events import Event, FlowRecord, InputMode


def test_flow_from_json_pascal_and_snake() -> None:
    pascal = flow_from_json({"SrcAddr": "10.0.0.5", "DstAddr": "203.0.113.9", "SrcPort": 44000,
                             "DstPort": 443, "Proto": 6, "Bytes": 5000, "Packets": 12,
                             "TimeFlowStartNs": 1_000_000_000, "TimeFlowEndNs": 3_000_000_000,
                             "TcpFlags": 2})
    assert pascal is not None
    assert pascal.src_ip == "10.0.0.5" and pascal.dst_port == 443 and pascal.mode is InputMode.FLOW
    assert pascal.bytes_fwd == 5000 and pascal.syn_seen is True
    assert pascal.last_ts - pascal.first_ts == 2.0

    snake = flow_from_json({"src_addr": "10.0.0.6", "dst_addr": "8.8.8.8", "src_port": 5353,
                            "dst_port": 53, "proto": 17, "bytes": 90, "packets": 1})
    assert snake is not None and snake.proto == 17

    assert flow_from_json({"Proto": 6}) is None  # no addresses -> skipped


def test_json_flow_source_streams(tmp_path: Path) -> None:
    lines = [
        {"SrcAddr": "10.0.0.5", "DstAddr": "203.0.113.9", "SrcPort": 40000, "DstPort": 443,
         "Proto": 6, "Bytes": 4000, "Packets": 10, "TcpFlags": 2},
        {"SrcAddr": "10.0.0.6", "DstAddr": "203.0.113.10", "SrcPort": 40001, "DstPort": 80,
         "Proto": 6, "Bytes": 800, "Packets": 6, "TcpFlags": 18},
    ]
    path = tmp_path / "flows.jsonl"
    path.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")

    async def collect() -> list[Event]:
        return [e async for e in JsonFlowSource(str(path)).events()]

    events = asyncio.run(collect())
    flows = [e for e in events if isinstance(e, FlowRecord)]
    assert len(flows) == 2
    assert {f.dst_port for f in flows} == {443, 80}
