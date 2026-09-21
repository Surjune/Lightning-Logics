"""On-demand analysis of an uploaded capture, for the file-upload demo endpoint.

The same streaming pipeline used for live replay is run to completion over the uploaded file
(``speed = 0``, i.e. as fast as possible), writing into the shared alert store and metrics so the
dashboard reflects the result. This is a convenience wrapper for the demo; the core product is
still the streaming enclave, not a batch analyser.
"""

from __future__ import annotations

from pathlib import Path

from enclave.core.config import Settings
from enclave.intel import Intel
from enclave.metrics import Metrics
from enclave.pipeline import Pipeline
from enclave.sinks.store import AlertStore


async def analyze_to_store(pcap_path: Path, settings: Settings, intel: Intel, store: AlertStore,
                           metrics: Metrics) -> None:
    """Run the full pipeline over one capture file, publishing alerts into the shared store."""
    from enclave.ingest.pcap_source import PcapSource

    source = PcapSource(pcap_path, speed=0.0)
    pipeline = Pipeline(settings, source, store, metrics, intel)
    await pipeline.run()
