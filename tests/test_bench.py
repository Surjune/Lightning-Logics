"""The throughput benchmark must run the engine over generated flows and report a sane rate."""

from __future__ import annotations

from enclave.bench import run


def test_benchmark_reports_throughput() -> None:
    result = run(n_flows=3000, seed=1)
    assert result["flows"] == 3000
    assert result["flows_per_s"] > 0
    assert result["elapsed_s"] > 0
    assert result["target_flows_per_s"] == 20_000
    assert "latency_ms" in result
