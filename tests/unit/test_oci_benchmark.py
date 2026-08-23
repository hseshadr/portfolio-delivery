"""Contract tests for the metadata-only OCI resource benchmark."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts/benchmark-oci-limits.py"
ITERATIONS = 21
MAX_OUTPUT_BYTES = 1_024


def _benchmark() -> tuple[dict[str, object], bytes]:
    command = (sys.executable, str(SCRIPT), "--iterations", str(ITERATIONS))
    result = subprocess.run(command, check=True, capture_output=True)  # noqa: S603
    return cast(dict[str, object], json.loads(result.stdout)), result.stdout


def test_should_exercise_exact_descriptor_and_aggregate_boundaries() -> None:
    # Given / When
    document, _ = _benchmark()

    # Then
    assert document["boundary"] == {
        "descriptor_count": 256,
        "largest_file_bytes": 67_108_864,
        "total_bytes": 536_870_912,
    }
    assert document["limits"] == {
        "max_descriptors": 256,
        "max_file_bytes": 67_108_864,
        "max_total_bytes": 536_870_912,
    }


def test_should_emit_bounded_cold_and_warm_percentile_json() -> None:
    # Given / When
    document, content = _benchmark()
    measurements = cast(dict[str, dict[str, int]], document["measurements"])

    # Then
    assert set(document) == {"boundary", "iterations", "limits", "measurements"}
    assert document["iterations"] == ITERATIONS
    assert set(measurements) == {"cold", "warm"}
    assert len(content) <= MAX_OUTPUT_BYTES
    for measurement in measurements.values():
        assert set(measurement) == {"p50_nanoseconds", "p95_nanoseconds"}
        assert 0 <= measurement["p50_nanoseconds"] <= measurement["p95_nanoseconds"]
