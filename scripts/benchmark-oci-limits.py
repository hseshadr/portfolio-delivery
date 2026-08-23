#!/usr/bin/env python3
"""Benchmark exact OCI metadata limits without allocating artifact payloads."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from time import perf_counter_ns

from portfolio_delivery.contracts.oci import DEFAULT_OCI_RESOURCE_LIMITS

DEFAULT_ITERATIONS = 1_001
MAX_ITERATIONS = 100_000


def _boundary_sizes() -> tuple[int, ...]:
    limits = DEFAULT_OCI_RESOURCE_LIMITS
    large = (limits.max_file_bytes,) * 8
    return large + ((0,) * (limits.max_descriptors - len(large)))


def _exercise(sizes: tuple[int, ...]) -> None:
    result = DEFAULT_OCI_RESOURCE_LIMITS.evaluate(sizes)
    if result.violation is not None:
        raise RuntimeError(f"boundary metadata was rejected: {result.violation.value}")


def _sample(operation: Callable[[], None], iterations: int) -> tuple[int, ...]:
    samples: list[int] = []
    for _ in range(iterations):
        started = perf_counter_ns()
        operation()
        samples.append(perf_counter_ns() - started)
    return tuple(sorted(samples))


def _percentile(samples: tuple[int, ...], percentile: int) -> int:
    index = ((len(samples) * percentile + 99) // 100) - 1
    return samples[index]


def _measurement(operation: Callable[[], None], iterations: int) -> dict[str, int]:
    samples = _sample(operation, iterations)
    return {
        "p50_nanoseconds": _percentile(samples, 50),
        "p95_nanoseconds": _percentile(samples, 95),
    }


def _document(iterations: int) -> dict[str, object]:
    sizes = _boundary_sizes()
    _exercise(sizes)
    return {
        "boundary": _boundary_document(sizes),
        "iterations": iterations,
        "limits": _limits_document(),
        "measurements": _measurements(sizes, iterations),
    }


def _boundary_document(sizes: tuple[int, ...]) -> dict[str, int]:
    return {
        "descriptor_count": len(sizes),
        "largest_file_bytes": max(sizes),
        "total_bytes": sum(sizes),
    }


def _limits_document() -> dict[str, int]:
    limits = DEFAULT_OCI_RESOURCE_LIMITS
    return {
        "max_descriptors": limits.max_descriptors,
        "max_file_bytes": limits.max_file_bytes,
        "max_total_bytes": limits.max_total_bytes,
    }


def _measurements(sizes: tuple[int, ...], iterations: int) -> dict[str, dict[str, int]]:
    def warm() -> None:
        _exercise(sizes)

    warm()
    return {
        "cold": _measurement(lambda: _exercise(_boundary_sizes()), iterations),
        "warm": _measurement(warm, iterations),
    }


def _iterations(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= MAX_ITERATIONS:
        raise argparse.ArgumentTypeError("iterations must be between 1 and 100000")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=_iterations, default=DEFAULT_ITERATIONS)
    arguments = parser.parse_args()
    print(json.dumps(_document(arguments.iterations), separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
