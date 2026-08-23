"""Shared OCI provider resource-policy contracts."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class OciResourceViolation(StrEnum):
    """Reasons an OCI descriptor inventory can exceed its resource policy."""

    DESCRIPTOR_COUNT = "descriptor-count"
    FILE_SIZE = "file-size"
    AGGREGATE_SIZE = "aggregate-size"
    INVALID_SIZE = "invalid-size"


@dataclass(frozen=True, slots=True)
class OciResourceResult:
    """Typed result of evaluating an OCI descriptor inventory."""

    violation: OciResourceViolation | None


@dataclass(frozen=True, slots=True)
class OciResourceLimits:
    """Maximum resource use accepted by OCI provider adapters."""

    max_descriptors: int
    max_file_bytes: int
    max_total_bytes: int

    def __post_init__(self) -> None:
        """Reject unusable policy values at the composition boundary."""
        for value in (self.max_descriptors, self.max_file_bytes, self.max_total_bytes):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError("OCI resource limits must be positive integers")

    def evaluate(self, sizes: Iterable[int]) -> OciResourceResult:
        """Evaluate declared descriptor sizes without reading their contents."""
        declared = tuple(sizes)
        violation = _resource_violation(declared, self)
        return OciResourceResult(violation=violation)


def _resource_violation(
    sizes: tuple[int, ...], limits: OciResourceLimits
) -> OciResourceViolation | None:
    checks = _policy_checks(sizes, limits)
    return next((violation for exceeded, violation in checks if exceeded), None)


def _policy_checks(
    sizes: tuple[int, ...], limits: OciResourceLimits
) -> tuple[tuple[bool, OciResourceViolation], ...]:
    return (
        (len(sizes) > limits.max_descriptors, OciResourceViolation.DESCRIPTOR_COUNT),
        (any(_invalid_size(size) for size in sizes), OciResourceViolation.INVALID_SIZE),
        (any(size > limits.max_file_bytes for size in sizes), OciResourceViolation.FILE_SIZE),
        (sum(sizes) > limits.max_total_bytes, OciResourceViolation.AGGREGATE_SIZE),
    )


def _invalid_size(size: object) -> bool:
    return isinstance(size, bool) or not isinstance(size, int) or size < 0


DEFAULT_OCI_RESOURCE_LIMITS: Final[OciResourceLimits] = OciResourceLimits(
    max_descriptors=256,
    max_file_bytes=64 * 1_048_576,
    max_total_bytes=512 * 1_048_576,
)
