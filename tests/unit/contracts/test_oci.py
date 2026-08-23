"""Behavioral tests for the shared OCI resource policy."""

from typing import Final

import pytest

from portfolio_delivery.contracts.oci import (
    DEFAULT_OCI_RESOURCE_LIMITS,
    OciResourceLimits,
    OciResourceViolation,
)

MIB: Final[int] = 1_048_576


@pytest.mark.parametrize(
    ("sizes", "expected"),
    (
        ((1,) * 256, None),
        ((1,) * 257, OciResourceViolation.DESCRIPTOR_COUNT),
        ((64 * MIB,), None),
        ((64 * MIB + 1,), OciResourceViolation.FILE_SIZE),
        ((64 * MIB,) * 8, None),
        ((64 * MIB,) * 8 + (1,), OciResourceViolation.AGGREGATE_SIZE),
        ((-1,), OciResourceViolation.INVALID_SIZE),
        ((0,), None),
        ((True,), OciResourceViolation.INVALID_SIZE),
        ((1.5,), OciResourceViolation.INVALID_SIZE),
    ),
)
def test_should_apply_exact_default_oci_resource_boundaries(
    sizes: tuple[int, ...], expected: OciResourceViolation | None
) -> None:
    # Given / When
    result = DEFAULT_OCI_RESOURCE_LIMITS.evaluate(sizes)

    # Then
    assert result.violation is expected


@pytest.mark.parametrize("value", (0, -1, True, 1.5))
def test_should_reject_invalid_policy_limits(value: object) -> None:
    # When / Then
    with pytest.raises(ValueError):
        OciResourceLimits(
            max_descriptors=value,  # type: ignore[arg-type]
            max_file_bytes=1,
            max_total_bytes=1,
        )
