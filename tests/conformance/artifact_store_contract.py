"""Reusable exact-byte behavior contract for artifact-store implementations."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

import pytest

from portfolio_delivery.adapters.oras import (
    ArtifactConflict,
    MalformedProviderResponse,
    ProviderTimeout,
    ProviderUnavailable,
)
from portfolio_delivery.contracts.storage import ArtifactStore
from portfolio_delivery.domain.stages import EnvelopeBundle, OciReference

type Fault = Literal[
    "conflict",
    "timeout-before",
    "timeout-after",
    "malformed",
    "oversized",
    "unavailable",
]


@runtime_checkable
class StoreProbe(Protocol):
    """Observable effect counters shared by memory and provider stores."""

    @property
    def write_count(self) -> int: ...

    @property
    def observation_count(self) -> int: ...


@dataclass(frozen=True, slots=True)
class ArtifactStoreHarness:
    """One fresh store plus controls that remain outside its production port."""

    store: ArtifactStore
    probe: StoreProbe
    bundle: EnvelopeBundle
    alternate: EnvelopeBundle
    reference_for: Callable[[EnvelopeBundle], OciReference]
    inject: Callable[[Fault], Awaitable[None]]


@runtime_checkable
class ArtifactStoreFactory(Protocol):
    """Create independent harnesses for every contract scenario."""

    async def create(self) -> ArtifactStoreHarness: ...


async def assert_absent_state_is_observed(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()

    # When
    observed = await harness.store.inspect(harness.reference_for(harness.bundle), "attempt-absent")

    # Then
    assert observed is None


async def assert_identical_state_is_reused(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()
    first = await harness.store.persist(harness.bundle, "attempt-first")

    # When
    second = await harness.store.persist(harness.bundle, "attempt-second")

    # Then
    assert first.manifest_sha256 == second.manifest_sha256
    assert harness.probe.write_count == 1


async def assert_conflicting_state_is_rejected(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()
    await harness.inject("conflict")

    # When / Then
    with pytest.raises((ArtifactConflict, ValueError)):
        await harness.store.persist(harness.bundle, "attempt-conflict")


async def assert_ten_retries_create_one_write(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()

    # When
    results = [
        await harness.store.persist(harness.bundle, f"attempt-{index}") for index in range(10)
    ]

    # Then
    assert len({result.manifest_sha256 for result in results}) == 1
    assert harness.probe.write_count == 1


async def assert_timeout_before_write_leaves_no_state(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()
    await harness.inject("timeout-before")

    # When / Then
    with pytest.raises(ProviderTimeout):
        await harness.store.persist(harness.bundle, "attempt-before-timeout")
    assert harness.probe.write_count == 0


async def assert_timeout_after_write_reconciles(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()
    await harness.inject("timeout-after")

    # When
    stored = await harness.store.persist(harness.bundle, "attempt-after-timeout")

    # Then
    expected = harness.reference_for(harness.bundle)
    observed = (stored.reference.repository, stored.reference.tag)
    assert observed == (expected.repository, expected.tag)
    assert harness.probe.write_count == 1


@pytest.mark.parametrize("fault", ("malformed", "oversized", "unavailable"))
async def assert_invalid_observations_fail_closed(
    factory: ArtifactStoreFactory, fault: Fault
) -> None:
    # Given
    harness = await factory.create()
    await harness.inject(fault)

    # When / Then
    with pytest.raises((MalformedProviderResponse, ProviderUnavailable)):
        await harness.store.inspect(harness.reference_for(harness.bundle), f"attempt-{fault}")


async def assert_inverted_observations_preserve_identity(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()
    second = await harness.store.persist(harness.alternate, "attempt-later-first")

    # When
    first = await harness.store.persist(harness.bundle, "attempt-earlier-second")
    restored = await harness.store.restore(first.reference, "attempt-restore-first")

    # Then
    assert first.reference != second.reference
    assert restored == harness.bundle


async def assert_restore_is_exact(factory: ArtifactStoreFactory) -> None:
    # Given
    harness = await factory.create()
    stored = await harness.store.persist(harness.bundle, "attempt-write")

    # When
    restored = await harness.store.restore(stored.reference, "attempt-restore")

    # Then
    assert restored == harness.bundle


CONTRACT_ASSERTIONS = (
    assert_absent_state_is_observed,
    assert_identical_state_is_reused,
    assert_conflicting_state_is_rejected,
    assert_ten_retries_create_one_write,
    assert_timeout_before_write_leaves_no_state,
    assert_timeout_after_write_reconciles,
    assert_inverted_observations_preserve_identity,
    assert_restore_is_exact,
)
