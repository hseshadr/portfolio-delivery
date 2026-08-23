"""Run the reusable artifact-store contract against the memory implementation."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import pytest

from portfolio_delivery.adapters.oras import (
    MalformedProviderResponse,
    ProviderTimeout,
    ProviderUnavailable,
)
from portfolio_delivery.domain.stages import EnvelopeBundle, OciReference, StoredEnvelope
from tests.conformance.artifact_store_contract import (
    CONTRACT_ASSERTIONS,
    ArtifactStoreFactory,
    ArtifactStoreHarness,
    Fault,
    assert_invalid_observations_fail_closed,
)
from tests.fakes.storage import FakeArtifactStore
from tests.unit.adapters.test_oras import make_bundle, make_signed_bundle


@dataclass(slots=True)
class MemoryControls:
    fault: Fault | None = None


class ControlledMemoryStore:
    """Inject transport faults around the real in-memory store behavior."""

    def __init__(self, store: FakeArtifactStore, controls: MemoryControls) -> None:
        self._store = store
        self._controls = controls

    async def inspect(self, reference: OciReference, attempt_id: str) -> StoredEnvelope | None:
        _raise_observation_fault(self._controls.fault)
        return await self._store.inspect(reference, attempt_id)

    async def persist(self, bundle: EnvelopeBundle, attempt_id: str) -> StoredEnvelope:
        if self._controls.fault == "timeout-before":
            raise ProviderTimeout("memory transport timed out")
        result = await self._store.persist(bundle, attempt_id)
        if self._controls.fault == "timeout-after":
            return await self._store.inspect(result.reference, attempt_id) or result
        return result

    async def restore(self, reference: OciReference, attempt_id: str) -> EnvelopeBundle:
        return await self._store.restore(reference, attempt_id)


class MemoryFactory:
    async def create(self) -> ArtifactStoreHarness:
        store = FakeArtifactStore()
        controls = MemoryControls()
        bundle = make_bundle()
        adapter = ControlledMemoryStore(store, controls)
        return ArtifactStoreHarness(
            adapter,
            store,
            bundle,
            make_signed_bundle(),
            lambda item: _reference(item, store.repository),
            _injector(controls, store, bundle),
        )


def _injector(
    controls: MemoryControls, store: FakeArtifactStore, bundle: EnvelopeBundle
) -> Callable[[Fault], Awaitable[None]]:
    async def inject(fault: Fault) -> None:
        controls.fault = fault
        if fault == "conflict":
            store.bundles[_key(_reference(bundle, store.repository))] = make_signed_bundle()

    return inject


def _reference(bundle: EnvelopeBundle, repository: str) -> OciReference:
    digest = bundle.qualified.envelope.content_sha256
    return OciReference(repository, f"sha256-{digest.hex}")


def _key(reference: OciReference) -> str:
    return f"{reference.repository}:{reference.tag}"


def _raise_observation_fault(fault: Fault | None) -> None:
    if fault in {"malformed", "oversized"}:
        raise MalformedProviderResponse("memory provider response is invalid")
    if fault == "unavailable":
        raise ProviderUnavailable("memory provider is unavailable")


@pytest.mark.parametrize("assertion", CONTRACT_ASSERTIONS)
async def test_should_satisfy_artifact_store_contract(assertion: object) -> None:
    # Given
    factory: ArtifactStoreFactory = MemoryFactory()

    # When / Then
    await assertion(factory)  # type: ignore[operator]


@pytest.mark.parametrize("fault", ("malformed", "oversized", "unavailable"))
async def test_should_fail_closed_for_invalid_observation(fault: Fault) -> None:
    # Given
    factory: ArtifactStoreFactory = MemoryFactory()

    # When / Then
    await assert_invalid_observations_fail_closed(factory, fault)
