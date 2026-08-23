"""Run the reusable artifact-store contract through the pure ORAS adapter."""

from __future__ import annotations

import pytest

from portfolio_delivery.adapters.oras import MAX_MANIFEST_BYTES, OrasAdapter
from portfolio_delivery.domain.stages import EnvelopeBundle, OrasOutcome
from tests.conformance.artifact_store_contract import (
    CONTRACT_ASSERTIONS,
    ArtifactStoreFactory,
    ArtifactStoreHarness,
    Fault,
    assert_invalid_observations_fail_closed,
)
from tests.fakes.oras import FakeFile, FakeOrasRunner
from tests.unit.adapters.test_oras import (
    ARTIFACT_BYTES,
    REPOSITORY,
    SBOM_BYTES,
    SIGNATURE_BYTES,
    content_reference,
    make_bundle,
    make_signed_bundle,
)


class OrasFactory:
    async def create(self) -> ArtifactStoreHarness:
        bundle = make_bundle()
        alternate = make_signed_bundle()
        runner = FakeOrasRunner(_files())
        adapter = OrasAdapter(runner, REPOSITORY)

        async def inject(fault: Fault) -> None:
            _inject_simple_fault(runner, bundle, fault)
            if fault == "conflict":
                await _seed_conflict(adapter, runner, bundle, alternate)

        return ArtifactStoreHarness(adapter, runner, bundle, alternate, content_reference, inject)


def _files() -> tuple[FakeFile, ...]:
    return (
        FakeFile("artifacts/package.whl", ARTIFACT_BYTES),
        FakeFile("sbom/package.cdx.json", SBOM_BYTES),
        FakeFile("signatures/package.sig", SIGNATURE_BYTES),
    )


def _inject_simple_fault(runner: FakeOrasRunner, bundle: EnvelopeBundle, fault: Fault) -> None:
    runner.timeout_before_write = fault == "timeout-before"
    runner.timeout_after_write = fault == "timeout-after"
    if fault in {"malformed", "oversized"}:
        content = b"{" if fault == "malformed" else b"x" * (MAX_MANIFEST_BYTES + 1)
        runner.put_manifest(f"{REPOSITORY}:{content_reference(bundle).tag}", content)
    if fault == "unavailable":
        runner.missing_outcome = OrasOutcome.FAILURE


async def _seed_conflict(
    adapter: OrasAdapter,
    runner: FakeOrasRunner,
    bundle: EnvelopeBundle,
    alternate: EnvelopeBundle,
) -> None:
    stored = await adapter.persist(alternate, "attempt-seed-conflict")
    manifest = runner.manifests[f"{stored.reference.repository}:{stored.reference.tag}"]
    runner.put_manifest(f"{REPOSITORY}:{content_reference(bundle).tag}", manifest)


@pytest.mark.parametrize("assertion", CONTRACT_ASSERTIONS)
async def test_should_satisfy_artifact_store_contract(assertion: object) -> None:
    # Given
    factory: ArtifactStoreFactory = OrasFactory()

    # When / Then
    await assertion(factory)  # type: ignore[operator]


@pytest.mark.parametrize("fault", ("malformed", "oversized", "unavailable"))
async def test_should_fail_closed_for_invalid_observation(fault: Fault) -> None:
    # Given
    factory: ArtifactStoreFactory = OrasFactory()

    # When / Then
    await assert_invalid_observations_fail_closed(factory, fault)
