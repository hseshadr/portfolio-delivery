"""Behavioral tests for immutable generic-OCI reconciliation through ORAS."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Final

import pytest

from portfolio_delivery.adapters.oras import (
    ArtifactConflict,
    MalformedProviderResponse,
    OrasAdapter,
    ProviderUnavailable,
)
from portfolio_delivery.domain.artifacts import Artifact, Evidence, EvidenceStatus, Sbom
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)
from portfolio_delivery.domain.stages import (
    EnvelopeBundle,
    OciReference,
    PrequalifiedBuild,
    QualifiedEnvelope,
    ReleaseSource,
    SignedBuild,
    SigningDisposition,
    SnapshottedSource,
    UnsignedBuild,
)
from portfolio_delivery.envelope.builder import (
    EnvelopeBuilder,
    EnvelopeMetadata,
    PinnedCompatibility,
    ProjectAdapterVersion,
    QualificationBuilder,
    ReleaseChannel,
    ReleasePolicyMetadata,
)
from tests.fakes.oras import FakeFile, FakeOrasRunner

REPOSITORY: Final[str] = "ghcr.io/hseshadr/delivery"
ARTIFACT_BYTES: Final[bytes] = b"wheel"
SBOM_BYTES: Final[bytes] = b'{"bomFormat":"CycloneDX"}\n'
MAX_MANIFEST_BYTES: Final[int] = 1_048_576
EXPECTED_INITIAL_OBSERVATIONS: Final[int] = 2
EXPECTED_PUSH_PREFIX: Final[tuple[str, ...]] = (
    "oras",
    "push",
    "--artifact-type",
    "application/vnd.hseshadr.portfolio-delivery.envelope.v1",
    "--config",
    "config.v1.json:application/vnd.hseshadr.portfolio-delivery.config.v1+json",
    "--concurrency",
    "1",
    "--annotation",
    "org.opencontainers.image.created=2024-08-24T04:00:00Z",
    "--export-manifest",
    "manifest.json",
)
EXPECTED_PUSH_LAYERS: Final[tuple[str, ...]] = (
    "build-envelope.v1.json:application/vnd.hseshadr.portfolio-delivery.build-envelope.v1+json",
    "qualification-record.v1.json:application/vnd.hseshadr.portfolio-delivery.qualification.v1+json",
    "artifacts/package.whl:application/zip",
    "sbom/package.cdx.json:application/vnd.cyclonedx+json",
)


@dataclass(frozen=True, slots=True)
class Scenario:
    bundle: EnvelopeBundle
    runner: FakeOrasRunner
    adapter: OrasAdapter


def make_digest(content: bytes) -> Sha256Digest:
    return Sha256Digest.from_bytes(content)


def make_source() -> SnapshottedSource:
    project = ProjectId("package")
    source_digest = make_digest(b"source")
    revision = SourceRevision(
        project, "hseshadr/package", "refs/heads/main", "a" * 40, source_digest
    )
    release = ReleaseId(project, "v1.2.3", source_digest, "package-v1.2.3")
    return SnapshottedSource(ReleaseSource(release, revision), make_digest(b"snapshot"))


def make_bundle() -> EnvelopeBundle:
    artifact = make_artifact()
    sbom = make_sbom(artifact)
    signed = make_signed(artifact, sbom)
    envelope = EnvelopeBuilder(make_metadata()).build(signed)
    final = Evidence("archive", "manifest", envelope.content_sha256, EvidenceStatus.PASSED)
    qualified = QualifiedEnvelope(envelope, QualificationBuilder().build(envelope, (final,)))
    return EnvelopeBundle(qualified, (artifact,), (sbom,))


def make_artifact() -> Artifact:
    return Artifact(
        "package",
        ArtifactPath("artifacts/package.whl"),
        "application/zip",
        len(ARTIFACT_BYTES),
        make_digest(ARTIFACT_BYTES),
    )


def make_sbom(artifact: Artifact) -> Sbom:
    return Sbom(
        artifact.path,
        ArtifactPath("sbom/package.cdx.json"),
        "application/vnd.cyclonedx+json",
        make_digest(SBOM_BYTES),
    )


def make_signed(artifact: Artifact, sbom: Sbom) -> SignedBuild:
    unsigned = UnsignedBuild(make_source(), (artifact,), (sbom,), (), ())
    precheck = Evidence("test", "unit", make_digest(b"check"), EvidenceStatus.PASSED)
    return SignedBuild(
        PrequalifiedBuild(unsigned, (precheck,)),
        None,
        SigningDisposition.SIGNING_NOT_REQUIRED,
    )


def make_metadata() -> EnvelopeMetadata:
    return EnvelopeMetadata(
        ProjectAdapterVersion("1.0.0"),
        1_724_472_000,
        ReleasePolicyMetadata("v1.2.3", (ReleaseChannel.STABLE,)),
        PinnedCompatibility("0.21.8", "1.3.3"),
    )


def make_scenario() -> Scenario:
    bundle = make_bundle()
    files = (
        FakeFile("artifacts/package.whl", ARTIFACT_BYTES),
        FakeFile("sbom/package.cdx.json", SBOM_BYTES),
    )
    runner = FakeOrasRunner(files)
    return Scenario(bundle, runner, OrasAdapter(runner, REPOSITORY))


def content_reference(bundle: EnvelopeBundle) -> OciReference:
    digest = bundle.qualified.envelope.content_sha256
    return OciReference(REPOSITORY, f"sha256-{digest.hex}")


def test_should_use_content_tag_and_fixed_layer_order_when_push_is_planned() -> None:
    scenario = make_scenario()

    invocation = scenario.adapter.plan_push(scenario.bundle)

    assert invocation.argv == expected_push_argv(scenario.bundle)
    assert invocation.input_bytes[1:] == (
        scenario.bundle.qualified.envelope.canonical_bytes,
        scenario.bundle.qualified.qualification.canonical_bytes,
    )


def test_should_plan_same_created_annotation_and_inputs_across_attempts() -> None:
    scenario = make_scenario()

    first = scenario.adapter.plan_push(scenario.bundle)
    second = scenario.adapter.plan_push(scenario.bundle)

    assert first == second
    assert "org.opencontainers.image.created=2024-08-24T04:00:00Z" in first.argv


def expected_push_argv(bundle: EnvelopeBundle) -> tuple[str, ...]:
    digest = bundle.qualified.envelope.content_sha256
    return (
        *EXPECTED_PUSH_PREFIX,
        f"{REPOSITORY}:sha256-{digest.hex}",
        *EXPECTED_PUSH_LAYERS,
    )


@pytest.mark.asyncio
async def test_should_push_once_and_reinspect_when_content_tag_is_absent() -> None:
    scenario = make_scenario()

    stored = await scenario.adapter.persist(scenario.bundle, "attempt-absent")

    assert stored.reference.tag == content_reference(scenario.bundle).tag
    assert scenario.runner.write_count == 1
    assert scenario.runner.observation_count == EXPECTED_INITIAL_OBSERVATIONS
    assert {attempt for _, attempt in scenario.runner.invocations} == {"attempt-absent"}


@pytest.mark.asyncio
async def test_should_not_push_when_content_tag_has_identical_bytes() -> None:
    scenario = make_scenario()
    first = await scenario.adapter.persist(scenario.bundle, "attempt-first")

    second = await scenario.adapter.persist(scenario.bundle, "attempt-second")

    assert second.manifest_sha256 == first.manifest_sha256
    assert scenario.runner.write_count == 1
    attempts = {attempt for _, attempt in scenario.runner.invocations}
    assert attempts == {"attempt-first", "attempt-second"}


@pytest.mark.asyncio
async def test_should_reject_conflicting_content_tag_without_takeover() -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    reference = f"{REPOSITORY}:{content_reference(scenario.bundle).tag}"
    scenario.runner.put_manifest(reference, conflicting_manifest(scenario.runner, reference))

    with pytest.raises(ArtifactConflict):
        await scenario.adapter.persist(scenario.bundle, "attempt-conflict")
    assert scenario.runner.write_count == 1


@pytest.mark.asyncio
async def test_should_reject_conflicting_provider_blob_without_takeover() -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    digest = scenario.bundle.artifacts[0].sha256.value
    scenario.runner.blobs[f"{REPOSITORY}@{digest}"] = b"bad!!"

    with pytest.raises(ArtifactConflict):
        await scenario.adapter.persist(scenario.bundle, "attempt-conflicting-blob")
    assert scenario.runner.write_count == 1


@pytest.mark.asyncio
async def test_should_reject_conflicting_created_annotation_without_takeover() -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    reference = f"{REPOSITORY}:{content_reference(scenario.bundle).tag}"
    manifest = conflicting_created_annotation(scenario.runner.manifests[reference])
    scenario.runner.put_manifest(reference, manifest)

    with pytest.raises(ArtifactConflict, match="annotation"):
        await scenario.adapter.persist(scenario.bundle, "attempt-created-conflict")
    assert scenario.runner.write_count == 1


@pytest.mark.asyncio
async def test_should_recover_by_inspection_when_push_times_out_after_write() -> None:
    scenario = make_scenario()
    scenario.runner.timeout_after_write = True

    stored = await scenario.adapter.persist(scenario.bundle, "attempt-timeout")

    assert stored.reference.tag == content_reference(scenario.bundle).tag
    assert scenario.runner.write_count == 1
    assert sum(item.argv[1] == "push" for item, _ in scenario.runner.invocations) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("content", (b"{", b"x" * (MAX_MANIFEST_BYTES + 1)))
async def test_should_reject_malformed_or_oversized_manifest(content: bytes) -> None:
    scenario = make_scenario()
    reference = f"{REPOSITORY}:{content_reference(scenario.bundle).tag}"
    scenario.runner.put_manifest(reference, content)

    with pytest.raises(MalformedProviderResponse):
        await scenario.adapter.inspect(content_reference(scenario.bundle), "attempt-malformed")


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ("media", "missing", "duplicate"))
async def test_should_reject_invalid_layer_manifest(mutation: str) -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    reference = f"{REPOSITORY}:{content_reference(scenario.bundle).tag}"
    mutated = mutate_layers(scenario.runner.manifests[reference], mutation)
    scenario.runner.put_manifest(reference, mutated)

    with pytest.raises(MalformedProviderResponse):
        await scenario.adapter.inspect(content_reference(scenario.bundle), "attempt-invalid")


@pytest.mark.asyncio
async def test_should_reject_remote_manifest_that_differs_at_digest_reference() -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    scenario.runner.digest_manifest_override = b"{}"

    with pytest.raises(MalformedProviderResponse, match="differ"):
        await scenario.adapter.inspect(content_reference(scenario.bundle), "attempt-different")


@pytest.mark.asyncio
async def test_should_restore_exact_envelope_and_payload_metadata() -> None:
    scenario = make_scenario()
    stored = await scenario.adapter.persist(scenario.bundle, "attempt-write")

    restored = await scenario.adapter.restore(stored.reference, "attempt-restore")

    assert_restored_bundle(restored, scenario.bundle)


def assert_restored_bundle(restored: EnvelopeBundle, expected: EnvelopeBundle) -> None:
    assert (
        restored.qualified.envelope.canonical_bytes == expected.qualified.envelope.canonical_bytes
    )
    assert (
        restored.qualified.qualification.canonical_bytes
        == expected.qualified.qualification.canonical_bytes
    )
    assert restored.artifacts == expected.artifacts
    assert restored.sboms == expected.sboms


@pytest.mark.asyncio
async def test_should_fail_closed_when_provider_is_unavailable() -> None:
    scenario = make_scenario()
    reference = OciReference(REPOSITORY, "sha256-" + "0" * 64)

    with pytest.raises(ProviderUnavailable):
        await scenario.adapter.restore(reference, "attempt-unavailable")


@pytest.mark.parametrize("repository", ("https://ghcr.io/repo", "UPPER/repo", "x" * 256))
def test_should_reject_noncanonical_or_unbounded_repository(repository: str) -> None:
    scenario = make_scenario()

    with pytest.raises(ValueError, match="repository"):
        OrasAdapter(scenario.runner, repository)


@pytest.mark.asyncio
async def test_should_reject_noncanonical_tag_before_provider_execution() -> None:
    scenario = make_scenario()
    reference = OciReference(REPOSITORY, "invalid/tag")

    with pytest.raises(ValueError, match="tag"):
        await scenario.adapter.inspect(reference, "attempt-invalid-tag")
    assert not scenario.runner.invocations


def test_should_reject_unbounded_layer_media_type_before_push() -> None:
    scenario = make_scenario()
    artifact = replace(scenario.bundle.artifacts[0], media_type="x" * 256)
    bundle = replace(scenario.bundle, artifacts=(artifact,))

    with pytest.raises(ValueError, match="media type"):
        scenario.adapter.plan_push(bundle)


def test_should_reject_unbounded_layer_path_before_push() -> None:
    scenario = make_scenario()
    artifact = replace(scenario.bundle.artifacts[0], path=ArtifactPath("a" * 4_097))
    bundle = replace(scenario.bundle, artifacts=(artifact,))

    with pytest.raises(ValueError, match="path"):
        scenario.adapter.plan_push(bundle)


def conflicting_manifest(runner: FakeOrasRunner, reference: str) -> bytes:
    document = json.loads(runner.manifests[reference])
    document["layers"][0]["digest"] = "sha256:" + "f" * 64
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def conflicting_created_annotation(content: bytes) -> bytes:
    document = json.loads(content)
    document["annotations"]["org.opencontainers.image.created"] = "2025-01-01T00:00:00Z"
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def mutate_layers(content: bytes, mutation: str) -> bytes:
    document = json.loads(content)
    layers = document["layers"]
    if mutation == "media":
        layers[0]["mediaType"] = "application/octet-stream"
    elif mutation == "missing":
        layers.pop(0)
    else:
        layers.append(layers[0])
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
