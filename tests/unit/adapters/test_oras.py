"""Behavioral tests for immutable generic-OCI reconciliation through ORAS."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Final, cast

import pytest

import portfolio_delivery.adapters.oras as oras_contracts
from portfolio_delivery.adapters.oras import (
    ArtifactConflict,
    MalformedProviderResponse,
    OrasAdapter,
    ProviderTimeout,
    ProviderUnavailable,
)
from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    EvidenceStatus,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
)
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)
from portfolio_delivery.domain.stages import (
    BuildEnvelope,
    EnvelopeBundle,
    OciReference,
    OrasOutcome,
    OrasResult,
    PrequalifiedBuild,
    QualificationRecord,
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
from portfolio_delivery.envelope.canonical import canonical_json_bytes
from portfolio_delivery.envelope.documents import (
    BuildEnvelopeDocument,
    EvidenceDocument,
    QualificationRecordDocument,
)
from tests.fakes.oras import FakeFile, FakeOrasRunner

REPOSITORY: Final[str] = "ghcr.io/hseshadr/delivery"
ARTIFACT_BYTES: Final[bytes] = b"wheel"
SBOM_BYTES: Final[bytes] = b'{"bomFormat":"CycloneDX"}\n'
MAX_MANIFEST_BYTES: Final[int] = 1_048_576
MAX_PROCESS_OUTPUT_BYTES: Final[int] = 65_536
EXPECTED_INITIAL_OBSERVATIONS: Final[int] = 8
OVERSIZED_BLOB: Final[int] = 1_073_741_825
SECOND_ARTIFACT_BYTES: Final[bytes] = b"second-wheel"
SECOND_SBOM_BYTES: Final[bytes] = b'{"bomFormat":"CycloneDX","serialNumber":"two"}\n'
SIGNATURE_BYTES: Final[bytes] = b"detached-signature"
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
    return make_bundle_from((artifact,), (sbom,))


def make_bundle_from(artifacts: tuple[Artifact, ...], sboms: tuple[Sbom, ...]) -> EnvelopeBundle:
    signed = make_signed(artifacts, sboms)
    envelope = EnvelopeBuilder(make_metadata()).build(signed)
    final = Evidence("archive", "manifest", envelope.content_sha256, EvidenceStatus.PASSED)
    qualified = QualifiedEnvelope(envelope, QualificationBuilder().build(envelope, (final,)))
    return EnvelopeBundle(qualified, artifacts, sboms)


def make_signed_bundle() -> EnvelopeBundle:
    artifact = make_artifact()
    signature = Artifact(
        "signature",
        ArtifactPath("signatures/package.sig"),
        "application/vnd.dev.sigstore.bundle+json",
        len(SIGNATURE_BYTES),
        make_digest(SIGNATURE_BYTES),
    )
    prequalified = make_signed((artifact,), (make_sbom(artifact),)).prequalified
    signed = SignedBuild(prequalified, signature, SigningDisposition.SIGNED)
    return make_qualified_bundle(signed, (artifact, signature))


def make_identity_bundle() -> EnvelopeBundle:
    artifact = make_artifact()
    signed = make_signed((artifact,), (make_sbom(artifact),))
    unsigned = replace(
        signed.prequalified.unsigned,
        locks=(LockIdentity(ArtifactPath("uv.lock"), make_digest(b"lock")),),
        toolchains=(ToolchainIdentity("python", "3.13.14", make_digest(b"python")),),
    )
    prequalified = replace(signed.prequalified, unsigned=unsigned)
    return make_qualified_bundle(replace(signed, prequalified=prequalified), (artifact,))


def make_qualified_bundle(signed: SignedBuild, artifacts: tuple[Artifact, ...]) -> EnvelopeBundle:
    envelope = EnvelopeBuilder(make_metadata()).build(signed)
    evidence = Evidence("archive", "manifest", envelope.content_sha256, EvidenceStatus.PASSED)
    qualified = QualifiedEnvelope(envelope, QualificationBuilder().build(envelope, (evidence,)))
    return EnvelopeBundle(qualified, artifacts, signed.prequalified.unsigned.sboms)


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


def make_signed(artifacts: tuple[Artifact, ...], sboms: tuple[Sbom, ...]) -> SignedBuild:
    unsigned = UnsignedBuild(make_source(), artifacts, sboms, (), ())
    precheck = Evidence("test", "unit", make_digest(b"check"), EvidenceStatus.PASSED)
    return SignedBuild(
        PrequalifiedBuild(unsigned, (precheck,)),
        None,
        SigningDisposition.SIGNING_NOT_REQUIRED,
    )


def make_two_artifact_bundle() -> EnvelopeBundle:
    first = make_artifact()
    second = make_second_artifact()
    second_sbom = Sbom(
        second.path,
        ArtifactPath("sbom/second.cdx.json"),
        "application/vnd.cyclonedx+json",
        make_digest(SECOND_SBOM_BYTES),
    )
    return make_bundle_from((second, first), (second_sbom, make_sbom(first)))


def make_second_artifact() -> Artifact:
    return Artifact(
        "second",
        ArtifactPath("artifacts/second.whl"),
        "application/zip",
        len(SECOND_ARTIFACT_BYTES),
        make_digest(SECOND_ARTIFACT_BYTES),
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
async def test_should_reject_concurrent_tag_overwrite_after_push() -> None:
    scenario = make_scenario()
    scenario.runner.overwrite_after_push = True

    with pytest.raises(ArtifactConflict, match="post-push"):
        await scenario.adapter.persist(scenario.bundle, "attempt-race")
    assert scenario.runner.write_count == 1


@pytest.mark.asyncio
async def test_should_keep_process_stdout_distinct_from_exported_manifest() -> None:
    scenario = make_scenario()
    scenario.runner.push_stdout = b"provider progress"

    stored = await scenario.adapter.persist(scenario.bundle, "attempt-distinct-export")

    assert stored.reference.manifest_sha256 == stored.manifest_sha256


@pytest.mark.asyncio
async def test_should_reject_push_that_omits_exported_manifest() -> None:
    scenario = make_scenario()
    scenario.runner.omit_exported_file = True

    with pytest.raises(MalformedProviderResponse, match="omitted"):
        await scenario.adapter.persist(scenario.bundle, "attempt-missing-export")


@pytest.mark.asyncio
async def test_should_reject_oversized_exported_manifest() -> None:
    scenario = make_scenario()
    scenario.runner.exported_file_override = b"x" * (MAX_MANIFEST_BYTES + 1)

    with pytest.raises(MalformedProviderResponse, match="exported"):
        await scenario.adapter.persist(scenario.bundle, "attempt-oversized-export")


@pytest.mark.asyncio
async def test_should_reject_oversized_process_stderr() -> None:
    scenario = make_scenario()
    scenario.runner.push_stderr = b"x" * (MAX_PROCESS_OUTPUT_BYTES + 1)

    with pytest.raises(MalformedProviderResponse, match="stderr"):
        await scenario.adapter.persist(scenario.bundle, "attempt-oversized-stderr")


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
async def test_should_reject_missing_bundle_artifact_before_write() -> None:
    scenario = make_scenario()
    poisoned = replace(scenario.bundle, artifacts=())

    with pytest.raises(ValueError, match="bundle"):
        await scenario.adapter.persist(poisoned, "attempt-missing-artifact")
    assert scenario.runner.write_count == 0
    assert not scenario.runner.invocations


@pytest.mark.asyncio
async def test_should_reject_unbound_qualification_before_write() -> None:
    scenario = make_scenario()
    poisoned = poison_qualification(scenario.bundle)

    with pytest.raises(ValueError, match="qualification"):
        await scenario.adapter.persist(poisoned, "attempt-poison-qualification")
    assert scenario.runner.write_count == 0
    assert not scenario.runner.invocations


@pytest.mark.asyncio
async def test_should_reject_unrecorded_signing_fact_before_write() -> None:
    scenario = make_scenario()
    poisoned = poison_signing(scenario.bundle)

    with pytest.raises(ValueError, match="envelope"):
        await scenario.adapter.persist(poisoned, "attempt-poison-signing")
    assert scenario.runner.write_count == 0
    assert not scenario.runner.invocations


def test_should_plan_canonical_layers_when_bundle_tuples_are_reordered() -> None:
    bundle = make_two_artifact_bundle()
    reordered = replace(
        bundle, artifacts=tuple(reversed(bundle.artifacts)), sboms=tuple(reversed(bundle.sboms))
    )
    adapter = OrasAdapter(FakeOrasRunner(), REPOSITORY)

    first = adapter.plan_push(bundle)
    second = adapter.plan_push(reordered)

    assert first.argv == second.argv
    assert first.input_bytes[1:] == second.input_bytes[1:]


@pytest.mark.asyncio
async def test_should_recover_by_inspection_when_push_times_out_after_write() -> None:
    scenario = make_scenario()
    scenario.runner.timeout_after_write = True

    stored = await scenario.adapter.persist(scenario.bundle, "attempt-timeout")

    assert stored.reference.tag == content_reference(scenario.bundle).tag
    assert scenario.runner.write_count == 1
    assert sum(item.argv[1] == "push" for item, _ in scenario.runner.invocations) == 1


@pytest.mark.asyncio
async def test_should_surface_timeout_when_push_did_not_write() -> None:
    scenario = make_scenario()
    scenario.runner.timeout_before_write = True

    with pytest.raises(ProviderTimeout):
        await scenario.adapter.persist(scenario.bundle, "attempt-timeout-before-write")

    assert scenario.runner.write_count == 0


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
@pytest.mark.parametrize("mutation", ("duplicate-key", "unexpected-annotation", "absolute-title"))
async def test_should_reject_noncanonical_manifest_descriptor(mutation: str) -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    reference = f"{REPOSITORY}:{content_reference(scenario.bundle).tag}"
    content = mutate_descriptor(scenario.runner.manifests[reference], mutation)
    scenario.runner.put_manifest(reference, content)

    with pytest.raises(MalformedProviderResponse):
        await scenario.adapter.inspect(content_reference(scenario.bundle), "attempt-descriptor")


@pytest.mark.asyncio
@pytest.mark.parametrize("layer", ("artifact", "sbom"))
async def test_should_reject_absolute_non_core_layer_title(layer: str) -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    reference = f"{REPOSITORY}:{content_reference(scenario.bundle).tag}"
    content = mutate_non_core_title(scenario.runner.manifests[reference], layer)
    scenario.runner.put_manifest(reference, content)

    with pytest.raises(MalformedProviderResponse, match="title"):
        await scenario.adapter.inspect(content_reference(scenario.bundle), "attempt-layer-title")


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


@pytest.mark.asyncio
async def test_should_restore_exact_lock_and_toolchain_fields() -> None:
    # Given
    bundle = make_identity_bundle()
    runner = FakeOrasRunner(
        (
            FakeFile("artifacts/package.whl", ARTIFACT_BYTES),
            FakeFile("sbom/package.cdx.json", SBOM_BYTES),
        )
    )
    adapter = OrasAdapter(runner, REPOSITORY)

    # When
    stored = await adapter.persist(bundle, "attempt-identity-write")
    restored = await adapter.restore(stored.reference, "attempt-identity-restore")

    # Then
    unsigned = restored.qualified.envelope.signed.prequalified.unsigned
    assert unsigned.locks == bundle.qualified.envelope.signed.prequalified.unsigned.locks
    assert unsigned.toolchains == bundle.qualified.envelope.signed.prequalified.unsigned.toolchains


@pytest.mark.asyncio
async def test_should_restore_exact_signed_stage_graph() -> None:
    bundle = make_signed_bundle()
    runner = FakeOrasRunner(
        (
            FakeFile("artifacts/package.whl", ARTIFACT_BYTES),
            FakeFile("sbom/package.cdx.json", SBOM_BYTES),
            FakeFile("signatures/package.sig", SIGNATURE_BYTES),
        )
    )
    adapter = OrasAdapter(runner, REPOSITORY)

    stored = await adapter.persist(bundle, "attempt-signed-write")
    restored = await adapter.restore(stored.reference, "attempt-signed-restore")

    assert restored == bundle


@pytest.mark.asyncio
async def test_should_restore_exact_reordered_stage_graph() -> None:
    bundle = make_two_artifact_bundle()
    runner = FakeOrasRunner(two_artifact_files())
    adapter = OrasAdapter(runner, REPOSITORY)

    stored = await adapter.persist(bundle, "attempt-reordered-write")
    restored = await adapter.restore(stored.reference, "attempt-reordered-restore")

    assert restored == bundle


def two_artifact_files() -> tuple[FakeFile, ...]:
    return (
        FakeFile("artifacts/package.whl", ARTIFACT_BYTES),
        FakeFile("artifacts/second.whl", SECOND_ARTIFACT_BYTES),
        FakeFile("sbom/package.cdx.json", SBOM_BYTES),
        FakeFile("sbom/second.cdx.json", SECOND_SBOM_BYTES),
    )


def assert_restored_bundle(restored: EnvelopeBundle, expected: EnvelopeBundle) -> None:
    assert restored == expected


@pytest.mark.asyncio
async def test_should_fail_closed_when_provider_is_unavailable() -> None:
    scenario = make_scenario()
    reference = OciReference(REPOSITORY, "sha256-" + "0" * 64)

    with pytest.raises(ProviderUnavailable):
        await scenario.adapter.restore(reference, "attempt-unavailable")


@pytest.mark.asyncio
async def test_should_treat_only_typed_not_found_as_absent() -> None:
    scenario = make_scenario()
    reference = content_reference(scenario.bundle)
    scenario.runner.missing_stderr = b"opaque provider text"

    assert await scenario.adapter.inspect(reference, "attempt-not-found") is None

    scenario.runner.missing_outcome = OrasOutcome.FAILURE
    scenario.runner.missing_stderr = b"manifest unknown: not found"
    with pytest.raises(ProviderUnavailable):
        await scenario.adapter.inspect(reference, "attempt-failure")


@pytest.mark.asyncio
async def test_should_bound_stdout_even_when_provider_fails() -> None:
    scenario = make_scenario()
    scenario.runner.missing_outcome = OrasOutcome.FAILURE
    scenario.runner.missing_stdout = b"x" * (MAX_MANIFEST_BYTES + 1)

    with pytest.raises(MalformedProviderResponse, match="stdout"):
        await scenario.adapter.inspect(content_reference(scenario.bundle), "attempt-stdout-bound")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exported", (b"unexpected", b"x" * (MAX_MANIFEST_BYTES + 1)), ids=("small", "oversized")
)
async def test_should_reject_exported_file_on_manifest_fetch(exported: bytes) -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    scenario.runner.manifest_exported_file_bytes = exported

    with pytest.raises(MalformedProviderResponse, match="exported file"):
        reference = content_reference(scenario.bundle)
        await scenario.adapter.inspect(reference, "attempt-manifest-export")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exported", (b"unexpected", b"x" * (MAX_MANIFEST_BYTES + 1)), ids=("small", "oversized")
)
async def test_should_reject_exported_file_on_blob_fetch(exported: bytes) -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    scenario.runner.blob_exported_file_bytes = exported

    with pytest.raises(MalformedProviderResponse, match="exported file"):
        await scenario.adapter.persist(scenario.bundle, "attempt-blob-export")


@pytest.mark.asyncio
@pytest.mark.parametrize("size", (len(SBOM_BYTES) + 1, OVERSIZED_BLOB))
async def test_should_reject_invalid_or_unbounded_blob_descriptor_size(size: int) -> None:
    scenario = make_scenario()
    await scenario.adapter.persist(scenario.bundle, "attempt-seed")
    reference = f"{REPOSITORY}:{content_reference(scenario.bundle).tag}"
    mutated = mutate_sbom_size(scenario.runner.manifests[reference], size)
    scenario.runner.put_manifest(reference, mutated)

    with pytest.raises(MalformedProviderResponse, match="size"):
        await scenario.adapter.persist(scenario.bundle, "attempt-size")


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
    bundle = make_bundle_from((artifact,), scenario.bundle.sboms)

    with pytest.raises(ValueError, match="media type"):
        scenario.adapter.plan_push(bundle)


def test_should_reject_unbounded_layer_path_before_push() -> None:
    scenario = make_scenario()
    artifact = replace(scenario.bundle.artifacts[0], path=ArtifactPath("a" * 4_097))
    sbom = replace(scenario.bundle.sboms[0], artifact_path=artifact.path)
    bundle = make_bundle_from((artifact,), (sbom,))

    with pytest.raises(ValueError, match="path"):
        scenario.adapter.plan_push(bundle)


def test_should_reject_non_bundle_contract_before_planning() -> None:
    with pytest.raises(ValueError):
        oras_contracts._validate_bundle(cast(EnvelopeBundle, object()))


def test_should_preserve_every_validated_bundle_component() -> None:
    validated = oras_contracts._validate_bundle(make_bundle())

    assert validated.envelope_document == validated.bundle.qualified.envelope.document
    assert validated.qualification_document == validated.bundle.qualified.qualification.document
    assert validated.artifacts == make_bundle().artifacts
    assert validated.sboms == make_bundle().sboms


def test_should_reject_bundle_document_that_differs_from_exact_bytes() -> None:
    bundle = make_bundle()
    envelope = replace(
        bundle.qualified.envelope,
        document=make_two_artifact_bundle().qualified.envelope.document,
    )
    poisoned = replace(bundle, qualified=replace(bundle.qualified, envelope=envelope))

    with pytest.raises(ValueError):
        oras_contracts._validate_bundle(poisoned)


def test_should_reject_qualification_document_that_differs_from_exact_bytes() -> None:
    bundle = make_bundle()
    record = replace(
        bundle.qualified.qualification,
        document=poison_qualification(bundle).qualified.qualification.document,
    )
    poisoned = replace(bundle, qualified=replace(bundle.qualified, qualification=record))

    with pytest.raises(ValueError):
        oras_contracts._validate_bundle(poisoned)


def test_should_reject_bundle_sbom_set_that_differs_from_envelope() -> None:
    with pytest.raises(ValueError):
        oras_contracts._validate_bundle(replace(make_bundle(), sboms=()))


@pytest.mark.parametrize("actual", ([], ("wrong-type",)))
def test_should_reject_non_tuple_or_wrong_typed_record_set(actual: object) -> None:
    expected = make_bundle().artifacts

    assert not oras_contracts._same_records(
        actual, expected, Artifact, oras_contracts._artifact_key
    )


def test_should_translate_invalid_local_documents_to_value_error() -> None:
    with pytest.raises(ValueError):
        oras_contracts._local_envelope_document(b"{}")
    with pytest.raises(ValueError):
        oras_contracts._local_qualification_document(b"{}")


def test_should_accept_exact_repository_and_tag_bounds() -> None:
    repository = "a/" + ("a" * 253)
    adapter = OrasAdapter(FakeOrasRunner(), repository)

    oras_contracts._validate_reference(OciReference(repository, "a" * 128))
    assert adapter.repository == repository


def test_should_reject_duplicate_expected_layer_paths() -> None:
    layer = oras_contracts._exact_layer("same", "application/octet-stream", b"x")

    with pytest.raises(ValueError):
        oras_contracts._validate_expected_layers((layer, layer))


def test_should_accept_exact_layer_text_bounds_and_reject_absolute_path() -> None:
    digest = make_digest(b"x")
    bounded = oras_contracts._ExpectedLayer("a" * 4_096, "m" * 255, digest, 1)
    absolute = oras_contracts._ExpectedLayer("/absolute", "m", digest, 1)

    oras_contracts._validate_layer_text(bounded)
    with pytest.raises(ValueError):
        oras_contracts._validate_layer_text(absolute)


def test_should_reject_unrepresentable_source_date_epoch() -> None:
    bundle = make_bundle()
    envelope_document = bundle.qualified.envelope.document
    assert isinstance(envelope_document, BuildEnvelopeDocument)
    document = envelope_document.model_dump(by_alias=True)
    document["sourceDateEpoch"] = 10**30
    content = json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    envelope = replace(
        bundle.qualified.envelope,
        canonical_bytes=content,
        content_sha256=make_digest(content),
    )
    qualified = SimpleNamespace(envelope=envelope)
    poisoned = cast(EnvelopeBundle, SimpleNamespace(qualified=qualified))

    with pytest.raises(ValueError):
        oras_contracts._created_timestamp(poisoned)


def test_should_preserve_exact_and_artifact_layer_contracts() -> None:
    exact = oras_contracts._exact_layer("file", "media", b"abc")
    artifact = oras_contracts._artifact_layer(make_artifact())

    assert (exact.size, exact.exact_bytes) == (3, b"abc")
    assert artifact.size == len(ARTIFACT_BYTES)


def test_should_build_exact_provider_fetch_invocations() -> None:
    manifest = oras_contracts._manifest_fetch("repo:tag")
    blob = oras_contracts._blob_fetch("repo@sha256:digest")

    assert manifest.argv == ("oras", "manifest", "fetch", "repo:tag")
    assert blob.argv == ("oras", "blob", "fetch", "repo@sha256:digest")


def test_should_fail_closed_for_non_successful_stdout() -> None:
    failed = OrasResult(1, OrasOutcome.FAILURE, b"", b"failed")

    with pytest.raises(ProviderUnavailable):
        oras_contracts._successful_stdout(failed, 1)


def test_should_accept_exact_process_and_manifest_response_bounds() -> None:
    result = OrasResult(0, OrasOutcome.SUCCESS, b"", b"x" * 65_536)

    oras_contracts._require_bounded_stderr(result)
    assert len(oras_contracts._bounded_export(b"x" * MAX_MANIFEST_BYTES)) == MAX_MANIFEST_BYTES


def _descriptor_from_layer(
    layer: oras_contracts._ExpectedLayer, *, title: bool
) -> oras_contracts._Descriptor:
    annotations = {oras_contracts.TITLE_ANNOTATION: layer.path} if title else {}
    size = layer.size if layer.size is not None else 0
    return oras_contracts._Descriptor(
        mediaType=layer.media_type, digest=layer.digest.value, size=size, annotations=annotations
    )


def _valid_manifest() -> oras_contracts._Manifest:
    layers = oras_contracts._expected_layers(oras_contracts._validate_bundle(make_bundle()))
    return oras_contracts._Manifest(
        schemaVersion=2,
        mediaType="application/vnd.oci.image.manifest.v1+json",
        artifactType="application/vnd.hseshadr.portfolio-delivery.envelope.v1",
        config=_descriptor_from_layer(layers[0], title=False),
        layers=tuple(_descriptor_from_layer(item, title=True) for item in layers[1:]),
        annotations={
            oras_contracts.CREATED_ANNOTATION: oras_contracts._created_timestamp(make_bundle())
        },
    )


@pytest.mark.parametrize("mutation", ("config-media", "config-annotation", "missing-core"))
def test_should_reject_invalid_manifest_core_contract(mutation: str) -> None:
    manifest = _valid_manifest()
    if mutation == "config-media":
        config = manifest.config.model_copy(update={"media_type": "wrong"})
        manifest = manifest.model_copy(update={"config": config})
    elif mutation == "config-annotation":
        config = manifest.config.model_copy(update={"annotations": {"title": "bad"}})
        manifest = manifest.model_copy(update={"config": config})
    else:
        manifest = manifest.model_copy(update={"layers": manifest.layers[:1]})
    with pytest.raises(MalformedProviderResponse):
        oras_contracts._validate_manifest_layers(manifest)


def test_should_accept_manifest_with_exactly_required_core_layers() -> None:
    manifest = _valid_manifest().model_copy(update={"layers": _valid_manifest().layers[:2]})

    oras_contracts._validate_manifest_layers(manifest)


def test_should_reject_missing_or_oversized_layer_title() -> None:
    for title in (None, "a" * 4_097):
        with pytest.raises(MalformedProviderResponse):
            oras_contracts._require_canonical_layer_title(title)
    oras_contracts._require_canonical_layer_title("a" * 4_096)


def test_should_reject_conflicting_declared_manifest_digest() -> None:
    reference = OciReference(REPOSITORY, "tag", make_digest(b"declared"))

    with pytest.raises(ArtifactConflict):
        oras_contracts._require_declared_manifest(reference, make_digest(b"actual"))


def test_should_reject_mismatched_descriptor_and_content_cardinality() -> None:
    descriptor = _valid_manifest().config

    with pytest.raises(ValueError):
        oras_contracts._require_descriptor_bytes((descriptor,), ())


@pytest.mark.parametrize("content", (b"xx", b"y"))
def test_should_reject_descriptor_size_or_digest_difference(content: bytes) -> None:
    descriptor = _descriptor_from_layer(
        oras_contracts._exact_layer("file", "media", b"x"), title=False
    )

    with pytest.raises(MalformedProviderResponse):
        oras_contracts._require_descriptor_bytes((descriptor,), (content,))


def test_should_accept_exact_maximum_blob_descriptor_size() -> None:
    oras_contracts._require_bounded_blob_size(1_073_741_824)


def test_should_preserve_reference_when_observation_is_stored() -> None:
    manifest = _valid_manifest()
    content = canonical_json_bytes(manifest)
    observation = oras_contracts._Observation(content, make_digest(content), manifest)
    reference = OciReference(REPOSITORY, "tag")

    stored = oras_contracts._stored(reference, observation)
    assert stored is not None
    assert stored.reference.repository == reference.repository


@pytest.mark.parametrize("order", ((0, 0), (1,), (-1,)))
def test_should_reject_invalid_record_order(order: tuple[int, ...]) -> None:
    with pytest.raises(ValueError):
        oras_contracts._ordered(("only",), order)


@pytest.mark.parametrize("exact", (False, True), ids=("declared-size", "reviewed-bytes"))
def test_should_preserve_conflict_type_for_blob_mismatch(exact: bool) -> None:
    content = b"x"
    size = 1 if exact else 2
    exact_bytes = b"y" if exact else None
    layer = oras_contracts._ExpectedLayer("file", "media", make_digest(content), size, exact_bytes)

    with pytest.raises(ArtifactConflict):
        oras_contracts._require_blob(content, layer, ArtifactConflict)


def _valid_restore_parts() -> tuple[oras_contracts._Manifest, tuple[bytes, ...]]:
    validated = oras_contracts._validate_bundle(make_bundle())
    contents = (
        canonical_json_bytes(validated.config_document),
        validated.bundle.qualified.envelope.canonical_bytes,
        validated.bundle.qualified.qualification.canonical_bytes,
        ARTIFACT_BYTES,
        SBOM_BYTES,
    )
    return _valid_manifest(), contents


def test_should_use_malformed_response_type_for_restored_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[type[oras_contracts.OrasAdapterError]] = []

    def record_type(
        _manifest: object, _expected: object, error_type: type[oras_contracts.OrasAdapterError]
    ) -> None:
        captured.append(error_type)

    monkeypatch.setattr(oras_contracts, "_require_descriptors", record_type)
    manifest, contents = _valid_restore_parts()
    oras_contracts._restore_bundle(manifest, contents)
    assert captured == [MalformedProviderResponse]


def test_should_translate_invalid_restored_record_assembly() -> None:
    validated = oras_contracts._validate_bundle(make_bundle())
    order = validated.config_document.stage_order.model_copy(
        update={"bundle_artifact_order": (0, 0)}
    )
    config = validated.config_document.model_copy(update={"stage_order": order})

    with pytest.raises(MalformedProviderResponse):
        oras_contracts._validated_assembly(
            config,
            validated.envelope_document,
            validated.qualification_document,
            validated.bundle.qualified.envelope.canonical_bytes,
            validated.bundle.qualified.qualification.canonical_bytes,
        )


def test_should_translate_invalid_restored_bundle_graph() -> None:
    config = oras_contracts._validate_bundle(make_bundle()).config_document

    with pytest.raises(MalformedProviderResponse):
        oras_contracts._validated_restored_bundle(cast(EnvelopeBundle, object()), config)


def test_should_reject_restored_config_that_differs_from_bundle_graph() -> None:
    bundle = make_bundle()
    config = oras_contracts._validate_bundle(bundle).config_document
    conflicting = config.model_copy(update={"release_idempotency_key": "different"})

    with pytest.raises(MalformedProviderResponse):
        oras_contracts._validated_restored_bundle(bundle, conflicting)


def test_should_reject_malformed_stored_config() -> None:
    with pytest.raises(MalformedProviderResponse):
        oras_contracts._parse_config(b"{}")


def test_should_reject_noncanonical_stored_documents() -> None:
    validated = oras_contracts._validate_bundle(make_bundle())
    values = (
        (oras_contracts._parse_config, canonical_json_bytes(validated.config_document)),
        (oras_contracts._parse_envelope, validated.bundle.qualified.envelope.canonical_bytes),
        (
            oras_contracts._parse_qualification,
            validated.bundle.qualified.qualification.canonical_bytes,
        ),
    )
    for parser, content in values:
        with pytest.raises(MalformedProviderResponse):
            parser(content[:-1] + b" \n")


def test_should_reject_signature_path_without_exact_artifact() -> None:
    validated = oras_contracts._validate_bundle(make_bundle())
    config = validated.config_document.model_copy(update={"signature_path": "missing.sig"})

    with pytest.raises(ValueError):
        oras_contracts._signature_artifact(validated.artifacts, config)


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


def poison_qualification(bundle: EnvelopeBundle) -> EnvelopeBundle:
    envelope = bundle.qualified.envelope
    evidence = EvidenceDocument(
        kind="archive", name="manifest", subject=make_digest(b"wrong").value, status="passed"
    )
    document = QualificationRecordDocument(
        subject=envelope.content_sha256.value, qualificationEvidence=(evidence,)
    )
    content = canonical_json_bytes(document)
    record = QualificationRecord(
        envelope.content_sha256, document, content, Sha256Digest.from_bytes(content)
    )
    return replace(bundle, qualified=QualifiedEnvelope(envelope, record))


def poison_signing(bundle: EnvelopeBundle) -> EnvelopeBundle:
    envelope = bundle.qualified.envelope
    signature = Artifact(
        "signature",
        ArtifactPath("signatures/package.sig"),
        "application/signature",
        3,
        make_digest(b"sig"),
    )
    signed = SignedBuild(envelope.signed.prequalified, signature, SigningDisposition.SIGNED)
    poisoned = BuildEnvelope(
        signed, envelope.document, envelope.canonical_bytes, envelope.content_sha256
    )
    qualified = QualifiedEnvelope(poisoned, bundle.qualified.qualification)
    return replace(bundle, qualified=qualified)


def mutate_descriptor(content: bytes, mutation: str) -> bytes:
    if mutation == "duplicate-key":
        return content.replace(b'"schemaVersion":2', b'"schemaVersion":2,"schemaVersion":2', 1)
    document = json.loads(content)
    if mutation == "unexpected-annotation":
        document["layers"][0]["annotations"]["unexpected"] = "value"
    else:
        title = document["layers"][0]["annotations"]["org.opencontainers.image.title"]
        document["layers"][0]["annotations"]["org.opencontainers.image.title"] = f"/work/{title}"
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def mutate_sbom_size(content: bytes, size: int) -> bytes:
    document = json.loads(content)
    document["layers"][-1]["size"] = size
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def mutate_non_core_title(content: bytes, layer: str) -> bytes:
    document = json.loads(content)
    index = -2 if layer == "artifact" else -1
    descriptor = document["layers"][index]
    title = descriptor["annotations"]["org.opencontainers.image.title"]
    descriptor["annotations"]["org.opencontainers.image.title"] = f"/work/{title}"
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
