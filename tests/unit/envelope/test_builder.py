"""Behavioral tests for final envelope and detached qualification builders."""

from collections.abc import Callable
from typing import Final, cast

import pytest

from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    EvidenceStatus,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
)
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)
from portfolio_delivery.domain.stages import (
    PrequalifiedBuild,
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
from portfolio_delivery.envelope.documents import BuildEnvelopeDocument

SOURCE_DATE_EPOCH: Final[int] = 1_724_472_000


def make_digest(character: str) -> Sha256Digest:
    return Sha256Digest(f"sha256:{character * 64}")


def make_source() -> SnapshottedSource:
    project = ProjectId("catalog")
    digest = make_digest("a")
    revision = SourceRevision(project, "hseshadr/catalog", "refs/heads/main", "b" * 40, digest)
    release = ReleaseSource(ReleaseId(project, "v1.2.3", digest, "catalog-v1.2.3"), revision)
    return SnapshottedSource(release, make_digest("c"))


def make_artifact(name: str = "catalog") -> Artifact:
    return Artifact(
        name, ArtifactPath(f"artifacts/{name}.whl"), "application/zip", 5, make_digest("d")
    )


def make_signed_build(artifact_name: str = "catalog") -> SignedBuild:
    unsigned = UnsignedBuild(make_source(), (make_artifact(artifact_name),), (), (), ())
    prequalified = PrequalifiedBuild(unsigned, (make_precheck(),))
    return SignedBuild(prequalified, make_signature(), SigningDisposition.SIGNED)


def make_precheck() -> Evidence:
    return Evidence("test", "unit", make_digest("e"), EvidenceStatus.PASSED)


def make_signature() -> Artifact:
    return Artifact(
        "signature",
        ArtifactPath("signatures/catalog.sig"),
        "application/signature",
        64,
        make_digest("f"),
    )


def make_final_check(envelope_digest: Sha256Digest, status: EvidenceStatus) -> Evidence:
    return Evidence("archive", "manifest", envelope_digest, status)


def make_metadata() -> EnvelopeMetadata:
    return EnvelopeMetadata(
        ProjectAdapterVersion("1.0.0"),
        SOURCE_DATE_EPOCH,
        ReleasePolicyMetadata("v1.2.3", (ReleaseChannel.STABLE,)),
        PinnedCompatibility("0.21.8", "1.3.3"),
    )


def test_should_keep_envelope_digest_when_final_checks_change() -> None:
    # Given
    envelope = EnvelopeBuilder(make_metadata()).build(make_signed_build())
    first_checks = (make_final_check(envelope.content_sha256, EvidenceStatus.PASSED),)
    second_checks = (make_final_check(envelope.content_sha256, EvidenceStatus.FAILED),)

    # When
    first = QualificationBuilder().build(envelope, first_checks)
    second = QualificationBuilder().build(envelope, second_checks)

    # Then
    assert first.subject == second.subject == envelope.content_sha256
    assert first.canonical_bytes != second.canonical_bytes
    assert first.content_sha256 != second.content_sha256


def test_should_include_signature_when_signed_build_is_assembled() -> None:
    # Given
    signed = make_signed_build()

    # When
    envelope = EnvelopeBuilder(make_metadata()).build(signed)

    # Then
    assert isinstance(envelope.document, BuildEnvelopeDocument)
    paths = tuple(item.path for item in envelope.document.artifacts)
    assert paths == ("artifacts/catalog.whl", "signatures/catalog.sig")


def test_should_change_envelope_digest_when_signed_artifact_changes() -> None:
    # Given
    first_signed = make_signed_build("catalog")
    second_signed = make_signed_build("catalog-next")

    # When
    first = EnvelopeBuilder(make_metadata()).build(first_signed)
    second = EnvelopeBuilder(make_metadata()).build(second_signed)

    # Then
    assert first.content_sha256 != second.content_sha256


def test_should_serialize_signed_build_components_when_envelope_is_assembled() -> None:
    # Given
    artifact = make_artifact()
    sbom = Sbom(
        artifact.path,
        ArtifactPath("sbom/catalog.cdx.json"),
        "application/vnd.cyclonedx+json",
        make_digest("1"),
    )
    lock = LockIdentity(ArtifactPath("uv.lock"), make_digest("2"))
    toolchain = ToolchainIdentity("python", "3.13", make_digest("3"))
    unsigned = UnsignedBuild(make_source(), (artifact,), (sbom,), (lock,), (toolchain,))
    signed = SignedBuild(
        PrequalifiedBuild(unsigned, (make_precheck(),)),
        None,
        SigningDisposition.SIGNING_NOT_REQUIRED,
    )

    # When
    envelope = EnvelopeBuilder(make_metadata()).build(signed)

    # Then
    assert isinstance(envelope.document, BuildEnvelopeDocument)
    assert envelope.document.locks[0].path == "uv.lock"
    assert envelope.document.toolchains[0].name == "python"
    assert envelope.document.sboms[0].path == "sbom/catalog.cdx.json"
    assert tuple(item.path for item in envelope.document.artifacts) == ("artifacts/catalog.whl",)


def test_should_reject_check_with_nonfinal_envelope_subject() -> None:
    # Given
    envelope = EnvelopeBuilder(make_metadata()).build(make_signed_build())
    invalid_check = Evidence("archive", "manifest", make_digest("9"), EvidenceStatus.PASSED)

    # When / Then
    with pytest.raises(InvalidIdentity, match="final envelope digest"):
        QualificationBuilder().build(envelope, (invalid_check,))


def test_should_reject_non_evidence_check_when_qualification_is_assembled() -> None:
    # Given
    envelope = EnvelopeBuilder(make_metadata()).build(make_signed_build())
    invalid_checks = cast(tuple[Evidence, ...], ("not-evidence",))

    # When / Then
    with pytest.raises(InvalidIdentity, match="evidence records"):
        QualificationBuilder().build(envelope, invalid_checks)


def test_should_use_declared_metadata_when_envelope_is_assembled() -> None:
    # Given
    metadata = make_metadata()

    # When
    envelope = EnvelopeBuilder(metadata).build(make_signed_build())

    # Then
    assert isinstance(envelope.document, BuildEnvelopeDocument)
    assert envelope.document.project_adapter_version == "1.0.0"
    assert envelope.document.source_date_epoch == SOURCE_DATE_EPOCH
    assert envelope.document.release_policy.channels == ("stable",)
    assert envelope.document.compatibility.dagger == "0.21.8"
    assert envelope.document.compatibility.oras == "1.3.3"


def test_should_require_declared_metadata_when_builder_is_created() -> None:
    # Given
    factory = cast(Callable[[], EnvelopeBuilder], EnvelopeBuilder)

    # When / Then
    with pytest.raises(TypeError):
        factory()


def test_should_reject_policy_that_disagrees_with_release_when_envelope_is_assembled() -> None:
    # Given
    metadata = EnvelopeMetadata(
        ProjectAdapterVersion("1.0.0"),
        SOURCE_DATE_EPOCH,
        ReleasePolicyMetadata("v9.9.9", (ReleaseChannel.STABLE,)),
        PinnedCompatibility("0.21.8", "1.3.3"),
    )

    # When / Then
    with pytest.raises(InvalidIdentity, match="match the release version"):
        EnvelopeBuilder(metadata).build(make_signed_build())


@pytest.mark.parametrize(
    "factory",
    (
        lambda: ProjectAdapterVersion("tbd"),
        lambda: ProjectAdapterVersion("1.0"),
        lambda: ReleasePolicyMetadata("release-1", (ReleaseChannel.STABLE,)),
        lambda: ReleasePolicyMetadata("v1.2.3", cast(tuple[ReleaseChannel, ...], ("tbd",))),
        lambda: PinnedCompatibility("0.22.0", "1.3.3"),
        lambda: PinnedCompatibility("0.21.8", "1.3.4"),
    ),
)
def test_should_reject_nonpinned_metadata_values_when_created(
    factory: Callable[[], object],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        factory()


@pytest.mark.parametrize(
    "factory",
    (
        lambda: ProjectAdapterVersion("1.0.0-tbd"),
        lambda: ProjectAdapterVersion("1.0.0-01"),
        lambda: ProjectAdapterVersion("1٢.0.0"),
        lambda: ProjectAdapterVersion("1.0.0-alpha.todo"),
        lambda: ProjectAdapterVersion("1.0.0+not-recorded"),
        lambda: ReleasePolicyMetadata("v1.2.3-01", (ReleaseChannel.STABLE,)),
        lambda: ReleasePolicyMetadata("v1.2.3-TBD", (ReleaseChannel.STABLE,)),
    ),
)
def test_should_reject_noncanonical_or_placeholder_semver_when_created(
    factory: Callable[[], object],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        factory()


@pytest.mark.parametrize("value", ("1.0.0-alpha.1+build.7", "2.4.6-rc.1"))
def test_should_allow_strict_semver_prerelease_when_adapter_version_is_created(value: str) -> None:
    # Given / When
    version = ProjectAdapterVersion(value)

    # Then
    assert version.value == value


def test_should_allow_strict_semver_prerelease_when_release_policy_is_created() -> None:
    # Given / When
    policy = ReleasePolicyMetadata("v1.2.3-beta.1+build.7", (ReleaseChannel.NEXT,))

    # Then
    assert policy.version == "v1.2.3-beta.1+build.7"


@pytest.mark.parametrize(
    "metadata",
    (
        lambda: EnvelopeMetadata(
            cast(ProjectAdapterVersion, "1.0.0"),
            1_724_472_000,
            ReleasePolicyMetadata("v1.2.3", (ReleaseChannel.STABLE,)),
            PinnedCompatibility("0.21.8", "1.3.3"),
        ),
        lambda: EnvelopeMetadata(
            ProjectAdapterVersion("1.0.0"),
            0,
            ReleasePolicyMetadata("v1.2.3", (ReleaseChannel.STABLE,)),
            PinnedCompatibility("0.21.8", "1.3.3"),
        ),
        lambda: EnvelopeMetadata(
            ProjectAdapterVersion("1.0.0"),
            1_724_472_000,
            ReleasePolicyMetadata("v1.2.3", cast(tuple[ReleaseChannel, ...], ())),
            PinnedCompatibility("0.21.8", "1.3.3"),
        ),
    ),
)
def test_should_reject_incomplete_declared_metadata_when_created(
    metadata: Callable[[], EnvelopeMetadata],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        metadata()
