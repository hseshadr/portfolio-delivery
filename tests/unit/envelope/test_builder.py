"""Behavioral tests for final envelope and detached qualification builders."""

from typing import cast

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
from portfolio_delivery.envelope.builder import EnvelopeBuilder, QualificationBuilder
from portfolio_delivery.envelope.documents import BuildEnvelopeDocument


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


def test_should_keep_envelope_digest_when_final_checks_change() -> None:
    # Given
    envelope = EnvelopeBuilder().build(make_signed_build())
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
    envelope = EnvelopeBuilder().build(signed)

    # Then
    assert isinstance(envelope.document, BuildEnvelopeDocument)
    paths = tuple(item.path for item in envelope.document.artifacts)
    assert paths == ("artifacts/catalog.whl", "signatures/catalog.sig")


def test_should_change_envelope_digest_when_signed_artifact_changes() -> None:
    # Given
    first_signed = make_signed_build("catalog")
    second_signed = make_signed_build("catalog-next")

    # When
    first = EnvelopeBuilder().build(first_signed)
    second = EnvelopeBuilder().build(second_signed)

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
    envelope = EnvelopeBuilder().build(signed)

    # Then
    assert isinstance(envelope.document, BuildEnvelopeDocument)
    assert envelope.document.locks[0].path == "uv.lock"
    assert envelope.document.toolchains[0].name == "python"
    assert envelope.document.sboms[0].path == "sbom/catalog.cdx.json"
    assert tuple(item.path for item in envelope.document.artifacts) == ("artifacts/catalog.whl",)


def test_should_reject_check_with_nonfinal_envelope_subject() -> None:
    # Given
    envelope = EnvelopeBuilder().build(make_signed_build())
    invalid_check = Evidence("archive", "manifest", make_digest("9"), EvidenceStatus.PASSED)

    # When / Then
    with pytest.raises(InvalidIdentity, match="final envelope digest"):
        QualificationBuilder().build(envelope, (invalid_check,))


def test_should_reject_non_evidence_check_when_qualification_is_assembled() -> None:
    # Given
    envelope = EnvelopeBuilder().build(make_signed_build())
    invalid_checks = cast(tuple[Evidence, ...], ("not-evidence",))

    # When / Then
    with pytest.raises(InvalidIdentity, match="evidence records"):
        QualificationBuilder().build(envelope, invalid_checks)
