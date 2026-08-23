from typing import cast

import pytest

from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    EvidenceStatus,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
    ensure_unique_artifact_paths,
)
from portfolio_delivery.domain.errors import DuplicateArtifact, InvalidIdentity
from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest


def make_digest(character: str) -> Sha256Digest:
    return Sha256Digest(f"sha256:{character * 64}")


def make_artifact(path: str = "dist/package.whl") -> Artifact:
    return Artifact(
        name="package",
        path=ArtifactPath(path),
        media_type="application/zip",
        size=42,
        sha256=make_digest("a"),
    )


def test_should_reject_negative_size_when_artifact_is_created() -> None:
    # Given
    path = ArtifactPath("dist/package.whl")

    # When / Then
    with pytest.raises(InvalidIdentity):
        Artifact("package", path, "application/zip", -1, make_digest("a"))


def test_should_reject_nonidentity_nested_value_when_artifact_is_created() -> None:
    # Given
    digest = make_digest("a")

    # When / Then
    with pytest.raises(InvalidIdentity):
        Artifact(
            "package",
            cast(ArtifactPath, "dist/package.whl"),
            "application/zip",
            42,
            digest,
        )


def test_should_reject_duplicate_paths_when_artifacts_are_checked() -> None:
    # Given
    artifacts = (make_artifact(), make_artifact())

    # When / Then
    with pytest.raises(DuplicateArtifact):
        ensure_unique_artifact_paths(artifacts)


def test_should_accept_distinct_artifact_paths_when_artifacts_are_checked() -> None:
    # Given
    artifacts = (make_artifact(), make_artifact("sbom/package.cdx.json"))

    # When
    ensure_unique_artifact_paths(artifacts)

    # Then
    assert tuple(artifact.path.value for artifact in artifacts) == (
        "dist/package.whl",
        "sbom/package.cdx.json",
    )


def test_should_preserve_explicit_artifact_metadata_when_sbom_is_created() -> None:
    # Given
    artifact = make_artifact()

    # When
    sbom = Sbom(
        artifact_path=artifact.path,
        path=ArtifactPath("sbom/package.cdx.json"),
        media_type="application/vnd.cyclonedx+json",
        sha256=make_digest("b"),
    )

    # Then
    assert sbom.artifact_path == artifact.path
    assert sbom.path.value == "sbom/package.cdx.json"


def test_should_preserve_exact_lock_and_toolchain_identities_when_created() -> None:
    # Given / When
    lock = LockIdentity(ArtifactPath("uv.lock"), make_digest("c"))
    toolchain = ToolchainIdentity("python", "3.13.14", make_digest("d"))

    # Then
    assert lock.path.value == "uv.lock"
    assert toolchain.version == "3.13.14"


def test_should_preserve_check_result_when_evidence_is_created() -> None:
    # Given
    subject = make_digest("e")

    # When
    evidence = Evidence("test", "unit", subject, EvidenceStatus.PASSED)

    # Then
    assert evidence.subject is subject
    assert evidence.status is EvidenceStatus.PASSED


@pytest.mark.parametrize(
    ("subject", "status"),
    (
        (cast(Sha256Digest, "sha256:" + ("e" * 64)), EvidenceStatus.PASSED),
        (make_digest("e"), cast(EvidenceStatus, "passed")),
    ),
)
def test_should_reject_invalid_nested_values_when_evidence_is_created(
    subject: Sha256Digest,
    status: EvidenceStatus,
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        Evidence("test", "unit", subject, status)
