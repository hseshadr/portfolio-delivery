from hashlib import sha256

import pytest

from portfolio_delivery.domain.errors import (
    InvalidArtifactPath,
    InvalidDigest,
    InvalidIdentity,
)
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)


def test_should_accept_lowercase_sha256_when_digest_is_canonical() -> None:
    # Given
    raw_digest = "sha256:" + ("a" * 64)

    # When
    digest = Sha256Digest(raw_digest)

    # Then
    assert digest.value == raw_digest


@pytest.mark.parametrize(
    "raw_digest",
    (
        "sha256:" + ("A" * 64),
        "sha256:" + ("a" * 63),
        "SHA256:" + ("a" * 64),
        "sha256:" + ("g" * 64),
    ),
)
def test_should_reject_noncanonical_digest_when_digest_is_created(raw_digest: str) -> None:
    # Given / When / Then
    with pytest.raises(InvalidDigest):
        Sha256Digest(raw_digest)


def test_should_hash_exact_bytes_when_digest_is_created_from_content() -> None:
    # Given
    content = b"portfolio-delivery\n"
    expected = "sha256:" + sha256(content).hexdigest()

    # When
    digest = Sha256Digest.from_bytes(content)

    # Then
    assert digest.value == expected
    assert digest.hex == expected.removeprefix("sha256:")


@pytest.mark.parametrize("raw_project", ("", " ", " edgeproc", "edgeproc "))
def test_should_reject_noncanonical_project_when_project_id_is_created(raw_project: str) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        ProjectId(raw_project)


def test_should_reject_parent_traversal_when_artifact_path_is_created() -> None:
    # Given
    raw_path = "dist/../secret.txt"

    # When / Then
    with pytest.raises(InvalidArtifactPath):
        ArtifactPath(raw_path)


@pytest.mark.parametrize(
    "raw_path", ("/dist/package.whl", "dist\\package.whl", "dist//package.whl")
)
def test_should_reject_noncanonical_path_when_artifact_path_is_created(raw_path: str) -> None:
    # Given / When / Then
    with pytest.raises(InvalidArtifactPath):
        ArtifactPath(raw_path)


def test_should_preserve_relative_posix_path_when_artifact_path_is_created() -> None:
    # Given
    raw_path = "dist/package.whl"

    # When
    artifact_path = ArtifactPath(raw_path)

    # Then
    assert artifact_path.value == raw_path


def test_should_reject_uppercase_commit_sha_when_source_revision_is_created() -> None:
    # Given
    source_digest = Sha256Digest("sha256:" + ("b" * 64))

    # When / Then
    with pytest.raises(InvalidIdentity):
        SourceRevision(
            project=ProjectId("edgeproc"),
            repository="hseshadr/edgeproc",
            protected_ref="refs/heads/main",
            commit_sha="A" * 40,
            source_tree_sha256=source_digest,
        )


def test_should_preserve_identity_parts_when_release_id_is_created() -> None:
    # Given
    project = ProjectId("edgeproc")
    source_digest = Sha256Digest("sha256:" + ("c" * 64))

    # When
    release = ReleaseId(project, "v0.1.3", source_digest, "publish-edgeproc-v0.1.3")

    # Then
    assert release.project is project
    assert release.source_sha256 is source_digest
