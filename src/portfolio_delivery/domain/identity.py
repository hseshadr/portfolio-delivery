"""Immutable validated identities for deterministic delivery records."""

import re
from dataclasses import dataclass
from hashlib import sha256

from portfolio_delivery.domain.errors import (
    InvalidArtifactPath,
    InvalidDigest,
    InvalidIdentity,
    diagnostic_error,
)

_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTITY_VALUE_MESSAGE = (
    "identity values must be non-empty and canonical"  # pragma: no mutate - diagnostic
)
_DIGEST_MESSAGE = (
    "digest must be a lowercase sha256:<64-hex> value"  # pragma: no mutate - diagnostic
)
_ARTIFACT_PATH_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "artifact path must be a canonical relative POSIX path"
)
_COMMIT_SHA_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "commit SHA must be 40 lowercase hexadecimal characters"
)
_SOURCE_IDENTITY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "source revision identity fields must use domain identity records"
)
_RELEASE_IDENTITY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "release identity fields must use domain identity records"
)


def _require_identity(value: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise diagnostic_error(InvalidIdentity, _IDENTITY_VALUE_MESSAGE)


def _validate_digest(value: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise diagnostic_error(InvalidDigest, _DIGEST_MESSAGE)


def _validate_artifact_path(value: str) -> None:
    if not isinstance(value, str):
        raise diagnostic_error(InvalidArtifactPath, _ARTIFACT_PATH_MESSAGE)
    if _is_unsafe_artifact_path(value):
        raise diagnostic_error(InvalidArtifactPath, _ARTIFACT_PATH_MESSAGE)


def _is_unsafe_artifact_path(value: str) -> bool:
    invalid_parts = any(part in {"", ".", ".."} for part in value.split("/"))
    return any((not value, "\\" in value, "\x00" in value, invalid_parts))


def _validate_commit_sha(value: str) -> None:
    if not isinstance(value, str) or _COMMIT_SHA.fullmatch(value) is None:
        raise diagnostic_error(InvalidIdentity, _COMMIT_SHA_MESSAGE)


def _validate_source_identities(project: object, source_digest: object) -> None:
    if not isinstance(project, ProjectId) or not isinstance(source_digest, Sha256Digest):
        raise diagnostic_error(InvalidIdentity, _SOURCE_IDENTITY_MESSAGE)


def _validate_release_identities(project: object, source_digest: object) -> None:
    if not isinstance(project, ProjectId) or not isinstance(source_digest, Sha256Digest):
        raise diagnostic_error(InvalidIdentity, _RELEASE_IDENTITY_MESSAGE)


@dataclass(frozen=True, slots=True)
class ProjectId:
    value: str

    def __post_init__(self) -> None:
        _require_identity(self.value)


@dataclass(frozen=True, slots=True)
class Sha256Digest:
    value: str

    def __post_init__(self) -> None:
        _validate_digest(self.value)

    @property
    def hex(self) -> str:
        return self.value.removeprefix("sha256:")

    @classmethod
    def from_bytes(cls, content: bytes) -> "Sha256Digest":
        return cls(f"sha256:{sha256(content).hexdigest()}")


@dataclass(frozen=True, slots=True)
class ArtifactPath:
    value: str

    def __post_init__(self) -> None:
        _validate_artifact_path(self.value)


@dataclass(frozen=True, slots=True)
class SourceRevision:
    project: ProjectId
    repository: str
    protected_ref: str
    commit_sha: str
    source_tree_sha256: Sha256Digest

    def __post_init__(self) -> None:
        _validate_source_identities(self.project, self.source_tree_sha256)
        _require_identity(self.repository)
        _require_identity(self.protected_ref)
        _validate_commit_sha(self.commit_sha)


@dataclass(frozen=True, slots=True)
class ReleaseId:
    project: ProjectId
    version: str
    source_sha256: Sha256Digest
    idempotency_key: str

    def __post_init__(self) -> None:
        _validate_release_identities(self.project, self.source_sha256)
        _require_identity(self.version)
        _require_identity(self.idempotency_key)
