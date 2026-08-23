"""Immutable validated identities for deterministic delivery records."""

import re
from dataclasses import dataclass
from hashlib import sha256

from portfolio_delivery.domain.errors import (
    InvalidArtifactPath,
    InvalidDigest,
    InvalidIdentity,
)

_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


def _require_identity(value: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvalidIdentity("identity values must be non-empty and canonical")


def _validate_digest(value: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise InvalidDigest("digest must be a lowercase sha256:<64-hex> value")


def _validate_artifact_path(value: str) -> None:
    if not isinstance(value, str):
        raise InvalidArtifactPath("artifact path must be a canonical relative POSIX path")
    if _is_unsafe_artifact_path(value):
        raise InvalidArtifactPath("artifact path must be a canonical relative POSIX path")


def _is_unsafe_artifact_path(value: str) -> bool:
    invalid_parts = any(part in {"", ".", ".."} for part in value.split("/"))
    return any((not value, value.startswith("/"), "\\" in value, "\x00" in value, invalid_parts))


def _validate_commit_sha(value: str) -> None:
    if not isinstance(value, str) or _COMMIT_SHA.fullmatch(value) is None:
        raise InvalidIdentity("commit SHA must be 40 lowercase hexadecimal characters")


def _validate_source_identities(project: object, source_digest: object) -> None:
    if not isinstance(project, ProjectId) or not isinstance(source_digest, Sha256Digest):
        raise InvalidIdentity("source revision identity fields must use domain identity records")


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
        _require_identity(self.version)
        _require_identity(self.idempotency_key)
