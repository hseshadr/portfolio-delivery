"""Immutable artifact, input, and evidence records."""

from dataclasses import dataclass
from enum import StrEnum

from portfolio_delivery.domain.errors import DuplicateArtifact, InvalidIdentity, diagnostic_error
from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest

_RECORD_VALUE_MESSAGE = (
    "record values must be non-empty and canonical"  # pragma: no mutate - diagnostic
)
_ARTIFACT_SIZE_MESSAGE = (
    "artifact size must be a non-negative integer"  # pragma: no mutate - diagnostic
)
_ARTIFACT_IDENTITY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "artifact identity fields must use domain identity records"
)
_EVIDENCE_IDENTITY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "evidence subject and status must use domain identity records"
)
_SBOM_IDENTITY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "SBOM artifact path must use a domain identity record"
)
_TOOLCHAIN_IDENTITY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "toolchain digest must use a domain identity record"
)
_DUPLICATE_ARTIFACT_MESSAGE = "artifact paths must be unique"  # pragma: no mutate - diagnostic


def _require_value(value: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise diagnostic_error(InvalidIdentity, _RECORD_VALUE_MESSAGE)


def _validate_size(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise diagnostic_error(InvalidIdentity, _ARTIFACT_SIZE_MESSAGE)


def _validate_artifact_identities(path: object, digest: object) -> None:
    if not isinstance(path, ArtifactPath) or not isinstance(digest, Sha256Digest):
        raise diagnostic_error(InvalidIdentity, _ARTIFACT_IDENTITY_MESSAGE)


def _validate_evidence_identities(subject: object, status: object) -> None:
    if not isinstance(subject, Sha256Digest) or not isinstance(status, EvidenceStatus):
        raise diagnostic_error(InvalidIdentity, _EVIDENCE_IDENTITY_MESSAGE)


def _validate_sbom_identities(artifact_path: object, path: object, digest: object) -> None:
    if not isinstance(artifact_path, ArtifactPath):
        raise diagnostic_error(InvalidIdentity, _SBOM_IDENTITY_MESSAGE)
    _validate_artifact_identities(path, digest)


def _validate_lock_identities(path: object, digest: object) -> None:
    _validate_artifact_identities(path, digest)


def _validate_toolchain_digest(digest: object) -> None:
    if not isinstance(digest, Sha256Digest):
        raise diagnostic_error(InvalidIdentity, _TOOLCHAIN_IDENTITY_MESSAGE)


def ensure_unique_artifact_paths(artifacts: tuple["Artifact", ...]) -> None:
    paths = tuple(artifact.path.value for artifact in artifacts)
    if len(paths) != len(set(paths)):
        raise diagnostic_error(DuplicateArtifact, _DUPLICATE_ARTIFACT_MESSAGE)


@dataclass(frozen=True, slots=True)
class Artifact:
    name: str
    path: ArtifactPath
    media_type: str
    size: int
    sha256: Sha256Digest

    def __post_init__(self) -> None:
        _validate_artifact_identities(self.path, self.sha256)
        _require_value(self.name)
        _require_value(self.media_type)
        _validate_size(self.size)


@dataclass(frozen=True, slots=True)
class Sbom:
    artifact_path: ArtifactPath
    path: ArtifactPath
    media_type: str
    sha256: Sha256Digest

    def __post_init__(self) -> None:
        _validate_sbom_identities(self.artifact_path, self.path, self.sha256)
        _require_value(self.media_type)


@dataclass(frozen=True, slots=True)
class LockIdentity:
    path: ArtifactPath
    sha256: Sha256Digest

    def __post_init__(self) -> None:
        _validate_lock_identities(self.path, self.sha256)


@dataclass(frozen=True, slots=True)
class ToolchainIdentity:
    name: str
    version: str
    sha256: Sha256Digest

    def __post_init__(self) -> None:
        _validate_toolchain_digest(self.sha256)
        _require_value(self.name)
        _require_value(self.version)


class EvidenceStatus(StrEnum):
    """A deterministic check result."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    name: str
    subject: Sha256Digest
    status: EvidenceStatus

    def __post_init__(self) -> None:
        _validate_evidence_identities(self.subject, self.status)
        _require_value(self.kind)
        _require_value(self.name)
