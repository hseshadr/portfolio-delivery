"""Immutable artifact, input, and evidence records."""

from dataclasses import dataclass
from enum import StrEnum

from portfolio_delivery.domain.errors import DuplicateArtifact, InvalidIdentity
from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest


def _require_value(value: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvalidIdentity("record values must be non-empty and canonical")


def _validate_size(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidIdentity("artifact size must be a non-negative integer")


def ensure_unique_artifact_paths(artifacts: tuple["Artifact", ...]) -> None:
    paths = tuple(artifact.path.value for artifact in artifacts)
    if len(paths) != len(set(paths)):
        raise DuplicateArtifact("artifact paths must be unique")


@dataclass(frozen=True, slots=True)
class Artifact:
    name: str
    path: ArtifactPath
    media_type: str
    size: int
    sha256: Sha256Digest

    def __post_init__(self) -> None:
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
        _require_value(self.media_type)


@dataclass(frozen=True, slots=True)
class LockIdentity:
    path: ArtifactPath
    sha256: Sha256Digest


@dataclass(frozen=True, slots=True)
class ToolchainIdentity:
    name: str
    version: str
    sha256: Sha256Digest

    def __post_init__(self) -> None:
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
        _require_value(self.kind)
        _require_value(self.name)
