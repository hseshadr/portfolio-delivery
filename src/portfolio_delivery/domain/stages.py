"""Immutable records for the ordered delivery stages."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
)
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import ReleaseId, Sha256Digest, SourceRevision


def _require_text(value: str, message: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvalidIdentity(message)


def _require_tuple(value: object, item_type: type[object], message: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(item, item_type) for item in value):
        raise InvalidIdentity(message)


def _require_attempt_id(attempt_id: str) -> None:
    _require_text(attempt_id, "attempt ID must be non-empty and canonical")


@dataclass(frozen=True, slots=True)
class InputSnapshotPlan:
    include_paths: tuple[str, ...]
    exclude_paths: tuple[str, ...] = ()
    inputs: tuple[LockIdentity, ...] = ()

    def __post_init__(self) -> None:
        _require_tuple(self.include_paths, str, "included paths must be a tuple of strings")
        _require_tuple(self.exclude_paths, str, "excluded paths must be a tuple of strings")
        _require_tuple(self.inputs, LockIdentity, "inputs must be lock identity records")


@dataclass(frozen=True, slots=True)
class BuildPlan:
    name: str
    commands: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.name, "build plan name must be non-empty and canonical")
        _require_tuple(self.commands, str, "build commands must be a tuple of strings")


class SigningDisposition(StrEnum):
    """The explicit result of the signing stage."""

    SIGNED = "signed"
    SIGNING_NOT_REQUIRED = "signing_not_required"


@dataclass(frozen=True, slots=True)
class SigningPolicy:
    key_id: str | None

    @classmethod
    def required(cls, key_id: str) -> SigningPolicy:
        _require_text(key_id, "signing key ID must be non-empty and canonical")
        return cls(key_id)

    @classmethod
    def none(cls) -> SigningPolicy:
        return cls(None)


@dataclass(frozen=True, slots=True)
class VerificationPlan:
    checks: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_tuple(self.checks, str, "verification checks must be a tuple of strings")


@dataclass(frozen=True, slots=True)
class ReleaseSource:
    release_id: ReleaseId
    revision: SourceRevision

    def __post_init__(self) -> None:
        if not _has_release_source_identities(self.release_id, self.revision):
            raise InvalidIdentity("release source must use release and source identity records")


def _has_release_source_identities(release_id: object, revision: object) -> bool:
    return isinstance(release_id, ReleaseId) and isinstance(revision, SourceRevision)


@dataclass(frozen=True, slots=True)
class SnapshottedSource:
    release: ReleaseSource
    input_snapshot_sha256: Sha256Digest

    def __post_init__(self) -> None:
        if not isinstance(self.release, ReleaseSource) or not isinstance(
            self.input_snapshot_sha256, Sha256Digest
        ):
            raise InvalidIdentity("snapshot source must use domain identity records")


@dataclass(frozen=True, slots=True)
class UnsignedBuild:
    source: SnapshottedSource
    artifacts: tuple[Artifact, ...]
    sboms: tuple[Sbom, ...]
    locks: tuple[LockIdentity, ...]
    toolchains: tuple[ToolchainIdentity, ...]

    def __post_init__(self) -> None:
        _validate_unsigned_build(self)


def _validate_unsigned_build(build: UnsignedBuild) -> None:
    if not isinstance(build.source, SnapshottedSource):
        raise InvalidIdentity("unsigned build source must be a snapshotted source")
    _require_tuple(build.artifacts, Artifact, "build artifacts must be artifact records")
    _require_tuple(build.sboms, Sbom, "build SBOMs must be SBOM records")
    _require_tuple(build.locks, LockIdentity, "build locks must be lock identity records")
    _require_tuple(
        build.toolchains,
        ToolchainIdentity,
        "build toolchains must be toolchain records",
    )


@dataclass(frozen=True, slots=True)
class PrequalifiedBuild:
    unsigned: UnsignedBuild
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.unsigned, UnsignedBuild):
            raise InvalidIdentity("prequalified build must contain an unsigned build")
        _require_tuple(
            self.evidence,
            Evidence,
            "prequalification evidence must be evidence records",
        )


@dataclass(frozen=True, slots=True)
class SignedBuild:
    prequalified: PrequalifiedBuild
    signature: Artifact | None
    disposition: SigningDisposition

    def __post_init__(self) -> None:
        _validate_signed_build(self)


def _validate_signed_build(build: SignedBuild) -> None:
    _validate_prequalified_build(build.prequalified)
    _validate_signing_disposition(build.disposition)
    _validate_signature(build.signature, build.disposition)


def _validate_prequalified_build(build: object) -> None:
    if not isinstance(build, PrequalifiedBuild):
        raise InvalidIdentity("signed build must contain a prequalified build")


def _validate_signing_disposition(disposition: object) -> None:
    if not isinstance(disposition, SigningDisposition):
        raise InvalidIdentity("signed build disposition must be explicit")


def _validate_signature(signature: Artifact | None, disposition: SigningDisposition) -> None:
    if disposition is SigningDisposition.SIGNED and not isinstance(signature, Artifact):
        raise InvalidIdentity("signed builds require a signature artifact")
    if disposition is SigningDisposition.SIGNING_NOT_REQUIRED and signature is not None:
        raise InvalidIdentity("unsigned policy cannot invent a signature artifact")


@dataclass(frozen=True, slots=True)
class BuildEnvelope:
    signed: SignedBuild
    document: object
    canonical_bytes: bytes
    content_sha256: Sha256Digest


@dataclass(frozen=True, slots=True)
class QualificationRecord:
    subject: Sha256Digest
    document: object
    canonical_bytes: bytes
    content_sha256: Sha256Digest


@dataclass(frozen=True, slots=True)
class QualifiedEnvelope:
    envelope: BuildEnvelope
    qualification: QualificationRecord


@dataclass(frozen=True, slots=True)
class EnvelopeBundle:
    qualified: QualifiedEnvelope
    artifacts: tuple[Artifact, ...]
    sboms: tuple[Sbom, ...]


@dataclass(frozen=True, slots=True)
class OciReference:
    repository: str
    tag: str
    manifest_sha256: Sha256Digest | None = None

    def __post_init__(self) -> None:
        _require_text(self.repository, "OCI repository must be non-empty and canonical")
        _require_text(self.tag, "OCI tag must be non-empty and canonical")
        if self.manifest_sha256 is not None and not isinstance(self.manifest_sha256, Sha256Digest):
            raise InvalidIdentity("OCI manifest must be a digest record")


@dataclass(frozen=True, slots=True)
class StoredEnvelope:
    reference: OciReference
    manifest_sha256: Sha256Digest


@dataclass(frozen=True, slots=True)
class OrasInvocation:
    argv: tuple[str, ...]
    input_bytes: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        _require_tuple(self.argv, str, "ORAS arguments must be a tuple of strings")
        _require_tuple(self.input_bytes, bytes, "ORAS inputs must be a tuple of bytes")


@dataclass(frozen=True, slots=True)
class OrasResult:
    exit_code: int
    stdout: bytes
    stderr: bytes

    def __post_init__(self) -> None:
        if isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int):
            raise InvalidIdentity("ORAS exit code must be an integer")


def validate_attempt_id(attempt_id: str) -> None:
    """Reject empty attempt identifiers at mutable port boundaries."""

    _require_attempt_id(attempt_id)
