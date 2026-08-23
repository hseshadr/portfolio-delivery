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
    if not isinstance(release_id, ReleaseId) or not isinstance(revision, SourceRevision):
        return False
    return _release_matches_revision(release_id, revision)


def _release_matches_revision(release_id: ReleaseId, revision: SourceRevision) -> bool:
    return (
        release_id.project == revision.project
        and release_id.source_sha256 == revision.source_tree_sha256
    )


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


def _validate_canonical_content(canonical_bytes: object, content_sha256: object) -> None:
    if not isinstance(canonical_bytes, bytes) or not isinstance(content_sha256, Sha256Digest):
        raise InvalidIdentity("canonical content must use bytes and a digest record")
    if Sha256Digest.from_bytes(canonical_bytes) != content_sha256:
        raise InvalidIdentity("canonical content digest must match exact bytes")


@dataclass(frozen=True, slots=True)
class BuildEnvelope:
    signed: SignedBuild
    document: object
    canonical_bytes: bytes
    content_sha256: Sha256Digest

    def __post_init__(self) -> None:
        _validate_canonical_content(self.canonical_bytes, self.content_sha256)


@dataclass(frozen=True, slots=True)
class QualificationRecord:
    subject: Sha256Digest
    document: object
    canonical_bytes: bytes
    content_sha256: Sha256Digest

    def __post_init__(self) -> None:
        _validate_canonical_content(self.canonical_bytes, self.content_sha256)


@dataclass(frozen=True, slots=True)
class QualifiedEnvelope:
    envelope: BuildEnvelope
    qualification: QualificationRecord

    def __post_init__(self) -> None:
        _validate_qualified_envelope(self.envelope, self.qualification)


def _validate_qualified_envelope(envelope: object, qualification: object) -> None:
    if not isinstance(envelope, BuildEnvelope) or not isinstance(
        qualification, QualificationRecord
    ):
        raise InvalidIdentity("qualified envelope must contain stage records")
    if qualification.subject != envelope.content_sha256:
        raise InvalidIdentity("qualification subject must match envelope content digest")


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


class OrasOutcome(StrEnum):
    """Typed classification of one ORAS provider execution."""

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class OrasResult:
    exit_code: int
    outcome: OrasOutcome
    stdout: bytes
    stderr: bytes
    exported_file_bytes: bytes | None = None

    def __post_init__(self) -> None:
        _validate_oras_result(self)


def _validate_oras_result(result: OrasResult) -> None:
    _validate_oras_exit_code(result.exit_code)
    _validate_oras_outcome(result.outcome)
    _validate_oras_process_output(result.stdout, result.stderr)
    _validate_oras_result_coherence(result)


def _validate_oras_exit_code(exit_code: object) -> None:
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise InvalidIdentity("ORAS exit code must be an integer")


def _validate_oras_outcome(outcome: object) -> None:
    if not isinstance(outcome, OrasOutcome):
        raise InvalidIdentity("ORAS outcome must use the typed provider classification")


def _validate_oras_process_output(stdout: object, stderr: object) -> None:
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise InvalidIdentity("ORAS process output must be exact bytes")


def _validate_oras_result_coherence(result: OrasResult) -> None:
    success = result.outcome is OrasOutcome.SUCCESS
    if success != (result.exit_code == 0):
        raise InvalidIdentity("ORAS outcome must agree with its exit code")
    _validate_oras_export(result.exported_file_bytes, success)


def _validate_oras_export(exported: object, success: bool) -> None:
    if exported is not None and not isinstance(exported, bytes):
        raise InvalidIdentity("ORAS exported file payload must be exact bytes")
    if not success and exported is not None:
        raise InvalidIdentity("failed ORAS executions cannot export authoritative file bytes")


def validate_attempt_id(attempt_id: str) -> None:
    """Reject empty attempt identifiers at mutable port boundaries."""

    _require_attempt_id(attempt_id)
