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
from portfolio_delivery.domain.errors import InvalidIdentity, diagnostic_error
from portfolio_delivery.domain.identity import ReleaseId, Sha256Digest, SourceRevision

_ATTEMPT_ID_MESSAGE = "attempt ID must be non-empty and canonical"  # pragma: no mutate
_INCLUDED_PATHS_MESSAGE = "included paths must be a tuple of strings"  # pragma: no mutate
_EXCLUDED_PATHS_MESSAGE = "excluded paths must be a tuple of strings"  # pragma: no mutate
_INPUTS_MESSAGE = "inputs must be lock identity records"  # pragma: no mutate
_BUILD_PLAN_NAME_MESSAGE = "build plan name must be non-empty and canonical"  # pragma: no mutate
_BUILD_COMMANDS_MESSAGE = "build commands must be a tuple of strings"  # pragma: no mutate
_SIGNING_KEY_MESSAGE = "signing key ID must be non-empty and canonical"  # pragma: no mutate
_VERIFICATION_CHECKS_MESSAGE = (  # pragma: no mutate
    "verification checks must be a tuple of strings"
)
_RELEASE_SOURCE_MESSAGE = (  # pragma: no mutate
    "release source must use release and source identity records"
)
_SNAPSHOT_SOURCE_MESSAGE = "snapshot source must use domain identity records"  # pragma: no mutate
_UNSIGNED_SOURCE_MESSAGE = "unsigned build source must be a snapshotted source"  # pragma: no mutate
_BUILD_ARTIFACTS_MESSAGE = "build artifacts must be artifact records"  # pragma: no mutate
_BUILD_SBOMS_MESSAGE = "build SBOMs must be SBOM records"  # pragma: no mutate
_BUILD_LOCKS_MESSAGE = "build locks must be lock identity records"  # pragma: no mutate
_BUILD_TOOLCHAINS_MESSAGE = "build toolchains must be toolchain records"  # pragma: no mutate
_PREQUALIFIED_BUILD_MESSAGE = (
    "prequalified build must contain an unsigned build"  # pragma: no mutate
)
_PREQUALIFICATION_EVIDENCE_MESSAGE = (  # pragma: no mutate
    "prequalification evidence must be evidence records"
)
_SIGNED_BUILD_MESSAGE = "signed build must contain a prequalified build"  # pragma: no mutate
_SIGNING_DISPOSITION_MESSAGE = "signed build disposition must be explicit"  # pragma: no mutate
_SIGNATURE_REQUIRED_MESSAGE = "signed builds require a signature artifact"  # pragma: no mutate
_SIGNATURE_FORBIDDEN_MESSAGE = (
    "unsigned policy cannot invent a signature artifact"  # pragma: no mutate
)
_CANONICAL_CONTENT_MESSAGE = (
    "canonical content must use bytes and a digest record"  # pragma: no mutate
)
_CONTENT_DIGEST_MESSAGE = "canonical content digest must match exact bytes"  # pragma: no mutate
_QUALIFIED_ENVELOPE_MESSAGE = "qualified envelope must contain stage records"  # pragma: no mutate
_QUALIFICATION_SUBJECT_MESSAGE = (  # pragma: no mutate
    "qualification subject must match envelope content digest"
)
_OCI_REPOSITORY_MESSAGE = "OCI repository must be non-empty and canonical"  # pragma: no mutate
_OCI_TAG_MESSAGE = "OCI tag must be non-empty and canonical"  # pragma: no mutate
_OCI_MANIFEST_MESSAGE = "OCI manifest must be a digest record"  # pragma: no mutate
_ORAS_ARGUMENTS_MESSAGE = "ORAS arguments must be a tuple of strings"  # pragma: no mutate
_ORAS_INPUTS_MESSAGE = "ORAS inputs must be a tuple of bytes"  # pragma: no mutate
_ORAS_EXIT_CODE_MESSAGE = "ORAS exit code must be an integer"  # pragma: no mutate
_ORAS_OUTCOME_MESSAGE = (
    "ORAS outcome must use the typed provider classification"  # pragma: no mutate
)
_ORAS_OUTPUT_MESSAGE = "ORAS process output must be exact bytes"  # pragma: no mutate
_ORAS_COHERENCE_MESSAGE = "ORAS outcome must agree with its exit code"  # pragma: no mutate
_ORAS_EXPORT_MESSAGE = "ORAS exported file payload must be exact bytes"  # pragma: no mutate
_ORAS_FAILED_EXPORT_MESSAGE = (  # pragma: no mutate
    "failed ORAS executions cannot export authoritative file bytes"
)


def _require_text(value: str, message: str) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise diagnostic_error(InvalidIdentity, message)


def _require_tuple(value: object, item_type: type[object], message: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(item, item_type) for item in value):
        raise diagnostic_error(InvalidIdentity, message)


def _require_attempt_id(attempt_id: str) -> None:
    _require_text(attempt_id, _ATTEMPT_ID_MESSAGE)


@dataclass(frozen=True, slots=True)
class InputSnapshotPlan:
    include_paths: tuple[str, ...]
    exclude_paths: tuple[str, ...] = ()
    inputs: tuple[LockIdentity, ...] = ()

    def __post_init__(self) -> None:
        _require_tuple(self.include_paths, str, _INCLUDED_PATHS_MESSAGE)
        _require_tuple(self.exclude_paths, str, _EXCLUDED_PATHS_MESSAGE)
        _require_tuple(self.inputs, LockIdentity, _INPUTS_MESSAGE)


@dataclass(frozen=True, slots=True)
class BuildPlan:
    name: str
    commands: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.name, _BUILD_PLAN_NAME_MESSAGE)
        _require_tuple(self.commands, str, _BUILD_COMMANDS_MESSAGE)


class SigningDisposition(StrEnum):
    """The explicit result of the signing stage."""

    SIGNED = "signed"
    SIGNING_NOT_REQUIRED = "signing_not_required"


@dataclass(frozen=True, slots=True)
class SigningPolicy:
    key_id: str | None

    @classmethod
    def required(cls, key_id: str) -> SigningPolicy:
        _require_text(key_id, _SIGNING_KEY_MESSAGE)
        return cls(key_id)

    @classmethod
    def none(cls) -> SigningPolicy:
        return cls(None)


@dataclass(frozen=True, slots=True)
class VerificationPlan:
    checks: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_tuple(self.checks, str, _VERIFICATION_CHECKS_MESSAGE)


@dataclass(frozen=True, slots=True)
class ReleaseSource:
    release_id: ReleaseId
    revision: SourceRevision

    def __post_init__(self) -> None:
        if not _has_release_source_identities(self.release_id, self.revision):
            raise diagnostic_error(InvalidIdentity, _RELEASE_SOURCE_MESSAGE)


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
            raise diagnostic_error(InvalidIdentity, _SNAPSHOT_SOURCE_MESSAGE)


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
        raise diagnostic_error(InvalidIdentity, _UNSIGNED_SOURCE_MESSAGE)
    _require_tuple(build.artifacts, Artifact, _BUILD_ARTIFACTS_MESSAGE)
    _require_tuple(build.sboms, Sbom, _BUILD_SBOMS_MESSAGE)
    _require_tuple(build.locks, LockIdentity, _BUILD_LOCKS_MESSAGE)
    _require_tuple(
        build.toolchains,
        ToolchainIdentity,
        _BUILD_TOOLCHAINS_MESSAGE,
    )


@dataclass(frozen=True, slots=True)
class PrequalifiedBuild:
    unsigned: UnsignedBuild
    evidence: tuple[Evidence, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.unsigned, UnsignedBuild):
            raise diagnostic_error(InvalidIdentity, _PREQUALIFIED_BUILD_MESSAGE)
        _require_tuple(
            self.evidence,
            Evidence,
            _PREQUALIFICATION_EVIDENCE_MESSAGE,
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
        raise diagnostic_error(InvalidIdentity, _SIGNED_BUILD_MESSAGE)


def _validate_signing_disposition(disposition: object) -> None:
    if not isinstance(disposition, SigningDisposition):
        raise diagnostic_error(InvalidIdentity, _SIGNING_DISPOSITION_MESSAGE)


def _validate_signature(signature: Artifact | None, disposition: SigningDisposition) -> None:
    if disposition is SigningDisposition.SIGNED and not isinstance(signature, Artifact):
        raise diagnostic_error(InvalidIdentity, _SIGNATURE_REQUIRED_MESSAGE)
    if disposition is SigningDisposition.SIGNING_NOT_REQUIRED and signature is not None:
        raise diagnostic_error(InvalidIdentity, _SIGNATURE_FORBIDDEN_MESSAGE)


def _validate_canonical_content(canonical_bytes: object, content_sha256: object) -> None:
    if not isinstance(canonical_bytes, bytes) or not isinstance(content_sha256, Sha256Digest):
        raise diagnostic_error(InvalidIdentity, _CANONICAL_CONTENT_MESSAGE)
    if Sha256Digest.from_bytes(canonical_bytes) != content_sha256:
        raise diagnostic_error(InvalidIdentity, _CONTENT_DIGEST_MESSAGE)


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
        raise diagnostic_error(InvalidIdentity, _QUALIFIED_ENVELOPE_MESSAGE)
    if qualification.subject != envelope.content_sha256:
        raise diagnostic_error(InvalidIdentity, _QUALIFICATION_SUBJECT_MESSAGE)


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
        _require_text(self.repository, _OCI_REPOSITORY_MESSAGE)
        _require_text(self.tag, _OCI_TAG_MESSAGE)
        if self.manifest_sha256 is not None and not isinstance(self.manifest_sha256, Sha256Digest):
            raise diagnostic_error(InvalidIdentity, _OCI_MANIFEST_MESSAGE)


@dataclass(frozen=True, slots=True)
class StoredEnvelope:
    reference: OciReference
    manifest_sha256: Sha256Digest


@dataclass(frozen=True, slots=True)
class OrasInvocation:
    argv: tuple[str, ...]
    input_bytes: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        _require_tuple(self.argv, str, _ORAS_ARGUMENTS_MESSAGE)
        _require_tuple(self.input_bytes, bytes, _ORAS_INPUTS_MESSAGE)


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
        raise diagnostic_error(InvalidIdentity, _ORAS_EXIT_CODE_MESSAGE)


def _validate_oras_outcome(outcome: object) -> None:
    if not isinstance(outcome, OrasOutcome):
        raise diagnostic_error(InvalidIdentity, _ORAS_OUTCOME_MESSAGE)


def _validate_oras_process_output(stdout: object, stderr: object) -> None:
    if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
        raise diagnostic_error(InvalidIdentity, _ORAS_OUTPUT_MESSAGE)


def _validate_oras_result_coherence(result: OrasResult) -> None:
    success = result.outcome is OrasOutcome.SUCCESS
    if success != (result.exit_code == 0):
        raise diagnostic_error(InvalidIdentity, _ORAS_COHERENCE_MESSAGE)
    _validate_oras_export(result.exported_file_bytes, success)


def _validate_oras_export(exported: object, success: bool) -> None:
    if exported is not None and not isinstance(exported, bytes):
        raise diagnostic_error(InvalidIdentity, _ORAS_EXPORT_MESSAGE)
    if not success and exported is not None:
        raise diagnostic_error(InvalidIdentity, _ORAS_FAILED_EXPORT_MESSAGE)


def validate_attempt_id(attempt_id: str) -> None:
    """Reject empty attempt identifiers at mutable port boundaries."""

    _require_attempt_id(attempt_id)
