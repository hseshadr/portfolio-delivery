"""Pure builders for deterministic build envelopes and detached qualifications."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
)
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import Sha256Digest
from portfolio_delivery.domain.stages import BuildEnvelope, QualificationRecord, SignedBuild
from portfolio_delivery.envelope.canonical import canonical_json_bytes
from portfolio_delivery.envelope.documents import (
    ArtifactDocument,
    BuildEnvelopeDocument,
    CompatibilityDocument,
    EvidenceDocument,
    LockDocument,
    QualificationRecordDocument,
    ReleasePolicyDocument,
    SbomDocument,
    SourceDocument,
    ToolchainDocument,
)

_PLACEHOLDER_VALUES: Final[frozenset[str]] = frozenset({"not-recorded", "unknown", "unset"})


@dataclass(frozen=True, slots=True)
class EnvelopeMetadata:
    """Declared immutable metadata supplied by a project composition root."""

    project_adapter_version: str
    source_date_epoch: int
    release_policy: ReleasePolicyDocument
    compatibility: CompatibilityDocument

    def __post_init__(self) -> None:
        _validate_metadata_texts(self)
        _validate_source_date_epoch(self.source_date_epoch)
        _validate_release_policy(self.release_policy)
        _validate_compatibility(self.compatibility)


class EnvelopeBuilder:
    """Assemble a canonical envelope from one already signed build."""

    def __init__(self, metadata: EnvelopeMetadata) -> None:
        self._metadata = metadata

    def build(self, signed: SignedBuild) -> BuildEnvelope:
        document = _build_document(signed, self._metadata)
        canonical_bytes = canonical_json_bytes(document)
        return BuildEnvelope(signed, document, canonical_bytes, _digest(canonical_bytes))


class QualificationBuilder:
    """Assemble detached final-check evidence for exact envelope bytes."""

    def build(self, envelope: BuildEnvelope, checks: tuple[Evidence, ...]) -> QualificationRecord:
        _validate_qualification_checks(envelope, checks)
        document = QualificationRecordDocument(
            subject=envelope.content_sha256.value,
            qualificationEvidence=tuple(_evidence_document(check) for check in checks),
        )
        canonical_bytes = canonical_json_bytes(document)
        return QualificationRecord(
            envelope.content_sha256, document, canonical_bytes, _digest(canonical_bytes)
        )


def _build_document(signed: SignedBuild, metadata: EnvelopeMetadata) -> BuildEnvelopeDocument:
    _require_policy_matches_release(signed, metadata)
    unsigned = signed.prequalified.unsigned
    return BuildEnvelopeDocument(
        source=_source_document(signed),
        projectAdapterVersion=metadata.project_adapter_version,
        sourceDateEpoch=metadata.source_date_epoch,
        locks=tuple(_lock_document(item) for item in unsigned.locks),
        toolchains=tuple(_toolchain_document(item) for item in unsigned.toolchains),
        artifacts=tuple(_artifact_document(item) for item in _signed_artifacts(signed)),
        sboms=tuple(_sbom_document(item) for item in unsigned.sboms),
        prequalificationEvidence=_evidence_documents(signed.prequalified.evidence),
        releasePolicy=metadata.release_policy,
        compatibility=metadata.compatibility,
    )


def _source_document(signed: SignedBuild) -> SourceDocument:
    revision = signed.prequalified.unsigned.source.release.revision
    return SourceDocument(
        project=revision.project.value,
        repository=revision.repository,
        protectedRef=revision.protected_ref,
        commitSha=revision.commit_sha,
        sourceTreeSha256=revision.source_tree_sha256.value,
    )


def _signed_artifacts(signed: SignedBuild) -> tuple[Artifact, ...]:
    artifacts = signed.prequalified.unsigned.artifacts
    if signed.signature is None:
        return artifacts
    return (*artifacts, signed.signature)


def _artifact_document(artifact: Artifact) -> ArtifactDocument:
    return ArtifactDocument(
        name=artifact.name,
        path=artifact.path.value,
        mediaType=artifact.media_type,
        size=artifact.size,
        sha256=artifact.sha256.value,
    )


def _sbom_document(sbom: Sbom) -> SbomDocument:
    return SbomDocument(
        artifactPath=sbom.artifact_path.value,
        path=sbom.path.value,
        mediaType=sbom.media_type,
        sha256=sbom.sha256.value,
    )


def _lock_document(lock: LockIdentity) -> LockDocument:
    return LockDocument(path=lock.path.value, sha256=lock.sha256.value)


def _toolchain_document(toolchain: ToolchainIdentity) -> ToolchainDocument:
    return ToolchainDocument(
        name=toolchain.name, version=toolchain.version, sha256=toolchain.sha256.value
    )


def _evidence_document(evidence: Evidence) -> EvidenceDocument:
    return EvidenceDocument(
        kind=evidence.kind,
        name=evidence.name,
        subject=evidence.subject.value,
        status=evidence.status.value,
    )


def _evidence_documents(evidence: tuple[Evidence, ...]) -> tuple[EvidenceDocument, ...]:
    return tuple(_evidence_document(item) for item in evidence)


def _digest(canonical_bytes: bytes) -> Sha256Digest:
    return Sha256Digest.from_bytes(canonical_bytes)


def _validate_qualification_checks(envelope: BuildEnvelope, checks: object) -> None:
    _require_evidence_checks(checks)
    _require_envelope_subjects(envelope, checks)


def _require_evidence_checks(checks: object) -> None:
    if not isinstance(checks, tuple):
        raise InvalidIdentity("qualification checks must be evidence records")
    if not all(isinstance(check, Evidence) for check in checks):
        raise InvalidIdentity("qualification checks must be evidence records")


def _require_envelope_subjects(envelope: BuildEnvelope, checks: object) -> None:
    if not isinstance(checks, tuple):
        raise InvalidIdentity("qualification checks must be evidence records")
    if any(_is_not_subject(check, envelope.content_sha256) for check in checks):
        raise InvalidIdentity("qualification checks must target the final envelope digest")


def _is_not_subject(check: object, subject: Sha256Digest) -> bool:
    return not isinstance(check, Evidence) or check.subject != subject


def _validate_metadata_texts(metadata: EnvelopeMetadata) -> None:
    _require_declared_text(metadata.project_adapter_version)


def _validate_source_date_epoch(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvalidIdentity("source date epoch must be a positive integer")


def _validate_release_policy(policy: object) -> None:
    if not isinstance(policy, ReleasePolicyDocument):
        raise InvalidIdentity("release policy must be a declared document")
    _require_declared_text(policy.version)
    _require_release_channels(policy.channels)


def _require_release_channels(channels: tuple[str, ...]) -> None:
    if not channels:
        raise InvalidIdentity("release policy channels must be declared")
    for channel in channels:
        _require_declared_text(channel)


def _validate_compatibility(compatibility: object) -> None:
    if not isinstance(compatibility, CompatibilityDocument):
        raise InvalidIdentity("compatibility must be a declared document")
    _require_declared_text(compatibility.dagger)
    _require_declared_text(compatibility.oras)


def _require_declared_text(value: object) -> None:
    if not isinstance(value, str) or not value or value != value.strip():
        raise InvalidIdentity("declared metadata must be canonical text")
    if value.casefold() in _PLACEHOLDER_VALUES:
        raise InvalidIdentity("declared metadata cannot use placeholders")


def _require_policy_matches_release(signed: SignedBuild, metadata: EnvelopeMetadata) -> None:
    version = signed.prequalified.unsigned.source.release.release_id.version
    if metadata.release_policy.version != version:
        raise InvalidIdentity("declared release policy must match the release version")
