"""Pure builders for deterministic build envelopes and detached qualifications."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast

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

_SEMVER: Final = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_RELEASE_VERSION: Final = re.compile(rf"v{_SEMVER.pattern}")
PINNED_DAGGER_VERSION: Final[str] = "0.21.8"
PINNED_ORAS_VERSION: Final[str] = "1.3.3"


class ReleaseChannel(StrEnum):
    """Declared release channels allowed by the Phase 1 policy contract."""

    STABLE = "stable"
    NEXT = "next"


@dataclass(frozen=True, slots=True)
class ProjectAdapterVersion:
    """Canonical semantic version for one project adapter."""

    value: str

    def __post_init__(self) -> None:
        _require_semver(self.value, "project adapter version")


@dataclass(frozen=True, slots=True)
class ReleasePolicyMetadata:
    """Declared release version and finite supported publication channels."""

    version: str
    channels: tuple[ReleaseChannel, ...]

    def __post_init__(self) -> None:
        _require_release_version(self.version)
        _require_release_channels(self.channels)


@dataclass(frozen=True, slots=True)
class PinnedCompatibility:
    """The exact Dagger and ORAS versions pinned for this foundation."""

    dagger: str
    oras: str

    def __post_init__(self) -> None:
        _require_exact_pin(self.dagger, PINNED_DAGGER_VERSION, "Dagger")
        _require_exact_pin(self.oras, PINNED_ORAS_VERSION, "ORAS")


@dataclass(frozen=True, slots=True)
class EnvelopeMetadata:
    """Declared immutable metadata supplied by a project composition root."""

    project_adapter_version: ProjectAdapterVersion
    source_date_epoch: int
    release_policy: ReleasePolicyMetadata
    compatibility: PinnedCompatibility

    def __post_init__(self) -> None:
        _validate_metadata_contracts(self)
        _validate_source_date_epoch(self.source_date_epoch)


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
        projectAdapterVersion=metadata.project_adapter_version.value,
        sourceDateEpoch=metadata.source_date_epoch,
        locks=tuple(_lock_document(item) for item in unsigned.locks),
        toolchains=tuple(_toolchain_document(item) for item in unsigned.toolchains),
        artifacts=tuple(_artifact_document(item) for item in _signed_artifacts(signed)),
        sboms=tuple(_sbom_document(item) for item in unsigned.sboms),
        prequalificationEvidence=_evidence_documents(signed.prequalified.evidence),
        releasePolicy=_release_policy_document(metadata.release_policy),
        compatibility=_compatibility_document(metadata.compatibility),
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


def _validate_metadata_contracts(metadata: EnvelopeMetadata) -> None:
    _require_contract_type(metadata.project_adapter_version, ProjectAdapterVersion)
    _require_contract_type(metadata.release_policy, ReleasePolicyMetadata)
    _require_contract_type(metadata.compatibility, PinnedCompatibility)


def _validate_source_date_epoch(value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise InvalidIdentity("source date epoch must be a positive integer")


def _require_contract_type(value: object, expected_type: type[object]) -> None:
    if not isinstance(value, expected_type):
        raise InvalidIdentity("metadata must use declared typed contracts")


def _require_semver(value: str, name: str) -> None:
    if not isinstance(value, str) or _SEMVER.fullmatch(value) is None:
        raise InvalidIdentity(f"{name} must be canonical semantic version text")


def _require_release_version(value: str) -> None:
    if not isinstance(value, str) or _RELEASE_VERSION.fullmatch(value) is None:
        raise InvalidIdentity("release policy version must be v-prefixed semantic version")


def _require_release_channels(channels: object) -> None:
    declared = _declared_release_channels(channels)
    _require_nonempty_channels(declared)
    _require_unique_channels(declared)


def _declared_release_channels(channels: object) -> tuple[ReleaseChannel, ...]:
    if not isinstance(channels, tuple):
        raise InvalidIdentity("release policy must declare channels")
    if not all(isinstance(channel, ReleaseChannel) for channel in channels):
        raise InvalidIdentity("release policy channels must use the declared channel contract")
    return cast(tuple[ReleaseChannel, ...], channels)


def _require_nonempty_channels(channels: tuple[ReleaseChannel, ...]) -> None:
    if not channels:
        raise InvalidIdentity("release policy must declare channels")


def _require_unique_channels(channels: tuple[ReleaseChannel, ...]) -> None:
    if len(channels) != len(set(channels)):
        raise InvalidIdentity("release policy channels must be unique")


def _require_exact_pin(value: str, expected: str, name: str) -> None:
    if value != expected:
        raise InvalidIdentity(f"{name} must match the foundation compatibility pin")


def _require_policy_matches_release(signed: SignedBuild, metadata: EnvelopeMetadata) -> None:
    version = signed.prequalified.unsigned.source.release.release_id.version
    if metadata.release_policy.version != version:
        raise InvalidIdentity("declared release policy must match the release version")


def _release_policy_document(policy: ReleasePolicyMetadata) -> ReleasePolicyDocument:
    return ReleasePolicyDocument(version=policy.version, channels=tuple(policy.channels))


def _compatibility_document(compatibility: PinnedCompatibility) -> CompatibilityDocument:
    return CompatibilityDocument(dagger=compatibility.dagger, oras=compatibility.oras)
