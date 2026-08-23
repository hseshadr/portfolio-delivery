"""Strict Pydantic boundary documents for deterministic delivery envelopes."""

from __future__ import annotations

from typing import Annotated, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from portfolio_delivery.domain.errors import diagnostic_error
from portfolio_delivery.domain.identity import ProjectId, Sha256Digest, SourceRevision
from portfolio_delivery.envelope.canonical import normalize_artifact_path

BUILD_ENVELOPE_MEDIA_TYPE: Final = (
    "application/vnd.hseshadr.portfolio-delivery.build-envelope.v1+json"
)
QUALIFICATION_MEDIA_TYPE: Final = (
    "application/vnd.hseshadr.portfolio-delivery.qualification.v1+json"
)
CONFIG_MEDIA_TYPE: Final = "application/vnd.hseshadr.portfolio-delivery.config.v1+json"
type OciOrderIndex = Annotated[int, Field(ge=0, strict=True)]
_IDEMPOTENCY_KEY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "release idempotency key must be non-empty and canonical"
)
_CONFIG_SIGNATURE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "signed config provenance requires exactly one signature path"
)
_DUPLICATE_PATH_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "normalized document paths must be unique"
)
_DUPLICATE_EVIDENCE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "evidence kind and name must be unique"
)


class BoundaryDocument(BaseModel):  # type: ignore[explicit-any]
    """The common immutable, closed-world configuration for boundary data."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", populate_by_name=True, serialize_by_alias=True
    )


class SourceDocument(BoundaryDocument):  # type: ignore[explicit-any]
    project: str
    repository: str
    protected_ref: str = Field(alias="protectedRef")
    commit_sha: str = Field(alias="commitSha")
    source_tree_sha256: str = Field(alias="sourceTreeSha256")

    @field_validator("project")
    @classmethod
    def validate_project(cls, value: str) -> str:
        return ProjectId(value).value

    @field_validator("source_tree_sha256")
    @classmethod
    def validate_source_digest(cls, value: str) -> str:
        return Sha256Digest(value).value

    @model_validator(mode="after")
    def validate_revision(self) -> Self:
        SourceRevision(
            ProjectId(self.project),
            self.repository,
            self.protected_ref,
            self.commit_sha,
            Sha256Digest(self.source_tree_sha256),
        )
        return self


class LockDocument(BoundaryDocument):  # type: ignore[explicit-any]
    path: str
    sha256: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_artifact_path(value).value

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value


class ToolchainDocument(BoundaryDocument):  # type: ignore[explicit-any]
    name: str
    version: str
    sha256: str

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value


class ArtifactDocument(BoundaryDocument):  # type: ignore[explicit-any]
    name: str
    path: str
    media_type: str = Field(alias="mediaType")
    size: int = Field(ge=0)
    sha256: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_artifact_path(value).value

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value


class SbomDocument(BoundaryDocument):  # type: ignore[explicit-any]
    artifact_path: str = Field(alias="artifactPath")
    path: str
    media_type: str = Field(alias="mediaType")
    sha256: str

    @field_validator("artifact_path", "path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return normalize_artifact_path(value).value

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value


class EvidenceDocument(BoundaryDocument):  # type: ignore[explicit-any]
    kind: str
    name: str
    subject: str
    status: Literal["passed", "failed", "skipped"]

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        return Sha256Digest(value).value


class ReleasePolicyDocument(BoundaryDocument):  # type: ignore[explicit-any]
    version: str
    channels: tuple[str, ...]


class CompatibilityDocument(BoundaryDocument):  # type: ignore[explicit-any]
    dagger: str
    oras: str


class BuildEnvelopeDocument(BoundaryDocument):  # type: ignore[explicit-any]
    schema_version: Literal["v1"] = Field(default="v1", alias="schemaVersion")
    source: SourceDocument
    project_adapter_version: str = Field(alias="projectAdapterVersion")
    source_date_epoch: int = Field(alias="sourceDateEpoch", ge=0, strict=True)
    locks: tuple[LockDocument, ...]
    toolchains: tuple[ToolchainDocument, ...]
    artifacts: tuple[ArtifactDocument, ...]
    sboms: tuple[SbomDocument, ...]
    prequalification_evidence: tuple[EvidenceDocument, ...] = Field(
        alias="prequalificationEvidence"
    )
    release_policy: ReleasePolicyDocument = Field(alias="releasePolicy")
    compatibility: CompatibilityDocument

    @field_validator("locks")
    @classmethod
    def sort_locks(cls, values: tuple[LockDocument, ...]) -> tuple[LockDocument, ...]:
        return tuple(sorted(values, key=lambda item: item.path))

    @field_validator("toolchains")
    @classmethod
    def sort_toolchains(
        cls, values: tuple[ToolchainDocument, ...]
    ) -> tuple[ToolchainDocument, ...]:
        return tuple(sorted(values, key=lambda item: item.name))

    @field_validator("artifacts")
    @classmethod
    def sort_artifacts(cls, values: tuple[ArtifactDocument, ...]) -> tuple[ArtifactDocument, ...]:
        return tuple(sorted(values, key=lambda item: (item.path, item.name)))

    @field_validator("sboms")
    @classmethod
    def sort_sboms(cls, values: tuple[SbomDocument, ...]) -> tuple[SbomDocument, ...]:
        return tuple(sorted(values, key=lambda item: item.artifact_path))

    @field_validator("prequalification_evidence")
    @classmethod
    def sort_evidence(cls, values: tuple[EvidenceDocument, ...]) -> tuple[EvidenceDocument, ...]:
        return tuple(sorted(values, key=lambda item: (item.kind, item.name)))

    @model_validator(mode="after")
    def reject_duplicate_paths(self) -> Self:
        _reject_duplicate_build_keys(self)
        return self


def _reject_duplicate_build_keys(document: BuildEnvelopeDocument) -> None:
    _reject_artifact_paths(document.artifacts)
    _reject_lock_paths(document.locks)
    _reject_toolchain_names(document.toolchains)
    _reject_sbom_paths(document.sboms)
    _reject_sbom_artifact_paths(document.sboms)
    _reject_duplicate_evidence(document.prequalification_evidence)


def _reject_artifact_paths(values: tuple[ArtifactDocument, ...]) -> None:
    _reject_duplicates(tuple(item.path for item in values))


def _reject_lock_paths(values: tuple[LockDocument, ...]) -> None:
    _reject_duplicates(tuple(item.path for item in values))


def _reject_toolchain_names(values: tuple[ToolchainDocument, ...]) -> None:
    _reject_duplicates(tuple(item.name for item in values))


def _reject_sbom_paths(values: tuple[SbomDocument, ...]) -> None:
    _reject_duplicates(tuple(item.path for item in values))


def _reject_sbom_artifact_paths(values: tuple[SbomDocument, ...]) -> None:
    _reject_duplicates(tuple(item.artifact_path for item in values))


class QualificationRecordDocument(BoundaryDocument):  # type: ignore[explicit-any]
    schema_version: Literal["v1"] = Field(default="v1", alias="schemaVersion")
    subject: str
    qualification_evidence: tuple[EvidenceDocument, ...] = Field(alias="qualificationEvidence")

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        return Sha256Digest(value).value

    @field_validator("qualification_evidence")
    @classmethod
    def sort_evidence(cls, values: tuple[EvidenceDocument, ...]) -> tuple[EvidenceDocument, ...]:
        return tuple(sorted(values, key=lambda item: (item.kind, item.name)))

    @model_validator(mode="after")
    def reject_duplicate_evidence(self) -> Self:
        _reject_duplicate_evidence(self.qualification_evidence)
        return self


class OciStageOrderDocument(BoundaryDocument):  # type: ignore[explicit-any]
    unsigned_artifact_order: tuple[OciOrderIndex, ...] = Field(alias="unsignedArtifactOrder")
    unsigned_sbom_order: tuple[OciOrderIndex, ...] = Field(alias="unsignedSbomOrder")
    lock_order: tuple[OciOrderIndex, ...] = Field(alias="lockOrder")
    toolchain_order: tuple[OciOrderIndex, ...] = Field(alias="toolchainOrder")
    prequalification_evidence_order: tuple[OciOrderIndex, ...] = Field(
        alias="prequalificationEvidenceOrder"
    )
    bundle_artifact_order: tuple[OciOrderIndex, ...] = Field(alias="bundleArtifactOrder")
    bundle_sbom_order: tuple[OciOrderIndex, ...] = Field(alias="bundleSbomOrder")


class OciConfigDocument(BoundaryDocument):  # type: ignore[explicit-any]
    schema_version: Literal["v1"] = Field(default="v1", alias="schemaVersion")
    media_type: Literal["application/vnd.hseshadr.portfolio-delivery.config.v1+json"] = Field(
        default=CONFIG_MEDIA_TYPE, alias="mediaType"
    )
    artifact_type: Literal["application/vnd.hseshadr.portfolio-delivery.envelope.v1"] = Field(
        default="application/vnd.hseshadr.portfolio-delivery.envelope.v1", alias="artifactType"
    )
    envelope_sha256: str = Field(alias="envelopeSha256")
    qualification_sha256: str = Field(alias="qualificationSha256")
    release_idempotency_key: str = Field(alias="releaseIdempotencyKey")
    input_snapshot_sha256: str = Field(alias="inputSnapshotSha256")
    signing_disposition: Literal["signed", "signing_not_required"] = Field(
        alias="signingDisposition"
    )
    signature_path: str | None = Field(alias="signaturePath")
    stage_order: OciStageOrderDocument = Field(alias="stageOrder")

    @field_validator("envelope_sha256", "qualification_sha256", "input_snapshot_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value

    @field_validator("release_idempotency_key")
    @classmethod
    def validate_idempotency_key(cls, value: str) -> str:
        if not value or value != value.strip():
            raise diagnostic_error(ValueError, _IDEMPOTENCY_KEY_MESSAGE)
        return value

    @field_validator("signature_path")
    @classmethod
    def validate_signature_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_artifact_path(value).value

    @model_validator(mode="after")
    def validate_signing_coherence(self) -> Self:
        has_signature = self.signature_path is not None
        if (self.signing_disposition == "signed") != has_signature:
            raise diagnostic_error(ValueError, _CONFIG_SIGNATURE_MESSAGE)
        return self


def _reject_duplicates(values: tuple[str, ...]) -> None:
    if len(values) != len(set(values)):
        raise diagnostic_error(ValueError, _DUPLICATE_PATH_MESSAGE)


def _reject_duplicate_evidence(values: tuple[EvidenceDocument, ...]) -> None:
    keys = tuple((item.kind, item.name) for item in values)
    if len(keys) != len(set(keys)):
        raise diagnostic_error(ValueError, _DUPLICATE_EVIDENCE_MESSAGE)
