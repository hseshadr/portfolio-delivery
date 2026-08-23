"""Strict Pydantic boundary documents for deterministic delivery envelopes."""
# mypy: disable-error-code="explicit-any"

from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from portfolio_delivery.domain.identity import ProjectId, Sha256Digest, SourceRevision
from portfolio_delivery.envelope.canonical import normalize_artifact_path

BUILD_ENVELOPE_MEDIA_TYPE: Final = (
    "application/vnd.hseshadr.portfolio-delivery.build-envelope.v1+json"
)
QUALIFICATION_MEDIA_TYPE: Final = (
    "application/vnd.hseshadr.portfolio-delivery.qualification.v1+json"
)
CONFIG_MEDIA_TYPE: Final = "application/vnd.hseshadr.portfolio-delivery.config.v1+json"


class BoundaryDocument(BaseModel):
    """The common immutable, closed-world configuration for boundary data."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", populate_by_name=True, serialize_by_alias=True
    )


class SourceDocument(BoundaryDocument):
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


class LockDocument(BoundaryDocument):
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


class ToolchainDocument(BoundaryDocument):
    name: str
    version: str
    sha256: str

    @field_validator("sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value


class ArtifactDocument(BoundaryDocument):
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


class SbomDocument(BoundaryDocument):
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


class EvidenceDocument(BoundaryDocument):
    kind: str
    name: str
    subject: str
    status: Literal["passed", "failed", "skipped"]

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        return Sha256Digest(value).value


class ReleasePolicyDocument(BoundaryDocument):
    version: str
    channels: tuple[str, ...]


class CompatibilityDocument(BoundaryDocument):
    dagger: str
    oras: str


class BuildEnvelopeDocument(BoundaryDocument):
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
        _reject_duplicates(tuple(item.path for item in self.artifacts))
        _reject_duplicates(tuple(item.path for item in self.locks))
        _reject_duplicates(tuple(item.path for item in self.sboms))
        _reject_duplicates(tuple(item.artifact_path for item in self.sboms))
        return self


class QualificationRecordDocument(BoundaryDocument):
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


class OciConfigDocument(BoundaryDocument):
    media_type: Literal["application/vnd.hseshadr.portfolio-delivery.config.v1+json"] = Field(
        default=CONFIG_MEDIA_TYPE, alias="mediaType"
    )
    artifact_type: Literal["application/vnd.hseshadr.portfolio-delivery.envelope.v1"] = Field(
        default="application/vnd.hseshadr.portfolio-delivery.envelope.v1", alias="artifactType"
    )


def _reject_duplicates(values: tuple[str, ...]) -> None:
    if len(values) != len(set(values)):
        raise ValueError("normalized document paths must be unique")
