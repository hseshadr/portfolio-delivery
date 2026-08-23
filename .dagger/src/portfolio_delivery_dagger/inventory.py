"""Bounded source-inventory and byte-manifest documents."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest
from portfolio_delivery.envelope.documents import EvidenceDocument


class FileRecord(BaseModel):  # type: ignore[explicit-any]
    """One regular file identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    size: int = Field(ge=0)
    sha256: str

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return ArtifactPath(value).value

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        return Sha256Digest(value).value


class FileManifest(BaseModel):  # type: ignore[explicit-any]
    """Canonical bounded regular-file manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    files: tuple[FileRecord, ...]


class SourceInventoryEntry(FileRecord):  # type: ignore[explicit-any]
    """One Git-tree entry supplied by the trusted caller."""

    kind: Literal["regular", "symlink", "submodule", "device"]
    mode: str = Field(pattern=r"^[0-7]{6}$")

    @model_validator(mode="after")
    def validate_git_kind_mode(self) -> Self:
        allowed = {
            "regular": frozenset({"100644", "100755"}),
            "symlink": frozenset({"120000"}),
            "submodule": frozenset({"160000"}),
            "device": frozenset(),
        }
        if self.mode not in allowed[self.kind]:
            raise ValueError("inventory entry must use canonical Git kind and mode")
        return self


class SourceInventoryDocument(BaseModel):  # type: ignore[explicit-any]
    """Canonical inventory of the exact Git commit/tree object database."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entries: tuple[SourceInventoryEntry, ...]

    @model_validator(mode="after")
    def validate_canonical_paths(self) -> Self:
        paths = tuple(item.path for item in self.entries)
        if len(set(paths)) != len(paths):
            raise ValueError("inventory paths must be unique")
        if paths != tuple(sorted(paths)):
            raise ValueError("inventory entries must use canonical path order")
        return self


class PrequalificationEvidenceDocument(BaseModel):  # type: ignore[explicit-any]
    """Canonical detached evidence emitted by a project check."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    schema_version: Literal["v1"] = Field(alias="schemaVersion")
    evidence: tuple[EvidenceDocument, ...] = Field(min_length=1, max_length=4_096)

    @field_validator("evidence")
    @classmethod
    def sort_evidence(cls, values: tuple[EvidenceDocument, ...]) -> tuple[EvidenceDocument, ...]:
        return tuple(sorted(values, key=lambda item: (item.kind, item.name)))

    @model_validator(mode="after")
    def reject_duplicate_evidence(self) -> Self:
        keys = tuple((item.kind, item.name) for item in self.evidence)
        if len(set(keys)) != len(keys):
            raise ValueError("prequalification evidence identities must be unique")
        return self
