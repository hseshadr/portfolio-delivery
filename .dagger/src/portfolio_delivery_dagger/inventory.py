"""Bounded source-inventory and byte-manifest documents."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest


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


class SourceInventoryDocument(BaseModel):  # type: ignore[explicit-any]
    """Canonical inventory of the exact Git commit/tree object database."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    entries: tuple[SourceInventoryEntry, ...]
