"""Composable Dagger interfaces used by the stable Phase 1 entrypoints."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from dagger import Directory, File, function, interface

from portfolio_delivery_dagger.plan import InputSnapshotPlan

__all__ = [
    "BuildOutput",
    "BuildPlan",
    "CheckOutput",
    "InputSnapshotPlan",
    "ProjectComposition",
    "SigningOutput",
    "SigningPlan",
    "VerificationPlan",
]


@interface
@runtime_checkable
class CheckOutput(Protocol):
    """Project-owned detached check output."""

    @function
    async def passed(self) -> bool: ...

    @function
    async def evidence(self) -> File: ...


@interface
@runtime_checkable
class ProjectComposition(Protocol):
    """Project-owned source selection and checks."""

    @function
    async def include_paths(self) -> list[str]: ...

    @function
    async def exclude_paths(self) -> list[str]: ...

    @function
    async def check(self, source: Directory) -> CheckOutput: ...


@interface
@runtime_checkable
class BuildOutput(Protocol):
    """Project-owned output bytes without foundation provenance fields."""

    @function
    async def build_input(self) -> File: ...

    @function
    async def artifacts(self) -> Directory: ...

    @function
    async def sboms(self) -> Directory: ...


@interface
@runtime_checkable
class BuildPlan(Protocol):
    """Project-owned hermetic build plan."""

    @function
    async def build(
        self, source: Directory, manifest: File, input_snapshot_sha256: str
    ) -> BuildOutput: ...


@interface
@runtime_checkable
class SigningOutput(Protocol):
    """Project-owned signed output bytes and explicit disposition."""

    @function
    async def artifacts(self) -> Directory: ...

    @function
    async def sboms(self) -> Directory: ...

    @function
    async def signature_path(self) -> str | None: ...


@interface
@runtime_checkable
class SigningPlan(Protocol):
    """Project-owned signing plan without plaintext secret fields."""

    @function
    async def sign(
        self, build_input: File, artifacts: Directory, sboms: Directory
    ) -> SigningOutput: ...


@interface
@runtime_checkable
class VerificationPlan(Protocol):
    """Project-owned checks before and after envelope assembly."""

    @function
    async def prequalify(
        self,
        build_input: File,
        artifacts: Directory,
        sboms: Directory,
        input_snapshot_sha256: str,
    ) -> CheckOutput: ...

    @function
    async def qualify(self, envelope: File, envelope_sha256: str) -> CheckOutput: ...
