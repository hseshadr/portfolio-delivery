"""Composable Dagger interfaces used by the stable Phase 1 entrypoints."""

from __future__ import annotations

from typing import Protocol

from dagger import Directory, function, interface

from portfolio_delivery_dagger.dto import (
    BuildEnvelope,
    CheckEvidence,
    PrequalifiedBuild,
    SignedBuild,
    SnapshottedSource,
    UnsignedBuild,
)


@interface
class ProjectComposition(Protocol):
    """Project-owned source selection and checks."""

    @function
    async def include_paths(self) -> list[str]: ...

    @function
    async def exclude_paths(self) -> list[str]: ...

    @function
    async def check(self, source: Directory) -> CheckEvidence: ...


@interface
class InputSnapshotPlan(Protocol):
    """Project-owned stable source selection."""

    @function
    async def include_paths(self) -> list[str]: ...

    @function
    async def exclude_paths(self) -> list[str]: ...


@interface
class BuildPlan(Protocol):
    """Project-owned hermetic build plan."""

    @function
    async def build(self, source: SnapshottedSource) -> UnsignedBuild: ...


@interface
class SigningPlan(Protocol):
    """Project-owned signing plan without plaintext secret fields."""

    @function
    async def sign(self, build: PrequalifiedBuild) -> SignedBuild: ...


@interface
class VerificationPlan(Protocol):
    """Project-owned checks before and after envelope assembly."""

    @function
    async def prequalify(self, build: UnsignedBuild) -> PrequalifiedBuild: ...

    @function
    async def qualify(self, envelope: BuildEnvelope) -> CheckEvidence: ...
