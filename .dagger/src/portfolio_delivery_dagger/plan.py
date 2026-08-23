"""Typed source-selection contract and immutable bound implementation."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from dagger import function, interface


@interface
@runtime_checkable
class InputSnapshotPlan(Protocol):
    """Project-owned stable source selection."""

    @function
    async def include_paths(self) -> list[str]: ...

    @function
    async def exclude_paths(self) -> list[str]: ...
