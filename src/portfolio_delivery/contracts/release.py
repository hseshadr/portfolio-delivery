"""Later-phase ports fixed at the pure-core boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from portfolio_delivery.domain.stages import QualifiedEnvelope, ReleaseSource, StoredEnvelope


@runtime_checkable
class Registry(Protocol):
    """Inspect and publish one exact qualified envelope."""

    async def inspect(self, release: ReleaseSource) -> StoredEnvelope | None:
        raise NotImplementedError

    async def publish(self, envelope: QualifiedEnvelope) -> StoredEnvelope:
        raise NotImplementedError


@runtime_checkable
class Versioner(Protocol):
    """Derive a release source from protected source state."""

    async def version(self, source: ReleaseSource) -> ReleaseSource:
        raise NotImplementedError


@runtime_checkable
class ReleaseLedger(Protocol):
    """Record detached delivery transitions in the authoritative ledger."""

    async def record(self, envelope: QualifiedEnvelope) -> None:
        raise NotImplementedError


@runtime_checkable
class DeploymentProvider(Protocol):
    """Deploy one previously qualified immutable envelope."""

    async def deploy(self, envelope: QualifiedEnvelope) -> None:
        raise NotImplementedError


@runtime_checkable
class DesiredState(Protocol):
    """Return the authoritative protected-source release."""

    async def current(self) -> ReleaseSource:
        raise NotImplementedError


@runtime_checkable
class Clock(Protocol):
    """Supply time only at later delivery-policy boundaries."""

    def now(self) -> datetime:
        raise NotImplementedError


@runtime_checkable
class TraceSink(Protocol):
    """Accept an opaque delivery trace reference."""

    def record(self, trace_id: str) -> None:
        raise NotImplementedError
