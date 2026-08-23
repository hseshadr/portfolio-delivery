"""Narrow contracts for exact-byte OCI envelope persistence."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from portfolio_delivery.domain.stages import (
    EnvelopeBundle,
    OciReference,
    OrasInvocation,
    OrasResult,
    StoredEnvelope,
)


@runtime_checkable
class ArtifactStore(Protocol):
    """Inspect, persist, and restore immutable envelope bundles."""

    async def inspect(self, reference: OciReference, attempt_id: str) -> StoredEnvelope | None:
        raise NotImplementedError

    async def persist(self, bundle: EnvelopeBundle, attempt_id: str) -> StoredEnvelope:
        raise NotImplementedError

    async def restore(self, reference: OciReference, attempt_id: str) -> EnvelopeBundle:
        raise NotImplementedError


@runtime_checkable
class OrasRunner(Protocol):
    """Execute one preplanned ORAS invocation."""

    async def run(self, invocation: OrasInvocation, attempt_id: str) -> OrasResult:
        raise NotImplementedError
