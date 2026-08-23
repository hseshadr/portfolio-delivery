"""Ordered pure-core assembly and exact-byte persistence for release envelopes."""

from __future__ import annotations

from dataclasses import dataclass

from portfolio_delivery.contracts.build import Builder, InputSnapshotter, Signer, Verifier
from portfolio_delivery.contracts.storage import ArtifactStore
from portfolio_delivery.domain.artifacts import Artifact
from portfolio_delivery.domain.stages import (
    BuildPlan,
    EnvelopeBundle,
    InputSnapshotPlan,
    QualifiedEnvelope,
    ReleaseSource,
    SigningPolicy,
    StoredEnvelope,
    VerificationPlan,
    validate_attempt_id,
)
from portfolio_delivery.envelope.builder import EnvelopeBuilder


@dataclass(frozen=True, slots=True)
class FoundationDependencies:
    """Narrow ports used by the staged foundation workflow."""

    snapshotter: InputSnapshotter
    builder: Builder
    verifier: Verifier
    signer: Signer
    store: ArtifactStore


class FoundationService:
    """Coordinate only the immutable stages that precede delivery mutation."""

    def __init__(
        self, dependencies: FoundationDependencies, envelope_builder: EnvelopeBuilder
    ) -> None:
        self._dependencies = dependencies
        self._envelope_builder = envelope_builder

    async def qualify(
        self,
        source: ReleaseSource,
        snapshot_plan: InputSnapshotPlan,
        build_plan: BuildPlan,
        signing_policy: SigningPolicy,
        verification_plan: VerificationPlan,
    ) -> QualifiedEnvelope:
        snapshot = await self._dependencies.snapshotter.snapshot(source, snapshot_plan)
        build = await self._dependencies.builder.build(snapshot, build_plan)
        prequalified = await self._dependencies.verifier.prequalify(build, verification_plan)
        signed = await self._dependencies.signer.sign(prequalified, signing_policy)
        envelope = self._envelope_builder.build(signed)
        qualification = await self._dependencies.verifier.qualify(envelope, verification_plan)
        return QualifiedEnvelope(envelope, qualification)

    async def persist(self, qualified: QualifiedEnvelope, attempt_id: str) -> StoredEnvelope:
        validate_attempt_id(attempt_id)
        return await self._dependencies.store.persist(_bundle_for(qualified), attempt_id)


def _bundle_for(qualified: QualifiedEnvelope) -> EnvelopeBundle:
    unsigned = qualified.envelope.signed.prequalified.unsigned
    return EnvelopeBundle(qualified, _signed_artifacts(qualified), unsigned.sboms)


def _signed_artifacts(qualified: QualifiedEnvelope) -> tuple[Artifact, ...]:
    signed = qualified.envelope.signed
    if signed.signature is None:
        return signed.prequalified.unsigned.artifacts
    return (*signed.prequalified.unsigned.artifacts, signed.signature)
