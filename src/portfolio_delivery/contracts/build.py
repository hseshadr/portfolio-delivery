"""Narrow ports for the ordered snapshot, build, sign, and verify stages."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from portfolio_delivery.domain.stages import (
    BuildEnvelope,
    BuildPlan,
    InputSnapshotPlan,
    PrequalifiedBuild,
    QualificationRecord,
    ReleaseSource,
    SignedBuild,
    SigningPolicy,
    SnapshottedSource,
    UnsignedBuild,
    VerificationPlan,
)


@runtime_checkable
class InputSnapshotter(Protocol):
    """Capture declared immutable inputs for a release source."""

    async def snapshot(self, release: ReleaseSource, plan: InputSnapshotPlan) -> SnapshottedSource:
        raise NotImplementedError


@runtime_checkable
class Builder(Protocol):
    """Create unsigned artifacts from one exact snapshot."""

    async def build(self, source: SnapshottedSource, plan: BuildPlan) -> UnsignedBuild:
        raise NotImplementedError


@runtime_checkable
class Signer(Protocol):
    """Apply the declared signing policy after prequalification."""

    async def sign(self, build: PrequalifiedBuild, policy: SigningPolicy) -> SignedBuild:
        raise NotImplementedError


@runtime_checkable
class Verifier(Protocol):
    """Verify before signing and qualify the final envelope separately."""

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        raise NotImplementedError

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        raise NotImplementedError
