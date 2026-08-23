"""Executable build-stage fakes that retain the full real stage records."""

from portfolio_delivery.domain.artifacts import Artifact
from portfolio_delivery.domain.stages import (
    BuildEnvelope,
    BuildPlan,
    InputSnapshotPlan,
    PrequalifiedBuild,
    QualificationRecord,
    ReleaseSource,
    SignedBuild,
    SigningDisposition,
    SigningPolicy,
    SnapshottedSource,
    UnsignedBuild,
    VerificationPlan,
)


class FakeInputSnapshotter:
    """Return the configured complete snapshot and count observations."""

    def __init__(self, snapshot: SnapshottedSource) -> None:
        self.snapshot_result = snapshot
        self.observation_count = 0

    async def snapshot(self, release: ReleaseSource, plan: InputSnapshotPlan) -> SnapshottedSource:
        self.observation_count += 1
        return self.snapshot_result


class FakeBuilder:
    """Return the configured complete unsigned build and count builds."""

    def __init__(self, build: UnsignedBuild) -> None:
        self.build_result = build
        self.build_count = 0

    async def build(self, source: SnapshottedSource, plan: BuildPlan) -> UnsignedBuild:
        self.build_count += 1
        return self.build_result


class FakeSigner:
    """Sign only when the supplied policy explicitly requires a signature."""

    def __init__(self, signature: Artifact) -> None:
        self.signature = signature
        self.sign_count = 0

    async def sign(self, build: PrequalifiedBuild, policy: SigningPolicy) -> SignedBuild:
        self.sign_count += 1
        return _signed_build(build, policy, self.signature)


def _signed_build(
    build: PrequalifiedBuild,
    policy: SigningPolicy,
    signature: Artifact,
) -> SignedBuild:
    if policy.key_id is None:
        return SignedBuild(build, None, SigningDisposition.SIGNING_NOT_REQUIRED)
    return SignedBuild(build, signature, SigningDisposition.SIGNED)


class FakeVerifier:
    """Return configured full verification records while recording observations."""

    def __init__(self, prequalified: PrequalifiedBuild, qualification: QualificationRecord) -> None:
        self.prequalified = prequalified
        self.qualification = qualification
        self.prequalification_count = 0
        self.qualification_count = 0

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        self.prequalification_count += 1
        return self.prequalified

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        self.qualification_count += 1
        return self.qualification
