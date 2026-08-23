"""Behavioral tests for the ordered pure-core foundation service."""

import pytest

from portfolio_delivery.application.foundation import FoundationDependencies, FoundationService
from portfolio_delivery.contracts.storage import ArtifactStore
from portfolio_delivery.domain.artifacts import Artifact, Evidence, EvidenceStatus
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)
from portfolio_delivery.domain.stages import (
    BuildEnvelope,
    BuildPlan,
    EnvelopeBundle,
    InputSnapshotPlan,
    OciReference,
    PrequalifiedBuild,
    QualificationRecord,
    ReleaseSource,
    SignedBuild,
    SigningDisposition,
    SigningPolicy,
    SnapshottedSource,
    StoredEnvelope,
    UnsignedBuild,
    VerificationPlan,
)
from portfolio_delivery.envelope.builder import EnvelopeBuilder, QualificationBuilder


def make_digest(character: str) -> Sha256Digest:
    return Sha256Digest(f"sha256:{character * 64}")


def make_source() -> ReleaseSource:
    project = ProjectId("catalog")
    digest = make_digest("a")
    revision = SourceRevision(project, "hseshadr/catalog", "refs/heads/main", "b" * 40, digest)
    return ReleaseSource(ReleaseId(project, "v1.2.3", digest, "catalog-v1.2.3"), revision)


def make_snapshot() -> SnapshottedSource:
    return SnapshottedSource(make_source(), make_digest("c"))


def make_artifact() -> Artifact:
    return Artifact(
        "catalog", ArtifactPath("artifacts/catalog.whl"), "application/zip", 5, make_digest("d")
    )


def make_unsigned() -> UnsignedBuild:
    return UnsignedBuild(make_snapshot(), (make_artifact(),), (), (), ())


def make_prequalified() -> PrequalifiedBuild:
    evidence = Evidence("test", "unit", make_digest("e"), EvidenceStatus.PASSED)
    return PrequalifiedBuild(make_unsigned(), (evidence,))


def make_signature() -> Artifact:
    return Artifact(
        "signature",
        ArtifactPath("signatures/catalog.sig"),
        "application/signature",
        64,
        make_digest("f"),
    )


class OrderedSnapshotter:
    def __init__(self, events: list[str], snapshot: SnapshottedSource) -> None:
        self.events = events
        self.snapshot_result = snapshot

    async def snapshot(self, release: ReleaseSource, plan: InputSnapshotPlan) -> SnapshottedSource:
        self.events.append("snapshot")
        return self.snapshot_result


class OrderedBuilder:
    def __init__(self, events: list[str], build: UnsignedBuild) -> None:
        self.events = events
        self.build_result = build

    async def build(self, source: SnapshottedSource, plan: BuildPlan) -> UnsignedBuild:
        self.events.append("build")
        return self.build_result


class OrderedVerifier:
    def __init__(self, events: list[str], prequalified: PrequalifiedBuild) -> None:
        self.events = events
        self.prequalified = prequalified

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        self.events.append("prequalify")
        return self.prequalified

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        self.events.append("qualify")
        check = Evidence("archive", "manifest", envelope.content_sha256, EvidenceStatus.PASSED)
        return QualificationBuilder().build(envelope, (check,))


class OrderedSigner:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def sign(self, build: PrequalifiedBuild, policy: SigningPolicy) -> SignedBuild:
        self.events.append("sign")
        if policy.key_id is None:
            return SignedBuild(build, None, SigningDisposition.SIGNING_NOT_REQUIRED)
        return SignedBuild(build, make_signature(), SigningDisposition.SIGNED)


class RecordingStore:
    def __init__(self) -> None:
        self.bundle: EnvelopeBundle | None = None
        self.attempt_id: str | None = None

    async def inspect(self, reference: OciReference, attempt_id: str) -> StoredEnvelope | None:
        return None

    async def persist(self, bundle: EnvelopeBundle, attempt_id: str) -> StoredEnvelope:
        self.bundle = bundle
        self.attempt_id = attempt_id
        reference = OciReference("memory.local/catalog", "immutable")
        return StoredEnvelope(reference, make_digest("f"))

    async def restore(self, reference: OciReference, attempt_id: str) -> EnvelopeBundle:
        if self.bundle is None:
            raise RuntimeError("no bundle was persisted")
        return self.bundle


def make_service(events: list[str], store: ArtifactStore) -> FoundationService:
    prequalified = make_prequalified()
    return FoundationService(
        FoundationDependencies(
            OrderedSnapshotter(events, prequalified.unsigned.source),
            OrderedBuilder(events, prequalified.unsigned),
            OrderedVerifier(events, prequalified),
            OrderedSigner(events),
            store,
        ),
        EnvelopeBuilder(),
    )


async def test_should_follow_stages_before_assembling_signed_envelope() -> None:
    # Given
    events: list[str] = []
    service = make_service(events, RecordingStore())

    # When
    qualified = await service.qualify(
        make_source(),
        InputSnapshotPlan(("src",)),
        BuildPlan("build", ("uv build",)),
        SigningPolicy.required("catalog-key"),
        VerificationPlan(("archive",)),
    )

    # Then
    assert events == ["snapshot", "build", "prequalify", "sign", "qualify"]
    assert qualified.envelope.signed.disposition is SigningDisposition.SIGNED


async def test_should_record_no_signature_when_none_policy_is_explicit() -> None:
    # Given
    events: list[str] = []
    service = make_service(events, RecordingStore())

    # When
    qualified = await service.qualify(
        make_source(),
        InputSnapshotPlan(("src",)),
        BuildPlan("build", ("uv build",)),
        SigningPolicy.none(),
        VerificationPlan(("archive",)),
    )

    # Then
    assert qualified.envelope.signed.disposition is SigningDisposition.SIGNING_NOT_REQUIRED
    assert qualified.envelope.signed.signature is None


async def test_should_persist_exact_qualified_bytes_without_rebuilding() -> None:
    # Given
    events: list[str] = []
    store = RecordingStore()
    service = make_service(events, store)
    qualified = await service.qualify(
        make_source(),
        InputSnapshotPlan(("src",)),
        BuildPlan("build", ("uv build",)),
        SigningPolicy.none(),
        VerificationPlan(("archive",)),
    )

    # When
    await service.persist(qualified, "attempt-1")

    # Then
    assert store.bundle is not None
    assert store.bundle.qualified is qualified
    assert store.bundle.qualified.envelope.canonical_bytes is qualified.envelope.canonical_bytes
    assert (
        store.bundle.qualified.qualification.canonical_bytes
        is qualified.qualification.canonical_bytes
    )
    assert store.attempt_id == "attempt-1"


async def test_should_reject_empty_attempt_before_store_persistence() -> None:
    # Given
    events: list[str] = []
    store = RecordingStore()
    service = make_service(events, store)
    qualified = await service.qualify(
        make_source(),
        InputSnapshotPlan(("src",)),
        BuildPlan("build", ("uv build",)),
        SigningPolicy.none(),
        VerificationPlan(("archive",)),
    )

    # When / Then
    with pytest.raises(InvalidIdentity, match="attempt ID"):
        await service.persist(qualified, "")
    assert store.bundle is None
