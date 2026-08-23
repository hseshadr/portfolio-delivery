"""Behavioral tests for the ordered pure-core foundation service."""

import pytest

from portfolio_delivery.application.foundation import FoundationDependencies, FoundationService
from portfolio_delivery.contracts.build import Verifier
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
from portfolio_delivery.envelope.builder import (
    EnvelopeBuilder,
    EnvelopeMetadata,
    PinnedCompatibility,
    ProjectAdapterVersion,
    QualificationBuilder,
    ReleaseChannel,
    ReleasePolicyMetadata,
)
from portfolio_delivery.envelope.canonical import canonical_json_bytes
from portfolio_delivery.envelope.documents import EvidenceDocument, QualificationRecordDocument


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


def make_metadata() -> EnvelopeMetadata:
    return EnvelopeMetadata(
        ProjectAdapterVersion("1.0.0"),
        1_724_472_000,
        ReleasePolicyMetadata("v1.2.3", (ReleaseChannel.STABLE,)),
        PinnedCompatibility("0.21.8", "1.3.3"),
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


class ForgedVerifier:
    def __init__(self, prequalified: PrequalifiedBuild) -> None:
        self.prequalified = prequalified

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        return self.prequalified

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        document = QualificationRecordDocument(
            subject=envelope.content_sha256.value,
            qualificationEvidence=(
                EvidenceDocument(
                    kind="archive",
                    name="manifest",
                    subject=make_digest("9").value,
                    status="passed",
                ),
            ),
        )
        canonical_bytes = canonical_json_bytes(document)
        return QualificationRecord(
            envelope.content_sha256,
            document,
            canonical_bytes,
            Sha256Digest.from_bytes(canonical_bytes),
        )


class MalformedVerifier:
    def __init__(self, prequalified: PrequalifiedBuild) -> None:
        self.prequalified = prequalified

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        return self.prequalified

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        canonical_bytes = b"{}\n"
        return QualificationRecord(
            envelope.content_sha256,
            object(),
            canonical_bytes,
            Sha256Digest.from_bytes(canonical_bytes),
        )


class NoncanonicalVerifier:
    def __init__(self, prequalified: PrequalifiedBuild) -> None:
        self.prequalified = prequalified

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        return self.prequalified

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        document = QualificationRecordDocument(
            subject=envelope.content_sha256.value,
            qualificationEvidence=(),
        )
        canonical_bytes = b"{}\n"
        return QualificationRecord(
            envelope.content_sha256,
            document,
            canonical_bytes,
            Sha256Digest.from_bytes(canonical_bytes),
        )


class WrongSubjectVerifier:
    def __init__(self, prequalified: PrequalifiedBuild) -> None:
        self.prequalified = prequalified

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        return self.prequalified

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        document = QualificationRecordDocument(
            subject=make_digest("9").value,
            qualificationEvidence=(),
        )
        canonical_bytes = canonical_json_bytes(document)
        return QualificationRecord(
            make_digest("9"), document, canonical_bytes, Sha256Digest.from_bytes(canonical_bytes)
        )


class DocumentSubjectVerifier:
    def __init__(self, prequalified: PrequalifiedBuild) -> None:
        self.prequalified = prequalified

    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        return self.prequalified

    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualificationRecord:
        document = QualificationRecordDocument(
            subject=make_digest("9").value,
            qualificationEvidence=(),
        )
        canonical_bytes = canonical_json_bytes(document)
        return QualificationRecord(
            envelope.content_sha256,
            document,
            canonical_bytes,
            Sha256Digest.from_bytes(canonical_bytes),
        )


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


def make_service(
    events: list[str], store: ArtifactStore, verifier: Verifier | None = None
) -> FoundationService:
    prequalified = make_prequalified()
    selected_verifier = verifier or OrderedVerifier(events, prequalified)
    return FoundationService(
        FoundationDependencies(
            OrderedSnapshotter(events, prequalified.unsigned.source),
            OrderedBuilder(events, prequalified.unsigned),
            selected_verifier,
            OrderedSigner(events),
            store,
        ),
        EnvelopeBuilder(make_metadata()),
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


async def test_should_reject_forged_final_evidence_subject_when_verifier_qualifies() -> None:
    # Given
    events: list[str] = []
    prequalified = make_prequalified()
    service = make_service(events, RecordingStore(), ForgedVerifier(prequalified))

    # When / Then
    with pytest.raises(InvalidIdentity, match="final envelope digest"):
        await service.qualify(
            make_source(),
            InputSnapshotPlan(("src",)),
            BuildPlan("build", ("uv build",)),
            SigningPolicy.none(),
            VerificationPlan(("archive",)),
        )


async def test_should_reject_unexpected_qualification_document_when_verifier_qualifies() -> None:
    # Given
    events: list[str] = []
    prequalified = make_prequalified()
    service = make_service(events, RecordingStore(), MalformedVerifier(prequalified))

    # When / Then
    with pytest.raises(InvalidIdentity, match="qualification document"):
        await service.qualify(
            make_source(),
            InputSnapshotPlan(("src",)),
            BuildPlan("build", ("uv build",)),
            SigningPolicy.none(),
            VerificationPlan(("archive",)),
        )


async def test_should_reject_noncanonical_qualification_bytes_when_verifier_qualifies() -> None:
    # Given
    events: list[str] = []
    prequalified = make_prequalified()
    service = make_service(events, RecordingStore(), NoncanonicalVerifier(prequalified))

    # When / Then
    with pytest.raises(InvalidIdentity, match="bytes must match"):
        await service.qualify(
            make_source(),
            InputSnapshotPlan(("src",)),
            BuildPlan("build", ("uv build",)),
            SigningPolicy.none(),
            VerificationPlan(("archive",)),
        )


async def test_should_reject_wrong_qualification_subject_when_verifier_qualifies() -> None:
    # Given
    events: list[str] = []
    prequalified = make_prequalified()
    service = make_service(events, RecordingStore(), WrongSubjectVerifier(prequalified))

    # When / Then
    with pytest.raises(InvalidIdentity, match="final envelope digest"):
        await service.qualify(
            make_source(),
            InputSnapshotPlan(("src",)),
            BuildPlan("build", ("uv build",)),
            SigningPolicy.none(),
            VerificationPlan(("archive",)),
        )


async def test_should_reject_forged_document_subject_when_verifier_qualifies() -> None:
    # Given
    events: list[str] = []
    prequalified = make_prequalified()
    service = make_service(events, RecordingStore(), DocumentSubjectVerifier(prequalified))

    # When / Then
    with pytest.raises(InvalidIdentity, match="document must target"):
        await service.qualify(
            make_source(),
            InputSnapshotPlan(("src",)),
            BuildPlan("build", ("uv build",)),
            SigningPolicy.none(),
            VerificationPlan(("archive",)),
        )


async def test_should_include_signature_in_bundle_when_signed_envelope_persists() -> None:
    # Given
    events: list[str] = []
    store = RecordingStore()
    service = make_service(events, store)
    qualified = await service.qualify(
        make_source(),
        InputSnapshotPlan(("src",)),
        BuildPlan("build", ("uv build",)),
        SigningPolicy.required("catalog-key"),
        VerificationPlan(("archive",)),
    )

    # When
    await service.persist(qualified, "attempt-1")

    # Then
    assert store.bundle is not None
    assert tuple(artifact.name for artifact in store.bundle.artifacts) == ("catalog", "signature")
