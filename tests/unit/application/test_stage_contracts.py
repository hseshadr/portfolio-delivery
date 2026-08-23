from collections.abc import Callable
from typing import Final, cast

import pytest

from portfolio_delivery.contracts.build import Signer
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
    OrasInvocation,
    OrasOutcome,
    OrasResult,
    PrequalifiedBuild,
    QualificationRecord,
    QualifiedEnvelope,
    ReleaseSource,
    SignedBuild,
    SigningDisposition,
    SigningPolicy,
    SnapshottedSource,
    UnsignedBuild,
    VerificationPlan,
)
from tests.fakes.build import FakeSigner
from tests.fakes.storage import FakeArtifactStore

EXPECTED_STORE_OBSERVATIONS: Final[int] = 2


def make_digest(character: str) -> Sha256Digest:
    return Sha256Digest(f"sha256:{character * 64}")


def make_signature_artifact() -> Artifact:
    return Artifact(
        name="catalog-signature",
        path=ArtifactPath("signatures/catalog.ed25519"),
        media_type="application/vnd.portfolio-delivery.signature",
        size=64,
        sha256=make_digest("a"),
    )


def make_snapshotted_source() -> SnapshottedSource:
    project = ProjectId("catalog")
    source_sha256 = make_digest("c")
    revision = SourceRevision(
        project=project,
        repository="hseshadr/catalog",
        protected_ref="refs/heads/main",
        commit_sha="d" * 40,
        source_tree_sha256=source_sha256,
    )
    release_id = ReleaseId(project, "v0.1.0", source_sha256, "catalog-v0.1.0")
    return SnapshottedSource(ReleaseSource(release_id, revision), make_digest("e"))


def make_prequalified_build() -> PrequalifiedBuild:
    unsigned = UnsignedBuild(
        source=make_snapshotted_source(),
        artifacts=(),
        sboms=(),
        locks=(),
        toolchains=(),
    )
    evidence = Evidence("tests", "unit", make_digest("b"), EvidenceStatus.PASSED)
    return PrequalifiedBuild(unsigned, (evidence,))


def make_signed_build() -> SignedBuild:
    return SignedBuild(
        make_prequalified_build(),
        make_signature_artifact(),
        SigningDisposition.SIGNED,
    )


def make_envelope_bundle() -> EnvelopeBundle:
    envelope = make_build_envelope()
    qualification = make_qualification_record(envelope)
    return EnvelopeBundle(QualifiedEnvelope(envelope, qualification), (), ())


def make_build_envelope() -> BuildEnvelope:
    canonical_bytes = b"envelope"
    return BuildEnvelope(
        make_signed_build(),
        object(),
        canonical_bytes,
        Sha256Digest.from_bytes(canonical_bytes),
    )


def make_qualification_record(envelope: BuildEnvelope) -> QualificationRecord:
    canonical_bytes = b"qualification"
    return QualificationRecord(
        envelope.content_sha256,
        object(),
        canonical_bytes,
        Sha256Digest.from_bytes(canonical_bytes),
    )


def make_conflicting_bundle(bundle: EnvelopeBundle) -> EnvelopeBundle:
    canonical_bytes = b"different-qualification"
    qualification = QualificationRecord(
        bundle.qualified.envelope.content_sha256,
        object(),
        canonical_bytes,
        Sha256Digest.from_bytes(canonical_bytes),
    )
    qualified = QualifiedEnvelope(bundle.qualified.envelope, qualification)
    return EnvelopeBundle(qualified, (), ())


async def test_should_preserve_exact_artifacts_when_build_advances_to_signed() -> None:
    # Given
    prequalified = make_prequalified_build()
    signer = FakeSigner(signature=make_signature_artifact())

    # When
    signed = await signer.sign(prequalified, SigningPolicy.required("assay-ed25519-v1"))

    # Then
    assert isinstance(signer, Signer)
    assert signed.prequalified is prequalified
    assert signed.signature is not None
    assert signed.signature.path.value == "signatures/catalog.ed25519"
    assert signed.disposition is SigningDisposition.SIGNED


async def test_should_record_explicit_disposition_when_signing_is_not_required() -> None:
    # Given
    prequalified = make_prequalified_build()
    signer = FakeSigner(signature=make_signature_artifact())

    # When
    signed: SignedBuild = await signer.sign(prequalified, SigningPolicy.none())

    # Then
    assert signed.prequalified is prequalified
    assert signed.signature is None
    assert signed.disposition is SigningDisposition.SIGNING_NOT_REQUIRED


async def test_should_retain_exact_bundle_when_fake_store_persists() -> None:
    # Given
    bundle = make_envelope_bundle()
    store = FakeArtifactStore()

    # When
    stored = await store.persist(bundle, "attempt-1")
    observed = await store.inspect(stored.reference, "attempt-2")
    restored = await store.restore(stored.reference, "attempt-2")

    # Then
    assert observed == stored
    assert restored is bundle
    assert store.observation_count == EXPECTED_STORE_OBSERVATIONS
    assert store.write_count == 1


async def test_should_reject_conflicting_content_tag_when_fake_store_persists() -> None:
    # Given
    bundle = make_envelope_bundle()
    store = FakeArtifactStore()
    await store.persist(bundle, "attempt-1")

    # When / Then
    with pytest.raises(ValueError, match="conflicting bytes"):
        await store.persist(make_conflicting_bundle(bundle), "attempt-3")


@pytest.mark.parametrize(
    "factory",
    (
        lambda: InputSnapshotPlan(cast(tuple[str, ...], ["src"]), (), ()),
        lambda: BuildPlan("build", cast(tuple[str, ...], ["pytest"])),
        lambda: VerificationPlan(cast(tuple[str, ...], ["unit"])),
    ),
)
def test_should_reject_mutable_stage_plan_fields_when_plans_are_created(
    factory: Callable[[], object],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        factory()


def test_should_reject_missing_signing_key_when_policy_requires_one() -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        SigningPolicy.required(" ")


@pytest.mark.parametrize(
    "signed_build",
    (
        lambda: SignedBuild(make_prequalified_build(), None, SigningDisposition.SIGNED),
        lambda: SignedBuild(
            make_prequalified_build(),
            make_signature_artifact(),
            SigningDisposition.SIGNING_NOT_REQUIRED,
        ),
    ),
)
def test_should_reject_incoherent_signature_state_when_signed_build_is_created(
    signed_build: Callable[[], SignedBuild],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        signed_build()


def test_should_reject_forged_stage_records_when_unsigned_build_is_created() -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        UnsignedBuild(cast(SnapshottedSource, None), (), (), (), ())


def test_should_reject_invalid_oci_and_oras_boundary_values_when_records_are_created() -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        OciReference("memory.local/catalog", "latest", cast(Sha256Digest, "sha256:forged"))
    with pytest.raises(InvalidIdentity):
        OrasInvocation(("oras",), cast(tuple[bytes, ...], [b"payload"]))
    with pytest.raises(InvalidIdentity):
        OrasResult(True, OrasOutcome.FAILURE, b"", b"")


@pytest.mark.parametrize(
    "factory",
    (
        lambda: OrasResult(0, cast(OrasOutcome, "success"), b"", b""),
        lambda: OrasResult(1, OrasOutcome.SUCCESS, b"", b""),
        lambda: OrasResult(0, OrasOutcome.NOT_FOUND, b"", b""),
        lambda: OrasResult(0, OrasOutcome.SUCCESS, b"", b"", cast(bytes, "manifest")),
    ),
)
def test_should_reject_incoherent_oras_result_when_record_is_created(
    factory: Callable[[], OrasResult],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        factory()


def test_should_keep_process_and_exported_bytes_distinct_when_oras_succeeds() -> None:
    # Given / When
    result = OrasResult(0, OrasOutcome.SUCCESS, b"progress", b"", b"manifest")

    # Then
    assert result.stdout == b"progress"
    assert result.exported_file_bytes == b"manifest"


def test_should_keep_exact_stage_bytes_when_envelope_bundle_is_created() -> None:
    # Given
    bundle = make_envelope_bundle()

    # When
    envelope_bytes = bundle.qualified.envelope.canonical_bytes
    qualification_bytes = bundle.qualified.qualification.canonical_bytes

    # Then
    assert envelope_bytes == b"envelope"
    assert qualification_bytes == b"qualification"


@pytest.mark.parametrize(
    "factory",
    (
        lambda: BuildEnvelope(
            make_signed_build(),
            object(),
            cast(bytes, "envelope"),
            Sha256Digest.from_bytes(b"envelope"),
        ),
        lambda: QualificationRecord(
            make_digest("a"),
            object(),
            cast(bytes, "qualification"),
            Sha256Digest.from_bytes(b"qualification"),
        ),
    ),
)
def test_should_reject_nonbyte_canonical_content_when_stage_record_is_created(
    factory: Callable[[], object],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        factory()


@pytest.mark.parametrize(
    "factory",
    (
        lambda: BuildEnvelope(make_signed_build(), object(), b"envelope", make_digest("a")),
        lambda: QualificationRecord(
            make_digest("a"),
            object(),
            b"qualification",
            make_digest("b"),
        ),
    ),
)
def test_should_reject_digest_that_does_not_match_canonical_content_when_stage_record_is_created(
    factory: Callable[[], object],
) -> None:
    # Given / When / Then
    with pytest.raises(InvalidIdentity):
        factory()


@pytest.mark.parametrize(
    "qualification",
    (
        lambda: QualificationRecord(
            make_digest("f"),
            object(),
            b"qualification",
            Sha256Digest.from_bytes(b"qualification"),
        ),
        lambda: cast(QualificationRecord, object()),
    ),
)
def test_should_reject_invalid_qualification_when_envelope_is_qualified(
    qualification: Callable[[], QualificationRecord],
) -> None:
    # Given
    envelope = make_build_envelope()

    # When / Then
    with pytest.raises(InvalidIdentity):
        QualifiedEnvelope(envelope, qualification())


@pytest.mark.parametrize(
    "release_id",
    (
        lambda: ReleaseId(ProjectId("other"), "v0.1.0", make_digest("c"), "catalog-v0.1.0"),
        lambda: ReleaseId(ProjectId("catalog"), "v0.1.0", make_digest("f"), "catalog-v0.1.0"),
    ),
)
def test_should_reject_release_identity_that_disagrees_with_revision_when_release_source_is_created(
    release_id: Callable[[], ReleaseId],
) -> None:
    # Given
    revision = make_snapshotted_source().release.revision

    # When / Then
    with pytest.raises(InvalidIdentity):
        ReleaseSource(release_id(), revision)
