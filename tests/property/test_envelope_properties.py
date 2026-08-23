import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from portfolio_delivery.domain.artifacts import Artifact, Evidence, EvidenceStatus
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)
from portfolio_delivery.domain.stages import (
    PrequalifiedBuild,
    ReleaseSource,
    SignedBuild,
    SigningDisposition,
    SnapshottedSource,
    UnsignedBuild,
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
from portfolio_delivery.envelope.canonical import canonical_sha256, normalize_artifact_path
from portfolio_delivery.envelope.documents import ArtifactDocument, BuildEnvelopeDocument

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "envelope"
GOLDEN_DIGEST = "sha256:a232a04be6fbf1942f6c3a5b77bb7213ed8cad1ed09d5df4335667f18752cd8c"


def fixture_bytes(relative_path: str) -> bytes:
    return (FIXTURE_ROOT / relative_path).read_bytes()


def make_build_document(artifacts: tuple[ArtifactDocument, ...]) -> BuildEnvelopeDocument:
    payload = json.loads(fixture_bytes("input/build-input.json"))
    payload["artifacts"] = [item.model_dump(by_alias=True) for item in artifacts]
    return BuildEnvelopeDocument.model_validate(payload)


def make_three_artifacts() -> tuple[ArtifactDocument, ...]:
    payload = json.loads(fixture_bytes("input/build-input.json"))
    return tuple(ArtifactDocument.model_validate(item) for item in payload["artifacts"])


@given(st.permutations(make_three_artifacts()))
def test_should_keep_digest_when_artifact_order_changes(
    artifacts: tuple[ArtifactDocument, ...],
) -> None:
    # Given
    document = make_build_document(artifacts)
    expected = GOLDEN_DIGEST

    # When
    digest = canonical_sha256(document)

    # Then
    assert digest.value == expected


@given(st.characters(blacklist_characters="/\\\x00", min_codepoint=0x80))
def test_should_preserve_unicode_path_when_path_is_canonical(character: str) -> None:
    # Given
    raw_path = f"artifacts/{character}.txt"

    # When
    normalized = normalize_artifact_path(raw_path)

    # Then
    assert normalized.value == raw_path


@given(st.integers(min_value=0, max_value=63))
def test_should_change_digest_when_one_artifact_digest_character_changes(index: int) -> None:
    # Given
    artifacts = list(make_three_artifacts())
    original = artifacts[0]
    replacement = "2" if original.sha256[index + 7] != "2" else "3"
    changed = original.sha256[: index + 7] + replacement + original.sha256[index + 8 :]
    artifacts[0] = original.model_copy(update={"sha256": changed})

    # When
    digest = canonical_sha256(make_build_document(tuple(artifacts)))

    # Then
    assert digest.value != GOLDEN_DIGEST


@pytest.mark.parametrize(
    "field_name",
    ("runId", "timestamp", "traceId", "provider", "attestation", "deployment", "liveCheck"),
)
def test_should_reject_delivery_field_when_document_is_parsed(field_name: str) -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    payload[field_name] = "forbidden"

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_duplicate_sbom_subject_when_document_is_parsed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    sboms = cast(list[dict[str, object]], payload["sboms"])
    duplicate = dict(sboms[0])
    duplicate["path"] = "sbom/package-copy.cdx.json"
    sboms.append(duplicate)

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_match_hand_calculated_golden_digest_when_fixture_is_hashed() -> None:
    # Given
    expected_bytes = fixture_bytes("expected/build-envelope.v1.json")
    expected = GOLDEN_DIGEST

    # When
    digest = "sha256:" + hashlib.sha256(expected_bytes).hexdigest()

    # Then
    assert digest == expected


@given(st.sampled_from(("catalog", "catalog-next", "catalog-final")))
def test_should_change_envelope_digest_when_signed_artifact_name_changes(name: str) -> None:
    # Given
    first = make_signed_build("catalog")
    second = make_signed_build(name)

    # When
    first_digest = EnvelopeBuilder(make_metadata()).build(first).content_sha256
    second_digest = EnvelopeBuilder(make_metadata()).build(second).content_sha256

    # Then
    assert (first_digest == second_digest) is (name == "catalog")


@given(st.sampled_from((EvidenceStatus.PASSED, EvidenceStatus.FAILED)))
def test_should_keep_envelope_digest_when_final_check_status_changes(
    status: EvidenceStatus,
) -> None:
    # Given
    envelope = EnvelopeBuilder(make_metadata()).build(make_signed_build("catalog"))
    check = Evidence("archive", "manifest", envelope.content_sha256, status)

    # When
    qualification = QualificationBuilder().build(envelope, (check,))

    # Then
    assert qualification.subject == envelope.content_sha256
    assert qualification.content_sha256 != envelope.content_sha256


def make_signed_build(name: str) -> SignedBuild:
    project = ProjectId("catalog")
    digest = Sha256Digest("sha256:" + ("a" * 64))
    revision = SourceRevision(project, "hseshadr/catalog", "refs/heads/main", "b" * 40, digest)
    release = ReleaseSource(ReleaseId(project, "v1.2.3", digest, "catalog-v1.2.3"), revision)
    snapshot = SnapshottedSource(release, Sha256Digest("sha256:" + ("c" * 64)))
    artifact = Artifact(
        name,
        ArtifactPath(f"artifacts/{name}.whl"),
        "application/zip",
        5,
        Sha256Digest("sha256:" + ("d" * 64)),
    )
    evidence = Evidence("test", "unit", Sha256Digest("sha256:" + ("e" * 64)), EvidenceStatus.PASSED)
    unsigned = UnsignedBuild(snapshot, (artifact,), (), (), ())
    prequalified = PrequalifiedBuild(unsigned, (evidence,))
    return SignedBuild(prequalified, None, SigningDisposition.SIGNING_NOT_REQUIRED)


def make_metadata() -> EnvelopeMetadata:
    return EnvelopeMetadata(
        ProjectAdapterVersion("1.0.0"),
        1_724_472_000,
        ReleasePolicyMetadata("v1.2.3", (ReleaseChannel.STABLE,)),
        PinnedCompatibility("0.21.8", "1.3.3"),
    )
