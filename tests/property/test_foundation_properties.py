"""Phase 1 safety properties across canonical assembly and persistence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from copy import deepcopy
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Final, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, ConfigDict, Field, Json, ValidationError

import portfolio_delivery.domain.stages as stage_contracts
import portfolio_delivery.envelope.builder as builder_contracts
import portfolio_delivery.envelope.canonical as canonical_contracts
from portfolio_delivery.adapters.oras import (
    ArtifactConflict,
    MalformedProviderResponse,
    ProviderUnavailable,
)
from portfolio_delivery.domain.artifacts import Artifact, Evidence, EvidenceStatus
from portfolio_delivery.domain.errors import InvalidIdentity, diagnostic_error
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)
from portfolio_delivery.domain.stages import (
    EnvelopeBundle,
    PrequalifiedBuild,
    QualifiedEnvelope,
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
from portfolio_delivery.envelope.canonical import canonical_json_bytes, parse_bounded_json
from portfolio_delivery.envelope.documents import BuildEnvelopeDocument
from tests.fakes.storage import FakeArtifactStore

FIXTURE: Final = Path(__file__).parents[1] / "fixtures/envelope/input/build-input.json"
SOURCE_DATE_EPOCH: Final[int] = 1_724_472_000
FORBIDDEN_DELIVERY_KEYS: Final = frozenset(
    {"runId", "timestamp", "traceId", "provider", "attestation", "deployment", "liveCheck"}
)
NESTED_RECORD_PATHS: Final = (
    ("source",),
    ("artifacts", 0),
    ("sboms", 0),
    ("prequalificationEvidence", 0),
    ("releasePolicy",),
    ("compatibility",),
)


def _metadata() -> EnvelopeMetadata:
    return EnvelopeMetadata(
        ProjectAdapterVersion("1.0.0"),
        SOURCE_DATE_EPOCH,
        ReleasePolicyMetadata("v1.2.3", (ReleaseChannel.STABLE,)),
        PinnedCompatibility("0.21.8", "1.3.3"),
    )


def _source() -> SnapshottedSource:
    project = ProjectId("portfolio-delivery")
    digest = Sha256Digest.from_bytes(b"source-tree")
    revision = SourceRevision(
        project, "hseshadr/portfolio-delivery", "refs/heads/main", "b" * 40, digest
    )
    release_id = ReleaseId(project, "v1.2.3", digest, "portfolio-delivery-v1.2.3")
    snapshot_digest = Sha256Digest.from_bytes(b"snapshot")
    return SnapshottedSource(ReleaseSource(release_id, revision), snapshot_digest)


def _signed_build(content: bytes) -> SignedBuild:
    artifact = Artifact(
        "package",
        ArtifactPath("artifacts/portfolio_delivery-0.1.0-py3-none-any.whl"),
        "application/zip",
        len(content),
        Sha256Digest.from_bytes(content),
    )
    unsigned = UnsignedBuild(_source(), (artifact,), (), (), ())
    check = Evidence("test", "unit", unsigned.source.input_snapshot_sha256, EvidenceStatus.PASSED)
    return SignedBuild(
        PrequalifiedBuild(unsigned, (check,)),
        None,
        SigningDisposition.SIGNING_NOT_REQUIRED,
    )


def _qualified_bundle(content: bytes, checks: tuple[str, ...] = ("archive",)) -> EnvelopeBundle:
    envelope = EnvelopeBuilder(_metadata()).build(_signed_build(content))
    evidence = tuple(
        Evidence("final", name, envelope.content_sha256, EvidenceStatus.PASSED) for name in checks
    )
    qualification = QualificationBuilder().build(envelope, evidence)
    artifact = envelope.signed.prequalified.unsigned.artifacts
    return EnvelopeBundle(QualifiedEnvelope(envelope, qualification), artifact, ())


def _fixture_payload() -> dict[str, object]:
    return cast(dict[str, object], json.loads(FIXTURE.read_bytes()))


def _nested_record(payload: dict[str, object], path: tuple[str | int, ...]) -> dict[str, object]:
    current: object = payload
    for component in path:
        if isinstance(component, int):
            current = cast(list[object], current)[component]
        else:
            current = cast(dict[str, object], current)[component]
    return cast(dict[str, object], current)


def _recursive_keys(value: object) -> frozenset[str]:
    if isinstance(value, dict):
        nested = (_recursive_keys(item) for item in value.values())
        return frozenset(value).union(*nested)
    if isinstance(value, (list, tuple)):
        return frozenset().union(*(_recursive_keys(item) for item in value))
    return frozenset()


def _stdlib_canonical(document: BuildEnvelopeDocument) -> bytes:
    payload = document.model_dump(by_alias=True, mode="json")
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return (text + "\n").encode()


@given(st.binary(min_size=1, max_size=128))
def test_should_emit_identical_canonical_bytes_for_same_inputs(content: bytes) -> None:
    # Given
    first = _signed_build(content)
    second = _signed_build(bytes(content))

    # When
    first_envelope = EnvelopeBuilder(_metadata()).build(first)
    second_envelope = EnvelopeBuilder(_metadata()).build(second)

    # Then
    first_document = cast(BuildEnvelopeDocument, first_envelope.document)
    expected = _stdlib_canonical(first_document)
    assert first_envelope.canonical_bytes == second_envelope.canonical_bytes == expected
    assert first_envelope.content_sha256.hex == hashlib.sha256(expected).hexdigest()


@given(st.binary(min_size=1, max_size=128))
def test_should_change_envelope_digest_when_artifact_bytes_change(content: bytes) -> None:
    # Given
    changed = content + b"\x00"

    # When
    original = EnvelopeBuilder(_metadata()).build(_signed_build(content))
    modified = EnvelopeBuilder(_metadata()).build(_signed_build(changed))

    # Then
    original_document = cast(BuildEnvelopeDocument, original.document)
    modified_document = cast(BuildEnvelopeDocument, modified.document)
    assert original_document.artifacts[0].sha256 == "sha256:" + hashlib.sha256(content).hexdigest()
    assert modified_document.artifacts[0].sha256 == "sha256:" + hashlib.sha256(changed).hexdigest()
    assert original.content_sha256 != modified.content_sha256


@given(st.permutations(("archive", "policy", "provenance")))
def test_should_keep_envelope_digest_when_final_checks_are_permuted(
    checks: tuple[str, ...],
) -> None:
    # Given
    bundle = _qualified_bundle(b"wheel", checks)
    reversed_bundle = _qualified_bundle(b"wheel", tuple(reversed(checks)))

    # When
    first = bundle.qualified
    second = reversed_bundle.qualified

    # Then
    assert first.envelope.content_sha256 == second.envelope.content_sha256
    assert first.qualification.canonical_bytes == second.qualification.canonical_bytes


@pytest.mark.asyncio
@given(st.binary(min_size=1, max_size=128))
async def test_should_converge_ten_persistence_attempts_on_one_manifest(content: bytes) -> None:
    # Given
    store = FakeArtifactStore()
    bundle = _qualified_bundle(content)

    # When
    stored = [await store.persist(bundle, f"attempt-{index}") for index in range(10)]

    # Then
    payload = (
        bundle.qualified.envelope.canonical_bytes + bundle.qualified.qualification.canonical_bytes
    )
    expected = "sha256:" + hashlib.sha256(payload).hexdigest()
    assert {item.manifest_sha256.value for item in stored} == {expected}
    assert store.write_count == 1


@given(
    st.sampled_from(("path", "digest", "document", "json")),
    st.sampled_from(("../escape.whl", "/absolute.whl", "artifacts//package.whl")),
)
def test_should_fail_closed_for_malformed_boundary_input(kind: str, malformed_path: str) -> None:
    # Given
    payload = _fixture_payload()
    artifact = cast(list[dict[str, object]], payload["artifacts"])[0]
    malformed = _malformed_document(payload, artifact, kind, malformed_path)

    # When / Then
    with pytest.raises((ValidationError, ValueError)):
        _parse_document(malformed, kind)


def _malformed_document(
    payload: dict[str, object], artifact: dict[str, object], kind: str, malformed_path: str
) -> bytes:
    if kind == "path":
        artifact["path"] = malformed_path
    if kind == "digest":
        artifact["sha256"] = "sha256:" + "A" * 64
    if kind == "document":
        payload["provider"] = "github"
    if kind == "json":
        return b'{"schemaVersion":"v1","schemaVersion":"v1"}'
    return json.dumps(payload).encode()


def _parse_document(content: bytes, kind: str) -> BuildEnvelopeDocument:
    parsed = parse_bounded_json(content, 4_194_304)
    if kind == "json":
        raise AssertionError("duplicate keys must fail before document validation")
    return BuildEnvelopeDocument.model_validate(parsed)


@given(
    st.sampled_from(tuple(FORBIDDEN_DELIVERY_KEYS)),
    st.sampled_from(NESTED_RECORD_PATHS),
)
def test_should_reject_forbidden_delivery_fact_at_any_document_depth(
    key: str, path: tuple[str | int, ...]
) -> None:
    # Given
    payload = deepcopy(_fixture_payload())
    _nested_record(payload, path)[key] = "forbidden"

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


@given(st.binary(min_size=1, max_size=128))
def test_should_contain_no_forbidden_delivery_facts_recursively(content: bytes) -> None:
    # Given
    envelope = EnvelopeBuilder(_metadata()).build(_signed_build(content))

    # When
    document = cast(BuildEnvelopeDocument, envelope.document)
    keys = _recursive_keys(document.model_dump(by_alias=True, mode="json"))

    # Then
    assert keys.isdisjoint(FORBIDDEN_DELIVERY_KEYS)


JSON_SCALARS: Final = (
    st.none() | st.booleans() | st.integers(min_value=-100, max_value=100) | st.text(max_size=16)
)
JSON_VALUES: Final = st.recursive(
    JSON_SCALARS,
    lambda children: (
        st.lists(children, max_size=4)
        | st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=4)
    ),
    max_leaves=16,
)


class CanonicalProbe(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(populate_by_name=True)
    label: str = Field(alias="wireLabel")
    released: date
    payload: Json[list[int]]


class NonfiniteProbe(BaseModel):  # type: ignore[explicit-any]
    value: float


@given(st.dictionaries(st.text(min_size=1, max_size=8), JSON_VALUES, max_size=4))
def test_should_terminate_while_validating_nested_finite_json(document: dict[str, object]) -> None:
    # Given
    content = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()

    # When
    parsed = parse_bounded_json(content, 4_194_304)

    # Then
    assert parsed == document


def test_should_apply_every_canonical_json_option() -> None:
    # Given
    probe = CanonicalProbe.model_validate(
        {"label": "café", "released": date(2026, 8, 23), "payload": "[1,2]"}
    )

    # When
    content = canonical_json_bytes(probe)

    # Then
    assert content == (b'{"payload":"[1,2]","released":"2026-08-23","wireLabel":"caf\xc3\xa9"}\n')


def test_should_reject_nonfinite_value_during_canonical_serialization() -> None:
    # Given
    probe = NonfiniteProbe(value=float("nan"))

    # When / Then
    with pytest.raises(ValueError):
        canonical_json_bytes(probe)


def test_should_pass_exact_canonical_options_to_stdlib_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    actual_dumps = json.dumps
    observed: dict[str, object] = {}

    def recording_dumps(
        payload: object,
        *,
        sort_keys: bool,
        separators: tuple[str, str],
        ensure_ascii: bool,
        allow_nan: bool,
    ) -> str:
        observed.update(ensure_ascii=ensure_ascii, allow_nan=allow_nan)
        return actual_dumps(
            payload,
            sort_keys=sort_keys,
            separators=separators,
            ensure_ascii=ensure_ascii,
            allow_nan=allow_nan,
        )

    monkeypatch.setattr(canonical_contracts, "json", SimpleNamespace(dumps=recording_dumps))

    # When
    canonical_json_bytes(NonfiniteProbe(value=1.0))

    # Then
    assert observed["ensure_ascii"] is False
    assert observed["allow_nan"] is False


@pytest.mark.parametrize("invalid_limit", (True, 0, -1, cast(int, "1"), cast(int, 1.5)))
def test_should_reject_every_invalid_json_limit(invalid_limit: int) -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(b"{}", invalid_limit)


def test_should_accept_exact_minimum_json_limit_and_source_epoch() -> None:
    # Given / When / Then
    canonical_contracts._validate_json_limit(b"x", 1)
    builder_contracts._validate_source_date_epoch(1)


@pytest.mark.parametrize("content", (b"[]", b"null", b'"text"', b"1"))
def test_should_reject_nonobject_json_documents(content: bytes) -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(content, 64)


@pytest.mark.parametrize("constant", (b"NaN", b"Infinity", b"-Infinity"))
def test_should_reject_every_nonfinite_json_constant(constant: bytes) -> None:
    # Given
    content = b'{"value":' + constant + b"}"

    # When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(content, 64)


def test_should_reject_duplicate_json_keys_with_value_error() -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(b'{"key":1,"key":2}', 64)


def test_should_enforce_json_content_and_global_size_bounds() -> None:
    # Given
    oversized = b"{" + b" " * canonical_contracts.MAX_JSON_BYTES + b"}"

    # When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(b"{}", 1)
    with pytest.raises(ValueError):
        parse_bounded_json(oversized, len(oversized))


@pytest.mark.parametrize("invalid", (cast(str, None), "", " leading", "trailing "))
def test_should_reject_every_noncanonical_artifact_text(invalid: str) -> None:
    # Given
    digest = Sha256Digest.from_bytes(b"artifact")

    # When / Then
    with pytest.raises(InvalidIdentity):
        Artifact("package", ArtifactPath("dist/package.whl"), invalid, 1, digest)


@pytest.mark.parametrize("invalid", (cast(int, "1"), True, -1))
def test_should_reject_every_invalid_artifact_size(invalid: int) -> None:
    # Given
    digest = Sha256Digest.from_bytes(b"artifact")

    # When / Then
    with pytest.raises(InvalidIdentity):
        Artifact("package", ArtifactPath("dist/package.whl"), "application/zip", invalid, digest)


def test_should_accept_zero_byte_artifact() -> None:
    # Given
    digest = Sha256Digest.from_bytes(b"")

    # When
    artifact = Artifact("empty", ArtifactPath("dist/empty.whl"), "application/zip", 0, digest)

    # Then
    assert artifact.size == 0


@pytest.mark.parametrize(
    "invalid", (cast(str, None), "", "/absolute", "a//b", "a/./b", "a/../b", "a\\b", "a\0b")
)
def test_should_reject_every_unsafe_artifact_path(invalid: str) -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        ArtifactPath(invalid)


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("source", object()),
        ("artifacts", (object(),)),
        ("sboms", (object(),)),
        ("locks", (object(),)),
        ("toolchains", (object(),)),
    ),
)
def test_should_reject_invalid_unsigned_build_component(field: str, invalid: object) -> None:
    # Given
    values: dict[str, object] = {
        "source": _source(),
        "artifacts": (),
        "sboms": (),
        "locks": (),
        "toolchains": (),
    }
    values[field] = invalid
    build = cast(UnsignedBuild, SimpleNamespace(**values))

    # When / Then
    with pytest.raises(InvalidIdentity):
        stage_contracts._validate_unsigned_build(build)


@pytest.mark.parametrize(
    "operation",
    (
        lambda: stage_contracts._require_tuple([], str, "tuple diagnostic"),
        lambda: stage_contracts._validate_prequalified_build(object()),
        lambda: stage_contracts._validate_signing_disposition(object()),
        lambda: stage_contracts._validate_oras_process_output("stdout", b""),
        lambda: stage_contracts._validate_oras_process_output(b"", "stderr"),
        lambda: stage_contracts._validate_oras_export("export", True),
        lambda: stage_contracts._validate_oras_export(b"export", False),
    ),
)
def test_should_reject_invalid_stage_component(operation: object) -> None:
    # Given
    invoke = cast(Callable[[], None], operation)

    # When / Then
    with pytest.raises(InvalidIdentity):
        invoke()


def test_should_reject_mismatched_release_source_identities() -> None:
    # Given
    release = _source().release.release_id
    revision = SourceRevision(
        release.project,
        "hseshadr/portfolio-delivery",
        "refs/heads/main",
        "c" * 40,
        Sha256Digest.from_bytes(b"different"),
    )

    # When / Then
    assert not stage_contracts._has_release_source_identities(release, revision)
    assert not stage_contracts._has_release_source_identities(object(), revision)
    assert not stage_contracts._has_release_source_identities(release, object())


def test_should_reject_qualification_checks_that_do_not_target_envelope() -> None:
    # Given
    envelope = _qualified_bundle(b"wheel").qualified.envelope
    wrong = Evidence("final", "wrong", Sha256Digest.from_bytes(b"wrong"), EvidenceStatus.PASSED)

    # When / Then
    with pytest.raises(InvalidIdentity):
        builder_contracts._require_envelope_subjects(envelope, [])
    with pytest.raises(InvalidIdentity):
        builder_contracts._require_envelope_subjects(envelope, (wrong,))


@pytest.mark.parametrize(
    "operation",
    (
        lambda: builder_contracts._require_evidence_checks([]),
        lambda: builder_contracts._require_evidence_checks((object(),)),
        lambda: builder_contracts._validate_source_date_epoch(True),
        lambda: builder_contracts._validate_source_date_epoch(cast(int, "1")),
        lambda: builder_contracts._validate_source_date_epoch(0),
        lambda: builder_contracts._require_contract_type(object(), EnvelopeMetadata),
        lambda: builder_contracts._require_semver(cast(str, None), "version"),
        lambda: builder_contracts._require_semver("not-semver", "version"),
        lambda: builder_contracts._require_semver("1.0.0-todo", "version"),
        lambda: builder_contracts._require_release_version(cast(str, None)),
        lambda: builder_contracts._require_release_version("1.0.0"),
        lambda: builder_contracts._require_release_version("vnot-semver"),
        lambda: builder_contracts._declared_release_channels([]),
        lambda: builder_contracts._declared_release_channels((object(),)),
        lambda: builder_contracts._require_nonempty_channels(()),
        lambda: builder_contracts._require_unique_channels(
            (ReleaseChannel.STABLE, ReleaseChannel.STABLE)
        ),
        lambda: builder_contracts._require_exact_pin("wrong", "expected", "tool"),
    ),
)
def test_should_reject_invalid_builder_contract(operation: object) -> None:
    # Given
    invoke = cast(Callable[[], None], operation)

    # When / Then
    with pytest.raises(InvalidIdentity):
        invoke()


@pytest.mark.parametrize(
    "error_type",
    (ValueError, InvalidIdentity, ProviderUnavailable, MalformedProviderResponse, ArtifactConflict),
)
@given(st.text(min_size=1))
def test_should_preserve_arbitrary_diagnostic_text(
    error_type: type[Exception], message: str
) -> None:
    # Given / When
    error = diagnostic_error(error_type, message)

    # Then
    assert type(error) is error_type
    assert error.args == (message,)


@pytest.mark.parametrize("invalid_message", (None, "", b"bytes", 1))
def test_should_fail_closed_for_invalid_diagnostic_text(invalid_message: object) -> None:
    # Given / When / Then
    with pytest.raises(TypeError):
        diagnostic_error(InvalidIdentity, cast(str, invalid_message))


@pytest.mark.parametrize(
    "invalid_type", (str, object, Exception, BaseException, None, ValueError("instance"))
)
def test_should_fail_closed_for_invalid_diagnostic_exception_type(
    invalid_type: object,
) -> None:
    # Given / When / Then
    with pytest.raises(TypeError):
        diagnostic_error(cast(type[Exception], invalid_type), "diagnostic")
