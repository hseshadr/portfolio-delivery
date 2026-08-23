import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from portfolio_delivery.envelope.canonical import canonical_json_bytes, parse_bounded_json
from portfolio_delivery.envelope.documents import (
    BuildEnvelopeDocument,
    QualificationRecordDocument,
)

FIXTURE_ROOT = Path(__file__).parents[2] / "fixtures" / "envelope"


def fixture_bytes(relative_path: str) -> bytes:
    return (FIXTURE_ROOT / relative_path).read_bytes()


def make_build_document_with_reversed_collections() -> BuildEnvelopeDocument:
    payload = json.loads(fixture_bytes("input/build-input.json"))
    payload["artifacts"].reverse()
    return BuildEnvelopeDocument.model_validate(payload)


def test_should_match_golden_bytes_when_input_order_differs() -> None:
    # Given
    document = make_build_document_with_reversed_collections()
    expected = fixture_bytes("expected/build-envelope.v1.json")

    # When
    actual = canonical_json_bytes(document)

    # Then
    assert actual == expected


def test_should_reject_noncanonical_commit_when_source_is_parsed() -> None:
    # Given
    payload = json.loads(fixture_bytes("input/build-input.json"))
    payload["source"]["commitSha"] = "A" * 40

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_boolean_epoch_when_document_is_parsed() -> None:
    # Given
    payload = json.loads(fixture_bytes("input/build-input.json"))
    payload["sourceDateEpoch"] = True

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_content_larger_than_global_limit_when_caller_limit_is_larger() -> None:
    # Given
    content = b'{"value":"' + (b"x" * 1_048_576) + b'"}'

    # When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(content, 2_000_000)


@pytest.mark.parametrize(
    "content",
    (
        b'{"number":NaN}',
        b'{"number":Infinity}',
        b'{"number":-Infinity}',
        b'{"number":1e400}',
        b'{"number":-1e400}',
    ),
)
def test_should_reject_nonfinite_number_when_json_is_parsed(content: bytes) -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(content, 1_048_576)


@pytest.mark.parametrize(
    "content",
    (b'{"key":1,"key":2}', b'{"nested":{"key":1,"key":2}}'),
)
def test_should_reject_duplicate_key_when_json_is_parsed(content: bytes) -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(content, 1_048_576)


def test_should_keep_canonical_bytes_when_every_build_collection_is_reversed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    _add_distinct_build_collection_items(payload)
    reversed_payload = _reverse_build_collections(payload)

    # When
    first = canonical_json_bytes(BuildEnvelopeDocument.model_validate(payload))
    second = canonical_json_bytes(BuildEnvelopeDocument.model_validate(reversed_payload))

    # Then
    assert first == second


def test_should_reject_duplicate_build_ownership_key_when_document_is_parsed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    toolchains = cast(list[dict[str, object]], payload["toolchains"])
    evidence = cast(list[dict[str, object]], payload["prequalificationEvidence"])
    toolchains.append({"name": "python", "version": "3.14", "sha256": _digest("b")})
    evidence.append({"kind": "test", "name": "unit", "subject": _digest("c"), "status": "failed"})

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_duplicate_artifact_path_when_document_is_parsed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    artifacts = cast(list[dict[str, object]], payload["artifacts"])
    artifacts.append(
        {
            "name": "package-copy",
            "path": "artifacts/portfolio_delivery-0.1.0-py3-none-any.whl",
            "mediaType": "application/vnd.python.wheel",
            "size": 35,
            "sha256": _digest("f"),
        }
    )

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_duplicate_sbom_path_when_document_is_parsed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    sboms = cast(list[dict[str, object]], payload["sboms"])
    sboms.append(
        {
            "artifactPath": "artifacts/alpha.txt",
            "path": "sbom/package.cdx.json",
            "mediaType": "application/vnd.cyclonedx+json",
            "sha256": _digest("f"),
        }
    )

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_duplicate_toolchain_name_when_document_is_parsed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    toolchains = cast(list[dict[str, object]], payload["toolchains"])
    toolchains.append({"name": "python", "version": "3.14", "sha256": _digest("b")})

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_duplicate_build_evidence_key_when_document_is_parsed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    evidence = cast(list[dict[str, object]], payload["prequalificationEvidence"])
    evidence.append({"kind": "test", "name": "unit", "subject": _digest("c"), "status": "failed"})

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_reject_duplicate_lock_path_when_document_is_parsed() -> None:
    # Given
    payload = cast(dict[str, object], json.loads(fixture_bytes("input/build-input.json")))
    locks = cast(list[dict[str, object]], payload["locks"])
    locks.append({"path": "uv.lock", "sha256": _digest("d")})

    # When / Then
    with pytest.raises(ValidationError):
        BuildEnvelopeDocument.model_validate(payload)


def test_should_keep_bytes_when_qualification_evidence_is_reversed() -> None:
    # Given
    payload = _qualification_payload()
    reversed_payload = _qualification_payload()
    evidence = cast(list[dict[str, object]], reversed_payload["qualificationEvidence"])
    evidence.reverse()

    # When
    first = canonical_json_bytes(QualificationRecordDocument.model_validate(payload))
    second = canonical_json_bytes(QualificationRecordDocument.model_validate(reversed_payload))

    # Then
    assert first == second


def test_should_reject_duplicate_qualification_evidence_key_when_document_is_parsed() -> None:
    # Given
    payload = _qualification_payload()
    evidence = cast(list[dict[str, object]], payload["qualificationEvidence"])
    evidence.append(
        {"kind": "archive", "name": "manifest", "subject": _digest("e"), "status": "failed"}
    )

    # When / Then
    with pytest.raises(ValidationError):
        QualificationRecordDocument.model_validate(payload)


def test_should_parse_deeply_nested_finite_json_without_recursion_error() -> None:
    # Given
    content = _nested_json(500, b"0")

    # When
    parsed = parse_bounded_json(content, 1_048_576)

    # Then
    assert "nested" in parsed


def test_should_reject_deeply_nested_nonfinite_json_without_recursion_error() -> None:
    # Given
    content = _nested_json(500, b"1e400")

    # When / Then
    with pytest.raises(ValueError):
        parse_bounded_json(content, 1_048_576)


def _add_distinct_build_collection_items(payload: dict[str, object]) -> None:
    locks = cast(list[dict[str, object]], payload["locks"])
    toolchains = cast(list[dict[str, object]], payload["toolchains"])
    sboms = cast(list[dict[str, object]], payload["sboms"])
    evidence = cast(list[dict[str, object]], payload["prequalificationEvidence"])
    locks.append({"path": "poetry.lock", "sha256": _digest("b")})
    toolchains.append({"name": "node", "version": "24.19.0", "sha256": _digest("c")})
    sboms.append(_alpha_sbom())
    evidence.append({"kind": "lint", "name": "ruff", "subject": _digest("d"), "status": "passed"})


def _reverse_build_collections(payload: dict[str, object]) -> dict[str, object]:
    copy = json.loads(json.dumps(payload))
    for name in ("locks", "toolchains", "artifacts", "sboms", "prequalificationEvidence"):
        cast(list[object], copy[name]).reverse()
    return cast(dict[str, object], copy)


def _qualification_payload() -> dict[str, object]:
    return {
        "subject": _digest("a"),
        "qualificationEvidence": [
            {"kind": "lint", "name": "ruff", "subject": _digest("b"), "status": "passed"},
            {"kind": "archive", "name": "manifest", "subject": _digest("c"), "status": "passed"},
        ],
    }


def _alpha_sbom() -> dict[str, object]:
    return {
        "artifactPath": "artifacts/alpha.txt",
        "path": "sbom/alpha.cdx.json",
        "mediaType": "application/vnd.cyclonedx+json",
        "sha256": _digest("e"),
    }


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _nested_json(depth: int, terminal: bytes) -> bytes:
    return (b'{"nested":' * depth) + terminal + (b"}" * depth)
