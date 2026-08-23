import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from portfolio_delivery.envelope.canonical import canonical_json_bytes, parse_bounded_json
from portfolio_delivery.envelope.documents import BuildEnvelopeDocument

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
