"""Canonical serialization and parsing for delivery boundary documents."""

from __future__ import annotations

import json
from math import isfinite
from typing import Final, cast

from pydantic import BaseModel

from portfolio_delivery.domain.errors import diagnostic_error
from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]

MAX_JSON_BYTES: Final = 1_048_576
_JSON_OBJECT_MESSAGE = "JSON content must be an object"  # pragma: no mutate - diagnostic text
_JSON_LIMIT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "JSON limit must be a positive integer"
)
_JSON_SIZE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "JSON content exceeds its configured byte limit"
)
_DUPLICATE_KEY_TEMPLATE = (  # pragma: no mutate - non-contractual diagnostic text
    "duplicate JSON key is forbidden: {key}"
)
_NONFINITE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "non-finite JSON number is forbidden"
)


def canonical_json_bytes(model: BaseModel) -> bytes:
    """Serialize a boundary model into its canonical UTF-8 representation."""

    payload = model.model_dump(mode="json", round_trip=True, by_alias=True)
    text = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return f"{text}\n".encode()


def canonical_sha256(model: BaseModel) -> Sha256Digest:
    """Return the SHA-256 identity for a canonical boundary document."""

    return Sha256Digest.from_bytes(canonical_json_bytes(model))


def normalize_artifact_path(raw: str) -> ArtifactPath:
    """Validate a canonical relative POSIX artifact path."""

    return ArtifactPath(raw)


def parse_bounded_json(content: bytes, limit: int) -> JsonObject:
    """Parse one bounded JSON object while rejecting non-finite numbers."""

    _validate_json_limit(content, limit)
    value = _parse_json_value(content)
    if not isinstance(value, dict):
        raise diagnostic_error(ValueError, _JSON_OBJECT_MESSAGE)
    _reject_nonfinite_value(value)
    return value


def _validate_json_limit(content: bytes, limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise diagnostic_error(ValueError, _JSON_LIMIT_MESSAGE)
    if len(content) > min(limit, MAX_JSON_BYTES):
        raise diagnostic_error(ValueError, _JSON_SIZE_MESSAGE)


def _parse_json_value(content: bytes) -> JsonValue:
    text = content.decode("utf-8")  # pragma: no mutate - UTF-8 aliases are equivalent
    parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    return cast(JsonValue, parsed)  # pragma: no mutate - runtime-neutral cast


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            _diagnostic_message = _DUPLICATE_KEY_TEMPLATE.format(key=key)  # pragma: no mutate
            raise diagnostic_error(ValueError, _diagnostic_message)
        result[key] = value
    return result


def _reject_nonfinite_value(value: JsonValue) -> None:
    pending = [value]
    for current in pending:
        _reject_nonfinite_float(current)
        pending.extend(_nested_values(current))


def _reject_nonfinite_float(value: JsonValue) -> None:
    if isinstance(value, float) and not isfinite(value):
        raise diagnostic_error(ValueError, _NONFINITE_MESSAGE)


def _nested_values(value: JsonValue) -> list[JsonValue]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []
