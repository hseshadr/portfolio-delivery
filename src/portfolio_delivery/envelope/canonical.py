"""Canonical serialization and parsing for delivery boundary documents."""

from __future__ import annotations

import json
from math import isfinite
from typing import Final, cast

from pydantic import BaseModel

from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]

MAX_JSON_BYTES: Final = 1_048_576


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
        raise ValueError("JSON content must be an object")
    _reject_nonfinite_value(value)
    return value


def _validate_json_limit(content: bytes, limit: int) -> None:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("JSON limit must be a positive integer")
    if len(content) > min(limit, MAX_JSON_BYTES):
        raise ValueError("JSON content exceeds its configured byte limit")


def _parse_json_value(content: bytes) -> JsonValue:
    return cast(
        JsonValue,
        json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        ),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, JsonValue]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key is forbidden: {key}")
        result[key] = value
    return result


def _reject_nonfinite_value(value: JsonValue) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        _reject_nonfinite_float(current)
        pending.extend(_nested_values(current))


def _reject_nonfinite_float(value: JsonValue) -> None:
    if isinstance(value, float) and not isfinite(value):
        raise ValueError("non-finite JSON number is forbidden")


def _nested_values(value: JsonValue) -> list[JsonValue]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return list(value.values())
    return []


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")
