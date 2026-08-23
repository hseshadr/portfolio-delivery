#!/usr/bin/env python3
"""Fail CI unless every generated mutation has a resolved safe outcome."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_STATS_BYTES: Final[int] = 65_536
EXPECTED_ARGUMENT_COUNT: Final[int] = 2
BAD_STATUSES: Final = (
    "survived",
    "no_tests",
    "suspicious",
    "timeout",
    "check_was_interrupted_by_user",
    "segfault",
)


class MutationStats(BaseModel):  # type: ignore[explicit-any]
    """Strict bounded shape exported by mutmut 3.7."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    killed: int = Field(ge=0)
    survived: int = Field(ge=0)
    total: int = Field(ge=1)
    no_tests: int = Field(ge=0)
    skipped: int = Field(ge=0)
    suspicious: int = Field(ge=0)
    timeout: int = Field(ge=0)
    check_was_interrupted_by_user: int = Field(ge=0)
    segfault: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_totals(self) -> MutationStats:
        outcomes = self.killed + sum(getattr(self, name) for name in BAD_STATUSES)
        if outcomes + self.skipped != self.total:
            raise ValueError("mutation outcome counts must equal the total")
        return self


def _load(path: Path) -> MutationStats:
    if path.stat().st_size > MAX_STATS_BYTES:
        raise ValueError("mutation stats exceed the configured byte limit")
    return MutationStats.model_validate_json(path.read_bytes())


def _unresolved(stats: MutationStats) -> tuple[tuple[str, int], ...]:
    return tuple((name, getattr(stats, name)) for name in BAD_STATUSES if getattr(stats, name))


def _success(stats: MutationStats) -> None:
    document = json.dumps({"killed": stats.killed, "total": stats.total}, sort_keys=True)
    sys.stdout.write(document + "\n")


def main() -> None:
    """Validate one exported stats document and use process status as the CI contract."""

    if len(sys.argv) != EXPECTED_ARGUMENT_COUNT:
        raise SystemExit("usage: check-mutation-stats.py PATH")
    stats = _load(Path(sys.argv[1]))
    unresolved = _unresolved(stats)
    if unresolved:
        details = ", ".join(f"{name}={count}" for name, count in unresolved)
        sys.stderr.write(f"unresolved mutation outcomes: {details}\n")
        raise SystemExit(1)
    _success(stats)


if __name__ == "__main__":
    main()
