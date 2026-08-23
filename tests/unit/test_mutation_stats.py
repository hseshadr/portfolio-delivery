"""Behavioral tests for the mutation CI result gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

ROOT: Final = Path(__file__).parents[2]
SCRIPT: Final = ROOT / "scripts/check-mutation-stats.py"


def _stats(**updates: int) -> dict[str, int]:
    values = {
        "killed": 10,
        "survived": 0,
        "total": 10,
        "no_tests": 0,
        "skipped": 0,
        "suspicious": 0,
        "timeout": 0,
        "check_was_interrupted_by_user": 0,
        "segfault": 0,
    }
    return values | updates


def _run_gate(tmp_path: Path, stats: dict[str, int]) -> subprocess.CompletedProcess[str]:
    document = tmp_path / "mutmut-cicd-stats.json"
    document.write_text(json.dumps(stats), encoding="utf-8")
    return subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), str(document)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_should_accept_only_fully_killed_mutation_run(tmp_path: Path) -> None:
    # Given / When
    result = _run_gate(tmp_path, _stats())

    # Then
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"killed": 10, "total": 10}


@pytest.mark.parametrize(
    "bad_status",
    (
        "survived",
        "no_tests",
        "suspicious",
        "timeout",
        "check_was_interrupted_by_user",
        "segfault",
    ),
)
def test_should_reject_any_unresolved_mutation_status(tmp_path: Path, bad_status: str) -> None:
    # Given / When
    result = _run_gate(tmp_path, _stats(killed=9, **{bad_status: 1}))

    # Then
    assert result.returncode == 1
    assert bad_status in result.stderr
