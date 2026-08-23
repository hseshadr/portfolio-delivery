"""Live stable-engine contract tests for the Phase 1 Dagger module."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Final, cast

ROOT: Final = Path(__file__).parents[2]
FIXTURE: Final = ROOT / "tests/fixtures/envelope/input"
INTROSPECTION_QUERY: Final = '{ __type(name: "PortfolioDelivery") { fields { name } } }'
DAGGER_CLI: Final = shutil.which("dagger")


def dagger_cli() -> str:
    if DAGGER_CLI is None:
        raise RuntimeError("the pinned Dagger CLI is required for live module tests")
    return DAGGER_CLI


def run_dagger_functions_json() -> object:
    result = subprocess.run(
        [dagger_cli(), "query", "--silent"],
        cwd=ROOT,
        input=INTROSPECTION_QUERY,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def root_function_names(result: object) -> set[str]:
    root = cast(dict[str, object], result)["__type"]
    fields = cast(dict[str, object], root)["fields"]
    declarations = cast(list[dict[str, str]], fields)
    names = (item["name"] for item in declarations if item["name"] != "id")
    return {re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", name).lower() for name in names}


def snapshot_sha256(source: Path) -> str:
    command = [
        dagger_cli(),
        "call",
        "--silent",
        "snapshot",
        f"--source={source}",
        "--include-paths=artifacts/**",
        "--exclude-paths=artifacts/excluded.txt",
        "input-snapshot-sha-256",
    ]
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def copied_fixture(tmp_path: Path) -> Path:
    source = tmp_path / "input"
    shutil.copytree(FIXTURE, source)
    return source


def test_should_expose_phase_one_functions_when_module_is_introspected() -> None:
    # Given
    expected = {
        "check",
        "version",
        "snapshot",
        "build",
        "prequalify",
        "sign",
        "envelope",
        "qualify",
        "publish-inputs",
    }

    # When
    result = run_dagger_functions_json()

    # Then
    assert root_function_names(result) == expected


def test_should_preserve_snapshot_sha256_when_excluded_file_changes(tmp_path: Path) -> None:
    # Given
    source = copied_fixture(tmp_path)
    (source / "artifacts/excluded.txt").write_text("first", encoding="utf-8")
    expected = snapshot_sha256(source)

    # When
    (source / "artifacts/excluded.txt").write_text("second", encoding="utf-8")

    # Then
    assert snapshot_sha256(source) == expected


def test_should_change_snapshot_sha256_when_included_artifact_changes(tmp_path: Path) -> None:
    # Given
    source = copied_fixture(tmp_path)
    original = snapshot_sha256(source)

    # When
    (source / "artifacts/package.whl").write_bytes(b"changed artifact bytes")

    # Then
    assert snapshot_sha256(source) != original
