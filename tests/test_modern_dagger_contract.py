"""Behavior contract for the lean, native Dagger module."""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
HANDWRITTEN_LIMIT = 400
TEST_LIMIT = 800
WORKFLOW_MIN_LINES = 15
WORKFLOW_MAX_LINES = 30
DAGGER = "/usr/local/bin/dagger"
EXPECTED_FUNCTIONS = frozenset({"build", "complexity", "lint", "publish", "typecheck", "unit"})
EXPECTED_CHECKS = frozenset({"complexity", "lint", "typecheck", "unit"})
EXPECTED_BUILD_FILES = frozenset({".dagger", "LICENSE", "dagger.json"})
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _dagger(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (DAGGER, "--silent", *arguments),
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=300,
    )


def _plain(output: str) -> str:
    return ANSI_ESCAPE.sub("", output)


def _check_names(output: str) -> frozenset[str]:
    return frozenset(token.rpartition(":")[2] for token in _plain(output).split())


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _python_lines(paths: tuple[Path, ...]) -> int:
    return sum(
        len(path.read_text(encoding="utf-8").splitlines())
        for root in paths
        for path in root.rglob("*.py")
    )


@pytest.mark.integration
def test_should_expose_concrete_user_goals_when_functions_are_listed() -> None:
    # Given / When
    result = _dagger("functions")

    # Then
    assert result.returncode == 0, result.stderr
    assert frozenset(_plain(result.stdout).split()) >= EXPECTED_FUNCTIONS


@pytest.mark.integration
def test_should_register_meaningful_checks_when_checks_are_listed() -> None:
    # Given / When
    result = _dagger("check", "-l")

    # Then
    assert result.returncode == 0, result.stderr
    assert _check_names(result.stdout) >= EXPECTED_CHECKS


@pytest.mark.integration
def test_should_pass_all_checks_when_checkout_is_clean() -> None:
    # Given / When
    result = _dagger("check")

    # Then
    assert result.returncode == 0, result.stderr


@pytest.mark.integration
def test_should_export_native_directory_when_module_is_built(tmp_path: Path) -> None:
    # Given
    destination = tmp_path / "module"

    # When
    result = _dagger("call", "build", "-o", str(destination))

    # Then
    assert result.returncode == 0, result.stderr
    assert frozenset(path.name for path in destination.iterdir()) == EXPECTED_BUILD_FILES


@pytest.mark.integration
def test_should_build_identical_bytes_when_inputs_are_unchanged(tmp_path: Path) -> None:
    # Given
    first = tmp_path / "first"
    second = tmp_path / "second"

    # When
    first_result = _dagger("call", "build", "-o", str(first))
    second_result = _dagger("call", "build", "-o", str(second))

    # Then
    assert first_result.returncode == second_result.returncode == 0
    assert _tree_digest(first) == _tree_digest(second)


@pytest.mark.integration
def test_should_exclude_unrelated_files_when_build_inputs_are_selected(tmp_path: Path) -> None:
    # Given
    destination = tmp_path / "module"

    # When
    result = _dagger("call", "build", "-o", str(destination))

    # Then
    assert result.returncode == 0, result.stderr
    assert not (destination / "README.md").exists()
    assert not (destination / "tests").exists()


@pytest.mark.integration
def test_should_type_registry_password_as_secret_when_publish_help_is_rendered() -> None:
    # Given / When
    result = _dagger("call", "publish", "--help")

    # Then
    assert result.returncode == 0, result.stderr
    assert "Secret" in _plain(result.stdout)
    assert "--password" in _plain(result.stdout)


def test_should_pin_thin_github_trigger_when_ci_is_configured() -> None:
    # Given
    workflow = ROOT / ".github/workflows/dagger.yml"

    # When
    content = workflow.read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*[^@\s]+@([^\s]+)", content)

    # Then
    assert WORKFLOW_MIN_LINES <= len(content.splitlines()) <= WORKFLOW_MAX_LINES
    assert uses and all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in uses)
    assert 'version: "0.21.8"' in content
    assert 'check: "**"' in content


def test_should_stay_under_handwritten_loc_budget_when_module_is_extended() -> None:
    # Given
    production_roots = (ROOT / ".dagger/src", ROOT / "src")
    test_roots = (ROOT / "tests",)

    # When
    production_lines = _python_lines(production_roots)
    test_lines = _python_lines(test_roots)

    # Then
    assert production_lines <= HANDWRITTEN_LIMIT
    assert test_lines <= TEST_LIMIT
