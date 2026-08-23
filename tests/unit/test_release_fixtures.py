"""Semantic integrity checks for the checked-in release demo fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath
from typing import cast

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator


def _source_repository_root(candidate: Path) -> Path:
    return candidate.parent if candidate.name == "mutants" else candidate


TEST_ROOT = Path(__file__).parents[2]
ROOT = _source_repository_root(TEST_ROOT)
FIXTURE = ROOT / "tests/fixtures/envelope/input"
WHEEL = FIXTURE / "artifacts/package.whl"
SBOM = FIXTURE / "sbom/package.cdx.json"
BUILD_INPUT = FIXTURE / "build-input.json"
PROJECT_NAME = "portfolio-delivery"
PROJECT_VERSION = "0.1.0"
SOURCE_DATE_EPOCH = "1724472000"


def test_should_resolve_original_source_from_mutmut_workspace(tmp_path: Path) -> None:
    # Given
    source_root = tmp_path / "repository"

    # When / Then
    assert _source_repository_root(source_root / "mutants") == source_root


def _wheel_names(wheel: zipfile.ZipFile) -> tuple[str, ...]:
    return tuple(info.filename for info in wheel.infolist())


def _single_metadata_path(names: tuple[str, ...], filename: str) -> str:
    matches = tuple(name for name in names if name.endswith(f".dist-info/{filename}"))
    assert len(matches) == 1
    return matches[0]


def _wheel_metadata(wheel: zipfile.ZipFile) -> tuple[str, str, str]:
    names = _wheel_names(wheel)
    metadata = BytesParser(policy=default).parsebytes(
        wheel.read(_single_metadata_path(names, "METADATA"))
    )
    wheel_text = wheel.read(_single_metadata_path(names, "WHEEL")).decode("utf-8")
    return str(metadata["Name"]), str(metadata["Version"]), wheel_text


def test_should_contain_real_portfolio_delivery_wheel_metadata() -> None:
    # Given / When
    with zipfile.ZipFile(WHEEL) as wheel:
        name, version, wheel_text = _wheel_metadata(wheel)

    # Then
    assert (name, version) == (PROJECT_NAME, PROJECT_VERSION)
    assert "Tag: py3-none-any" in wheel_text


def test_should_contain_importable_portfolio_delivery_package() -> None:
    # Given
    source = ROOT / "src"
    expected = frozenset(str(path.relative_to(source)) for path in source.rglob("*.py"))

    # When
    with zipfile.ZipFile(WHEEL) as wheel:
        names = frozenset(_wheel_names(wheel))

    # Then
    assert expected
    assert expected.issubset(names)


def _is_safe_wheel_entry(info: zipfile.ZipInfo) -> bool:
    path = PurePosixPath(info.filename)
    mode = (info.external_attr >> 16) & 0o170000
    return (
        not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in info.filename
        and "\x00" not in info.filename
        and not stat.S_ISLNK(mode)
    )


def test_should_contain_only_safe_non_symlink_wheel_paths() -> None:
    # Given / When
    with zipfile.ZipFile(WHEEL) as wheel:
        entries = tuple(wheel.infolist())

    # Then
    assert entries
    assert all(_is_safe_wheel_entry(info) for info in entries)


def _build_context(destination: Path) -> None:
    destination.mkdir()
    shutil.copy2(ROOT / "pyproject.toml", destination / "pyproject.toml")
    shutil.copytree(ROOT / "src", destination / "src")


def _build_wheel(context: Path, output: Path) -> bytes:
    command = (
        "uv",
        "build",
        "--wheel",
        "--no-sources",
        "--no-build-logs",
        "--no-python-downloads",
        "--out-dir",
        str(output),
        str(context),
    )
    env = {**os.environ, "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}
    subprocess.run(command, check=True, env=env, capture_output=True)  # noqa: S603
    wheels = tuple(output.glob("*.whl"))
    assert len(wheels) == 1
    return wheels[0].read_bytes()


def test_should_match_two_independent_deterministic_wheel_builds(tmp_path: Path) -> None:
    # Given
    first, second = tmp_path / "first", tmp_path / "second"
    _build_context(first)
    _build_context(second)

    # When
    first_bytes = _build_wheel(first, tmp_path / "first-dist")
    second_bytes = _build_wheel(second, tmp_path / "second-dist")

    # Then
    assert first_bytes == second_bytes == WHEEL.read_bytes()


def _build_input() -> dict[str, object]:
    return cast(dict[str, object], json.loads(BUILD_INPUT.read_bytes()))


def _package_declaration(document: dict[str, object]) -> dict[str, object]:
    artifacts = cast(list[dict[str, object]], document["artifacts"])
    return next(artifact for artifact in artifacts if artifact["path"] == "artifacts/package.whl")


def _sbom_component(document: dict[str, object]) -> dict[str, object]:
    metadata = cast(dict[str, object], document["metadata"])
    return cast(dict[str, object], metadata["component"])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_should_be_valid_cyclonedx_1_6_document() -> None:
    # Given
    validator = JsonStrictValidator(SchemaVersion.V1_6)

    # When / Then
    assert validator.validate_str(SBOM.read_text(encoding="utf-8")) is None


def _generate_sbom(output: Path) -> bytes:
    command = (
        sys.executable,
        str(ROOT / "scripts/build-release-sbom.py"),
        "--wheel",
        str(WHEEL),
        "--output",
        str(output),
        "--source-date-epoch",
        SOURCE_DATE_EPOCH,
    )
    subprocess.run(command, check=True, capture_output=True)  # noqa: S603
    return output.read_bytes()


def test_should_match_two_deterministic_official_sbom_generations(tmp_path: Path) -> None:
    # Given / When
    first = _generate_sbom(tmp_path / "first.cdx.json")
    second = _generate_sbom(tmp_path / "second.cdx.json")

    # Then
    assert first == second == SBOM.read_bytes()


def test_should_bind_sbom_component_to_wheel_and_build_input() -> None:
    # Given
    sbom = cast(dict[str, object], json.loads(SBOM.read_bytes()))
    component = _sbom_component(sbom)
    package = _package_declaration(_build_input())
    hashes = cast(list[dict[str, str]], component["hashes"])

    # When
    sha256 = _sha256(WHEEL)

    # Then
    assert (component["name"], component["version"], component["type"]) == (
        PROJECT_NAME,
        PROJECT_VERSION,
        "library",
    )
    assert component["purl"] == f"pkg:pypi/{PROJECT_NAME}@{PROJECT_VERSION}"
    assert hashes == [{"alg": "SHA-256", "content": sha256}]
    assert package["sha256"] == f"sha256:{sha256}"
    assert package["size"] == WHEEL.stat().st_size
