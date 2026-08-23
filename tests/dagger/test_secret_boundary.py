"""Secret and cache boundary regressions for ORAS provider execution."""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Final

import portfolio_delivery_dagger.oras as oras_runtime
import pytest
from portfolio_delivery_dagger.oras import (
    ATTEMPT_ENV,
    REGISTRY_CONFIG_PATH,
    _authenticated_argv,
)

from portfolio_delivery.domain.stages import OrasInvocation
from tests.dagger.test_module_api import (
    LIVE_FIXTURE,
    ROOT,
    PipelineFiles,
    dagger_cli,
    pipeline_files,
)
from tests.dagger.test_oras_service import (
    RestoredOutputs,
    _run_live_oras,
)

CANARY_PREFIX: Final = "task8-secret-canary-"
RG: Final = shutil.which("rg")


@pytest.fixture(scope="session")
def live_fixture() -> Path:
    subprocess.run([dagger_cli(), "develop"], cwd=LIVE_FIXTURE, check=True, capture_output=True)
    return LIVE_FIXTURE


def test_should_keep_registry_secret_out_of_provider_argv() -> None:
    # Given
    canary = CANARY_PREFIX + secrets.token_hex(12)
    invocation = ("oras", "manifest", "fetch", "registry:5000/repo:tag")

    # When
    argv = _authenticated_argv(invocation, has_registry_config=True)

    # Then
    assert canary not in "\0".join(argv)
    assert REGISTRY_CONFIG_PATH in argv


def test_should_use_regular_attempt_environment_name() -> None:
    # When / Then
    assert ATTEMPT_ENV == "PORTFOLIO_DELIVERY_ATTEMPT_ID"


def test_should_keep_actual_secret_bytes_out_of_recorded_provider_surfaces() -> None:
    # Given
    canary = CANARY_PREFIX + secrets.token_hex(12)
    base = ("oras", "manifest", "fetch", "registry:5000/repo:tag")
    argv = oras_runtime._authenticated_argv(base, has_registry_config=True)

    # When
    plan = oras_runtime._execution_plan(OrasInvocation(argv), "attempt-secret-recorder", 1, 30)

    # Then
    assert canary.encode() not in repr(plan).encode()
    assert plan.environment == ((ATTEMPT_ENV, "attempt-secret-recorder"),)
    assert plan.cache_mounts == ()
    assert REGISTRY_CONFIG_PATH in plan.argv


def test_should_hide_typed_registry_secret_from_every_observable_surface(
    tmp_path: Path, live_fixture: Path
) -> None:
    # Given
    files = pipeline_files(tmp_path)
    outputs = RestoredOutputs.create(tmp_path / "secret-restored")
    canary = CANARY_PREFIX + secrets.token_hex(12)

    # When
    result = _secret_live_result(files, outputs, live_fixture, canary)

    # Then
    assert result.returncode == 0, result.stderr
    _assert_canary_absent(canary, result, files, outputs)


def _secret_live_result(
    files: PipelineFiles, outputs: RestoredOutputs, fixture: Path, canary: str
) -> subprocess.CompletedProcess[str]:
    config = json.dumps({"auths": {}, "credHelpers": {"unused.invalid": canary}})
    return _run_live_oras(files, outputs, fixture, config)


def _assert_canary_absent(
    canary: str,
    result: subprocess.CompletedProcess[str],
    files: PipelineFiles,
    outputs: RestoredOutputs,
) -> None:
    observed = result.stdout.encode() + result.stderr.encode()
    observed += _pipeline_input_bytes(files) + _output_bytes(outputs)
    assert canary.encode() not in observed
    source_probe = subprocess.run(
        [_rg_cli(), "-F", canary, ".dagger/src", "tests"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert source_probe.returncode == 1


def _rg_cli() -> str:
    if RG is None:
        raise RuntimeError("ripgrep is required for the secret source-boundary test")
    return RG


def _output_bytes(outputs: RestoredOutputs) -> bytes:
    return _path_bytes(outputs.envelope.parent)


def _pipeline_input_bytes(files: PipelineFiles) -> bytes:
    paths = (
        files.source,
        files.inventory,
        files.build_input,
        files.evidence,
        files.artifacts,
        files.sboms,
    )
    return b"".join(_path_bytes(path) for path in paths)


def _path_bytes(path: Path) -> bytes:
    if path.is_file():
        return path.read_bytes()
    return b"".join(item.read_bytes() for item in sorted(path.rglob("*")) if item.is_file())
