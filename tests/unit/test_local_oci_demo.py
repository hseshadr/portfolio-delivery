"""Behavioral tests for the copy-pasteable local OCI demonstration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Final

import pytest

ROOT: Final = Path(__file__).parents[2]
SCRIPT: Final = ROOT / "scripts/local-oci-demo.py"
ENVELOPE_DIGEST: Final = "sha256:" + "a" * 64
MANIFEST_DIGEST: Final = "sha256:" + "b" * 64
FAKE_DAGGER: Final = f"""#!{sys.executable}
import json
import pathlib
import sys

arguments = {{item.split('=', 1)[0]: item.split('=', 1)[1] for item in sys.argv if '=' in item}}
root = pathlib.Path({str(ROOT)!r})
wheel_name = 'portfolio_delivery-0.1.0-py3-none-any.whl'
artifact = pathlib.Path(arguments['--artifacts']) / 'artifacts' / wheel_name
sbom = pathlib.Path(arguments['--sboms']) / 'sbom/package.cdx.json'
evidence = json.loads(pathlib.Path(arguments['--prequalification-evidence']).read_text())
expected_artifact = root / 'tests/fixtures/envelope/input/artifacts' / wheel_name
expected_sbom = root / 'tests/fixtures/envelope/input/sbom/package.cdx.json'
assert artifact.read_bytes() == expected_artifact.read_bytes()
assert sbom.read_bytes() == expected_sbom.read_bytes()
assert evidence['evidence'][0]['name'] == 'unit'

def metrics(executions, inspections, pushes, attempt):
    return {{
        'execution_count': executions,
        'inspection_count': inspections,
        'push_count': pushes,
        'attempt_ids': [attempt],
    }}

document = {{
    'envelope_uri': 'registry:5000/portfolio/envelopes:sha256-' + 'a' * 64,
    'envelope_bytes_sha256': {ENVELOPE_DIGEST!r},
    'first_digest': {MANIFEST_DIGEST!r},
    'second_digest': {MANIFEST_DIGEST!r},
    'first': metrics(2, 1, 1, 'attempt-one-run'),
    'second': metrics(1, 1, 0, 'attempt-two-run'),
    'restore_one': metrics(4, 4, 0, 'restore-attempt-one-run'),
    'restore_two': metrics(4, 4, 0, 'restore-attempt-two-run'),
    'exact_bytes': True,
    'object_ids': ['one', 'two'],
    'registry_stdout': '',
    'registry_stderr': '',
}}
sys.stdout.write(json.dumps(document))
"""


def _fake_source(mutation: str) -> str:
    output = "sys.stdout.write(json.dumps(document))"
    return FAKE_DAGGER.replace(
        output,
        f"{mutation}\n{output}",
    )


def _fake_path(tmp_path: Path, mutation: str = "") -> Path:
    executable = tmp_path / "dagger"
    executable.write_text(_fake_source(mutation), encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _run_demo(tmp_path: Path, mutation: str = "") -> subprocess.CompletedProcess[str]:
    _fake_path(tmp_path, mutation)
    environment = {**os.environ, "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}"}
    return subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_should_print_bounded_proof_from_checked_in_release_inputs(tmp_path: Path) -> None:
    # Given / When
    result = _run_demo(tmp_path)

    # Then
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "attempts": 2,
        "envelope_sha256": ENVELOPE_DIGEST,
        "exact_restore": True,
        "manifest_sha256": MANIFEST_DIGEST,
        "provider_writes": 1,
    }


@pytest.mark.parametrize(
    "mutation",
    (
        "document['first']['attempt_ids'] = ['']",
        "document['second']['attempt_ids'] = document['first']['attempt_ids']",
        "document['first']['attempt_ids'] = ['restore-attempt-one-run']",
        "document['first']['execution_count'] = 1",
        "document['second']['inspection_count'] = 0",
        "document['restore_one'] = metrics(0, 0, 0, 'restore-attempt-one-run')",
        "document['restore_two']['attempt_ids'] = document['restore_one']['attempt_ids']",
        "document['envelope_bytes_sha256'] = 'sha256:' + 'c' * 64",
        "document['second_digest'] = 'sha256:' + 'c' * 64",
        "document['exact_bytes'] = False",
    ),
)
def test_should_reject_vacuous_or_mismatched_provider_evidence(
    tmp_path: Path, mutation: str
) -> None:
    # Given / When
    result = _run_demo(tmp_path, mutation)

    # Then
    assert result.returncode != 0
    assert result.stdout == ""
