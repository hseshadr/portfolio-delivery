"""Behavioral tests for the copy-pasteable local OCI demonstration."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Final

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
artifact = pathlib.Path(arguments['--artifacts']) / 'artifacts/package.whl'
sbom = pathlib.Path(arguments['--sboms']) / 'sbom/package.cdx.json'
evidence = json.loads(pathlib.Path(arguments['--prequalification-evidence']).read_text())
expected_artifact = root / 'tests/fixtures/envelope/input/artifacts/package.whl'
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
    'first_digest': {MANIFEST_DIGEST!r},
    'second_digest': {MANIFEST_DIGEST!r},
    'first': metrics(2, 1, 1, 'one'),
    'second': metrics(1, 1, 0, 'two'),
    'restore_one': metrics(4, 4, 0, 'three'),
    'restore_two': metrics(4, 4, 0, 'four'),
    'exact_bytes': True,
    'object_ids': ['one', 'two'],
    'registry_stdout': '',
    'registry_stderr': '',
}}
sys.stdout.write(json.dumps(document))
"""


def _fake_path(tmp_path: Path, content: str = FAKE_DAGGER) -> Path:
    executable = tmp_path / "dagger"
    executable.write_text(content, encoding="utf-8")
    executable.chmod(0o755)
    return executable


def _run_demo(tmp_path: Path) -> subprocess.CompletedProcess[str]:
    _fake_path(tmp_path)
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
