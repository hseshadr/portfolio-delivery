#!/usr/bin/env python3
"""Run the checked-in release fixture through the public local OCI lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from portfolio_delivery.domain.identity import Sha256Digest

ROOT: Final = Path(__file__).parents[1]
FIXTURE: Final = ROOT / "tests/fixtures/envelope/input"
LIVE_FIXTURE: Final = ROOT / "tests/dagger/live_fixture"
MAX_DIAGNOSTIC_CHARACTERS: Final[int] = 4_096
DEMO_TIMEOUT_SECONDS: Final[int] = 600


class DemoError(RuntimeError):
    """The public local OCI lifecycle did not satisfy its proof contract."""


class ProviderMetrics(BaseModel):  # type: ignore[explicit-any]
    """Bounded provider counters returned by the public smoke function."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    execution_count: int = Field(ge=0)
    inspection_count: int = Field(ge=0)
    push_count: int = Field(ge=0)
    attempt_ids: tuple[str, ...] = Field(max_length=32)


class PublicSmoke(BaseModel):  # type: ignore[explicit-any]
    """Strict output boundary for the public Dagger smoke function."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    envelope_uri: str = Field(max_length=2_048)
    first_digest: str
    second_digest: str
    first: ProviderMetrics
    second: ProviderMetrics
    restore_one: ProviderMetrics
    restore_two: ProviderMetrics
    exact_bytes: bool
    object_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    registry_stdout: str = Field(max_length=131_072)
    registry_stderr: str = Field(max_length=131_072)

    @field_validator("first_digest", "second_digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value


class DemoProof(BaseModel):  # type: ignore[explicit-any]
    """Small machine-readable proof printed for a human quickstart."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    envelope_sha256: str
    manifest_sha256: str
    attempts: int = Field(ge=0)
    provider_writes: int = Field(ge=0)
    exact_restore: bool

    @field_validator("envelope_sha256", "manifest_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value


@dataclass(frozen=True, slots=True)
class DemoInputs:
    """Materialized paths supplied to the external project composition."""

    source: Path
    inventory: Path
    build_input: Path
    artifacts: Path
    sboms: Path
    evidence: Path


def _write_json(path: Path, value: object) -> None:
    content = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(content, encoding="utf-8")


def _source_inventory(root: Path) -> tuple[Path, str]:
    source_file = root / "source/src/app.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(b"portfolio-delivery demo\n")
    entry = _inventory_entry(source_file, root / "source")
    inventory = root / "source-inventory.v1.json"
    _write_json(inventory, {"entries": [entry]})
    return inventory, Sha256Digest.from_bytes(inventory.read_bytes()).value


def _inventory_entry(path: Path, root: Path) -> dict[str, str | int]:
    content = path.read_bytes()
    return {
        "kind": "regular",
        "mode": "100644",
        "path": path.relative_to(root).as_posix(),
        "sha256": Sha256Digest.from_bytes(content).value,
        "size": len(content),
    }


def _copy_outputs(root: Path) -> tuple[Path, Path]:
    artifacts = root / "artifacts/artifacts"
    sboms = root / "sboms/sbom"
    artifacts.mkdir(parents=True)
    sboms.mkdir(parents=True)
    shutil.copy2(FIXTURE / "artifacts/package.whl", artifacts / "package.whl")
    shutil.copy2(FIXTURE / "sbom/package.cdx.json", sboms / "package.cdx.json")
    return artifacts.parent, sboms.parent


def _build_input(root: Path, source_digest: str) -> tuple[Path, Path]:
    document = cast(dict[str, object], json.loads((FIXTURE / "build-input.json").read_bytes()))
    source = cast(dict[str, object], document["source"])
    source["sourceTreeSha256"] = source_digest
    document["artifacts"] = _package_artifact(document)
    evidence = cast(list[dict[str, object]], document["prequalificationEvidence"])
    evidence[0]["subject"] = source_digest
    build_input = root / "build-input.json"
    evidence_path = root / "prequalification-evidence.v1.json"
    _write_json(build_input, document)
    _write_json(evidence_path, {"schemaVersion": "v1", "evidence": evidence})
    return build_input, evidence_path


def _package_artifact(document: dict[str, object]) -> list[dict[str, object]]:
    artifacts = cast(list[dict[str, object]], document["artifacts"])
    return [item for item in artifacts if item["path"] == "artifacts/package.whl"]


def _prepare_inputs(root: Path) -> DemoInputs:
    inventory, digest = _source_inventory(root)
    artifacts, sboms = _copy_outputs(root)
    build_input, evidence = _build_input(root, digest)
    return DemoInputs(root / "source", inventory, build_input, artifacts, sboms, evidence)


def _dagger_command(inputs: DemoInputs, run_id: str) -> list[str]:
    return [
        "dagger",
        "-s",
        "call",
        "public-oras-smoke",
        f"--source={inputs.source}",
        f"--inventory={inputs.inventory}",
        f"--build-input={inputs.build_input}",
        f"--artifacts={inputs.artifacts}",
        f"--sboms={inputs.sboms}",
        f"--prequalification-evidence={inputs.evidence}",
        "--registry-config=env:PORTFOLIO_DELIVERY_DEMO_REGISTRY_CONFIG",
        f"--run-id={run_id}",
        "contents",
    ]


def _run_public_smoke(inputs: DemoInputs) -> PublicSmoke:
    run_id = hashlib.sha256(inputs.inventory.read_bytes()).hexdigest()[:24]
    command = _dagger_command(inputs, run_id)
    environment = {**os.environ, "PORTFOLIO_DELIVERY_DEMO_REGISTRY_CONFIG": '{"auths":{}}'}
    result = subprocess.run(  # noqa: S603
        command,
        cwd=LIVE_FIXTURE,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=DEMO_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise DemoError(result.stderr[-MAX_DIAGNOSTIC_CHARACTERS:])
    return PublicSmoke.model_validate_json(result.stdout)


def _envelope_digest(uri: str) -> str:
    marker = ":sha256-"
    if marker not in uri:
        raise DemoError("public smoke returned a non-content-addressed envelope URI")
    return Sha256Digest("sha256:" + uri.rsplit(marker, 1)[1]).value


def _proof(smoke: PublicSmoke) -> DemoProof:
    writes = smoke.first.push_count + smoke.second.push_count
    if smoke.first_digest != smoke.second_digest or writes != 1 or not smoke.exact_bytes:
        raise DemoError("public smoke did not prove idempotent exact persistence")
    return DemoProof(
        envelope_sha256=_envelope_digest(smoke.envelope_uri),
        manifest_sha256=smoke.first_digest,
        attempts=2,
        provider_writes=writes,
        exact_restore=smoke.exact_bytes,
    )


def main() -> None:
    """Run the real public graph and emit one bounded canonical JSON proof."""

    with tempfile.TemporaryDirectory(prefix="portfolio-delivery-demo-") as temporary:
        smoke = _run_public_smoke(_prepare_inputs(Path(temporary)))
    proof = _proof(smoke)
    sys.stdout.write(json.dumps(proof.model_dump(), sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
