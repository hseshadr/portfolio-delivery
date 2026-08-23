"""Live registry behavior for the concrete Dagger ORAS executor."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import pytest
from dagger import Directory, File
from portfolio_delivery_dagger.dto import QualifiedEnvelope as DaggerQualifiedEnvelope
from portfolio_delivery_dagger.oras import ORAS_IMAGE, DaggerOrasRunner, _reconstruct_bundle

from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import Sha256Digest
from portfolio_delivery.domain.stages import EnvelopeBundle, OrasInvocation, OrasResult
from portfolio_delivery.envelope.documents import BuildEnvelopeDocument, QualificationRecordDocument
from tests.dagger.test_module_api import (
    LIVE_FIXTURE,
    PipelineFiles,
    _pipeline_references,
    _plan_shell,
    dagger_cli,
    pipeline_files,
)
from tests.unit.adapters.test_oras import make_bundle

EXPECTED_ORAS_IMAGE: Final = (
    "ghcr.io/oras-project/oras@sha256:"
    "a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8"
)
REGISTRY_IMAGE: Final = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)


@pytest.fixture(scope="session")
def live_fixture() -> Path:
    subprocess.run([dagger_cli(), "develop"], cwd=LIVE_FIXTURE, check=True, capture_output=True)
    return LIVE_FIXTURE


def test_should_pin_only_reviewed_oras_image() -> None:
    # When / Then
    assert ORAS_IMAGE == EXPECTED_ORAS_IMAGE


def test_should_reject_poisoned_bundle_before_provider_execution() -> None:
    # Given
    bundle = make_bundle()
    runner = RecordingRunner()
    dto = _dagger_dto(bundle, "signed")

    # When / Then
    _assert_poisoned_reconstruction(dto, bundle)
    assert runner.invocations == []


def _assert_poisoned_reconstruction(dto: DaggerQualifiedEnvelope, bundle: EnvelopeBundle) -> None:
    qualified = bundle.qualified
    document = cast(BuildEnvelopeDocument, qualified.envelope.document)
    record = cast(QualificationRecordDocument, qualified.qualification.document)
    with pytest.raises(InvalidIdentity, match="disposition"):
        _reconstruct_bundle(
            dto,
            document,
            record,
            qualified.envelope.canonical_bytes,
            qualified.qualification.canonical_bytes,
        )


def _dagger_dto(bundle: EnvelopeBundle, disposition: str) -> DaggerQualifiedEnvelope:
    qualified = bundle.qualified
    snapshot = qualified.envelope.signed.prequalified.unsigned.source.input_snapshot_sha256
    placeholder_file = cast(File, object())
    placeholder_directory = cast(Directory, object())
    return _dagger_dto_values(
        bundle, disposition, snapshot.value, placeholder_file, placeholder_directory
    )


def _dagger_dto_values(
    bundle: EnvelopeBundle, disposition: str, snapshot: str, file: File, directory: Directory
) -> DaggerQualifiedEnvelope:
    qualified = bundle.qualified
    return DaggerQualifiedEnvelope(
        envelope=file,
        qualification=file,
        envelope_sha256=qualified.envelope.content_sha256.value,
        qualification_sha256=qualified.qualification.content_sha256.value,
        artifacts=directory,
        sboms=directory,
        prequalification_evidence=file,
        prequalification_evidence_sha256=Sha256Digest.from_bytes(b"evidence").value,
        input_snapshot_sha256=snapshot,
        signing_disposition=disposition,
        signature_path=None,
    )


class RecordingRunner:
    def __init__(self) -> None:
        self.invocations: list[OrasInvocation] = []

    async def run(self, invocation: OrasInvocation, attempt_id: str) -> OrasResult:
        self.invocations.append(invocation)
        raise AssertionError(f"provider called for {attempt_id}")


def test_should_construct_runner_with_real_registry_service_contract() -> None:
    # Given / When
    runner_type = DaggerOrasRunner

    # Then
    assert runner_type.__name__ == "DaggerOrasRunner"
    assert REGISTRY_IMAGE.endswith("18f9457e")


def test_should_reconcile_and_restore_exact_bytes_with_empty_cache(
    tmp_path: Path, live_fixture: Path
) -> None:
    # Given
    files = pipeline_files(tmp_path)
    outputs = RestoredOutputs.create(tmp_path / "restored")

    # When
    result = _run_live_oras(files, outputs, live_fixture)

    # Then
    assert result.returncode == 0, result.stderr
    _assert_live_result(result.stdout, outputs)


@dataclass(frozen=True, slots=True)
class RestoredOutputs:
    envelope: Path
    qualification: Path
    artifacts: Path
    sboms: Path

    @classmethod
    def create(cls, root: Path) -> RestoredOutputs:
        root.mkdir()
        return cls(
            root / "build-envelope.v1.json",
            root / "qualification-record.v1.json",
            root / "artifacts",
            root / "sboms",
        )


def _run_live_oras(
    files: PipelineFiles,
    outputs: RestoredOutputs,
    fixture: Path,
    registry_config: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _live_command(files, outputs, registry_config is not None),
        cwd=fixture,
        check=False,
        capture_output=True,
        text=True,
        env=_live_environment(registry_config),
    )


def _live_command(
    files: PipelineFiles, outputs: RestoredOutputs, has_registry_config: bool
) -> list[str]:
    verbosity = ["-d", "--progress=plain"] if has_registry_config else ["-s"]
    command = _oras_shell(files, outputs, has_registry_config)
    return [dagger_cli(), "shell", *verbosity, "-c", command]


def _live_environment(registry_config: str | None) -> dict[str, str]:
    environment = os.environ.copy()
    if registry_config is not None:
        environment["TASK8_REGISTRY_CONFIG"] = registry_config
    return environment


def _oras_shell(
    files: PipelineFiles, outputs: RestoredOutputs, has_registry_config: bool = False
) -> str:
    cache_key = f"task8-registry-{hashlib.sha256(str(outputs.envelope).encode()).hexdigest()}"
    storage = f'storage=$(cache-volume --key="{cache_key}")'
    commands = (
        *_pipeline_references(files),
        _plan_shell(None),
        *_qualified_stages(),
        storage,
        _registry_service(),
        *_oras_effects(outputs, has_registry_config),
    )
    return "; ".join(commands)


def _registry_service() -> str:
    return (
        f'registry=$(container | from --address="{REGISTRY_IMAGE}" '
        '| with-mounted-cache /var/lib/registry "$storage" --sharing=LOCKED '
        "| with-exposed-port --port=5000 | as-service)"
    )


def _qualified_stages() -> tuple[str, ...]:
    return (
        'release=$(portfolio-delivery | version --source="$src" --inventory="$inv" '
        '--include-paths="src/**" --exclude-paths="__none__" --build-input="$input")',
        'snap=$(portfolio-delivery | snapshot --release="$release" --plan="$release")',
        'unsigned=$(portfolio-delivery | build --source="$snap" --plan="$plan")',
        'checked=$(portfolio-delivery | prequalify --build="$unsigned" --plan="$plan")',
        'signed=$(portfolio-delivery | sign --build="$checked" --plan="$plan")',
        'envelope=$(portfolio-delivery | envelope --build="$signed")',
        'qualified=$(portfolio-delivery | qualify --envelope="$envelope" --plan="$plan")',
    )


def _oras_effects(outputs: RestoredOutputs, has_registry_config: bool) -> tuple[str, ...]:
    repository = "registry:5000/portfolio/envelopes"
    arguments = f'--bundle="$qualified" --repository="{repository}"'
    service = '--registry-service="$registry"'
    secret = " --registry-config=env:TASK8_REGISTRY_CONFIG" if has_registry_config else ""
    return (
        *_persist_effects(arguments, service, secret),
        *_restore_effects(outputs, service, secret),
        _live_summary_effect(),
    )


def _persist_effects(arguments: str, service: str, secret: str) -> tuple[str, ...]:
    return (
        f"first=$(portfolio-delivery | persist-oci {arguments} "
        f'--attempt-id="attempt-one" {service}{secret})',
        f"second=$(portfolio-delivery | persist-oci {arguments} "
        f'--attempt-id="attempt-two" {service}{secret})',
        'uri=$("$first" | envelope-uri)',
        'digest1=$("$first" | envelope-digest)',
        'digest2=$("$second" | envelope-digest)',
    )


def _restore_effects(outputs: RestoredOutputs, service: str, secret: str) -> tuple[str, ...]:
    return (
        _restore_call(service, secret),
        f'"$restored" | envelope | export --path="{outputs.envelope}"',
        f'"$restored" | qualification | export --path="{outputs.qualification}"',
        f'"$restored" | artifacts | export --path="{outputs.artifacts}"',
        f'"$restored" | sboms | export --path="{outputs.sboms}"',
    )


def _live_summary_effect() -> str:
    return (
        f'container | from --address="{ORAS_IMAGE}" '
        '| with-exec --args="echo,$digest1|$digest2|$uri" | stdout'
    )


def _restore_call(service: str, secret: str) -> str:
    return (
        "restored=$(portfolio-delivery | restore-qualified "
        '--release-id="portfolio-delivery:v0.1.0" --envelope-uri="$uri" '
        f'--envelope-digest="$digest1" {service}{secret})'
    )


def _assert_live_result(stdout: str, outputs: RestoredOutputs) -> None:
    digest1, digest2, uri = _live_summary(stdout)
    envelope = outputs.envelope.read_bytes()
    qualification = json.loads(outputs.qualification.read_bytes())
    digest = hashlib.sha256(envelope).hexdigest()
    assert digest1 == digest2
    assert uri.endswith(f":sha256-{digest}")
    assert qualification["subject"] == f"sha256:{digest}"
    assert (outputs.artifacts / "artifacts/package.whl").read_bytes() == b"wheel"
    assert (outputs.sboms / "sbom/package.cdx.json").read_bytes() == b'{"bomFormat":"CycloneDX"}\n'


def _live_summary(stdout: str) -> tuple[str, str, str]:
    pattern = r"(sha256:[0-9a-f]{64})\|(sha256:[0-9a-f]{64})\|([^\n]+)$"
    match = re.search(pattern, stdout)
    if match is None:
        raise AssertionError(f"live ORAS summary was absent: {stdout!r}")
    return match.group(1), match.group(2), match.group(3)
