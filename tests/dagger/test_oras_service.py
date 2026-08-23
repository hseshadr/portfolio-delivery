"""Live registry behavior for the concrete Dagger ORAS executor."""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final, cast

import portfolio_delivery_dagger.oras as oras_runtime
import pytest
from dagger import Directory, File
from portfolio_delivery_dagger.dto import QualifiedEnvelope as DaggerQualifiedEnvelope
from portfolio_delivery_dagger.inventory import (
    FileManifest,
    FileRecord,
    PrequalificationEvidenceDocument,
)
from portfolio_delivery_dagger.oras import ORAS_IMAGE, DaggerOrasRunner
from pydantic import BaseModel, ConfigDict

from portfolio_delivery.adapters.oras import MalformedProviderResponse
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import Sha256Digest
from portfolio_delivery.domain.stages import (
    EnvelopeBundle,
    OrasInvocation,
    OrasOutcome,
    OrasResult,
)
from portfolio_delivery.envelope.canonical import canonical_json_bytes
from portfolio_delivery.envelope.documents import EvidenceDocument
from tests.dagger.test_module_api import (
    LIVE_FIXTURE,
    ROOT,
    PipelineFiles,
    dagger_cli,
    pipeline_files,
)
from tests.unit.adapters.test_oras import SBOM_BYTES, make_bundle

EXPECTED_ORAS_IMAGE: Final = (
    "ghcr.io/oras-project/oras@sha256:"
    "a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8"
)
REGISTRY_IMAGE: Final = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
MIB: Final = 1_048_576
PRIVATE_CAPTURE_PREFIX: Final = "/tmp/portfolio-delivery-run/"  # noqa: S108
type Scanner = Callable[[Directory], Awaitable[FileManifest]]


class ProviderMetricsDocument(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    execution_count: int
    inspection_count: int
    push_count: int
    attempt_ids: tuple[str, ...]


class LiveMetricsDocument(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    envelope_uri: str
    first_digest: str
    second_digest: str
    first: ProviderMetricsDocument
    second: ProviderMetricsDocument
    restore_one: ProviderMetricsDocument
    restore_two: ProviderMetricsDocument


@pytest.fixture(scope="session")
def live_fixture() -> Path:
    subprocess.run([dagger_cli(), "develop"], cwd=LIVE_FIXTURE, check=True, capture_output=True)
    return LIVE_FIXTURE


def test_should_pin_only_reviewed_oras_image() -> None:
    # When / Then
    assert ORAS_IMAGE == EXPECTED_ORAS_IMAGE


@pytest.mark.parametrize(
    ("stderr", "expected"),
    (
        (
            b'Error response from registry: failed to fetch the content of "registry:5000/r:t": '
            b"registry:5000/r:t: not found\n",
            OrasOutcome.NOT_FOUND,
        ),
        (b"Error response from registry: manifest unknown\n", OrasOutcome.NOT_FOUND),
        (b"Error response from registry: manifest_unknown\n", OrasOutcome.NOT_FOUND),
        (b"unauthorized: manifest unknown", OrasOutcome.FAILURE),
        (b"403 proxy: manifest_unknown", OrasOutcome.FAILURE),
        (b"backend unavailable: manifest unknown", OrasOutcome.FAILURE),
        (
            b"Error response from registry: manifest unknown: authentication required",
            OrasOutcome.FAILURE,
        ),
        (b"dial tcp: manifest unknown: network unavailable", OrasOutcome.FAILURE),
        (b"Error response from registry: r:t: not found; proxy unavailable", OrasOutcome.FAILURE),
    ),
)
def test_should_allowlist_only_authoritative_registry_absence(
    stderr: bytes, expected: OrasOutcome
) -> None:
    # Given
    invocation = OrasInvocation(("oras", "manifest", "fetch", "registry:5000/r:t"))

    # When
    outcome = oras_runtime._outcome(invocation, 1, stderr)

    # Then
    assert outcome is expected


def test_should_drop_exported_manifest_when_push_times_out_after_write() -> None:
    # Given
    invocation = OrasInvocation(("oras", "push", "registry:5000/r:t"))

    # When
    result = oras_runtime._provider_result(
        invocation, 124, b"", b"provider timed out", b'{"written":true}'
    )

    # Then
    assert result.outcome is OrasOutcome.TIMEOUT
    assert result.exported_file_bytes is None


def test_should_cancel_concrete_provider_execution_at_deadline() -> None:
    # When
    result = subprocess.run(
        [
            dagger_cli(),
            "-s",
            "run",
            "env",
            "PYTHONPATH=.:.dagger/src",
            "uv",
            "run",
            "python",
            "tests/dagger/runner_timeout_probe.py",
        ],
        cwd=Path(__file__).parents[2],
        check=False,
        capture_output=True,
        text=True,
    )

    # Then
    assert result.returncode == 0, result.stderr


def test_should_chunk_maximum_blob_bridge_output() -> None:
    # When
    ordinals = oras_runtime._output_chunk_ordinals(4 * MIB)

    # Then
    assert ordinals == tuple(range(4))


@pytest.mark.parametrize(
    "collision",
    (
        "manifest.json",
        ".portfolio-delivery.stdout",
        ".portfolio-delivery.process-stdout",
        ".portfolio-delivery.stderr",
    ),
)
def test_should_keep_capture_files_private_when_user_layer_names_collide(collision: str) -> None:
    # Given
    invocation = _collision_invocation(collision)

    # When
    plan = oras_runtime._execution_plan(invocation, "attempt-collision", 7, 30)

    # Then
    assert f"{collision}:application/octet-stream" in plan.argv
    assert plan.capture.stdout.startswith(PRIVATE_CAPTURE_PREFIX)
    assert plan.capture.stderr.startswith(PRIVATE_CAPTURE_PREFIX)
    assert plan.capture.manifest.startswith(PRIVATE_CAPTURE_PREFIX)
    assert plan.argv[plan.argv.index("--export-manifest") + 1] == plan.capture.manifest


def _collision_invocation(collision: str) -> OrasInvocation:
    return OrasInvocation(
        (
            "oras",
            "push",
            "--export-manifest",
            "manifest.json",
            "registry:5000/r:t",
            f"{collision}:application/octet-stream",
        )
    )


def _restore_manifest(layer_count: int, sizes: tuple[int, ...]) -> bytes:
    repeated = sizes + ((1,) * max(0, layer_count - len(sizes)))
    layers = [
        {"digest": f"sha256:{index:064x}", "mediaType": "application/octet-stream", "size": size}
        for index, size in enumerate(repeated)
    ]
    document = {"config": layers[0], "layers": layers[1:], "schemaVersion": 2}
    return json.dumps(document, separators=(",", ":")).encode()


@pytest.mark.parametrize(
    "manifest",
    (
        pytest.param(_restore_manifest(257, (1,)), id="layer-count"),
        pytest.param(_restore_manifest(2, (5 * MIB,)), id="per-file-bridge"),
        pytest.param(_restore_manifest(2, (33 * MIB, 32 * MIB)), id="aggregate"),
    ),
)
def test_should_reject_unbounded_restore_plan_before_blob_fetch(manifest: bytes) -> None:
    # When / Then
    with pytest.raises(MalformedProviderResponse):
        oras_runtime._validate_restore_manifest(manifest)


@pytest.mark.parametrize(
    "poison",
    ("snapshot-manifest", "snapshot-digest", "disposition", "signature-path", "evidence"),
)
async def test_should_reject_poisoned_provenance_before_provider_execution(poison: str) -> None:
    # Given
    bundle = make_bundle()
    runner = RecordingRunner()
    dto, scanner = _exact_dagger_bundle(bundle)
    poisoned = _poisoned_dto(dto, poison)

    # When / Then
    with pytest.raises(InvalidIdentity):
        await oras_runtime.persist_qualified_bundle(
            poisoned, scanner, lambda _: runner, "registry.example/repo", "attempt-poison"
        )
    assert runner.invocations == []


def _exact_dagger_bundle(bundle: EnvelopeBundle) -> tuple[DaggerQualifiedEnvelope, Scanner]:
    qualified = bundle.qualified
    snapshot = qualified.envelope.signed.prequalified.unsigned.source.input_snapshot_sha256
    evidence = _prequalification_bytes(bundle)
    dto = DaggerQualifiedEnvelope(
        envelope=cast(File, MemoryFile(qualified.envelope.canonical_bytes)),
        qualification=cast(File, MemoryFile(qualified.qualification.canonical_bytes)),
        envelope_sha256=qualified.envelope.content_sha256.value,
        qualification_sha256=qualified.qualification.content_sha256.value,
        artifacts=cast(Directory, object()),
        sboms=cast(Directory, object()),
        prequalification_evidence=cast(File, MemoryFile(evidence)),
        prequalification_evidence_sha256=Sha256Digest.from_bytes(evidence).value,
        input_snapshot_manifest=cast(File, MemoryFile(b"snapshot")),
        input_snapshot_sha256=snapshot.value,
        signing_disposition="signing_not_required",
        signature_path=None,
    )
    return dto, _manifest_scanner(bundle)


@dataclass(frozen=True, slots=True)
class MemoryFile:
    content: bytes

    async def size(self) -> int:
        return len(self.content)

    async def contents(self) -> str:
        return self.content.decode()


def _prequalification_bytes(bundle: EnvelopeBundle) -> bytes:
    evidence = bundle.qualified.envelope.signed.prequalified.evidence
    records = tuple(
        EvidenceDocument(
            kind=item.kind,
            name=item.name,
            subject=item.subject.value,
            status=item.status.value,
        )
        for item in evidence
    )
    document = PrequalificationEvidenceDocument(schemaVersion="v1", evidence=records)
    return canonical_json_bytes(document)


def _manifest_scanner(bundle: EnvelopeBundle) -> Scanner:
    manifests = [_artifact_manifest(bundle), _sbom_manifest(bundle)]

    async def scan(_: Directory) -> FileManifest:
        return manifests.pop(0)

    return scan


def _artifact_manifest(bundle: EnvelopeBundle) -> FileManifest:
    records = tuple(
        FileRecord(path=item.path.value, size=item.size, sha256=item.sha256.value)
        for item in bundle.artifacts
    )
    return FileManifest(files=records)


def _sbom_manifest(bundle: EnvelopeBundle) -> FileManifest:
    records = tuple(
        FileRecord(path=item.path.value, size=len(SBOM_BYTES), sha256=item.sha256.value)
        for item in bundle.sboms
    )
    return FileManifest(files=records)


def _poisoned_dto(dto: DaggerQualifiedEnvelope, poison: str) -> DaggerQualifiedEnvelope:
    mutations = {
        "snapshot-manifest": {"input_snapshot_manifest": cast(File, MemoryFile(b"poison"))},
        "snapshot-digest": {"input_snapshot_sha256": Sha256Digest.from_bytes(b"poison").value},
        "disposition": {"signing_disposition": "signed"},
        "signature-path": {"signature_path": "artifacts/package.whl"},
        "evidence": {"prequalification_evidence": cast(File, MemoryFile(b"{}"))},
    }
    return replace(dto, **mutations[poison])  # type: ignore[arg-type]


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
    original_envelope: Path
    original_qualification: Path
    original_artifacts: Path
    original_sboms: Path
    envelope: Path
    qualification: Path
    artifacts: Path
    sboms: Path
    repeated_envelope: Path
    repeated_qualification: Path
    repeated_artifacts: Path
    repeated_sboms: Path

    @classmethod
    def create(cls, root: Path) -> RestoredOutputs:
        root.mkdir()
        return cls(
            root / "original-build-envelope.v1.json",
            root / "original-qualification-record.v1.json",
            root / "original-artifacts",
            root / "original-sboms",
            root / "build-envelope.v1.json",
            root / "qualification-record.v1.json",
            root / "artifacts",
            root / "sboms",
            root / "repeat-build-envelope.v1.json",
            root / "repeat-qualification-record.v1.json",
            root / "repeat-artifacts",
            root / "repeat-sboms",
        )


def _run_live_oras(
    files: PipelineFiles,
    outputs: RestoredOutputs,
    _: Path,
    registry_config: str | None = None,
) -> subprocess.CompletedProcess[str]:
    config_path = _registry_config_file(files, registry_config)
    try:
        return subprocess.run(
            _live_command(files, outputs, config_path),
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    finally:
        if config_path is not None:
            config_path.unlink(missing_ok=True)


def _live_command(
    files: PipelineFiles, outputs: RestoredOutputs, registry_config: Path | None
) -> list[str]:
    verbosity = ["-d", "--progress=plain"] if registry_config is not None else ["-s"]
    command = [
        dagger_cli(),
        *verbosity,
        "run",
        "env",
        "PYTHONPATH=.:.dagger/src:tests/dagger/live_fixture/src",
        "uv",
        "run",
        "python",
        "tests/dagger/live_oras_probe.py",
        "--source",
        str(files.source),
        "--inventory",
        str(files.inventory),
        "--build-input",
        str(files.build_input),
        "--evidence",
        str(files.evidence),
        "--artifacts",
        str(files.artifacts),
        "--sboms",
        str(files.sboms),
        "--output",
        str(outputs.envelope.parent),
        "--run-id",
        secrets.token_hex(12),
    ]
    if registry_config is not None:
        command.extend(("--registry-config", str(registry_config)))
    return command


def _registry_config_file(files: PipelineFiles, content: str | None) -> Path | None:
    if content is None:
        return None
    path = files.source.parent / "task8-registry-config.json"
    path.write_text(content, encoding="utf-8")
    return path


def _assert_live_result(stdout: str, outputs: RestoredOutputs) -> None:
    metrics = LiveMetricsDocument.model_validate_json(stdout)
    envelope = outputs.envelope.read_bytes()
    qualification = json.loads(outputs.qualification.read_bytes())
    digest = hashlib.sha256(envelope).hexdigest()
    assert metrics.first_digest == metrics.second_digest
    assert metrics.envelope_uri.endswith(f":sha256-{digest}")
    assert qualification["subject"] == f"sha256:{digest}"
    assert outputs.original_envelope.read_bytes() == envelope
    assert outputs.original_qualification.read_bytes() == outputs.qualification.read_bytes()
    assert _directory_bytes(outputs.original_artifacts) == _directory_bytes(outputs.artifacts)
    assert _directory_bytes(outputs.original_sboms) == _directory_bytes(outputs.sboms)
    assert outputs.repeated_envelope.read_bytes() == envelope
    assert outputs.repeated_qualification.read_bytes() == outputs.qualification.read_bytes()
    assert _directory_bytes(outputs.repeated_artifacts) == _directory_bytes(outputs.artifacts)
    assert _directory_bytes(outputs.repeated_sboms) == _directory_bytes(outputs.sboms)
    assert (outputs.artifacts / "artifacts/package.whl").read_bytes() == b"wheel"
    assert (outputs.sboms / "sbom/package.cdx.json").read_bytes() == b'{"bomFormat":"CycloneDX"}\n'
    _assert_provider_metrics(metrics)
    _assert_attempt_ids(metrics)


def _directory_bytes(path: Path) -> tuple[tuple[str, bytes], ...]:
    return tuple(
        (item.relative_to(path).as_posix(), item.read_bytes())
        for item in sorted(path.rglob("*"))
        if item.is_file()
    )


def _assert_provider_metrics(metrics: LiveMetricsDocument) -> None:
    first = metrics.first
    second = metrics.second
    assert first.execution_count == first.inspection_count + first.push_count
    assert second.execution_count == second.inspection_count + second.push_count
    assert first.push_count + second.push_count == 1
    assert first.inspection_count > 0 and second.inspection_count > 0
    assert first.inspection_count + second.inspection_count > first.inspection_count
    assert metrics.restore_one.push_count == metrics.restore_two.push_count == 0
    assert metrics.restore_one.inspection_count > 0
    assert metrics.restore_two.inspection_count > 0
    assert metrics.restore_one.inspection_count + metrics.restore_two.inspection_count > (
        metrics.restore_one.inspection_count
    )


def _assert_attempt_ids(metrics: LiveMetricsDocument) -> None:
    expected = (
        (metrics.first.attempt_ids, "attempt-one-"),
        (metrics.second.attempt_ids, "attempt-two-"),
        (metrics.restore_one.attempt_ids, "restore-attempt-one-"),
        (metrics.restore_two.attempt_ids, "restore-attempt-two-"),
    )
    values = tuple(_single_attempt(attempts, prefix) for attempts, prefix in expected)
    assert len(set(values)) == len(values)


def _single_attempt(attempts: tuple[str, ...], prefix: str) -> str:
    observed = set(attempts)
    assert len(observed) == 1
    attempt_id = observed.pop()
    assert attempt_id.startswith(prefix)
    return attempt_id
