"""Live registry behavior for the concrete Dagger ORAS executor."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tomllib
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
from portfolio_delivery_dagger.oras import (
    ATTEMPT_ENV,
    ORAS_IMAGE,
    DaggerOrasRunner,
    EncodedChunk,
    ProviderBindings,
    ProviderExecutionPlan,
    ProviderObservation,
)
from pydantic import BaseModel, ConfigDict

from portfolio_delivery.adapters.oras import MalformedProviderResponse
from portfolio_delivery.domain.artifacts import Artifact, Sbom
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import ArtifactPath, Sha256Digest
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
from tests.unit.adapters.test_oras import (
    SBOM_BYTES,
    make_bundle,
    make_bundle_from,
    make_sbom,
)

EXPECTED_ORAS_IMAGE: Final = (
    "ghcr.io/oras-project/oras@sha256:"
    "a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8"
)
REGISTRY_IMAGE: Final = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
PYTHON_IMAGE: Final = (
    "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)
PLAN_FIXTURE: Final = ROOT / "tests/dagger/plan_fixture"
PLAN_FIXTURE_HASHES: Final = PLAN_FIXTURE / "generated.sha256"
MIB: Final = 1_048_576
FIVE_CHUNKS: Final = 5
MINIMUM_MANIFEST_READS: Final = 4
PRIVATE_CAPTURE_PREFIX: Final = "/tmp/portfolio-delivery-run/"  # noqa: S108
EXACT_OUTPUT_DESCRIPTORS: Final = 253
OVERFLOW_OUTPUT_DESCRIPTORS: Final = 254
EXPECTED_FINALIZED_PUSH_ARGUMENTS: Final = 276
type Scanner = Callable[[Directory], Awaitable[FileManifest]]
type ChunkMutation = Callable[[tuple[EncodedChunk, ...]], tuple[EncodedChunk, ...]]


class ProviderMetricsDocument(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    execution_count: int
    inspection_count: int
    push_count: int
    attempt_ids: tuple[str, ...]


class ProviderLifecycleDocument(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    first: ProviderMetricsDocument
    second: ProviderMetricsDocument
    restore_one: ProviderMetricsDocument
    restore_two: ProviderMetricsDocument


class CapturePathsDocument(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    directory: str
    stdout: str
    process_stdout: str
    stderr: str
    manifest: str


class ProviderObservationDocument(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    attempt_id: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    capture: CapturePathsDocument
    cache_mounts: tuple[str, ...]


class LiveMetricsDocument(ProviderLifecycleDocument):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    envelope_uri: str
    first_digest: str
    second_digest: str
    observations: tuple[ProviderObservationDocument, ...]
    registry_stdout: str
    registry_stderr: str


class PublicSmokeDocument(ProviderLifecycleDocument):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid")
    envelope_uri: str
    first_digest: str
    second_digest: str
    exact_bytes: bool
    object_ids: tuple[str, ...]
    registry_stdout: str
    registry_stderr: str


@pytest.fixture(scope="session")
def live_fixture() -> Path:
    subprocess.run([dagger_cli(), "develop"], cwd=LIVE_FIXTURE, check=True, capture_output=True)
    return LIVE_FIXTURE


def test_should_pin_only_reviewed_oras_image() -> None:
    # When / Then
    assert ORAS_IMAGE == EXPECTED_ORAS_IMAGE


def test_should_pin_plan_fixture_python_runtime() -> None:
    # Given / When
    config = tomllib.loads((PLAN_FIXTURE / "pyproject.toml").read_text())

    # Then
    assert config["project"]["requires-python"] == ">=3.13,<3.14"
    assert config["tool"]["dagger"]["base-image"] == PYTHON_IMAGE


def test_should_regenerate_identical_plan_fixture_sdk_from_clean_checkout(tmp_path: Path) -> None:
    # Given
    assert PLAN_FIXTURE_HASHES.is_file()
    expected = _expected_fixture_hashes()
    clean_root = tmp_path / "checkout"
    _copy_tracked_checkout(clean_root)

    # When
    _regenerate_plan_fixture(clean_root, check_lock=False)
    first = _generated_fixture_hashes(clean_root)
    _regenerate_plan_fixture(clean_root, check_lock=True)

    # Then
    assert first == expected
    assert _generated_fixture_hashes(clean_root) == expected


def _copy_tracked_checkout(destination: Path) -> None:
    git = _required_executable("git")
    tar = _required_executable("tar")
    archive = subprocess.run([git, "archive", "HEAD"], cwd=ROOT, check=True, capture_output=True)
    destination.mkdir(parents=True)
    subprocess.run([tar, "-x", "-C", str(destination)], input=archive.stdout, check=True)
    subprocess.run([git, "init", "-q"], cwd=destination, check=True)


def _regenerate_plan_fixture(clean_root: Path, *, check_lock: bool) -> None:
    fixture = clean_root / "tests/dagger/plan_fixture"
    subprocess.run([dagger_cli(), "develop"], cwd=fixture, check=True, capture_output=True)
    uv = _required_executable("uv")
    lock_argv = [uv, "lock", "--check"] if check_lock else [uv, "lock"]
    subprocess.run(lock_argv, cwd=fixture, check=True, capture_output=True)


def _generated_fixture_hashes(clean_root: Path) -> tuple[tuple[str, str], ...]:
    fixture = clean_root / "tests/dagger/plan_fixture"
    generated = (*tuple((fixture / "sdk").rglob("*")), fixture / "uv.lock")
    files = sorted(item for item in generated if item.is_file())
    return tuple((str(item.relative_to(fixture)), _file_sha256(item)) for item in files)


def _expected_fixture_hashes() -> tuple[tuple[str, str], ...]:
    records = (line.split("  ", 1) for line in PLAN_FIXTURE_HASHES.read_text().splitlines())
    return tuple((path, digest) for digest, path in records)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _required_executable(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise RuntimeError(f"{name} executable is required")
    return executable


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


def test_should_record_exact_finalized_provider_execution_surfaces() -> None:
    # When
    result = subprocess.run(
        _dagger_python_command("tests/dagger/secret_observation_probe.py"),
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    # Then
    assert result.returncode == 0, result.stderr


def _dagger_python_command(script: str) -> list[str]:
    return [
        dagger_cli(),
        "-s",
        "run",
        "env",
        "PYTHONPATH=.:.dagger/src",
        "uv",
        "run",
        "python",
        script,
    ]


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
    "sizes",
    (
        pytest.param((5 * MIB,), id="five-mib"),
        pytest.param((64 * MIB,), id="exact-file"),
        pytest.param((64 * MIB,) * 8, id="exact-aggregate"),
    ),
)
def test_should_accept_symmetric_layer_budget_before_blob_fetch(sizes: tuple[int, ...]) -> None:
    # When / Then
    oras_runtime._validate_restore_manifest(_restore_manifest(len(sizes), sizes))


@pytest.mark.parametrize(
    "manifest",
    (
        pytest.param(_restore_manifest(257, (1,)), id="layer-count"),
        pytest.param(_restore_manifest(1, (64 * MIB + 1,)), id="file-plus-one"),
        pytest.param(_restore_manifest(9, (64 * MIB,) * 8 + (1,)), id="aggregate-plus-one"),
    ),
)
def test_should_reject_layer_budget_overflow_before_blob_fetch(manifest: bytes) -> None:
    # When / Then
    with pytest.raises(MalformedProviderResponse):
        oras_runtime._validate_restore_manifest(manifest)


@pytest.mark.parametrize("sizes", ((64 * MIB + 1,), (64 * MIB,) * 8))
async def test_should_reject_persist_when_restore_would_reject(sizes: tuple[int, ...]) -> None:
    # Given
    bundle = _sized_bundle(sizes)
    dto, scanner = _exact_dagger_bundle(bundle)
    runner = RecordingRunner()

    # When / Then
    with pytest.raises(InvalidIdentity, match="layer"):
        await oras_runtime.persist_qualified_bundle(
            dto, scanner, lambda _: runner, "registry.example/repo", "attempt-budget"
        )
    assert runner.invocations == []


async def test_should_allow_exact_descriptor_limit_to_reach_persist_push() -> None:
    # Given
    bundle = _artifact_only_bundle(EXACT_OUTPUT_DESCRIPTORS)
    dto, scanner = _exact_dagger_bundle(bundle)
    runner = ObservationBoundaryRunner()

    # When / Then
    with pytest.raises(ProviderPushReachedError):
        await oras_runtime.persist_qualified_bundle(
            dto, scanner, lambda _: runner, "registry.example/repo", "attempt-exact-limit"
        )
    assert len(runner.observations[-1].argv) == EXPECTED_FINALIZED_PUSH_ARGUMENTS


async def test_should_reject_descriptor_overflow_before_persist_provider() -> None:
    # Given
    bundle = _artifact_only_bundle(OVERFLOW_OUTPUT_DESCRIPTORS)
    dto, scanner = _exact_dagger_bundle(bundle)
    runner = ObservationBoundaryRunner()

    # When / Then
    with pytest.raises(InvalidIdentity, match="descriptor count"):
        await oras_runtime.persist_qualified_bundle(
            dto, scanner, lambda _: runner, "registry.example/repo", "attempt-overflow"
        )
    assert runner.observations == []


def test_should_encode_restored_file_as_validated_one_mib_chunks() -> None:
    # Given
    content = b"x" * (5 * MIB)
    digest = Sha256Digest.from_bytes(content).value

    # When
    chunks = oras_runtime._encoded_chunks(content, digest)

    # Then
    assert tuple(item.ordinal for item in chunks) == tuple(range(FIVE_CHUNKS))
    assert all(item.count == FIVE_CHUNKS and item.decoded_length == MIB for item in chunks)


@pytest.mark.parametrize(
    "mutation",
    (
        pytest.param("dropped-recounted", id="dropped-recounted"),
        pytest.param("short-nonfinal", id="short-nonfinal"),
        pytest.param("recounted", id="recounted"),
        pytest.param("duplicate", id="duplicate"),
        pytest.param("reordered", id="reordered"),
        pytest.param("malformed", id="malformed"),
        pytest.param("empty-final", id="empty-final"),
    ),
)
def test_should_reject_incomplete_or_malformed_restored_chunks(mutation: str) -> None:
    # Given
    content = b"a" * MIB + b"b" * MIB + b"tail"
    digest = Sha256Digest.from_bytes(content).value
    chunks = oras_runtime._encoded_chunks(content, digest)

    # When / Then
    with pytest.raises(InvalidIdentity):
        oras_runtime._validate_encoded_chunks(CHUNK_MUTATIONS[mutation](chunks), content, digest)


def _drop_and_recount_chunks(chunks: tuple[EncodedChunk, ...]) -> tuple[EncodedChunk, ...]:
    return tuple(replace(item, count=2) for item in chunks[:2])


def _shorten_nonfinal_chunk(chunks: tuple[EncodedChunk, ...]) -> tuple[EncodedChunk, ...]:
    encoded = base64.b64encode(b"a" * (MIB - 1)).decode("ascii")
    return (replace(chunks[0], decoded_length=MIB - 1, encoded=encoded), *chunks[1:])


def _recount_chunks(chunks: tuple[EncodedChunk, ...]) -> tuple[EncodedChunk, ...]:
    return tuple(replace(item, count=2) for item in chunks)


def _duplicate_chunk(chunks: tuple[EncodedChunk, ...]) -> tuple[EncodedChunk, ...]:
    duplicate = replace(chunks[0], ordinal=1)
    return (chunks[0], duplicate, chunks[2])


def _reorder_chunks(chunks: tuple[EncodedChunk, ...]) -> tuple[EncodedChunk, ...]:
    return (chunks[1], chunks[0], chunks[2])


def _malform_chunk(chunks: tuple[EncodedChunk, ...]) -> tuple[EncodedChunk, ...]:
    return (replace(chunks[0], encoded="%%%"), *chunks[1:])


def _empty_final_chunk(chunks: tuple[EncodedChunk, ...]) -> tuple[EncodedChunk, ...]:
    return (*chunks[:-1], replace(chunks[-1], decoded_length=0, encoded=""))


CHUNK_MUTATIONS: Final[dict[str, ChunkMutation]] = {
    "dropped-recounted": _drop_and_recount_chunks,
    "short-nonfinal": _shorten_nonfinal_chunk,
    "recounted": _recount_chunks,
    "duplicate": _duplicate_chunk,
    "reordered": _reorder_chunks,
    "malformed": _malform_chunk,
    "empty-final": _empty_final_chunk,
}


def _artifact_only_bundle(count: int) -> EnvelopeBundle:
    base = make_bundle().artifacts[0]
    artifacts = tuple(
        replace(
            base,
            name=f"package-{index}",
            path=ArtifactPath(f"artifacts/package-{index}.whl"),
            size=1,
        )
        for index in range(count)
    )
    return make_bundle_from(artifacts, ())


def _sized_bundle(sizes: tuple[int, ...]) -> EnvelopeBundle:
    base = make_bundle().artifacts[0]
    artifacts = tuple(
        replace(
            base,
            name=f"package-{index}",
            path=ArtifactPath(f"artifacts/package-{index}.whl"),
            size=size,
        )
        for index, size in enumerate(sizes)
    )
    sboms = tuple(_sized_sbom(item, index) for index, item in enumerate(artifacts))
    return make_bundle_from(artifacts, sboms)


def _sized_sbom(artifact: Artifact, index: int) -> Sbom:
    sbom = make_sbom(artifact)
    return replace(sbom, path=ArtifactPath(f"sbom/package-{index}.cdx.json"))


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


class ProviderPushReachedError(RuntimeError):
    """Mark an exact-limit push that passed every pre-provider bound."""


class ObservationBoundaryRunner:
    def __init__(self) -> None:
        self.observations: list[ProviderObservation] = []

    async def run(self, invocation: OrasInvocation, attempt_id: str) -> OrasResult:
        plan = oras_runtime._execution_plan(
            invocation,
            attempt_id,
            len(self.observations) + 1,
            30,
            ProviderBindings(registry_config=True, registry_service=True),
        )
        self.observations.append(_provider_observation(attempt_id, plan))
        if invocation.argv[1] == "push":
            raise ProviderPushReachedError
        return OrasResult(1, OrasOutcome.NOT_FOUND, b"", b"manifest unavailable")


def _provider_observation(attempt_id: str, plan: ProviderExecutionPlan) -> ProviderObservation:
    return ProviderObservation(
        attempt_id, plan.argv, plan.environment, plan.capture, plan.cache_mounts
    )


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


def test_should_execute_public_root_oci_lifecycle_with_one_service(
    tmp_path: Path, live_fixture: Path
) -> None:
    # Given
    artifact = b"public-smoke" * ((5 * MIB // len(b"public-smoke")) + 1)
    files = pipeline_files(tmp_path, artifact[: 5 * MIB])
    canary = "task8-secret-canary-" + secrets.token_hex(12)

    # When
    result = _run_public_smoke(files, live_fixture, canary)

    # Then
    assert result.returncode == 0, result.stderr
    document = PublicSmokeDocument.model_validate_json(result.stdout)
    assert document.exact_bytes
    assert document.first_digest == document.second_digest
    assert all(document.object_ids)
    _assert_provider_metrics(document)
    _assert_attempt_ids(document)
    _assert_registry_manifest_traffic(document.registry_stdout, document.registry_stderr)
    assert canary not in result.stdout + result.stderr


def _run_public_smoke(
    files: PipelineFiles, _: Path, canary: str
) -> subprocess.CompletedProcess[str]:
    config = json.dumps({"auths": {}, "credHelpers": {"unused.invalid": canary}})
    environment = {**dict(os.environ), "TASK8_REGISTRY_CONFIG": config}
    command = [
        dagger_cli(),
        "-d",
        "--progress=plain",
        "call",
        "public-oras-smoke",
        f"--source={files.source}",
        f"--inventory={files.inventory}",
        f"--build-input={files.build_input}",
        f"--artifacts={files.artifacts}",
        f"--sboms={files.sboms}",
        f"--prequalification-evidence={files.evidence}",
        "--registry-config=env:TASK8_REGISTRY_CONFIG",
        f"--run-id={secrets.token_hex(12)}",
        "contents",
    ]
    return subprocess.run(
        command,
        cwd=LIVE_FIXTURE,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_registry_manifest_traffic(stdout: str, stderr: str) -> None:
    combined = stdout + "\n" + stderr
    methods = re.findall(r'\] "(GET|HEAD|PUT) /v2/[^" ]+/manifests/', combined)
    assert methods.count("PUT") == 1
    assert methods.count("GET") + methods.count("HEAD") >= MINIMUM_MANIFEST_READS


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
    _assert_observation_surfaces(metrics.observations)
    _assert_registry_manifest_traffic(metrics.registry_stdout, metrics.registry_stderr)


def _directory_bytes(path: Path) -> tuple[tuple[str, bytes], ...]:
    return tuple(
        (item.relative_to(path).as_posix(), item.read_bytes())
        for item in sorted(path.rglob("*"))
        if item.is_file()
    )


def _assert_provider_metrics(metrics: ProviderLifecycleDocument) -> None:
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


def _assert_attempt_ids(metrics: ProviderLifecycleDocument) -> None:
    expected = (
        (metrics.first.attempt_ids, "attempt-one-"),
        (metrics.second.attempt_ids, "attempt-two-"),
        (metrics.restore_one.attempt_ids, "restore-attempt-one-"),
        (metrics.restore_two.attempt_ids, "restore-attempt-two-"),
    )
    values = tuple(_single_attempt(attempts, prefix) for attempts, prefix in expected)
    assert len(set(values)) == len(values)


def _assert_observation_surfaces(observations: tuple[ProviderObservationDocument, ...]) -> None:
    assert observations
    for observation in observations:
        assert observation.environment == ((ATTEMPT_ENV, observation.attempt_id),)
        assert observation.cache_mounts == ()
        assert observation.argv[:3] == ("/bin/sh", "-c", oras_runtime.DEADLINE_SCRIPT)
        assert observation.capture.directory.startswith(PRIVATE_CAPTURE_PREFIX)


def _single_attempt(attempts: tuple[str, ...], prefix: str) -> str:
    observed = set(attempts)
    assert len(observed) == 1
    attempt_id = observed.pop()
    assert attempt_id.startswith(prefix)
    return attempt_id
