"""Pinned Dagger execution for the pure ORAS reconciliation adapter."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import PurePosixPath
from typing import Final, Literal, cast

from dagger import (
    Client,
    Container,
    Directory,
    File,
    ReturnType,
    Secret,
    Service,
    field,
    object_type,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from portfolio_delivery.adapters.oras import (
    MAX_MANIFEST_BYTES,
    MAX_PROCESS_STDOUT_BYTES,
    MAX_STDERR_BYTES,
    MalformedProviderResponse,
    OrasAdapter,
)
from portfolio_delivery.contracts.oci import DEFAULT_OCI_RESOURCE_LIMITS
from portfolio_delivery.contracts.storage import OrasRunner
from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    EvidenceStatus,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
)
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.identity import (
    ArtifactPath,
    ProjectId,
    ReleaseId,
    Sha256Digest,
    SourceRevision,
)
from portfolio_delivery.domain.stages import (
    BuildEnvelope,
    EnvelopeBundle,
    OciReference,
    OrasInvocation,
    OrasOutcome,
    OrasResult,
    PrequalifiedBuild,
    QualificationRecord,
    QualifiedEnvelope,
    ReleaseSource,
    SignedBuild,
    SigningDisposition,
    SnapshottedSource,
    UnsignedBuild,
    validate_attempt_id,
)
from portfolio_delivery.domain.stages import (
    StoredEnvelope as CoreStoredEnvelope,
)
from portfolio_delivery.envelope.builder import (
    EnvelopeBuilder,
    EnvelopeMetadata,
    PinnedCompatibility,
    ProjectAdapterVersion,
    QualificationBuilder,
    ReleaseChannel,
    ReleasePolicyMetadata,
)
from portfolio_delivery.envelope.canonical import parse_bounded_json
from portfolio_delivery.envelope.documents import (
    BuildEnvelopeDocument,
    EvidenceDocument,
    LockDocument,
    QualificationRecordDocument,
    ToolchainDocument,
)
from portfolio_delivery_dagger.dto import QualifiedEnvelope as DaggerQualifiedEnvelope
from portfolio_delivery_dagger.inventory import FileManifest, PrequalificationEvidenceDocument

ORAS_IMAGE: Final = (
    "ghcr.io/oras-project/oras@sha256:"
    "a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8"
)
REGISTRY_CONFIG_PATH: Final = "/run/secrets/registry-config.json"
ATTEMPT_ENV: Final = "PORTFOLIO_DELIVERY_ATTEMPT_ID"
WORKDIR: Final = "/work"
CAPTURE_ROOT: Final = "/tmp/portfolio-delivery-run"  # noqa: S108
RESTORE_ROOT: Final = f"{CAPTURE_ROOT}/restore"
CORE_INPUT_PATHS: Final = (
    "config.v1.json",
    "build-envelope.v1.json",
    "qualification-record.v1.json",
)
TIMEOUT_EXIT_CODE: Final = 124
DEFAULT_EXECUTION_DEADLINE_SECONDS: Final = 120
OUTPUT_CHUNK_BYTES: Final = 1_048_576
ORAS_PUSH_PREFIX_ARGUMENTS: Final = 12
REGISTRY_CONFIG_OPTION_ARGUMENTS: Final = 2
REGISTRY_SERVICE_OPTION_ARGUMENTS: Final = 1
DEADLINE_WRAPPER_ARGUMENTS: Final = 5
MAX_OBSERVATION_ARGUMENTS: Final = DEFAULT_OCI_RESOURCE_LIMITS.max_descriptors + (
    ORAS_PUSH_PREFIX_ARGUMENTS
    + REGISTRY_CONFIG_OPTION_ARGUMENTS
    + REGISTRY_SERVICE_OPTION_ARGUMENTS
    + DEADLINE_WRAPPER_ARGUMENTS
)
MAX_OBSERVATION_TEXT_BYTES: Final = 4_096
CHUNK_READ_SCRIPT: Final = 'dd if="$1" bs="$2" skip="$3" count=1 2>/dev/null | base64'
DEADLINE_SCRIPT: Final = (
    'deadline="$1"; shift; timeout -s TERM -k 5 "$deadline" "$@"; status=$?; '
    'case "$status" in 137|143) exit 124;; *) exit "$status";; esac'
)
NOT_FOUND_RESPONSES: Final = (
    re.compile(rb"error response from registry: manifest unknown\r?\n?", re.IGNORECASE),
    re.compile(rb"error response from registry: manifest_unknown\r?\n?", re.IGNORECASE),
    re.compile(
        rb'error response from registry: failed to fetch the content of "([^"\r\n]+)": '
        rb"\1: not found\r?\n?",
        re.IGNORECASE,
    ),
)
type DirectoryScanner = Callable[[Directory], Awaitable[FileManifest]]
type RunnerFactory = Callable[[EnvelopeBundle], OrasRunner]


class _RestoreDescriptor(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="allow")
    size: int = Field(ge=0, strict=True)


class _RestoreManifest(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="allow")
    schema_version: Literal[2] = Field(alias="schemaVersion")
    config: _RestoreDescriptor
    layers: tuple[_RestoreDescriptor, ...]


@dataclass(frozen=True, slots=True)
class CapturePaths:
    directory: str
    stdout: str
    process_stdout: str
    stderr: str
    manifest: str


@dataclass(frozen=True, slots=True)
class ProviderExecutionPlan:
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    capture: CapturePaths
    cache_mounts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProviderBindings:
    registry_config: bool = False
    registry_service: bool = False


NO_PROVIDER_BINDINGS: Final = ProviderBindings()


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    attempt_id: str
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    capture: CapturePaths
    cache_mounts: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_observation(self)


@dataclass(frozen=True, slots=True)
class EncodedChunk:
    ordinal: int
    count: int
    decoded_length: int
    encoded: str


@dataclass(frozen=True, slots=True)
class RetainedRecordBytes:
    envelope: bytes
    qualification: bytes
    snapshot_manifest: bytes
    prequalification_evidence: bytes


@dataclass(frozen=True, slots=True)
class ValidatedBundleOutputs:
    bundle: EnvelopeBundle
    artifacts: FileManifest
    sboms: FileManifest


@dataclass(kw_only=True)
@object_type
class StoredEnvelope:
    """Pinned OCI reference returned after authoritative reconciliation."""

    envelope_uri: str = field()
    envelope_digest: str = field()
    provider_execution_count: int = field()
    provider_inspection_count: int = field()
    provider_push_count: int = field()
    attempt_ids: list[str] = field()


@dataclass(kw_only=True)
@object_type
class QualifiedEnvelopeRef:
    """Exact restored public qualification bytes and their published outputs."""

    release_id: str = field()
    envelope_uri: str = field()
    envelope_digest: str = field()
    envelope: File = field()
    qualification: File = field()
    artifacts: Directory = field()
    sboms: Directory = field()
    provider_execution_count: int = field()
    provider_inspection_count: int = field()
    provider_push_count: int = field()
    attempt_ids: list[str] = field()


@dataclass(slots=True)
class DaggerOrasRunner:
    """Run one preplanned ORAS command in the sole reviewed provider image."""

    client: Client
    repository: str
    artifacts: Directory | None = None
    sboms: Directory | None = None
    artifact_paths: tuple[str, ...] = ()
    sbom_paths: tuple[str, ...] = ()
    registry_config: Secret | None = None
    registry_service: Service | None = None
    execution_deadline_seconds: int = DEFAULT_EXECUTION_DEADLINE_SECONDS
    execution_count: int = 0
    inspection_count: int = 0
    push_count: int = 0
    service_started: bool = False
    fetched_blobs: dict[str, bytes] = dataclass_field(default_factory=dict)
    previous_container: Container | None = None
    observations: list[ProviderObservation] = dataclass_field(default_factory=list)

    async def run(self, invocation: OrasInvocation, attempt_id: str) -> OrasResult:
        validate_attempt_id(attempt_id)
        await self._start_service()
        plan = self._plan(invocation, attempt_id)
        self._record(invocation, plan)
        executed = self._execute(invocation, plan)
        self.previous_container = executed
        result = await _execution_result(executed, invocation, plan)
        _validate_successful_manifest(invocation, result)
        self._retain_blob(invocation, result.stdout, result.exit_code)
        return result

    def _record(self, invocation: OrasInvocation, plan: ProviderExecutionPlan) -> None:
        self.execution_count += 1
        self.observations.append(
            ProviderObservation(
                plan.environment[0][1],
                plan.argv,
                plan.environment,
                plan.capture,
                plan.cache_mounts,
            )
        )
        if _is_push(invocation.argv):
            self.push_count += 1
        else:
            self.inspection_count += 1

    async def _start_service(self) -> None:
        if self.registry_service is None or self.service_started:
            return
        await self.registry_service.start()
        self.service_started = True

    def _plan(self, invocation: OrasInvocation, attempt_id: str) -> ProviderExecutionPlan:
        bindings = ProviderBindings(
            self.registry_config is not None, self.registry_service is not None
        )
        return _execution_plan(
            invocation,
            attempt_id,
            self.execution_count + 1,
            self.execution_deadline_seconds,
            bindings,
        )

    def _execute(self, invocation: OrasInvocation, plan: ProviderExecutionPlan) -> Container:
        container = self._configured_container(invocation, plan)
        return container.with_env_variable(*plan.environment[0]).with_exec(
            list(plan.argv),
            redirect_stdout=plan.capture.process_stdout,
            redirect_stderr=plan.capture.stderr,
            expect=ReturnType.ANY,
        )

    def _configured_container(
        self, invocation: OrasInvocation, plan: ProviderExecutionPlan
    ) -> Container:
        if self.previous_container is not None:
            container = self._mount_invocation(self.previous_container, invocation)
            return container.with_directory(plan.capture.directory, self.client.directory())
        container = self._base_container()
        container = self._mount_invocation(container, invocation)
        return container.with_directory(plan.capture.directory, self.client.directory())

    def _base_container(self) -> Container:
        container = self.client.container().from_(ORAS_IMAGE)
        container = container.with_directory(WORKDIR, self.client.directory())
        container = container.with_workdir(WORKDIR)
        container = _mount_secret(container, self.registry_config)
        return _bind_service(container, self.repository, self.registry_service)

    def _mount_invocation(self, container: Container, invocation: OrasInvocation) -> Container:
        container = _mount_planned_inputs(container, self.client, invocation)
        if invocation.input_bytes:
            return self._mount_payloads(container)
        return container

    def _mount_payloads(self, container: Container) -> Container:
        if self.artifacts is not None:
            container = _mount_directory_files(container, self.artifacts, self.artifact_paths)
        if self.sboms is not None:
            container = _mount_directory_files(container, self.sboms, self.sbom_paths)
        return container

    def _retain_blob(self, invocation: OrasInvocation, content: bytes, code: int) -> None:
        if invocation.argv[1:3] == ("blob", "fetch") and code == 0:
            self.fetched_blobs[invocation.argv[-1]] = content


def _mount_planned_inputs(
    container: Container, client: Client, invocation: OrasInvocation
) -> Container:
    if not invocation.input_bytes:
        return container
    if len(invocation.input_bytes) != len(CORE_INPUT_PATHS):
        raise InvalidIdentity("ORAS push must carry exactly the three reviewed record inputs")
    for path, content in zip(CORE_INPUT_PATHS, invocation.input_bytes, strict=True):
        source = _text_file(client, path, content)
        container = container.with_mounted_file(f"{WORKDIR}/{path}", source)
    return container


def _text_file(client: Client, path: str, content: bytes) -> File:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InvalidIdentity("planned ORAS record input must be canonical UTF-8") from error
    return client.file(path, text)


def _mount_directory_files(
    container: Container, directory: Directory, paths: tuple[str, ...]
) -> Container:
    for path in paths:
        container = container.with_mounted_file(f"{WORKDIR}/{path}", directory.file(path))
    return container


def _mount_secret(container: Container, secret: Secret | None) -> Container:
    if secret is None:
        return container
    return container.with_mounted_secret(REGISTRY_CONFIG_PATH, secret, owner="0:0", mode=0o400)


def _bind_service(container: Container, repository: str, service: Service | None) -> Container:
    if service is None:
        return container
    return container.with_service_binding(_registry_host(repository), service)


def _registry_host(repository: str) -> str:
    authority = repository.split("/", 1)[0]
    return authority.rsplit(":", 1)[0]


def _execution_argv(
    argv: tuple[str, ...], has_registry_config: bool, has_registry_service: bool
) -> tuple[str, ...]:
    authenticated = _authenticated_argv(argv, has_registry_config)
    if not has_registry_service:
        return authenticated
    return _insert_provider_options(authenticated, ("--plain-http",))


def _execution_plan(
    invocation: OrasInvocation,
    attempt_id: str,
    ordinal: int,
    deadline_seconds: int,
    bindings: ProviderBindings = NO_PROVIDER_BINDINGS,
) -> ProviderExecutionPlan:
    validate_attempt_id(attempt_id)
    capture = _capture_paths(ordinal)
    provider = _execution_argv(invocation.argv, bindings.registry_config, bindings.registry_service)
    argv = _private_output_argv(provider, capture)
    return ProviderExecutionPlan(
        _deadline_argv(argv, deadline_seconds), ((ATTEMPT_ENV, attempt_id),), capture
    )


def _validate_observation(observation: ProviderObservation) -> None:
    _validate_observation_argv(observation.argv)
    _validate_observation_text(observation)
    _validate_observation_state(observation)
    _validate_capture_observation(observation.capture)


def _validate_observation_argv(argv: tuple[str, ...]) -> None:
    if not argv or len(argv) > MAX_OBSERVATION_ARGUMENTS:
        raise InvalidIdentity("provider observation argument count is outside its bound")


def _validate_observation_text(observation: ProviderObservation) -> None:
    texts = (*observation.argv, *(item for pair in observation.environment for item in pair))
    if any(len(item.encode()) > MAX_OBSERVATION_TEXT_BYTES for item in texts):
        raise InvalidIdentity("provider observation text exceeds its byte bound")


def _validate_observation_state(observation: ProviderObservation) -> None:
    if observation.environment != ((ATTEMPT_ENV, observation.attempt_id),):
        raise InvalidIdentity("provider observation must retain only the regular attempt variable")
    if observation.cache_mounts:
        raise InvalidIdentity("provider observation must not contain cache mounts")


def _validate_capture_observation(capture: CapturePaths) -> None:
    paths = (
        capture.directory,
        capture.stdout,
        capture.process_stdout,
        capture.stderr,
        capture.manifest,
    )
    if any(not item.startswith(f"{CAPTURE_ROOT}/") for item in paths):
        raise InvalidIdentity("provider observation capture escaped its private namespace")
    if any(len(item.encode()) > MAX_OBSERVATION_TEXT_BYTES for item in paths):
        raise InvalidIdentity("provider observation capture path exceeds its byte bound")


def _capture_paths(ordinal: int) -> CapturePaths:
    directory = f"{CAPTURE_ROOT}/{ordinal}"
    return CapturePaths(
        directory,
        f"{directory}/stdout",
        f"{directory}/process-stdout",
        f"{directory}/stderr",
        f"{directory}/manifest.json",
    )


def _private_output_argv(argv: tuple[str, ...], capture: CapturePaths) -> tuple[str, ...]:
    if argv[1:3] in {("manifest", "fetch"), ("blob", "fetch")}:
        return _insert_provider_options(argv, ("--output", capture.stdout))
    if _is_push(argv):
        return _replace_option(argv, "--export-manifest", capture.manifest)
    return argv


def _replace_option(argv: tuple[str, ...], option: str, value: str) -> tuple[str, ...]:
    index = argv.index(option) + 1
    return (*argv[:index], value, *argv[index + 1 :])


def _deadline_argv(argv: tuple[str, ...], seconds: int) -> tuple[str, ...]:
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 1:
        raise InvalidIdentity("provider execution deadline must be a positive integer")
    return ("/bin/sh", "-c", DEADLINE_SCRIPT, "deadline-wrapper", str(seconds), *argv)


def _authenticated_argv(argv: tuple[str, ...], has_registry_config: bool) -> tuple[str, ...]:
    if not has_registry_config:
        return argv
    return _insert_provider_options(argv, ("--registry-config", REGISTRY_CONFIG_PATH))


def _insert_provider_options(argv: tuple[str, ...], options: tuple[str, ...]) -> tuple[str, ...]:
    index = _reference_index(argv)
    return (*argv[:index], *options, *argv[index:])


def _reference_index(argv: tuple[str, ...]) -> int:
    if _is_push(argv):
        return argv.index("manifest.json") + 1
    return len(argv) - 1


def _is_push(argv: tuple[str, ...]) -> bool:
    return len(argv) > 1 and argv[1] == "push"


def _stdout_limit(invocation: OrasInvocation) -> int:
    command = invocation.argv[1:3]
    if command == ("manifest", "fetch"):
        return MAX_MANIFEST_BYTES
    if command == ("blob", "fetch"):
        return DEFAULT_OCI_RESOURCE_LIMITS.max_file_bytes
    return MAX_PROCESS_STDOUT_BYTES


def _provider_output_path(invocation: OrasInvocation, capture: CapturePaths) -> str:
    if invocation.argv[1:3] in {("manifest", "fetch"), ("blob", "fetch")}:
        return capture.stdout
    return capture.process_stdout


async def _execution_result(
    container: Container, invocation: OrasInvocation, plan: ProviderExecutionPlan
) -> OrasResult:
    exit_code = await container.exit_code()
    stdout = await _read_provider_stdout(container, invocation, plan)
    stderr = await _read_output(container, plan.capture.stderr, MAX_STDERR_BYTES)
    exported = await _exported_manifest(container, invocation, plan, exit_code)
    return _provider_result(invocation, exit_code, stdout, stderr, exported)


async def _read_provider_stdout(
    container: Container, invocation: OrasInvocation, plan: ProviderExecutionPlan
) -> bytes:
    path = _provider_output_path(invocation, plan.capture)
    return await _read_output(container, path, _stdout_limit(invocation))


async def _read_output(container: Container, path: str, limit: int) -> bytes:
    if not await container.exists(path):
        return b""
    size = await container.file(path).size()
    if size > limit:
        raise MalformedProviderResponse("ORAS provider output exceeded its response bound")
    chunks = [
        await _read_output_chunk(container, path, item) for item in _output_chunk_ordinals(size)
    ]
    content = b"".join(chunks)
    if len(content) != size:
        raise MalformedProviderResponse("ORAS provider output changed during bounded capture")
    return content


async def _read_output_chunk(container: Container, path: str, ordinal: int) -> bytes:
    argv = [
        "/bin/sh",
        "-c",
        CHUNK_READ_SCRIPT,
        "bounded-output-reader",
        path,
        str(OUTPUT_CHUNK_BYTES),
        str(ordinal),
    ]
    encoded = await container.with_exec(argv).stdout()
    try:
        return base64.b64decode(encoded)
    except ValueError as error:
        raise MalformedProviderResponse("ORAS provider output encoding was malformed") from error


def _output_chunk_ordinals(size: int) -> tuple[int, ...]:
    count = (size + OUTPUT_CHUNK_BYTES - 1) // OUTPUT_CHUNK_BYTES
    return tuple(range(count))


async def _exported_manifest(
    container: Container, invocation: OrasInvocation, plan: ProviderExecutionPlan, code: int
) -> bytes | None:
    path = plan.capture.manifest
    if code != 0 or not _is_push(invocation.argv) or not await container.exists(path):
        return None
    return await _read_output(container, path, MAX_MANIFEST_BYTES)


def _provider_result(
    invocation: OrasInvocation,
    code: int,
    stdout: bytes,
    stderr: bytes,
    exported: bytes | None,
) -> OrasResult:
    authoritative = exported if code == 0 and _is_push(invocation.argv) else None
    return OrasResult(code, _outcome(invocation, code, stderr), stdout, stderr, authoritative)


def _outcome(invocation: OrasInvocation, code: int, stderr: bytes) -> OrasOutcome:
    if code == 0:
        return OrasOutcome.SUCCESS
    if code == TIMEOUT_EXIT_CODE:
        return OrasOutcome.TIMEOUT
    if invocation.argv[1:3] == ("manifest", "fetch") and _is_not_found(stderr):
        return OrasOutcome.NOT_FOUND
    return OrasOutcome.FAILURE


def _is_not_found(stderr: bytes) -> bool:
    return any(pattern.fullmatch(stderr) is not None for pattern in NOT_FOUND_RESPONSES)


def _validate_successful_manifest(invocation: OrasInvocation, result: OrasResult) -> None:
    if invocation.argv[1:3] == ("manifest", "fetch") and result.outcome is OrasOutcome.SUCCESS:
        _validate_restore_manifest(result.stdout)


def _validate_restore_manifest(content: bytes) -> None:
    try:
        payload = parse_bounded_json(content, MAX_MANIFEST_BYTES)
        manifest = _RestoreManifest.model_validate(payload)
    except (ValidationError, ValueError) as error:
        raise MalformedProviderResponse("ORAS returned a malformed OCI manifest") from error
    _require_restore_descriptor_bounds((manifest.config, *manifest.layers))


def _require_restore_descriptor_bounds(descriptors: tuple[_RestoreDescriptor, ...]) -> None:
    sizes = tuple(item.size for item in descriptors)
    violation = DEFAULT_OCI_RESOURCE_LIMITS.evaluate(sizes).violation
    if violation is not None:
        raise MalformedProviderResponse(f"OCI resource limit violation: {violation.value}")


async def qualified_bundle(
    bundle: DaggerQualifiedEnvelope, scanner: DirectoryScanner
) -> EnvelopeBundle:
    return (await _qualified_bundle_outputs(bundle, scanner)).bundle


async def _qualified_bundle_outputs(
    bundle: DaggerQualifiedEnvelope, scanner: DirectoryScanner
) -> ValidatedBundleOutputs:
    records = await _validated_record_bytes(bundle)
    payload = parse_bounded_json(records.envelope, MAX_MANIFEST_BYTES)
    document = BuildEnvelopeDocument.model_validate(payload)
    qualification = QualificationRecordDocument.model_validate(
        parse_bounded_json(records.qualification, MAX_MANIFEST_BYTES)
    )
    _validate_retained_provenance(records, document)
    manifests = await _validate_output_directories(bundle, document, scanner)
    core = _reconstruct_bundle(
        bundle, document, qualification, records.envelope, records.qualification
    )
    return ValidatedBundleOutputs(core, *manifests)


async def _validated_record_bytes(bundle: DaggerQualifiedEnvelope) -> RetainedRecordBytes:
    envelope = await _bounded_file_bytes(bundle.envelope, MAX_MANIFEST_BYTES)
    qualification = await _bounded_file_bytes(bundle.qualification, MAX_MANIFEST_BYTES)
    snapshot = await _bounded_file_bytes(bundle.input_snapshot_manifest, MAX_MANIFEST_BYTES)
    evidence = await _bounded_file_bytes(bundle.prequalification_evidence, MAX_MANIFEST_BYTES)
    _require_digest(envelope, bundle.envelope_sha256, "envelope")
    _require_digest(qualification, bundle.qualification_sha256, "qualification")
    _require_digest(snapshot, bundle.input_snapshot_sha256, "input snapshot manifest")
    _require_digest(evidence, bundle.prequalification_evidence_sha256, "prequalification evidence")
    return RetainedRecordBytes(envelope, qualification, snapshot, evidence)


def _validate_retained_provenance(
    records: RetainedRecordBytes,
    document: BuildEnvelopeDocument,
) -> None:
    evidence = PrequalificationEvidenceDocument.model_validate(
        parse_bounded_json(records.prequalification_evidence, MAX_MANIFEST_BYTES)
    )
    if evidence.evidence != document.prequalification_evidence:
        raise InvalidIdentity("retained evidence must match canonical envelope declarations")


async def _bounded_file_bytes(file: File, limit: int) -> bytes:
    if await file.size() > limit:
        raise InvalidIdentity("Dagger record exceeds its configured byte bound")
    content = (await file.contents()).encode()
    if len(content) > limit:
        raise InvalidIdentity("Dagger record exceeds its configured byte bound")
    return content


def _require_digest(content: bytes, digest: str, name: str) -> None:
    if Sha256Digest.from_bytes(content).value != digest:
        raise InvalidIdentity(f"{name} bytes must match their retained digest")


async def _validate_output_directories(
    bundle: DaggerQualifiedEnvelope,
    document: BuildEnvelopeDocument,
    scanner: DirectoryScanner,
) -> tuple[FileManifest, FileManifest]:
    artifacts = await scanner(bundle.artifacts)
    sboms = await scanner(bundle.sboms)
    _require_artifact_records(artifacts, document)
    _require_sbom_records(sboms, document)
    return artifacts, sboms


def _require_artifact_records(manifest: FileManifest, document: BuildEnvelopeDocument) -> None:
    expected = {item.path: (item.size, item.sha256) for item in document.artifacts}
    observed = {item.path: (item.size, item.sha256) for item in manifest.files}
    if observed != expected:
        raise InvalidIdentity("artifact directory bytes must match the canonical envelope")


def _require_sbom_records(manifest: FileManifest, document: BuildEnvelopeDocument) -> None:
    expected = {item.path: item.sha256 for item in document.sboms}
    observed = {item.path: item.sha256 for item in manifest.files}
    if observed != expected:
        raise InvalidIdentity("SBOM directory bytes must match the canonical envelope")


def _reconstruct_bundle(
    dto: DaggerQualifiedEnvelope,
    document: BuildEnvelopeDocument,
    qualification: QualificationRecordDocument,
    envelope_bytes: bytes,
    qualification_bytes: bytes,
) -> EnvelopeBundle:
    signed = _signed_state(dto, document)
    envelope = EnvelopeBuilder(_metadata(document)).build(signed)
    _require_exact_envelope(envelope, envelope_bytes)
    checks = tuple(_evidence(item) for item in qualification.qualification_evidence)
    record = QualificationBuilder().build(envelope, checks)
    _require_exact_qualification(record, qualification_bytes)
    qualified = QualifiedEnvelope(envelope, record)
    return EnvelopeBundle(qualified, _artifacts(document), _sboms(document))


def _metadata(document: BuildEnvelopeDocument) -> EnvelopeMetadata:
    policy = document.release_policy
    compatibility = document.compatibility
    release_policy = ReleasePolicyMetadata(
        policy.version, tuple(ReleaseChannel(item) for item in policy.channels)
    )
    return EnvelopeMetadata(
        ProjectAdapterVersion(document.project_adapter_version),
        document.source_date_epoch,
        release_policy,
        PinnedCompatibility(compatibility.dagger, compatibility.oras),
    )


def _signed_state(dto: DaggerQualifiedEnvelope, document: BuildEnvelopeDocument) -> SignedBuild:
    artifacts = _artifacts(document)
    signature = _signature(artifacts, dto.signature_path)
    disposition = SigningDisposition(dto.signing_disposition)
    _require_signing_coherence(signature, disposition)
    unsigned = _unsigned_state(dto, document, artifacts, signature)
    evidence = tuple(_evidence(item) for item in document.prequalification_evidence)
    return SignedBuild(PrequalifiedBuild(unsigned, evidence), signature, disposition)


def _unsigned_state(
    dto: DaggerQualifiedEnvelope,
    document: BuildEnvelopeDocument,
    artifacts: tuple[Artifact, ...],
    signature: Artifact | None,
) -> UnsignedBuild:
    unsigned_artifacts = tuple(item for item in artifacts if item != signature)
    return UnsignedBuild(
        _snapshot(document, dto.input_snapshot_sha256),
        unsigned_artifacts,
        _sboms(document),
        tuple(_lock(item) for item in document.locks),
        tuple(_toolchain(item) for item in document.toolchains),
    )


def _snapshot(document: BuildEnvelopeDocument, input_snapshot: str) -> SnapshottedSource:
    source = document.source
    project = ProjectId(source.project)
    digest = Sha256Digest(source.source_tree_sha256)
    revision = SourceRevision(
        project, source.repository, source.protected_ref, source.commit_sha, digest
    )
    key = f"{source.project}:{document.release_policy.version}"
    release_id = ReleaseId(project, document.release_policy.version, digest, key)
    return SnapshottedSource(ReleaseSource(release_id, revision), Sha256Digest(input_snapshot))


def _signature(artifacts: tuple[Artifact, ...], path: str | None) -> Artifact | None:
    if path is None:
        return None
    matches = tuple(item for item in artifacts if item.path.value == path)
    if len(matches) != 1:
        raise InvalidIdentity("signature path must identify one canonical artifact")
    return matches[0]


def _require_signing_coherence(signature: Artifact | None, disposition: SigningDisposition) -> None:
    if (signature is not None) != (disposition is SigningDisposition.SIGNED):
        raise InvalidIdentity("retained signing disposition must match canonical artifacts")


def _require_exact_envelope(envelope: BuildEnvelope, content: bytes) -> None:
    if envelope.canonical_bytes != content:
        raise InvalidIdentity("reconstructed domain graph must match canonical envelope bytes")


def _require_exact_qualification(record: QualificationRecord, content: bytes) -> None:
    if record.canonical_bytes != content:
        message = "reconstructed qualification must match canonical qualification bytes"
        raise InvalidIdentity(message)


def _artifacts(document: BuildEnvelopeDocument) -> tuple[Artifact, ...]:
    return tuple(
        Artifact(
            item.name,
            ArtifactPath(item.path),
            item.media_type,
            item.size,
            Sha256Digest(item.sha256),
        )
        for item in document.artifacts
    )


def _sboms(document: BuildEnvelopeDocument) -> tuple[Sbom, ...]:
    return tuple(
        Sbom(
            ArtifactPath(item.artifact_path),
            ArtifactPath(item.path),
            item.media_type,
            item.size,
            Sha256Digest(item.sha256),
        )
        for item in document.sboms
    )


def _lock(document: LockDocument) -> LockIdentity:
    return LockIdentity(ArtifactPath(document.path), Sha256Digest(document.sha256))


def _toolchain(document: ToolchainDocument) -> ToolchainIdentity:
    return ToolchainIdentity(document.name, document.version, Sha256Digest(document.sha256))


def _evidence(document: EvidenceDocument) -> Evidence:
    return Evidence(
        document.kind,
        document.name,
        Sha256Digest(document.subject),
        EvidenceStatus(document.status),
    )


async def persist_qualified_bundle(
    bundle: DaggerQualifiedEnvelope,
    scanner: DirectoryScanner,
    runner_factory: RunnerFactory,
    repository: str,
    attempt_id: str,
) -> StoredEnvelope:
    validated = await _qualified_bundle_outputs(bundle, scanner)
    runner = runner_factory(validated.bundle)
    adapter = OrasAdapter(runner, repository)
    stored = await adapter.persist(validated.bundle, attempt_id)
    return stored_dto(stored, cast(DaggerOrasRunner, runner))


def stored_dto(stored: CoreStoredEnvelope, runner: DaggerOrasRunner) -> StoredEnvelope:
    reference = stored.reference
    return StoredEnvelope(
        envelope_uri=f"{reference.repository}:{reference.tag}",
        envelope_digest=stored.manifest_sha256.value,
        provider_execution_count=runner.execution_count,
        provider_inspection_count=runner.inspection_count,
        provider_push_count=runner.push_count,
        attempt_ids=_attempt_ids(runner),
    )


def restored_dto(
    runner: DaggerOrasRunner,
    release_id: str,
    envelope_uri: str,
    envelope_digest: str,
    bundle: EnvelopeBundle,
) -> QualifiedEnvelopeRef:
    identity = (release_id, envelope_uri, envelope_digest)
    return _restored_ref(runner, identity, bundle)


def _restored_ref(
    runner: DaggerOrasRunner, identity: tuple[str, str, str], bundle: EnvelopeBundle
) -> QualifiedEnvelopeRef:
    release, uri, digest = identity
    client = runner.client
    qualified = bundle.qualified
    return QualifiedEnvelopeRef(
        release_id=release,
        envelope_uri=uri,
        envelope_digest=digest,
        envelope=_bytes_file(
            client,
            "build-envelope.v1.json",
            qualified.envelope.canonical_bytes,
            qualified.envelope.content_sha256.value,
        ),
        qualification=_bytes_file(
            client,
            "qualification-record.v1.json",
            qualified.qualification.canonical_bytes,
            qualified.qualification.content_sha256.value,
        ),
        artifacts=_record_directory(client, runner, bundle, artifacts=True),
        sboms=_record_directory(client, runner, bundle, artifacts=False),
        provider_execution_count=runner.execution_count,
        provider_inspection_count=runner.inspection_count,
        provider_push_count=runner.push_count,
        attempt_ids=_attempt_ids(runner),
    )


def _attempt_ids(runner: DaggerOrasRunner) -> list[str]:
    return [item.attempt_id for item in runner.observations]


def _record_directory(
    client: Client, runner: DaggerOrasRunner, bundle: EnvelopeBundle, *, artifacts: bool
) -> Directory:
    records = bundle.artifacts if artifacts else bundle.sboms
    directory = client.directory()
    for record in records:
        path = record.path.value
        content = _restored_content(runner, record.sha256.value)
        directory = directory.with_file(
            path, _bytes_file(client, path, content, record.sha256.value)
        )
    return directory


def _restored_content(runner: DaggerOrasRunner, digest: str) -> bytes:
    reference = f"{runner.repository}@{digest}"
    try:
        return runner.fetched_blobs[reference]
    except KeyError as error:
        raise InvalidIdentity("restored provider blob bytes were not retained") from error


def _bytes_file(client: Client, name: str, content: bytes, digest: str) -> File:
    chunks = _encoded_chunks(content, digest)
    if not chunks:
        return client.file(PurePosixPath(name).name, "")
    container = _empty_restore_container(client)
    for chunk in chunks:
        container = _append_encoded_chunk(client, container, chunk)
    return container.file(f"{RESTORE_ROOT}/output")


def _encoded_chunks(content: bytes, digest: str) -> tuple[EncodedChunk, ...]:
    _require_restored_digest(content, digest)
    pieces = tuple(
        content[offset : offset + OUTPUT_CHUNK_BYTES]
        for offset in range(0, len(content), OUTPUT_CHUNK_BYTES)
    )
    count = len(pieces)
    chunks = tuple(_encoded_chunk(item, ordinal, count) for ordinal, item in enumerate(pieces))
    _validate_encoded_chunks(chunks, content, digest)
    return chunks


def _encoded_chunk(content: bytes, ordinal: int, count: int) -> EncodedChunk:
    return EncodedChunk(ordinal, count, len(content), base64.b64encode(content).decode("ascii"))


def _validate_encoded_chunks(chunks: tuple[EncodedChunk, ...], content: bytes, digest: str) -> None:
    _validate_chunk_sequence(chunks)
    decoded = tuple(_decoded_chunk(item) for item in chunks)
    _validate_chunk_sizes(decoded)
    _validate_decoded_stream(decoded, content, digest)


def _validate_chunk_sequence(chunks: tuple[EncodedChunk, ...]) -> None:
    expected = tuple(range(len(chunks)))
    if tuple(item.ordinal for item in chunks) != expected:
        raise InvalidIdentity("restored transfer chunk ordinals were not contiguous")
    if any(item.count != len(chunks) for item in chunks):
        raise InvalidIdentity("restored transfer chunk count was inconsistent")


def _validate_chunk_sizes(decoded: tuple[bytes, ...]) -> None:
    if not decoded:
        return
    if any(len(item) != OUTPUT_CHUNK_BYTES for item in decoded[:-1]):
        raise InvalidIdentity("restored transfer nonfinal chunk length was invalid")
    if not 0 < len(decoded[-1]) <= OUTPUT_CHUNK_BYTES:
        raise InvalidIdentity("restored transfer final chunk length was invalid")


def _validate_decoded_stream(decoded: tuple[bytes, ...], content: bytes, digest: str) -> None:
    reconstructed = b"".join(decoded)
    if len(reconstructed) != len(content):
        raise InvalidIdentity("restored transfer chunk lengths did not cover provider bytes")
    if reconstructed != content:
        raise InvalidIdentity("restored transfer chunks changed provider bytes")
    _require_restored_digest(reconstructed, digest)


def _decoded_chunk(chunk: EncodedChunk) -> bytes:
    try:
        decoded = base64.b64decode(chunk.encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidIdentity("restored transfer chunk encoding was malformed") from error
    if len(decoded) != chunk.decoded_length or len(decoded) > OUTPUT_CHUNK_BYTES:
        raise InvalidIdentity("restored transfer chunk length was invalid")
    return decoded


def _require_restored_digest(content: bytes, digest: str) -> None:
    if Sha256Digest.from_bytes(content).value != Sha256Digest(digest).value:
        raise InvalidIdentity("restored transfer bytes differ from their descriptor digest")


def _empty_restore_container(client: Client) -> Container:
    output = f"{RESTORE_ROOT}/output"
    command = ["sh", "-c", 'mkdir -p "$1"; : > "$2"', "init", RESTORE_ROOT, output]
    return client.container().from_(ORAS_IMAGE).with_exec(command)


def _append_encoded_chunk(client: Client, container: Container, chunk: EncodedChunk) -> Container:
    path = f"{RESTORE_ROOT}/chunk-{chunk.ordinal}.base64"
    source = client.file(f"chunk-{chunk.ordinal}.base64", chunk.encoded)
    command = ["sh", "-c", 'base64 -d "$1" >> "$2"', "append", path, f"{RESTORE_ROOT}/output"]
    return container.with_mounted_file(path, source).with_exec(command)


def parse_reference(envelope_uri: str, envelope_digest: str) -> OciReference:
    if ":" not in envelope_uri:
        raise InvalidIdentity("envelope URI must include an immutable content tag")
    repository, tag = envelope_uri.rsplit(":", 1)
    return OciReference(repository, tag, Sha256Digest(envelope_digest))


def validate_release_id(bundle: EnvelopeBundle, release_id: str) -> None:
    actual = bundle.qualified.envelope.signed.prequalified.unsigned.source.release.release_id
    if actual.idempotency_key != release_id:
        raise InvalidIdentity("release ID must match restored canonical provenance")
