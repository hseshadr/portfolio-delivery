"""Pure ORAS command planning and immutable generic-OCI reconciliation.

The injected runner owns authentication, mounted payload files, and execution. Push
results surface the exact ``--export-manifest`` bytes through ``OrasResult.stdout``;
manifest and blob fetches likewise return their exact bytes through stdout.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, NoReturn

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from portfolio_delivery.contracts.storage import OrasRunner
from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    EvidenceStatus,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
)
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
    OrasResult,
    PrequalifiedBuild,
    QualificationRecord,
    QualifiedEnvelope,
    ReleaseSource,
    SignedBuild,
    SigningDisposition,
    SnapshottedSource,
    StoredEnvelope,
    UnsignedBuild,
    validate_attempt_id,
)
from portfolio_delivery.envelope.canonical import canonical_json_bytes
from portfolio_delivery.envelope.documents import (
    BUILD_ENVELOPE_MEDIA_TYPE,
    CONFIG_MEDIA_TYPE,
    QUALIFICATION_MEDIA_TYPE,
    ArtifactDocument,
    BuildEnvelopeDocument,
    EvidenceDocument,
    LockDocument,
    OciConfigDocument,
    QualificationRecordDocument,
    SbomDocument,
    ToolchainDocument,
)

ARTIFACT_TYPE: Final[str] = "application/vnd.hseshadr.portfolio-delivery.envelope.v1"
MANIFEST_MEDIA_TYPE: Final[str] = "application/vnd.oci.image.manifest.v1+json"
TITLE_ANNOTATION: Final[str] = "org.opencontainers.image.title"
CREATED_ANNOTATION: Final[str] = "org.opencontainers.image.created"
MAX_MANIFEST_BYTES: Final[int] = 1_048_576
MAX_STDERR_BYTES: Final[int] = 65_536
MAX_REPOSITORY_LENGTH: Final[int] = 255
MAX_TAG_LENGTH: Final[int] = 128
MAX_PATH_LENGTH: Final[int] = 4_096
MAX_MEDIA_TYPE_LENGTH: Final[int] = 255
TIMEOUT_EXIT_CODE: Final[int] = 124
REQUIRED_CORE_LAYERS: Final[int] = 2
_REPOSITORY: Final = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
)
_TAG: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")


class OrasAdapterError(RuntimeError):
    """Base failure for explicit ORAS provider interactions."""


class ProviderTimeoutError(OrasAdapterError):
    """The provider did not complete within its execution deadline."""


class ProviderUnavailableError(OrasAdapterError):
    """The provider could not authoritatively answer the request."""


class MalformedProviderResponseError(OrasAdapterError):
    """Provider output violated the bounded OCI response contract."""


class ArtifactConflictError(OrasAdapterError):
    """An immutable content tag already names different provider bytes."""


ProviderTimeout = ProviderTimeoutError
ProviderUnavailable = ProviderUnavailableError
MalformedProviderResponse = MalformedProviderResponseError
ArtifactConflict = ArtifactConflictError


class _BoundaryModel(BaseModel):  # type: ignore[explicit-any]
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


class _Descriptor(_BoundaryModel):  # type: ignore[explicit-any]
    media_type: str = Field(alias="mediaType", min_length=1, max_length=MAX_MEDIA_TYPE_LENGTH)
    digest: str
    size: int = Field(ge=0, strict=True)
    annotations: Mapping[str, str] = Field(default_factory=dict)

    @field_validator("digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        return Sha256Digest(value).value

    @property
    def title(self) -> str | None:
        return self.annotations.get(TITLE_ANNOTATION)


class _Manifest(_BoundaryModel):  # type: ignore[explicit-any]
    schema_version: Literal[2] = Field(alias="schemaVersion")
    media_type: Literal["application/vnd.oci.image.manifest.v1+json"] = Field(alias="mediaType")
    artifact_type: Literal["application/vnd.hseshadr.portfolio-delivery.envelope.v1"] = Field(
        alias="artifactType"
    )
    config: _Descriptor
    layers: tuple[_Descriptor, ...]
    annotations: Mapping[str, str] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _Observation:
    content: bytes
    digest: Sha256Digest
    manifest: _Manifest


@dataclass(frozen=True, slots=True)
class _ExpectedLayer:
    path: str
    media_type: str
    digest: Sha256Digest
    size: int | None
    exact_bytes: bytes | None = None


@dataclass(frozen=True, slots=True)
class OrasAdapter:
    """Plan and reconcile one immutable generic-OCI envelope repository."""

    runner: OrasRunner
    repository: str

    def __post_init__(self) -> None:
        _validate_repository(self.repository)

    def plan_push(self, bundle: EnvelopeBundle) -> OrasInvocation:
        layers = _expected_layers(bundle)
        _validate_expected_layers(layers)
        return OrasInvocation(_push_argv(self.repository, bundle, layers), _input_bytes(bundle))

    async def inspect(self, reference: OciReference, attempt_id: str) -> StoredEnvelope | None:
        validate_attempt_id(attempt_id)
        _validate_reference(reference)
        observation = await self._observe_tag(reference, attempt_id)
        return _stored(reference, observation)

    async def persist(self, bundle: EnvelopeBundle, attempt_id: str) -> StoredEnvelope:
        validate_attempt_id(attempt_id)
        reference = _content_reference(bundle, self.repository)
        existing = await self._observe_tag(reference, attempt_id)
        if existing is not None:
            await self._require_bundle(existing, bundle, attempt_id, ArtifactConflict)
            return _stored_required(reference, existing)
        return await self._push_and_reconcile(bundle, reference, attempt_id)

    async def restore(self, reference: OciReference, attempt_id: str) -> EnvelopeBundle:
        validate_attempt_id(attempt_id)
        _validate_reference(reference)
        observation = await self._observe_tag(reference, attempt_id)
        if observation is None:
            raise ProviderUnavailable("OCI envelope manifest was not found")
        return await self._restore_observation(observation, reference.repository, attempt_id)

    async def _push_and_reconcile(
        self, bundle: EnvelopeBundle, reference: OciReference, attempt_id: str
    ) -> StoredEnvelope:
        try:
            exported = await self._push(bundle, attempt_id)
        except ProviderTimeout as timeout:
            return await self._recover_timeout(bundle, reference, attempt_id, timeout)
        observed = await self._observe_digest(exported, self.repository, attempt_id)
        await self._require_bundle(observed, bundle, attempt_id, MalformedProviderResponse)
        return _stored_required(reference, observed)

    async def _push(self, bundle: EnvelopeBundle, attempt_id: str) -> _Observation:
        result = await self.runner.run(self.plan_push(bundle), attempt_id)
        content = _successful_stdout(result, MAX_MANIFEST_BYTES)
        return _parse_manifest(content)

    async def _recover_timeout(
        self,
        bundle: EnvelopeBundle,
        reference: OciReference,
        attempt_id: str,
        error: ProviderTimeoutError,
    ) -> StoredEnvelope:
        observed = await self._observe_tag(reference, attempt_id)
        if observed is None:
            raise error
        await self._require_bundle(observed, bundle, attempt_id, ArtifactConflict)
        return _stored_required(reference, observed)

    async def _observe_tag(self, reference: OciReference, attempt_id: str) -> _Observation | None:
        result = await self.runner.run(_manifest_fetch(_tag_reference(reference)), attempt_id)
        content = _manifest_stdout_or_none(result)
        if content is None:
            return None
        observation = _parse_manifest(content)
        _require_declared_manifest(reference, observation.digest)
        return await self._observe_digest(observation, reference.repository, attempt_id)

    async def _observe_digest(
        self, expected: _Observation, repository: str, attempt_id: str
    ) -> _Observation:
        reference = f"{repository}@{expected.digest.value}"
        result = await self.runner.run(_manifest_fetch(reference), attempt_id)
        content = _successful_stdout(result, MAX_MANIFEST_BYTES)
        if content != expected.content:
            raise MalformedProviderResponse("manifest bytes differ at digest reference")
        return _parse_manifest(content)

    async def _require_bundle(
        self,
        observation: _Observation,
        bundle: EnvelopeBundle,
        attempt_id: str,
        conflict_type: type[OrasAdapterError],
    ) -> None:
        expected = _expected_layers(bundle)
        _require_created_annotation(observation.manifest, bundle, conflict_type)
        _require_descriptors(observation.manifest, expected, conflict_type)
        await self._require_blobs(observation, expected, attempt_id, conflict_type)

    async def _require_blobs(
        self,
        observation: _Observation,
        expected: tuple[_ExpectedLayer, ...],
        attempt_id: str,
        conflict_type: type[OrasAdapterError],
    ) -> None:
        descriptors = (observation.manifest.config, *observation.manifest.layers)
        for descriptor, layer in zip(descriptors, expected, strict=True):
            content = await self._fetch_blob(descriptor, self.repository, attempt_id)
            _require_blob(content, layer, conflict_type)

    async def _fetch_blob(self, descriptor: _Descriptor, repository: str, attempt_id: str) -> bytes:
        reference = f"{repository}@{descriptor.digest}"
        result = await self.runner.run(_blob_fetch(reference), attempt_id)
        return _successful_stdout(result, descriptor.size)

    async def _restore_observation(
        self, observation: _Observation, repository: str, attempt_id: str
    ) -> EnvelopeBundle:
        descriptors = (observation.manifest.config, *observation.manifest.layers)
        contents = tuple(
            [await self._fetch_blob(item, repository, attempt_id) for item in descriptors]
        )
        _require_descriptor_bytes(descriptors, contents)
        return _restore_bundle(observation.manifest, contents)


def _validate_repository(repository: str) -> None:
    if len(repository) > MAX_REPOSITORY_LENGTH or _REPOSITORY.fullmatch(repository) is None:
        raise ValueError("OCI repository must be a bounded canonical repository name")


def _validate_reference(reference: OciReference) -> None:
    _validate_repository(reference.repository)
    if len(reference.tag) > MAX_TAG_LENGTH or _TAG.fullmatch(reference.tag) is None:
        raise ValueError("OCI tag must be a bounded canonical tag")


def _validate_expected_layers(layers: tuple[_ExpectedLayer, ...]) -> None:
    if len({item.path for item in layers}) != len(layers):
        raise ValueError("OCI layer paths must be unique")
    for item in layers:
        _validate_layer_text(item)


def _validate_layer_text(layer: _ExpectedLayer) -> None:
    if len(layer.path) > MAX_PATH_LENGTH or layer.path.startswith("/"):
        raise ValueError("OCI layer path must be bounded and relative to /work")
    ArtifactPath(layer.path)
    if len(layer.media_type) > MAX_MEDIA_TYPE_LENGTH:
        raise ValueError("OCI layer media type must be bounded")


def _content_reference(bundle: EnvelopeBundle, repository: str) -> OciReference:
    digest = bundle.qualified.envelope.content_sha256
    return OciReference(repository, f"sha256-{digest.hex}")


def _push_argv(
    repository: str, bundle: EnvelopeBundle, layers: tuple[_ExpectedLayer, ...]
) -> tuple[str, ...]:
    reference = _content_reference(bundle, repository)
    layer_specs = tuple(f"{item.path}:{item.media_type}" for item in layers[1:])
    return (*_push_prefix(bundle), f"{repository}:{reference.tag}", *layer_specs)


def _push_prefix(bundle: EnvelopeBundle) -> tuple[str, ...]:
    return (
        "oras",
        "push",
        "--artifact-type",
        ARTIFACT_TYPE,
        "--config",
        f"config.v1.json:{CONFIG_MEDIA_TYPE}",
        "--concurrency",
        "1",
        "--annotation",
        _created_annotation(bundle),
        "--export-manifest",
        "manifest.json",
    )


def _created_annotation(bundle: EnvelopeBundle) -> str:
    return f"{CREATED_ANNOTATION}={_created_timestamp(bundle)}"


def _created_timestamp(bundle: EnvelopeBundle) -> str:
    content = bundle.qualified.envelope.canonical_bytes
    source_date_epoch = _parse_envelope(content).source_date_epoch
    try:
        created = datetime.fromtimestamp(source_date_epoch, UTC)
    except (OSError, OverflowError, ValueError) as error:
        raise ValueError("sourceDateEpoch must fit a canonical UTC timestamp") from error
    return created.isoformat(timespec="seconds").replace("+00:00", "Z")


def _input_bytes(bundle: EnvelopeBundle) -> tuple[bytes, ...]:
    return (
        canonical_json_bytes(OciConfigDocument()),
        bundle.qualified.envelope.canonical_bytes,
        bundle.qualified.qualification.canonical_bytes,
    )


def _expected_layers(bundle: EnvelopeBundle) -> tuple[_ExpectedLayer, ...]:
    envelope = bundle.qualified.envelope.canonical_bytes
    qualification = bundle.qualified.qualification.canonical_bytes
    return (
        _exact_layer(
            "config.v1.json", CONFIG_MEDIA_TYPE, canonical_json_bytes(OciConfigDocument())
        ),
        _exact_layer("build-envelope.v1.json", BUILD_ENVELOPE_MEDIA_TYPE, envelope),
        _exact_layer("qualification-record.v1.json", QUALIFICATION_MEDIA_TYPE, qualification),
        *tuple(_artifact_layer(item) for item in bundle.artifacts),
        *tuple(_sbom_layer(item) for item in bundle.sboms),
    )


def _exact_layer(path: str, media_type: str, content: bytes) -> _ExpectedLayer:
    return _ExpectedLayer(path, media_type, Sha256Digest.from_bytes(content), len(content), content)


def _artifact_layer(artifact: Artifact) -> _ExpectedLayer:
    return _ExpectedLayer(
        artifact.path.value,
        artifact.media_type,
        artifact.sha256,
        artifact.size,
    )


def _sbom_layer(sbom: Sbom) -> _ExpectedLayer:
    return _ExpectedLayer(sbom.path.value, sbom.media_type, sbom.sha256, None)


def _manifest_fetch(reference: str) -> OrasInvocation:
    return OrasInvocation(("oras", "manifest", "fetch", reference))


def _blob_fetch(reference: str) -> OrasInvocation:
    return OrasInvocation(("oras", "blob", "fetch", reference))


def _manifest_stdout_or_none(result: OrasResult) -> bytes | None:
    _require_bounded_stderr(result)
    if result.exit_code == 0:
        return _bounded_stdout(result.stdout, MAX_MANIFEST_BYTES)
    if result.exit_code == 1 and _is_not_found(result.stderr):
        return None
    _raise_result_error(result)


def _successful_stdout(result: OrasResult, limit: int) -> bytes:
    _require_bounded_stderr(result)
    if result.exit_code != 0:
        _raise_result_error(result)
    return _bounded_stdout(result.stdout, limit)


def _require_bounded_stderr(result: OrasResult) -> None:
    if len(result.stderr) > MAX_STDERR_BYTES:
        raise MalformedProviderResponse("ORAS stderr exceeded its response bound")


def _bounded_stdout(content: bytes, limit: int) -> bytes:
    if len(content) > limit:
        raise MalformedProviderResponse("ORAS stdout exceeded its response bound")
    return content


def _raise_result_error(result: OrasResult) -> NoReturn:
    if result.exit_code == TIMEOUT_EXIT_CODE:
        raise ProviderTimeout("ORAS provider execution timed out")
    raise ProviderUnavailable("ORAS provider execution failed")


def _is_not_found(stderr: bytes) -> bool:
    lowered = stderr.lower()
    return b"not found" in lowered or b"manifest unknown" in lowered


def _parse_manifest(content: bytes) -> _Observation:
    bounded = _bounded_stdout(content, MAX_MANIFEST_BYTES)
    try:
        manifest = _Manifest.model_validate_json(bounded)
    except ValidationError as error:
        raise MalformedProviderResponse("ORAS returned a malformed OCI manifest") from error
    _validate_manifest_layers(manifest)
    return _Observation(bounded, Sha256Digest.from_bytes(bounded), manifest)


def _validate_manifest_layers(manifest: _Manifest) -> None:
    if manifest.config.media_type != CONFIG_MEDIA_TYPE:
        raise MalformedProviderResponse("OCI manifest has an unexpected config media type")
    if len(manifest.layers) < REQUIRED_CORE_LAYERS:
        raise MalformedProviderResponse("OCI manifest is missing required envelope layers")
    _require_core_layer(manifest.layers[0], "build-envelope.v1.json", BUILD_ENVELOPE_MEDIA_TYPE)
    _require_core_layer(
        manifest.layers[1], "qualification-record.v1.json", QUALIFICATION_MEDIA_TYPE
    )
    _require_unique_layer_titles(manifest.layers)


def _require_core_layer(descriptor: _Descriptor, title: str, media_type: str) -> None:
    if _normalized_title(descriptor.title) != title or descriptor.media_type != media_type:
        raise MalformedProviderResponse("OCI manifest has an unexpected required layer")


def _require_unique_layer_titles(layers: tuple[_Descriptor, ...]) -> None:
    titles = tuple(item.title for item in layers)
    if None in titles or len(titles) != len(set(titles)):
        raise MalformedProviderResponse("OCI manifest has missing or duplicate layer titles")


def _require_declared_manifest(reference: OciReference, digest: Sha256Digest) -> None:
    if reference.manifest_sha256 is not None and reference.manifest_sha256 != digest:
        raise ArtifactConflict("declared OCI manifest digest conflicts with provider bytes")


def _require_created_annotation(
    manifest: _Manifest,
    bundle: EnvelopeBundle,
    conflict_type: type[OrasAdapterError],
) -> None:
    created = manifest.annotations.get(CREATED_ANNOTATION)
    if created != _created_timestamp(bundle) or len(manifest.annotations) != 1:
        raise conflict_type("OCI manifest has conflicting deterministic annotations")


def _require_descriptors(
    manifest: _Manifest,
    expected: tuple[_ExpectedLayer, ...],
    conflict_type: type[OrasAdapterError],
) -> None:
    descriptors = (manifest.config, *manifest.layers)
    if len(descriptors) != len(expected):
        raise conflict_type("OCI content tag has a conflicting layer set")
    for descriptor, layer in zip(descriptors, expected, strict=True):
        _require_descriptor(descriptor, layer, conflict_type)


def _require_descriptor(
    descriptor: _Descriptor,
    expected: _ExpectedLayer,
    conflict_type: type[OrasAdapterError],
) -> None:
    identity = (_normalized_title(descriptor.title), descriptor.media_type, descriptor.digest)
    wanted = (_expected_title(expected), expected.media_type, expected.digest.value)
    if identity != wanted or (expected.size is not None and descriptor.size != expected.size):
        raise conflict_type("OCI content tag has conflicting descriptor bytes")


def _expected_title(expected: _ExpectedLayer) -> str | None:
    if expected.path == "config.v1.json":
        return None
    return expected.path


def _normalized_title(title: str | None) -> str | None:
    if title is None:
        return None
    return title.removeprefix("/work/")


def _require_blob(
    content: bytes, expected: _ExpectedLayer, conflict_type: type[OrasAdapterError]
) -> None:
    _require_blob_digest(content, expected, conflict_type)
    _require_blob_size(content, expected, conflict_type)
    _require_exact_blob(content, expected, conflict_type)


def _require_blob_digest(
    content: bytes, expected: _ExpectedLayer, conflict_type: type[OrasAdapterError]
) -> None:
    if Sha256Digest.from_bytes(content) != expected.digest:
        raise conflict_type("OCI provider returned conflicting blob bytes")


def _require_blob_size(
    content: bytes, expected: _ExpectedLayer, conflict_type: type[OrasAdapterError]
) -> None:
    if expected.size is not None and len(content) != expected.size:
        raise conflict_type("OCI provider returned a conflicting blob size")


def _require_exact_blob(
    content: bytes, expected: _ExpectedLayer, conflict_type: type[OrasAdapterError]
) -> None:
    if expected.exact_bytes is not None and content != expected.exact_bytes:
        raise conflict_type("OCI provider returned non-identical reviewed bytes")


def _require_descriptor_bytes(
    descriptors: tuple[_Descriptor, ...], contents: tuple[bytes, ...]
) -> None:
    for descriptor, content in zip(descriptors, contents, strict=True):
        digest_differs = Sha256Digest.from_bytes(content).value != descriptor.digest
        if len(content) != descriptor.size or digest_differs:
            raise MalformedProviderResponse("OCI blob bytes do not match their descriptor")


def _stored(reference: OciReference, observation: _Observation | None) -> StoredEnvelope | None:
    if observation is None:
        return None
    return _stored_required(reference, observation)


def _stored_required(reference: OciReference, observation: _Observation) -> StoredEnvelope:
    pinned = OciReference(reference.repository, reference.tag, observation.digest)
    return StoredEnvelope(pinned, observation.digest)


def _tag_reference(reference: OciReference) -> str:
    return f"{reference.repository}:{reference.tag}"


def _restore_bundle(manifest: _Manifest, contents: tuple[bytes, ...]) -> EnvelopeBundle:
    envelope_bytes, qualification_bytes = contents[1:3]
    envelope_document = _parse_envelope(envelope_bytes)
    qualification_document = _parse_qualification(qualification_bytes)
    artifacts = tuple(_artifact(item) for item in envelope_document.artifacts)
    sboms = tuple(_sbom(item) for item in envelope_document.sboms)
    bundle = _validated_assembly(
        envelope_document, qualification_document, envelope_bytes, qualification_bytes
    )
    _require_descriptors(manifest, _expected_layers(bundle), MalformedProviderResponse)
    return EnvelopeBundle(bundle.qualified, artifacts, sboms)


def _validated_assembly(
    document: BuildEnvelopeDocument,
    qualification: QualificationRecordDocument,
    envelope_bytes: bytes,
    qualification_bytes: bytes,
) -> EnvelopeBundle:
    try:
        return _assembled_bundle(document, qualification, envelope_bytes, qualification_bytes)
    except ValueError as error:
        raise MalformedProviderResponse("stored envelope records are inconsistent") from error


def _parse_envelope(content: bytes) -> BuildEnvelopeDocument:
    try:
        document = BuildEnvelopeDocument.model_validate_json(content)
    except ValidationError as error:
        raise MalformedProviderResponse("stored build envelope is malformed") from error
    if canonical_json_bytes(document) != content:
        raise MalformedProviderResponse("stored build envelope is not canonical")
    return document


def _parse_qualification(content: bytes) -> QualificationRecordDocument:
    try:
        document = QualificationRecordDocument.model_validate_json(content)
    except ValidationError as error:
        raise MalformedProviderResponse("stored qualification is malformed") from error
    if canonical_json_bytes(document) != content:
        raise MalformedProviderResponse("stored qualification is not canonical")
    return document


def _assembled_bundle(
    document: BuildEnvelopeDocument,
    qualification: QualificationRecordDocument,
    envelope_bytes: bytes,
    qualification_bytes: bytes,
) -> EnvelopeBundle:
    signed = _signed_build(document)
    envelope_digest = Sha256Digest.from_bytes(envelope_bytes)
    envelope = BuildEnvelope(signed, document, envelope_bytes, envelope_digest)
    record = _qualification_record(qualification, qualification_bytes)
    qualified = QualifiedEnvelope(envelope, record)
    return EnvelopeBundle(qualified, _artifacts(document), _sboms(document))


def _qualification_record(
    qualification: QualificationRecordDocument, content: bytes
) -> QualificationRecord:
    return QualificationRecord(
        Sha256Digest(qualification.subject),
        qualification,
        content,
        Sha256Digest.from_bytes(content),
    )


def _signed_build(document: BuildEnvelopeDocument) -> SignedBuild:
    artifacts = _artifacts(document)
    unsigned = UnsignedBuild(
        _snapshot(document),
        artifacts,
        _sboms(document),
        tuple(_lock(item) for item in document.locks),
        tuple(_toolchain(item) for item in document.toolchains),
    )
    evidence = tuple(_evidence(item) for item in document.prequalification_evidence)
    prequalified = PrequalifiedBuild(unsigned, evidence)
    return SignedBuild(prequalified, None, SigningDisposition.SIGNING_NOT_REQUIRED)


def _snapshot(document: BuildEnvelopeDocument) -> SnapshottedSource:
    source = document.source
    project = ProjectId(source.project)
    digest = Sha256Digest(source.source_tree_sha256)
    revision = SourceRevision(
        project, source.repository, source.protected_ref, source.commit_sha, digest
    )
    release_id = ReleaseId(
        project,
        document.release_policy.version,
        digest,
        f"{project.value}-{document.release_policy.version}",
    )
    return SnapshottedSource(ReleaseSource(release_id, revision), digest)


def _artifacts(document: BuildEnvelopeDocument) -> tuple[Artifact, ...]:
    return tuple(_artifact(item) for item in document.artifacts)


def _artifact(document: ArtifactDocument) -> Artifact:
    return Artifact(
        document.name,
        ArtifactPath(document.path),
        document.media_type,
        document.size,
        Sha256Digest(document.sha256),
    )


def _sboms(document: BuildEnvelopeDocument) -> tuple[Sbom, ...]:
    return tuple(_sbom(item) for item in document.sboms)


def _sbom(document: SbomDocument) -> Sbom:
    return Sbom(
        ArtifactPath(document.artifact_path),
        ArtifactPath(document.path),
        document.media_type,
        Sha256Digest(document.sha256),
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
