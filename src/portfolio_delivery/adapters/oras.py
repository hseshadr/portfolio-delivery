"""Pure ORAS command planning and immutable generic-OCI reconciliation.

The injected runner owns authentication, mounted payload files, and execution. Push
results surface exact ``--export-manifest`` bytes separately from bounded process
output; manifest and blob fetches return their exact bytes through stdout.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal, NoReturn, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from portfolio_delivery.contracts.oci import DEFAULT_OCI_RESOURCE_LIMITS, OciResourceLimits
from portfolio_delivery.contracts.storage import OrasRunner
from portfolio_delivery.domain.artifacts import (
    Artifact,
    Evidence,
    EvidenceStatus,
    LockIdentity,
    Sbom,
    ToolchainIdentity,
)
from portfolio_delivery.domain.errors import InvalidIdentity, diagnostic_error
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
    StoredEnvelope,
    UnsignedBuild,
    validate_attempt_id,
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
from portfolio_delivery.envelope.canonical import canonical_json_bytes, parse_bounded_json
from portfolio_delivery.envelope.documents import (
    BUILD_ENVELOPE_MEDIA_TYPE,
    CONFIG_MEDIA_TYPE,
    QUALIFICATION_MEDIA_TYPE,
    ArtifactDocument,
    BuildEnvelopeDocument,
    EvidenceDocument,
    LockDocument,
    OciConfigDocument,
    OciStageOrderDocument,
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
MAX_PROCESS_STDOUT_BYTES: Final[int] = 65_536
REQUIRED_CORE_LAYERS: Final[int] = 2
_REPOSITORY: Final = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
)
_TAG: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}")
_ANNOTATIONS_MESSAGE = (
    "OCI descriptor annotations are not allowlisted"  # pragma: no mutate - diagnostic
)
_MANIFEST_NOT_FOUND_MESSAGE = (
    "OCI envelope manifest was not found"  # pragma: no mutate - diagnostic
)
_MANIFEST_DIGEST_MESSAGE = (
    "manifest bytes differ at digest reference"  # pragma: no mutate - diagnostic
)
_BLOB_SIZE_MESSAGE = "OCI blob size differs from its descriptor"  # pragma: no mutate - diagnostic
_BUNDLE_CONTRACT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle must use the immutable envelope bundle contract"
)
_BUNDLE_ENVELOPE_BYTES_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle envelope document must match its exact canonical bytes"
)
_BUNDLE_ENVELOPE_GRAPH_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle envelope stage graph must match its canonical document"
)
_BUNDLE_QUALIFICATION_BYTES_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle qualification document must match its exact canonical bytes"
)
_BUNDLE_QUALIFICATION_SUBJECT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle qualification must bind every final-envelope subject"
)
_BUNDLE_ARTIFACTS_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle artifacts must exactly match the canonical envelope"
)
_BUNDLE_SBOMS_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle SBOMs must exactly match the canonical envelope"
)
_CANONICAL_ENVELOPE_MESSAGE = (
    "bundle envelope bytes must be canonical"  # pragma: no mutate - diagnostic
)
_CANONICAL_QUALIFICATION_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "bundle qualification bytes must be canonical"
)
_REPOSITORY_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI repository must be a bounded canonical repository name"
)
_TAG_MESSAGE = "OCI tag must be a bounded canonical tag"  # pragma: no mutate - diagnostic
_LAYER_PATHS_MESSAGE = "OCI layer paths must be unique"  # pragma: no mutate - diagnostic
_LAYER_PATH_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI layer path must be bounded and relative to /work"
)
_LAYER_MEDIA_TYPE_MESSAGE = "OCI layer media type must be bounded"  # pragma: no mutate - diagnostic
_TIMESTAMP_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "sourceDateEpoch must fit a canonical UTC timestamp"
)
_PUSH_EXPORT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "ORAS push omitted its exported manifest bytes"
)
_UNEXPECTED_EXPORT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "non-push ORAS result carried an unexpected exported file"
)
_STDERR_BOUND_MESSAGE = "ORAS stderr exceeded its response bound"  # pragma: no mutate - diagnostic
_STDOUT_BOUND_MESSAGE = "ORAS stdout exceeded its response bound"  # pragma: no mutate - diagnostic
_MANIFEST_BOUND_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "ORAS exported manifest exceeded its response bound"
)
_TIMEOUT_MESSAGE = "ORAS provider execution timed out"  # pragma: no mutate - diagnostic
_UNAVAILABLE_MESSAGE = "ORAS provider execution failed"  # pragma: no mutate - diagnostic
_MALFORMED_MANIFEST_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "ORAS returned a malformed OCI manifest"
)
_CONFIG_MEDIA_TYPE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI manifest has an unexpected config media type"
)
_CONFIG_ANNOTATION_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI config descriptor has unexpected annotations"
)
_REQUIRED_LAYERS_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI manifest is missing required envelope layers"
)
_UNEXPECTED_LAYER_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI manifest has an unexpected required layer"
)
_LAYER_TITLES_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI manifest has missing or duplicate layer titles"
)
_CANONICAL_LAYER_TITLE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI layer title must be bounded and canonical"
)
_RELATIVE_LAYER_TITLE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI layer title must be a canonical relative path"
)
_DECLARED_MANIFEST_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "declared OCI manifest digest conflicts with provider bytes"
)
_POST_PUSH_MANIFEST_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "post-push OCI tag differs from exported manifest bytes"
)
_ANNOTATION_CONFLICT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI manifest has conflicting deterministic annotations"
)
_LAYER_SET_CONFLICT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI content tag has a conflicting layer set"
)
_DESCRIPTOR_CONFLICT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI content tag has conflicting descriptor bytes"
)
_BLOB_CONFLICT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI provider returned conflicting blob bytes"
)
_BLOB_SIZE_CONFLICT_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI provider returned a conflicting blob size"
)
_REVIEWED_BYTES_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI provider returned non-identical reviewed bytes"
)
_BLOB_DIGEST_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI blob bytes do not match their descriptor"
)
_BLOB_BOUND_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI blob descriptor size exceeded its response bound"
)
_RESOURCE_LIMIT_TEMPLATE = (  # pragma: no mutate - non-contractual diagnostic text
    "OCI resource limit violation: {violation}"
)
_STORED_RECORDS_MESSAGE = (
    "stored envelope records are inconsistent"  # pragma: no mutate - diagnostic
)
_STORED_GRAPH_MESSAGE = "stored envelope graph is inconsistent"  # pragma: no mutate - diagnostic
_STORED_CONFIG_GRAPH_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "stored config does not match the envelope graph"
)
_STORED_CONFIG_MALFORMED_MESSAGE = (
    "stored OCI config is malformed"  # pragma: no mutate - diagnostic
)
_STORED_CONFIG_CANONICAL_MESSAGE = (
    "stored OCI config is not canonical"  # pragma: no mutate - diagnostic
)
_STORED_ENVELOPE_MALFORMED_MESSAGE = (
    "stored build envelope is malformed"  # pragma: no mutate - diagnostic
)
_STORED_ENVELOPE_CANONICAL_MESSAGE = (
    "stored build envelope is not canonical"  # pragma: no mutate - diagnostic
)
_STORED_QUALIFICATION_MALFORMED_MESSAGE = (
    "stored qualification is malformed"  # pragma: no mutate - diagnostic
)
_STORED_QUALIFICATION_CANONICAL_MESSAGE = (
    "stored qualification is not canonical"  # pragma: no mutate - diagnostic
)
_STORED_ORDER_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "stored config order must select unique existing records"
)
_STORED_SIGNATURE_MESSAGE = (  # pragma: no mutate - non-contractual diagnostic text
    "signed config signature path must identify exactly one artifact"
)


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

    @model_validator(mode="after")
    def validate_annotations(self) -> _Descriptor:
        keys = set(self.annotations)
        if keys not in (set(), {TITLE_ANNOTATION}):
            raise diagnostic_error(ValueError, _ANNOTATIONS_MESSAGE)
        return self


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
    size: int
    exact_bytes: bytes | None = None


@dataclass(frozen=True, slots=True)
class _ValidatedBundle:
    bundle: EnvelopeBundle
    envelope_document: BuildEnvelopeDocument
    qualification_document: QualificationRecordDocument
    config_document: OciConfigDocument
    artifacts: tuple[Artifact, ...]
    sboms: tuple[Sbom, ...]


@dataclass(frozen=True, slots=True)
class OrasAdapter:
    """Plan and reconcile one immutable generic-OCI envelope repository."""

    runner: OrasRunner
    repository: str
    limits: OciResourceLimits = DEFAULT_OCI_RESOURCE_LIMITS

    def __post_init__(self) -> None:
        _validate_repository(self.repository)
        if not isinstance(self.limits, OciResourceLimits):
            raise TypeError("limits must use the OCI resource policy contract")

    def plan_push(self, bundle: EnvelopeBundle) -> OrasInvocation:
        return _plan_push(_validate_bundle(bundle), self.repository, self.limits)

    async def inspect(self, reference: OciReference, attempt_id: str) -> StoredEnvelope | None:
        validate_attempt_id(attempt_id)
        _validate_reference(reference)
        observation = await self._observe_tag(reference, attempt_id)
        return _stored(reference, observation)

    async def persist(self, bundle: EnvelopeBundle, attempt_id: str) -> StoredEnvelope:
        validate_attempt_id(attempt_id)
        validated = _validate_bundle(bundle)
        _require_expected_resource_limits(validated, self.limits, InvalidIdentity)
        reference = _content_reference(bundle, self.repository)
        existing = await self._observe_tag(reference, attempt_id)
        if existing is not None:
            await self._require_bundle(existing, validated, attempt_id, ArtifactConflict)
            return _stored_required(reference, existing)
        return await self._push_and_reconcile(validated, reference, attempt_id)

    async def restore(self, reference: OciReference, attempt_id: str) -> EnvelopeBundle:
        validate_attempt_id(attempt_id)
        _validate_reference(reference)
        observation = await self._observe_tag(reference, attempt_id)
        if observation is None:
            raise diagnostic_error(ProviderUnavailable, _MANIFEST_NOT_FOUND_MESSAGE)
        return await self._restore_observation(observation, reference.repository, attempt_id)

    async def _push_and_reconcile(
        self, bundle: _ValidatedBundle, reference: OciReference, attempt_id: str
    ) -> StoredEnvelope:
        try:
            exported = await self._push(bundle, attempt_id)
        except ProviderTimeout as timeout:
            return await self._recover_timeout(bundle, reference, attempt_id, timeout)
        observed = _require_post_push_manifest(
            exported, await self._observe_tag(reference, attempt_id)
        )
        await self._require_bundle(observed, bundle, attempt_id, MalformedProviderResponse)
        return _stored_required(reference, observed)

    async def _push(self, bundle: _ValidatedBundle, attempt_id: str) -> _Observation:
        result = await self.runner.run(_plan_push(bundle, self.repository, self.limits), attempt_id)
        content = _successful_exported_file(result)
        return _parse_manifest(content, self.limits)

    async def _recover_timeout(
        self,
        bundle: _ValidatedBundle,
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
        observation = _parse_manifest(content, self.limits)
        _require_declared_manifest(reference, observation.digest)
        return await self._observe_digest(observation, reference.repository, attempt_id)

    async def _observe_digest(
        self, expected: _Observation, repository: str, attempt_id: str
    ) -> _Observation:
        reference = f"{repository}@{expected.digest.value}"
        result = await self.runner.run(_manifest_fetch(reference), attempt_id)
        content = _successful_stdout(result, MAX_MANIFEST_BYTES)
        if content != expected.content:
            raise diagnostic_error(MalformedProviderResponse, _MANIFEST_DIGEST_MESSAGE)
        return _parse_manifest(content, self.limits)

    async def _require_bundle(
        self,
        observation: _Observation,
        bundle: _ValidatedBundle,
        attempt_id: str,
        conflict_type: type[OrasAdapterError],
    ) -> None:
        expected = _expected_layers(bundle)
        _require_created_annotation(observation.manifest, bundle.bundle, conflict_type)
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
        _require_bounded_blob_size(descriptor.size, self.limits)
        reference = f"{repository}@{descriptor.digest}"
        result = await self.runner.run(_blob_fetch(reference), attempt_id)
        content = _successful_stdout(result, descriptor.size)
        if len(content) != descriptor.size:
            raise diagnostic_error(MalformedProviderResponse, _BLOB_SIZE_MESSAGE)
        return content

    async def _restore_observation(
        self, observation: _Observation, repository: str, attempt_id: str
    ) -> EnvelopeBundle:
        descriptors = (observation.manifest.config, *observation.manifest.layers)
        contents = tuple(
            [await self._fetch_blob(item, repository, attempt_id) for item in descriptors]
        )
        _require_descriptor_bytes(descriptors, contents)
        return _restore_bundle(observation.manifest, contents)


def _plan_push(
    bundle: _ValidatedBundle, repository: str, limits: OciResourceLimits
) -> OrasInvocation:
    layers = _expected_layers(bundle)
    _validate_expected_layers(layers)
    _require_resource_limits(tuple(item.size for item in layers), limits, InvalidIdentity)
    argv = _push_argv(repository, bundle.bundle, layers)
    return OrasInvocation(argv, _input_bytes(bundle))


def _validate_bundle(bundle: EnvelopeBundle) -> _ValidatedBundle:
    if not isinstance(bundle, EnvelopeBundle):
        raise diagnostic_error(ValueError, _BUNDLE_CONTRACT_MESSAGE)
    envelope_document = _validate_bundle_envelope(bundle)
    qualification_document = _validate_bundle_qualification(bundle)
    artifacts = _validate_bundle_artifacts(bundle, envelope_document)
    sboms = _validate_bundle_sboms(bundle, envelope_document)
    config = _config_document(bundle, envelope_document)
    return _ValidatedBundle(
        bundle, envelope_document, qualification_document, config, artifacts, sboms
    )


def _validate_bundle_envelope(bundle: EnvelopeBundle) -> BuildEnvelopeDocument:
    envelope = bundle.qualified.envelope
    document = _local_envelope_document(envelope.canonical_bytes)
    if envelope.document != document:
        raise diagnostic_error(ValueError, _BUNDLE_ENVELOPE_BYTES_MESSAGE)
    rebuilt = EnvelopeBuilder(_metadata(document)).build(envelope.signed)
    if rebuilt != envelope:
        raise diagnostic_error(ValueError, _BUNDLE_ENVELOPE_GRAPH_MESSAGE)
    return document


def _validate_bundle_qualification(bundle: EnvelopeBundle) -> QualificationRecordDocument:
    envelope = bundle.qualified.envelope
    record = bundle.qualified.qualification
    document = _local_qualification_document(record.canonical_bytes)
    if record.document != document:
        raise diagnostic_error(ValueError, _BUNDLE_QUALIFICATION_BYTES_MESSAGE)
    checks = tuple(_evidence(item) for item in document.qualification_evidence)
    QualificationBuilder().build(envelope, checks)
    return document


def _validate_bundle_artifacts(
    bundle: EnvelopeBundle, document: BuildEnvelopeDocument
) -> tuple[Artifact, ...]:
    artifacts = _artifacts(document)
    if not _same_records(bundle.artifacts, artifacts, Artifact, _artifact_key):
        raise diagnostic_error(ValueError, _BUNDLE_ARTIFACTS_MESSAGE)
    return artifacts


def _validate_bundle_sboms(
    bundle: EnvelopeBundle, document: BuildEnvelopeDocument
) -> tuple[Sbom, ...]:
    sboms = _sboms(document)
    if not _same_records(bundle.sboms, sboms, Sbom, _sbom_key):
        raise diagnostic_error(ValueError, _BUNDLE_SBOMS_MESSAGE)
    return sboms


def _same_records[T](
    actual: object,
    expected: tuple[T, ...],
    item_type: type[object],
    key: Callable[[T], str],
) -> bool:
    if not isinstance(actual, tuple) or not all(isinstance(item, item_type) for item in actual):
        return False
    records = cast(tuple[T, ...], actual)  # pragma: no mutate - runtime-neutral cast
    return tuple(sorted(records, key=key)) == expected


def _artifact_key(artifact: Artifact) -> str:
    return artifact.path.value


def _sbom_key(sbom: Sbom) -> str:
    return sbom.artifact_path.value


def _metadata(document: BuildEnvelopeDocument) -> EnvelopeMetadata:
    channels = tuple(ReleaseChannel(item) for item in document.release_policy.channels)
    return EnvelopeMetadata(
        ProjectAdapterVersion(document.project_adapter_version),
        document.source_date_epoch,
        ReleasePolicyMetadata(document.release_policy.version, channels),
        PinnedCompatibility(document.compatibility.dagger, document.compatibility.oras),
    )


def _config_document(bundle: EnvelopeBundle, document: BuildEnvelopeDocument) -> OciConfigDocument:
    signed = bundle.qualified.envelope.signed
    unsigned = signed.prequalified.unsigned
    snapshot = unsigned.source
    return OciConfigDocument(
        envelopeSha256=bundle.qualified.envelope.content_sha256.value,
        qualificationSha256=bundle.qualified.qualification.content_sha256.value,
        releaseIdempotencyKey=snapshot.release.release_id.idempotency_key,
        inputSnapshotSha256=snapshot.input_snapshot_sha256.value,
        signingDisposition=signed.disposition.value,
        signaturePath=_signature_path(signed),
        stageOrder=_stage_order(bundle, document),
    )


def _stage_order(bundle: EnvelopeBundle, document: BuildEnvelopeDocument) -> OciStageOrderDocument:
    signed = bundle.qualified.envelope.signed
    unsigned = signed.prequalified.unsigned
    return OciStageOrderDocument(
        unsignedArtifactOrder=_record_order(unsigned.artifacts, _artifacts(document)),
        unsignedSbomOrder=_record_order(unsigned.sboms, _sboms(document)),
        lockOrder=_record_order(unsigned.locks, _locks(document)),
        toolchainOrder=_record_order(unsigned.toolchains, _toolchains(document)),
        prequalificationEvidenceOrder=_record_order(
            signed.prequalified.evidence, _evidence_records(document)
        ),
        bundleArtifactOrder=_record_order(bundle.artifacts, _artifacts(document)),
        bundleSbomOrder=_record_order(bundle.sboms, _sboms(document)),
    )


def _signature_path(signed: SignedBuild) -> str | None:
    if signed.signature is None:
        return None
    return signed.signature.path.value


def _record_order[T](records: tuple[T, ...], canonical: tuple[T, ...]) -> tuple[int, ...]:
    return tuple(canonical.index(item) for item in records)


def _local_envelope_document(content: bytes) -> BuildEnvelopeDocument:
    try:
        return _parse_envelope(content)
    except MalformedProviderResponse as error:
        raise diagnostic_error(ValueError, _CANONICAL_ENVELOPE_MESSAGE) from error


def _local_qualification_document(content: bytes) -> QualificationRecordDocument:
    try:
        return _parse_qualification(content)
    except MalformedProviderResponse as error:
        raise diagnostic_error(ValueError, _CANONICAL_QUALIFICATION_MESSAGE) from error


def _validate_repository(repository: str) -> None:
    if len(repository) > MAX_REPOSITORY_LENGTH or _REPOSITORY.fullmatch(repository) is None:
        raise diagnostic_error(ValueError, _REPOSITORY_MESSAGE)


def _validate_reference(reference: OciReference) -> None:
    _validate_repository(reference.repository)
    if len(reference.tag) > MAX_TAG_LENGTH or _TAG.fullmatch(reference.tag) is None:
        raise diagnostic_error(ValueError, _TAG_MESSAGE)


def _validate_expected_layers(layers: tuple[_ExpectedLayer, ...]) -> None:
    if len({item.path for item in layers}) != len(layers):
        raise diagnostic_error(ValueError, _LAYER_PATHS_MESSAGE)
    for item in layers:
        _validate_layer_text(item)


def _validate_layer_text(layer: _ExpectedLayer) -> None:
    if len(layer.path) > MAX_PATH_LENGTH:
        raise diagnostic_error(ValueError, _LAYER_PATH_MESSAGE)
    ArtifactPath(layer.path)
    if len(layer.media_type) > MAX_MEDIA_TYPE_LENGTH:
        raise diagnostic_error(ValueError, _LAYER_MEDIA_TYPE_MESSAGE)


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
        raise diagnostic_error(ValueError, _TIMESTAMP_MESSAGE) from error
    return created.isoformat(timespec="seconds").replace("+00:00", "Z")


def _input_bytes(bundle: _ValidatedBundle) -> tuple[bytes, ...]:
    return (
        canonical_json_bytes(bundle.config_document),
        bundle.bundle.qualified.envelope.canonical_bytes,
        bundle.bundle.qualified.qualification.canonical_bytes,
    )


def _expected_layers(bundle: _ValidatedBundle) -> tuple[_ExpectedLayer, ...]:
    envelope = bundle.bundle.qualified.envelope.canonical_bytes
    qualification = bundle.bundle.qualified.qualification.canonical_bytes
    return (
        _exact_layer(
            "config.v1.json", CONFIG_MEDIA_TYPE, canonical_json_bytes(bundle.config_document)
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
    return _ExpectedLayer(sbom.path.value, sbom.media_type, sbom.sha256, sbom.size)


def _manifest_fetch(reference: str) -> OrasInvocation:
    return OrasInvocation(("oras", "manifest", "fetch", reference))


def _blob_fetch(reference: str) -> OrasInvocation:
    return OrasInvocation(("oras", "blob", "fetch", reference))


def _manifest_stdout_or_none(result: OrasResult) -> bytes | None:
    _require_no_exported_file(result)
    _require_bounded_outputs(result, MAX_MANIFEST_BYTES)
    if result.outcome is OrasOutcome.SUCCESS:
        return result.stdout
    if result.outcome is OrasOutcome.NOT_FOUND:
        return None
    _raise_result_error(result)


def _successful_stdout(result: OrasResult, limit: int) -> bytes:
    _require_no_exported_file(result)
    _require_bounded_outputs(result, limit)
    if result.outcome is not OrasOutcome.SUCCESS:
        _raise_result_error(result)
    return result.stdout


def _successful_exported_file(result: OrasResult) -> bytes:
    _require_bounded_outputs(result, MAX_PROCESS_STDOUT_BYTES)
    if result.outcome is not OrasOutcome.SUCCESS:
        _raise_result_error(result)
    if result.exported_file_bytes is None:
        raise diagnostic_error(MalformedProviderResponse, _PUSH_EXPORT_MESSAGE)
    return _bounded_export(result.exported_file_bytes)


def _require_no_exported_file(result: OrasResult) -> None:
    if result.exported_file_bytes is not None:
        raise diagnostic_error(MalformedProviderResponse, _UNEXPECTED_EXPORT_MESSAGE)


def _require_bounded_outputs(result: OrasResult, stdout_limit: int) -> None:
    _bounded_stdout(result.stdout, stdout_limit)
    _require_bounded_stderr(result)


def _require_bounded_stderr(result: OrasResult) -> None:
    if len(result.stderr) > MAX_STDERR_BYTES:
        raise diagnostic_error(MalformedProviderResponse, _STDERR_BOUND_MESSAGE)


def _bounded_stdout(content: bytes, limit: int) -> bytes:
    if len(content) > limit:
        raise diagnostic_error(MalformedProviderResponse, _STDOUT_BOUND_MESSAGE)
    return content


def _bounded_export(content: bytes) -> bytes:
    if len(content) > MAX_MANIFEST_BYTES:
        raise diagnostic_error(MalformedProviderResponse, _MANIFEST_BOUND_MESSAGE)
    return content


def _raise_result_error(result: OrasResult) -> NoReturn:
    if result.outcome is OrasOutcome.TIMEOUT:
        raise diagnostic_error(ProviderTimeout, _TIMEOUT_MESSAGE)
    raise diagnostic_error(ProviderUnavailable, _UNAVAILABLE_MESSAGE)


def _parse_manifest(content: bytes, limits: OciResourceLimits) -> _Observation:
    bounded = _bounded_stdout(content, MAX_MANIFEST_BYTES)
    try:
        manifest = _Manifest.model_validate(parse_bounded_json(bounded, MAX_MANIFEST_BYTES))
    except (ValidationError, ValueError) as error:
        raise diagnostic_error(MalformedProviderResponse, _MALFORMED_MANIFEST_MESSAGE) from error
    _validate_manifest_layers(manifest)
    descriptors = (manifest.config, *manifest.layers)
    _require_resource_limits(
        tuple(item.size for item in descriptors), limits, MalformedProviderResponse
    )
    return _Observation(bounded, Sha256Digest.from_bytes(bounded), manifest)


def _validate_manifest_layers(manifest: _Manifest) -> None:
    if manifest.config.media_type != CONFIG_MEDIA_TYPE:
        raise diagnostic_error(MalformedProviderResponse, _CONFIG_MEDIA_TYPE_MESSAGE)
    if manifest.config.annotations:
        raise diagnostic_error(MalformedProviderResponse, _CONFIG_ANNOTATION_MESSAGE)
    if len(manifest.layers) < REQUIRED_CORE_LAYERS:
        raise diagnostic_error(MalformedProviderResponse, _REQUIRED_LAYERS_MESSAGE)
    _require_core_layer(manifest.layers[0], "build-envelope.v1.json", BUILD_ENVELOPE_MEDIA_TYPE)
    _require_core_layer(
        manifest.layers[1], "qualification-record.v1.json", QUALIFICATION_MEDIA_TYPE
    )
    _require_unique_layer_titles(manifest.layers)


def _require_core_layer(descriptor: _Descriptor, title: str, media_type: str) -> None:
    if descriptor.title != title or descriptor.media_type != media_type:
        raise diagnostic_error(MalformedProviderResponse, _UNEXPECTED_LAYER_MESSAGE)


def _require_unique_layer_titles(layers: tuple[_Descriptor, ...]) -> None:
    titles = tuple(item.title for item in layers)
    if None in titles or len(titles) != len(set(titles)):
        raise diagnostic_error(MalformedProviderResponse, _LAYER_TITLES_MESSAGE)
    for title in titles:
        _require_canonical_layer_title(title)


def _require_canonical_layer_title(title: str | None) -> None:
    if title is None or len(title) > MAX_PATH_LENGTH:
        raise diagnostic_error(MalformedProviderResponse, _CANONICAL_LAYER_TITLE_MESSAGE)
    try:
        ArtifactPath(title)
    except ValueError as error:
        raise diagnostic_error(MalformedProviderResponse, _RELATIVE_LAYER_TITLE_MESSAGE) from error


def _require_declared_manifest(reference: OciReference, digest: Sha256Digest) -> None:
    if reference.manifest_sha256 is not None and reference.manifest_sha256 != digest:
        raise diagnostic_error(ArtifactConflict, _DECLARED_MANIFEST_MESSAGE)


def _require_post_push_manifest(
    exported: _Observation, observed: _Observation | None
) -> _Observation:
    if observed is None or observed.content != exported.content:
        raise diagnostic_error(ArtifactConflict, _POST_PUSH_MANIFEST_MESSAGE)
    return observed


def _require_created_annotation(
    manifest: _Manifest,
    bundle: EnvelopeBundle,
    conflict_type: type[OrasAdapterError],
) -> None:
    created = manifest.annotations.get(CREATED_ANNOTATION)
    if created != _created_timestamp(bundle) or len(manifest.annotations) != 1:
        raise diagnostic_error(conflict_type, _ANNOTATION_CONFLICT_MESSAGE)


def _require_descriptors(
    manifest: _Manifest,
    expected: tuple[_ExpectedLayer, ...],
    conflict_type: type[OrasAdapterError],
) -> None:
    descriptors = (manifest.config, *manifest.layers)
    if len(descriptors) != len(expected):
        raise diagnostic_error(conflict_type, _LAYER_SET_CONFLICT_MESSAGE)
    for index, descriptor in enumerate(descriptors):
        _require_descriptor(descriptor, expected[index], conflict_type)


def _require_descriptor(
    descriptor: _Descriptor,
    expected: _ExpectedLayer,
    conflict_type: type[OrasAdapterError],
) -> None:
    identity = (descriptor.title, descriptor.media_type, descriptor.digest)
    wanted = (_expected_title(expected), expected.media_type, expected.digest.value)
    if identity != wanted or descriptor.size != expected.size:
        raise diagnostic_error(conflict_type, _DESCRIPTOR_CONFLICT_MESSAGE)


def _expected_title(expected: _ExpectedLayer) -> str | None:
    if expected.path == "config.v1.json":
        return None
    return expected.path


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
        raise diagnostic_error(conflict_type, _BLOB_CONFLICT_MESSAGE)


def _require_blob_size(
    content: bytes, expected: _ExpectedLayer, conflict_type: type[OrasAdapterError]
) -> None:
    if len(content) != expected.size:
        raise diagnostic_error(conflict_type, _BLOB_SIZE_CONFLICT_MESSAGE)


def _require_exact_blob(
    content: bytes, expected: _ExpectedLayer, conflict_type: type[OrasAdapterError]
) -> None:
    if expected.exact_bytes is not None and content != expected.exact_bytes:
        raise diagnostic_error(conflict_type, _REVIEWED_BYTES_MESSAGE)


def _require_descriptor_bytes(
    descriptors: tuple[_Descriptor, ...], contents: tuple[bytes, ...]
) -> None:
    for descriptor, content in zip(descriptors, contents, strict=True):
        digest_differs = Sha256Digest.from_bytes(content).value != descriptor.digest
        if len(content) != descriptor.size or digest_differs:
            raise diagnostic_error(MalformedProviderResponse, _BLOB_DIGEST_MESSAGE)


def _require_bounded_blob_size(size: int, limits: OciResourceLimits) -> None:
    if size > limits.max_file_bytes:
        raise diagnostic_error(MalformedProviderResponse, _BLOB_BOUND_MESSAGE)


def _require_expected_resource_limits(
    bundle: _ValidatedBundle,
    limits: OciResourceLimits,
    error_type: type[Exception],
) -> None:
    sizes = tuple(item.size for item in _expected_layers(bundle))
    _require_resource_limits(sizes, limits, error_type)


def _require_resource_limits(
    sizes: tuple[int, ...], limits: OciResourceLimits, error_type: type[Exception]
) -> None:
    violation = limits.evaluate(sizes).violation
    if violation is not None:
        message = _RESOURCE_LIMIT_TEMPLATE.format(violation=violation.value)
        raise diagnostic_error(error_type, message)


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
    config = _parse_config(contents[0])
    envelope_bytes, qualification_bytes = contents[1:3]
    envelope_document = _parse_envelope(envelope_bytes)
    qualification_document = _parse_qualification(qualification_bytes)
    bundle = _validated_assembly(
        config, envelope_document, qualification_document, envelope_bytes, qualification_bytes
    )
    validated = _validated_restored_bundle(bundle, config)
    _require_created_annotation(manifest, bundle, MalformedProviderResponse)
    _require_descriptors(manifest, _expected_layers(validated), MalformedProviderResponse)
    return bundle


def _validated_assembly(
    config: OciConfigDocument,
    document: BuildEnvelopeDocument,
    qualification: QualificationRecordDocument,
    envelope_bytes: bytes,
    qualification_bytes: bytes,
) -> EnvelopeBundle:
    try:
        return _assembled_bundle(
            config, document, qualification, envelope_bytes, qualification_bytes
        )
    except ValueError as error:
        raise diagnostic_error(MalformedProviderResponse, _STORED_RECORDS_MESSAGE) from error


def _validated_restored_bundle(
    bundle: EnvelopeBundle, config: OciConfigDocument
) -> _ValidatedBundle:
    try:
        validated = _validate_bundle(bundle)
    except ValueError as error:
        raise diagnostic_error(MalformedProviderResponse, _STORED_GRAPH_MESSAGE) from error
    if validated.config_document != config:
        raise diagnostic_error(MalformedProviderResponse, _STORED_CONFIG_GRAPH_MESSAGE)
    return validated


def _parse_config(content: bytes) -> OciConfigDocument:
    try:
        document = OciConfigDocument.model_validate(parse_bounded_json(content, MAX_MANIFEST_BYTES))
    except (ValidationError, ValueError) as error:
        raise diagnostic_error(
            MalformedProviderResponse, _STORED_CONFIG_MALFORMED_MESSAGE
        ) from error
    if canonical_json_bytes(document) != content:
        raise diagnostic_error(MalformedProviderResponse, _STORED_CONFIG_CANONICAL_MESSAGE)
    return document


def _parse_envelope(content: bytes) -> BuildEnvelopeDocument:
    try:
        document = BuildEnvelopeDocument.model_validate_json(content)
    except ValidationError as error:
        raise diagnostic_error(
            MalformedProviderResponse, _STORED_ENVELOPE_MALFORMED_MESSAGE
        ) from error
    if canonical_json_bytes(document) != content:
        raise diagnostic_error(MalformedProviderResponse, _STORED_ENVELOPE_CANONICAL_MESSAGE)
    return document


def _parse_qualification(content: bytes) -> QualificationRecordDocument:
    try:
        document = QualificationRecordDocument.model_validate_json(content)
    except ValidationError as error:
        raise diagnostic_error(
            MalformedProviderResponse, _STORED_QUALIFICATION_MALFORMED_MESSAGE
        ) from error
    if canonical_json_bytes(document) != content:
        raise diagnostic_error(MalformedProviderResponse, _STORED_QUALIFICATION_CANONICAL_MESSAGE)
    return document


def _assembled_bundle(
    config: OciConfigDocument,
    document: BuildEnvelopeDocument,
    qualification: QualificationRecordDocument,
    envelope_bytes: bytes,
    qualification_bytes: bytes,
) -> EnvelopeBundle:
    signed = _signed_build(document, config)
    envelope_digest = Sha256Digest.from_bytes(envelope_bytes)
    envelope = BuildEnvelope(signed, document, envelope_bytes, envelope_digest)
    record = _qualification_record(qualification, qualification_bytes)
    qualified = QualifiedEnvelope(envelope, record)
    artifacts = _ordered(_artifacts(document), config.stage_order.bundle_artifact_order)
    sboms = _ordered(_sboms(document), config.stage_order.bundle_sbom_order)
    return EnvelopeBundle(qualified, artifacts, sboms)


def _qualification_record(
    qualification: QualificationRecordDocument, content: bytes
) -> QualificationRecord:
    return QualificationRecord(
        Sha256Digest(qualification.subject),
        qualification,
        content,
        Sha256Digest.from_bytes(content),
    )


def _signed_build(document: BuildEnvelopeDocument, config: OciConfigDocument) -> SignedBuild:
    artifacts = _artifacts(document)
    signature = _signature_artifact(artifacts, config)
    unsigned_artifacts = _ordered(artifacts, config.stage_order.unsigned_artifact_order)
    unsigned = _unsigned_build(document, config, unsigned_artifacts)
    evidence = _ordered(
        _evidence_records(document), config.stage_order.prequalification_evidence_order
    )
    prequalified = PrequalifiedBuild(unsigned, evidence)
    return SignedBuild(prequalified, signature, SigningDisposition(config.signing_disposition))


def _unsigned_build(
    document: BuildEnvelopeDocument,
    config: OciConfigDocument,
    artifacts: tuple[Artifact, ...],
) -> UnsignedBuild:
    return UnsignedBuild(
        _snapshot(document, config),
        artifacts,
        _ordered(_sboms(document), config.stage_order.unsigned_sbom_order),
        _ordered(_locks(document), config.stage_order.lock_order),
        _ordered(_toolchains(document), config.stage_order.toolchain_order),
    )


def _ordered[T](records: tuple[T, ...], order: tuple[int, ...]) -> tuple[T, ...]:
    if len(set(order)) != len(order):
        raise diagnostic_error(ValueError, _STORED_ORDER_MESSAGE)
    if any(index not in range(len(records)) for index in order):
        raise diagnostic_error(ValueError, _STORED_ORDER_MESSAGE)
    return tuple(records[index] for index in order)


def _signature_artifact(
    artifacts: tuple[Artifact, ...], config: OciConfigDocument
) -> Artifact | None:
    if config.signature_path is None:
        return None
    matches = tuple(item for item in artifacts if item.path.value == config.signature_path)
    if len(matches) != 1:
        raise diagnostic_error(ValueError, _STORED_SIGNATURE_MESSAGE)
    return matches[0]


def _snapshot(document: BuildEnvelopeDocument, config: OciConfigDocument) -> SnapshottedSource:
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
        config.release_idempotency_key,
    )
    snapshot = Sha256Digest(config.input_snapshot_sha256)
    return SnapshottedSource(ReleaseSource(release_id, revision), snapshot)


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
        document.size,
        Sha256Digest(document.sha256),
    )


def _lock(document: LockDocument) -> LockIdentity:
    return LockIdentity(ArtifactPath(document.path), Sha256Digest(document.sha256))


def _locks(document: BuildEnvelopeDocument) -> tuple[LockIdentity, ...]:
    return tuple(_lock(item) for item in document.locks)


def _toolchain(document: ToolchainDocument) -> ToolchainIdentity:
    return ToolchainIdentity(document.name, document.version, Sha256Digest(document.sha256))


def _toolchains(document: BuildEnvelopeDocument) -> tuple[ToolchainIdentity, ...]:
    return tuple(_toolchain(item) for item in document.toolchains)


def _evidence(document: EvidenceDocument) -> Evidence:
    return Evidence(
        document.kind,
        document.name,
        Sha256Digest(document.subject),
        EvidenceStatus(document.status),
    )


def _evidence_records(document: BuildEnvelopeDocument) -> tuple[Evidence, ...]:
    return tuple(_evidence(item) for item in document.prequalification_evidence)
