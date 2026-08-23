"""Stable Dagger mappings for deterministic Phase 1 release records."""

from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Final, cast

from dagger import Directory, File, dag, function, object_type

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
    BuildEnvelope as CoreBuildEnvelope,
)
from portfolio_delivery.domain.stages import (
    PrequalifiedBuild as CorePrequalifiedBuild,
)
from portfolio_delivery.domain.stages import (
    ReleaseSource as CoreReleaseSource,
)
from portfolio_delivery.domain.stages import (
    SignedBuild as CoreSignedBuild,
)
from portfolio_delivery.domain.stages import (
    SigningDisposition,
)
from portfolio_delivery.domain.stages import (
    SnapshottedSource as CoreSnapshottedSource,
)
from portfolio_delivery.domain.stages import (
    UnsignedBuild as CoreUnsignedBuild,
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
from portfolio_delivery.envelope.canonical import canonical_json_bytes
from portfolio_delivery.envelope.documents import (
    ArtifactDocument,
    BuildEnvelopeDocument,
    EvidenceDocument,
    LockDocument,
    QualificationRecordDocument,
    SbomDocument,
    SourceDocument,
    ToolchainDocument,
)
from portfolio_delivery_dagger.dto import (
    BuildEnvelope,
    CheckEvidence,
    PrequalifiedBuild,
    QualifiedEnvelope,
    ReleaseSource,
    SignedBuild,
    SnapshottedSource,
    UnsignedBuild,
)
from portfolio_delivery_dagger.interfaces import (
    BuildPlan,
    ProjectComposition,
    SigningPlan,
    VerificationPlan,
)

PYTHON_IMAGE: Final = (
    "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)
REPOSITORY_SEGMENTS: Final = 2
HASH_SCRIPT: Final = """
import hashlib, json, pathlib
root = pathlib.Path('/source')
files = []
for path in sorted(item for item in root.rglob('*') if item.is_file()):
    content = path.read_bytes()
    files.append({'path': path.relative_to(root).as_posix(),
                  'sha256': 'sha256:' + hashlib.sha256(content).hexdigest(),
                  'size': len(content)})
print(json.dumps({'files': files}, sort_keys=True, separators=(',', ':')))
"""
ARCHIVE_SCRIPT: Final = """
import hashlib, pathlib, tarfile
root = pathlib.Path('/inputs')
paths = sorted(path for path in root.rglob('*') if path.is_file())
lines = [hashlib.sha256(path.read_bytes()).hexdigest() + '  ' +
         path.relative_to(root).as_posix() for path in paths]
(root / 'checksums.sha256').write_text('\\n'.join(lines) + '\\n', encoding='utf-8')
with tarfile.open('/publish-inputs.tar', 'w') as archive:
    for path in sorted(item for item in root.rglob('*') if item.is_file()):
        info = archive.gettarinfo(str(path), path.relative_to(root).as_posix())
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ''
        info.mode = 0o644
        with path.open('rb') as stream:
            archive.addfile(info, stream)
"""


@dataclass(frozen=True, slots=True)
class SnapshotManifest:
    """Canonical manifest text and its public SHA-256 identity."""

    content: str
    sha256: str


@object_type
class PortfolioDelivery:
    """Expose provider-independent Phase 1 release assembly."""

    @function
    async def check(self, source: Directory, composition: ProjectComposition) -> CheckEvidence:
        """Run project checks against only the declared source paths."""
        include_paths = await cast(Awaitable[list[str]], composition.include_paths())
        exclude_paths = await cast(Awaitable[list[str]], composition.exclude_paths())
        filtered = _filter_source(source, include_paths, exclude_paths)
        return await cast(Awaitable[CheckEvidence], composition.check(filtered))

    @function
    async def version(
        self,
        source: Directory,
        include_paths: list[str],
        exclude_paths: list[str],
        build_input: File,
    ) -> ReleaseSource:
        """Validate one full source revision and derive its byte identity."""
        filtered = _filter_source(source, include_paths, exclude_paths)
        snapshot = await _snapshot_manifest(filtered)
        document = await _build_document(build_input)
        _validate_version(document, snapshot.sha256)
        return _release_dto(filtered, document, snapshot.sha256)

    @function
    async def snapshot(
        self, source: Directory, include_paths: list[str], exclude_paths: list[str]
    ) -> SnapshottedSource:
        """Filter source and emit a canonical per-file SHA-256 manifest."""
        filtered = _filter_source(source, include_paths, exclude_paths)
        snapshot = await _snapshot_manifest(filtered)
        manifest = dag.file("input-snapshot.v1.json", snapshot.content)
        return SnapshottedSource(
            source=filtered, manifest=manifest, input_snapshot_sha256=snapshot.sha256
        )

    @function
    async def build(self, source: SnapshottedSource, plan: BuildPlan) -> UnsignedBuild:
        """Delegate one exact source snapshot to a typed build plan."""
        return await cast(Awaitable[UnsignedBuild], plan.build(source))

    @function
    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        """Delegate pre-signing checks to a typed verification plan."""
        return await cast(Awaitable[PrequalifiedBuild], plan.prequalify(build))

    @function
    async def sign(self, build: PrequalifiedBuild, plan: SigningPlan) -> SignedBuild:
        """Delegate signing after prequalification to a typed signing plan."""
        return await cast(Awaitable[SignedBuild], plan.sign(build))

    @function
    async def envelope(self, build: SignedBuild) -> BuildEnvelope:
        """Assemble exact canonical envelope bytes through the pure builder."""
        document = await _build_document(build.build_input)
        envelope = EnvelopeBuilder(_metadata(document)).build(_signed_build(document, build))
        return BuildEnvelope(
            envelope=dag.file("build-envelope.v1.json", envelope.canonical_bytes.decode()),
            envelope_sha256=envelope.content_sha256.value,
            artifacts=build.artifacts,
            sboms=build.sboms,
        )

    @function
    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualifiedEnvelope:
        """Pair exact envelope bytes with a detached qualification record."""
        evidence = await cast(Awaitable[CheckEvidence], plan.qualify(envelope))
        record = await _qualification_record(envelope.envelope, evidence)
        return QualifiedEnvelope(
            envelope=envelope.envelope,
            qualification=record[0],
            envelope_sha256=envelope.envelope_sha256,
            qualification_sha256=record[1],
            artifacts=envelope.artifacts,
            sboms=envelope.sboms,
        )

    @function
    def publish_inputs(self, envelope: QualifiedEnvelope) -> File:
        """Package exact qualified bytes and outputs without rebuilding."""
        inputs = _publish_directory(envelope)
        return (
            dag.container()
            .from_(PYTHON_IMAGE)
            .with_directory("/inputs", inputs)
            .with_exec(["python", "-c", ARCHIVE_SCRIPT])
            .file("/publish-inputs.tar")
        )


def _filter_source(source: Directory, include: list[str], exclude: list[str]) -> Directory:
    return source.filter(include=list(include), exclude=list(exclude), gitignore=False)


async def _snapshot_manifest(source: Directory) -> SnapshotManifest:
    output = await (
        dag.container()
        .from_(PYTHON_IMAGE)
        .with_mounted_directory("/source", source)
        .with_exec(["python", "-c", HASH_SCRIPT])
        .stdout()
    )
    content = output.removesuffix("\n")
    return SnapshotManifest(content, Sha256Digest.from_bytes(content.encode()).value)


def _release_source(
    project: str, version: str, source: SourceDocument, source_sha256: str
) -> CoreReleaseSource:
    _validate_repository(source.repository)
    _validate_ref(source.protected_ref)
    project_id = ProjectId(project)
    digest = Sha256Digest(source_sha256)
    revision = SourceRevision(
        project_id, source.repository, source.protected_ref, source.commit_sha, digest
    )
    release_id = ReleaseId(project_id, version, digest, _release_key(project, version))
    return CoreReleaseSource(release_id, revision)


def _require_source_digest(source: SourceDocument, source_sha256: str) -> None:
    if source.source_tree_sha256 != source_sha256:
        raise InvalidIdentity("declared source digest must match filtered source bytes")


def _validate_repository(repository: str) -> None:
    parts = repository.split("/")
    if len(parts) != REPOSITORY_SEGMENTS:
        raise InvalidIdentity("repository must be a canonical owner/name value")
    if any(not part or part != part.strip() for part in parts):
        raise InvalidIdentity("repository must be a canonical owner/name value")


def _validate_ref(protected_ref: str) -> None:
    branch = protected_ref.removeprefix("refs/heads/")
    if branch == protected_ref or not branch or branch != branch.strip():
        raise InvalidIdentity("protected ref must be a canonical refs/heads value")


def _release_key(project: str, version: str) -> str:
    return f"{project}:{version}"


async def _build_document(file: File) -> BuildEnvelopeDocument:
    return BuildEnvelopeDocument.model_validate_json(await file.contents())


def _validate_version(document: BuildEnvelopeDocument, source_sha256: str) -> None:
    revision = document.source
    _require_source_digest(revision, source_sha256)
    _release_source(revision.project, document.release_policy.version, revision, source_sha256)


def _release_dto(
    source: Directory, document: BuildEnvelopeDocument, source_sha256: str
) -> ReleaseSource:
    revision = document.source
    return ReleaseSource(
        source=source,
        project=revision.project,
        version=document.release_policy.version,
        repository=revision.repository,
        protected_ref=revision.protected_ref,
        commit_sha=revision.commit_sha,
        source_tree_sha256=source_sha256,
    )


def _metadata(document: BuildEnvelopeDocument) -> EnvelopeMetadata:
    policy = document.release_policy
    compatibility = document.compatibility
    return EnvelopeMetadata(
        ProjectAdapterVersion(document.project_adapter_version),
        document.source_date_epoch,
        ReleasePolicyMetadata(
            policy.version, tuple(ReleaseChannel(item) for item in policy.channels)
        ),
        PinnedCompatibility(compatibility.dagger, compatibility.oras),
    )


def _signed_build(document: BuildEnvelopeDocument, build: SignedBuild) -> CoreSignedBuild:
    artifacts = _artifacts(document)
    signature = _signature(artifacts, build.signature_path)
    unsigned = _unsigned_build(document, build, artifacts)
    prequalified = CorePrequalifiedBuild(unsigned, _prequalification_evidence(document))
    return CoreSignedBuild(prequalified, signature, _disposition(signature))


def _unsigned_build(
    document: BuildEnvelopeDocument,
    build: SignedBuild,
    artifacts: tuple[Artifact, ...],
) -> CoreUnsignedBuild:
    unsigned = CoreUnsignedBuild(
        _snapshot_source(document, build.input_snapshot_sha256),
        _unsigned_artifacts(artifacts, build.signature_path),
        _sboms(document),
        _locks(document),
        _toolchains(document),
    )
    return unsigned


def _artifacts(document: BuildEnvelopeDocument) -> tuple[Artifact, ...]:
    return tuple(_artifact(item) for item in document.artifacts)


def _sboms(document: BuildEnvelopeDocument) -> tuple[Sbom, ...]:
    return tuple(_sbom(item) for item in document.sboms)


def _locks(document: BuildEnvelopeDocument) -> tuple[LockIdentity, ...]:
    return tuple(_lock(item) for item in document.locks)


def _toolchains(document: BuildEnvelopeDocument) -> tuple[ToolchainIdentity, ...]:
    return tuple(_toolchain(item) for item in document.toolchains)


def _prequalification_evidence(document: BuildEnvelopeDocument) -> tuple[Evidence, ...]:
    return tuple(_evidence(item) for item in document.prequalification_evidence)


def _snapshot_source(
    document: BuildEnvelopeDocument, input_snapshot_sha256: str
) -> CoreSnapshottedSource:
    source = document.source
    release = _release_source(
        source.project,
        document.release_policy.version,
        source,
        source.source_tree_sha256,
    )
    return CoreSnapshottedSource(release, Sha256Digest(input_snapshot_sha256))


def _artifact(document: ArtifactDocument) -> Artifact:
    return Artifact(
        document.name,
        ArtifactPath(document.path),
        document.media_type,
        document.size,
        Sha256Digest(document.sha256),
    )


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


def _signature(artifacts: tuple[Artifact, ...], signature_path: str | None) -> Artifact | None:
    if signature_path is None:
        return None
    matches = tuple(item for item in artifacts if item.path.value == signature_path)
    if len(matches) != 1:
        raise InvalidIdentity("signature path must identify exactly one artifact")
    return matches[0]


def _unsigned_artifacts(
    artifacts: tuple[Artifact, ...], signature_path: str | None
) -> tuple[Artifact, ...]:
    return tuple(item for item in artifacts if item.path.value != signature_path)


def _disposition(signature: Artifact | None) -> SigningDisposition:
    if signature is None:
        return SigningDisposition.SIGNING_NOT_REQUIRED
    return SigningDisposition.SIGNED


async def _qualification_record(envelope_file: File, evidence: CheckEvidence) -> tuple[File, str]:
    envelope = await _core_envelope(envelope_file)
    document = QualificationRecordDocument.model_validate_json(await evidence.evidence.contents())
    checks = tuple(_evidence(item) for item in document.qualification_evidence)
    _validate_check_summary(evidence.passed, checks)
    record = QualificationBuilder().build(envelope, checks)
    file = dag.file("qualification.v1.json", record.canonical_bytes.decode())
    return file, record.content_sha256.value


async def _core_envelope(file: File) -> CoreBuildEnvelope:
    content = (await file.contents()).encode()
    document = BuildEnvelopeDocument.model_validate_json(content)
    canonical = canonical_json_bytes(document)
    if content != canonical:
        raise InvalidIdentity("qualified envelope file must contain exact canonical bytes")
    state = _synthetic_signed_build(document, document.source.source_tree_sha256)
    return CoreBuildEnvelope(state, document, content, Sha256Digest.from_bytes(content))


def _synthetic_signed_build(
    document: BuildEnvelopeDocument, snapshot_sha256: str
) -> CoreSignedBuild:
    state = SignedBuild(
        source=dag.directory(),
        build_input=dag.file("input.json", "{}"),
        input_snapshot_sha256=snapshot_sha256,
        artifacts=dag.directory(),
        sboms=dag.directory(),
        signature_path=None,
    )
    return _signed_build(document, state)


def _validate_check_summary(passed: bool, checks: tuple[Evidence, ...]) -> None:
    all_passed = all(check.status is EvidenceStatus.PASSED for check in checks)
    if passed != all_passed:
        raise InvalidIdentity("check summary must match detached evidence statuses")


def _publish_directory(envelope: QualifiedEnvelope) -> Directory:
    return (
        dag.directory()
        .with_file("records/build-envelope.v1.json", envelope.envelope)
        .with_file("records/qualification.v1.json", envelope.qualification)
        .with_directory("artifacts", envelope.artifacts)
        .with_directory("sboms", envelope.sboms)
    )
