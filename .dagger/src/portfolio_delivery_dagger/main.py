"""Stable Dagger mappings for deterministic Phase 1 release records."""

from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, cast

from dagger import Container, Directory, File, dag, function, object_type

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
from portfolio_delivery.domain.stages import BuildEnvelope as CoreBuildEnvelope
from portfolio_delivery.domain.stages import PrequalifiedBuild as CorePrequalifiedBuild
from portfolio_delivery.domain.stages import ReleaseSource as CoreReleaseSource
from portfolio_delivery.domain.stages import SignedBuild as CoreSignedBuild
from portfolio_delivery.domain.stages import SigningDisposition
from portfolio_delivery.domain.stages import SnapshottedSource as CoreSnapshottedSource
from portfolio_delivery.domain.stages import UnsignedBuild as CoreUnsignedBuild
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
    BuildOutput,
    BuildPlan,
    CheckOutput,
    ProjectComposition,
    SigningOutput,
    SigningPlan,
    VerificationPlan,
)
from portfolio_delivery_dagger.inventory import (
    FileManifest,
    FileRecord,
    SourceInventoryDocument,
    SourceInventoryEntry,
)
from portfolio_delivery_dagger.plan import InputSnapshotPlan

PYTHON_IMAGE: Final = (
    "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)
MAX_JSON_BYTES: Final = 1_048_576
MAX_FILES: Final = 4_096
MAX_PATH_BYTES: Final = 1_024
MAX_FILE_BYTES: Final = 67_108_864
MAX_TOTAL_BYTES: Final = 536_870_912
MAX_MANIFEST_BYTES: Final = 4_194_304
REPOSITORY_SEGMENTS: Final = 2

SCAN_SCRIPT: Final = r"""
import hashlib, json, os, stat
root = '/source'; pending = [root]; files = []; total = 0
while pending:
    directory = pending.pop()
    for entry in os.scandir(directory):
        info = entry.stat(follow_symlinks=False)
        rel = os.path.relpath(entry.path, root).replace(os.sep, '/')
        if len(rel.encode()) > 1024: raise ValueError('path exceeds configured byte limit')
        if stat.S_ISLNK(info.st_mode): raise ValueError('symbolic links are forbidden')
        if stat.S_ISDIR(info.st_mode): pending.append(entry.path); continue
        if not stat.S_ISREG(info.st_mode): raise ValueError('non-regular files are forbidden')
        if info.st_size > 67108864: raise ValueError('file exceeds configured byte limit')
        total += info.st_size
        if total > 536870912: raise ValueError('directory exceeds configured byte limit')
        files.append((rel, entry.path, info.st_size, info.st_dev, info.st_ino))
        if len(files) > 4096: raise ValueError('directory exceeds configured file limit')
records = []
for rel, path, size, device, inode in sorted(files):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode): raise ValueError('file type changed during scan')
        if (current.st_dev, current.st_ino, current.st_size) != (device, inode, size):
            raise ValueError('file changed during scan')
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1048576): digest.update(chunk)
    finally: os.close(fd)
    records.append({'path': rel, 'sha256': 'sha256:' + digest.hexdigest(), 'size': size})
output = json.dumps({'files': records}, sort_keys=True, separators=(',', ':'))
if len(output.encode()) > 4194304: raise ValueError('manifest exceeds configured byte limit')
print(output)
"""

ARCHIVE_SCRIPT: Final = r"""
import hashlib, io, os, stat, tarfile
root = '/inputs'; pending = [root]; files = []; total = 0
while pending:
    directory = pending.pop()
    for entry in os.scandir(directory):
        info = entry.stat(follow_symlinks=False)
        rel = os.path.relpath(entry.path, root).replace(os.sep, '/')
        if len(rel.encode()) > 1024: raise ValueError('path exceeds configured byte limit')
        if stat.S_ISLNK(info.st_mode): raise ValueError('symbolic links are forbidden')
        if stat.S_ISDIR(info.st_mode): pending.append(entry.path); continue
        if not stat.S_ISREG(info.st_mode): raise ValueError('non-regular files are forbidden')
        if info.st_size > 67108864: raise ValueError('file exceeds configured byte limit')
        total += info.st_size
        if total > 536870912: raise ValueError('archive exceeds configured byte limit')
        files.append((rel, entry.path, info.st_size, info.st_dev, info.st_ino))
        if len(files) > 4096: raise ValueError('archive exceeds configured file limit')
contents = []
for rel, path, size, device, inode in sorted(files):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        current = os.fstat(fd)
        if not stat.S_ISREG(current.st_mode): raise ValueError('file type changed during archive')
        if (current.st_dev, current.st_ino, current.st_size) != (device, inode, size):
            raise ValueError('file changed during archive')
        content = b''
        while chunk := os.read(fd, 1048576): content += chunk
    finally: os.close(fd)
    contents.append((rel, content))
lines = [hashlib.sha256(content).hexdigest() + '  ' + rel for rel, content in contents]
checksums = ('\n'.join(lines) + '\n').encode()
if len(files) >= 4096: raise ValueError('archive exceeds configured file limit')
if len(checksums) > 67108864 or total + len(checksums) > 536870912:
    raise ValueError('archive checksum exceeds configured byte limit')
contents.append(('checksums.sha256', checksums))
with tarfile.open('/publish-inputs.tar', 'w') as archive:
    for rel, content in contents:
        info = tarfile.TarInfo(rel); info.size = len(content); info.mode = 0o644
        info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''
        archive.addfile(info, io.BytesIO(content))
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
        """Run checks against only the declared source paths."""
        include, exclude = await _selection(composition)
        filtered = _filter(source, include, exclude)
        output = composition.check(filtered)
        return await _check_dto(output)

    @function
    async def version(
        self,
        source: Directory,
        inventory: File,
        include_paths: list[str],
        exclude_paths: list[str],
        build_input: File,
    ) -> ReleaseSource:
        """Bind trusted Git-tree inventory and validated release identity."""
        document, inventory_doc, digest = await _version_inputs(build_input, inventory)
        filtered = _filter(source, include_paths, exclude_paths)
        await _snapshot_manifest(filtered, inventory_doc, include_paths, exclude_paths)
        _validate_version(document, digest)
        return _release_dto(source, inventory, (include_paths, exclude_paths), document, digest)

    @function
    async def snapshot(self, release: ReleaseSource, plan: InputSnapshotPlan) -> SnapshottedSource:
        """Reconcile typed selection, inventory, and materialized regular bytes."""
        include, exclude = await _selection(plan)
        filtered = _filter(release.source, include, exclude)
        inventory, digest = await _inventory_document(release.inventory)
        _require_release_inventory(release, digest)
        snapshot = await _snapshot_manifest(filtered, inventory, include, exclude)
        return _snapshot_dto(release, filtered, snapshot)

    @function
    async def build(self, source: SnapshottedSource, plan: BuildPlan) -> UnsignedBuild:
        """Delegate output creation while retaining typed snapshot provenance."""
        output = plan.build(source.source, source.manifest, source.input_snapshot_sha256)
        return await _unsigned_dto(source, output)

    @function
    async def prequalify(self, build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild:
        """Delegate checks without allowing provenance replacement."""
        checked = plan.prequalify(
            build.build_input, build.artifacts, build.sboms, build.input_snapshot_sha256
        )
        evidence = await _check_dto(checked)
        await _validate_prequalification(build, evidence)
        return _prequalified_dto(build)

    @function
    async def sign(self, build: PrequalifiedBuild, plan: SigningPlan) -> SignedBuild:
        """Delegate signing without allowing provenance replacement."""
        signed = plan.sign(build.build_input, build.artifacts, build.sboms)
        return await _signed_dto(build, signed)

    @function
    async def envelope(self, build: SignedBuild) -> BuildEnvelope:
        """Validate actual bytes before assembling the pure canonical envelope."""
        state, document = await _validated_signed_build(build)
        envelope = EnvelopeBuilder(_metadata(document)).build(state)
        return _envelope_dto(build, envelope)

    @function
    async def qualify(self, envelope: BuildEnvelope, plan: VerificationPlan) -> QualifiedEnvelope:
        """Validate exact envelope bytes and attach exact qualification bytes."""
        core = await _core_envelope(envelope)
        output = plan.qualify(envelope.envelope, envelope.envelope_sha256)
        evidence = await _check_dto(output)
        qualification, digest = await _qualification_record(core, evidence)
        return _qualified_dto(envelope, qualification, digest)

    @function
    async def publish_inputs(self, envelope: QualifiedEnvelope) -> File:
        """Package revalidated qualified bytes and outputs without rebuilding."""
        await _validate_qualified(envelope)
        return _archive(_publish_directory(envelope))


def _filter(source: Directory, include: list[str], exclude: list[str]) -> Directory:
    return source.filter(include=list(include), exclude=list(exclude), gitignore=False)


async def _selection(plan: InputSnapshotPlan | ProjectComposition) -> tuple[list[str], list[str]]:
    include = await cast(Awaitable[list[str]], plan.include_paths())
    exclude = await cast(Awaitable[list[str]], plan.exclude_paths())
    return list(include), list(exclude)


async def _version_inputs(
    build_input: File, inventory: File
) -> tuple[BuildEnvelopeDocument, SourceInventoryDocument, str]:
    document = await _build_document(build_input)
    inventory_document, digest = await _inventory_document(inventory)
    return document, inventory_document, digest


async def _bounded_bytes(file: File, limit: int) -> bytes:
    if await file.size() > limit:
        raise InvalidIdentity("file exceeds configured JSON byte limit")
    content = (await file.contents()).encode()
    if len(content) > limit:
        raise InvalidIdentity("file exceeds configured JSON byte limit")
    return content


async def _build_document(file: File) -> BuildEnvelopeDocument:
    content = await _bounded_bytes(file, MAX_JSON_BYTES)
    return BuildEnvelopeDocument.model_validate(parse_bounded_json(content, MAX_JSON_BYTES))


async def _inventory_document(file: File) -> tuple[SourceInventoryDocument, str]:
    content = await _bounded_bytes(file, MAX_JSON_BYTES)
    document = SourceInventoryDocument.model_validate(parse_bounded_json(content, MAX_JSON_BYTES))
    canonical = canonical_json_bytes(document)
    if content != canonical:
        raise InvalidIdentity("source inventory must contain exact canonical bytes")
    _validate_inventory_bounds(document)
    return document, Sha256Digest.from_bytes(canonical).value


def _validate_inventory_bounds(document: SourceInventoryDocument) -> None:
    entries = document.entries
    _require(len(entries) <= MAX_FILES, "source inventory exceeds configured file limit")
    _require(
        sum(item.size for item in entries) <= MAX_TOTAL_BYTES,
        "source inventory exceeds configured byte limit",
    )
    _require_inventory_entry_bounds(entries)
    _require(len({item.path for item in entries}) == len(entries), "inventory paths must be unique")


def _require_inventory_entry_bounds(entries: tuple[SourceInventoryEntry, ...]) -> None:
    _require(
        all(len(item.path.encode()) <= MAX_PATH_BYTES for item in entries),
        "source inventory path exceeds configured byte limit",
    )
    _require(
        all(item.size <= MAX_FILE_BYTES for item in entries),
        "source inventory entry exceeds configured byte limit",
    )


async def _snapshot_manifest(
    source: Directory,
    inventory: SourceInventoryDocument,
    include: list[str],
    exclude: list[str],
) -> SnapshotManifest:
    selected = _selected_inventory(inventory, include, exclude)
    _reject_nonregular(selected)
    manifest = await _scan_directory(source)
    _validate_inventory_match(selected, manifest)
    content = canonical_json_bytes(manifest).decode().removesuffix("\n")
    return SnapshotManifest(content, Sha256Digest.from_bytes(content.encode()).value)


def _selected_inventory(
    document: SourceInventoryDocument, include: list[str], exclude: list[str]
) -> tuple[SourceInventoryEntry, ...]:
    return tuple(
        item
        for item in document.entries
        if _selected(item.path, include) and not _selected(item.path, exclude)
    )


def _selected(path: str, patterns: list[str]) -> bool:
    return any(_matches(path, pattern) for pattern in patterns)


def _matches(path: str, pattern: str) -> bool:
    prefix = pattern.removesuffix("/**")
    if prefix != pattern and (path == prefix or path.startswith(f"{prefix}/")):
        return True
    return PurePosixPath(path).match(pattern)


def _reject_nonregular(entries: tuple[SourceInventoryEntry, ...]) -> None:
    if any(item.kind != "regular" for item in entries):
        raise InvalidIdentity("selected source inventory entries must be regular files")


async def _scan_directory(source: Directory) -> FileManifest:
    output = await _scanner(source).stdout()
    content = output.removesuffix("\n").encode()
    return FileManifest.model_validate(parse_bounded_json(content, MAX_MANIFEST_BYTES))


def _scanner(source: Directory) -> Container:
    return (
        dag.container()
        .from_(PYTHON_IMAGE)
        .with_mounted_directory("/source", source)
        .with_exec(["python", "-c", SCAN_SCRIPT])
    )


def _validate_inventory_match(
    selected: tuple[SourceInventoryEntry, ...], actual: FileManifest
) -> None:
    expected = {item.path: (item.size, item.sha256) for item in selected}
    observed = {item.path: (item.size, item.sha256) for item in actual.files}
    if expected != observed:
        raise InvalidIdentity("materialized source must exactly match selected inventory bytes")


def _release_source(
    project: str, version: str, source: SourceDocument, digest: str
) -> CoreReleaseSource:
    _validate_repository(source.repository)
    _validate_ref(source.protected_ref)
    project_id = ProjectId(project)
    source_digest = Sha256Digest(digest)
    revision = SourceRevision(
        project_id, source.repository, source.protected_ref, source.commit_sha, source_digest
    )
    release_id = ReleaseId(project_id, version, source_digest, f"{project}:{version}")
    return CoreReleaseSource(release_id, revision)


def _validate_repository(repository: str) -> None:
    parts = repository.split("/")
    if len(parts) != REPOSITORY_SEGMENTS or any(not item or item != item.strip() for item in parts):
        raise InvalidIdentity("repository must be a canonical owner/name value")


def _validate_ref(protected_ref: str) -> None:
    branch = protected_ref.removeprefix("refs/heads/")
    if branch == protected_ref or not branch or branch != branch.strip():
        raise InvalidIdentity("protected ref must be a canonical refs/heads value")


def _validate_version(document: BuildEnvelopeDocument, digest: str) -> None:
    if document.source.source_tree_sha256 != digest:
        raise InvalidIdentity("declared source digest must match canonical source inventory")
    source = document.source
    _release_source(source.project, document.release_policy.version, source, digest)


def _release_dto(
    source: Directory,
    inventory: File,
    selection: tuple[list[str], list[str]],
    document: BuildEnvelopeDocument,
    digest: str,
) -> ReleaseSource:
    revision = document.source
    include, exclude = selection
    return ReleaseSource(
        source=source,
        inventory=inventory,
        includes=list(include),
        excludes=list(exclude),
        project=revision.project,
        version=document.release_policy.version,
        repository=revision.repository,
        protected_ref=revision.protected_ref,
        commit_sha=revision.commit_sha,
        source_tree_sha256=digest,
    )


def _require_release_inventory(release: ReleaseSource, digest: str) -> None:
    if release.source_tree_sha256 != digest:
        raise InvalidIdentity("release identity must match its canonical source inventory")


def _snapshot_dto(
    release: ReleaseSource, source: Directory, snapshot: SnapshotManifest
) -> SnapshottedSource:
    return SnapshottedSource(
        source=source,
        manifest=dag.file("input-snapshot.v1.json", snapshot.content),
        input_snapshot_sha256=snapshot.sha256,
        project=release.project,
        version=release.version,
        repository=release.repository,
        protected_ref=release.protected_ref,
        commit_sha=release.commit_sha,
        source_tree_sha256=release.source_tree_sha256,
    )


async def _check_dto(output: CheckOutput) -> CheckEvidence:
    passed = await cast(Awaitable[bool], output.passed())
    return CheckEvidence(passed=passed, evidence=output.evidence())


async def _unsigned_dto(source: SnapshottedSource, output: BuildOutput) -> UnsignedBuild:
    return UnsignedBuild(
        source=source.source,
        build_input=output.build_input(),
        input_snapshot_sha256=source.input_snapshot_sha256,
        artifacts=output.artifacts(),
        sboms=output.sboms(),
        project=source.project,
        version=source.version,
        repository=source.repository,
        protected_ref=source.protected_ref,
        commit_sha=source.commit_sha,
        source_tree_sha256=source.source_tree_sha256,
    )


async def _validate_prequalification(build: UnsignedBuild, evidence: CheckEvidence) -> None:
    content = await _bounded_bytes(evidence.evidence, MAX_JSON_BYTES)
    parse_bounded_json(content, MAX_JSON_BYTES)
    if not evidence.passed:
        raise InvalidIdentity("prequalification must pass before signing")


def _prequalified_dto(build: UnsignedBuild) -> PrequalifiedBuild:
    return PrequalifiedBuild(
        source=build.source,
        build_input=build.build_input,
        input_snapshot_sha256=build.input_snapshot_sha256,
        artifacts=build.artifacts,
        sboms=build.sboms,
        project=build.project,
        version=build.version,
        repository=build.repository,
        protected_ref=build.protected_ref,
        commit_sha=build.commit_sha,
        source_tree_sha256=build.source_tree_sha256,
    )


async def _signed_dto(build: PrequalifiedBuild, signed: SigningOutput) -> SignedBuild:
    signature_path = await cast(Awaitable[str | None], signed.signature_path())
    return SignedBuild(
        source=build.source,
        build_input=build.build_input,
        input_snapshot_sha256=build.input_snapshot_sha256,
        artifacts=signed.artifacts(),
        sboms=signed.sboms(),
        signature_path=signature_path,
        project=build.project,
        version=build.version,
        repository=build.repository,
        protected_ref=build.protected_ref,
        commit_sha=build.commit_sha,
        source_tree_sha256=build.source_tree_sha256,
    )


async def _validated_signed_build(
    build: SignedBuild,
) -> tuple[CoreSignedBuild, BuildEnvelopeDocument]:
    document = await _build_document(build.build_input)
    _validate_build_identity(document, build)
    await _validate_build_bytes(document, build)
    return _signed_build(document, build), document


def _validate_build_identity(document: BuildEnvelopeDocument, build: SignedBuild) -> None:
    source = document.source
    observed = (build.project, build.repository, build.protected_ref, build.commit_sha)
    declared = (source.project, source.repository, source.protected_ref, source.commit_sha)
    if observed != declared or build.version != document.release_policy.version:
        raise InvalidIdentity("build provenance must match its release document")
    if build.source_tree_sha256 != source.source_tree_sha256:
        raise InvalidIdentity("build source identity must match its release document")


async def _validate_build_bytes(document: BuildEnvelopeDocument, build: SignedBuild) -> None:
    source, artifacts, sboms = await _build_manifests(build)
    content = canonical_json_bytes(source).decode().removesuffix("\n").encode()
    if Sha256Digest.from_bytes(content).value != build.input_snapshot_sha256:
        raise InvalidIdentity("build source bytes must match the typed input snapshot")
    _validate_artifact_records(document.artifacts, artifacts.files)
    _validate_sbom_records(document.sboms, sboms.files)
    _validate_publish_paths(artifacts.files, sboms.files)
    _validate_evidence_subjects(document.prequalification_evidence, build.source_tree_sha256)


async def _build_manifests(
    build: SignedBuild,
) -> tuple[FileManifest, FileManifest, FileManifest]:
    source = await _scan_directory(build.source)
    artifacts = await _scan_directory(build.artifacts)
    sboms = await _scan_directory(build.sboms)
    return source, artifacts, sboms


def _validate_artifact_records(
    declared: tuple[ArtifactDocument, ...], actual: tuple[FileRecord, ...]
) -> None:
    expected = {item.path: (item.size, item.sha256) for item in declared}
    observed = {item.path: (item.size, item.sha256) for item in actual}
    if expected != observed:
        raise InvalidIdentity("artifact bytes must exactly match envelope declarations")


def _validate_sbom_records(
    declared: tuple[SbomDocument, ...], actual: tuple[FileRecord, ...]
) -> None:
    expected = {item.path: item.sha256 for item in declared}
    observed = {item.path: item.sha256 for item in actual}
    if expected != observed:
        raise InvalidIdentity("SBOM bytes must exactly match envelope declarations")


def _validate_publish_paths(
    artifacts: tuple[FileRecord, ...], sboms: tuple[FileRecord, ...]
) -> None:
    artifact_paths = {item.path for item in artifacts}
    sbom_paths = {item.path for item in sboms}
    reserved = {"checksums.sha256"}
    protected = artifact_paths | sbom_paths
    _require(
        not artifact_paths & sbom_paths and not protected & reserved,
        "published output paths must be unique and non-reserved",
    )
    _require(
        all(not path.startswith("records/") for path in protected),
        "published output paths must not overlap release records",
    )


def _validate_evidence_subjects(declared: tuple[EvidenceDocument, ...], subject: str) -> None:
    if any(item.subject != subject for item in declared):
        raise InvalidIdentity("prequalification evidence must target the bound source identity")


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
    artifacts = tuple(_artifact(item) for item in document.artifacts)
    signature = _signature(artifacts, build.signature_path)
    unsigned = _unsigned_state(document, build, artifacts)
    evidence = tuple(_evidence(item) for item in document.prequalification_evidence)
    state = CorePrequalifiedBuild(unsigned, evidence)
    return CoreSignedBuild(state, signature, _disposition(signature))


def _unsigned_state(
    document: BuildEnvelopeDocument, build: SignedBuild, artifacts: tuple[Artifact, ...]
) -> CoreUnsignedBuild:
    return CoreUnsignedBuild(
        _snapshot_source(document, build.input_snapshot_sha256),
        _unsigned_artifacts(artifacts, build.signature_path),
        _sboms(document),
        _locks(document),
        _toolchains(document),
    )


def _unsigned_artifacts(
    artifacts: tuple[Artifact, ...], signature_path: str | None
) -> tuple[Artifact, ...]:
    return tuple(item for item in artifacts if item.path.value != signature_path)


def _sboms(document: BuildEnvelopeDocument) -> tuple[Sbom, ...]:
    return tuple(_sbom(item) for item in document.sboms)


def _locks(document: BuildEnvelopeDocument) -> tuple[LockIdentity, ...]:
    return tuple(_lock(item) for item in document.locks)


def _toolchains(document: BuildEnvelopeDocument) -> tuple[ToolchainIdentity, ...]:
    return tuple(_toolchain(item) for item in document.toolchains)


def _snapshot_source(document: BuildEnvelopeDocument, snapshot: str) -> CoreSnapshottedSource:
    source = document.source
    release = _release_source(
        source.project, document.release_policy.version, source, source.source_tree_sha256
    )
    return CoreSnapshottedSource(release, Sha256Digest(snapshot))


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


def _signature(artifacts: tuple[Artifact, ...], path: str | None) -> Artifact | None:
    if path is None:
        return None
    matches = tuple(item for item in artifacts if item.path.value == path)
    _require(len(matches) == 1, "signature path must identify exactly one artifact")
    return matches[0]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidIdentity(message)


def _disposition(signature: Artifact | None) -> SigningDisposition:
    return SigningDisposition.SIGNED if signature else SigningDisposition.SIGNING_NOT_REQUIRED


def _envelope_dto(build: SignedBuild, envelope: CoreBuildEnvelope) -> BuildEnvelope:
    return BuildEnvelope(
        envelope=dag.file("build-envelope.v1.json", envelope.canonical_bytes.decode()),
        envelope_sha256=envelope.content_sha256.value,
        artifacts=build.artifacts,
        sboms=build.sboms,
        source=build.source,
        build_input=build.build_input,
        input_snapshot_sha256=build.input_snapshot_sha256,
        signature_path=build.signature_path,
        project=build.project,
        version=build.version,
        repository=build.repository,
        protected_ref=build.protected_ref,
        commit_sha=build.commit_sha,
        source_tree_sha256=build.source_tree_sha256,
    )


async def _core_envelope(envelope: BuildEnvelope) -> CoreBuildEnvelope:
    state, document = await _validated_signed_build(_envelope_build(envelope))
    expected = EnvelopeBuilder(_metadata(document)).build(state)
    content = await _bounded_bytes(envelope.envelope, MAX_JSON_BYTES)
    parse_bounded_json(content, MAX_JSON_BYTES)
    if (
        content != expected.canonical_bytes
        or envelope.envelope_sha256 != expected.content_sha256.value
    ):
        raise InvalidIdentity("envelope file, digest, and validated build bytes must agree")
    return expected


def _envelope_build(envelope: BuildEnvelope) -> SignedBuild:
    return SignedBuild(
        source=envelope.source,
        build_input=envelope.build_input,
        input_snapshot_sha256=envelope.input_snapshot_sha256,
        artifacts=envelope.artifacts,
        sboms=envelope.sboms,
        signature_path=envelope.signature_path,
        project=envelope.project,
        version=envelope.version,
        repository=envelope.repository,
        protected_ref=envelope.protected_ref,
        commit_sha=envelope.commit_sha,
        source_tree_sha256=envelope.source_tree_sha256,
    )


async def _qualification_record(
    envelope: CoreBuildEnvelope, evidence: CheckEvidence
) -> tuple[File, str]:
    content = await _bounded_bytes(evidence.evidence, MAX_JSON_BYTES)
    payload = parse_bounded_json(content, MAX_JSON_BYTES)
    document = QualificationRecordDocument.model_validate(payload)
    checks = tuple(_evidence(item) for item in document.qualification_evidence)
    _validate_check_summary(evidence.passed, checks)
    record = QualificationBuilder().build(envelope, checks)
    file = dag.file("qualification-record.v1.json", record.canonical_bytes.decode())
    return file, record.content_sha256.value


def _validate_check_summary(passed: bool, checks: tuple[Evidence, ...]) -> None:
    actual = all(check.status is EvidenceStatus.PASSED for check in checks)
    if passed != actual:
        raise InvalidIdentity("check summary must match detached evidence statuses")


def _qualified_dto(envelope: BuildEnvelope, qualification: File, digest: str) -> QualifiedEnvelope:
    return QualifiedEnvelope(
        envelope=envelope.envelope,
        qualification=qualification,
        envelope_sha256=envelope.envelope_sha256,
        qualification_sha256=digest,
        artifacts=envelope.artifacts,
        sboms=envelope.sboms,
    )


async def _validate_qualified(envelope: QualifiedEnvelope) -> None:
    content = await _bounded_bytes(envelope.envelope, MAX_JSON_BYTES)
    qualification = await _bounded_bytes(envelope.qualification, MAX_JSON_BYTES)
    if Sha256Digest.from_bytes(content).value != envelope.envelope_sha256:
        raise InvalidIdentity("published envelope digest must match exact bytes")
    if Sha256Digest.from_bytes(qualification).value != envelope.qualification_sha256:
        raise InvalidIdentity("published qualification digest must match exact bytes")
    await _scan_directory(envelope.artifacts)
    await _scan_directory(envelope.sboms)


def _publish_directory(envelope: QualifiedEnvelope) -> Directory:
    return (
        dag.directory()
        .with_file("records/build-envelope.v1.json", envelope.envelope)
        .with_file("records/qualification-record.v1.json", envelope.qualification)
        .with_directory(".", envelope.artifacts)
        .with_directory(".", envelope.sboms)
    )


def _archive(inputs: Directory) -> File:
    return (
        dag.container()
        .from_(PYTHON_IMAGE)
        .with_directory("/inputs", inputs)
        .with_exec(["python", "-c", ARCHIVE_SCRIPT])
        .file("/publish-inputs.tar")
    )
