"""Dagger-compatible state objects for the stable Phase 1 boundary."""

from __future__ import annotations

from dataclasses import dataclass

from dagger import Directory, File, field, function, object_type

from portfolio_delivery_dagger.plan import InputSnapshotPlan


@dataclass(kw_only=True)
@object_type
class CheckEvidence:
    """One typed check outcome and its detached evidence document."""

    passed: bool = field()
    evidence: File = field()


@dataclass(kw_only=True)
@object_type
class ReleaseSource(InputSnapshotPlan):
    """A validated source revision paired with its explicit directory."""

    source: Directory = field()
    inventory: File = field()
    includes: list[str] = field()
    excludes: list[str] = field()
    project: str = field()
    version: str = field()
    repository: str = field()
    protected_ref: str = field()
    commit_sha: str = field()
    source_tree_sha256: str = field()

    @function
    def include_paths(self) -> list[str]:
        return list(self.includes)

    @function
    def exclude_paths(self) -> list[str]:
        return list(self.excludes)


@dataclass(kw_only=True)
@object_type
class SnapshottedSource:
    """A filtered source and canonical per-file SHA-256 manifest."""

    source: Directory = field()
    manifest: File = field()
    input_snapshot_sha256: str = field()
    project: str = field()
    version: str = field()
    repository: str = field()
    protected_ref: str = field()
    commit_sha: str = field()
    source_tree_sha256: str = field()


@dataclass(kw_only=True)
@object_type
class UnsignedBuild:
    """Declared build outputs before verification and signing."""

    source: Directory = field()
    build_input: File = field()
    input_snapshot_sha256: str = field()
    artifacts: Directory = field()
    sboms: Directory = field()
    project: str = field()
    version: str = field()
    repository: str = field()
    protected_ref: str = field()
    commit_sha: str = field()
    source_tree_sha256: str = field()


@dataclass(kw_only=True)
@object_type
class PrequalifiedBuild:
    """Build outputs carrying exact prequalification evidence."""

    source: Directory = field()
    build_input: File = field()
    input_snapshot_sha256: str = field()
    artifacts: Directory = field()
    sboms: Directory = field()
    prequalification_evidence: File = field()
    prequalification_evidence_sha256: str = field()
    project: str = field()
    version: str = field()
    repository: str = field()
    protected_ref: str = field()
    commit_sha: str = field()
    source_tree_sha256: str = field()


@dataclass(kw_only=True)
@object_type
class SignedBuild:
    """Prequalified outputs after the explicit signing disposition."""

    source: Directory = field()
    build_input: File = field()
    input_snapshot_sha256: str = field()
    artifacts: Directory = field()
    sboms: Directory = field()
    prequalification_evidence: File = field()
    prequalification_evidence_sha256: str = field()
    signature_path: str | None = field()
    project: str = field()
    version: str = field()
    repository: str = field()
    protected_ref: str = field()
    commit_sha: str = field()
    source_tree_sha256: str = field()


@dataclass(kw_only=True)
@object_type
class BuildEnvelope:
    """Exact canonical envelope bytes and the outputs they describe."""

    envelope: File = field()
    envelope_sha256: str = field()
    artifacts: Directory = field()
    sboms: Directory = field()
    source: Directory = field()
    build_input: File = field()
    input_snapshot_sha256: str = field()
    prequalification_evidence: File = field()
    prequalification_evidence_sha256: str = field()
    signature_path: str | None = field()
    project: str = field()
    version: str = field()
    repository: str = field()
    protected_ref: str = field()
    commit_sha: str = field()
    source_tree_sha256: str = field()


@dataclass(kw_only=True)
@object_type
class QualifiedEnvelope:
    """Exact envelope bytes paired with one detached qualification record."""

    envelope: File = field()
    qualification: File = field()
    envelope_sha256: str = field()
    qualification_sha256: str = field()
    artifacts: Directory = field()
    sboms: Directory = field()
    prequalification_evidence: File = field()
    prequalification_evidence_sha256: str = field()
