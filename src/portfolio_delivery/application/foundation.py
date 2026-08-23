"""Ordered pure-core assembly and exact-byte persistence for release envelopes."""

from __future__ import annotations

from dataclasses import dataclass

from portfolio_delivery.contracts.build import Builder, InputSnapshotter, Signer, Verifier
from portfolio_delivery.contracts.storage import ArtifactStore
from portfolio_delivery.domain.artifacts import Artifact
from portfolio_delivery.domain.errors import InvalidIdentity
from portfolio_delivery.domain.stages import (
    BuildEnvelope,
    BuildPlan,
    EnvelopeBundle,
    InputSnapshotPlan,
    QualificationRecord,
    QualifiedEnvelope,
    ReleaseSource,
    SigningPolicy,
    StoredEnvelope,
    VerificationPlan,
    validate_attempt_id,
)
from portfolio_delivery.envelope.builder import EnvelopeBuilder
from portfolio_delivery.envelope.canonical import canonical_json_bytes
from portfolio_delivery.envelope.documents import QualificationRecordDocument


@dataclass(frozen=True, slots=True)
class FoundationDependencies:
    """Narrow ports used by the staged foundation workflow."""

    snapshotter: InputSnapshotter
    builder: Builder
    verifier: Verifier
    signer: Signer
    store: ArtifactStore


class FoundationService:
    """Coordinate only the immutable stages that precede delivery mutation."""

    def __init__(
        self, dependencies: FoundationDependencies, envelope_builder: EnvelopeBuilder
    ) -> None:
        self._dependencies = dependencies
        self._envelope_builder = envelope_builder

    async def qualify(
        self,
        source: ReleaseSource,
        snapshot_plan: InputSnapshotPlan,
        build_plan: BuildPlan,
        signing_policy: SigningPolicy,
        verification_plan: VerificationPlan,
    ) -> QualifiedEnvelope:
        snapshot = await self._dependencies.snapshotter.snapshot(source, snapshot_plan)
        build = await self._dependencies.builder.build(snapshot, build_plan)
        prequalified = await self._dependencies.verifier.prequalify(build, verification_plan)
        signed = await self._dependencies.signer.sign(prequalified, signing_policy)
        envelope = self._envelope_builder.build(signed)
        qualification = await self._dependencies.verifier.qualify(envelope, verification_plan)
        _validate_final_qualification(envelope, qualification)
        return QualifiedEnvelope(envelope, qualification)

    async def persist(self, qualified: QualifiedEnvelope, attempt_id: str) -> StoredEnvelope:
        validate_attempt_id(attempt_id)
        return await self._dependencies.store.persist(_bundle_for(qualified), attempt_id)


def _bundle_for(qualified: QualifiedEnvelope) -> EnvelopeBundle:
    unsigned = qualified.envelope.signed.prequalified.unsigned
    return EnvelopeBundle(qualified, _signed_artifacts(qualified), unsigned.sboms)


def _signed_artifacts(qualified: QualifiedEnvelope) -> tuple[Artifact, ...]:
    signed = qualified.envelope.signed
    if signed.signature is None:
        return signed.prequalified.unsigned.artifacts
    return (*signed.prequalified.unsigned.artifacts, signed.signature)


def _validate_final_qualification(
    envelope: BuildEnvelope, qualification: QualificationRecord
) -> None:
    document = _qualification_document(qualification)
    _require_canonical_qualification_bytes(qualification, document)
    _require_qualification_subject(envelope, qualification)
    _require_evidence_subjects(envelope, document)


def _qualification_document(qualification: QualificationRecord) -> QualificationRecordDocument:
    if not isinstance(qualification, QualificationRecord):
        raise InvalidIdentity("final qualification must be a qualification record")
    if not isinstance(qualification.document, QualificationRecordDocument):
        raise InvalidIdentity("final qualification document must be a qualification document")
    return qualification.document


def _require_canonical_qualification_bytes(
    qualification: QualificationRecord, document: QualificationRecordDocument
) -> None:
    if canonical_json_bytes(document) != qualification.canonical_bytes:
        raise InvalidIdentity("final qualification bytes must match its canonical document")


def _require_qualification_subject(
    envelope: BuildEnvelope, qualification: QualificationRecord
) -> None:
    if qualification.subject != envelope.content_sha256:
        raise InvalidIdentity("final qualification must target the final envelope digest")


def _require_evidence_subjects(
    envelope: BuildEnvelope, document: QualificationRecordDocument
) -> None:
    if document.subject != envelope.content_sha256.value:
        raise InvalidIdentity("final qualification document must target the final envelope digest")
    subjects = tuple(item.subject for item in document.qualification_evidence)
    if any(subject != envelope.content_sha256.value for subject in subjects):
        raise InvalidIdentity("final qualification evidence must target the final envelope digest")
