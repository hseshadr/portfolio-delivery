"""In-memory exact-byte artifact-store and ORAS-runner fakes."""

from portfolio_delivery.domain.identity import Sha256Digest
from portfolio_delivery.domain.stages import (
    EnvelopeBundle,
    OciReference,
    OrasInvocation,
    OrasResult,
    StoredEnvelope,
    validate_attempt_id,
)


class FakeArtifactStore:
    """Store complete bundles and reject a second payload for one content tag."""

    def __init__(self, repository: str = "memory.local/portfolio-delivery") -> None:
        self.repository = repository
        self.bundles: dict[str, EnvelopeBundle] = {}
        self.observation_count = 0
        self.write_count = 0

    async def inspect(self, reference: OciReference, attempt_id: str) -> StoredEnvelope | None:
        validate_attempt_id(attempt_id)
        self.observation_count += 1
        bundle = self.bundles.get(_store_key(reference))
        return _stored_envelope(reference, bundle)

    async def persist(self, bundle: EnvelopeBundle, attempt_id: str) -> StoredEnvelope:
        validate_attempt_id(attempt_id)
        reference = _reference_for(bundle, self.repository)
        _store_bundle(self, reference, bundle)
        return _require_stored_envelope(reference, bundle)

    async def restore(self, reference: OciReference, attempt_id: str) -> EnvelopeBundle:
        validate_attempt_id(attempt_id)
        self.observation_count += 1
        bundle = self.bundles[_store_key(reference)]
        return bundle


def _store_key(reference: OciReference) -> str:
    return f"{reference.repository}:{reference.tag}"


def _reference_for(bundle: EnvelopeBundle, repository: str) -> OciReference:
    digest = bundle.qualified.envelope.content_sha256
    return OciReference(repository, f"sha256-{digest.hex}")


def _store_bundle(
    store: FakeArtifactStore,
    reference: OciReference,
    bundle: EnvelopeBundle,
) -> None:
    key = _store_key(reference)
    existing = store.bundles.get(key)
    if existing is not None and _bundle_bytes(existing) != _bundle_bytes(bundle):
        raise ValueError("conflicting bytes for an immutable content tag")
    if existing is None:
        store.bundles[key] = bundle
        store.write_count += 1


def _stored_envelope(
    reference: OciReference,
    bundle: EnvelopeBundle | None,
) -> StoredEnvelope | None:
    if bundle is None:
        return None
    manifest = Sha256Digest.from_bytes(_bundle_bytes(bundle))
    return StoredEnvelope(reference, manifest)


def _require_stored_envelope(reference: OciReference, bundle: EnvelopeBundle) -> StoredEnvelope:
    stored = _stored_envelope(reference, bundle)
    if stored is None:
        raise RuntimeError("a persisted bundle must have a stored envelope")
    return stored


def _bundle_bytes(bundle: EnvelopeBundle) -> bytes:
    envelope = bundle.qualified.envelope.canonical_bytes
    qualification = bundle.qualified.qualification.canonical_bytes
    return envelope + qualification


class FakeOrasRunner:
    """Return configured ORAS results while retaining full invocations."""

    def __init__(self, result: OrasResult) -> None:
        self.result = result
        self.invocations: list[OrasInvocation] = []

    async def run(self, invocation: OrasInvocation, attempt_id: str) -> OrasResult:
        validate_attempt_id(attempt_id)
        self.invocations.append(invocation)
        return self.result
