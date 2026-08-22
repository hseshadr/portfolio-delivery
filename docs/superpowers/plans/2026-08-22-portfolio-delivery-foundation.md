# Portfolio Delivery Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Phase 1 as a tested, typed foundation that creates and qualifies deterministic release envelopes and stores them as generic OCI artifacts without giving Dagger release authority.

**Architecture:** A Python 3.13 package owns immutable domain records, narrow `Protocol` ports, canonical serialization, qualification, and provider-independent reconciliation. A separate Dagger Python module maps those pure records to Dagger `@object_type`, `@interface`, `Directory`, `File`, `Secret`, and `Service` types. ORAS is split into a pure command/manifest adapter and a Dagger executor so provider behavior is testable without leaking Dagger types into the domain.

**Tech Stack:** Python 3.13.14, uv, Pydantic v2, pytest, Hypothesis, mutmut, Ruff, mypy strict, Xenon/Radon Grade A, Dagger v0.21.8, ORAS v1.3.3, OCI Distribution Spec 1.1.

**Spec:** `docs/superpowers/specs/2026-08-22-portfolio-delivery-design.md`

## Global Constraints

- Phase 1 includes only the pure domain/core, its contracts and test fakes, deterministic `BuildEnvelope` and detached `QualificationRecord`, the generic-OCI ORAS adapter, the stable Dagger module, and their conformance/integration tests.
- Phase 1 does not implement the Durable Object controller, GitHub reusable workflows, Release Please behavior, npm/PyPI publication, Cloudflare deployment, maturity alarms, consumer PRs, or production rollout.
- Python is `3.13`; the repository and Dagger runtime use `3.13.14` and reject Python 3.14.
- Dagger engine, CLI, and Python SDK are `v0.21.8` at source commit `7902e644beeba4468f1ea786015b4be1d6d5bbcd`.
- `dagger/dagger-for-github` is `v8.4.1` at commit `27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77`.
- Node.js is `v24.19.0` LTS; Wrangler is `4.120.0`; `@cloudflare/vitest-pool-workers` is `0.20.3`.
- ORAS is `v1.3.3`, using `ghcr.io/oras-project/oras@sha256:a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8`.
- `googleapis/release-please-action` v4 is pinned to `5c625bfb5d1ff62eadeeb3772007f7f66fdcf071`.
- The Dagger CLI checksums are `f3f37a831afd53d09bf9c9a9df63492c16ad43622e5c197d9815e82f334ef1c4` for Darwin arm64 and `53e226c7da8fb75171e58c35759d736d961ce8b3a12db0baa7b7107954fccc5a` for Linux amd64.
- The Dagger engine index is `registry.dagger.io/engine@sha256:c9c1a0a6546380983d42e8d75adde070a2a0935c54b498d8bc9045d9cb2ee336`.
- The Python runtime image is `python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6`.
- The integration registry is `registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e`.
- No module or workflow uses `latest`, a tag without a digest, preview Workspace/Checks APIs, Dagger Cloud Engines, or `_EXPERIMENTAL_DAGGER_RUNNER_HOST`.
- Dagger entrypoints accept explicit `Directory` values and immediately apply stable `Directory.filter(include=list(plan.include_paths), exclude=list(plan.exclude_paths), gitignore=False)`.
- Dagger `Directory.digest()` and `File.digest()` may be diagnostic evidence only. Public identities are canonical SHA-256 values computed from bytes.
- Functions that read mutable provider state or cause effects use `@function(cache="never")`; every provider `with_exec` receives a required, unique, regular `PORTFOLIO_DELIVERY_ATTEMPT_ID` environment value. `with_volatile_variable` is forbidden for cache invalidation.
- Cache volumes have explicit `LOCKED`, `PRIVATE`, or `SHARED` modes and correctness must pass with an empty cache.
- Secrets cross the Dagger boundary only as typed `Secret` references and are mounted under `/run/secrets`; plaintext never appears in scalar arguments, source, cache, exported files, envelopes, or logs.
- Pure domain modules import no Dagger, network, filesystem, subprocess, or provider SDK modules.
- Internal records are frozen dataclasses; Pydantic v2 models with `ConfigDict(frozen=True, extra="forbid")` validate file, JSON, CLI, and registry boundaries.
- Protocols are `@runtime_checkable`, contain at most five methods, and use composition. `TypedDict`, explicit `Any`, `Dict[str, Any]`, service locators, global mutable registries, and provider-name switches are forbidden.
- Every production behavior follows red -> verify red -> minimal green -> verify green -> refactor. Test names use `test_should_<behavior>_when_<condition>` and Given/When/Then blocks.
- Every Python function is at most 15 lines, has cyclomatic complexity 1-5, at most three branches, and at most three nesting levels.
- All validation runs through Poe tasks. The final gate is `uv run poe lock-check && uv run poe lint && uv run poe typecheck && uv run poe complexity && uv run poe test && uv run poe mutation && uv run poe audit`.
- Core branch coverage is at least 90%; mutation survivors in `src/portfolio_delivery/domain`, `src/portfolio_delivery/envelope`, and `src/portfolio_delivery/adapters/oras.py` are zero.
- Preserve unrelated work. Each task commits only the files listed for that task.

## Planned File Map

| Path | Responsibility |
|---|---|
| `.python-version` | Pin Python 3.13.14 for uv and Dagger discovery. |
| `pyproject.toml` | Root package, strict quality configuration, and Poe tasks. |
| `uv.lock` | Exact Python dependency graph. |
| `toolchain.lock.toml` | Human-readable compatibility tuple and image/checksum pins. |
| `dagger.json` | Stable v0.21.8 Python module metadata and narrow root includes. |
| `.dagger/pyproject.toml` | Dagger runtime package, pinned Python base image, root-package path dependency. |
| `.dagger/uv.lock` | Exact Dagger runtime dependencies. |
| `.dagger/sdk/` | Committed v0.21.8 generated Python SDK bindings. |
| `.dagger/src/portfolio_delivery_dagger/interfaces.py` | Dagger-only composable plan interfaces. |
| `.dagger/src/portfolio_delivery_dagger/dto.py` | Dagger-only state-bearing DTOs. |
| `.dagger/src/portfolio_delivery_dagger/oras.py` | Dagger container executor for ORAS. |
| `.dagger/src/portfolio_delivery_dagger/main.py` | Stable Phase 1 Dagger entrypoints. |
| `src/portfolio_delivery/domain/errors.py` | Concrete validation, conflict, and boundary exceptions. |
| `src/portfolio_delivery/domain/identity.py` | Project, SHA-256, path, source, and release identities. |
| `src/portfolio_delivery/domain/artifacts.py` | Artifact, SBOM, toolchain, lock, and evidence records. |
| `src/portfolio_delivery/domain/stages.py` | Typed build/qualification stage records. |
| `src/portfolio_delivery/contracts/build.py` | Snapshot, build, sign, and verification ports. |
| `src/portfolio_delivery/contracts/storage.py` | ArtifactStore and ORAS execution ports. |
| `src/portfolio_delivery/contracts/release.py` | Phase-later narrow release/provider ports fixed at the core boundary. |
| `src/portfolio_delivery/envelope/documents.py` | Strict Pydantic v1 envelope/qualification/OCI boundary schemas. |
| `src/portfolio_delivery/envelope/canonical.py` | Canonical JSON, path normalization, SHA-256, and bounded parsing. |
| `src/portfolio_delivery/envelope/builder.py` | Deterministic envelope and qualification assembly. |
| `src/portfolio_delivery/application/foundation.py` | Typed Phase 1 orchestration through qualify and persist. |
| `src/portfolio_delivery/adapters/oras.py` | Pure ORAS command plans and manifest verification. |
| `tests/fakes/` | Deterministic clock, plans, runner, and in-memory store used only by tests. |
| `tests/unit/` | Behavior-first tests for domain, canonicalization, orchestration, and ORAS parsing. |
| `tests/property/` | Permutation, idempotency, monotonic identity, and forbidden-field properties. |
| `tests/conformance/` | Reusable ArtifactStore contract exercised by memory and ORAS implementations. |
| `tests/dagger/` | Real stable-engine tests for filtering, caching, services, secrets, and OCI round trips. |
| `tests/fixtures/envelope/` | Hand-authored canonical input, expected JSON, artifacts, SBOM, and evidence. |

---

### Task 1: Bootstrap the Locked Python and Quality Contract

**Files:**
- Create: `.python-version`
- Create: `pyproject.toml`
- Create: `uv.lock`
- Create: `toolchain.lock.toml`
- Modify: `.gitignore`
- Create: `src/portfolio_delivery/__init__.py`
- Create: `tests/unit/test_package_contract.py`

**Interfaces:**
- Produces: importable package `portfolio_delivery` with `__version__ == "0.1.0"`.
- Produces: Poe tasks `lock-check`, `lint`, `typecheck`, `complexity`, `test-unit`, `test-property`, `test-conformance`, `test-dagger`, `test`, `mutation`, and `audit`.
- Produces: the exact compatibility tuple consumed by envelope metadata and Dagger tests.

- [ ] **Step 1: Create the test harness configuration, without production package code**

Set `.python-version` to `3.13.14`. Configure `pyproject.toml` with `requires-python = ">=3.13,<3.14"`, `uv_build`, and these dependency groups:

```toml
[project]
name = "portfolio-delivery"
version = "0.1.0"
requires-python = ">=3.13,<3.14"
dependencies = ["pydantic>=2.12,<3"]

[build-system]
requires = ["uv_build>=0.8.4,<0.9.0"]
build-backend = "uv_build"

[dependency-groups]
dev = [
  "hypothesis>=6.140,<7",
  "mypy>=1.18,<2",
  "mutmut>=3.3,<4",
  "pip-audit>=2.9,<3",
  "poethepoet>=0.37,<1",
  "pytest>=8.4,<9",
  "pytest-asyncio>=1.2,<2",
  "pytest-cov>=7,<8",
  "ruff>=0.13,<1",
  "xenon>=0.9.3,<1",
]
```

Configure Ruff for Python 3.13, 100 columns, and `E,F,I,W,C901,B,UP,SIM,N,RUF,ASYNC,S,PL`; mypy strict with `warn_unreachable = true` and `disallow_any_explicit = true`; pytest with `asyncio_mode = "auto"`; and these Poe commands:

```toml
[tool.poe.tasks]
lock-check = "uv lock --check"
lint = "ruff check --fix . && ruff format ."
typecheck = "mypy --strict src tests"
complexity = "xenon --max-absolute A --max-modules A --max-average A src"
test-unit = "pytest tests/unit"
test-property = "pytest tests/property"
test-conformance = "pytest tests/conformance"
test-dagger = "pytest tests/dagger"
test = "pytest --cov=src/portfolio_delivery --cov-branch --cov-report=term-missing --cov-fail-under=90"
mutation = "mutmut run"
audit = "pip-audit"
```

Exclude `.dagger/sdk` from Ruff, mypy, coverage, and mutation analysis, but do not git-ignore it. Replace the current `.dagger/` ignore rule with `.dagger/.venv/`, `.dagger/**/__pycache__/`, and `.dagger/.pytest_cache/`.

Create `toolchain.lock.toml` with every exact value in Global Constraints, including `oras.version = "1.3.3"`, `node.version = "24.19.0"`, `wrangler.version = "4.120.0"`, and `vitest_pool_workers.version = "0.20.3"`.

- [ ] **Step 2: Write the failing package contract test**

```python
from portfolio_delivery import __version__


def test_should_expose_foundation_version_when_package_imports() -> None:
    # Given / When / Then
    assert __version__ == "0.1.0"
```

- [ ] **Step 3: Run the focused test and verify RED**

Run: `uv lock && uv sync --python 3.13.14 && uv run poe test-unit -- -q tests/unit/test_package_contract.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'portfolio_delivery'`.

- [ ] **Step 4: Add the minimal package initializer**

```python
"""Typed, deterministic delivery foundations."""

from typing import Final

__version__: Final[str] = "0.1.0"
```

- [ ] **Step 5: Verify GREEN and the initial quality contract**

Run: `uv run poe test-unit -- -q tests/unit/test_package_contract.py`

Expected: PASS.

Run: `uv run poe lock-check && uv run poe lint && uv run poe typecheck && uv run poe complexity`

Expected: all four tasks exit 0 with no warnings.

- [ ] **Step 6: Commit the bootstrap**

```bash
git add .python-version .gitignore pyproject.toml uv.lock toolchain.lock.toml src/portfolio_delivery/__init__.py tests/unit/test_package_contract.py
git commit -m "build: bootstrap locked delivery foundation"
```

### Task 2: Add Validated Domain Identities and Artifact Records

**Files:**
- Create: `src/portfolio_delivery/domain/__init__.py`
- Create: `src/portfolio_delivery/domain/errors.py`
- Create: `src/portfolio_delivery/domain/identity.py`
- Create: `src/portfolio_delivery/domain/artifacts.py`
- Create: `tests/unit/domain/test_identity.py`
- Create: `tests/unit/domain/test_artifacts.py`

**Interfaces:**
- Produces: `ProjectId`, `Sha256Digest`, `ArtifactPath`, `SourceRevision`, `ReleaseId`.
- Produces: `Artifact`, `Sbom`, `LockIdentity`, `ToolchainIdentity`, `Evidence`, `EvidenceStatus`.
- Produces: concrete `InvalidIdentity`, `InvalidDigest`, `InvalidArtifactPath`, and `DuplicateArtifact` exceptions.

- [ ] **Step 1: Write failing identity tests using hand-derived values**

```python
def test_should_reject_parent_traversal_when_artifact_path_is_created() -> None:
    # Given
    raw_path = "dist/../secret.txt"

    # When / Then
    with pytest.raises(InvalidArtifactPath):
        ArtifactPath(raw_path)


def test_should_accept_lowercase_sha256_when_digest_is_canonical() -> None:
    # Given
    raw_digest = "sha256:" + ("a" * 64)

    # When
    digest = Sha256Digest(raw_digest)

    # Then
    assert digest.value == raw_digest
```

Add separate tests for empty project IDs, uppercase/malformed digests, absolute paths, backslashes, duplicate artifact paths, negative sizes, and a commit SHA that is not 40 lowercase hexadecimal characters.

- [ ] **Step 2: Verify RED**

Run: `uv run poe test-unit -- -q tests/unit/domain/test_identity.py tests/unit/domain/test_artifacts.py`

Expected: collection fails because the domain modules do not exist.

- [ ] **Step 3: Implement immutable value records and concrete validation errors**

Use these exact public shapes:

```python
@dataclass(frozen=True, slots=True)
class ProjectId:
    value: str


@dataclass(frozen=True, slots=True)
class Sha256Digest:
    value: str

    @property
    def hex(self) -> str:
        return self.value.removeprefix("sha256:")

    @classmethod
    def from_bytes(cls, content: bytes) -> "Sha256Digest":
        return cls(f"sha256:{sha256(content).hexdigest()}")


@dataclass(frozen=True, slots=True)
class ArtifactPath:
    value: str


@dataclass(frozen=True, slots=True)
class SourceRevision:
    project: ProjectId
    repository: str
    protected_ref: str
    commit_sha: str
    source_tree_sha256: Sha256Digest


@dataclass(frozen=True, slots=True)
class Artifact:
    name: str
    path: ArtifactPath
    media_type: str
    size: int
    sha256: Sha256Digest
```

Validate in short named helpers called from `__post_init__`. Normalize nothing silently: invalid or non-canonical caller data raises a concrete error. Collections are tuples sorted by the envelope builder, never mutable lists on domain records.

- [ ] **Step 4: Verify GREEN, refactor, and run mutation-oriented edge cases**

Run: `uv run poe test-unit -- -q tests/unit/domain/test_identity.py tests/unit/domain/test_artifacts.py`

Expected: PASS.

Run: `uv run poe lint && uv run poe typecheck && uv run poe complexity`

Expected: all exit 0; no function exceeds 15 lines or Grade A complexity.

- [ ] **Step 5: Commit the domain records**

```bash
git add src/portfolio_delivery/domain tests/unit/domain
git commit -m "feat: add immutable delivery identities"
```

### Task 3: Define Typed Stage Records and Narrow Ports

**Files:**
- Create: `src/portfolio_delivery/domain/stages.py`
- Create: `src/portfolio_delivery/contracts/__init__.py`
- Create: `src/portfolio_delivery/contracts/build.py`
- Create: `src/portfolio_delivery/contracts/storage.py`
- Create: `src/portfolio_delivery/contracts/release.py`
- Create: `tests/fakes/__init__.py`
- Create: `tests/fakes/build.py`
- Create: `tests/fakes/storage.py`
- Create: `tests/unit/application/test_stage_contracts.py`

**Interfaces:**
- Produces: `ReleaseSource`, `SnapshottedSource`, `UnsignedBuild`, `PrequalifiedBuild`, `SignedBuild`, `BuildEnvelope`, `QualificationRecord`, `QualifiedEnvelope`, `EnvelopeBundle`, `StoredEnvelope`, `OciReference`, `OrasInvocation`, and `OrasResult`.
- Produces plan records: `InputSnapshotPlan`, `BuildPlan`, `SigningPolicy`, and `VerificationPlan`.
- Produces build ports: `InputSnapshotter.snapshot`, `Builder.build`, `Signer.sign`, and `Verifier.prequalify` / `Verifier.qualify`.
- Produces storage ports: `ArtifactStore.inspect` / `persist` / `restore` and `OrasRunner.run`.
- Produces later-phase ports without implementations: `Registry`, `Versioner`, `ReleaseLedger`, `DeploymentProvider`, `DesiredState`, `Clock`, and `TraceSink`.

- [ ] **Step 1: Write a failing test that drives typed stage ordering**

```python
async def test_should_preserve_exact_artifacts_when_build_advances_to_signed() -> None:
    # Given
    prequalified = make_prequalified_build()
    signer = FakeSigner(signature=make_signature_artifact())

    # When
    signed = await signer.sign(prequalified, SigningPolicy.required("assay-ed25519-v1"))

    # Then
    assert signed.prequalified is prequalified
    assert signed.signature.path.value == "signatures/catalog.ed25519"
```

Add a test in which `SigningPolicy.none()` produces the explicit `SIGNING_NOT_REQUIRED` disposition without inventing a signature file.

- [ ] **Step 2: Verify RED**

Run: `uv run poe test-unit -- -q tests/unit/application/test_stage_contracts.py`

Expected: FAIL because `stages` and the ports do not exist.

- [ ] **Step 3: Implement stage records and protocols with these exact signatures**

```python
class InputSnapshotter(Protocol):
    async def snapshot(
        self, release: ReleaseSource, plan: InputSnapshotPlan
    ) -> SnapshottedSource:
        raise NotImplementedError


class Builder(Protocol):
    async def build(self, source: SnapshottedSource, plan: BuildPlan) -> UnsignedBuild:
        raise NotImplementedError


class Signer(Protocol):
    async def sign(self, build: PrequalifiedBuild, policy: SigningPolicy) -> SignedBuild:
        raise NotImplementedError


class Verifier(Protocol):
    async def prequalify(
        self, build: UnsignedBuild, plan: VerificationPlan
    ) -> PrequalifiedBuild:
        raise NotImplementedError

    async def qualify(
        self, envelope: BuildEnvelope, plan: VerificationPlan
    ) -> QualificationRecord:
        raise NotImplementedError


class ArtifactStore(Protocol):
    async def inspect(
        self, reference: OciReference, attempt_id: str
    ) -> StoredEnvelope | None:
        raise NotImplementedError

    async def persist(self, bundle: EnvelopeBundle, attempt_id: str) -> StoredEnvelope:
        raise NotImplementedError

    async def restore(self, reference: OciReference, attempt_id: str) -> EnvelopeBundle:
        raise NotImplementedError
```

All protocols are `@runtime_checkable`; each method has an explicit return type. Put executable fakes under `tests/fakes`, not production. The fakes store full real records, reject conflicting bytes, and count observations/writes so later conformance tests assert component behavior rather than mock existence.

- [ ] **Step 4: Verify GREEN and strict typing**

Run: `uv run poe test-unit -- -q tests/unit/application/test_stage_contracts.py`

Expected: PASS.

Run: `uv run poe typecheck && uv run poe complexity`

Expected: PASS with no explicit `Any`, `TypedDict`, or protocol over five methods.

- [ ] **Step 5: Commit the typed boundaries**

```bash
git add src/portfolio_delivery/domain/stages.py src/portfolio_delivery/contracts tests/fakes tests/unit/application/test_stage_contracts.py
git commit -m "feat: define delivery stage contracts"
```

### Task 4: Build Canonical Envelope Boundary Documents

**Files:**
- Create: `src/portfolio_delivery/envelope/__init__.py`
- Create: `src/portfolio_delivery/envelope/documents.py`
- Create: `src/portfolio_delivery/envelope/canonical.py`
- Create: `tests/fixtures/envelope/input/build-input.json`
- Create: `tests/fixtures/envelope/input/artifacts/package.whl`
- Create: `tests/fixtures/envelope/input/sbom/package.cdx.json`
- Create: `tests/fixtures/envelope/expected/build-envelope.v1.json`
- Create: `tests/unit/envelope/test_canonical.py`
- Create: `tests/property/test_envelope_properties.py`

**Interfaces:**
- Produces: strict `BuildEnvelopeDocument`, `QualificationRecordDocument`, `OciConfigDocument`, and nested Pydantic boundary models.
- Produces: `canonical_json_bytes(model: BaseModel) -> bytes`, `canonical_sha256(model: BaseModel) -> Sha256Digest`, `normalize_artifact_path(raw: str) -> ArtifactPath`, and `parse_bounded_json(content: bytes, limit: int) -> JsonObject`.
- Uses media types `application/vnd.hseshadr.portfolio-delivery.build-envelope.v1+json`, `application/vnd.hseshadr.portfolio-delivery.qualification.v1+json`, and `application/vnd.hseshadr.portfolio-delivery.config.v1+json`.

- [ ] **Step 1: Hand-author the golden fixture and failing canonical-byte test**

The expected file is one sorted UTF-8 JSON object followed by one newline. It contains `schemaVersion`, `source`, `projectAdapterVersion`, `sourceDateEpoch`, `locks`, `toolchains`, `artifacts`, `sboms`, `prequalificationEvidence`, `releasePolicy`, and `compatibility`. It contains none of `digest`, `ociDigest`, `runId`, `timestamp`, `traceId`, `provider`, `attestation`, `deployment`, or `liveCheck`.

```python
def test_should_match_golden_bytes_when_input_order_differs() -> None:
    # Given
    document = make_build_document_with_reversed_collections()
    expected = fixture_bytes("expected/build-envelope.v1.json")

    # When
    actual = canonical_json_bytes(document)

    # Then
    assert actual == expected
```

The test's expected bytes come only from the hand-authored fixture; do not generate the expected file with production helpers.

- [ ] **Step 2: Verify RED**

Run: `uv run poe test-unit -- -q tests/unit/envelope/test_canonical.py`

Expected: FAIL because `canonical_json_bytes` is missing.

- [ ] **Step 3: Implement strict documents and canonical JSON**

Every boundary model uses:

```python
model_config = ConfigDict(frozen=True, extra="forbid")
```

`canonical_json_bytes` calls `model_dump(mode="json", round_trip=True)`, sorts keys, uses separators `(",", ":")`, sets `ensure_ascii=False` and `allow_nan=False`, encodes UTF-8, and appends exactly one newline. Sort artifacts by `(path, name)`, locks by path, toolchains by name, SBOMs by artifact path, and evidence by `(kind, name)` before constructing the document. Reject absolute paths, `..`, backslashes, duplicate normalized paths, non-lowercase SHA-256, NaN/infinity, unknown fields, and JSON larger than `1_048_576` bytes.

- [ ] **Step 4: Add failing property tests before generalizing the implementation**

```python
@given(st.permutations(make_three_artifacts()))
def test_should_keep_digest_when_artifact_order_changes(
    artifacts: list[Artifact],
) -> None:
    # Given
    document = make_build_document(artifacts=tuple(artifacts))
    expected_bytes = fixture_bytes("expected/build-envelope.v1.json")
    expected = "sha256:" + hashlib.sha256(expected_bytes).hexdigest()

    # When
    digest = canonical_sha256(document)

    # Then
    assert digest.value == expected
```

Also generate Unicode paths, permutation changes, one-byte artifact-digest changes, unknown fields, and forbidden delivery-field names. The fixed digest is calculated once from the checked-in golden fixture using `sha256sum`, not with `canonical_sha256` inside the expectation.

- [ ] **Step 5: Verify GREEN, properties, and the golden digest**

Run: `uv run poe test-unit -- -q tests/unit/envelope/test_canonical.py`

Run: `uv run poe test-property -- -q tests/property/test_envelope_properties.py`

Run: `sha256sum tests/fixtures/envelope/expected/build-envelope.v1.json`

Expected: both pytest commands pass; the independent stdlib/`sha256sum` digest agrees with `canonical_sha256`.

- [ ] **Step 6: Commit canonical documents**

```bash
git add src/portfolio_delivery/envelope tests/fixtures/envelope tests/unit/envelope tests/property/test_envelope_properties.py
git commit -m "feat: canonicalize release envelopes"
```

### Task 5: Assemble Final Envelopes and Detached Qualification Records

**Files:**
- Create: `src/portfolio_delivery/envelope/builder.py`
- Create: `src/portfolio_delivery/application/__init__.py`
- Create: `src/portfolio_delivery/application/foundation.py`
- Create: `tests/unit/envelope/test_builder.py`
- Create: `tests/unit/application/test_foundation.py`
- Extend: `tests/property/test_envelope_properties.py`

**Interfaces:**
- Produces: `EnvelopeBuilder.build(signed: SignedBuild) -> BuildEnvelope`.
- Produces: `QualificationBuilder.build(envelope: BuildEnvelope, checks: tuple[Evidence, ...]) -> QualificationRecord`.
- Produces: `FoundationService.qualify(source, snapshot_plan, build_plan, signing_policy, verification_plan) -> QualifiedEnvelope` and `FoundationService.persist(qualified, attempt_id) -> StoredEnvelope`.

- [ ] **Step 1: Write a failing regression test for the identity-cycle boundary**

```python
async def test_should_keep_envelope_digest_when_final_checks_change() -> None:
    # Given
    envelope = EnvelopeBuilder().build(make_signed_build())
    first_checks = (make_final_check(name="archive", status=EvidenceStatus.PASSED),)
    second_checks = (make_final_check(name="archive", status=EvidenceStatus.FAILED),)

    # When
    first = QualificationBuilder().build(envelope, first_checks)
    second = QualificationBuilder().build(envelope, second_checks)

    # Then
    assert first.subject == second.subject == envelope.content_sha256
    assert first.canonical_bytes != second.canonical_bytes
```

Add tests proving signing happens before envelope assembly, `SigningPolicy.none()` is explicit, all qualification checks target the final envelope digest, and persistence receives the exact qualified bytes without rebuilding.

- [ ] **Step 2: Verify RED**

Run: `uv run poe test-unit -- -q tests/unit/envelope/test_builder.py tests/unit/application/test_foundation.py`

Expected: FAIL because the builders and service are absent.

- [ ] **Step 3: Implement the minimal staged service**

`FoundationService.qualify` performs exactly: snapshot -> build -> prequalify -> sign/signing-not-required -> envelope -> final qualification. It never catches domain exceptions, never reads the clock, never adds run/provider fields, and never invokes storage. `persist` accepts only `QualifiedEnvelope`, constructs one `EnvelopeBundle`, and delegates once to `ArtifactStore.persist` with the caller's non-empty attempt ID.

The `BuildEnvelope` holds `document`, `canonical_bytes`, and `content_sha256`; the serialized document contains no self-digest. The `QualificationRecord` holds `subject`, `document`, `canonical_bytes`, and its own SHA-256. The `EnvelopeBundle` carries those exact bytes plus artifacts and SBOMs.

- [ ] **Step 4: Verify GREEN and property invariants**

Run: `uv run poe test-unit -- -q tests/unit/envelope/test_builder.py tests/unit/application/test_foundation.py`

Run: `uv run poe test-property -- -q tests/property/test_envelope_properties.py`

Expected: PASS; changing a final check changes only the qualification digest, while changing a signed artifact changes the build-envelope digest.

- [ ] **Step 5: Commit the foundation service**

```bash
git add src/portfolio_delivery/envelope/builder.py src/portfolio_delivery/application tests/unit/envelope/test_builder.py tests/unit/application/test_foundation.py tests/property/test_envelope_properties.py
git commit -m "feat: qualify exact final envelope bytes"
```

### Task 6: Add the Pure ORAS Generic-OCI Adapter

**Files:**
- Create: `src/portfolio_delivery/adapters/__init__.py`
- Create: `src/portfolio_delivery/adapters/oras.py`
- Create: `tests/fakes/oras.py`
- Create: `tests/unit/adapters/test_oras.py`

**Interfaces:**
- Consumes: `OciReference(repository: str, tag: str, manifest_sha256: Sha256Digest | None)`, `OrasInvocation`, and `OrasResult` from Task 3.
- Produces: `OrasAdapter(runner: OrasRunner, repository: str)`, `plan_push(bundle) -> OrasInvocation`, `inspect(reference, attempt_id) -> StoredEnvelope | None`, `persist(bundle, attempt_id) -> StoredEnvelope`, and `restore(reference, attempt_id) -> EnvelopeBundle`.
- Consumes: `OrasRunner.run(invocation, attempt_id) -> OrasResult` from Task 3.

- [ ] **Step 1: Write failing command and conflict tests**

```python
def test_should_use_content_tag_and_fixed_layer_order_when_push_is_planned() -> None:
    # Given
    bundle = make_envelope_bundle()

    # When
    adapter = OrasAdapter(make_oras_runner(), "ghcr.io/hseshadr/delivery")
    invocation = adapter.plan_push(bundle)

    # Then
    assert invocation.argv == (
        "oras", "push", "--artifact-type",
        "application/vnd.hseshadr.portfolio-delivery.envelope.v1",
        "--config",
        "/work/config.v1.json:application/vnd.hseshadr.portfolio-delivery.config.v1+json",
        "--concurrency", "1", "--export-manifest", "/work/manifest.json",
        f"ghcr.io/hseshadr/delivery:sha256-{bundle.envelope.content_sha256.hex}",
        "/work/build-envelope.v1.json:application/vnd.hseshadr.portfolio-delivery.build-envelope.v1+json",
        "/work/qualification-record.v1.json:application/vnd.hseshadr.portfolio-delivery.qualification.v1+json",
        "/work/artifacts/package.whl:application/zip",
        "/work/sbom/package.cdx.json:application/vnd.cyclonedx+json",
    )
```

Add tests for absent state -> one push -> re-inspect, identical state -> no push, conflicting content tag -> `ArtifactConflict`, timeout after a write -> inspect-only recovery, malformed manifest, manifest over 1 MiB, unexpected media type, missing layer, duplicate layer, and remote-manifest bytes differing from the exported local manifest.

- [ ] **Step 2: Verify RED**

Run: `uv run poe test-unit -- -q tests/unit/adapters/test_oras.py`

Expected: FAIL because `OrasAdapter` is missing.

- [ ] **Step 3: Implement compare-before-write and write-then-reinspect**

Use only stable ORAS v1.3.3 flags. Do not use experimental JSON formatting, template formatting, backup/restore, OCI-layout-path, or preview `--image-spec`. Raw layers are identity-compressed: ORAS receives the exact files and media types; no tar or gzip step is allowed. Compute the manifest identity as SHA-256 of the exact exported manifest bytes, fetch the manifest again by `repository@sha256:<hex>`, and require byte equality.

The adapter never accepts credentials. Authentication is the runner's concern through a mounted registry-config path. It passes no shell string, runs no project command, validates repository/tag/path/media-type lengths, bounds stdout/stderr, and raises `ProviderTimeout`, `MalformedProviderResponse`, `ArtifactConflict`, or `ProviderUnavailable` without returning a sentinel.

- [ ] **Step 4: Verify GREEN and quality**

Run: `uv run poe test-unit -- -q tests/unit/adapters/test_oras.py`

Run: `uv run poe lint && uv run poe typecheck && uv run poe complexity`

Expected: PASS; the fake runner records full invocations and provider state, while assertions target stored bytes and write counts.

- [ ] **Step 5: Commit the pure adapter**

```bash
git add src/portfolio_delivery/adapters tests/fakes/oras.py tests/unit/adapters/test_oras.py
git commit -m "feat: add reconciling ORAS adapter"
```

### Task 7: Generate and Implement the Stable Dagger v0.21.8 Module

**Files:**
- Create: `dagger.json`
- Create: `.dagger/.gitignore`
- Create: `.dagger/pyproject.toml`
- Create: `.dagger/uv.lock`
- Create: `.dagger/sdk/`
- Create: `.dagger/src/portfolio_delivery_dagger/__init__.py`
- Create: `.dagger/src/portfolio_delivery_dagger/interfaces.py`
- Create: `.dagger/src/portfolio_delivery_dagger/dto.py`
- Create: `.dagger/src/portfolio_delivery_dagger/main.py`
- Modify: `pyproject.toml`
- Create: `tests/dagger/test_module_api.py`

**Interfaces:**
- Produces stable Phase 1 entrypoints: `check`, `version`, `snapshot`, `build`, `prequalify`, `sign`, `envelope`, `qualify`, and `publish_inputs`.
- Produces Dagger DTOs `CheckEvidence`, `ReleaseSource`, `SnapshottedSource`, `UnsignedBuild`, `PrequalifiedBuild`, `SignedBuild`, `BuildEnvelope`, `QualifiedEnvelope`.
- Produces Dagger interfaces `ProjectComposition`, `InputSnapshotPlan`, `BuildPlan`, `SigningPlan`, and `VerificationPlan`.
- Does not add later-phase mutation entrypoints as stubs.

- [ ] **Step 1: Generate the pinned module and commit-ready SDK**

Install the verified v0.21.8 CLI, confirm `dagger version` reports `v0.21.8`, then run:

```bash
dagger init --sdk=python --name=portfolio-delivery
```

Set `dagger.json` to `engineVersion: "v0.21.8"`, `source: ".dagger"`, and include only `src/**`, `pyproject.toml`, `uv.lock`, and `toolchain.lock.toml` beyond the module source. In `.dagger/pyproject.toml`, set Python to `>=3.13,<3.14`, set `[tool.dagger] base-image` to the pinned Python image from Global Constraints, retain generated `dagger-io = { path = "sdk", editable = true }`, and add `portfolio-delivery = { path = "..", editable = true }`. Remove only generated example functions. Keep `.dagger/sdk` tracked.

Update the root Poe `typecheck` task to `mypy --strict src tests .dagger/src` and `complexity` to `xenon --max-absolute A --max-modules A --max-average A src .dagger/src`; generated `.dagger/sdk` remains excluded.

- [ ] **Step 2: Write the failing live module-boundary test**

```python
def test_should_expose_phase_one_functions_when_module_is_introspected() -> None:
    # Given
    expected = {
        "check", "version", "snapshot", "build", "prequalify",
        "sign", "envelope", "qualify", "publish-inputs",
    }

    # When
    result = run_dagger_functions_json()

    # Then
    assert root_function_names(result) == expected
```

Add a live call test that passes `tests/fixtures/envelope/input` as a `Directory`, changes an excluded file, and proves the returned canonical SHA-256 is unchanged; then changes an included artifact and proves the SHA-256 changes.

- [ ] **Step 3: Verify RED**

Run: `uv run poe test-dagger -- -q tests/dagger/test_module_api.py`

Expected: FAIL because the Phase 1 functions and DTOs are absent.

- [ ] **Step 4: Implement the Dagger-only mapping layer**

Pure records remain in `src/portfolio_delivery`; every Dagger DTO contains only scalars, `File`, `Directory`, or Dagger interface values. `version` validates the repository/ref/full commit SHA. `snapshot` applies explicit include/exclude filters and emits a canonical per-file SHA-256 manifest. `build`, `prequalify`, and `sign` delegate to typed interfaces. `envelope` calls the pure builder and returns the exact `build-envelope.v1.json` as a `File`. `qualify` pairs that exact file digest with a detached `QualificationRecord`. `publish_inputs` exports a deterministic directory/archive containing the two records, artifacts, SBOMs, and checksum file; it never rebuilds.

Use `Directory.filter`, never Workspace or Checks. Never use a Dagger filesystem digest as the `SourceRevision` or envelope identity.

- [ ] **Step 5: Verify GREEN, code generation drift, and strict gates**

Run: `uv run poe test-dagger -- -q tests/dagger/test_module_api.py`

Run: `dagger develop && git diff --exit-code -- dagger.json .dagger/sdk .dagger/uv.lock`

Run: `uv run poe lint && uv run poe typecheck && uv run poe complexity`

Expected: all pass; generated bindings and the Dagger lock are unchanged after regeneration.

- [ ] **Step 6: Commit the stable module**

```bash
git add dagger.json .dagger tests/dagger/test_module_api.py .gitignore pyproject.toml uv.lock
git commit -m "feat: expose stable Dagger foundation API"
```

### Task 8: Execute ORAS Through Dagger and Run Adapter Conformance

**Files:**
- Create: `.dagger/src/portfolio_delivery_dagger/oras.py`
- Modify: `.dagger/src/portfolio_delivery_dagger/main.py`
- Modify: `tests/dagger/test_module_api.py`
- Create: `tests/conformance/artifact_store_contract.py`
- Create: `tests/conformance/test_memory_artifact_store.py`
- Create: `tests/conformance/test_oras_artifact_store.py`
- Create: `tests/dagger/test_oras_service.py`
- Create: `tests/dagger/test_secret_boundary.py`

**Interfaces:**
- Produces: `persist_oci(bundle: QualifiedEnvelope, repository: str, attempt_id: str, registry_config: Secret | None, registry_service: Service | None) -> StoredEnvelope` with `cache="never"`.
- Produces: `restore_qualified(release_id: str, envelope_uri: str, envelope_digest: str, registry_config: Secret | None) -> QualifiedEnvelopeRef` for later phases.
- Consumes: the Task 6 command planner/parser and the pinned ORAS image.

- [ ] **Step 1: Write the failing reusable conformance suite**

The suite is parameterized by an `ArtifactStoreFactory` and asserts: absent/identical/conflicting state; ten identical retries produce one write; timeout immediately before write produces no state; timeout after write reconciles the identical state; malformed/oversized/unavailable responses fail closed; two inverted observations cannot replace content-derived identity; and restore returns byte-identical envelope, qualification, artifacts, and SBOMs.

```python
async def assert_ten_retries_create_one_write(factory: ArtifactStoreFactory) -> None:
    # Given
    store, probe = await factory.create()
    bundle = make_envelope_bundle()

    # When
    results = [await store.persist(bundle, f"attempt-{index}") for index in range(10)]

    # Then
    assert len({result.manifest_sha256 for result in results}) == 1
    assert probe.write_count == 1
```

- [ ] **Step 2: Write failing Dagger integration tests**

Start `registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e` as a Dagger `Service` with a health check. Call the ORAS adapter twice with distinct attempt IDs. Assert two provider inspections, one push, identical OCI manifest digests, byte-identical restore, and success with an empty cache. A secret-boundary test passes a canary through a typed `Secret` and asserts the canary is absent from stdout, stderr, trace text, exported inputs, cache exports, envelope bytes, and source snapshots.

- [ ] **Step 3: Verify RED**

Run: `uv run poe test-conformance -- -q`

Run: `uv run poe test-dagger -- -q tests/dagger/test_oras_service.py tests/dagger/test_secret_boundary.py`

Expected: FAIL because the Dagger ORAS executor and conformance factories are missing.

- [ ] **Step 4: Implement the Dagger executor with cache and secret discipline**

Build only from `ghcr.io/oras-project/oras@sha256:a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8`. Mount input bytes read-only under `/work`; mount an optional registry config `Secret` at `/run/secrets/registry-config.json`; bind an optional registry `Service`; pass command arguments as a list. Before every inspect, push, fetch, or pull `with_exec`, set regular environment variable `PORTFOLIO_DELIVERY_ATTEMPT_ID` to the required attempt ID. Do not set it with `with_volatile_variable`.

Mark provider-reading/effectful entrypoints `cache="never"`. If a cache is required for ORAS blobs, key it by ORAS version, platform, and repository and mount it with explicit `CacheSharingMode.LOCKED`; rerun the complete conformance suite with the cache removed.

Extend `test_module_api.py` so the final expected set also contains `persist-oci` and `restore-qualified`; both functions are exercised, not merely found in introspection output.

- [ ] **Step 5: Verify GREEN and repeated execution**

Run: `uv run poe test-conformance -- -q`

Run: `uv run poe test-dagger -- -q tests/dagger/test_oras_service.py tests/dagger/test_secret_boundary.py`

Run the Dagger ORAS test a second time unchanged.

Expected: both runs pass; provider inspection count increases, write count remains one, and no canary is observable.

- [ ] **Step 6: Commit ORAS execution and conformance**

```bash
git add .dagger/src/portfolio_delivery_dagger tests/conformance tests/dagger/test_oras_service.py tests/dagger/test_secret_boundary.py
git commit -m "test: enforce OCI adapter conformance"
```

### Task 9: Close Phase 1 With Property, Mutation, and Runnable Documentation Gates

**Files:**
- Modify: `README.md`
- Modify: `pyproject.toml`
- Create: `tests/property/test_foundation_properties.py`
- Create: `tests/unit/test_forbidden_dependencies.py`

**Interfaces:**
- Produces: one copy-pasteable local quickstart and one realistic envelope -> qualification -> local OCI registry demonstration.
- Produces: a repository-wide proof that the pure package does not import Dagger/provider/network/filesystem modules from `domain`, `contracts`, `envelope`, or `application`.

- [ ] **Step 1: Add failing safety properties**

Add Hypothesis tests proving: identical declared inputs always yield identical canonical bytes; any artifact byte change changes the envelope digest; final-check permutations do not change the envelope digest; ten persistence attempts converge on one manifest; malformed paths/digests/documents fail closed; and no forbidden delivery fact appears recursively in an envelope document.

Add an AST-based dependency test that imports each pure module and rejects `dagger`, `httpx`, `requests`, `subprocess`, `socket`, provider SDKs, and `pathlib` outside boundary/adapters. The assertion targets the architectural effect—pure modules can be imported with those packages blocked—not a grep of source text.

Configure mutation scope in `pyproject.toml`:

```toml
[tool.mutmut]
paths_to_mutate = [
  "src/portfolio_delivery/domain/",
  "src/portfolio_delivery/envelope/",
  "src/portfolio_delivery/adapters/oras.py",
]
tests_dir = ["tests/unit/", "tests/property/"]
```

- [ ] **Step 2: Verify RED, then make only the minimal fixes**

Run: `uv run poe test-property -- -q tests/property/test_foundation_properties.py`

Run: `uv run poe test-unit -- -q tests/unit/test_forbidden_dependencies.py`

Expected: new tests fail on any uncovered invariant; change only the relevant production helper, rerun each test, and keep every function within the Python quality limits.

- [ ] **Step 3: Document the exact runnable path**

Put a TL;DR first in `README.md`, followed by:

```bash
uv sync --python 3.13.14
uv run poe lock-check
uv run poe test
dagger functions
uv run poe test-dagger -- -q tests/dagger/test_oras_service.py
```

The realistic demo uses the checked-in wheel, CycloneDX SBOM, prequalification evidence, detached final qualification, and local registry service. It prints the canonical envelope SHA-256 and OCI manifest SHA-256, runs the same request twice, and shows one provider write. State explicitly that Phase 1 does not publish npm/PyPI, deploy applications, or provide the durable release authority.

- [ ] **Step 4: Run the complete Python quality and Dagger gates**

Run:

```bash
uv run poe lock-check
uv run poe lint
uv run poe typecheck
uv run poe complexity
uv run poe test
uv run poe mutation
uv run poe audit
dagger develop
git diff --exit-code -- dagger.json .dagger/sdk .dagger/uv.lock
git diff --check
```

Expected: every command exits 0; branch coverage is at least 90%; mutation survivors are zero; dependency audit reports no known vulnerability; generated bindings do not drift.

- [ ] **Step 5: Commit the completed Phase 1 foundation**

```bash
git add README.md pyproject.toml tests/property/test_foundation_properties.py tests/unit/test_forbidden_dependencies.py uv.lock
git commit -m "docs: prove delivery foundation quickstart"
```

## Phase 1 Exit Evidence

Before handing the branch to review, attach these exact results to the PR or execution log:

- `uv run poe test`: test count, branch coverage percentage, and zero failures.
- `uv run poe mutation`: zero surviving mutants in the configured Phase 1 core.
- `uv run poe lint`, `typecheck`, and `complexity`: all clean; Xenon A/A/A.
- `dagger develop` drift check: no changes to `dagger.json`, `.dagger/sdk`, or `.dagger/uv.lock`.
- Dagger module API test: only the implemented Phase 1 functions are exposed.
- ORAS service conformance: two inspections, one write, identical manifest digest, exact restore.
- Secret canary test: no occurrence in any observable or exported surface.
- Golden fixture: exact canonical build-envelope SHA-256 and detached qualification SHA-256.
- Git history: one focused commit per task, with no unrelated files.
