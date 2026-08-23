# Application Delivery Migrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate EdgeReco, AlmaMesh, and AML Filter to the automatic Portfolio Delivery path, ship their exact Assay dev2 integrations, deploy the qualified bytes to production, and prove candidate, live, and recovery behavior without weakening any existing gate.

**Architecture:** Each application keeps product logic and gates in its own repository and adds exactly four integration files: `portfolio-delivery.toml`, `delivery/composition.py`, `delivery/contracts.json`, and `.github/workflows/portfolio-delivery.yml`. The shared Dagger module snapshots every network input, builds one qualified envelope, persists it in GHCR, and gives Cloudflare the exact extracted Pages bytes; the controller fences stale work, automates shadow comparison and cutover, and chooses ordinary rollback for EdgeReco or monotonic `RecoveryRelease` for AlmaMesh and AML Filter.

**Tech Stack:** Python 3.13, TypeScript, Dagger `v0.21.8`, GitHub Actions, GHCR generic OCI artifacts, Cloudflare Pages direct upload, Cloudflare Durable Objects, pnpm `11.5.0`, Bun, uv, Vitest, pytest, Playwright, Assay `assay-engine==0.5.0.dev2` and `@edgeproc/assay==0.5.0-dev.2`, Avow, Release Please.

**Spec:** `docs/superpowers/specs/2026-08-22-portfolio-delivery-design.md`

## Global Constraints

- Work only in the active integration worktrees: EdgeReco `/Users/harish/dev/.codex-worktrees/edge-reco-assay-avow` on `codex/assay-avow-ranking-proof`, AlmaMesh `/Users/harish/dev/.codex-worktrees/almamesh-assay-avow` on `codex/assay-avow-production`, and AML Filter `/Users/harish/dev/.codex-worktrees/aml-filter-assay-avow` on `codex/assay-avow-production`; preserve every existing uncommitted change.
- The npm release is `@edgeproc/assay@0.5.0-dev.2`, published at `2026-08-22T14:19:26.405Z`. Do not resolve it before `2026-08-23T14:19:26.405Z`; do not add `minimumReleaseAgeExclude`, `minimumReleaseAgeExcludes`, a local tarball, a link, an override, or any other exemption.
- The npm tarball identity is SHA-256
  `b1cd13c4919bf00e8b52d8467bc783c14d9b78cf0768ca0c04556b03c8242a33`,
  SHA-1 `077352a82a36ad4635cad0c5fedc04cc81855d6b`, and SRI
  `sha512-R5uFYeU7l4UkAGRvY7HDcOlLBpSw10WAi2w14WtmkzhpcxYsJO43OsGc/jJ9JN0dxeZjucpFftcXJNRwsSeDJw==`.
- EdgeReco and AML Filter retain pnpm `minimumReleaseAge: 1440`; AlmaMesh retains Bun `minimumReleaseAge = 86400`. Exact frozen registry locks must contain `0.5.0-dev.2` and an integrity value after the maturity boundary.
- Python consumers use the exact immutable release
  `assay-engine[metrics]==0.5.0.dev2`; the wheel SHA-256 is
  `9e112118987f48ad0b9132ad592e8674e853b1d0f1967a08255750f1619061e8`
  and the sdist SHA-256 is
  `661f132cd0fd1ec64668985bb150a563f627d690eb68d8ac8dd4dbe71a8a4713`.
  Every `uv.lock` is hash-bearing; no path, git, or editable Assay source remains.
- Use red -> green -> refactor for every behavior change. A Python edit also runs the registered `python-quality` contract after the focused test and before the repository gate.
- The existing repository gate is the minimum gate. The Dagger adapter must invoke it unchanged and may add checks, but may not skip, filter, relax, or reimplement it.
- A shadow run has no registry, signing, GitHub release, or Cloudflare write authority. It must compare gate names/results, artifact file SHA-256 values, input snapshot digests, source SHA, Assay versions, and build-envelope digest.
- Automatic cutover requires three consecutive protected-main shadow runs with full gate parity, identical artifact bytes for identical source/input snapshots, no unresolved controller incident, and a successful candidate plus recovery drill.
- The Pages candidate and production deployment consume the same extracted `pages-dist.tar.zst` from the qualified OCI envelope. Neither deployment job checks out source, installs dependencies, downloads inputs, signs, or rebuilds.
- Missing credentials, a skipped deploy, an unverifiable no-op, a stale desired SHA, a digest disagreement, or a failed rollback verification fails closed and opens an incident.
- EdgeReco rollback may restore the captured prior successful Pages deployment ID. AlmaMesh and both AML Filter streams must create a fresh, controller-allocated, higher-sequence `RecoveryRelease` from verified predecessor bytes; they never reactivate an older signed pointer.
- All generated workflow callers pin the shared workflow to the exact 40-character `portfolio-delivery` commit SHA. Project jobs have `contents: read` only; provider mutation remains in the trusted central workflow.
- Only release-bot, non-Dependabot pull requests may auto-merge after every required check passes. Do not merge Dependabot pull requests.
- Production completion means the controller is at `live_verified`, the public `build.json` identifies the intended source/envelope, the signed data pointer identifies the intended digest/sequence, browser checks have zero console errors and no forbidden egress, and rollback/recovery evidence is durable.

## File Map and Ownership Boundaries

| Repository | Path | Responsibility |
|---|---|---|
| portfolio-delivery | `src/portfolio_delivery/projects/contracts.py` | Immutable four-file adapter ABI and strict manifest/fixture values. |
| portfolio-delivery | `src/portfolio_delivery/projects/loader.py` | Bounded loader for one repository-local `COMPOSITION`; no network or mutation. |
| portfolio-delivery | `.dagger/src/portfolio_delivery_dagger/application.py` | Map a validated project adapter to shared Dagger delivery and verifier functions. |
| portfolio-delivery | `tests/projects/*` | Adapter loading, four-file, shadow, exact-byte, and recovery conformance. |
| each application | `portfolio-delivery.toml` | Identity, streams, exact dependencies, input snapshots, artifacts, gates, environments, verification, and recovery. |
| each application | `delivery/composition.py` | Typed composition of snapshot/build/artifact/release/sign/deploy/verify/recovery plans. |
| each application | `delivery/contracts.json` | Success, retry, conflict, stale-work, rollback, and live-check-failure fixtures. |
| each application | `.github/workflows/portfolio-delivery.yml` | Generated, commit-pinned caller with no project delivery logic. |
| EdgeReco | existing Assay proof files listed in Task 2 | Python/TypeScript score parity, ranking proof, UI evidence, dependency locks. |
| AlmaMesh | existing Assay strength files listed in Task 5 | Strength Assay composition, Avow receipt, predictive UI/PDF evidence, dependency lock. |
| AML Filter | existing Assay scoring files listed in Task 8 | Additive score result, signed receipt, decision/eval parity, dependency locks. |

The three application task groups do not share files. Within each group, the Assay task owns existing product files, the adapter task owns only the four new integration files, and the cutover task owns only superseded workflow files and external controller/GitHub/Cloudflare state.

---

### Task 1: Freeze the Four-File Application Adapter ABI

**Files:**
- Create: `src/portfolio_delivery/projects/__init__.py`
- Create: `src/portfolio_delivery/projects/contracts.py`
- Create: `src/portfolio_delivery/projects/loader.py`
- Create: `.dagger/src/portfolio_delivery_dagger/application.py`
- Modify: `.dagger/src/portfolio_delivery_dagger/main.py`
- Test: `tests/projects/test_contracts.py`
- Test: `tests/projects/test_loader.py`
- Test: `tests/projects/test_application_module.py`
- Test support: `tests/projects/conftest.py`
- Test fixture: `tests/fixtures/projects/minimal/portfolio-delivery.toml`
- Test fixture: `tests/fixtures/projects/minimal/delivery/composition.py`
- Test fixture: `tests/fixtures/projects/minimal/delivery/contracts.json`
- Test fixture: `tests/fixtures/projects/minimal/.github/workflows/portfolio-delivery.yml`

**Interfaces:**
- Consumes: Phase 1 `InputSnapshotPlan`, `BuildPlan`, `SigningPolicy`, `VerificationPlan`, `QualifiedEnvelope`; Phase 3 `delivery`, `verify-candidate`, and `verify-live` workflow contract.
- Produces: `AdapterContractError`, `InputKind`, `ArtifactKind`, `RecoveryMode`, `ProjectAdapterSpec`, `ArtifactSpec`, `InputSpec`, `StreamSpec`, `DeploymentSpec`, `VerificationSpec`, `RecoverySpec`, `ContractScenario`, `ProjectManifest`, `load_manifest(path: Path) -> ProjectManifest`, `load_bounded_module(path: Path) -> ModuleType`, `narrow_adapter(value: object, manifest: ProjectManifest) -> ProjectAdapterSpec`, `validate_four_files(root: Path, adapter: ProjectAdapterSpec) -> None`, `validate_network_snapshots(adapter: ProjectAdapterSpec) -> None`, `validate_recovery_modes(adapter: ProjectAdapterSpec) -> None`, `load_project_adapter(root: Path) -> ProjectAdapterSpec`, `validate_contract_scenarios(path: Path, project: ProjectAdapterSpec) -> tuple[ContractScenario, ...]`, and Dagger functions `delivery`, `verify_candidate`, and `verify_live`.

- [ ] **Step 1: Write failing four-file and safety tests**

```python
def test_loads_exactly_the_four_repository_integration_files(minimal_project: Path) -> None:
    adapter = load_project_adapter(minimal_project)
    assert adapter.project_id == "fixture-app"
    assert adapter.integration_paths == (
        "portfolio-delivery.toml",
        "delivery/composition.py",
        "delivery/contracts.json",
        ".github/workflows/portfolio-delivery.yml",
    )


def test_rejects_network_input_without_snapshot_contract(minimal_project: Path) -> None:
    path = minimal_project / "delivery/composition.py"
    path.write_text(path.read_text().replace("snapshot=True", "snapshot=False"))
    with pytest.raises(AdapterContractError, match="network input model must be snapshotted"):
        load_project_adapter(minimal_project)


def test_rejects_signed_monotonic_stream_with_ordinary_rollback(minimal_project: Path) -> None:
    path = minimal_project / "portfolio-delivery.toml"
    path.write_text(path.read_text().replace('recovery = "none"', 'recovery = "ordinary"'))
    with pytest.raises(AdapterContractError, match="requires recovery_release"):
        load_project_adapter(minimal_project)
```

Also assert the six fixture scenario names are exactly `success`, `retry`, `conflict`, `stale_work`, `rollback`, and `live_check_failure`; the caller has one reusable-workflow `uses`, no `run`, no `workflow_dispatch`, no secret expression, and a full commit SHA.

- [ ] **Step 2: Run tests and verify RED**

Run: `uv run pytest -q tests/projects/test_contracts.py tests/projects/test_loader.py tests/projects/test_application_module.py`

Expected: FAIL because the project adapter package and application Dagger functions do not exist.

- [ ] **Step 3: Implement immutable contracts and a bounded composition loader**

```python
class RecoveryMode(StrEnum):
    ORDINARY = "ordinary"
    RECOVERY_RELEASE = "recovery_release"


@dataclass(frozen=True, slots=True)
class ProjectAdapterSpec:
    project_id: str
    repository: str
    streams: tuple[StreamSpec, ...]
    inputs: tuple[InputSpec, ...]
    artifacts: tuple[ArtifactSpec, ...]
    checks: tuple[str, ...]
    deployment: DeploymentSpec
    verification: VerificationSpec
    recovery: RecoverySpec


def load_project_adapter(root: Path) -> ProjectAdapterSpec:
    manifest = load_manifest(root / "portfolio-delivery.toml")
    module = load_bounded_module(root / "delivery/composition.py")
    adapter = narrow_adapter(module.COMPOSITION, manifest)
    validate_four_files(root, adapter)
    validate_network_snapshots(adapter)
    validate_recovery_modes(adapter)
    return adapter
```

The loader accepts only the `COMPOSITION` value, refuses symlinks and paths outside the source root, caps the manifest at 256 KiB and fixtures at 1 MiB, rejects unknown fields, and performs no import-time network or provider call. The Dagger layer copies the four files into a credential-free container, validates them, snapshots declared inputs, invokes exact command arrays without a shell, and exports the required qualified tree. `verify_candidate` and `verify_live` accept only a qualified directory and an HTTPS URL.

- [ ] **Step 4: Run GREEN, property tests, and Dagger boundary tests**

Run: `uv run pytest -q tests/projects`

Run: `uv run pytest -q tests/property -k 'adapter or snapshot or recovery'`

Run: `uv run poe test-dagger -- -q tests/projects/test_application_module.py`

Run: `uv run ruff check src/portfolio_delivery/projects tests/projects .dagger/src/portfolio_delivery_dagger && uv run mypy --strict src tests .dagger/src && uv run xenon --max-absolute A --max-modules A --max-average A src .dagger/src`

Expected: all pass; repeated input orderings produce identical adapter/envelope digests; malformed or escaping paths fail; all production functions remain credential-free.

- [ ] **Step 5: Commit the ABI**

```bash
git add src/portfolio_delivery/projects .dagger/src/portfolio_delivery_dagger tests/projects tests/fixtures/projects
git commit -m "feat: define application delivery adapter contract"
```

### Task 2: Finalize EdgeReco Assay Proof and Exact Mature Locks

**Files (EdgeReco worktree only):**
- Modify: `backend/pyproject.toml`
- Modify: `backend/uv.lock`
- Create: `backend/src/edgereco/reco/formula.py`
- Modify: `backend/src/edgereco/reco/scorer.py`
- Modify: `backend/src/edgereco/reco/score_receipt.py`
- Modify: `backend/src/edgereco/catalog/models.py`
- Modify: `backend/src/edgereco/catalog/publish.py`
- Test: `backend/tests/unit/reco/test_scorer.py`
- Test: `backend/tests/unit/reco/test_score_receipt.py`
- Test: `backend/tests/unit/catalog/test_publish.py`
- Test: `backend/tests/unit/test_assay_dependency_contract.py`
- Modify: `frontend/packages/edgeproc-browser/package.json`
- Modify: `frontend/pnpm-lock.yaml`
- Create: `frontend/packages/edgeproc-browser/src/engine/formula.ts`
- Create: `frontend/packages/edgeproc-browser/src/engine/rankingProof.ts`
- Create: `frontend/packages/edgeproc-browser/src/engine/rankingProof.test.ts`
- Create: `frontend/packages/edgeproc-browser/src/engine/runtimeRankingProof.test.ts`
- Create: `frontend/packages/edgeproc-browser/src/engine/__fixtures__/ranking_proof_v1.json`
- Modify: `frontend/packages/edgeproc-browser/src/engine/reranker.ts`
- Modify: `frontend/packages/edgeproc-browser/src/engine/runtime.ts`
- Modify: `frontend/packages/edgeproc-browser/src/engine/searchEngine.ts`
- Modify: `frontend/app/src/api/client.ts`
- Modify: `frontend/app/src/api/types.ts`
- Modify/Test: `frontend/app/src/components/{ProductDetail,RailCard,RailRow,RailStack,Storefront,WhyPopover}.tsx`
- Test: `frontend/app/tests/e2e/storefront.spec.ts`
- Test: `frontend/app/scripts/assay-package-contract.test.mjs`
- Modify: `README.md`, `CLAUDE.md`, `docs/ARCHITECTURE.md`, `frontend/README.md`

**Interfaces:**
- Produces Python `FormulaSignals`, `formula_request(signals, weights) -> AdditiveRequest`, `explain_score(signals, weights) -> ScoreResult`, `RankingProof`, and `RankingReceipt`.
- Produces TypeScript `FORMULA_METHOD_VERSION`, `FormulaSignals`, `formulaRequest`, `explainScore`, `RANKING_PROOF_SCHEMA`, `buildRankingProof`, and `verifyRankingProof`.
- Locks Python `assay-engine[metrics]==0.5.0.dev2` and npm `@edgeproc/assay==0.5.0-dev.2` with registry hashes.

- [ ] **Step 1: Run the focused behavioral tests against the current worktree**

Run: `cd backend && uv run pytest -q tests/unit/reco/test_scorer.py tests/unit/reco/test_score_receipt.py tests/unit/catalog/test_publish.py tests/unit/test_assay_dependency_contract.py`

Run: `cd frontend && pnpm exec vitest run packages/edgeproc-browser/src/engine/rankingProof.test.ts packages/edgeproc-browser/src/engine/runtimeRankingProof.test.ts packages/edgeproc-browser/src/engine/reranker.test.ts app/src/api/client.test.ts app/src/components/RailCard.test.tsx app/src/components/Storefront.test.tsx`

Expected: every test passes. If a behavior is missing, add a failing literal test first for ordered components, raw/coefficient/contribution, clamp, stable inputs hash, Python/TypeScript proof parity, Avow verification, proof-unavailable fallback, and visible UI disclosure before editing production code.

- [ ] **Step 2: Cross the npm maturity boundary without an exemption**

Run after `2026-08-23T14:19:26.405Z` only:

```bash
cd frontend
pnpm --filter @edgeproc/browser pkg set "dependencies.@edgeproc/assay=0.5.0-dev.2"
pnpm install --lockfile-only
pnpm install --frozen-lockfile
```

Run: `rg -n 'link:|file:.*assay|minimumReleaseAgeExclude|minimumReleaseAgeExcludes' packages/edgeproc-browser/package.json pnpm-lock.yaml pnpm-workspace.yaml`

Expected: `rg` exits 1 with no matches; the manifest specifier is exactly
`0.5.0-dev.2`; the lock entry is the npm registry release with the exact SRI
from Global Constraints; `minimumReleaseAge: 1440` remains unchanged.

Run: `cd backend && uv lock --check && uv sync --frozen && uv tree | rg '^assay-engine v0\.5\.0\.dev2'`

Expected: the exact PyPI release is installed from the hash-bearing lock with no path or git source.

- [ ] **Step 3: Refactor only after parity is green**

Keep one ordered term table in each language, keep UTF-16 identifier ordering for cross-runtime proof parity, and expose one stable unavailable-proof state rather than manufacturing evidence. Remove the temporary local Assay contract paths from both package-contract tests only after the registry tests assert exact version and package exports.

- [ ] **Step 4: Run EdgeReco's complete gates**

Run: `cd backend && uv run poe gate`

Run: `cd frontend && pnpm run gate`

Run: `git diff --check && git status --short`

Expected: backend format/lint/strict typing/Xenon A/A/A/pytest with at least 90% coverage pass; frontend lint/typecheck/coverage/preflight/Pages artifact tests and all three Playwright lanes pass; no untracked generated model or secret is staged.

- [ ] **Step 5: Commit the EdgeReco product integration**

```bash
git add backend frontend README.md CLAUDE.md docs/ARCHITECTURE.md
git commit -m "feat: add Assay-backed ranking proof"
```

### Task 3: Add EdgeReco's Four-File Adapter and Prove Shadow Parity

**Files (EdgeReco worktree only):**
- Create: `portfolio-delivery.toml`
- Create: `delivery/composition.py`
- Create: `delivery/contracts.json`
- Create: `.github/workflows/portfolio-delivery.yml`

**Interfaces:**
- Consumes: `ProjectAdapterSpec` from Task 1, the exact EdgeReco gate commands from Task 2, `frontend/app/scripts/download-model.mjs`, the signed catalog origin contract, and the central generated caller.
- Produces: streams `edge-reco-app` and `edge-reco-catalog`; artifacts `pages-dist.tar.zst`, `catalog-origin.tar.zst`, `ranking_receipt.json`, and `build.json`; ordinary Pages recovery.

- [ ] **Step 1: Write the failing adapter fixture first**

Create `delivery/contracts.json` with schema version 1 and exactly these expectations:

```json
{
  "schema_version": 1,
  "scenarios": [
    {"name":"success","expected_writes":["persist","candidate","activate"],"terminal":"live_verified"},
    {"name":"retry","attempts":10,"expected_provider_writes":1,"terminal":"live_verified"},
    {"name":"conflict","observed_digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","expected_writes":[],"terminal":"incident"},
    {"name":"stale_work","completion_order":["new","old"],"expected_winner":"new","terminal":"live_verified"},
    {"name":"rollback","requested":true,"expected_recovery":"ordinary","terminal":"rolled_back"},
    {"name":"live_check_failure","expected_activation":true,"expected_recovery":"ordinary","terminal":"rolled_back"}
  ]
}
```

Run: `uv run portfolio-delivery check-project /Users/harish/dev/.codex-worktrees/edge-reco-assay-avow`

Expected: FAIL because the manifest, composition, and generated caller are absent.

- [ ] **Step 2: Implement the manifest and typed composition**

The manifest must declare repository `hseshadr/edge-reco`, production URL `https://edge-reco.com`, Cloudflare project `edge-reco`, exact Assay Python/npm versions, `maturity_seconds = 86400`, `maturity_exemptions = []`, the four current workflow schedules, and `recovery = "ordinary"`.

`delivery/composition.py` must export exactly one immutable value:

```python
COMPOSITION = ProjectAdapterSpec(
    project_id="edge-reco",
    repository="hseshadr/edge-reco",
    streams=(
        StreamSpec("edge-reco-app", signed=False, sequence_field=None, requires=("edge-reco-catalog",)),
        StreamSpec("edge-reco-catalog", signed=True, sequence_field=None, requires=()),
    ),
    inputs=(
        InputSpec("minilm-q8", InputKind.NETWORK, ("node", "frontend/app/scripts/download-model.mjs"), "frontend/app/public/models", snapshot=True),
        InputSpec("catalog-csv", InputKind.SOURCE, (), "backend/examples/source/catalog.csv", snapshot=True),
    ),
    artifacts=(
        ArtifactSpec("pages-dist.tar.zst", ArtifactKind.TREE, "frontend/app/dist", "application/vnd.edgeproc.pages.v1+tar+zstd"),
        ArtifactSpec("catalog-origin.tar.zst", ArtifactKind.TREE, "frontend/app/dist/bundle", "application/vnd.edgeproc.catalog.v2+tar+zstd"),
        ArtifactSpec("ranking_receipt.json", ArtifactKind.FILE, "frontend/app/dist/bundle/ranking_receipt.json", "application/vnd.avow.receipt.v1+json"),
        ArtifactSpec("build.json", ArtifactKind.FILE, "frontend/app/dist/build.json", "application/json"),
    ),
    checks=("cd backend && uv run poe gate", "cd frontend && pnpm run gate"),
    deployment=DeploymentSpec("cloudflare_pages", "edge-reco", "https://edge-reco.com", "pages-dist.tar.zst"),
    verification=VerificationSpec(("build_identity", "catalog_integrity", "assay_replay", "avow", "storefront", "offline", "console", "no_forbidden_egress")),
    recovery=RecoverySpec(RecoveryMode.ORDINARY, sequence_field=None),
)
```

The model snapshot records URL, upstream revision identity from the pinned download manifest, byte size, and SHA-256 for every file. The catalog artifact records the source CSV digest, signed pointer, manifest digest, every chunk digest, and ranking proof digest.

- [ ] **Step 3: Generate the exact caller and verify local conformance**

Run:

```bash
cd /Users/harish/dev/portfolio-delivery
shared_ref="$(git rev-parse HEAD)"
uv run portfolio-delivery render-project \
  --project-root /Users/harish/dev/.codex-worktrees/edge-reco-assay-avow \
  --shared-ref "$shared_ref"
```

Run: `uv run portfolio-delivery check-project /Users/harish/dev/.codex-worktrees/edge-reco-assay-avow`

Run: `dagger call -m . application-contract --source=/Users/harish/dev/.codex-worktrees/edge-reco-assay-avow --attempt-id=edge-local-1`

Expected: all six scenarios pass; caller `uses` contains the exact current 40-character shared commit, has no `run`, secret, mutable ref, or manual dispatch.

- [ ] **Step 4: Commit the four files**

```bash
git add portfolio-delivery.toml delivery/composition.py delivery/contracts.json .github/workflows/portfolio-delivery.yml
git commit -m "ci: add EdgeReco portfolio delivery adapter"
```

- [ ] **Step 5: Run and record protected-main shadow parity**

Push the adapter atop Task 2, create the integration PR, and enable auto-merge only after EdgeReco's existing CI and `portfolio-delivery-shadow` are green. After merge, require three protected-main shadow records. For each record, compare the existing CI gate set, Pages tree file hashes, catalog pointer/manifest/chunk hashes, source SHA, model snapshot digest, `assay-engine==0.5.0.dev2`, and `@edgeproc/assay==0.5.0-dev.2`.

Run: `gh run list --repo hseshadr/edge-reco --branch main --limit 20 --json databaseId,workflowName,headSha,status,conclusion`

Expected: three consecutive source SHAs have successful legacy and shadow runs; the controller reports `shadow_parity=true` and `cutover_eligible=true`; provider writes remain zero.

### Task 4: Prepare EdgeReco Automatic Cutover and Ordinary Rollback

**Files (EdgeReco worktree only):**
- Delete after shadow eligibility: `.github/workflows/ci.yml`
- Delete after shadow eligibility: `.github/workflows/deploy.yml`
- Delete after shadow eligibility: `.github/workflows/parity-fixtures.yml`
- Delete after shadow eligibility: `.github/workflows/security-audit.yml`

**Interfaces:**
- Consumes: Task 3's qualified `pages-dist.tar.zst`, captured production deployment ID, candidate URL, desired protected-main SHA, and controller cutover eligibility.
- Produces: a release-bot cutover PR, verified candidate, exact-byte production activation, public live evidence, and verified ordinary rollback evidence.

- [ ] **Step 1: Test candidate and rollback before deleting legacy callers**

Run the central deployment workflow in controller shadow-write mode against a nonproduction candidate branch. It must extract the OCI `pages-dist.tar.zst`, upload it with commit hash equal to the envelope source SHA, and return the immutable candidate URL/deployment ID plus captured production predecessor ID.

Run: `dagger call -m . verify-candidate --qualified=.delivery/qualified --candidate-url="$CANDIDATE_URL" export --path=.delivery/candidate-evidence.json`

Expected: candidate `build.json` source/envelope match; catalog pointer, manifest, chunks, ranking receipt, Assay replay, Avow signature, storefront flow, offline/PWA, console, and network checks pass.

Inject a live-check failure in the contract provider, authorize recovery once, call the captured predecessor deployment ID, and verify `https://edge-reco.com/build.json` returns the predecessor identity. Ten retries produce one rollback write.

- [ ] **Step 2: Verify legacy-gate coverage before removal**

Run: `uv run portfolio-delivery compare-workflow-coverage --project-root /Users/harish/dev/.codex-worktrees/edge-reco-assay-avow --legacy .github/workflows/ci.yml --legacy .github/workflows/deploy.yml --legacy .github/workflows/parity-fixtures.yml --legacy .github/workflows/security-audit.yml`

Expected: every legacy command and schedule maps to a manifest check/schedule; the report has no missing or weakened item.

- [ ] **Step 3: Remove only superseded YAML and run all gates through Dagger**

```bash
git rm .github/workflows/ci.yml .github/workflows/deploy.yml \
  .github/workflows/parity-fixtures.yml .github/workflows/security-audit.yml
git commit -m "ci: cut EdgeReco delivery to Dagger"
dagger call -m github.com/hseshadr/portfolio-delivery@"$(git -C /Users/harish/dev/portfolio-delivery rev-parse HEAD)" \
  delivery --source=. --project-id=edge-reco --event=pull_request \
  --source-sha="$(git rev-parse HEAD)" --attempt-id="edge-cutover-local-1" \
  export --path=.delivery/qualified
```

Expected: both complete repository gates pass and the qualified Pages/catalog bytes match a second independent run byte-for-byte.

- [ ] **Step 4: Leave the cutover PR eligible for Task 11**

Create a release-bot PR whose body includes the three shadow run IDs, envelope/artifact digests, candidate deployment ID, predecessor deployment ID, candidate evidence digest, and rollback evidence digest. Do not manually merge it; controller policy enables auto-merge after all required checks.

### Task 5: Finalize AlmaMesh Assay Strength Evidence and Exact Mature Lock

**Files (AlmaMesh worktree only):**
- Modify: `frontend/packages/browser/package.json`
- Modify: `frontend/bun.lock`
- Create: `frontend/packages/browser/src/pyodide/strengthAssay.ts`
- Create: `frontend/packages/browser/src/pyodide/__tests__/strengthAssay.test.ts`
- Modify: `frontend/packages/browser/src/pyodide/strengthReceipt.ts`
- Modify: `frontend/packages/browser/src/pyodide/__tests__/strengthReceipt.test.ts`
- Modify: `frontend/packages/browser/src/pyodide/chartWorker.ts`
- Modify: `frontend/packages/browser/src/pyodide/predictive.ts`
- Modify: `frontend/packages/browser/src/types.ts`
- Modify: `frontend/packages/shared-types/src/index.ts`
- Modify: `frontend/packages/store/src/adapters/predictive.ts`
- Test: `frontend/packages/store/src/adapters/predictive.test.ts`
- Modify/Test: `frontend/apps/web/src/components/features/predictive/{DomainsPanel,StrengthEvidencePanels}.tsx`
- Modify/Test: `frontend/apps/web/src/lib/strengthProvenance.ts`
- Modify/Test: `frontend/apps/web/src/components/report-pdf/{buildComprehensiveSections,types}.ts`
- Modify: `frontend/apps/web/src/components/report-pdf/sections/ReportPdfDomains.tsx`
- Test: `frontend/apps/web/e2e/report-pdf.e2e.spec.ts`
- Modify: `frontend/apps/web/src/locales/{en,es,pt}/predictive.json`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces `DomainStrengthAssayResult`, `composeDomainStrength(summary)`, `composeDomainStrengths(summaries)`, `DomainStrengthSubject`, `signDomainStrength`, `sealDomainStrengths`, `verifyDomainStrength`, and `verifyDomainStrengthClaim`.
- Carries Assay components and Avow evidence through worker, shared types, store persistence, UI, and complete PDF output without changing the domain-strength numeric result.
- Locks npm `@edgeproc/assay==0.5.0-dev.2` in Bun with the existing 86,400-second maturity policy and no excludes.

- [ ] **Step 1: Run focused strength and persistence tests**

Run:

```bash
cd frontend
bunx vitest run \
  packages/browser/src/pyodide/__tests__/strengthAssay.test.ts \
  packages/browser/src/pyodide/__tests__/strengthReceipt.test.ts \
  packages/store/src/adapters/predictive.test.ts \
  apps/web/src/lib/__tests__/strengthProvenance.test.ts \
  apps/web/src/components/features/predictive/__tests__/DomainsPanel.test.tsx \
  apps/web/src/components/report-pdf/__tests__/comprehensiveSections.test.ts \
  apps/web/src/components/report-pdf/__tests__/maximalReportPdf.test.tsx \
  apps/web/src/components/report-pdf/__tests__/pdfCompleteness.test.tsx
```

Expected: all pass. Any missing behavior starts with a failing literal test for percent scaling, ordered component identities, clamp, stable inputs hash, seal/verify/tamper behavior, stored round trip, multilingual visible evidence, and PDF pagination/completeness.

- [ ] **Step 2: Refresh the exact registry lock only after maturity**

Run after `2026-08-23T14:19:26.405Z` only:

```bash
cd frontend
bun install
bun install --frozen-lockfile
bun pm ls @edgeproc/assay
```

Expected: exactly `@edgeproc/assay@0.5.0-dev.2` with the exact SRI from Global
Constraints; `bunfig.toml` still contains `minimumReleaseAge = 86400`; neither
`bunfig.toml` nor the lock contains an age exclude, path, link, or tarball Assay
source.

- [ ] **Step 3: Refactor the evidence flow without changing arithmetic**

Keep Assay composition in `strengthAssay.ts`, Avow signing/verification in `strengthReceipt.ts`, serialization types in shared types, and rendering in UI/PDF files. Every displayed component must come from the verified `ScoreResult`; unavailable or failed evidence is explicit and never presented as verified.

- [ ] **Step 4: Run AlmaMesh's complete gates and real PDF lane**

Run: `uv run poe gate`

Run: `cd frontend && bun run --filter @almamesh/web test:e2e:report:pdf`

Run: `git diff --check && git status --short`

Expected: backend coverage remains at least 90%; frontend typecheck/lint/Knip/unit/build pass; the real maximal PDF includes every chart/table/evidence panel with no clipping or overlap.

- [ ] **Step 5: Commit the AlmaMesh product integration**

```bash
git add CHANGELOG.md frontend
git commit -m "feat: add Assay strength provenance"
```

### Task 6: Add AlmaMesh's Four-File Adapter and Prove Shadow Parity

**Files (AlmaMesh worktree only):**
- Create: `portfolio-delivery.toml`
- Create: `delivery/composition.py`
- Create: `delivery/contracts.json`
- Create: `.github/workflows/portfolio-delivery.yml`

**Interfaces:**
- Consumes: Task 5 gates, `frontend/apps/web/scripts/setup-dev-assets.sh`, Pyodide `0.29.4`, MiniLM q8 assets, signed bundle sequence/public key contract, and PDF/browser checks.
- Produces: stream `almamesh-app`; snapshots `pyodide-0.29.4` and `minilm-q8`; artifacts `pages-dist.tar.zst`, signed bundle tree, `public.key`, and `build.json`; `RecoveryRelease` recovery.

- [ ] **Step 1: Write AlmaMesh contract fixtures and verify RED**

Create the same six scenario names as Task 3, but set rollback expectations to:

```json
{"name":"rollback","failure":"live_check","expected_recovery":"recovery_release","expected_sequence_relation":"recovery > failed > predecessor","terminal":"live_verified"}
```

Add a retry fixture that crashes after the predecessor bytes are copied but before signing; the resumed run must allocate/reuse one recovery ID and publish one higher sequence. Add a stale completion fixture where a lower sequence finishes last and is rejected.

Run: `uv run portfolio-delivery check-project /Users/harish/dev/.codex-worktrees/almamesh-assay-avow`

Expected: FAIL until all four files exist and monotonic recovery is declared.

- [ ] **Step 2: Implement snapshot, build, signing, verification, and recovery plans**

The manifest declares repository `hseshadr/almamesh`, URL `https://almamesh.com`, Pages project `almamesh`, exact npm Assay version, Bun maturity 86,400 seconds with an empty exemption list, and `recovery = "recovery_release"`.

The composition exports:

```python
COMPOSITION = ProjectAdapterSpec(
    project_id="almamesh",
    repository="hseshadr/almamesh",
    streams=(StreamSpec("almamesh-app", signed=True, sequence_field="bundle.sequence", requires=()),),
    inputs=(
        InputSpec("pyodide-0.29.4", InputKind.NETWORK, ("bash", "frontend/apps/web/scripts/setup-dev-assets.sh"), "frontend/apps/web/public/pyodide", snapshot=True),
        InputSpec("minilm-q8", InputKind.NETWORK, ("bash", "frontend/apps/web/scripts/setup-dev-assets.sh"), "frontend/apps/web/public/models", snapshot=True),
    ),
    artifacts=(
        ArtifactSpec("pages-dist.tar.zst", ArtifactKind.TREE, "frontend/apps/web/dist", "application/vnd.edgeproc.pages.v1+tar+zstd"),
        ArtifactSpec("signed-bundle.tar.zst", ArtifactKind.TREE, "frontend/apps/web/dist/bundle", "application/vnd.edgeproc.bundle.v2+tar+zstd"),
        ArtifactSpec("public.key", ArtifactKind.FILE, "frontend/apps/web/dist/public.key", "application/octet-stream"),
        ArtifactSpec("build.json", ArtifactKind.FILE, "frontend/apps/web/dist/build.json", "application/json"),
    ),
    checks=("uv run poe gate", "cd frontend/apps/web && bunx playwright test e2e/report-pdf.e2e.spec.ts"),
    deployment=DeploymentSpec("cloudflare_pages", "almamesh", "https://almamesh.com", "pages-dist.tar.zst"),
    verification=VerificationSpec(("build_identity", "signed_bundle", "cpython_parity", "assay_avow", "privacy", "locales", "onboarding", "offline", "pdf_geometry")),
    recovery=RecoverySpec(RecoveryMode.RECOVERY_RELEASE, sequence_field="bundle.sequence"),
)
```

Snapshot Pyodide's 20 files and every MiniLM file as canonical bytes with URL, version/revision, source timestamp when available, byte size, and SHA-256. Production signing occurs after prequalification in the credential-isolated central phase; project Dagger code sees no private key. The final Pages archive is built once after the signed assets/public key are injected, then qualified and persisted.

- [ ] **Step 3: Generate the caller and run local conformance**

Use `uv run portfolio-delivery render-project` with the current `portfolio-delivery` HEAD exactly as in Task 3, targeting the AlmaMesh worktree. Run `check-project`, the six contract scenarios, two independent Dagger builds, and the production verifier against a local static service.

Expected: two runs with the same source and snapshots have identical envelope and Pages tree digests; changing one Pyodide or model byte invalidates only dependent stages; a lower-sequence recovery fails.

- [ ] **Step 4: Commit the four files**

```bash
git add portfolio-delivery.toml delivery/composition.py delivery/contracts.json .github/workflows/portfolio-delivery.yml
git commit -m "ci: add AlmaMesh portfolio delivery adapter"
```

- [ ] **Step 5: Merge shadow mode and collect three exact parity records**

Push Tasks 5-6 as the AlmaMesh integration PR and enable auto-merge after the existing `Test` workflow and new shadow caller pass. On three protected-main runs compare the complete backend/frontend gate set, CPython parity, signed bundle bytes/sequence, privacy/no-egress, multilingual/onboarding/offline, Assay/Avow, PDF geometry, source SHA, snapshot digests, and Pages tree.

Expected: controller `cutover_eligible=true`; all three runs have zero privileged provider writes.

### Task 7: Prepare AlmaMesh Automatic Cutover and Monotonic Recovery

**Files (AlmaMesh worktree only):**
- Delete after shadow eligibility: `.github/workflows/test.yml`
- Delete after shadow eligibility: `.github/workflows/deploy.yml`
- Delete after shadow eligibility: `.github/workflows/nightly-e2e.yml`
- Delete after shadow eligibility: `.github/workflows/security-audit.yml`

**Interfaces:**
- Consumes: a verified signed predecessor envelope, controller-allocated `RecoveryId`, failed/current sequence, exact candidate Pages bytes, and Task 6 cutover evidence.
- Produces: candidate/live evidence and a fresh signed recovery envelope whose sequence is greater than the failed release.

- [ ] **Step 1: Exercise candidate and crash-safe recovery**

Deploy the qualified Pages archive to a candidate branch and run candidate verification: exact `build.json`, public key, pointer signature, pointer/manifest/chunk reconstruction, Assay/Avow strength replay, privacy/no-egress, all three locales, onboarding/offline, and maximal PDF geometry.

Inject a live failure after production activation. The controller must allocate `RecoveryId(project="almamesh", environment="production", sequence=current+1, predecessor_digest=...)`, re-sign verified predecessor content, qualify/persist it as a new envelope, deploy its exact Pages archive, and live-verify the higher sequence. Crash before signing, after signing, after upload, and after activation; each retry converges with no duplicate sequence or stale completion.

- [ ] **Step 2: Prove the new manifest covers every legacy gate and schedule**

Run `uv run portfolio-delivery compare-workflow-coverage` with all four AlmaMesh legacy workflow paths. Expected: no missing test, build, audit, nightly browser, deploy, identity, or verification step.

- [ ] **Step 3: Remove superseded YAML and run the complete Dagger gate**

```bash
git rm .github/workflows/test.yml .github/workflows/deploy.yml \
  .github/workflows/nightly-e2e.yml .github/workflows/security-audit.yml
git commit -m "ci: cut AlmaMesh delivery to Dagger"
dagger call -m github.com/hseshadr/portfolio-delivery@"$(git -C /Users/harish/dev/portfolio-delivery rev-parse HEAD)" \
  delivery --source=. --project-id=almamesh --event=pull_request \
  --source-sha="$(git rev-parse HEAD)" --attempt-id="almamesh-cutover-local-1" \
  export --path=.delivery/qualified
```

Expected: full repository and PDF gates pass; the signed recovery conformance suite passes; independent builds produce identical bytes.

- [ ] **Step 4: Create the release-bot cutover PR**

Attach three shadow run IDs, input/envelope/Pages/bundle digests, candidate ID, candidate evidence, failed release sequence, recovery ID/sequence, and live recovery evidence. Leave auto-merge to controller policy in Task 11.

### Task 8: Finalize AML Filter Assay Scoring and Exact Mature Locks

**Files (AML Filter worktree only):**
- Modify: `frontend/packages/amlfilter-browser/package.json`
- Modify: `frontend/pnpm-lock.yaml`
- Create: `frontend/packages/amlfilter-browser/src/engine/assayScoring.ts`
- Create: `frontend/packages/amlfilter-browser/src/engine/assayScoring.test.ts`
- Modify: `frontend/packages/amlfilter-browser/src/engine/{domain,scoring,screeningEngine,scoreReceipt,matchReceipts,multiEngine,sequenceMatcher,version}.ts`
- Test: matching `*.test.ts`, `scoring.parity.test.ts`, `scoreReceipt.integration.test.ts`, and `scoreReceiptV2.test.ts`
- Modify: `frontend/packages/amlfilter-publisher/src/decision/{artifact,decide,emit,levels,runDecision}.ts`
- Test: `frontend/packages/amlfilter-publisher/src/decision/{decide,emit}.test.ts`
- Modify: `frontend/packages/amlfilter-publisher/package.json`
- Create: `frontend/packages/amlfilter-publisher/src/snapshotSources.ts`
- Test: `frontend/packages/amlfilter-publisher/src/snapshotSources.test.ts`
- Modify/Test: `frontend/app/src/pages/{strictness,DossierCard,ScreenPage,decisionParity}.ts*`
- Test: `frontend/app/tests/e2e-c1/{receipt-badge,screen-flow}.spec.ts`
- Test: `frontend/app/tests/score-receipt-browser.spec.ts`
- Modify: `eval/pyproject.toml`
- Modify: `eval/uv.lock`
- Modify: `eval/src/amlfilter_eval/artifact.py`
- Test: `eval/tests/test_artifact.py`
- Test: `eval/tests/test_supply_chain.py`
- Modify: `.github/workflows/{ci,deploy,publish-watchlist}.yml` only for the current Assay proof gates; Task 10 owns their deletion.
- Modify: `README.md`, `CLAUDE.md`, `frontend/README.md`, `docs/ARCHITECTURE.md`, `docs/QUICKSTART.md`, `docs/diagrams/screening-pipeline.d2`, `docs/diagrams/screening-pipeline.svg`

**Interfaces:**
- Produces `SCORING_POLICY_VERSION = "amlfilter.additive.v2"`, `ScoringSignalValues`, `calculateAssayScore`, `ScoringPolicyDecision`, `scoringPolicyDecision`, signed `MatchScoreSubject`, and strict receipt verification.
- Produces `snapshotSources(outputRoot: string) -> Promise<SnapshotManifest>` and package script `snapshot`, which writes bounded canonical raw feed bytes plus URL/header/source-time/SHA-256 metadata without building or publishing a watchlist.
- Renames the Ratcliff/Obershelp signal to `name_sequence` under the new policy version without changing numeric scoring; app, publisher decision harness, golden fixture, and Python evaluation remain in parity.
- Locks npm `@edgeproc/assay==0.5.0-dev.2` and Python `assay-engine[metrics]==0.5.0.dev2` from immutable registries.

- [ ] **Step 1: Run focused scoring, receipt, decision, and evaluation tests**

Run:

```bash
cd frontend
pnpm exec vitest run \
  packages/amlfilter-browser/src/engine/assayScoring.test.ts \
  packages/amlfilter-browser/src/engine/scoring.test.ts \
  packages/amlfilter-browser/src/engine/scoring.parity.test.ts \
  packages/amlfilter-browser/src/engine/scoreReceipt.integration.test.ts \
  packages/amlfilter-browser/src/engine/scoreReceiptV2.test.ts \
  packages/amlfilter-browser/src/engine/matchReceipts.test.ts \
  packages/amlfilter-browser/src/engine/screeningEngine.test.ts \
  packages/amlfilter-publisher/src/decision/decide.test.ts \
  packages/amlfilter-publisher/src/decision/emit.test.ts \
  packages/amlfilter-publisher/src/snapshotSources.test.ts \
  app/src/pages/decisionParity.test.ts
cd ../eval
uv run pytest -q tests/test_artifact.py tests/test_supply_chain.py
```

Expected: all pass. A missing behavior begins with a failing literal test for ordered five-term components, raw/coefficient/contribution, clamp, inputs hash, threshold tier, reason/component parity, subject tamper, exact dependency source, and `name_sequence` cross-runtime parity.

- [ ] **Step 2: Replace local candidates with exact mature registry locks**

Run after `2026-08-23T14:19:26.405Z` only:

```bash
cd frontend
pnpm --filter @amlfilter/browser pkg set "dependencies.@edgeproc/assay=0.5.0-dev.2"
pnpm install --lockfile-only
pnpm install --frozen-lockfile
cd ../eval
uv lock --check
uv sync --frozen
```

Run: `rg -n 'file:.*assay|link:.*assay|minimumReleaseAgeExclude|minimumReleaseAgeExcludes' frontend/packages/amlfilter-browser/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml eval/pyproject.toml eval/uv.lock`

Expected: `rg` exits 1; pnpm lock has the exact registry SRI for
`0.5.0-dev.2`; uv resolves exact `0.5.0.dev2` with both expected artifact
hashes; `minimumReleaseAge: 1440` remains.

- [ ] **Step 3: Keep the scoring boundary single and typed**

`assayScoring.ts` alone constructs Assay terms and policy decisions. `scoring.ts` retains candidate signal derivation, `scoreReceipt.ts` owns Avow subject/sign/verify, publisher decision code consumes the typed score/policy, and `amlfilter_eval.artifact` imports metrics only through the existing evaluation seam. Delete the legacy v1 test file only when v2 regression coverage names every removed behavior.

Implement `snapshotSources` by invoking the existing OFAC, UN, EU, UK, and alias source adapters, preserving each adapter's bounded timeout and size checks, writing canonical bytes under the supplied root, and emitting a sorted manifest with source ID, final URL, ETag/Last-Modified, original source timestamp, byte size, and SHA-256. It performs no signing, watchlist build, or provider write; the Dagger build consumes only this snapshot directory.

- [ ] **Step 4: Run AML Filter's complete gates**

Run: `cd frontend && pnpm run gate`

Run: `cd eval && uv run poe gate`

Run: `git diff --check && git status --short`

Expected: lint/typecheck/coverage/build, publisher recall/decision, Python quality, canonical worker/i18n, receipt, C1, KYC, signed bundle, and mobile Playwright lanes all pass with at least 90% Python branch coverage and no security-source exemption.

- [ ] **Step 5: Commit the AML Filter product integration**

```bash
git add .github/workflows CLAUDE.md README.md docs eval frontend
git commit -m "feat: add Assay scoring receipts"
```

### Task 9: Add AML Filter's Four-File Split-Stream Adapter and Prove Shadow Parity

**Files (AML Filter worktree only):**
- Create: `portfolio-delivery.toml`
- Create: `delivery/composition.py`
- Create: `delivery/contracts.json`
- Create: `.github/workflows/portfolio-delivery.yml`

**Interfaces:**
- Consumes: Task 8 gates, MiniLM download manifest, OFAC/UN/EU/UK source adapters, signed watchlist publisher, same-origin bundle contract, and exact app/watchlist dependency relationship.
- Produces independent streams `aml-filter-watchlists` and `aml-filter-app`; the app envelope references one exact watchlist snapshot/envelope digest; both use monotonic `RecoveryRelease`.

- [ ] **Step 1: Write split-stream fixtures and verify RED**

Create the six shared scenarios for each stream plus a cross-stream case:

```json
{
  "name": "app_watchlist_reference",
  "watchlist_envelope": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "app_expected_reference": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "allow_mutable_pointer": false
}
```

The watchlist recovery fixture asserts `recovery_sequence > failed_sequence > predecessor_sequence`. The app stale-work fixture changes the desired watchlist digest while an older app build completes and expects zero provider writes from that older attempt.

Run: `uv run portfolio-delivery check-project /Users/harish/dev/.codex-worktrees/aml-filter-assay-avow`

Expected: FAIL until two independent streams, immutable data reference, and monotonic policies exist.

- [ ] **Step 2: Implement canonical feed/model snapshots and both compositions**

The manifest declares repository `hseshadr/aml-filter`, URL `https://aml-filter.com`, Pages project `aml-filter`, exact npm/Python Assay versions, pnpm maturity 86,400 seconds with no exemptions, and separate schedules/triggers for app source and watchlist freshness.

`delivery/composition.py` exports:

```python
COMPOSITION = ProjectAdapterSpec(
    project_id="aml-filter",
    repository="hseshadr/aml-filter",
    streams=(
        StreamSpec("aml-filter-watchlists", signed=True, sequence_field="pointer.sequence", requires=()),
        StreamSpec("aml-filter-app", signed=True, sequence_field="bundle.sequence", requires=("aml-filter-watchlists",)),
    ),
    inputs=(
        InputSpec("minilm-q8", InputKind.NETWORK, ("node", "frontend/app/scripts/download-model.mjs"), "frontend/app/public/models", snapshot=True),
        InputSpec("watchlist-feeds", InputKind.NETWORK, ("pnpm", "--filter", "@amlfilter/publisher", "run", "snapshot"), ".delivery/inputs/watchlists", snapshot=True),
    ),
    artifacts=(
        ArtifactSpec("pages-dist.tar.zst", ArtifactKind.TREE, "frontend/app/dist", "application/vnd.edgeproc.pages.v1+tar+zstd"),
        ArtifactSpec("watchlist-origin.tar.zst", ArtifactKind.TREE, "frontend/app/dist/bundle/origin", "application/vnd.edgeproc.watchlist.v2+tar+zstd"),
        ArtifactSpec("build.json", ArtifactKind.FILE, "frontend/app/dist/build.json", "application/json"),
    ),
    checks=("cd frontend && pnpm run gate", "cd eval && uv run poe gate"),
    deployment=DeploymentSpec("cloudflare_pages", "aml-filter", "https://aml-filter.com", "pages-dist.tar.zst"),
    verification=VerificationSpec(("build_identity", "watchlist_integrity", "screening", "kyc", "c1", "mobile", "assay_avow", "tamper", "privacy")),
    recovery=RecoverySpec(RecoveryMode.RECOVERY_RELEASE, sequence_field="pointer.sequence"),
)
```

Each feed snapshot stores canonical raw bytes, final URL, response/source timestamp, ETag/Last-Modified when present, source ID, digest, and retrieval evidence. A source outage may carry forward only a previously verified immutable per-list snapshot under existing freshness policy; the new envelope identifies it as stale and retains its original timestamp. The app build receives only the chosen watchlist envelope digest and restored bytes, never a mutable live URL.

- [ ] **Step 3: Generate the caller and prove local split-stream conformance**

Generate with the exact shared HEAD, run `check-project`, all fixtures, independent duplicate builds, an A/B out-of-order completion, and a restart after each write boundary. Assert the app stream does not rerun feed downloads when only app source changes; a feed digest change invalidates the watchlist build and then the dependent app envelope.

Expected: exact digest reproducibility, one write per idempotency key, no stale winner, and no app envelope without an exact watchlist digest.

- [ ] **Step 4: Commit the four files**

```bash
git add portfolio-delivery.toml delivery/composition.py delivery/contracts.json .github/workflows/portfolio-delivery.yml
git commit -m "ci: add AML Filter portfolio delivery adapter"
```

- [ ] **Step 5: Merge shadow mode and collect three parity records for both streams**

Push Tasks 8-9 as the AML Filter integration PR and enable auto-merge only after existing CI and shadow pass. Compare application CI plus watchlist publication shadow independently: screening/KYC, C1, mobile, receipt/tamper, decision parity, source freshness, per-list health/carry-forward state, bundle reconstruction, privacy/no-egress, source SHA, input snapshot digests, and Pages tree.

Expected: three consecutive protected-main app parity records and three scheduled watchlist parity records; no provider write; controller cutover eligibility for both streams.

### Task 10: Prepare AML Filter Automatic Cutover and Monotonic Recovery

**Files (AML Filter worktree only):**
- Delete after both streams are shadow-eligible: `.github/workflows/ci.yml`
- Delete after both streams are shadow-eligible: `.github/workflows/deploy.yml`
- Delete after both streams are shadow-eligible: `.github/workflows/publish-watchlist.yml`
- Delete after both streams are shadow-eligible: `.github/workflows/watchlist-freshness.yml`
- Delete after coverage mapping: `.github/workflows/security-audit.yml`

**Interfaces:**
- Consumes: exact app/watchlist envelopes, signed current/predecessor pointers, controller-allocated stream-specific recovery IDs/sequences, and Task 9 eligibility.
- Produces: independent candidate/live/recovery evidence for `aml-filter-watchlists` and `aml-filter-app` without coupling a feed refresh to an app rebuild failure.

- [ ] **Step 1: Exercise candidate verification and both recovery paths**

Deploy the app candidate from the exact Pages archive and verify `build.json`, CSP/privacy, visible Assay receipt, screening/KYC, C1, mobile, browser console/network, and the exact embedded watchlist envelope digest. Reconstruct the candidate watchlist pointer -> manifest -> every zstd chunk -> every file and verify source health/freshness.

Inject a watchlist live failure and separately an app live failure. Each must allocate a higher sequence, re-sign verified predecessor bytes into a new `RecoveryRelease`, qualify/persist/deploy, and live-verify. Crashes before/after sign and before/after activation converge once; a lower-sequence completion cannot win.

- [ ] **Step 2: Prove new coverage of all five legacy workflows**

Run `uv run portfolio-delivery compare-workflow-coverage` with the five AML Filter workflow paths. Expected: full app gate, security audit, daily freshness, per-list publish/carry-forward, production identity, exact origin verification, custom-domain checks, and deploy behavior are all represented with unchanged or stricter assertions.

- [ ] **Step 3: Remove superseded YAML and run both streams through Dagger**

```bash
git rm .github/workflows/ci.yml .github/workflows/deploy.yml \
  .github/workflows/publish-watchlist.yml .github/workflows/watchlist-freshness.yml \
  .github/workflows/security-audit.yml
git commit -m "ci: cut AML Filter delivery to Dagger"
dagger call -m github.com/hseshadr/portfolio-delivery@"$(git -C /Users/harish/dev/portfolio-delivery rev-parse HEAD)" \
  delivery --source=. --project-id=aml-filter --event=pull_request \
  --source-sha="$(git rev-parse HEAD)" --attempt-id="aml-cutover-local-1" \
  export --path=.delivery/qualified
```

Expected: application and watchlist gates pass; the qualified app references the exact qualified watchlist digest; independent reruns are byte-identical.

- [ ] **Step 4: Create the release-bot cutover PR**

Attach both streams' shadow IDs, snapshot/envelope/artifact digests, candidate ID, app/watchlist candidate evidence, current/failed/recovery sequences, and live recovery evidence. Leave auto-merge to controller policy in Task 11.

### Task 11: Coordinate Auto-Merge, Production Activation, Live Proof, and Legacy Shutdown

**Files:**
- No source file changes; this task mutates only GitHub PR/repository policy, controller desired state, GHCR evidence, and Cloudflare deployments already authorized by Tasks 4, 7, and 10.

**Interfaces:**
- Consumes: three release-bot cutover PRs, protected required checks, exact qualified OCI tuples, candidate/live/recovery evidence, and the automatic controller policy.
- Produces: merged cutovers, automatic protected-main deployments, durable `live_verified` records for EdgeReco/AlmaMesh/AML Filter, and proof that legacy workflows and manual release paths are inactive.

- [ ] **Step 1: Audit all PR heads and enable policy-driven auto-merge**

Run:

```bash
gh pr list --repo hseshadr/edge-reco --state open --json number,headRefOid,author,isDraft,statusCheckRollup
gh pr list --repo hseshadr/almamesh --state open --json number,headRefOid,author,isDraft,statusCheckRollup
gh pr list --repo hseshadr/aml-filter --state open --json number,headRefOid,author,isDraft,statusCheckRollup
```

Expected: each cutover PR author is the configured release bot, none is Dependabot, each head matches the audited commit, each required legacy-parity/Dagger/security/product check is successful, and the controller still reports the corresponding source/envelope as desired. Enable auto-merge through the controller; do not use an admin bypass.

- [ ] **Step 2: Observe merges and automatic candidate-to-production transitions**

For each repository, watch the merge run to terminal success with `gh run watch --exit-status`. The controller must show `persisted -> candidate_deployed -> candidate_verified -> production_activated -> live_verified`; stale/out-of-order runs return `observe` and make no provider write.

Expected: each production deployment ID differs from its candidate deployment ID but both extracted trees have the same file SHA-256 manifest and envelope digest. No Actions artifact or rebuild supplies production bytes.

- [ ] **Step 3: Verify exact public identities and signed data**

Run:

```bash
curl --fail --silent --show-error --max-time 15 https://edge-reco.com/build.json | jq -e .
curl --fail --silent --show-error --max-time 15 https://almamesh.com/build.json | jq -e .
curl --fail --silent --show-error --max-time 15 https://aml-filter.com/build.json | jq -e .
curl --fail --silent --show-error --max-time 15 https://aml-filter.com/bundle/origin/latest | jq -e .
```

Expected: every `build.json` reports the intended protected-main SHA and qualified envelope digest; EdgeReco reports the intended catalog/ranking proof digest; AlmaMesh's signed bundle sequence/digest are the activated release; AML's signed pointer sequence, manifest hash, and app-referenced watchlist envelope are exact.

- [ ] **Step 4: Run full production browser verification from restored envelopes**

For each application, restore the qualified tree from GHCR by URI/digest and invoke the public credential-free verifier:

```bash
dagger call -m github.com/hseshadr/portfolio-delivery@"$(git -C /Users/harish/dev/portfolio-delivery rev-parse HEAD)" \
  verify-live --qualified=.delivery/qualified --production-url=https://edge-reco.com \
  export --path=.delivery/edge-live.json
dagger call -m github.com/hseshadr/portfolio-delivery@"$(git -C /Users/harish/dev/portfolio-delivery rev-parse HEAD)" \
  verify-live --qualified=.delivery/qualified --production-url=https://almamesh.com \
  export --path=.delivery/alma-live.json
dagger call -m github.com/hseshadr/portfolio-delivery@"$(git -C /Users/harish/dev/portfolio-delivery rev-parse HEAD)" \
  verify-live --qualified=.delivery/qualified --production-url=https://aml-filter.com \
  export --path=.delivery/aml-live.json
```

Expected: EdgeReco storefront/search/proof/offline checks pass; AlmaMesh multilingual/onboarding/strength/PDF/offline/no-egress checks pass; AML screening/KYC/C1/mobile/receipt/tamper/watchlist/privacy checks pass; all three have zero console errors and no forbidden external-origin request.

- [ ] **Step 5: Prove automatic recovery and reconciliation one final time**

Use the controller's fault-injection provider, not live customer traffic, to replay one post-activation live failure per project. Verify EdgeReco ordinary rollback returns to the captured predecessor ID; AlmaMesh and AML produce higher-sequence recovery releases. Replay every controller request ten times and reverse completion order; provider write counts remain one and the newest desired release wins.

Expected: recovery evidence is attached to each release, alarms reconcile interrupted states, no target remains `rolling_back`/`recovering`, and all public domains finish on their intended desired release.

- [ ] **Step 6: Confirm the legacy path is disabled and close the migration**

Run: `gh api repos/hseshadr/edge-reco/actions/workflows --jq '.workflows[].path'`, and repeat for AlmaMesh and AML Filter.

Expected: `.github/workflows/portfolio-delivery.yml` is the only project delivery caller; superseded CI/deploy/watchlist YAML is absent; scheduled checks are controller-owned; no long-lived npm/PyPI/Cloudflare token is referenced; no manual publish/deploy documentation remains authoritative.

Record the three source SHAs, exact Assay versions, input snapshot digests, OCI URIs/manifest digests, Cloudflare candidate/production/recovery IDs, controller attempts/fences, Dagger trace URLs, GitHub run IDs, and live evidence digests in each release's detached `DeliveryRecord`. Mark this phase complete only when all three application releases are `live_verified` and no incident is open.

## Phase Completion Gate

Run in `/Users/harish/dev/portfolio-delivery`:

```bash
uv run poe lint
uv run poe typecheck
uv run poe complexity
uv run poe test
uv run poe mutation
uv run poe audit
uv run pytest -q tests/projects tests/workflows tests/controller
actionlint -shellcheck= -pyflakes= .github/workflows/*.yml
uvx zizmor==1.29.0 .github/workflows
git diff --check
```

Run the complete EdgeReco, AlmaMesh, and AML Filter gates from Tasks 2, 5, and 8 once more against the exact merged SHAs. Expected: every command exits 0; Python branch coverage remains at least 90%; Python complexity meets each repository's existing bound and the shared platform is A/A/A; mutation survivors are zero in the shared safety core; generated callers have no drift; all dependency audits are clean.

The final evidence must demonstrate that the npm maturity policy was honored without exemptions, each four-file adapter passes conformance, shadow output matched existing CI, the exact qualified bytes reached candidate and production, live behavior works, automatic rollback/recovery is idempotent and race-safe, and every superseded manual path is inactive.
