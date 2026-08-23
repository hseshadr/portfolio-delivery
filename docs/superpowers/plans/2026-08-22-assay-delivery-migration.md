# Assay Portfolio Delivery Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Assay from its proven `0.5.0-dev.2` release machinery to the shared Portfolio Delivery controller through a shadow-first, automatic cutover that preserves every current quality gate and artifact byte, proves rollback without publishing a new package, and leaves only four permanent repository-local delivery integration files.

**Architecture:** Assay continues to own product qualification in one typed Dagger composition adapter. The adapter emits the standard qualified-envelope directory once; central reusable workflows persist it to OCI and ask the durable controller for every mutation. Release Please may update version files through a protected pull request but may not tag or release. A generated, byte-authorized, shell-free caller is the only privileged repository workflow. Shadow runs compare the shared path with the immutable `0.5.0-dev.2` baseline before control is cut over, and the legacy publisher is deleted only after automatic cutover and a no-write rollback drill pass.

**Tech Stack:** Python 3.13.14, Dagger `v0.21.8`, typed Python composition, pytest, Ruff, mypy, Radon, GitHub Actions, Release Please, GHCR generic OCI artifacts, GitHub App authorization, npm/PyPI trusted publishing.

**Spec:** `docs/superpowers/specs/2026-08-22-portfolio-delivery-design.md`

## Global Constraints

- Start implementation in a new clean worktree from `origin/main`; at planning time the protected main is `8a292becb6dd98fee5aa1ba08017f86ebec47c0c`. Do not implement on the stale `codex/assay-oidc-trusted-publishing` worktree.
- Treat the existing immutable release as the migration oracle: version `0.5.0-dev.2`, source commit `35c1fe926c39dfd533b9b7f297abd63eac77c6e6`, annotated tag object `fdc653872fbf0ba62f8c44bd85bc9f581df5f319`, wheel SHA-256 `9e112118987f48ad0b9132ad592e8674e853b1d0f1967a08255750f1619061e8`, sdist SHA-256 `661f132cd0fd1ec64668985bb150a563f627d690eb68d8ac8dd4dbe71a8a4713`, npm tarball SHA-256 `b1cd13c4919bf00e8b52d8467bc783c14d9b78cf0768ca0c04556b03c8242a33`, and npm integrity `sha512-R5uFYeU7l4UkAGRvY7HDcOlLBpSw10WAi2w14WtmkzhpcxYsJO43OsGc/jJ9JN0dxeZjucpFftcXJNRwsSeDJw==`.
- Planning and migration drills must not publish, unpublish, retag, or create a new PyPI/npm package version. Import and observe the already-published `0.5.0-dev.2` bytes. The first future package publication is a separate automatic event after a later qualified Release Please merge.
- Pin Dagger engine, CLI, and Python SDK to `v0.21.8` / source commit `7902e644beeba4468f1ea786015b4be1d6d5bbcd`; pin `dagger/dagger-for-github@v8.4.1` to `27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77`.
- Pin ORAS `v1.3.3` to `ghcr.io/oras-project/oras@sha256:a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8`.
- Central workflow tooling uses Node `24.19.0`, Wrangler `4.120.0`, and `@cloudflare/vitest-pool-workers` `0.20.3`. Assay product gates retain Node `22.13.0`, pnpm `11.5.0`, uv `0.11.32`, actionlint `1.7.12`, Gitleaks `8.30.1`, and ShellCheck `0.11.0` until an independent dependency change is reviewed.
- Pin Release Please action commit `5c625bfb5d1ff62eadeeb3772007f7f66fdcf071`; it opens/updates protected release PRs only and never creates a tag or GitHub release.
- The permanent integration is exactly `portfolio-delivery.toml`, `delivery/assay.py`, `delivery/contracts.json`, and `.github/workflows/publish.yml`. Tests, documentation, CODEOWNERS, and a temporary shadow job are governance/support files, not additional runtime integration.
- The generated `.github/workflows/publish.yml` has no `run`, `workflow_dispatch`, caller-controlled command, mutable reference, package token, or project checkout. It calls `hseshadr/portfolio-delivery/.github/workflows/publish-package.yml@$APPROVED_DELIVERY_REF`, where generation rejects the value unless it is the 40-hex merge commit returned by `gh pr view "$PORTFOLIO_DELIVERY_PR" --repo hseshadr/portfolio-delivery --json mergeCommit --jq .mergeCommit.oid`; its exact byte digest is registered with the controller.
- Project source executes only in credential-free qualification jobs with `contents: read`; jobs with `id-token: write`, `packages: write`, PyPI, or npm trust never check out or execute project source.
- The one product build runs `scripts/build_release_artifacts.sh /work/out/release` exactly once. Do not wrap `scripts/verify_release_candidate.sh`, because the legacy path rebuilds after qualification.
- Every controller transition uses `release_id`, immutable `envelope_uri`, an envelope digest matching `sha256:[0-9a-f]{64}`, attempt ID, fence, source SHA, workflow claims, and exact generated caller digest. Only `decision=proceed` permits one provider write; `observe`, `complete`, and `incident` cannot write.
- npm remains last and uses exactly `npm publish "$archive" --tag "$selected_tag" --ignore-scripts --provenance --access public`; never invoke `npm dist-tag`.
- Use red -> green -> refactor for every behavior. New/changed Python follows `python-quality`: typed boundaries, no `Dict[str, Any]` or `TypedDict`, functions at most 15 lines, Radon grade A, and at least 90% branch coverage for `delivery/`.
- Make one focused commit after each task. Never combine the governance cutover with legacy deletion.

## Consumed Interfaces

The Assay adapter must provide these public Dagger functions:

```text
dagger call -m . delivery \
  --source=. --project-id=assay --event="$EVENT" \
  --source-sha="$SOURCE_SHA" --attempt-id="$RUN_ID-$RUN_ATTEMPT" \
  export --path=.delivery/qualified

dagger call -m . verify-candidate --qualified=.delivery/qualified \
  --candidate-url="$CANDIDATE_URL" export --path=.delivery/candidate-evidence.json

dagger call -m . verify-live --qualified=.delivery/qualified \
  --production-url="$PRODUCTION_URL" export --path=.delivery/live-evidence.json
```

For this package-only project, `verify-candidate` and `verify-live` verify public PyPI/npm/GHCR evidence and never mutate a registry. `delivery` produces exactly:

```text
.delivery/qualified/build-envelope.v1.json
.delivery/qualified/qualification-record.v1.json
.delivery/qualified/checksums.sha256
.delivery/qualified/artifacts/assay_engine-*-py3-none-any.whl
.delivery/qualified/artifacts/assay_engine-*.tar.gz
.delivery/qualified/artifacts/edgeproc-assay-*.tgz
```

The generated caller passes only `project_id=assay`, event/ref/SHA/attempt scalars, and the qualified OCI tuple to the central workflow. The central workflow uses these controller endpoints:

```text
POST /v1/callers/assay/authorize
POST /v1/releases/{release_id}/authorize-persist
POST /v1/releases/{release_id}/record-persisted
POST /v1/releases/{release_id}/authorize-package
POST /v1/releases/{release_id}/live-evidence
POST /v1/releases/{release_id}/recover
POST /v1/releases/{release_id}/reconcile
```

### Task 1: Freeze the dev2 Oracle and Declare the Four-File Contract

**Files:**
- Create: `portfolio-delivery.toml`
- Create: `delivery/contracts.json`
- Create: `tests/delivery/test_manifest.py`
- Create: `tests/delivery/test_contract_fixtures.py`
- Modify: `pyproject.toml`

**Interfaces:**
- `portfolio-delivery.toml` declares `schema_version=1`, `project_id="assay"`, Python/npm package identities, artifact globs, required gates, publication order `pypi,mirror,npm`, npm channel policy, maturity margin, and the exact reusable-workflow full commit.
- `delivery/contracts.json` contains named cases `success`, `retry`, `conflict`, `stale`, `rollback`, and `live_check_failure`; each case has an immutable input, expected controller decision, expected side-effect count, and expected evidence status.

- [ ] **Step 1: Create a clean implementation worktree and prove the oracle before editing**

```bash
git -C /Users/harish/dev/assay fetch origin
git -C /Users/harish/dev/assay worktree add -b codex/portfolio-delivery-assay /Users/harish/dev/.codex-worktrees/assay-portfolio-delivery origin/main
cd /Users/harish/dev/.codex-worktrees/assay-portfolio-delivery
git rev-parse HEAD
gh release view v0.5.0-dev.2 --json tagName,isPrerelease,isImmutable,targetCommitish
python -m pip index versions assay-engine --pre
npm view @edgeproc/assay@0.5.0-dev.2 dist --json
```

Expected: clean `origin/main`; release is immutable/prerelease and registry metadata matches the hashes in Global Constraints.

- [ ] **Step 2: Write failing schema and scenario tests**

```python
def test_manifest_preserves_assay_gate_and_publish_order() -> None:
    manifest = load_manifest(ROOT / "portfolio-delivery.toml")
    assert manifest.project_id == "assay"
    assert manifest.required_gates == EXPECTED_ASSAY_GATES
    assert manifest.publish_order == ("pypi", "mirror", "npm")


@pytest.mark.parametrize("name", [
    "success", "retry", "conflict", "stale", "rollback", "live_check_failure"
])
def test_contract_case_has_a_closed_side_effect_budget(name: str) -> None:
    case = load_case(name)
    assert case.expected_side_effect_count in (0, 1)
    assert case.expected_decision in {"proceed", "observe", "complete", "incident"}
```

- [ ] **Step 3: Run RED**

Run: `uv run pytest tests/delivery/test_manifest.py tests/delivery/test_contract_fixtures.py -q`

Expected: collection or file-load failure because the manifest and fixtures do not exist.

- [ ] **Step 4: Add the manifest, six hand-authored cases, and test dependencies**

List every preserved gate explicitly; do not use an opaque `script` field or caller-supplied command. Add `delivery` to Ruff, mypy, Radon, pytest coverage, and package inclusion in `pyproject.toml`.

- [ ] **Step 5: Run GREEN and quality checks**

```bash
uv run pytest tests/delivery/test_manifest.py tests/delivery/test_contract_fixtures.py -q
uv run ruff check tests/delivery
uv run mypy tests/delivery
git diff --check
```

- [ ] **Step 6: Commit**

```bash
git add portfolio-delivery.toml delivery/contracts.json tests/delivery pyproject.toml
git commit -m "test(delivery): freeze assay migration contract"
```

### Task 2: Build the Typed Assay Composition Adapter

**Files:**
- Create: `delivery/__init__.py`
- Create: `delivery/assay.py`
- Create: `tests/delivery/test_assay_adapter.py`
- Create: `tests/delivery/test_assay_envelope.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Frozen values: `DeliveryInput(project_id, event, source_sha, attempt_id)`, `Artifact(name, sha256, size, media_type)`, `GateResult(name, status, duration_ms, evidence)`, and `QualifiedRelease(release_id, version, source_sha, artifacts, gates)`.
- Pure functions: `release_identity(source: Directory, request: DeliveryInput) -> QualifiedRelease`, `artifact_inventory(directory: Directory) -> tuple[Artifact, ...]`, and `build_envelope(release: QualifiedRelease) -> bytes`.
- Dagger object: `Assay.delivery(source, project_id, event, source_sha, attempt_id) -> Directory`, plus credential-free `verify_candidate` and `verify_live` methods.

- [ ] **Step 1: Write failing typed behavior tests**

```python
def test_delivery_rejects_a_non_assay_project() -> None:
    request = DeliveryInput("other", "main", "a" * 40, "1-1")
    with pytest.raises(ValueError, match="project_id"):
        request.validate()


def test_envelope_artifacts_are_sorted_and_content_addressed() -> None:
    envelope = json.loads(build_envelope(qualified_release()))
    assert [item["name"] for item in envelope["artifacts"]] == sorted(EXPECTED_NAMES)
    assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", item["digest"])
               for item in envelope["artifacts"])
```

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/delivery/test_assay_adapter.py tests/delivery/test_assay_envelope.py -q`

Expected: import failure for `delivery.assay`.

- [ ] **Step 3: Compose the exact existing quality graph**

The Dagger method must run these commands in pinned, network-minimized containers and stop on the first failed gate:

```text
uv sync --frozen --all-groups --all-extras
pnpm --dir ts install --frozen-lockfile --ignore-scripts
uv run poe gate
pnpm --dir ts gate
uv run pytest tests/test_consumer_conformance.py tests/test_metric_vectors.py -q
pnpm --dir ts exec vitest run src/compositionVectors.test.ts src/metricVectors.test.ts
uv run poe mutants
uv run python -m benchmarks.release
pnpm --dir ts benchmark
bash examples/run_composite.sh
uv run poe workflow-lint
uv run poe workflow-security
uv run poe secrets
uv run poe audit
shellcheck examples/*.sh scripts/*.sh
bash scripts/build_release_artifacts.sh /work/out/release
uv run python scripts/verify_release_artifacts.py /work/out/release
git diff --check
git diff --exit-code
git status --porcelain=v1 --untracked-files=all
```

The adapter must assert the last output is empty. It invokes the build script once and never invokes a publish or staging script. Use composition helpers for toolchain, gate, build, and evidence containers rather than inheritance.

- [ ] **Step 4: Run focused GREEN and Python quality**

```bash
uv run pytest tests/delivery/test_assay_adapter.py tests/delivery/test_assay_envelope.py --cov=delivery --cov-branch --cov-fail-under=90 -q
uv run ruff check delivery tests/delivery
uv run ruff format --check delivery tests/delivery
uv run mypy delivery tests/delivery
uv run radon cc -s -a delivery
```

Expected: tests pass; mypy has no errors; all functions are Radon grade A.

- [ ] **Step 5: Commit**

```bash
git add delivery tests/delivery pyproject.toml uv.lock
git commit -m "feat(delivery): compose assay qualification adapter"
```

### Task 3: Prove Local dev2 Artifact and Gate Parity

**Files:**
- Create: `tests/delivery/test_dev2_parity.py`
- Create: `tests/fixtures/delivery/dev2-oracle.json`
- Modify: `scripts/verify_release_candidate.sh`
- Modify: `tests/test_release_contract.py`

**Interfaces:**
- `dev2-oracle.json` records source SHA, filenames, sizes, SHA-256 digests, npm integrity, PyPI upload timestamps, and existing registry coordinates.
- `compare_oracle(qualified: Path, oracle: Dev2Oracle) -> ParityReport` returns missing gates, extra/missing artifacts, byte mismatches, and metadata mismatches without registry writes.

- [ ] **Step 1: Write failing parity and single-build regression tests**

```python
def test_dev2_adapter_reproduces_all_three_release_bytes(dev2_checkout: Path) -> None:
    report = compare_oracle(run_delivery(dev2_checkout), load_dev2_oracle())
    assert report == ParityReport.clean()


def test_candidate_script_does_not_stage_or_publish() -> None:
    text = (ROOT / "scripts/verify_release_candidate.sh").read_text()
    assert "stage_npm_publisher.sh" not in text
    assert "npm publish" not in text
```

- [ ] **Step 2: Run RED against the unmodified script and missing oracle**

Run: `uv run pytest tests/delivery/test_dev2_parity.py tests/test_release_contract.py -q`

Expected: oracle load fails and the existing npm staging assertion fails.

- [ ] **Step 3: Record the immutable oracle and remove publisher staging from candidate verification**

Build from detached source `35c1fe926c39dfd533b9b7f297abd63eac77c6e6` in a disposable worktree. Compare all three output bytes to the dev2 hashes; compare the manifest gate set to the legacy CI, security, mutation, example, benchmark, and artifact jobs. Do not weaken reproducibility flags to make parity pass.

- [ ] **Step 4: Run the real adapter twice and prove deterministic bytes**

```bash
dagger call -m . delivery --source=. --project-id=assay --event=main --source-sha=35c1fe926c39dfd533b9b7f297abd63eac77c6e6 --attempt-id=dev2-local-1 export --path=/tmp/assay-dev2-a
dagger call -m . delivery --source=. --project-id=assay --event=main --source-sha=35c1fe926c39dfd533b9b7f297abd63eac77c6e6 --attempt-id=dev2-local-2 export --path=/tmp/assay-dev2-b
sha256sum /tmp/assay-dev2-a/artifacts/*
diff -ru /tmp/assay-dev2-a/artifacts /tmp/assay-dev2-b/artifacts
uv run pytest tests/delivery/test_dev2_parity.py tests/test_release_contract.py -q
```

Expected: the three hashes equal the oracle and `diff` is empty. Attempt-specific evidence may differ; artifact bytes may not.

- [ ] **Step 5: Commit**

```bash
git add tests/delivery/test_dev2_parity.py tests/fixtures/delivery/dev2-oracle.json scripts/verify_release_candidate.sh tests/test_release_contract.py
git commit -m "test(delivery): prove dev2 qualification parity"
```

### Task 4: Add a No-Write Hosted Shadow Against Controller and OCI

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `tests/delivery/test_shadow_workflow.py`
- Create: `tests/fixtures/delivery/shadow-controller.json`
- Modify: `portfolio-delivery.toml`

**Interfaces:**
- Temporary job `delivery-shadow` invokes the commit-pinned central qualification/persistence workflow with `mode: shadow`, `project_id: assay`, and no package environment.
- Shadow result schema: `schema_version`, `release_id`, `source_sha`, `envelope_uri`, `envelope_digest`, `legacy_gate_statuses`, `shared_gate_statuses`, `artifact_digests`, `controller_decision`, `provider_write_count`, and `parity`.
- `mode=shadow` may persist the qualified envelope to `ghcr.io/hseshadr/assay/delivery` and record evidence, but controller package authorization must return `observe`; PyPI/npm write jobs must be structurally absent.

- [ ] **Step 1: Write failing semantic workflow tests**

```python
def test_shadow_has_no_registry_write_capability() -> None:
    workflow = load_workflow(ROOT / ".github/workflows/ci.yml")
    shadow = workflow.jobs["delivery-shadow"]
    assert shadow.uses == CENTRAL_QUALIFY_REF
    assert shadow.with_["mode"] == "shadow"
    assert "npm-release" not in shadow.environments
    assert shadow.permissions == {"contents": "read", "id-token": "write"}


def test_shadow_fixture_proves_parity_without_package_writes() -> None:
    result = load_shadow_fixture()
    assert result.parity == "match"
    assert result.controller_decision == "observe"
    assert result.provider_write_count == 0
```

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/delivery/test_shadow_workflow.py -q`

Expected: `delivery-shadow` is missing.

- [ ] **Step 3: Add the temporary job using the approved central full commit**

The PR job qualifies the current SHA and persists its OCI envelope. For the historical dev2 run, use a central migration-dispatch input bound to source `35c1fe926c39dfd533b9b7f297abd63eac77c6e6`; the controller imports the existing registry observations and never authorizes package writes. The OCI descriptor annotations include `org.opencontainers.image.revision`, `org.opencontainers.image.version=0.5.0-dev.2`, release ID, and envelope digest.

- [ ] **Step 4: Validate locally and run the hosted shadow**

```bash
uv run pytest tests/delivery/test_shadow_workflow.py -q
uv run poe workflow-contract
uv run poe workflow-lint
uv run poe workflow-security
git push -u origin codex/portfolio-delivery-assay
gh pr create --title "Migrate Assay delivery in shadow mode" --body "Shadow the proven dev2 release through Portfolio Delivery; do not publish a new package."
gh pr checks --watch
gh run view --job delivery-shadow --log
SHADOW_DIGEST="$(jq -r .envelope_digest tests/fixtures/delivery/shadow-controller.json)"
oras manifest fetch "ghcr.io/hseshadr/assay/delivery@$SHADOW_DIGEST"
```

Expected: every old and shared gate is green, three artifact digests equal the oracle, OCI inspection succeeds, controller returns `observe`, and provider write count is zero. Substitute only the emitted immutable digest in the inspection command; do not use a tag.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml tests/delivery/test_shadow_workflow.py tests/fixtures/delivery/shadow-controller.json portfolio-delivery.toml
git commit -m "ci(delivery): shadow assay through shared controller"
```

### Task 5: Configure Release Please as PR-Only Version Steward

**Files:**
- Create: `release-please-config.json`
- Create: `.release-please-manifest.json`
- Create: `.github/workflows/release-please.yml`
- Create: `tests/delivery/test_release_please.py`
- Create: `.github/CODEOWNERS`

**Interfaces:**
- Release Please updates `pyproject.toml`, `ts/package.json`, and changelog/version metadata in one protected PR.
- `.github/workflows/release-please.yml` uses action commit `5c625bfb5d1ff62eadeeb3772007f7f66fdcf071`, `release-type: simple`, and an App token authorized only for contents/pull-request writes.
- The workflow consumes `release-please-config.json` and `.release-please-manifest.json`; it must set `skip-github-release: true` and `skip-github-pull-request: false`.

- [ ] **Step 1: Write failing policy tests**

```python
def test_release_please_can_open_a_pr_but_cannot_release() -> None:
    config = load_json(ROOT / "release-please-config.json")
    workflow = load_workflow(ROOT / ".github/workflows/release-please.yml")
    assert config["skip-github-release"] is True
    assert config["skip-github-pull-request"] is False
    assert workflow.has_action_commit(RELEASE_PLEASE_COMMIT)
    assert workflow.permissions == {"contents": "read"}
    assert not workflow.has_tag_or_release_write_step()


def test_release_pr_updates_python_and_npm_versions_together() -> None:
    assert extra_files() == ("pyproject.toml", "ts/package.json")
```

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/delivery/test_release_please.py -q`

Expected: configuration files are absent.

- [ ] **Step 3: Add PR-only configuration and ownership**

Use the Portfolio Delivery GitHub App token rather than `GITHUB_TOKEN` so required checks run on the release PR. Give the token only `contents: write` and `pull-requests: write` at token creation; keep job-level default `contents: read`. Add the four integration files, both Release Please files, and the workflow itself to CODEOWNERS for the delivery maintainer team.

- [ ] **Step 4: Validate PR-only behavior**

```bash
uv run pytest tests/delivery/test_release_please.py -q
uv run poe workflow-contract
uv run poe workflow-lint
uv run poe workflow-security
gh api repos/hseshadr/assay/releases --jq '.[].tag_name' > /tmp/releases-before
gh api repos/hseshadr/assay/git/refs/tags --jq '.[].ref' > /tmp/tags-before
```

After a test execution on the migration branch, compare the same API outputs byte-for-byte to the before files and inspect the created/updated PR. Expected: one release PR, no tag, no GitHub release.

- [ ] **Step 5: Commit**

```bash
git add release-please-config.json .release-please-manifest.json .github/workflows/release-please.yml .github/CODEOWNERS tests/delivery/test_release_please.py
git commit -m "ci(release): make release please pr only"
```

### Task 6: Generate and Externally Authorize the Privileged Caller

**Files:**
- Replace generated: `.github/workflows/publish.yml`
- Create: `tests/delivery/test_generated_caller.py`
- Modify: `.github/CODEOWNERS`
- Modify: `portfolio-delivery.toml`
- External controller fixture: `tests/fixtures/callers/assay.expected.yml` in the Portfolio Delivery repository
- External controller registry: `config/callers/assay.toml` in the Portfolio Delivery repository

**Interfaces:**
- Generate with `uv run portfolio-delivery-workflows render --manifest portfolio-delivery.toml --output .github/workflows/publish.yml`; stdout is the lowercase SHA-256 of exact bytes.
- Caller trigger is only `push.tags: ["v*"]`; tags can be created only by the governed controller App. The caller passes fixed `project_id: assay` to `hseshadr/portfolio-delivery/.github/workflows/publish-package.yml@$APPROVED_DELIVERY_REF`, and the renderer accepts only the exact 40-hex commit recorded in the manifest.
- `POST /v1/callers/assay/authorize` receives `repository`, `workflow_ref`, `source_sha`, `caller_sha256`, `central_workflow_ref`, and GitHub App identity; the allowlist stores the exact digest and source commit.

- [ ] **Step 1: Write failing byte and privilege tests**

```python
def test_publish_caller_is_exact_generated_output() -> None:
    rendered = render_from_manifest(ROOT / "portfolio-delivery.toml")
    assert (ROOT / ".github/workflows/publish.yml").read_bytes() == rendered


def test_publish_caller_has_no_local_privilege_surface() -> None:
    caller = load_workflow(ROOT / ".github/workflows/publish.yml")
    assert "workflow_dispatch" not in caller.on
    assert caller.run_steps == ()
    assert caller.mutable_uses == ()
    assert caller.on == {"push": {"tags": ["v*"]}}
    assert caller.caller_inputs == ()
```

- [ ] **Step 2: Run RED against the legacy publisher**

Run: `uv run pytest tests/delivery/test_generated_caller.py tests/test_workflow_contract.py -q`

Expected: legacy tag/manual triggers, shell steps, and local privileged jobs violate the generated contract.

- [ ] **Step 3: Render, register, and protect exact bytes**

Generate once from the manifest. Commit the same expected bytes and SHA-256 in the central repository, update `config/callers/assay.toml`, deploy the controller allowlist, and require the Portfolio Delivery App `caller-authorized` status plus CODEOWNERS review on changes to the caller, manifest, adapter, or fixtures. Extend tag ruleset `20920170` so only the App may create `refs/tags/v*`; deletion and non-fast-forward remain blocked.

- [ ] **Step 4: Prove generated governance**

```bash
uv run portfolio-delivery-workflows check --manifest portfolio-delivery.toml --caller .github/workflows/publish.yml
sha256sum .github/workflows/publish.yml
uv run pytest tests/delivery/test_generated_caller.py tests/test_workflow_contract.py -q
uv run poe workflow-lint
uv run poe workflow-security
gh api repos/hseshadr/assay/rulesets/20920170
```

Expected: local digest equals the controller registration; a one-byte mutation makes `check` and `caller-authorized` fail; the ruleset permits tag creation only to the installed App while deletion/non-fast-forward remain denied.

- [ ] **Step 5: Commit Assay and central governance separately**

```bash
git add .github/workflows/publish.yml .github/CODEOWNERS portfolio-delivery.toml tests/delivery/test_generated_caller.py tests/test_workflow_contract.py
git commit -m "ci(delivery): install generated assay publisher"
```

In the Portfolio Delivery worktree:

```bash
git add tests/fixtures/callers/assay.expected.yml config/callers/assay.toml
git commit -m "feat(governance): authorize assay caller bytes"
```

Do not merge either side until both PRs are green and the central commit referenced by Assay is immutable and approved.

### Task 7: Import dev2, Cut Over Automatically, and Drill Both Rollback Fences

**Files:**
- Create: `tests/delivery/test_cutover_contract.py`
- Create: `tests/fixtures/delivery/dev2-import.json`
- Create: `tests/fixtures/delivery/rollback-before-write.json`
- Create: `tests/fixtures/delivery/rollback-after-dispatch.json`
- Modify: `.github/workflows/ci.yml`
- Modify: `portfolio-delivery.toml`

**Interfaces:**
- Controller import records existing dev2 source/tag/package observations and persisted OCI envelope under one release ID without provider writes.
- Cutover preconditions are machine-readable: two consecutive shadow matches, exact caller authorization, central workflow pin deployed, controller reconciliation green, OCI digest inspectable, package maturity margin elapsed, and rollback fixtures passing.
- Before `write_dispatched`, `recover` may atomically return control to shadow/legacy observation with zero provider writes. At or after `write_dispatched`, `recover` must refuse takeover, preserve the fence, and permit observation/reconciliation only.

- [ ] **Step 1: Write failing state-machine contract tests**

```python
def test_import_of_dev2_is_observation_only() -> None:
    result = simulate(load_case("dev2-import"))
    assert result.release_id == "assay-0.5.0-dev.2"
    assert result.provider_write_count == 0
    assert result.package_digests == DEV2_DIGESTS


@pytest.mark.parametrize("case,writes,control", [
    ("rollback-before-write", 0, "shadow"),
    ("rollback-after-dispatch", 0, "reconcile-only"),
])
def test_rollback_never_creates_a_second_publisher(case: str, writes: int,
                                                    control: str) -> None:
    result = simulate(load_case(case))
    assert result.additional_provider_writes == writes
    assert result.control == control
```

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/delivery/test_cutover_contract.py -q`

Expected: import/cutover/rollback fixtures are missing.

- [ ] **Step 3: Import the immutable dev2 evidence and satisfy cutover gates**

Use controller migration authorization bound to source SHA, the OCI envelope digest from Task 4, the exact PyPI/npm/GitHub release observations, and App identity. Re-inspect all providers after import. Execute a second hosted shadow from the same dev2 source with a new attempt ID and prove controller returns `complete` or `observe`, never `proceed` for package writes.

- [ ] **Step 4: Run the automatic cutover and no-write drills**

Merge the central governance PR first, then the Assay PR through protected main after every required check passes. The controller flips `assay.delivery_mode` from `shadow` to `active` only when all declared preconditions evaluate true; no human dispatch is added. Run the pre-write rollback case in the controller sandbox namespace, restore active mode, then inject the post-dispatch state with a fake provider adapter and prove takeover is fenced. Neither drill may create a `v*` tag or contact a package publish endpoint.

```bash
uv run pytest tests/delivery/test_cutover_contract.py -q
gh pr checks --watch
gh api repos/hseshadr/assay/releases --jq '.[].tag_name' > /tmp/releases-after-cutover
gh api repos/hseshadr/assay/git/refs/tags --jq '.[].ref' > /tmp/tags-after-cutover
cmp /tmp/releases-before /tmp/releases-after-cutover
cmp /tmp/tags-before /tmp/tags-after-cutover
npm view @edgeproc/assay@0.5.0-dev.2 dist.integrity
python -m pip index versions assay-engine --pre
```

Expected: before/after release and tag lists are identical; npm integrity and PyPI dev2 remain unchanged; controller audit contains two shadow matches, one atomic cutover, a successful pre-write rollback/restore, and a refused post-dispatch takeover.

- [ ] **Step 5: Remove the temporary shadow job and commit**

Once the evidence is attached to the migration PR, remove only `delivery-shadow` from `.github/workflows/ci.yml`; keep ordinary CI gates. Set `delivery_mode="active"` in the manifest so repository intent matches controller state.

```bash
git add tests/delivery/test_cutover_contract.py tests/fixtures/delivery .github/workflows/ci.yml portfolio-delivery.toml
git commit -m "ci(delivery): cut assay over after no-write rollback drill"
```

### Task 8: Delete Legacy Mutation Paths and Verify Production State

**Files:**
- Delete: `scripts/npm-publish.sh`
- Delete: `scripts/pypi-publish.sh`
- Delete: `scripts/registry_release_guard.py`
- Delete: `scripts/release_epoch.py`
- Delete: `scripts/stage_npm_publisher.sh`
- Delete: `scripts/verify_npm_dist_tag.py`
- Delete: `scripts/verify_published_release.py`
- Delete: `tests/test_manual_publish_scripts.py`
- Modify: `tests/test_release_contract.py`
- Modify: `tests/test_workflow_contract.py`
- Modify: `README.md`
- Modify: `docs/RELEASES.md`

**Interfaces:**
- The supported path is protected merge -> Release Please version PR -> qualification -> OCI persistence -> controller/App tag -> central OIDC package workflow -> maturity-aware public verification.
- `verify_release_candidate.sh`, `build_release_artifacts.sh`, `build_python_artifacts.sh`, `minimize_sdist.py`, `verify_release_artifacts.py`, `verify_release_identity.py`, and the mutation test harness remain product verification tools; none may publish.

- [ ] **Step 1: Replace legacy-presence assertions with failing absence/sole-authority assertions**

```python
@pytest.mark.parametrize("path", LEGACY_MUTATION_PATHS)
def test_legacy_mutation_path_is_absent(path: str) -> None:
    assert not (ROOT / path).exists()


def test_only_generated_caller_can_reach_shared_publish_workflow() -> None:
    workflows = load_all_workflows(ROOT / ".github/workflows")
    assert workflows.registry_mutation_callers() == ("publish.yml",)
    assert workflows.local_publish_steps() == ()
```

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/test_manual_publish_scripts.py tests/test_release_contract.py tests/test_workflow_contract.py -q`

Expected: legacy files still exist and old assertions still describe them.

- [ ] **Step 3: Delete only mutation/recovery machinery and update runnable documentation**

Document the copy-pasteable local proof:

```bash
dagger call -m . delivery --source=. --project-id=assay --event=main --source-sha="$(git rev-parse HEAD)" --attempt-id="local-1" export --path=.delivery/qualified
uv run python scripts/verify_release_artifacts.py .delivery/qualified/artifacts
uv run portfolio-delivery-workflows check --manifest portfolio-delivery.toml --caller .github/workflows/publish.yml
```

Describe recovery as controller reconciliation, not rerunning a publish script. State explicitly that registry packages are immutable and rollback changes control/application state, never package bytes.

- [ ] **Step 4: Run the complete Assay gate**

```bash
uv sync --frozen --all-groups --all-extras
pnpm --dir ts install --frozen-lockfile --ignore-scripts
uv run poe gate
pnpm --dir ts gate
uv run pytest tests/test_consumer_conformance.py tests/test_metric_vectors.py -q
pnpm --dir ts exec vitest run src/compositionVectors.test.ts src/metricVectors.test.ts
uv run poe mutants
uv run python -m benchmarks.release
pnpm --dir ts benchmark
bash examples/run_composite.sh
uv run poe workflow-lint
uv run poe workflow-security
uv run poe secrets
uv run poe audit
shellcheck examples/*.sh scripts/*.sh
uv run pytest tests/delivery --cov=delivery --cov-branch --cov-fail-under=90 -q
git diff --check
git status --porcelain=v1 --untracked-files=all
```

Expected: every gate passes and only intentional migration files appear.

- [ ] **Step 5: Verify the already-published production state without publishing**

```bash
gh release view v0.5.0-dev.2 --json tagName,isPrerelease,isImmutable,targetCommitish,assets
npm view @edgeproc/assay@0.5.0-dev.2 dist --json
python -m pip index versions assay-engine --pre
IMPORTED_DIGEST="$(jq -r .envelope_digest tests/fixtures/delivery/dev2-import.json)"
oras manifest fetch "ghcr.io/hseshadr/assay/delivery@$IMPORTED_DIGEST"
```

Expected: GitHub, npm, PyPI, OCI, and controller all identify the same source and dev2 artifacts; no new version exists. Substitute only the immutable digest recorded in `tests/fixtures/delivery/dev2-import.json`.

- [ ] **Step 6: Commit**

```bash
git add -A -- scripts/npm-publish.sh scripts/pypi-publish.sh scripts/registry_release_guard.py scripts/release_epoch.py scripts/stage_npm_publisher.sh scripts/verify_npm_dist_tag.py scripts/verify_published_release.py tests/test_manual_publish_scripts.py
git add tests/test_release_contract.py tests/test_workflow_contract.py README.md docs/RELEASES.md
git commit -m "refactor(delivery): retire assay legacy publishers"
```

## Completion Evidence

The migration is complete only when all of the following are attached to the Assay and Portfolio Delivery PRs:

1. Full Assay gate output and `delivery/` branch coverage at or above 90%.
2. Two hosted shadow results with identical gate sets and dev2 artifact digests.
3. OCI manifest by digest plus controller import/reinspection evidence for dev2.
4. Exact caller SHA-256, external allowlist entry, CODEOWNERS rule, required App status, and tag ruleset response.
5. Release Please test showing one protected PR and byte-identical tag/release lists.
6. Automatic cutover audit plus pre-write rollback success and post-dispatch takeover refusal, both with zero provider writes.
7. Repository search proving the generated caller is the only registry mutation entry point.
8. Final public verification of the existing `0.5.0-dev.2` release with no new PyPI/npm version.

Do not call the phase complete from CI success alone. The final acceptance proof is agreement among source SHA, envelope digest, OCI bytes, controller ledger, GitHub tag/release, PyPI files, npm integrity, and the live no-write verification record.
