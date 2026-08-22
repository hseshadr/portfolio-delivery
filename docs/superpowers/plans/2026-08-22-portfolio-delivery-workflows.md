# Portfolio Delivery Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver generated repository callers and centrally pinned GitHub workflows that qualify once with Dagger, persist and attest the exact envelope in GHCR, publish Assay through OIDC, deploy application candidates, activate and live-verify them, and reconcile every interrupted transition automatically.

**Architecture:** Repository workflows are deterministic, shell-free generated callers of commit-pinned reusable workflows. The reusable workflows keep project-controlled Dagger execution in credential-free jobs and move GHCR, package-registry, and deployment mutations into isolated central jobs that accept only a qualified OCI URI/digest tuple. A typed Python workflow package renders callers, validates their effective security graph, and converts controller responses into fail-closed scalar outputs; the durable controller and project Dagger modules are consumed through the exact contracts below and remain owned by Phases 1 and 2.

**Tech Stack:** Python 3.13, frozen dataclasses, Jinja2, PyYAML, pytest, Hypothesis, GitHub Actions reusable workflows, Dagger `v0.21.8`, ORAS `v1.3.3`, GHCR generic OCI artifacts, GitHub attestations, Release Please, npm/PyPI trusted publishing, actionlint `v1.7.12`, zizmor `1.29.0`.

**Spec:** `docs/superpowers/specs/2026-08-22-portfolio-delivery-design.md`

## Global Constraints

- Pin Dagger engine, CLI, and Python SDK to `v0.21.8` / source commit `7902e644beeba4468f1ea786015b4be1d6d5bbcd`.
- Pin `dagger/dagger-for-github@v8.4.1` to `27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77`.
- Pin ORAS `v1.3.3` to `ghcr.io/oras-project/oras@sha256:a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8`.
- Pin Release Please `v4` to `5c625bfb5d1ff62eadeeb3772007f7f66fdcf071` and configure release-PR-only behavior.
- Pin checkout `v7.0.1` to `3d3c42e5aac5ba805825da76410c181273ba90b1`, setup-node `v7.0.0` to `820762786026740c76f36085b0efc47a31fe5020`, setup-python `v7.0.0` to `5fda3b95a4ea91299a34e894583c3862153e4b97`, attest-build-provenance `v4.2.2` to `4d101475d8b20a2381f78447822ac1eab6504dd8`, upload-artifact `v7.0.1` to `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`, download-artifact `v8.0.1` to `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`, PyPI publish `v1.14.2` to `dc37677b2e1c63e2034f94d8a5b11f265b73ba33`, and create-github-app-token `v3.2.0` to `bcd2ba49218906704ab6c1aa796996da409d3eb1`.
- Generated callers contain no `run`, `workflow_dispatch`, caller-selected command, registry token, or mutable action/module reference.
- Project source runs only in jobs with `contents: read`; it never receives `id-token: write`, `packages: write`, a registry credential, a signing key, or a Cloudflare credential.
- OIDC-bearing package jobs never check out or execute project source. PyPI receives exactly one wheel and one sdist; npm receives exactly one reviewed tarball.
- npm invokes `npm publish <archive> --tag <selected-tag> --ignore-scripts --provenance --access public`; it never invokes `npm dist-tag`.
- Every mutation consumes `release_id`, immutable `envelope_uri`, and `sha256:<64 lowercase hex>` `envelope_digest`, then re-inspects the provider before recording success.
- GitHub-hosted runners are outside the trusted build boundary. Durable correctness comes from OCI bytes and controller CAS/fencing, not an Actions artifact, concurrency group, or runner disk.
- Normal protected-merge delivery has no human approval. Dependabot pull requests never receive auto-merge.
- Use red -> green -> refactor for every behavior; branch coverage on `src/portfolio_delivery/workflows` must remain at least 90%.

---

## File Structure and Consumed Boundaries

Phase 3 owns these focused units:

- `src/portfolio_delivery/workflows/contracts.py`: immutable workflow request/response values and strict scalar validation.
- `src/portfolio_delivery/workflows/pins.py`: the single compatibility table for action, Dagger, and ORAS identities.
- `src/portfolio_delivery/workflows/render.py`: deterministic Jinja rendering and atomic caller generation.
- `src/portfolio_delivery/workflows/policy.py`: semantic validation of parsed callers and reusable workflow job graphs.
- `src/portfolio_delivery/workflows/governance.py`: Assay caller byte digest and controller authorization request.
- `src/portfolio_delivery/workflows/cli.py`: `render`, `check`, `authorize`, and `decode-controller` commands used by CI.
- `templates/workflows/*.yml.j2`: generated repository caller contracts.
- `.github/workflows/*.yml`: centrally pinned reusable workflows and their own workflow CI.
- `tests/workflows/*` and `tests/fixtures/workflows/*`: behavioral, graph, failure, and generation fixtures.

The plan consumes, but does not implement, these two Phase 1/2 boundaries:

```text
# project repository Dagger module, invoked with dagger-for-github
dagger call -m . delivery \
  --source=. --project-id=<project> --event=<pull_request|main|tag> \
  --source-sha=<40-hex> --attempt-id=<run_id>-<run_attempt> \
  export --path=.delivery/qualified

# required output tree
.delivery/qualified/build-envelope.v1.json
.delivery/qualified/qualification-record.v1.json
.delivery/qualified/checksums.sha256
.delivery/qualified/artifacts/**

# public, credential-free project verifiers
dagger call -m . verify-candidate --qualified=.delivery/qualified \
  --candidate-url=<https-url> export --path=.delivery/candidate-evidence.json
dagger call -m . verify-live --qualified=.delivery/qualified \
  --production-url=<https-url> export --path=.delivery/live-evidence.json
```

The controller client contract is JSON over HTTPS with an Actions OIDC bearer whose audience is `portfolio-delivery-controller`. Each request includes `schema_version: 1`, `correlation_id`, `repository`, `workflow_ref`, `job_workflow_ref`, `ref`, and `sha`; the controller independently validates those claims. Phase 3 uses these endpoints:

```text
POST /v1/releases/{release_id}/authorize-persist
POST /v1/releases/{release_id}/record-persisted
POST /v1/releases/{release_id}/authorize-package
POST /v1/releases/{release_id}/candidate
POST /v1/releases/{release_id}/candidate-evidence
POST /v1/releases/{release_id}/activate
POST /v1/releases/{release_id}/live-evidence
POST /v1/releases/{release_id}/recover
POST /v1/releases/{release_id}/reconcile
POST /v1/callers/assay/authorize
```

Authorization responses use `{ "decision": "proceed|observe|complete|incident", "attempt_id": "...", "fence": 7, ... }`. Only `proceed` permits one provider write, `observe` permits inspection only, `complete` is a proven no-op, and `incident` fails closed. Package authorization additionally returns `pypi: "publish|observe|complete"`, `mirror: "publish|observe|complete"`, `npm: "publish|observe|complete"`, and `selected_tag`, where `selected_tag` matches `latest|next|release-[0-9]+-[0-9]+-[0-9]+(?:-[0-9A-Za-z-]+)?`.

### Task 1: Typed Workflow Contracts and Compatibility Pins

**Files:**
- Create: `src/portfolio_delivery/workflows/__init__.py`
- Create: `src/portfolio_delivery/workflows/contracts.py`
- Create: `src/portfolio_delivery/workflows/pins.py`
- Test: `tests/workflows/test_contracts.py`
- Test: `tests/workflows/test_pins.py`

**Interfaces:**
- Consumes: Python 3.13 and the scalar controller/Dagger contract above.
- Produces: `WorkflowKind`, `WorkflowCallerSpec`, `QualifiedEnvelopeRef`, `ControllerDecision`, `PackageAuthorization`, `CandidateResult`, `ActivationResult`, `ActionPin`, `ACTION_PINS`, `DAGGER_VERSION`, and `ORAS_IMAGE`.

- [ ] **Step 1: Write failing contract tests with hand-derived literals**

```python
def test_envelope_ref_rejects_non_sha256_digest() -> None:
    with pytest.raises(ValueError, match="envelope_digest"):
        QualifiedEnvelopeRef("assay-1.2.3", "ghcr.io/x@y", "abc")


def test_package_authorization_rejects_a_channel_outside_policy() -> None:
    payload = {"decision": "proceed", "attempt_id": "a1", "fence": 4,
               "pypi": "publish", "mirror": "publish", "npm": "publish",
               "selected_tag": "beta"}
    with pytest.raises(ValueError, match="selected_tag"):
        PackageAuthorization.from_mapping(payload)
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `uv run pytest tests/workflows/test_contracts.py tests/workflows/test_pins.py -q`

Expected: collection fails because `portfolio_delivery.workflows.contracts` and `pins` do not exist.

- [ ] **Step 3: Implement frozen dataclasses, enums, validators, and the exact pin table**

```python
@dataclass(frozen=True, slots=True)
class QualifiedEnvelopeRef:
    release_id: str
    envelope_uri: str
    envelope_digest: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.envelope_digest):
            raise ValueError("invalid envelope_digest")
```

Keep every function at 15 lines or fewer and model JSON mappings as `Mapping[str, object]`; do not use an unbounded-value dictionary or a structural dictionary alias.

- [ ] **Step 4: Run GREEN, refactor, and enforce Python quality**

Run: `uv run pytest tests/workflows/test_contracts.py tests/workflows/test_pins.py -q`

Run: `uv run ruff check src/portfolio_delivery/workflows tests/workflows && uv run mypy src/portfolio_delivery/workflows && uv run radon cc -s -a src/portfolio_delivery/workflows`

Expected: all tests pass, mypy reports no errors, and every function is Radon grade A.

- [ ] **Step 5: Commit**

```bash
git add src/portfolio_delivery/workflows tests/workflows
git commit -m "feat(workflows): define delivery contracts and pins"
```

### Task 2: Deterministic Generated Caller Contract

**Files:**
- Create: `templates/workflows/application-caller.yml.j2`
- Create: `templates/workflows/package-caller.yml.j2`
- Create: `templates/workflows/assay-publish-caller.yml.j2`
- Create: `templates/workflows/release-please-caller.yml.j2`
- Create: `src/portfolio_delivery/workflows/render.py`
- Create: `src/portfolio_delivery/workflows/cli.py`
- Test: `tests/workflows/test_render.py`
- Test fixture: `tests/fixtures/manifests/assay.toml`
- Test fixture: `tests/fixtures/manifests/edge-reco.toml`
- Test fixture: `tests/fixtures/workflows/callers/assay.expected.yml`
- Test fixture: `tests/fixtures/workflows/callers/edge-reco.expected.yml`

**Interfaces:**
- Consumes: `WorkflowCallerSpec` and `ACTION_PINS` from Task 1.
- Produces: `render_caller(spec: WorkflowCallerSpec) -> bytes`, `write_caller(spec, destination: Path) -> str`, and CLI `portfolio-delivery-workflows render --manifest <path> --output <path>` where the return value is the lowercase SHA-256 of the exact generated bytes.

- [ ] **Step 1: Write failing deterministic-render tests**

```python
def test_application_caller_is_shell_free_and_byte_stable() -> None:
    first = render_caller(edge_reco_spec())
    second = render_caller(edge_reco_spec())
    assert first == fixture("callers/edge-reco.expected.yml")
    assert second == first
    parsed = load_workflow_bytes(first)
    assert all("run" not in job for job in parsed["jobs"].values())
    assert "workflow_dispatch" not in parsed["on"]
```

The expected caller has `pull_request`, protected `push`, and hourly `schedule` triggers; queued concurrency is `portfolio-delivery-${{ github.repository }}-${{ github.ref }}` with `cancel-in-progress: false`; its only job calls `hseshadr/portfolio-delivery/.github/workflows/project-delivery.yml@<40-hex approved commit>`.

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/workflows/test_render.py -q`

Expected: FAIL because `render_caller` is absent.

- [ ] **Step 3: Implement strict Jinja rendering and atomic generation**

```python
def render_caller(spec: WorkflowCallerSpec) -> bytes:
    template = _environment().get_template(spec.template_name)
    rendered = template.render(spec=spec, pins=ACTION_PINS)
    return (rendered.rstrip() + "\n").encode()
```

Use `StrictUndefined`, LF newlines, UTF-8, stable key order in templates, `Path.replace()` from a sibling temporary file, and `sha256(rendered).hexdigest()`. `load_workflow_bytes` uses a local PyYAML safe-loader subclass with YAML 1.2 boolean resolution so GitHub's `on` key remains a string. A second identical generation must leave the destination mtime unchanged.

- [ ] **Step 4: Run GREEN and exercise the real CLI twice**

Run: `uv run pytest tests/workflows/test_render.py -q`

Run: `uv run portfolio-delivery-workflows render --manifest tests/fixtures/manifests/assay.toml --output /tmp/assay-publish.yml && uv run portfolio-delivery-workflows render --manifest tests/fixtures/manifests/assay.toml --output /tmp/assay-publish.yml`

Expected: both invocations print the same 64-character digest and `/tmp/assay-publish.yml` equals `tests/fixtures/workflows/callers/assay.expected.yml`.

- [ ] **Step 5: Commit**

```bash
git add templates/workflows src/portfolio_delivery/workflows tests/workflows tests/fixtures/workflows
git commit -m "feat(workflows): generate pinned repository callers"
```

### Task 3: Semantic Workflow Security and Governance Policy

**Files:**
- Create: `src/portfolio_delivery/workflows/policy.py`
- Create: `src/portfolio_delivery/workflows/governance.py`
- Test: `tests/workflows/test_policy.py`
- Test: `tests/workflows/test_governance.py`
- Test fixture: `tests/fixtures/workflows/unsafe/unpinned-action.yml`
- Test fixture: `tests/fixtures/workflows/unsafe/oidc-with-checkout.yml`
- Test fixture: `tests/fixtures/workflows/unsafe/manual-assay-publish.yml`

**Interfaces:**
- Consumes: rendered YAML bytes, `WorkflowCallerSpec`, controller `POST /v1/callers/assay/authorize`.
- Produces: `WorkflowViolation(code: str, path: str, message: str)`, `validate_workflow(document: Mapping[str, object], kind: WorkflowKind) -> tuple[WorkflowViolation, ...]`, `caller_digest(content: bytes) -> str`, and `AssayCallerAuthorization(repository, path, sha, byte_sha256)`.

- [ ] **Step 1: Write failing behavioral policy tests**

```python
@pytest.mark.parametrize(
    ("fixture_name", "code"),
    [("unpinned-action.yml", "mutable-use"),
     ("oidc-with-checkout.yml", "oidc-project-source"),
     ("manual-assay-publish.yml", "manual-publish")],
)
def test_unsafe_workflow_fails_closed(fixture_name: str, code: str) -> None:
    violations = validate_workflow(load_unsafe(fixture_name), WorkflowKind.PACKAGE)
    assert code in {violation.code for violation in violations}
```

Name the mutations these tests catch: replacing a 40-hex action SHA with a tag, adding checkout to an OIDC job, adding `workflow_dispatch`, widening permissions, adding a caller `run`, accepting a channel outside policy, or inserting `npm dist-tag`.

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/workflows/test_policy.py tests/workflows/test_governance.py -q`

Expected: FAIL because the policy and governance modules are absent.

- [ ] **Step 3: Implement the parsed job-graph validator and Assay byte authorization**

The validator must resolve workflow-level and job-level permissions, traverse `needs`, classify project-source and privileged jobs, and reject every path from untrusted source to secret/OIDC-bearing execution. `caller_digest` hashes raw bytes, not parsed YAML. `authorize` submits the exact path `.github/workflows/publish.yml`, protected tag ref, source SHA, and byte digest; only a controller `decision` of `proceed` or `complete` is accepted.

- [ ] **Step 4: Run GREEN, mutation checks, and the CLI**

Run: `uv run pytest tests/workflows/test_policy.py tests/workflows/test_governance.py -q`

Run: `uv run mutmut run`

Run: `uv run portfolio-delivery-workflows check --root tests/fixtures/workflows/callers`

Expected: tests and mutation run pass; caller fixtures report zero violations.

- [ ] **Step 5: Commit**

```bash
git add src/portfolio_delivery/workflows tests/workflows tests/fixtures/workflows
git commit -m "feat(workflows): enforce workflow security policy"
```

### Task 4: Dagger Qualification, GHCR Persistence, and Attestation Workflow

**Files:**
- Create: `.github/workflows/project-delivery.yml`
- Test: `tests/workflows/test_project_delivery_workflow.py`
- Test fixture: `tests/fixtures/workflows/events/main-push.json`
- Test fixture: `tests/fixtures/workflows/events/pull-request.json`

**Interfaces:**
- Consumes: `workflow_call` inputs `project_id`, `source_sha`, `event`, `delivery_ref`, and optional `production_url`; project Dagger `delivery` command; controller persist endpoints.
- Produces: reusable outputs `release_id`, `envelope_uri`, `envelope_digest`, `oci_manifest_digest`, and `trace_url`; GHCR artifact `ghcr.io/hseshadr/portfolio-delivery-envelopes@sha256:<manifest>` plus GitHub provenance and project annotations.

- [ ] **Step 1: Write a failing workflow-graph test**

```python
def test_privileged_persist_cannot_execute_project_source() -> None:
    graph = load_workflow(".github/workflows/project-delivery.yml")
    assert graph.needs("persist") == {"qualify"}
    assert graph.job("qualify").permissions == {"contents": "read"}
    assert graph.job("persist").permissions == {
        "actions": "read", "attestations": "write", "contents": "read",
        "id-token": "write", "packages": "write"}
    assert not graph.job("persist").checks_out_caller
    assert not graph.job("persist").invokes_project_dagger
```

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/workflows/test_project_delivery_workflow.py -q`

Expected: FAIL because `project-delivery.yml` does not exist.

- [ ] **Step 3: Implement the reusable workflow with four explicit jobs**

`qualify` checks out exactly `source_sha`, invokes pinned Dagger with `version: v0.21.8`, `module: .`, and the exact `delivery ... export` call, verifies `checksums.sha256`, and uploads the qualified directory as a one-day transport artifact. `authorize-persist` obtains an OIDC token for the controller and records the intended URI/digest without registry credentials. `persist` downloads the transport, verifies every file digest again, uses the pinned ORAS image to push fixed media types under `sha256-<envelope hex>`, re-inspects the returned manifest digest, and calls `actions/attest-build-provenance` with `push-to-registry: true`. `record-persisted` submits both digests to the controller. Pull requests end after unprivileged qualification; protected main/tag events run persistence.

The OCI media types are `application/vnd.portfolio-delivery.build-envelope.v1+json` for the config and `application/vnd.portfolio-delivery.artifact.v1` for layers. ORAS arguments use canonical lexical file order and no mutable correctness tag.

- [ ] **Step 4: Run GREEN and static workflow engines**

Run: `uv run pytest tests/workflows/test_project_delivery_workflow.py -q`

Run: `actionlint -shellcheck= -pyflakes= .github/workflows/project-delivery.yml`

Run: `uvx zizmor==1.29.0 .github/workflows/project-delivery.yml`

Expected: all commands succeed with no policy finding.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/project-delivery.yml tests/workflows tests/fixtures/workflows/events
git commit -m "feat(workflows): persist and attest qualified envelopes"
```

### Task 5: Assay OIDC Package Publication and Caller Governance

**Files:**
- Create: `.github/workflows/publish-package.yml`
- Modify: `templates/workflows/assay-publish-caller.yml.j2`
- Modify: `src/portfolio_delivery/workflows/governance.py`
- Test: `tests/workflows/test_publish_package_workflow.py`
- Test: `tests/workflows/test_assay_caller.py`
- Test fixture: `tests/fixtures/workflows/controller/package-proceed.json`
- Test fixture: `tests/fixtures/workflows/controller/package-observe.json`

**Interfaces:**
- Consumes: `workflow_call` inputs `release_id`, `envelope_uri`, `envelope_digest`, `source_sha`, and `tag`; controller caller/package authorization; exact archives restored from GHCR.
- Produces: verified PyPI wheel/sdist, immutable GitHub release mirror, npm tarball published with the controller-selected tag, registry timestamps, and publication evidence bound to the envelope digest.

- [ ] **Step 1: Write failing isolation and command tests**

```python
def test_npm_is_the_final_mutation_and_has_no_project_checkout() -> None:
    graph = load_workflow(".github/workflows/publish-package.yml")
    assert graph.needs("npm") == {"mirror", "authorize-npm"}
    assert graph.job("npm").permissions == {"contents": "read", "id-token": "write"}
    assert not graph.job("npm").checks_out_caller
    assert graph.job("npm").run_argv == [
        "npm", "publish", "$ARCHIVE", "--tag", "$SELECTED_TAG",
        "--ignore-scripts", "--provenance", "--access", "public"]
    assert "dist-tag" not in graph.all_run_tokens()
```

Also assert that the PyPI job uses the pinned PyPA action with `packages-dir: .delivery/python`, `skip-existing: false`, `attestations: true`; the generated Assay caller has no shell/manual trigger and calls the reusable workflow at the approved commit; and `observe` performs registry inspection without a publish command.

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/workflows/test_publish_package_workflow.py tests/workflows/test_assay_caller.py -q`

Expected: FAIL because the central publication workflow is absent.

- [ ] **Step 3: Implement verify, PyPI, mirror, authorize-npm, npm, and record jobs**

`verify` has no OIDC permission, restores the OCI manifest by digest, validates the envelope and all archive SHA-256 values, and requires exactly one `.whl`, one `.tar.gz`, and one `.tgz`. `pypi` is an isolated GitHub-hosted `release` environment job with only `id-token: write`; it publishes exact files through the pinned PyPA action. `mirror` creates or verifies immutable `v<version>` release assets and rejects different existing bytes. `authorize-npm` re-reads desired release and current channel immediately before npm. `npm` accepts only the validated tag grammar, installs Node `24.19.0` with cache disabled, and runs the one fixed publish command. `record` submits separate provider timestamps and observed digests.

The generated Assay `.github/workflows/publish.yml` triggers only `push.tags: ["v*"]`, grants `contents: read`, `id-token: write`, and `attestations: write` to its reusable-workflow job, and passes no secrets or command inputs. Its digest is not embedded in the caller because that would create a self-referential hash. The controller uses its GitHub App to fetch `.github/workflows/publish.yml` at the authenticated source SHA, hashes the raw bytes, and compares them with the external allowlist produced by `caller_digest`. Both the caller and called workflow receive `id-token: write`; the controller checks `workflow_ref=hseshadr/assay/.github/workflows/publish.yml@<ref>` and `job_workflow_ref=hseshadr/portfolio-delivery/.github/workflows/publish-package.yml@<approved commit>` before returning `proceed`.

- [ ] **Step 4: Run GREEN and security validation**

Run: `uv run pytest tests/workflows/test_publish_package_workflow.py tests/workflows/test_assay_caller.py -q`

Run: `actionlint -shellcheck= -pyflakes= .github/workflows/publish-package.yml && uvx zizmor==1.29.0 .github/workflows/publish-package.yml`

Expected: all checks pass; tests prove no project checkout/OIDC overlap and no path can execute `dist-tag`.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/publish-package.yml templates/workflows/assay-publish-caller.yml.j2 src/portfolio_delivery/workflows/governance.py tests/workflows tests/fixtures/workflows/controller
git commit -m "feat(workflows): publish Assay packages with OIDC"
```

### Task 6: Application Candidate, Activation, Live Verification, and Recovery

**Files:**
- Create: `.github/workflows/deploy-application.yml`
- Modify: `.github/workflows/project-delivery.yml`
- Test: `tests/workflows/test_deploy_application_workflow.py`
- Test fixture: `tests/fixtures/workflows/controller/candidate-proceed.json`
- Test fixture: `tests/fixtures/workflows/controller/stale-observe.json`
- Test fixture: `tests/fixtures/workflows/controller/live-failed.json`

**Interfaces:**
- Consumes: `release_id`, `envelope_uri`, `envelope_digest`, `project_id`, `source_sha`, `production_url`; controller candidate/activation/evidence endpoints; public Dagger `verify-candidate` and `verify-live` functions.
- Produces: `candidate_url`, `candidate_deployment_id`, `production_deployment_id`, `predecessor_deployment_id`, and detached candidate/live/rollback evidence.

- [ ] **Step 1: Write failing state-order and stale-work tests**

```python
def test_activation_requires_candidate_evidence_and_fresh_authority() -> None:
    graph = load_workflow(".github/workflows/deploy-application.yml")
    assert graph.needs("activate") == {"record-candidate-evidence", "authorize-activation"}
    assert graph.needs("verify-live") == {"activate"}
    assert graph.needs("record-live") == {"verify-live"}
    assert graph.job("verify-candidate").permissions == {"contents": "read"}


def test_observe_decision_has_no_provider_write() -> None:
    run = simulate_deployment(controller_fixture="stale-observe.json")
    assert run.provider_writes == []
    assert run.controller_calls[-1].path.endswith("/reconcile")
```

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/workflows/test_deploy_application_workflow.py -q`

Expected: FAIL because `deploy-application.yml` does not exist.

- [ ] **Step 3: Implement the candidate-to-live reusable workflow**

The controller performs or authorizes provider mutations against exact OCI bytes and returns immutable candidate/production identities; project verifiers receive URLs and qualified public bytes but no provider credential. Before activation, the workflow asks the controller to re-read desired protected main and current production. `proceed` activates, `complete` verifies the existing exact digest, `observe` reconciles without writing, and `incident` fails. A failed live check calls the controller recovery endpoint with the captured predecessor. EdgeReco may use ordinary Pages rollback; AlmaMesh and AML receive a newly allocated monotonic `RecoveryId` and cannot restore an older signed artifact.

`project-delivery.yml` calls this reusable workflow only for a protected-main application event after persistence. A skipped deploy, missing URL/credential, malformed controller response, or unverified no-op fails the workflow.

- [ ] **Step 4: Run GREEN and exercise all four decisions**

Run: `uv run pytest tests/workflows/test_deploy_application_workflow.py -q`

Run: `actionlint -shellcheck= -pyflakes= .github/workflows/deploy-application.yml .github/workflows/project-delivery.yml`

Expected: all state-order, failure, rollback, and no-write observation cases pass.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/deploy-application.yml .github/workflows/project-delivery.yml tests/workflows tests/fixtures/workflows/controller
git commit -m "feat(workflows): verify and activate application candidates"
```

### Task 7: Reconciliation Schedules and Release-PR-Only Automation

**Files:**
- Create: `.github/workflows/reconcile.yml`
- Create: `.github/workflows/release-please.yml`
- Modify: `templates/workflows/application-caller.yml.j2`
- Modify: `templates/workflows/package-caller.yml.j2`
- Modify: `templates/workflows/release-please-caller.yml.j2`
- Test: `tests/workflows/test_reconcile_workflow.py`
- Test: `tests/workflows/test_release_please_workflow.py`

**Interfaces:**
- Consumes: controller `reconcile` endpoint and due `next_action_at` records; GitHub App credentials `PORTFOLIO_DELIVERY_APP_ID` and `PORTFOLIO_DELIVERY_APP_PRIVATE_KEY`; Conventional Commit squash titles.
- Produces: hourly per-repository reconciliation, 15-minute central backup reconciliation, Release Please PRs without tags/releases, and non-Dependabot bot PR auto-merge after required checks.

- [ ] **Step 1: Write failing schedule and release-authority tests**

```python
def test_release_please_cannot_create_a_tag_or_release() -> None:
    workflow = load_workflow(".github/workflows/release-please.yml")
    step = workflow.step_using("googleapis/release-please-action")
    assert step.with_values["skip-github-release"] == "true"
    assert step.with_values["skip-github-pull-request"] == "false"
    assert workflow.permissions["contents"] == "write"
    assert not workflow.has_tag_creation_command()


def test_reconciler_never_cancels_an_older_observer() -> None:
    workflow = load_workflow(".github/workflows/reconcile.yml")
    assert workflow.schedule == ["7,22,37,52 * * * *"]
    assert workflow.concurrency.cancel_in_progress is False
```

Also test that an App-authored release PR may auto-merge only when the author is the configured GitHub App, all required checks are successful, and the actor is not `dependabot[bot]`.

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/workflows/test_reconcile_workflow.py tests/workflows/test_release_please_workflow.py -q`

Expected: FAIL because both reusable workflows are absent.

- [ ] **Step 3: Implement schedules, GitHub App identity, and PR-only release automation**

The central reconciler obtains OIDC, asks the controller for due release IDs, and dispatches inspection-only reconciliation; Durable Object alarms remain the primary maturity wakeup. Generated callers retain an hourly schedule so each repository reports source/config drift. Release Please uses the pinned action and a short-lived token from pinned `actions/create-github-app-token`; the action updates manifest versions/changelogs only. The controller alone creates protected `v*` tags after the exact versioned commit is qualified. Auto-merge is enabled through the GitHub App only after repository gates complete and is hard-disabled for Dependabot.

- [ ] **Step 4: Run GREEN and lint both workflows**

Run: `uv run pytest tests/workflows/test_reconcile_workflow.py tests/workflows/test_release_please_workflow.py -q`

Run: `actionlint -shellcheck= -pyflakes= .github/workflows/reconcile.yml .github/workflows/release-please.yml`

Run: `uvx zizmor==1.29.0 .github/workflows/reconcile.yml .github/workflows/release-please.yml`

Expected: tests and workflow linters pass without findings.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/reconcile.yml .github/workflows/release-please.yml templates/workflows tests/workflows
git commit -m "feat(workflows): automate releases and reconciliation"
```

### Task 8: Workflow Conformance Gate and Hosted Shadow Proof

**Files:**
- Create: `.github/workflows/workflow-ci.yml`
- Create: `tests/workflows/test_all_workflows.py`
- Create: `tests/workflows/test_failure_injection.py`
- Create: `tests/fixtures/workflows/controller/timeout-after-dispatch.json`
- Create: `tests/fixtures/workflows/controller/conflicting-bytes.json`
- Create: `tests/fixtures/workflows/controller/out_of_order_completion.json`
- Create: `docs/workflows/README.md`

**Interfaces:**
- Consumes: every central workflow/template, generated caller fixture, controller decision fixture, and pin table.
- Produces: required `workflow-conformance` check, uploaded JSON evidence report, and a copy-pasteable shadow-run procedure that does not mutate registries or production.

- [ ] **Step 1: Write the failing cross-workflow conformance tests**

```python
def test_every_generated_and_central_workflow_passes_policy() -> None:
    violations = validate_repository(Path("."))
    assert violations == ()


@given(st.permutations(["older-qualified", "newer-qualified", "newer-live", "older-complete"]))
def test_out_of_order_completion_never_regresses_live_digest(order: list[str]) -> None:
    result = run_failure_model(order)
    assert result.live_digest != result.older_digest
    assert result.provider_write_count_by_idempotency_key.max() <= 1
```

Add explicit tests for ten retries, timeout immediately after dispatch, conflicting bytes, malformed controller JSON, empty credential, skipped job, and live verification failure. Expectations must assert provider writes and final state, not mock call existence.

- [ ] **Step 2: Run RED**

Run: `uv run pytest tests/workflows/test_all_workflows.py tests/workflows/test_failure_injection.py -q`

Expected: FAIL until repository-wide validation and failure-model fixtures are wired.

- [ ] **Step 3: Implement the required CI gate and runnable shadow guide**

`workflow-ci.yml` runs render-drift, pytest with branch coverage, Ruff, mypy, Radon, actionlint `v1.7.12`, and zizmor `1.29.0`; it uploads `workflow-evidence.json` and never receives write/OIDC permissions. `docs/workflows/README.md` starts with a TL;DR, explains the trust boundary, and provides these runnable commands:

```bash
uv sync --frozen
uv run portfolio-delivery-workflows check --root .
uv run pytest tests/workflows --cov=portfolio_delivery.workflows --cov-branch --cov-fail-under=90
dagger call -m . delivery --source=. --project-id=edge-reco --event=main \
  --source-sha="$(git rev-parse HEAD)" --attempt-id="shadow-$(git rev-parse --short HEAD)" \
  export --path=.delivery/shadow
```

The shadow command stops at a qualified local envelope. The guide separately shows how a protected hosted run records OCI/candidate evidence while the controller policy has mutations disabled.

- [ ] **Step 4: Run the complete Phase 3 quality gate**

Run: `uv run portfolio-delivery-workflows check --root .`

Run: `uv run pytest tests/workflows --cov=portfolio_delivery.workflows --cov-branch --cov-fail-under=90`

Run: `uv run ruff check src/portfolio_delivery/workflows tests/workflows && uv run mypy src/portfolio_delivery/workflows && uv run radon cc -s -a src/portfolio_delivery/workflows`

Run: `actionlint -shellcheck= -pyflakes= .github/workflows/*.yml && uvx zizmor==1.29.0 .github/workflows`

Expected: every command exits 0; branch coverage is at least 90%; all functions are Radon A; generated caller bytes have no drift; no workflow security finding remains.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/workflow-ci.yml tests/workflows tests/fixtures/workflows/controller docs/workflows/README.md
git commit -m "test(workflows): enforce delivery conformance"
```

## Phase 3 Completion Evidence

Before handing Phase 3 to migration plans, save the successful command output as `workflow-evidence.json`, run one hosted shadow qualification for Assay and one application, and verify from GitHub that the unprivileged job has no OIDC token while the privileged jobs have no project checkout. Record the OCI manifest digest, build-envelope digest, attestation URL, Dagger trace URL, controller attempt/fence, and candidate/live evidence identities. Do not call package registries or production providers until the project-specific cutover plan authorizes those mutations.
