# Portfolio Delivery Architecture

## TL;DR

Portfolio Delivery replaces copied GitHub Actions, shell-heavy release scripts,
rebuild-after-test behavior, manual approvals, manual package promotion, and
post-deploy-only verification with one extensible delivery system.

GitHub is the automatic identity and policy control plane. A version-pinned
Dagger module is the execution and artifact data plane. A pure Python release
core coordinates side effects through small contracts and composed adapters.
Each project supplies four repository-local integration files—a manifest,
composition adapter, contract fixtures, and a generated workflow caller—without
changing the shared core. The same source and declared inputs produce one
immutable artifact envelope, and that exact digest
is tested, published, deployed, promoted, and live-verified without rebuilding.

Normal delivery after protected checks requires zero human actions.

## Why This Exists

The existing projects have strong individual tests but not a coherent delivery
system. Current workflows rebuild after qualification, keep recovery artifacts
for too little time, coordinate through mutable external state, permit stale
deployments to overtake newer ones, verify only after production changes, and
require humans to version, tag, approve, wait, update downstream locks, merge,
deploy, and inspect production.

This design makes the release process itself a tested product.

## Goals

1. Build once and use the same digest for every later transition.
2. Make every transition retryable, reconcilable, and safe after interruption.
3. Eliminate routine approvals, browser logins, copied tokens, manual tags,
   manual maturity waits, manual dependency updates, and dashboard rollbacks.
4. Prevent stale or out-of-order work from changing registries or production.
5. Store every release envelope content-addressably with provenance and evidence.
6. Provide automatic candidate verification, promotion, live checks, and rollback.
7. Add a project with one manifest, one composition adapter, contract fixtures,
   and one generated workflow caller, without changing the shared core.
8. Keep project-specific product gates in their owning repositories.
9. Use the latest production-grade Dagger capabilities while pinning every tool.
10. Preserve npm/PyPI OIDC publishing, GitHub attestations, and immutable releases.

## Non-Goals

- Dagger is not the release authority, durable cross-run lock, or registry ledger.
- Dagger Cloud Engines are not required for correctness or initial production.
- The platform does not invent a new package registry or artifact file format.
- Project quality gates are not rewritten merely to look uniform.
- Dependabot pull requests are never auto-merged.

## Technology Baseline

- Python 3.13.
- Dagger engine, CLI, and Python SDK `v0.21.8`, source commit
  `7902e644beeba4468f1ea786015b4be1d6d5bbcd`.
- `dagger/dagger-for-github` `v8.4.1`, pinned to commit
  `27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77`.
- Node.js `v24.19.0` LTS for controller and workflow tooling.
- Wrangler `4.120.0` and `@cloudflare/vitest-pool-workers` `0.20.3`.
- ORAS `v1.3.3`, pinned as the multi-platform image index
  `ghcr.io/oras-project/oras@sha256:a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8`.
- `googleapis/release-please-action` `v4`, pinned to commit
  `5c625bfb5d1ff62eadeeb3772007f7f66fdcf071`.
- GitHub Actions for events, protected refs, OIDC, queued concurrency,
  attestations, deployments, and status reporting.
- GHCR generic OCI artifacts for durable,
  content-addressed envelopes.
- A SQLite-backed Cloudflare Durable Object ledger for cross-repository CAS,
  fencing, recovery, and maturity alarms.
- GitHub immutable releases for public library/package mirrors.
- npm and PyPI trusted publishing with OIDC only.
- Cloudflare APIs for candidate deployment, promotion, status, and rollback.
- OpenTelemetry emitted by Dagger and correlated with release identifiers.

The compatibility tuple pins the Dagger CLI checksum, engine image digest,
Python SDK lock hash, GitHub Action commit, ORAS image digest, and every
toolchain image digest. No workflow or module uses an unpinned `latest`. Newer Dagger releases are
adopted through a compatibility PR that runs the complete conformance suite.
Preview-only Dagger services may run in a non-blocking evaluation lane, but they
cannot become required release infrastructure until promoted to stable.

## Architectural Boundary

```text
protected GitHub event
        |
        v
thin GitHub workflow: identity, OIDC, permissions, queue, attestations
        |
        v
typed Dagger entrypoint
        |
        +--> pure Python ReleaseOrchestrator
        |       |
        |       +--> release policies and state transitions
        |       +--> composed ports
        |
        +--> unprivileged Dagger build/check/package adapters
        +--> centrally versioned GitHub/npm/PyPI/GHCR/Cloudflare adapters
        |
        v
immutable envelope digest --> candidate --> promotion --> live verification
```

GitHub YAML contains no project delivery logic. It checks out the exact source,
installs the pinned Dagger action, passes GitHub identity, invokes one typed
function, and reports the result.

The privileged publication boundary is outside project-controlled Dagger code.
Assay's local `.github/workflows/publish.yml` is a trigger-only caller containing
no shell steps; it invokes
`hseshadr/portfolio-delivery/.github/workflows/publish-package.yml@<commit>`.
The centrally pinned reusable workflow does not check out Assay source or run
package code. It restores a qualified envelope, verifies its OCI and file
digests, and publishes only those exact archives.

npm and PyPI identify the Assay-local caller workflow, so that generated file is
explicitly privileged code rather than an untrusted shim. It has no
`workflow_dispatch`, accepts no caller-provided command, and is byte-for-byte
generated from a central template. A required Portfolio Delivery GitHub App
status checks its blob digest against an allowlist stored outside Assay. CODEOWNERS
and branch rules require release-platform review for changes to that file, while
normal releases need no review. The release environment permits only protected
`v*` tags, and the tag ruleset permits creation only by the controller GitHub
App. Thus a repository writer cannot mint a trusted-publisher token merely by
retaining the expected workflow filename.

## SOLID Object Model

The domain core uses immutable dataclasses and composition. It has no dependency
on Dagger, GitHub, a registry, Cloudflare, the network, or the filesystem.

### Domain Objects

- `ProjectId`: stable project identity.
- `SourceRevision`: repository, protected ref, commit SHA, and source digest.
- `ReleaseId`: project, version, source SHA, and idempotency key.
- `RecoveryId`: project, environment, coordinator-allocated monotonic sequence,
  predecessor digest, reason, and idempotency key. It deliberately has no source
  SHA because recovery republishes previously verified content as a new release.
- `Artifact`: logical name, media type, byte size, and file SHA-256. Ordinary
  files do not claim an OCI digest.
- `BuildEnvelope`: deterministic source/toolchain/lock identities, artifacts,
  normalized SBOMs, normalized pre-publication evidence, and content digest.
- `QualificationRecord`: detached deterministic check results whose subject is
  one final build-envelope digest; it cannot change the subject bytes it proves.
- `DeliveryRecord`: detached append-only events referencing a build-envelope
  digest, including attestations, provider observations, timestamps, traces,
  deployment IDs, live checks, incidents, and rollback evidence.
- `ReleaseRecord`: desired state, observed state, completed transitions, external
  identities, timestamps, and last verified evidence.
- `DeploymentCandidate`: provider, environment, immutable artifact digest,
  deployment identifier, predecessor identifier, and source SHA.
- `RecoveryRelease`: verified predecessor content with a `RecoveryId`, sequence
  above current, fresh signature, and envelope digest.
- `Evidence`: named check, subject digest, result, timestamps, and trace link.
- `TransitionResult`: previous state, next state, observed side effects, and proof.

### Narrow Ports

- `ProjectComposition`: a wiring-only facade that composes the following narrow
  plans without implementing their behavior.
- `InputSnapshotPlan`: declares all network inputs and their immutable digests.
- `BuildPlan`: declares hermetic project build and test operations.
- `ArtifactPlan`: declares artifacts, canonicalization, SBOM, and media types.
- `ReleasePolicy`: declares versioning, registries, channels, and maturity.
- `SigningPolicy`: declares schemas, key identity, and protected signing phase.
- `DeploymentPlan`: declares provider targets and candidate semantics.
- `VerificationPlan`: declares candidate, live, privacy, and rollback evidence.
- `RecoveryPolicy`: declares ordinary rollback or monotonic recovery release.
- `Builder`: creates an envelope from an immutable source snapshot.
- `ArtifactStore`: stores and retrieves envelopes by digest without overwriting.
- `Registry`: inspects a version, publishes absent bytes, and verifies exact bytes
  and provenance.
- `Versioner`: reconciles release intent and release pull requests.
- `ReleaseLedger`: records transitions using atomic compare-and-set and fencing.
- `DeploymentProvider`: stages, inspects, promotes, and rolls back candidates.
- `Verifier`: verifies envelopes, candidates, production, and rollbacks.
- `DesiredState`: returns the authoritative protected-main/source target.
- `Clock`: supplies deterministic time and maturity calculations.
- `TraceSink`: correlates Dagger traces, GitHub runs, artifacts, and deployments.

Ports are Python `Protocol` interfaces in the pure core and Dagger `@interface`
types at module boundaries where cross-module composition is required.

### Composition Roots

The shared platform composition root wires common adapters. Each project owns a
small composition root that supplies its plans, product verifiers,
and provider configuration. No shared function switches on a project name.

Inheritance is limited to framework-required types. There are no service
locators, global mutable registries, giant base pipeline classes, or hidden
singletons.

## Dagger Module API

The pure domain types remain ordinary dataclasses. Separate Dagger DTO
`@object_type` wrappers map them to Dagger-compatible scalars, `File`,
`Directory`, and interface types. Dagger object IDs never serve as durable state;
workflow restarts use a scalar release ID plus an OCI URI and digest.

The shared Python module exposes state-bearing typed `@object_type` and
`@function` entrypoints:

- `check(source: Directory, composition: ProjectComposition) -> CheckEvidence`
- `version(source: Directory, policy: ReleasePolicy) -> ReleaseSource`
- `snapshot(release: ReleaseSource, plan: InputSnapshotPlan) -> SnapshottedSource`
- `build(source: SnapshottedSource, plan: BuildPlan) -> UnsignedBuild`
- `prequalify(build: UnsignedBuild, plan: VerificationPlan) -> PrequalifiedBuild`
- `sign(build: PrequalifiedBuild, policy: SigningPolicy) -> SignedBuild`
- `envelope(build: SignedBuild) -> BuildEnvelope`
- `qualify(envelope: BuildEnvelope, plan: VerificationPlan) -> QualifiedEnvelope`
- `publish_inputs(envelope: QualifiedEnvelope) -> File`
- `restore_qualified(release_id: str, envelope_uri: str, envelope_digest: str) -> QualifiedEnvelopeRef`
- `publish(release: QualifiedEnvelopeRef, policy: ReleasePolicy) -> ReleaseRecord`
- `deploy_candidate(release: QualifiedEnvelopeRef, plan: DeploymentPlan) -> DeploymentCandidate`
- `verify_candidate(candidate: DeploymentCandidate, plan: VerificationPlan) -> VerifiedCandidate`
- `activate(candidate: VerifiedCandidate, plan: DeploymentPlan) -> DeploymentRecord`
- `smoke(target, project) -> VerificationEvidence`
- `reconcile(release_id: str, envelope_uri: str, envelope_digest: str) -> ReleaseRecord`
- `restore_mature(release_id: str, envelope_uri: str, envelope_digest: str) -> MaturePackageReleaseRef`
- `promote_dependencies(release: MaturePackageReleaseRef) -> PromotionRecord`

The two `restore_*` functions are the only cross-run reconstruction boundaries.
They retrieve the OCI subject, verify its manifest and build-envelope digests,
confirm the required ledger `qualified` or `mature` event for that exact tuple,
and only then construct the typed reference accepted by mutation entrypoints.
`reconcile` is an internal inspect-and-record operation and cannot dispatch a
provider write. Raw URI/digest scalars are otherwise not accepted by mutation
entrypoints. Projects that need no production signature use
a centrally declared `SigningPolicy.none`; they still pass through the same typed
ordering and final-envelope qualification.

Stable `v0.21.8` entrypoints accept explicit filtered `Directory` inputs; they do
not use preview Workspace or Checks APIs. Pure and hermetic functions use
Dagger's content-addressed default caching. Functions that read mutable external
state or perform side effects use `cache="never"`. Every provider `withExec` also
receives a unique regular `attempt_id` environment input so its container layer
cannot reuse a prior mutable-state read or write. `withVolatileVariable` is not
used for this purpose. This guarantees execution, not exactly-once behavior;
every such function still performs inspect/compare/write/reinspect
reconciliation. Tests prove two identical calls cause two provider inspections.

Test databases, preview servers, and browser targets use Dagger `Service` inputs
with health checks. Cache volumes use lock/platform/tool-specific keys and
explicit `LOCKED`, `PRIVATE`, or `SHARED` modes; correctness must pass empty-cache.

Repository modules implement project-specific adapters and import the shared
module by immutable commit. Generated SDK bindings are committed and checked for
drift.

## Deterministic Build Envelope and Detached Delivery Record

Every qualified build emits one deterministic build envelope containing:

- Source repository, protected ref, commit SHA, and source tree digest.
- Project manifest and project-adapter version.
- Lockfile digests and pinned toolchain/container image digests.
- Exact deployable files and package archives.
- Artifact names, sizes, media types, and SHA-256 values.
- CycloneDX or SPDX SBOMs for each deployable artifact.
- Deterministic prequalification test, coverage, mutation, security, browser,
  parity, and benchmark evidence. Checks that consume the final signed envelope
  are stored in the detached `QualificationRecord`.
- Release policy and compatibility metadata.
- Canonical `build-envelope.v1.json` using sorted UTF-8 JSON, normalized paths,
  normalized timestamps, and an explicit versioned media type. The content digest
  is computed with digest fields absent, then written into the detached record.

Run IDs, timestamps, trace IDs, provider observations, attestations, deployments,
and live checks are excluded from the build envelope. They are append-only
delivery events whose subject is the build-envelope content digest.

The exact order is unsigned build, hermetic prequalification, privileged signing
when required, final envelope assembly, qualification of those exact final bytes,
then OCI persistence. Signing can therefore never change already-qualified
bytes. The detached `DeliveryRecord`, not the build envelope, records the returned
OCI manifest digest and later provider facts; this removes any identity cycle.
The `QualifiedEnvelope` type pairs the immutable envelope digest with its
`QualificationRecord`; final qualification evidence is never inserted back into
the envelope it verifies.

A pinned ORAS adapter creates a generic OCI artifact with fixed media types,
canonical file order, normalized metadata, and explicitly fixed compression. It
pushes under a content-derived immutable tag, captures the returned OCI manifest
digest, and re-inspects it. Dagger `Directory.digest()` and `File.digest()` are
cache/debug evidence only and never public release identities.

Mutable convenience tags may point to an envelope, but correctness never depends
on a tag. Package releases also copy exact package files to an immutable GitHub
Release.

GHCR retention is a two-pass mark-and-sweep policy. Roots are computed from the
ledger and include every current desired or observed production digest, each
deployment stream's immediate verified predecessor, every nonterminal release,
all package subjects that reached any registry, immutable release-mirror
subjects, every recovery release and its predecessor, and every open incident or
explicit legal/audit hold. Completed unrooted envelopes remain retained for at
least 90 days. An unmarked digest receives a deletion-candidate event, waits a
seven-day grace period, and is deleted only if a second independent traversal
still finds it unrooted. The collector then re-inspects GHCR and records the
provider deletion; ambiguity opens an incident rather than assuming deletion.
Published package mirrors and their manifests remain permanent.

## Durable Ledger, Fencing, and Scheduling

The production `ReleaseLedger` is a centrally deployed SQLite-backed Cloudflare
Durable Object. Release objects store evidence, but exactly one stream
coordinator owns each externally mutable target: package version,
package/channel, or project/environment. Only that coordinator may dispatch a
provider write for its target; release objects submit immutable desired-state
intents to it.

SQLite transactions atomically compare the expected record version, increment a
monotonic fencing token, record a lease deadline, and return the transition
attempt. Provider work occurs outside the transaction. Provider APIs such as npm
and Cloudflare do not consume the token, so the ledger uses a stricter dispatch
protocol:

```text
prepared -> write_dispatched -> observing -> committed | incident
```

`prepared` attempts may expire and be replaced. Immediately before the network
call, the coordinator durably records `write_dispatched`; after that point no
lease expiry or newer intent may dispatch another write to the same target.
Another worker may acquire an observer lease, but it may only inspect and
reconcile. The stream is released only after the provider proves the exact
desired state and monotonic ordering, or after a provider-specific definitive
failure proves no write escaped. A timeout, runner death, ambiguous response, or
eventual-consistency gap remains `observing` until the reconciliation horizon and
then becomes an incident; it is never treated as absence. This prevents a late
old npm tag or Pages production upload from completing after a successor.
Completion still requires the current fence, and stale callbacks are evidence
only, never authority.

When provider and ledger disagree:

- Identical provider state is imported as an observed successful transition.
- Missing or uncertain state enters `reconciling` and is re-inspected; writes are
  never assumed absent after a timeout.
- Conflicting bytes, identities, or regressed production enter `incident`, fence
  later promotion, create a GitHub incident issue, and page the configured sink.
- Ledger-complete/provider-missing state is an incident, not an automatic rewrite.

Durable Object alarms provide at-least-once maturity wakeups. Records store
`next_action_at`; the alarm dispatches the central controller through the
Portfolio Delivery GitHub App and reschedules until authoritative completion.
A periodic reconciler is a backup, not the source of timing truth.

The controller Worker authenticates GitHub Actions OIDC JWTs by issuer, audience,
repository, workflow, ref, SHA, and reusable `job_workflow_ref`. Cross-repository
GitHub operations use short-lived installation tokens from a dedicated GitHub
App, never a PAT.

## Typed State Machines

Build and qualification are common to packages and applications:

```text
discovered
  -> version_planned
  -> source_versioned
  -> inputs_snapshotted
  -> unsigned_built
  -> prequalified
  -> signed | signing_not_required
  -> final_enveloped
  -> qualified
  -> persisted
```

Packages then use:

```text
persisted
  -> python_published
  -> mirror_published
  -> npm_ready
  -> npm_published_with_channel
  -> publication_verified
  -> maturity_wait
  -> mature
  -> consumers_updated
```

Applications use an orthogonal deployment stream:

```text
persisted
  -> candidate_deployed
  -> candidate_verified
  -> production_activated
  -> live_verified
```

Publication has independent PyPI, npm-version-with-channel, attestation, and
GitHub-mirror substates. `publication_partial` can only reconcile or complete
missing unambiguous components; immutable successes are never repeated.
`failed_retryable` may return to its immediately preceding pre-dispatch state
with the same idempotency key up to the policy ceiling. `write_dispatched` and
`observing` allow inspections only. `conflict`, exhausted retries, and
`rollback_failed` enter terminal `incident`; later promotion is fenced. `degraded`
may enter `rolling_back` or `recovering`, which ends in `rolled_back`, a new
qualified recovery release, or `rollback_failed`. Incident clearance is an
append-only resolution event: automatic clearance requires exact provider-state
convergence and policy proof; otherwise the configured two-person release-admin
procedure may continue observation or record provider proof of definitive
failure, provider-side cancellation plus quiescence, or permanent target
revocation. It cannot abandon an ambiguous dispatched write or allocate a
recovery sequence on that target. Only after one of those safe terminal proofs
may the coordinator release the stream for a new write. Replay always creates a
new attempt and never erases prior evidence.

Each transition:

1. Uses an idempotency key derived from project, version, source SHA, and digest.
2. Acquires the authoritative target coordinator's CAS lease and fencing token.
   The deployment-stream coordinator alone allocates `RecoveryId.sequence` above
   the current sequence. Central GitHub queued concurrency is only an efficiency
   optimization.
3. Re-reads the desired protected source before any irreversible mutation.
4. Inspects the provider before writing.
5. Treats an identical existing result as success.
6. Treats the same identity with different bytes as a hard incident.
7. Writes once, then re-inspects and records proof.
8. Refuses promotion when a newer desired source or digest exists.

The ledger is backed up through point-in-time recovery and exportable delivery
records. It reconciles against OCI records, GitHub deployments, immutable
releases, registries, and Cloudflare state. No transition depends only on an
Actions artifact or runner-local file.

## Automatic Versioning

A pinned Release Please adapter runs in release-PR-only mode: it updates versions
and changelogs but cannot create tags or GitHub releases. The central controller
exclusively creates a tag after the versioned source is qualified. Conventional
Commit semantics are enforced on squash PR titles.

Only GitHub-App-authored, non-Dependabot PRs may enable auto-merge. The app uses
short-lived installation tokens and minimum repository permissions for contents,
pull requests, deployments, checks, actions dispatch, and issues. Required
quality and security checks apply normally. Merging the release PR creates the
release source revision and automatically invokes Dagger qualification.

Assay uses a manifest release so Python and npm versions remain one logical
release. Applications deploy every protected-main merge and do not require a
package-style version PR.

Tags are created automatically only after the exact release commit is qualified.
Registry publication never rebuilds the envelope.

## Package Publication and Maturity

Assay publication proceeds automatically:

1. Qualify and persist the exact envelope.
2. Attest the envelope and package subjects in GitHub.
3. Export exact verified package files and checksums to the centrally pinned
   reusable publication workflow called by Assay's generated, privileged
   `publish.yml`.
   Its unprivileged verifier job has no OIDC permission. A final isolated job,
   after verification succeeds, receives `id-token: write`, no checkout, no
   project dependencies, and the minimum provider permissions. Trusted-publisher
   Provider configuration binds the caller repository, local workflow filename,
   protected release environment, and audience. The controller additionally
   verifies protected ref and SHA,
   `workflow_ref=hseshadr/assay/.github/workflows/publish.yml@<ref>`, and
   `job_workflow_ref=hseshadr/portfolio-delivery/.github/workflows/publish-package.yml@<commit>`.
   PyPI receives only the wheel and sdist. The later npm job receives only the
   reviewed tarball. Project Dagger code receives no OIDC request context or
   registry credential.
4. Reconcile identical already-published bytes as success.
5. Reject conflicts for an existing version.
6. Create and verify an immutable GitHub release mirror before npm publication.
7. Treat npm as the final publication mutation. Immediately before its isolated
   OIDC step, re-read the authoritative desired release and current channel. A
   desired prerelease publishes once with `--tag next`; a desired stable release
   publishes once with `--tag latest`. An older retry publishes with a
   version-derived non-channel tag and never moves a channel backward. npm
   trusted publishing authenticates this `npm publish` operation. The fixed
   command is:

   ```bash
   npm publish <archive> --tag <selected-tag> --ignore-scripts --provenance --access public
   ```

   The platform never calls `npm dist-tag` and needs no registry token. The package/channel
   coordinator is the sole supported writer. Any observed concurrent external
   channel mutation fails final verification and opens an incident; normal
   automation does not race an independent writer.
8. Record separate authoritative registry publication timestamps.
9. Set the ledger alarm for the maximum required maturity time plus safety margin.
10. Re-verify bytes and provenance when maturity opens.
11. Generate exact-version consumer lock updates, open bot PRs, and enable
    auto-merge only after each repository's complete gates pass.

No maturity exclusion is added. No browser approval, token copy, or manual rerun
is part of the normal path.

PR qualification uses fixture or keyless signing only. After protected main is
prequalified, an isolated centrally versioned signing adapter validates the
declared payload schema and mounts the production key as an ephemeral secret
file. It creates the only production-signed bytes once; the final envelope is
then qualified, persisted, and consumed unchanged by candidate and production
checks. Project-controlled source never executes with the key.

## Deployment, Promotion, and Rollback

Each application deploys the exact OCI envelope:

1. Direct-upload exact extracted envelope bytes to a unique Cloudflare Pages
   preview branch and verify the returned immutable deployment URL. Workers use
   version upload and an immutable version identifier.
2. Run project-specific candidate verification.
3. Re-read desired protected main and current production.
4. For Pages, direct-upload the same extracted bytes to production; this is a
   second provider deployment but never a rebuild. Workers promote the verified
   version. Promote only if the candidate remains desired.
5. Run full public-domain live verification.
6. Ordinary Pages rollback calls the API with the captured prior successful
   production deployment ID. On failure, verify the rollback.
7. Mark success only when the desired digest is demonstrably live.

An absent credential, skipped job, or unresolved desired state is a failure. A
no-op succeeds only after proving the exact desired digest is already live.

Rollback is project-specific. AlmaMesh and AML Filter never restore an older
signed artifact. Their `RecoveryPolicy` creates a new `RecoveryRelease` by
re-signing verified predecessor content under a sequence higher than current,
qualifying it as a new immutable envelope, deploying it, and verifying it.

## Project Adapters

### Assay

- Python and npm parity, full mutation gates, resource and packaging contracts.
- One Python/npm release identity and exact registry provenance.
- Immutable GitHub package mirror.

### EdgeReco

- Backend and frontend gates, catalog/model integrity, offline/PWA behavior,
  Assay replay, Avow verification, browser console/network, and real storefront.
- Candidate and production verification bind build identity and catalog digest.

### AlmaMesh

- Backend/frontend, CPython parity, signed bundle sequence, privacy/no-egress,
  multilingual UI, onboarding, offline, Assay/Avow evidence, and PDF geometry.
- Rollback re-releases compatible content under a new valid sequence when needed.

### AML Filter

- Application and watchlist pipelines are independent immutable streams.
- App envelopes reference an exact signed watchlist digest.
- Screening/KYC, C1, mobile, receipt/tamper, decision parity, source freshness,
  bundle integrity, and privacy checks remain mandatory.

## Adding Another Lego

A new project adds, without changing the shared core:

1. `portfolio-delivery.toml` with identity, release policy, artifact declarations,
   maturity rules, environments, URLs, and evidence requirements.
2. A small typed composition module implementing only the narrow project plans.
3. Contract fixtures for success, retry, conflict, stale work, rollback, and
   live-check failure.
4. A thin GitHub workflow that invokes the pinned shared module.

The shared orchestrator is closed for modification but open to new adapters.

All mutable upstream build inputs are snapshot releases before the deterministic
build begins. AlmaMesh runtime assets and AML source feeds receive canonical
bytes, source timestamps, provenance, digest, retention, and compatibility
metadata. App envelopes reference snapshot digests, never mutable URLs.

## Testing Strategy

### Pure Core

- Unit tests for every transition and policy branch.
- Property tests for idempotency, monotonicity, and stale-work rejection.
- Mutation tests for safety decisions.
- Deterministic fake clock and provider states.

### Adapter Conformance

Every adapter runs the same suite:

- Absent, identical, and conflicting external state.
- Failure immediately before and after every write, including lease expiry and
  stale-fence completion.
- Ten identical retries without duplicate effects.
- Timeout, malformed response, oversized response, and unavailable provider.
- A/B completion inversion where older work must not win.
- Process restart from every state.
- Rollback success, rollback failure, and rollback verification failure.

### Dagger Integration

- Hermetic toolchain and dependency setup.
- Cache-hit and selective invalidation assertions.
- Ephemeral service health checks.
- Exact envelope byte/digest reproducibility from independent engines.
- Secret redaction and non-persistence. Production signing keys are mounted only
  as ephemeral typed Dagger secret files in centrally reviewed adapters; plaintext
  never enters scalar arguments, source checkout, cache, exported artifacts,
  envelopes, or logs.
- OpenTelemetry correlation.

### Hosted and Production

- Shadow runs compare existing and Dagger outputs before cutover.
- Provider sandbox or preview deploys prove adapter behavior.
- Production rollout is one repository at a time.
- Automated rollback drills are required before declaring each migration done.

## GitHub Control Plane

Every repository has a minimal workflow that:

1. Triggers on protected pull request, protected main, release, or scheduled
   reconciliation events.
2. Uses pinned actions and toolchain/container image digests. GitHub-hosted runner
   images are treated as mutable and kept outside the trusted build boundary.
3. Grants the minimum permissions for that job.
4. Uses queued concurrency and a project/environment key as an optimization; the
   Durable Object fence remains authoritative across repositories.
5. Invokes the pinned Dagger function.
6. Creates GitHub attestations from the returned checksums.
7. Records deployment and release status.

The central controller rechecks desired state before promotion. Security and
dependency audits are required checks in all repositories. Missing required
configuration fails closed.

## Observability

Every transition carries one correlation identifier across:

- Dagger OpenTelemetry traces.
- GitHub workflow run, check, attestation, release, and deployment records.
- OCI envelope annotations.
- npm/PyPI publication metadata.
- Cloudflare candidate, promotion, and rollback identifiers.
- Public build identity endpoints.

A final production evidence record answers: what source, what dependencies, what
artifact digest, what tests, what publisher identity, what deployment, what live
checks, and what rollback target produced the currently served system.

## Security Model

- OIDC-only package publication; no long-lived registry publish tokens.
- Least-privilege provider tokens restricted to exact projects and operations.
- Dagger `Secret` references may be typed arguments and ephemeral secret files;
  secret plaintext never enters scalar arguments, source, cache, envelopes, or logs.
- Unprivileged project-source build/test adapters never receive production
  credentials. Privileged signing/publish/deploy adapters are centrally versioned,
  accept only qualified immutable envelopes plus declarative policy, and never
  execute project-source commands.
- Pinned actions, Dagger modules, SDKs, toolchains, and container image digests.
- Protected release-bot identity and explicit rejection of Dependabot auto-merge.
- Attestations bind source repository, workflow, ref, SHA, and artifact digest.
- Immutable releases and compare-before-write prevent silent replacement.
- External responses are time- and size-bounded and parsed fail-closed.

## Efficiency Model

- Dagger content-addressed layers, volumes, and pure function results avoid
  repeated dependency installation and unaffected gates.
- Explicit `Directory` inputs use stable include/exclude filters so only required
  source paths enter the graph.
- Independent gates execute in parallel; side effects remain ordered.
- Qualification builds one envelope; no downstream stage rebuilds.
- Cache effectiveness and total critical-path time are measured and budgeted.

Caching is an optimization only. Correctness never depends on cache retention.

## Migration Sequence

1. Build the pure core, adapter contracts, fakes, conformance suite, and Dagger
   module in `portfolio-delivery`.
2. Migrate Assay qualification in shadow mode and prove exact artifact parity.
3. Cut Assay release control to the new pipeline and delete special-case recovery.
4. Migrate EdgeReco build/candidate/live flow, then verify production rollback.
5. Migrate AlmaMesh with monotonic sequence-aware rollback.
6. Split AML watchlist/app streams and migrate both.
7. Enable automatic Assay maturity promotion and consumer PR auto-merge.
8. Remove superseded scripts, duplicated YAML, unused secrets, and manual docs.
9. Run full release, interruption, stale-run, rollback, and live-verification drills.

Each migration is independently deployable and reversible until its final legacy
cleanup commit.

## Acceptance Criteria

1. Zero human action is required after a protected merge during normal delivery.
2. Qualification, publication, deployment, and verification use one deterministic
   build-envelope content digest and its captured OCI manifest digest.
3. Repeating every transition ten times creates no duplicate external effect.
4. Restarting after every transition reconstructs and resumes state automatically.
5. Out-of-order runs never move a registry channel or production backward.
6. Inactive envelopes are durable for at least 90 days; current, rollback,
   recovery, and published subjects are retained by policy; public mirrors are immutable.
7. Every envelope includes source, locks, toolchains, SBOM, evidence, and provenance.
8. npm and PyPI use trusted OIDC only and reconcile exact bytes.
9. Maturity promotion occurs automatically without exclusions.
10. Only release-bot, non-Dependabot PRs can auto-merge after all required checks.
11. Every app stages, verifies, promotes, live-verifies, and rolls back automatically.
12. A skipped deploy cannot be reported as successful.
13. AML app/watchlist and AlmaMesh sequence invariants survive retries and rollback.
14. Live evidence binds the exact Assay versions, app source, artifact, and data.
15. No workflow uses mutable tools, long-lived registry tokens, or manual versions.
16. A fifth lego can be onboarded without modifying the shared orchestrator.
17. The shared module and every adapter pass unit, property, mutation, conformance,
    integration, failure-injection, and hosted shadow tests.
18. All four production applications are deployed and live-verified on the new path.
19. Durable Object CAS/fencing tests reject stale completions across repositories,
    and alarm tests prove at-least-once maturity reconciliation.
20. Deterministic build envelopes contain no clock, trace, run, provider, or
    attestation fields; detached delivery records bind those facts to the subject.
21. Privileged OIDC/signing/deployment jobs execute only centrally pinned code
    against qualified immutable envelopes and never execute project source.
22. Pages previews use immutable deployment URLs, production receives the same
    extracted bytes, and rollback or recovery releases are provider-accurate.

## Rollout Safety

The existing delivery path remains available while each new path runs in shadow.
Cutover occurs only when exact outputs and evidence agree or deliberate differences
are reviewed. After cutover, legacy paths are disabled before deletion, and a full
release plus rollback drill proves the new path. Provider-side state and production
identity are independently inspected before declaring completion.

## Official References

- Dagger: <https://docs.dagger.io/>
- Dagger stable release: <https://github.com/dagger/dagger/releases/tag/v0.21.8>
- Dagger Python SDK: <https://dagger-io.readthedocs.io/en/sdk-python-v0.21.8/>
- Dagger GitHub Actions: <https://docs.dagger.io/adopting/triggers/github-actions/>
- Dagger caching: <https://docs.dagger.io/features/caching/>
- Dagger function caching: <https://docs.dagger.io/extending/function-caching/>
- GitHub reusable workflows: <https://docs.github.com/en/actions/concepts/workflows-and-actions/reusing-workflow-configurations>
- GitHub concurrency: <https://docs.github.com/en/actions/concepts/workflows-and-actions/concurrency>
- GitHub artifact attestations: <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations>
- GitHub immutable releases: <https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases>
- Release Please: <https://github.com/googleapis/release-please-action>
- Cloudflare CI/CD: <https://developers.cloudflare.com/workers/ci-cd/>
- Cloudflare SQLite Durable Objects: <https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/>
- Cloudflare Durable Object alarms: <https://developers.cloudflare.com/durable-objects/api/alarms/>
- GitHub reusable-workflow OIDC claims: <https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows>
- GitHub App authentication: <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app>
