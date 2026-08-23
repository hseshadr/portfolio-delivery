# Portfolio Delivery Controller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy the authenticated Cloudflare Worker control plane whose SQLite Durable Objects serialize release transitions, authorize at most one provider write per mutable target, reconcile ambiguous outcomes, schedule maturity work, and safely collect unrooted OCI envelopes.

**Architecture:** The Worker is a thin authenticated HTTP adapter over three coordination atoms: one `ReleaseLedger` Durable Object per project, one `TargetCoordinator` per externally mutable target, and one low-throughput `PortfolioCatalog` for active-release discovery and retention marks. Domain state machines and services are pure TypeScript objects; Durable Objects compose them with synchronous SQLite repositories, while GitHub/OIDC/GHCR interactions sit behind narrow ports. External provider writes remain in centrally pinned GitHub workflows: the coordinator grants a fresh attempt exactly one `WRITE_ONCE` response, and every retry or takeover becomes observer-only.

**Tech Stack:** Node.js 24.19.0 LTS, TypeScript 7.0.2, Cloudflare Workers, SQLite Durable Objects, Wrangler 4.120.0, `@cloudflare/vitest-pool-workers` 0.20.3, Vitest 4.1.11, fast-check 4.9.0, Zod 4.4.3, jose 6.2.10, ESLint 10.9.0, Prettier 3.9.6, Stryker 10.0.0, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-22-portfolio-delivery-design.md`

## Global Constraints

- Keep Python 3.13 and Dagger engine, CLI, and Python SDK `v0.21.8` intact at the controller boundary.
- Use Node.js `v24.19.0` LTS, Wrangler `4.120.0`, and `@cloudflare/vitest-pool-workers` `0.20.3`; these are one reviewed compatibility tuple even though a newer Cloudflare test plugin exists.
- Keep `dagger/dagger-for-github` pinned to `27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77` and ORAS `v1.3.3` pinned to `ghcr.io/oras-project/oras@sha256:a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8` in callers that interact with this controller.
- Keep `googleapis/release-please-action` pinned to `5c625bfb5d1ff62eadeeb3772007f7f66fdcf071`; the controller alone authorizes tags and subsequent mutations.
- Use SQLite Durable Object classes declared with `new_sqlite_classes`; track application schema in `_sql_schema_migrations`, because `PRAGMA user_version` is unsupported.
- Route DOs by coordination atom: `ReleaseLedger` by project ID and `TargetCoordinator` by canonical target key. `PortfolioCatalog` is only the low-volume global index/retention coordinator, never the release mutation hot path.
- Use public typed RPC methods on DO stubs. Use `blockConcurrencyWhile()` only for schema initialization and never across network I/O.
- Perform related SQLite reads/writes synchronously with parameter bindings and no intervening `await`; provider work always happens outside storage transactions.
- No provider accepts the fence token, so `write_dispatched` is a durable point of no return. Once set, no expired lease, successor, retry, or restarted runner may receive another write authorization for that target.
- A lost `WRITE_ONCE` response is ambiguous and therefore observer-only on retry. Identical provider state commits; conflicting or unresolved state opens an incident.
- Authenticate every mutation with GitHub Actions OIDC and validate issuer, audience, expiry, repository, workflow, protected ref, SHA, and reusable `job_workflow_ref`/`job_workflow_sha` against exact policy. Use GitHub App installation tokens for outgoing GitHub operations; never accept or store a PAT.
- Store no plaintext secret, bearer token, private key, or provider credential in SQLite, logs, test snapshots, response bodies, or request scalar evidence.
- Retain unrooted completed envelopes for at least 90 days, then require two independent unrooted traversals separated by seven days before issuing a deletion authorization. Permanent package mirrors are never eligible.
- Treat alarms as at-least-once notifications. Alarm handlers dispatch idempotent central reconciliation workflows and reschedule on failure; they never perform a package/channel/deployment write.
- Red -> green -> refactor for every behavior. A test must fail for the intended missing behavior before production code is written.
- Use strict TypeScript, immutable `readonly` records, discriminated unions, constructor injection, narrow interfaces, structured logs, and no unvalidated `unknown` values beyond boundary parsers.
- Every task ends with focused tests and one reviewable commit. Never merge Dependabot pull requests.

## File Structure

```text
controller/
  package.json                         pinned tooling and quality commands
  package-lock.json                    exact npm dependency graph
  tsconfig.json                        strict Worker/domain compilation
  vitest.config.ts                     Workers-runtime integration configuration
  vitest.domain.config.ts              fast pure-domain/property test configuration
  stryker.config.json                  mutation gate for safety decisions
  eslint.config.mjs                    type-aware lint policy
  .prettierrc.json                     deterministic formatting
  wrangler.jsonc                       Worker, DO bindings, SQLite migration, observability
  openapi.v1.json                      machine-readable authenticated controller API
  README.md                            runnable local/controller quickstart
  src/
    index.ts                           Worker entrypoint and DO exports
    env.ts                             binding/config contract and fail-closed parsing
    domain/
      model.ts                         immutable release, attempt, observation, and retention types
      errors.ts                        concrete domain errors and HTTP translation codes
      release-machine.ts               package/application release transition policy
      attempt-machine.ts               dispatch/observation/incident transition policy
      canonical.ts                     canonical JSON and SHA-256 helpers
      retention-policy.ts              pure root and mark/sweep decisions
    ports/
      clock.ts                         deterministic time contract
      github.ts                        desired-state, token, dispatch, and incident ports
      catalog.ts                       inventory/deletion observation contracts
      telemetry.ts                     structured transition event contract
    storage/
      migrations.ts                    idempotent schema migrations for all three DO classes
      release-repository.ts            release CAS, events, evidence, schedules, export
      target-repository.ts             target fence, attempt, observer lease, recovery sequence
      catalog-repository.ts            active releases, root claims, sweeps, deletion candidates
    services/
      release-service.ts               safe root-registration and append orchestration
      target-service.ts                prepare, authorize-once, observe, and recover orchestration
      scheduler-service.ts             due-action claiming and GitHub dispatch reconciliation
      retention-collector.ts           two-pass mark/sweep and deletion confirmation
      incident-service.ts              idempotent fencing, evidence, GitHub issue dispatch
    auth/
      claims.ts                        strict GitHub OIDC claim schema and caller policy
      oidc-authenticator.ts             jose verification and claim authorization
      github-app.ts                    short-lived installation token adapter
    api/
      schemas.ts                       strict Zod request/response schemas
      router.ts                        authenticated route dispatch and error mapping
      controller.ts                    DO composition and cross-DO safety ordering
    durable/
      release-ledger.ts                project-scoped release RPC and maturity alarm
      target-coordinator.ts            target-scoped dispatch RPC and reconcile alarm
      portfolio-catalog.ts             active index and retention RPC/alarm
  policy/
    callers.v1.json                    exact repository/workflow/ref allowlist
  test/
    tsconfig.json                      Workers test runtime types
    support/
      builders.ts                      literal immutable record builders
      fake-clock.ts                    deterministic test clock
      github-fixture.ts                complete GitHub API response fixture server
      oidc-fixture.ts                  ephemeral key/JWT fixture
      failure-injector.ts              named crash boundaries used by conformance tests
    domain/
      release-machine.test.ts
      attempt-machine.test.ts
      retention-policy.test.ts
    integration/
      release-ledger.test.ts
      target-coordinator.test.ts
      dispatch-races.test.ts
      alarms.test.ts
      auth.test.ts
      github-app.test.ts
      http-api.test.ts
      retention-collector.test.ts
      controller-conformance.test.ts
  contracts/
    controller-conformance.v1.json     literal scenario inputs and expected outcomes
  scripts/
    verify-openapi.ts                  executable API/schema drift gate
    smoke-controller.ts                authenticated deployed health/status check
docs/
  controller-operations.md             deployment, incident, backup/export, recovery runbook
.github/workflows/
  controller-ci.yml                    pinned controller quality/conformance gate
  controller-deploy.yml                automatic central Worker deployment and smoke check
  reconcile.yml                        GitHub-App-dispatched idempotent observer workflow
```

The implementation deliberately keeps `ReleaseLedger`, `TargetCoordinator`, and `PortfolioCatalog` repositories separate. A worker changing release-state rules does not need to understand SQL, auth, GitHub token creation, or GHCR inventory shape, and a fifth project changes only policy/manifests rather than shared control flow.

---

### Task 1: Bootstrap the strict controller package and pure state machines

**Files:**
- Create: `controller/package.json`
- Create: `controller/package-lock.json`
- Create: `controller/tsconfig.json`
- Create: `controller/vitest.config.ts`
- Create: `controller/vitest.domain.config.ts`
- Create: `controller/eslint.config.mjs`
- Create: `controller/.prettierrc.json`
- Create: `controller/src/domain/model.ts`
- Create: `controller/src/domain/errors.ts`
- Create: `controller/src/domain/release-machine.ts`
- Create: `controller/src/domain/attempt-machine.ts`
- Create: `controller/test/domain/release-machine.test.ts`
- Create: `controller/test/domain/attempt-machine.test.ts`

**Interfaces:**
- Produces: `ReleaseMachine.transition(snapshot: ReleaseSnapshot, command: ReleaseTransition): ReleaseSnapshot`
- Produces: `AttemptMachine.apply(snapshot: TargetSnapshot, command: AttemptCommand): AttemptDecision`
- Produces: `ReleaseState`, `AttemptState`, `ProviderObservation`, `ReleaseSnapshot`, `TargetSnapshot`, and the concrete errors consumed by every later task.

- [ ] **Step 1: Add the pinned test/tool configuration and failing state-machine tests**

Create `package.json` with exact dependencies and scripts:

```json
{
  "name": "@hseshadr/portfolio-delivery-controller",
  "private": true,
  "type": "module",
  "engines": { "node": "24.19.0" },
  "packageManager": "npm@11.17.0",
  "scripts": {
    "types": "wrangler types src/worker-configuration.d.ts",
    "test": "vitest run --coverage",
    "test:domain": "vitest run --config vitest.domain.config.ts",
    "test:mutation": "stryker run",
    "typecheck": "tsc --noEmit",
    "lint": "eslint . --max-warnings 0",
    "format": "prettier --write .",
    "format:check": "prettier --check .",
    "check": "npm run types && npm run format:check && npm run lint && npm run typecheck && npm test"
  },
  "dependencies": {
    "jose": "6.2.10",
    "zod": "4.4.3"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "0.20.3",
    "@eslint/js": "10.0.1",
    "@stryker-mutator/core": "10.0.0",
    "@stryker-mutator/vitest-runner": "10.0.0",
    "@types/node": "24.10.1",
    "@vitest/coverage-v8": "4.1.11",
    "eslint": "10.9.0",
    "fast-check": "4.9.0",
    "prettier": "3.9.6",
    "tsx": "4.23.12",
    "typescript": "7.0.2",
    "typescript-eslint": "8.67.0",
    "vitest": "4.1.11",
    "wrangler": "4.120.0"
  }
}
```

Use `defineWorkersConfig` from `@cloudflare/vitest-pool-workers/config` in `vitest.config.ts`; use ordinary `defineConfig` with Node environment for pure-domain tests. Set branch/function/line/statement thresholds to 90 in the Workers config. In the first tests, use literal records and assert these breaks:

```ts
it("rejects candidate deployment before persistence", () => {
  const snapshot = releaseSnapshot({ state: "qualified", recordVersion: 8 });
  expect(() => machine.transition(snapshot, transition("candidate_deployed", 8)))
    .toThrowError(InvalidReleaseTransition);
});

it("returns observer-only when dispatch authorization is replayed", () => {
  const dispatched = targetSnapshot({ attemptState: "write_dispatched", fence: 11 });
  expect(machine.apply(dispatched, authorize({ fence: 11 }))).toEqual({
    kind: "OBSERVE_ONLY",
    reason: "already_dispatched"
  });
});
```

- [ ] **Step 2: Run the focused tests and verify the intended failure**

Run: `cd controller && npm install --package-lock-only && npm install && npm run test:domain`

Expected: FAIL because `ReleaseMachine`, `AttemptMachine`, and their immutable input types do not exist.

- [ ] **Step 3: Implement the minimal immutable types and transition tables**

Define exact discriminated states in `model.ts`:

```ts
export type ReleaseState =
  | "discovered" | "version_planned" | "source_versioned" | "inputs_snapshotted"
  | "unsigned_built" | "prequalified" | "signed" | "signing_not_required"
  | "final_enveloped" | "qualified" | "persisted"
  | "versions_published" | "mirror_published" | "publication_verified"
  | "maturity_wait" | "mature" | "channels_promoted" | "consumers_updated"
  | "candidate_deployed" | "candidate_verified" | "production_activated" | "live_verified"
  | "publication_partial" | "failed_retryable" | "degraded" | "rolling_back"
  | "recovering" | "rolled_back" | "conflict" | "incident" | "rollback_failed";

export type AttemptState =
  | "idle" | "prepared" | "write_dispatched" | "observing"
  | "committed" | "definitive_failure" | "incident";

export type ProviderObservation =
  | Readonly<{ kind: "absent"; proofDigest: string }>
  | Readonly<{ kind: "identical"; digest: string; providerId: string; proofDigest: string }>
  | Readonly<{ kind: "conflict"; digest: string; providerId: string; proofDigest: string }>
  | Readonly<{ kind: "uncertain"; detailCode: string; proofDigest: string }>
  | Readonly<{ kind: "definitive_failure"; detailCode: string; proofDigest: string }>;

export type PublicationComponentState = "pending" | "dispatched" | "verified" | "conflict";

export type PublicationStatus = Readonly<{
  pypi: PublicationComponentState;
  npmVersion: PublicationComponentState;
  npmChannel: PublicationComponentState;
  attestation: PublicationComponentState;
  githubMirror: PublicationComponentState;
}>;

export type IncidentResolution =
  | Readonly<{ kind: "automatic"; providerProofDigest: string; policyProofDigest: string }>
  | Readonly<{ kind: "release_admin"; decision: "reconcile" | "abandon" | "recover";
      firstActorId: string; secondActorId: string; rationale: string }>;
```

Use frozen transition maps with separate package and application lanes. Both `signed` and `signing_not_required` may advance to `final_enveloped`; only `persisted` may enter package or application lanes. `failed_retryable` stores and returns only to its recorded `resumeState`. `conflict`, `incident`, and `rollback_failed` are terminal until an explicit append-only resolution command.

`ReleaseSnapshot` embeds `PublicationStatus`; immutable component successes never reset or repeat. `publication_partial` may advance only an unverified component, and `channels_promoted` requires all five components verified. Automatic incident clearance requires exact provider/policy proofs; an administrator decision requires two distinct configured actor IDs.

In `AttemptMachine`, only `prepared + absent + matching current fence` returns `WRITE_ONCE`; `prepared + identical` returns `COMMIT_IDENTICAL`; replay after `write_dispatched` returns `OBSERVE_ONLY`; conflict returns `OPEN_INCIDENT`; uncertain returns `OBSERVE_ONLY`; definitive failure releases the stream without claiming provider success.

- [ ] **Step 4: Add edge-path tests, refactor, and run the domain gate**

Add tests for both signing branches, package/application lane separation, resume-state validation, terminal incidents, stale fences, identical pre-existing provider state, and conflicting bytes. Run:

`cd controller && npm run test:domain && npm run typecheck && npm run lint`

Expected: all domain tests pass; strict compilation and lint pass.

- [ ] **Step 5: Commit**

```bash
git add controller/package.json controller/package-lock.json controller/tsconfig.json controller/vitest.config.ts controller/vitest.domain.config.ts controller/eslint.config.mjs controller/.prettierrc.json controller/src/domain controller/test/domain
git commit -m "feat(controller): define release and dispatch state machines"
```

### Task 2: Add canonical identities and SQLite schema migrations

**Files:**
- Create: `controller/src/domain/canonical.ts`
- Create: `controller/src/storage/migrations.ts`
- Create: `controller/src/durable/release-ledger.ts`
- Create: `controller/src/durable/target-coordinator.ts`
- Create: `controller/src/durable/portfolio-catalog.ts`
- Create: `controller/src/index.ts`
- Create: `controller/src/env.ts`
- Create: `controller/wrangler.jsonc`
- Create: `controller/test/integration/migrations.test.ts`
- Create: `controller/test/tsconfig.json`

**Interfaces:**
- Consumes: domain identifiers and states from Task 1.
- Produces: `canonicalJson(value: JsonValue): string`, `sha256(value: string): Promise<string>`, `migrateReleaseLedger(sql)`, `migrateTargetCoordinator(sql)`, and `migratePortfolioCatalog(sql)`.

- [ ] **Step 1: Write failing migration and canonicalization tests**

Test that two differently ordered input objects produce the same canonical bytes/digest, all dynamic SQL values use bound parameters, schema initialization is idempotent, and each DO receives isolated SQLite storage. Use `runInDurableObject` to assert exact table names and columns. The release schema must include `release_records`, `release_events`, `evidence`, and `scheduled_actions`; target schema must include `target_records` and `attempt_events`; catalog schema must include `active_releases`, `root_claims`, `sweeps`, `deletion_candidates`, and `incidents`.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/migrations.test.ts`

Expected: FAIL because Wrangler bindings and migrations do not exist.

- [ ] **Step 3: Add exact DO bindings and the v1 SQLite migration**

Create `wrangler.jsonc` with compatibility date `2026-08-22`, observability enabled, and these bindings/migration:

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "portfolio-delivery-controller",
  "main": "src/index.ts",
  "compatibility_date": "2026-08-22",
  "observability": { "enabled": true },
  "durable_objects": {
    "bindings": [
      { "name": "RELEASE_LEDGER", "class_name": "ReleaseLedger" },
      { "name": "TARGET_COORDINATOR", "class_name": "TargetCoordinator" },
      { "name": "PORTFOLIO_CATALOG", "class_name": "PortfolioCatalog" }
    ]
  },
  "migrations": [
    { "tag": "v1", "new_sqlite_classes": ["ReleaseLedger", "TargetCoordinator", "PortfolioCatalog"] }
  ]
}
```

Each DO constructor calls `ctx.blockConcurrencyWhile(async () => migrateX(ctx.storage.sql))` and does nothing else inside the critical section. `migrations.ts` creates `_sql_schema_migrations`, checks `MAX(id)`, creates tables/indexes with `NOT NULL`, `CHECK`, and uniqueness constraints, then inserts migration ID 1 in the same synchronous SQL batch.

Use `RELEASE_LEDGER.getByName(projectId)`, `TARGET_COORDINATOR.getByName(targetKey)`, and `PORTFOLIO_CATALOG.getByName("portfolio-v1")`; never persist or expose raw DO IDs.

- [ ] **Step 4: Generate binding types and run integration/type gates**

Run: `cd controller && npm run types && npx vitest run test/integration/migrations.test.ts && npm run typecheck`

Expected: generated `src/worker-configuration.d.ts` is stable, migration tests pass twice against the same objects, and strict typecheck passes.

- [ ] **Step 5: Commit**

```bash
git add controller/src controller/test/integration/migrations.test.ts controller/test/tsconfig.json controller/wrangler.jsonc
git commit -m "feat(controller): add SQLite Durable Object schema"
```

### Task 3: Implement the append-only project release ledger

**Files:**
- Create: `controller/src/storage/release-repository.ts`
- Create: `controller/src/services/release-service.ts`
- Modify: `controller/src/durable/release-ledger.ts`
- Create: `controller/test/integration/release-ledger.test.ts`

**Interfaces:**
- Consumes: `ReleaseMachine`, canonical request hashes, and `ReleaseLedger` SQLite schema.
- Produces: `ReleaseLedger.init(input)`, `append(input)`, `recordEvidence(input)`, `snapshot(releaseId)`, `listNonterminal(cursor, limit)`, and `exportEvents(releaseId, afterSequence, limit)` RPC methods.

- [ ] **Step 1: Write failing CAS, replay, evidence, and export tests**

Cover literal behaviors:

```ts
it("returns the stored transition when an identical idempotency key is replayed", async () => {
  const first = await ledger.append(appendInput({ expectedVersion: 0, idempotencyKey: "release:a:1" }));
  const replay = await ledger.append(appendInput({ expectedVersion: 0, idempotencyKey: "release:a:1" }));
  expect(replay).toEqual(first);
  expect((await ledger.exportEvents("assay:1.0.0", 0, 100)).events).toHaveLength(1);
});

it("rejects a reused key whose canonical request differs", async () => {
  await ledger.append(appendInput({ idempotencyKey: "release:a:1", nextState: "qualified" }));
  await expect(ledger.append(appendInput({ idempotencyKey: "release:a:1", nextState: "persisted" })))
    .rejects.toThrowError(IdempotencyConflict);
});
```

Also test stale `expectedVersion`, wrong project/release routing, evidence subject mismatch, duplicate evidence equality, conflicting evidence, pagination, and a complete JSONL export whose event sequence is gap-free.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/release-ledger.test.ts`

Expected: FAIL because the ledger RPC methods and SQL repository are absent.

- [ ] **Step 3: Implement synchronous repository CAS and append-only evidence**

Define `SqlReleaseRepository.append` to:

1. canonicalize and hash the command before touching storage;
2. return the stored result only when idempotency key and request hash both match;
3. read the current record and enforce `expectedVersion`;
4. call `ReleaseMachine.transition`;
5. update `release_records` with `WHERE record_version = ?`;
6. insert one immutable `release_events` row with the next sequence;
7. assert the update count is one and return the newly stored snapshot.

All steps from 3 through 6 use synchronous `sql.exec` calls without `await`. Store event/evidence canonical JSON plus SHA-256. `exportEvents` returns bounded pages of 100 records and a cursor; it never returns secrets or raw auth headers.

- [ ] **Step 4: Verify crash/restart reconstruction and full focused gate**

Instantiate a fresh `ReleaseService` over the same SQL repository after every legal state and prove `snapshot` plus `exportEvents` reconstruct identical state without class-memory fields. Run:

`cd controller && npx vitest run test/integration/release-ledger.test.ts --coverage && npm run typecheck`

Expected: all release ledger tests pass and touched lines/branches are at least 90% covered.

- [ ] **Step 5: Commit**

```bash
git add controller/src/storage/release-repository.ts controller/src/services/release-service.ts controller/src/durable/release-ledger.ts controller/test/integration/release-ledger.test.ts
git commit -m "feat(controller): persist append-only release transitions"
```

### Task 4: Implement target CAS, leases, fencing, and recovery sequences

**Files:**
- Create: `controller/src/storage/target-repository.ts`
- Create: `controller/src/services/target-service.ts`
- Create: `controller/src/ports/clock.ts`
- Modify: `controller/src/durable/target-coordinator.ts`
- Create: `controller/test/integration/target-coordinator.test.ts`

**Interfaces:**
- Consumes: `AttemptMachine`, `Clock`, `ProviderObservation`, and target schema.
- Produces: `prepare(input): PrepareResult`, `authorizeDispatch(input): DispatchDecision`, `acquireObserver(input): ObserverLease`, `observe(input): ObservationResult`, `allocateRecovery(input): RecoveryId`, and `snapshot(): TargetSnapshot`.

- [ ] **Step 1: Write failing fence, lease, monotonicity, and recovery tests**

Use a fake clock and literal desired sequences. Assert:

- a valid `prepare` atomically increments record version and fence;
- an expired `prepared` lease can be replaced;
- `write_dispatched` cannot be replaced after its lease expires;
- desired sequence 9 is rejected after desired sequence 10;
- a stale completion is appended as evidence but cannot change observed digest/state;
- recovery allocation returns `max(desiredSequence, observedSequence, recoverySequence) + 1`, preserves predecessor digest/reason, and omits source SHA;
- replaying the recovery idempotency key returns the identical `RecoveryId`.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/target-coordinator.test.ts`

Expected: FAIL because target repository/service RPC methods do not exist.

- [ ] **Step 3: Implement the target repository and coordinator service**

Use these immutable command boundaries:

```ts
export type PrepareAttempt = Readonly<{
  targetKey: string;
  releaseId: string;
  desiredDigest: string;
  desiredSourceSha: string;
  desiredSequence: number;
  expectedVersion: number;
  leaseDurationMs: number;
  reconciliationHorizonMs: number;
  idempotencyKey: string;
}>;

export type RecoveryId = Readonly<{
  projectId: string;
  environment: string;
  sequence: number;
  predecessorDigest: string;
  reason: string;
  idempotencyKey: string;
}>;
```

Reject empty/oversized identifiers, non-SHA-256 digests, non-40-character Git SHAs, nonpositive leases, and overflowed sequences at the service boundary. `SqlTargetRepository` updates the singleton target row with `WHERE record_version = ? AND fence = ?`; it inserts every attempt decision into `attempt_events` before returning.

- [ ] **Step 4: Refactor and run focused coverage/type gates**

Run: `cd controller && npx vitest run test/integration/target-coordinator.test.ts --coverage && npm run typecheck && npm run lint`

Expected: target tests pass with at least 90% branch coverage; no mutable target state lives only in memory.

- [ ] **Step 5: Commit**

```bash
git add controller/src/storage/target-repository.ts controller/src/services/target-service.ts controller/src/ports/clock.ts controller/src/durable/target-coordinator.ts controller/test/integration/target-coordinator.test.ts
git commit -m "feat(controller): add target fencing and recovery allocation"
```

### Task 5: Enforce no-takeover dispatch and observer-only reconciliation

**Files:**
- Modify: `controller/src/domain/attempt-machine.ts`
- Modify: `controller/src/services/target-service.ts`
- Modify: `controller/src/storage/target-repository.ts`
- Create: `controller/test/integration/dispatch-races.test.ts`

**Interfaces:**
- Consumes: prepared attempts and provider observations from Task 4.
- Produces: exactly one fresh `Readonly<{ kind: "WRITE_ONCE"; attemptId: string; fence: number }>`; every replay returns `OBSERVE_ONLY`.

- [ ] **Step 1: Write failing interruption and A/B inversion tests**

Drive the real coordinator through these exact scenarios: ten identical authorize calls yield one `WRITE_ONCE`; a lost first response followed by retry yields `OBSERVE_ONLY`; runner A reaches `write_dispatched`, runner B arrives with a higher desired sequence, and B cannot dispatch; B may acquire only an observer lease after A expires; late A completion after B becomes desired is recorded but cannot commit; identical observed bytes commit; different bytes incident; absent/uncertain after dispatch stays observing until the horizon and then incidents; provider-specific definitive failure proves no write escaped and releases the target for the successor.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/dispatch-races.test.ts`

Expected: FAIL because replay/takeover paths can still authorize or finalize incorrectly.

- [ ] **Step 3: Implement the durable point-of-no-return protocol**

`authorizeDispatch` must make one conditional SQLite update from `prepared` to `write_dispatched`. Only the caller whose update changes one row receives `WRITE_ONCE`. A zero-row update re-reads state and returns `OBSERVE_ONLY` or a stale-fence error; it never repeats authorization. `observe` accepts an observer lease but never grants write authority. After a dispatched attempt, `absent` and `uncertain` observations remain ambiguous; only `identical`, `conflict`, or `definitive_failure` can release the stream. Every stale callback is appended to `attempt_events` with `authoritative=false`.

- [ ] **Step 4: Run the race suite repeatedly**

Run: `cd controller && for i in 1 2 3 4 5; do npx vitest run test/integration/dispatch-races.test.ts || exit 1; done`

Expected: five clean runs, one authorization per scenario, and no order-dependent failure.

- [ ] **Step 5: Commit**

```bash
git add controller/src/domain/attempt-machine.ts controller/src/services/target-service.ts controller/src/storage/target-repository.ts controller/test/integration/dispatch-races.test.ts
git commit -m "feat(controller): make provider dispatch no-takeover"
```

### Task 6: Authenticate GitHub OIDC callers fail-closed

**Files:**
- Create: `controller/src/auth/claims.ts`
- Create: `controller/src/auth/oidc-authenticator.ts`
- Create: `controller/policy/callers.v1.json`
- Create: `controller/test/support/oidc-fixture.ts`
- Create: `controller/test/integration/auth.test.ts`

**Interfaces:**
- Produces: `OidcAuthenticator.authenticate(bearerToken: string): Promise<ControllerPrincipal>`.
- Produces: `CallerPolicy.authorize(claims: GithubOidcClaims): ControllerPrincipal`.

- [ ] **Step 1: Write failing signed-JWT authorization tests**

Generate an ephemeral ES256 keypair in the fixture, sign real JWTs, and verify the real jose path. The happy token must contain literal `iss=https://token.actions.githubusercontent.com`, `aud=portfolio-delivery-controller`, protected `ref`, 40-character `sha`, caller `repository`, `workflow_ref`, `job_workflow_ref`, `job_workflow_sha`, `run_id`, `run_attempt`, `iat`, `nbf`, and `exp`. Independently mutate each claim and assert rejection. Also reject expired/future tokens, unknown fields required by policy, a token over 16 KiB, an unprotected ref, a different workflow SHA, and a caller absent from policy.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/auth.test.ts`

Expected: FAIL because claim parsing and signature/policy verification are absent.

- [ ] **Step 3: Implement jose verification and exact policy matching**

Parse claims with strict Zod schemas. Configure `jwtVerify` with exact issuer/audience and an injected JWK resolver; the production resolver is `createRemoteJWKSet(new URL("https://token.actions.githubusercontent.com/.well-known/jwks"))`. Match repository, caller workflow path/ref, protected ref, and central reusable workflow path; require `job_workflow_sha === env.CONTROLLER_RELEASE_SHA`. Return only normalized identity fields, never the token. `callers.v1.json` contains exact entries for `hseshadr/assay`, `hseshadr/edge-reco`, `hseshadr/almamesh`, `hseshadr/aml-filter`, and `hseshadr/portfolio-delivery`; additions are data-only changes.

- [ ] **Step 4: Run auth, type, and lint gates**

Run: `cd controller && npx vitest run test/integration/auth.test.ts --coverage && npm run typecheck && npm run lint`

Expected: all authorization branches pass with no token/private claim in snapshots or logs.

- [ ] **Step 5: Commit**

```bash
git add controller/src/auth controller/policy controller/test/support/oidc-fixture.ts controller/test/integration/auth.test.ts
git commit -m "feat(controller): verify GitHub Actions OIDC callers"
```

#### Part B: Add short-lived GitHub App operations and incident reporting

**Files:**
- Create: `controller/src/ports/github.ts`
- Create: `controller/src/auth/github-app.ts`
- Create: `controller/src/services/incident-service.ts`
- Create: `controller/test/support/github-fixture.ts`
- Create: `controller/test/integration/github-app.test.ts`

**Interfaces:**
- Produces: `GitHubApp.installationToken(): Promise<InstallationCredential>`.
- Produces: `GitHubApp.readProtectedHead(repository: string, ref: string): Promise<DesiredStateProof>`.
- Produces: `GitHubApp.dispatchReconciliation(command): Promise<DispatchReceipt>` and `GitHubApp.openIncident(command): Promise<IncidentReceipt>`.
- Produces: `IncidentService.openOnce(incident): Promise<IncidentReceipt>`.

- [ ] **Step 1: Write failing GitHub boundary tests**

Against a complete fixture HTTP server, assert the app JWT uses RS256, `iat=now-60`, `exp=now+540`, and configured app ID; installation token creation calls `/app/installations/{id}/access_tokens`; the credential is discarded 60 seconds before provider expiry; protected-head lookup returns the exact current SHA and response proof digest; dispatch uses `/repos/hseshadr/portfolio-delivery/actions/workflows/reconcile.yml/dispatches`; incident creation uses the affected repository and stable incident idempotency marker. Assert timeout, non-2xx, oversized body, malformed JSON, missing expiry, and permissions mismatch all fail closed.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/github-app.test.ts`

Expected: FAIL because the GitHub App adapter and incident service do not exist.

- [ ] **Step 3: Implement narrow GitHub ports**

Load `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, and `GITHUB_APP_PRIVATE_KEY` only from secret bindings. Import the PKCS#8 key with jose, mint the app JWT, request a repository-scoped installation credential with minimum contents/pull-requests/deployments/checks/actions/issues permissions, and keep it only in an in-memory expiry-aware cache. Bound fetch to 10 seconds and response bodies to 1 MiB. `IncidentService` records an incident row before the network request and treats an existing GitHub issue with the same marker as success.

- [ ] **Step 4: Run focused and secret-leak gates**

Run: `cd controller && npx vitest run test/integration/github-app.test.ts && ! rg -n 'ghp_|github_pat_|BEGIN (RSA )?PRIVATE KEY' controller/src controller/test`

Expected: tests pass and the leak scan prints no matches.

- [ ] **Step 5: Commit**

```bash
git add controller/src/ports/github.ts controller/src/auth/github-app.ts controller/src/services/incident-service.ts controller/test/support/github-fixture.ts controller/test/integration/github-app.test.ts
git commit -m "feat(controller): add GitHub App dispatch and incidents"
```

### Task 7: Schedule maturity, reconciliation, and the authenticated API

**Files:**
- Create: `controller/src/services/scheduler-service.ts`
- Modify: `controller/src/storage/release-repository.ts`
- Modify: `controller/src/storage/target-repository.ts`
- Modify: `controller/src/durable/release-ledger.ts`
- Modify: `controller/src/durable/target-coordinator.ts`
- Create: `controller/test/integration/alarms.test.ts`

**Interfaces:**
- Produces: `schedule(action: ScheduledAction): Promise<void>` and `runDue(alarmInfo): Promise<AlarmResult>` on each scheduling DO.
- Consumes: GitHub App reconciliation dispatch from Task 7.

- [ ] **Step 1: Write failing at-least-once alarm tests**

Use `runDurableObjectAlarm()` to prove: the earliest `nextActionAt` owns the single alarm; later actions do not postpone it; a due maturity action dispatches exact release/target/reason/correlation inputs; duplicate alarm delivery is safe; a GitHub outage retains the due row and schedules a bounded retry; more than six failures still leave a future alarm; a success marks only the dispatch event, not the release/provider transition; the next pending action is scheduled.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/alarms.test.ts`

Expected: FAIL because alarm handlers and durable schedules are absent.

- [ ] **Step 3: Implement durable due-action claiming and rescheduling**

Store one row per `(action_id, release_id, kind)` with states `pending`, `dispatching`, and `dispatched`. Claim synchronously; release storage gates; perform GitHub I/O; then synchronously record the receipt. On any caught error, record a failure event, return the row to `pending`, and call `setAlarm(min(now + boundedBackoff, nextDue))` before returning so Cloudflare's finite automatic retry budget is not the only recovery mechanism. Dispatch may duplicate after a crash, but the central workflow's coordinator key makes it observer-only after the first provider authorization.

- [ ] **Step 4: Run alarm and dispatch-race tests together**

Run: `cd controller && npx vitest run test/integration/alarms.test.ts test/integration/dispatch-races.test.ts`

Expected: both suites pass, demonstrating scheduling duplicates cannot duplicate a provider write.

- [ ] **Step 5: Commit**

```bash
git add controller/src/services/scheduler-service.ts controller/src/storage controller/src/durable controller/test/integration/alarms.test.ts
git commit -m "feat(controller): reconcile maturity through durable alarms"
```

#### Part B: Expose the strict authenticated controller API

**Files:**
- Create: `controller/src/api/schemas.ts`
- Create: `controller/src/api/controller.ts`
- Create: `controller/src/api/router.ts`
- Modify: `controller/src/index.ts`
- Create: `controller/openapi.v1.json`
- Create: `controller/scripts/verify-openapi.ts`
- Create: `controller/test/integration/http-api.test.ts`

**Interfaces:**
- Consumes: OIDC principal, release/target/catalog stubs, and all commands above.
- Produces: `/healthz`, `/v1/releases/:id/authorize-persist`,
  `/record-persisted`, `/authorize-package`, `/candidate`,
  `/candidate-evidence`, `/activate`, `/live-evidence`, `/recover`,
  `/reconcile`, `/transitions`, `/evidence`, `/export`,
  `/v1/callers/assay/authorize`, `/v1/targets/:key/prepare`, `/dispatch`,
  `/observer-leases`, `/observations`, `/recovery-ids`, and catalog/retention
  routes. These names are the exact Phase 3 workflow client contract.

- [ ] **Step 1: Write failing end-to-end route tests**

Call `SELF.fetch` with real signed fixture JWTs. Assert health has no state/secrets, every `/v1` route rejects missing/invalid auth, wrong method is 405, unknown route 404, content type must be JSON, body over 256 KiB is 413, Zod rejects unknown fields, caller repository/project mismatch is 403, stale CAS is 409, incident is 423, and success responses validate against literal response schemas. Prove `dispatch` re-reads the protected head, refuses a mismatched SHA without changing attempt state, returns `WRITE_ONCE` once for an exact SHA, and returns `OBSERVE_ONLY` thereafter.

Exercise every Phase 3 facade route with the shared request fields
`schema_version`, `correlation_id`, `repository`, `workflow_ref`,
`job_workflow_ref`, `ref`, and `sha`. Prove each facade maps to one allowed
state-machine command and never bypasses target authorization.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/http-api.test.ts`

Expected: FAIL because the Worker router and API schemas do not exist.

- [ ] **Step 3: Implement thin routing and safe cross-DO ordering**

`Controller.appendTransition` protects new retention roots in `PortfolioCatalog` before appending the release event and retires obsolete roots only after append succeeds; an interruption therefore leaks retention rather than deleting live content. It records an active release before the first project-ledger transition and removes it only after terminal state/export persistence. `Controller.authorizeDispatch` reads the protected ref through the GitHub App immediately before target CAS; a SHA mismatch returns stale work and never reaches `WRITE_ONCE`. The router authenticates first, parses one strict schema, delegates once, translates concrete errors to generic JSON, and emits a structured correlation event without bearer/body/private-key fields.

Facade routes are declarative aliases over the same typed service commands;
they contain no provider call and no alternate state transition logic. The
Assay caller authorization route fetches and hashes the caller bytes at the
authenticated SHA before comparing the centrally allowlisted digest.

Encode the same request/response/status contracts in `openapi.v1.json`. `verify-openapi.ts` loads every Zod fixture, validates it against the OpenAPI schema, calls the Worker route, and rejects route/schema drift by behavior rather than source-text matching.

- [ ] **Step 4: Run API drift and full controller tests**

Run: `cd controller && npx vitest run test/integration/http-api.test.ts && node --import tsx scripts/verify-openapi.ts`

Expected: HTTP tests and the executable schema drift gate pass under pinned `tsx` 4.23.12.

- [ ] **Step 5: Commit**

```bash
git add controller/src/api controller/src/index.ts controller/openapi.v1.json controller/scripts/verify-openapi.ts controller/test/integration/http-api.test.ts controller/package.json controller/package-lock.json
git commit -m "feat(controller): expose authenticated release control API"
```

### Task 8: Implement fail-safe two-pass OCI retention collection

**Files:**
- Create: `controller/src/ports/catalog.ts`
- Create: `controller/src/domain/retention-policy.ts`
- Create: `controller/src/storage/catalog-repository.ts`
- Create: `controller/src/services/retention-collector.ts`
- Modify: `controller/src/durable/portfolio-catalog.ts`
- Create: `controller/test/domain/retention-policy.test.ts`
- Create: `controller/test/integration/retention-collector.test.ts`

**Interfaces:**
- Produces: `protect`, `retire`, `startSweep`, `submitInventoryPage`, `finishSweep`, `listDeletionAuthorizations`, and `recordDeletionObservation`.
- Consumes: authoritative inventory snapshots produced by the pinned central ORAS/GHCR workflow.

- [ ] **Step 1: Write failing retention safety tests**

Cover every root class: desired/observed production, immediate verified predecessor, nonterminal release, any registry publication, immutable mirror, recovery plus predecessor, open incident, and audit/legal hold. Assert completed unrooted content is ineligible before 90 days; first traversal only creates a candidate; second traversal must have a different inventory ID and occur at least seven days later; regaining any root cancels candidacy; permanent package/mirror subjects never authorize; incomplete/ambiguous inventory incidents and authorizes nothing; deletion is complete only after a provider-missing observation; provider ambiguity opens an incident.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/domain/retention-policy.test.ts test/integration/retention-collector.test.ts`

Expected: FAIL because retention decisions and persistence do not exist.

- [ ] **Step 3: Implement the safety-biased collector**

Use constants `MINIMUM_COMPLETED_RETENTION_MS = 7_776_000_000` and `SECOND_TRAVERSAL_GRACE_MS = 604_800_000`. `InventorySnapshot` carries a unique ID, observed timestamp, complete-page marker, OCI URI, manifest digest, and provider proof digest. The catalog stores root claims before referencing transitions and retires them after; duplicate claims are idempotent. A deletion authorization contains digest, immutable inventory proofs, fence, and expiry but no registry credential. The central pinned workflow performs the ORAS deletion, re-inspects GHCR, and submits `missing`, `present`, or `uncertain`; only `missing` closes the candidate.

- [ ] **Step 4: Run retention crash-boundary tests**

Inject failure before/after root protection, release append, root retirement, first mark, second mark, deletion authorization, provider deletion, and deletion observation. Run:

`cd controller && npx vitest run test/domain/retention-policy.test.ts test/integration/retention-collector.test.ts --coverage`

Expected: no injected interruption authorizes a rooted/permanent/too-young digest; all retry paths converge.

- [ ] **Step 5: Commit**

```bash
git add controller/src/ports/catalog.ts controller/src/domain/retention-policy.ts controller/src/storage/catalog-repository.ts controller/src/services/retention-collector.ts controller/src/durable/portfolio-catalog.ts controller/test/domain/retention-policy.test.ts controller/test/integration/retention-collector.test.ts
git commit -m "feat(controller): add two-pass envelope retention collector"
```

### Task 9: Prove controller conformance, properties, restarts, and mutations

**Files:**
- Create: `controller/contracts/controller-conformance.v1.json`
- Create: `controller/test/support/builders.ts`
- Create: `controller/test/support/fake-clock.ts`
- Create: `controller/test/support/failure-injector.ts`
- Create: `controller/test/integration/controller-conformance.test.ts`
- Create: `controller/stryker.config.json`

**Interfaces:**
- Consumes: the public HTTP API and pure state machines only.
- Produces: an executable conformance contract reusable by Python/Dagger controller adapters.

- [ ] **Step 1: Add literal conformance fixtures and failing property tests**

The JSON fixture has fully specified success, retry, conflict, stale, timeout, restart, rollback, and alarm cases with literal expected states/fences/effects. Parameterize the real HTTP API over those cases. Add fast-check properties for: ten identical commands produce one effect; `recordVersion`, fence, desired sequence, observed sequence, and recovery sequence never decrease; a stale fence never becomes authoritative; no state after `write_dispatched` returns `WRITE_ONCE`; arbitrary crashes followed by replay converge to success, observer-only, or incident without duplicate provider authorization.

- [ ] **Step 2: Run tests and verify the intended failure**

Run: `cd controller && npx vitest run test/integration/controller-conformance.test.ts`

Expected: FAIL on at least one missing failure-injection/restart behavior.

- [ ] **Step 3: Complete restart and failure-injection support through production boundaries**

Keep failure injection in test adapters, not production classes. Recreate `ReleaseService`, `TargetService`, and `RetentionCollector` over the same stored repository after every state; invoke DO RPC again for persisted integration cases. Assert every safety mutation has a named test: removed fence comparison, repeated dispatch grant, accepted stale callback, early retention delete, alarm row deleted before dispatch, unverified incident clearance, and recovery sequence reuse.

- [ ] **Step 4: Configure and pass mutation/coverage/quality gates**

Configure Stryker to mutate only `src/domain/**/*.ts` and `src/services/**/*.ts`, use the Vitest runner/domain config, and require mutation score at least 90 with break threshold 90. Run:

`cd controller && npm run check && npm run test:mutation`

Expected: all tests pass, coverage is at least 90% branch/line, mutation score is at least 90, and output has no warnings.

- [ ] **Step 5: Commit**

```bash
git add controller/contracts controller/test/support controller/test/integration/controller-conformance.test.ts controller/stryker.config.json
git commit -m "test(controller): prove release coordination conformance"
```

### Task 10: Automate controller CI, deployment, and operations proof

**Files:**
- Create: `.github/workflows/controller-ci.yml`
- Create: `.github/workflows/controller-deploy.yml`
- Create: `controller/scripts/smoke-controller.ts`
- Create: `controller/README.md`
- Create: `docs/controller-operations.md`

**Interfaces:**
- Consumes: controller quality gate, Wrangler deployment, OIDC API, and GitHub App dispatch.
- Produces: automatic protected-main deployment, authenticated smoke evidence,
  and exact incident/export/recovery commands. Phase 3 owns the scheduled
  reconciliation workflow that calls this API.

- [ ] **Step 1: Write failing workflow and deployed-smoke contract tests**

Extend `verify-openapi.ts` to execute workflow fixtures as controller callers and add a smoke-script test using a local Worker URL. Assert CI uses Node 24.19.0 and `npm ci`; deployment cannot run unless CI succeeds; all actions use immutable commits; deploy grants only contents read plus Cloudflare secrets; post-deploy smoke verifies `/healthz` build SHA and an authenticated read-only ledger snapshot.

- [ ] **Step 2: Run the contract tests and verify the intended failure**

Run: `cd controller && npm run test:domain && node --import tsx scripts/verify-openapi.ts`

Expected: FAIL because the workflows/runbook/smoke command are not present in the executable fixtures.

- [ ] **Step 3: Add pinned workflows and runnable operations documentation**

Pin actions exactly:

- `actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09`
- `actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444`
- `cloudflare/wrangler-action@9acf94ace14e7dc412b076f2c5c20b8ce93c79cd`
- `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`

`controller-ci.yml` runs `npm ci`, `npm run check`, and `npm run test:mutation`. `controller-deploy.yml` runs only after successful CI on protected main, uses `CLOUDFLARE_API_TOKEN`/`CLOUDFLARE_ACCOUNT_ID`, sets `CONTROLLER_RELEASE_SHA` to the exact commit, deploys with Wrangler, then runs `smoke-controller.ts` against `CONTROLLER_URL`. The Phase 3 reconciliation workflow later acquires an OIDC token for this controller API and contains no controller or project build logic.

The runbook starts with copy-paste commands for local install/test/dev, describes secret creation without printing values, exports paginated delivery records, verifies point-in-time recovery, resolves incidents through append-only two-person decisions, and performs a sandbox drill for lost dispatch response, maturity alarm retry, stale callback, and retention ambiguity. Document that normal protected-main delivery has no approval step and that rollback cannot erase prior evidence.

- [ ] **Step 4: Run local gates, deploy, and verify production evidence**

Run locally: `cd controller && npm ci && npm run check && npm run test:mutation && npx wrangler deploy --dry-run`

After the protected-main workflow deploys, run: `cd controller && node --import tsx scripts/smoke-controller.ts --url "$CONTROLLER_URL" --expected-sha "$GITHUB_SHA"`

Expected: dry-run succeeds; deployment workflow succeeds; smoke returns the exact build SHA, healthy DO binding checks, and a correlation ID; no secret appears in logs.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/controller-ci.yml .github/workflows/controller-deploy.yml controller/scripts/smoke-controller.ts controller/README.md docs/controller-operations.md
git commit -m "ci(controller): automate deployment and smoke proof"
```

## Final Verification

- [ ] Run `cd controller && npm ci && npm run check && npm run test:mutation` from a clean checkout.
- [ ] Run `cd controller && npx wrangler deploy --dry-run` and inspect that all three SQLite DO migrations/bindings are present.
- [ ] Run controller CI and automatic deployment from protected main.
- [ ] Run the hosted no-takeover drill: kill the runner after the provider call, start a successor, and prove only observers run until exact provider state commits or incidents.
- [ ] Run the hosted maturity alarm drill and prove duplicate alarm/workflow dispatches yield one provider authorization.
- [ ] Run the hosted retention drill with a rooted digest, a 90-day eligible unrooted fixture, two independent inventories seven days apart, and a provider reinspection.
- [ ] Export delivery records, restore the Worker/DOs through the documented recovery path, and rerun conformance against restored state.
- [ ] Verify repository protection requires controller CI and security checks, while normal controller deployment has no manual approval.
- [ ] Confirm no PAT, registry token, private key, or bearer token is present in git history, artifacts, Worker logs, SQLite exports, or GHCR envelopes.

The phase is complete only when the deployed controller, not merely local fakes, demonstrates CAS rejection, single write authorization, observer takeover, alarm reconciliation, incident fencing, and two-pass retention behavior.
