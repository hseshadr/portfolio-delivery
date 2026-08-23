# Portfolio Delivery Execution Order

These plans implement the approved
[Portfolio Delivery architecture](../specs/2026-08-22-portfolio-delivery-design.md)
as independently testable phases.

1. [Foundation](2026-08-22-portfolio-delivery-foundation.md) — typed Python
   domain, deterministic envelopes, ORAS, and the stable Dagger module.
2. [Controller](2026-08-22-portfolio-delivery-controller.md) — Durable Object
   ledger, CAS/no-takeover coordination, alarms, identity, and retention.
3. [Reusable workflows](2026-08-22-portfolio-delivery-workflows.md) — generated
   callers, GHCR/attestations, OIDC package publication, deployments, and
   reconciliation.
4. [Assay migration](2026-08-22-assay-delivery-migration.md) — shadow the proven
   dev2 path, cut over automatically, drill rollback, then retire legacy paths.
5. [Application migrations](2026-08-22-application-delivery-migrations.md) —
   exact mature Assay locks and automated EdgeReco, AlmaMesh, and AML Filter
   delivery through production and live verification.

Each phase uses its own subagent-driven-development ledger and cannot advance
past an open Critical or Important review finding.
