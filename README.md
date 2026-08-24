# Portfolio Delivery

## TL;DR

Portfolio Delivery is a small Dagger `v0.21.8` module with four checks and two user goals:

```bash
dagger check
dagger call build -o ./dist/module
dagger call publish \
  --registry=ghcr.io \
  --address=ghcr.io/OWNER/portfolio-delivery:TAG \
  --username=OWNER \
  --password=env:GITHUB_TOKEN
```

`build` returns a native `Directory`. `publish` uses native `Container.publish` and accepts the
registry password as a native `Secret`. There is no release framework, controller, workflow
renderer, artifact DTO, repository layer, or custom OCI client.

## Why

Dagger already supplies the execution graph, content-addressed caching, typed files and
directories, services, secret handling, OCI image publication, checks, and traces. Rebuilding
those capabilities made the previous implementation difficult to use and maintain.

This module follows the official design:

- the workspace supplies only the files each function needs;
- checks run with `dagger check` locally and in CI;
- functions expose user goals rather than internal stages;
- functions return Dagger core objects so callers can keep composing;
- publication delegates the side effect to the engine's native `Container.publish` operation.

## Quickstart

Prerequisites: Dagger `v0.21.8`, Python `3.13.14`, and `uv`.

```bash
uv sync --python 3.13.14
uv run poe lock-check
dagger functions
dagger check
dagger call build -o ./dist/module
```

The build output is the self-contained module source needed by Dagger. Documentation and tests
are deliberately excluded from its cache key.

## API

| Function | Result | Purpose |
|---|---|---|
| `build` | `Directory` | Return the exportable module source |
| `lint` | `Container` check | Ruff lint and formatting |
| `typecheck` | `Container` check | Strict mypy |
| `complexity` | `Container` check | Xenon grade A |
| `unit` | `Container` check | Host-independent contract tests |
| `publish` | digest-pinned `str` | Publish through native OCI support |

GitHub Actions is only a pinned trigger for `dagger check`; it contains no delivery logic.

## Reuse before code

Before adding code:

1. Check Dagger core types and functions.
2. Search official Dagger modules and toolchains.
3. Search maintained ecosystem modules.
4. Add custom code only with a written gap and a behavior test.

Examples of native replacements are `Workspace.directory` for source selection, `@check` for
validation, `CacheVolume` for tool caches, `Secret` for credentials, `Service` for dependencies,
`Changeset` for generated edits, and `Container.publish` for container publication.

## Enforced size limits

- Handwritten production Python: at most 400 lines; target 300 or fewer.
- Handwritten Python tests: at most 800 lines.
- GitHub trigger: 15–30 lines.
- Generated Dagger SDK and lock files are excluded.

A change is rejected if it adds a custom DTO for a Dagger core type, wraps a single native
operation, adds a controller to ordinary CI, duplicates Dagger caching or secret handling, or
cannot show why a native feature or maintained dependency is insufficient.

## Deliberate boundary

Dagger caching is not a durable cross-run release ledger. If a future product truly requires
cross-repository compare-and-set coordination, that service must be optional, separate, and
justified by real consumers. Ordinary check, build, and publish flows do not depend on one.
