# Portfolio Delivery

## TL;DR

Portfolio Delivery turns declared source, artifact, SBOM, and verification inputs into one
canonical release envelope, attaches final qualification without changing that envelope, and
persists the exact bytes idempotently as a generic OCI artifact. Dagger runs the graph; typed
Python contracts keep the release logic independent of GitHub and registry implementations.

Run the full local proof:

```bash
uv sync --python 3.13.14
uv run poe lock-check
uv run poe test
dagger functions
uv run poe test-dagger -q
uv run poe demo-local-oci
```

The final command starts a pinned, storage-less local Registry service inside Dagger, submits the
same qualified envelope twice, restores it, stops the service in `finally`, and prints a bounded
JSON proof. It does not publish or deploy anything outside the local Dagger session.

## Why this exists

Assay, EdgeReco, AlmaMesh, AML Filter, and future portfolio projects need the same release safety
properties without copying mutable shell workflows between repositories. This foundation provides
one composable sequence:

1. snapshot declared Git-tree inputs;
2. build artifacts and CycloneDX SBOMs;
3. retain prequalification evidence;
4. create deterministic canonical envelope bytes;
5. attach detached final qualification for that exact envelope digest; and
6. reconcile the qualified bytes into content-addressed OCI storage.

GitHub remains the control plane for protected events, OIDC, concurrency, attestations, and
deployment status. The Dagger graph is the execution and artifact plane. Project behavior enters
through narrow contracts and composed adapters, so adding another project does not fork the core.

## Prerequisites and exact pins

- Python `3.13.14` and `uv` on `PATH`; wheels use the exact `uv_build==0.8.24` backend.
- CycloneDX Python Library `11.12.0` with its official JSON validator (locked development tool).
- Dagger CLI `v0.21.8`; the module also declares engine `v0.21.8`.
- A local Dagger-compatible container runtime and network access for the first pinned image pull.
- ORAS `v1.3.3` from
  `ghcr.io/oras-project/oras@sha256:a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8`.
- Local Registry
  `registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e`.

[`toolchain.lock.toml`](toolchain.lock.toml) is the authoritative complete matrix, including the
Dagger source commit and engine digest, the Python runtime image, GitHub integration commit, Node,
Wrangler, Vitest pool worker, and Release Please pins. `uv.lock` is the authoritative Python
dependency resolution.

## Quickstart

From a clean checkout:

```bash
uv sync --python 3.13.14
uv run poe lock-check
uv run poe test
dagger functions
uv run poe test-dagger -q tests/dagger/test_oras_service.py
```

Poe 0.48 passes trailing arguments directly, so these commands intentionally omit the obsolete
`--` separator. The test command proves the real ORAS adapter against the pinned local Registry,
including repeated inspection, one write, manifest identity, exact restore, and secret canaries.

To prove generated Dagger bindings have not drifted:

```bash
dagger develop
git diff --exit-code -- dagger.json .dagger/sdk .dagger/uv.lock
```

## Realistic local OCI demonstration

The demo consumes the checked-in wheel, CycloneDX 1.6 SBOM, and prequalification evidence under
`tests/fixtures/envelope/input`. It invokes the tested `public-oras-smoke` Dagger function, which
creates the envelope, attaches detached qualification, performs two identical persistence
attempts, restores exact bytes, and owns the Registry service lifecycle.

The wheel is a real `py3-none-any` archive containing the importable `portfolio_delivery` package,
not placeholder bytes. Its CycloneDX component records the same project name and version, a purl,
and the wheel SHA-256. Unit tests rebuild the wheel in two independent clean source directories,
regenerate the SBOM twice with the official library, require byte-identical output, validate the
CycloneDX 1.6 schema, and verify the build-input declarations against both files.

```bash
uv run poe demo-local-oci
```

To regenerate only the reviewed wheel and its deterministic SBOM after an intentional source
change, use the pinned backend and the envelope's fixed epoch; the semantic fixture test then
fails until the reviewed build-input and golden envelope declarations are updated:

```bash
SOURCE_DATE_EPOCH=1724472000 uv build --wheel --no-sources --out-dir dist .
cp dist/portfolio_delivery-0.1.0-py3-none-any.whl tests/fixtures/envelope/input/artifacts/package.whl
uv run python scripts/build-release-sbom.py \
  --wheel tests/fixtures/envelope/input/artifacts/package.whl \
  --output tests/fixtures/envelope/input/sbom/package.cdx.json \
  --source-date-epoch 1724472000
uv run pytest -q tests/unit/test_release_fixtures.py tests/unit/envelope/test_canonical.py
```

The output is one canonical JSON object with this bounded shape:

```json
{"attempts":2,"envelope_sha256":"sha256:<64 lowercase hex>","exact_restore":true,"manifest_sha256":"sha256:<64 lowercase hex>","provider_writes":1}
```

`envelope_sha256` identifies the canonical build-envelope bytes.
`manifest_sha256` identifies the OCI manifest produced by the provider. `attempts: 2` with
`provider_writes: 1` is the observable idempotency proof; `exact_restore: true` covers the envelope,
detached qualification, wheel, and SBOM bytes.

## Quality and architecture gates

```bash
uv run poe lint
uv run poe typecheck
uv run poe complexity
uv run poe test
uv run poe mutation
uv run poe audit
```

The mutation task scopes mutations to `domain`, `envelope`, and the pure ORAS adapter, exports
`mutmut-cicd-stats.json`, and fails closed for survived, untested, suspicious, timed-out,
segfaulted, or interrupted mutations. Pure `domain`, `contracts`, `envelope`, and `application`
modules are also imported in an isolated process with Dagger, provider, network, process, socket,
and filesystem delivery dependencies blocked.

## Phase 1 limitations

Phase 1 deliberately stops at a qualified, locally persisted OCI envelope:

- it does not publish npm packages;
- it does not publish PyPI packages;
- it does not deploy applications; and
- it does not provide the durable release authority that authorizes tags or production mutation.

Those control-plane and project-migration capabilities belong to later phases. The approved full
architecture is in
[`docs/superpowers/specs/2026-08-22-portfolio-delivery-design.md`](docs/superpowers/specs/2026-08-22-portfolio-delivery-design.md).
