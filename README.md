# Portfolio Delivery

Internal CI tooling for Harish's own repos: a small Dagger module that checks and packages its own code, kept as the example those repos copy.

**Try it:** `git clone https://github.com/hseshadr/portfolio-delivery && cd portfolio-delivery && dagger check` (needs Dagger 0.21.8 and Docker running).

This is not a product for other people. It is a worked example Harish keeps for his own
repos. [Dagger](https://dagger.io) runs build and test steps inside containers, so the same
command gives the same result on a laptop and in GitHub Actions. This repo is one Dagger module
of about 90 lines of Python. It checks its own code (lint, types, complexity, tests), exports
itself as a folder, and has a function to push that folder to a container registry (which
is broken today; see below).

It used to be a custom release framework with its own stages, storage layer and registry
client. Dagger already does all of that, so version 0.2.0 deleted it and kept only what Dagger
does not. Today no other repo imports this module. Harish's other repos run their own Dagger
modules, and this one shows the pattern they follow: CI is a short workflow that runs
`dagger check`, and the real work lives in typed Dagger functions.

**Technical docs:** [Architecture](docs/ARCHITECTURE.md) · [Getting started for developers](docs/GETTING_STARTED.md) · [Interactive architecture map](docs/architecture/index.html)

## Try it

You need Dagger `0.21.8`, Docker (or another container runtime) running, and
[uv](https://docs.astral.sh/uv/). Setup steps are in [Getting started](docs/GETTING_STARTED.md).

1. Clone it and list what the module can do:

   ```bash
   git clone https://github.com/hseshadr/portfolio-delivery
   cd portfolio-delivery
   dagger functions
   ```

   ```text
   Name         Description
   build        Return the exportable, self-contained module source.
   complexity   Require Xenon grade A complexity.
   lint         Check Ruff lint and formatting.
   publish      Publish the built module with native OCI support.
   typecheck    Check the module with strict mypy.
   unit         Run fast, host-independent contract tests.
   ```

2. Run every check, the same command CI runs. It takes 20 to 35 seconds once Dagger's caches
   are warm, and exits 0 when all four pass:

   ```bash
   dagger --progress=plain check
   ```

   The last lines of the output:

   ```text
   portfolio-delivery:lint DONE [10.4s]
   portfolio-delivery:complexity DONE [10.8s]
   portfolio-delivery:unit DONE [11.1s]
   portfolio-delivery:typecheck DONE [19.1s]
   ```

3. Export the module as a folder another repo could load:

   ```bash
   dagger call build -o ./dist/module
   ls -A dist/module
   ```

   ```text
   Saved to "…/portfolio-delivery/dist/module".
   .dagger
   LICENSE
   dagger.json
   ```

   Only those three entries go in. The README, docs and tests are left out, so editing them
   does not change the build.

## How it works

`dagger.json` tells Dagger where the module lives and pins the engine to version 0.21.8. The
module is one Python class in `.dagger/src/portfolio_delivery_dagger/main.py`. The four check
functions (`lint`, `typecheck`, `complexity`, `unit`) each start a pinned Python 3.13 container,
install the dev tools with uv, and run one task. `build` returns the module's own files, and
`publish` puts them in an image and pushes it with Dagger's built-in `Container.publish`,
taking the registry password as a Dagger secret so it never appears in logs. The GitHub
workflow only installs Dagger and runs `dagger check`.

## What it does not do

- **`publish` does not work yet.** It builds its image from `scratch`, which is not a real
  image, so it fails with `docker.io/library/scratch:latest: not found` before pushing
  anything. No test pushes an image, so this was not caught. Details are in
  [Architecture](docs/ARCHITECTURE.md#known-problem-with-publish).
- **Nothing depends on it.** It is not a shared library or a reusable GitHub workflow that
  other repos call. It is the reference they copy from.
- **It only builds itself.** There is no option to point it at another project.
- **CI skips the slower tests.** CI runs `dagger check`, which runs the quick tests only. The
  tests that drive the real `dagger` CLI (build is repeatable, the right files are exported,
  the password is a secret) run only when you run `uv run poe test` locally.
- **It keeps no release history.** Dagger's cache is not a record of what was published.

If you want CI that runs the same way locally and in the cloud for your own project, start
from [Dagger's own docs](https://docs.dagger.io) and modules at
[daggerverse.dev](https://daggerverse.dev), not from this repo.

## Develop

```bash
uv sync --python 3.13.14
dagger check          # what CI runs: lint, typecheck, complexity, unit (20 to 35 s)
uv run poe test       # every test, including the ones that call the real dagger CLI (about 1 min)
```

[Getting started for developers](docs/GETTING_STARTED.md) covers setup, the traps we hit, a
map of the code, a first change, and how to open a PR.

## More detail

- [Architecture](docs/ARCHITECTURE.md): each function, what files it sees, why the old
  framework was removed, the size limits the tests enforce, and the known `publish` bug.
- [Getting started for developers](docs/GETTING_STARTED.md): from a fresh clone to a green
  run and your first change.
- [Interactive architecture map](docs/architecture/index.html): a clickable diagram, one
  offline HTML file.
- [CHANGELOG](CHANGELOG.md): what changed in each version.

## License

MIT. See [LICENSE](LICENSE).
