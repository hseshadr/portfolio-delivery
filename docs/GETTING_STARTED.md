# Getting started for developers

From a fresh clone to a green local run and your first change. Timings are from an Apple Silicon
Mac with Docker already running and the Dagger engine already downloaded. A cold first run is
slower because Dagger pulls its engine image and the Python base image.

## 1. Prerequisites

| Tool | Version | How to get it |
| --- | --- | --- |
| Dagger CLI | exactly `0.21.8`, installed at `/usr/local/bin/dagger` | `curl -fsSL https://dl.dagger.io/dagger/install.sh \| DAGGER_VERSION=0.21.8 BIN_DIR=/usr/local/bin sudo -E sh` |
| A container runtime | Docker Desktop, OrbStack, or Podman | Dagger runs its engine as a container. It must be running. |
| uv | 0.8 or newer | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Python | `3.13.14` (from `.python-version`) | `uv python install 3.13.14` |

Traps we hit:

- Dagger prints "A new release of dagger is available: v0.21.8 → v0.21.9" on every command.
  Don't upgrade. `dagger.json`, CI, and a test all pin `0.21.8`.
- The integration tests call `/usr/local/bin/dagger` by that exact path. A Dagger installed
  only through Homebrew somewhere else makes them fail with "No such file".
- macOS has no `timeout` command, so don't copy Linux snippets that wrap `dagger` in it.
- `uv sync` installs the Dagger Python SDK from the vendored `.dagger/sdk` folder, not from
  PyPI. Don't edit that folder by hand.

## 2. Clone, install, run the tests

```bash
git clone https://github.com/hseshadr/portfolio-delivery
cd portfolio-delivery
uv sync --python 3.13.14      # about 1 s with a warm uv cache
uv run poe lock-check         # "Resolved 72 packages", under 1 s
uv run poe test-unit          # fast tests only, about 1 s
```

Success for the last line looks like this (16 tests collected, the 7 slow ones skipped):

```text
tests/test_modern_dagger_contract.py ..                                  [ 22%]
tests/test_readme_contract.py .......                                    [100%]

======================= 9 passed, 7 deselected in 0.04s ========================
```

## 3. The full check (what CI runs)

```bash
dagger check
```

This is exactly what CI runs. It builds a Python container and runs four checks in parallel:
`lint`, `typecheck`, `complexity`, and `unit`. It took 21 to 35 seconds here with warm caches.
It exits 0 when everything passes.

CI does not run the integration tests. Run them yourself before a PR that touches the module:

```bash
uv run poe test               # every test, including the ones that drive the real dagger CLI
```

This took 45 to 60 seconds here and ends with `16 passed`.

## 4. Map of the code

| Path | What it is |
| --- | --- |
| `.dagger/src/portfolio_delivery_dagger/main.py` | All handwritten module code: the six Dagger functions. |
| `dagger.json` | Module name, pinned engine version, and the files Dagger loads. |
| `pyproject.toml` | Dev tools and the `poe` tasks (`lint-check`, `typecheck`, `complexity`, `test-unit`, `test`, `audit`). |
| `tests/test_modern_dagger_contract.py` | Tests for the module's behavior, size limits, and CI file. |
| `tests/test_readme_contract.py` | Tests that keep the README true and plain. |
| `.github/workflows/dagger.yml` | CI: installs Dagger and runs `dagger check`. |
| `.dagger/sdk/` | Generated Dagger SDK. Leave it alone. |
| `docs/architecture/` | The interactive architecture map (one offline HTML file plus its JSON source). |

## 5. Make your first change

A realistic small change: `pyproject.toml` already has an `audit` task (pip-audit), but no
Dagger check runs it. Here is how you would add one.

1. Write the failing test first. In `tests/test_modern_dagger_contract.py`, add `"audit"` to
   both `EXPECTED_FUNCTIONS` and `EXPECTED_CHECKS`.
2. Run just that test and watch it fail:

   ```bash
   uv run pytest -k register_meaningful_checks -q
   ```

   It takes about 6 seconds, because it calls the real `dagger check -l`.
3. In `main.py`, copy the `unit` function, rename it `audit`, and make it run
   `["uv", "run", "poe", "audit"]`.
4. Run the same test again. It should pass.
5. Run `uv run poe lint` (fixes formatting), then `dagger check` and `uv run poe test`.

Keep handwritten module code under 400 lines. A test fails if it goes over.

## 6. Open a pull request

- Branch off `main` with a short prefix and name, such as `feat/audit-check`,
  `fix/publish-empty-image`, or `docs/readme-plain-english`.
- CI runs one job, **Dagger / check**, which is `dagger check` on Ubuntu. It must be green.
- Say in the PR what you ran locally, including `uv run poe test`, since CI skips the
  integration tests.
- Reviewers look for: Dagger built-ins used instead of new wrapper code, the workflow file
  staying thin with SHA-pinned actions, no new files leaking into the `build` output, and a
  test that fails without your change.
