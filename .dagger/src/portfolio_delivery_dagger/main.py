"""Lean delivery functions built only from Dagger core types."""

from __future__ import annotations

from typing import Final

import dagger
from dagger import check, dag, function, object_type

PYTHON_IMAGE: Final = (
    "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)
UV_VERSION: Final = "0.8.24"
RELEASE_INCLUDE: Final = [".dagger/**", "LICENSE", "dagger.json"]
QUALITY_INCLUDE: Final = [
    ".dagger/sdk/**",
    ".dagger/src/**",
    ".github/workflows/dagger.yml",
    "pyproject.toml",
    "tests/**",
    "uv.lock",
]


@object_type
class PortfolioDelivery:
    """Build, validate, and publish the self-contained Dagger module."""

    @function
    def build(self) -> dagger.Directory:
        """Return the exportable, self-contained module source."""
        return dag.current_workspace().directory("/", include=RELEASE_INCLUDE)

    @function
    @check
    def lint(self) -> dagger.Container:
        """Check Ruff lint and formatting."""
        return self._quality().with_exec(["uv", "run", "poe", "lint-check"])

    @function
    @check
    def typecheck(self) -> dagger.Container:
        """Check the module with strict mypy."""
        return self._quality().with_exec(["uv", "run", "poe", "typecheck"])

    @function
    @check
    def complexity(self) -> dagger.Container:
        """Require Xenon grade A complexity."""
        return self._quality().with_exec(["uv", "run", "poe", "complexity"])

    @function
    @check
    def unit(self) -> dagger.Container:
        """Run fast, host-independent contract tests."""
        return self._quality().with_exec(["uv", "run", "poe", "test-unit"])

    @function
    async def publish(
        self,
        registry: str,
        address: str,
        username: str,
        password: dagger.Secret,
    ) -> str:
        """Publish the built module with native OCI support."""
        image = self._image().with_registry_auth(registry, username, password)
        return await image.publish(address)

    def _image(self) -> dagger.Container:
        return dag.container().from_("scratch").with_directory("/module", self.build())

    def _quality(self) -> dagger.Container:
        source = dag.current_workspace().directory("/", include=QUALITY_INCLUDE)
        return (
            dag.container()
            .from_(PYTHON_IMAGE)
            .with_directory("/src", source)
            .with_workdir("/src")
            .with_mounted_cache("/root/.cache/uv", dag.cache_volume("portfolio-delivery-uv"))
            .with_exec(["python", "-m", "pip", "install", f"uv=={UV_VERSION}"])
            .with_exec(["uv", "sync", "--frozen"])
        )
