"""Record the actual finalized ORAS execution surface with a real typed Secret."""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass
from typing import cast

import dagger
from dagger import Container, Secret, dag
from portfolio_delivery_dagger.oras import (
    ATTEMPT_ENV,
    REGISTRY_CONFIG_PATH,
    DaggerOrasRunner,
    ProviderExecutionPlan,
    ProviderObservation,
)

from portfolio_delivery.domain.stages import OrasInvocation

REGISTRY_IMAGE = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)


async def _probe() -> None:
    await dagger.connect()
    try:
        canary, _config, secret = await _actual_secret()
        recorder = ExecutionRecorder()
        runner = _runner(recorder, secret)
        invocation = OrasInvocation(("oras", "manifest", "fetch", "registry:5000/r:t"))
        plan = runner._plan(invocation, "attempt-finalized")
        runner._record(invocation, plan)
        runner._execute(invocation, plan)
        _assert_surface(runner.observations[0], recorder, plan, canary)
    finally:
        await dagger.close()


async def _actual_secret() -> tuple[str, str, Secret]:
    canary = f"task8-finalized-secret-{secrets.token_hex(8)}"
    config = json.dumps({"auths": {}, "credHelpers": {"unused.invalid": canary}})
    secret = dag.set_secret("task8-finalized-config", config)
    assert await secret.plaintext() == config
    return canary, config, secret


@dataclass(slots=True)
class ExecutionRecorder:
    environment: tuple[str, str] | None = None
    argv: tuple[str, ...] = ()

    def with_directory(self, path: str, directory: object) -> ExecutionRecorder:
        return self

    def with_env_variable(self, name: str, value: str) -> ExecutionRecorder:
        self.environment = (name, value)
        return self

    def with_exec(self, argv: list[str], **_: object) -> ExecutionRecorder:
        self.argv = tuple(argv)
        return self


def _runner(recorder: ExecutionRecorder, secret: Secret) -> DaggerOrasRunner:
    service = dag.container().from_(REGISTRY_IMAGE).as_service()
    return DaggerOrasRunner(
        dag,
        "registry:5000/portfolio/envelopes",
        registry_config=secret,
        registry_service=service,
        previous_container=cast(Container, recorder),
    )


def _assert_surface(
    surface: ProviderObservation,
    recorder: ExecutionRecorder,
    execution: ProviderExecutionPlan,
    canary: str,
) -> None:
    assert surface.argv == recorder.argv == execution.argv
    assert recorder.environment == (ATTEMPT_ENV, "attempt-finalized")
    assert REGISTRY_CONFIG_PATH in surface.argv and "--plain-http" in surface.argv
    assert surface.capture.stdout in surface.argv
    assert surface.cache_mounts == execution.cache_mounts == ()
    assert canary not in repr(surface)


if __name__ == "__main__":
    asyncio.run(_probe())
