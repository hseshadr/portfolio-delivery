"""Record the actual finalized ORAS execution surface with a real typed Secret."""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass, field
from typing import cast

import dagger
from dagger import Client, Container, Directory, ReturnType, Secret, Service, dag
from portfolio_delivery_dagger.oras import (
    ATTEMPT_ENV,
    ORAS_IMAGE,
    REGISTRY_CONFIG_PATH,
    WORKDIR,
    DaggerOrasRunner,
    ProviderExecutionPlan,
    ProviderObservation,
)

from portfolio_delivery.domain.stages import OrasInvocation

REGISTRY_IMAGE = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
EXPECTED_DIRECTORY_CALLS = 2


async def _probe() -> None:
    await dagger.connect()
    try:
        await _run_probe()
    finally:
        await dagger.close()


async def _run_probe() -> None:
    canary, _config, secret = await _actual_secret()
    service = dag.container().from_(REGISTRY_IMAGE).as_service()
    recorder = ExecutionRecorder()
    client = RecordingClient(recorder)
    runner = _runner(client, secret, service)
    invocation = OrasInvocation(("oras", "manifest", "fetch", "registry:5000/r:t"))
    plan = runner._plan(invocation, "attempt-finalized")
    runner._record(invocation, plan)
    runner._execute(invocation, plan)
    _assert_base_configuration(recorder, client, plan, secret, service)
    _assert_execution(runner.observations[0], recorder, plan, canary)


async def _actual_secret() -> tuple[str, str, Secret]:
    canary = f"task8-finalized-secret-{secrets.token_hex(8)}"
    config = json.dumps({"auths": {}, "credHelpers": {"unused.invalid": canary}})
    secret = dag.set_secret("task8-finalized-config", config)
    assert await secret.plaintext() == config
    return canary, config, secret


@dataclass(frozen=True, slots=True)
class SecretMount:
    path: str
    secret: Secret
    owner: str
    mode: int


@dataclass(frozen=True, slots=True)
class ServiceBinding:
    alias: str
    service: Service


@dataclass(frozen=True, slots=True)
class ExecCall:
    argv: tuple[str, ...]
    redirect_stdout: str
    redirect_stderr: str
    expect: ReturnType


@dataclass(slots=True)
class ExecutionRecorder:
    images: list[str] = field(default_factory=list)
    directory_mounts: list[str] = field(default_factory=list)
    workdirs: list[str] = field(default_factory=list)
    secret_mounts: list[SecretMount] = field(default_factory=list)
    service_bindings: list[ServiceBinding] = field(default_factory=list)
    environment: tuple[str, str] | None = None
    exec_call: ExecCall | None = None
    mounted_cache_calls: int = 0

    def from_(self, image: str) -> ExecutionRecorder:
        self.images.append(image)
        return self

    def with_directory(self, path: str, directory: object) -> ExecutionRecorder:
        self.directory_mounts.append(path)
        return self

    def with_workdir(self, path: str) -> ExecutionRecorder:
        self.workdirs.append(path)
        return self

    def with_mounted_secret(
        self, path: str, secret: Secret, *, owner: str, mode: int
    ) -> ExecutionRecorder:
        self.secret_mounts.append(SecretMount(path, secret, owner, mode))
        return self

    def with_service_binding(self, alias: str, service: Service) -> ExecutionRecorder:
        self.service_bindings.append(ServiceBinding(alias, service))
        return self

    def with_env_variable(self, name: str, value: str) -> ExecutionRecorder:
        self.environment = (name, value)
        return self

    def with_exec(
        self,
        argv: list[str],
        *,
        redirect_stdout: str,
        redirect_stderr: str,
        expect: ReturnType,
    ) -> ExecutionRecorder:
        self.exec_call = ExecCall(tuple(argv), redirect_stdout, redirect_stderr, expect)
        return self

    def with_mounted_cache(self, path: str, cache: object) -> ExecutionRecorder:
        self.mounted_cache_calls += 1
        return self


@dataclass(slots=True)
class RecordingClient:
    recorder: ExecutionRecorder
    container_calls: int = 0
    directory_calls: int = 0
    cache_volume_calls: int = 0

    def container(self) -> Container:
        self.container_calls += 1
        return cast(Container, self.recorder)

    def directory(self) -> Directory:
        self.directory_calls += 1
        return cast(Directory, object())

    def cache_volume(self, key: str) -> object:
        self.cache_volume_calls += 1
        return object()


def _runner(client: RecordingClient, secret: Secret, service: Service) -> DaggerOrasRunner:
    return DaggerOrasRunner(
        cast(Client, client),
        "registry:5000/portfolio/envelopes",
        registry_config=secret,
        registry_service=service,
    )


def _assert_execution(
    surface: ProviderObservation,
    recorder: ExecutionRecorder,
    execution: ProviderExecutionPlan,
    canary: str,
) -> None:
    call = recorder.exec_call
    assert call is not None
    assert surface.argv == call.argv == execution.argv
    assert recorder.environment == (ATTEMPT_ENV, "attempt-finalized")
    _assert_exec_call(call, execution)
    assert REGISTRY_CONFIG_PATH in surface.argv and "--plain-http" in surface.argv
    assert surface.capture.stdout in surface.argv
    assert surface.cache_mounts == execution.cache_mounts == ()
    assert canary not in repr(surface)


def _assert_exec_call(call: ExecCall, execution: ProviderExecutionPlan) -> None:
    assert call.redirect_stdout == execution.capture.process_stdout
    assert call.redirect_stderr == execution.capture.stderr
    assert call.expect is ReturnType.ANY


def _assert_base_configuration(
    recorder: ExecutionRecorder,
    client: RecordingClient,
    execution: ProviderExecutionPlan,
    secret: Secret,
    service: Service,
) -> None:
    assert recorder.images == [ORAS_IMAGE]
    assert recorder.directory_mounts == [WORKDIR, execution.capture.directory]
    assert recorder.workdirs == [WORKDIR]
    assert recorder.secret_mounts == [SecretMount(REGISTRY_CONFIG_PATH, secret, "0:0", 0o400)]
    assert recorder.service_bindings == [ServiceBinding("registry", service)]
    assert client.container_calls == 1
    assert client.directory_calls == EXPECTED_DIRECTORY_CALLS
    assert client.cache_volume_calls == recorder.mounted_cache_calls == 0


if __name__ == "__main__":
    asyncio.run(_probe())
