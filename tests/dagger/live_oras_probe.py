"""Exercise the public Dagger pipeline against one storage-less Registry service."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Awaitable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast

import dagger
from dagger import Directory, File, Secret, Service, dag
from portfolio_delivery_dagger.dto import (
    BuildEnvelope,
    PrequalifiedBuild,
    QualifiedEnvelope,
    ReleaseSource,
    SignedBuild,
    SnapshottedSource,
    UnsignedBuild,
)
from portfolio_delivery_dagger.main import PortfolioDelivery, _oras_runner, _scan_directory
from portfolio_delivery_dagger.oras import (
    DaggerOrasRunner,
    ProviderObservation,
    QualifiedEnvelopeRef,
    qualified_bundle,
    restored_dto,
    validate_release_id,
)

from portfolio_delivery.adapters.oras import OrasAdapter
from portfolio_delivery.domain.stages import EnvelopeBundle
from portfolio_delivery.domain.stages import StoredEnvelope as CoreStoredEnvelope

REGISTRY_IMAGE = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
REPOSITORY = "registry:5000/portfolio/envelopes"
RELEASE_ID = "portfolio-delivery:v0.1.0"


@dataclass(frozen=True, slots=True)
class ProbePaths:
    source: Path
    inventory: Path
    build_input: Path
    evidence: Path
    artifacts: Path
    sboms: Path
    output: Path
    registry_config: Path | None
    run_id: str


@dataclass(frozen=True, slots=True)
class Metrics:
    execution_count: int
    inspection_count: int
    push_count: int
    attempt_ids: list[str]


@dataclass(frozen=True, slots=True)
class LiveMetrics:
    envelope_uri: str
    first_digest: str
    second_digest: str
    first: Metrics
    second: Metrics
    restore_one: Metrics
    restore_two: Metrics
    observations: tuple[ProviderObservation, ...]
    registry_stdout: str
    registry_stderr: str


@dataclass(frozen=True, slots=True)
class RunnerMark:
    execution_count: int
    inspection_count: int
    push_count: int
    observation_count: int


@dataclass(frozen=True, slots=True)
class DirectPlan:
    input_file: File
    artifact_directory: Directory
    sbom_directory: Directory
    check_file: File

    async def include_paths(self) -> list[str]:
        return ["src/**"]

    async def exclude_paths(self) -> list[str]:
        return ["__none__"]

    def build(self, source: Directory, manifest: File, input_snapshot_sha256: str) -> DirectPlan:
        return self

    def build_input(self) -> File:
        return self.input_file

    def artifacts(self) -> Directory:
        return self.artifact_directory

    def sboms(self) -> Directory:
        return self.sbom_directory

    def prequalify(
        self, build_input: File, artifacts: Directory, sboms: Directory, snapshot: str
    ) -> DirectPlan:
        return self

    def qualify(self, envelope: File, envelope_sha256: str) -> DirectPlan:
        evidence = dag.file("qualification-input.json", _qualification_json(envelope_sha256))
        return DirectPlan(self.input_file, self.artifact_directory, self.sbom_directory, evidence)

    async def passed(self) -> bool:
        return True

    def evidence(self) -> File:
        return self.check_file

    def sign(self, build_input: File, artifacts: Directory, sboms: Directory) -> DirectPlan:
        return self

    async def signature_path(self) -> str | None:
        return None


async def _probe(paths: ProbePaths) -> None:
    await dagger.connect()
    try:
        qualified = await _qualified(paths)
        service = _registry_service()
        secret = _registry_secret(paths.registry_config)
        service = await service.start()
        try:
            document, restored, repeated = await _effects(qualified, service, secret, paths.run_id)
            await _export_outputs(paths.output, qualified, restored, repeated)
            sys.stdout.write(json.dumps(asdict(document), sort_keys=True, separators=(",", ":")))
        finally:
            await service.stop()
    finally:
        await dagger.close()


async def _qualified(paths: ProbePaths) -> QualifiedEnvelope:
    source, inventory, build_input, plan = _pipeline_inputs(paths)
    delivery = PortfolioDelivery()
    release_call = delivery.version(source, inventory, ["src/**"], ["__none__"], build_input)
    release = await cast(Awaitable[ReleaseSource], release_call)
    snapshot = await cast(Awaitable[SnapshottedSource], delivery.snapshot(release, plan))
    unsigned = await cast(Awaitable[UnsignedBuild], delivery.build(snapshot, plan))
    checked = await cast(Awaitable[PrequalifiedBuild], delivery.prequalify(unsigned, plan))
    signed = await cast(Awaitable[SignedBuild], delivery.sign(checked, plan))
    envelope = await cast(Awaitable[BuildEnvelope], delivery.envelope(signed))
    return await cast(Awaitable[QualifiedEnvelope], delivery.qualify(envelope, plan))


def _pipeline_inputs(paths: ProbePaths) -> tuple[Directory, File, File, DirectPlan]:
    source = _dagger_directory(paths.source)
    inventory = _dagger_file(paths.inventory)
    build_input = _dagger_file(paths.build_input)
    plan = DirectPlan(
        build_input,
        _dagger_directory(paths.artifacts),
        _dagger_directory(paths.sboms),
        _dagger_file(paths.evidence),
    )
    return source, inventory, build_input, plan


def _dagger_directory(root: Path) -> Directory:
    directory = dag.directory()
    for path in sorted(root.rglob("*")):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            directory = directory.with_file(relative, _dagger_file(path))
    return directory


def _dagger_file(path: Path) -> File:
    return dag.file(path.name, path.read_text(encoding="utf-8"))


def _registry_service() -> Service:
    container = dag.container().from_(REGISTRY_IMAGE)
    container = container.with_file(
        "/log-entrypoint", dag.file("entrypoint", _log_entrypoint()), permissions=0o755
    )
    container = container.with_file(
        "/serve-stdout", dag.file("stdout", _log_server("stdout")), permissions=0o755
    )
    container = container.with_file(
        "/serve-stderr", dag.file("stderr", _log_server("stderr")), permissions=0o755
    )
    return _exposed_registry(container.with_entrypoint(["/log-entrypoint"]))


def _exposed_registry(container: dagger.Container) -> Service:
    return (
        container.with_exposed_port(5000)
        .with_exposed_port(5101)
        .with_exposed_port(5102)
        .as_service()
    )


def _log_entrypoint() -> str:
    return """#!/bin/sh
set -eu
mkdir -p /tmp/registry-logs
: > /tmp/registry-logs/stdout
: > /tmp/registry-logs/stderr
busybox nc -lk -p 5101 -e /serve-stdout &
busybox nc -lk -p 5102 -e /serve-stderr &
exec /entrypoint.sh /etc/distribution/config.yml \
  >>/tmp/registry-logs/stdout 2>>/tmp/registry-logs/stderr
"""


def _log_server(name: str) -> str:
    return f"""#!/bin/sh
path=/tmp/registry-logs/{name}
snapshot=/tmp/registry-logs/{name}-$$
tail -c 32768 "$path" > "$snapshot"
length=$(wc -c < "$snapshot")
printf 'HTTP/1.1 200 OK\\r\\n'
printf 'Content-Type: text/plain\\r\\n'
printf 'Content-Length: %s\\r\\n' "$length"
printf 'Connection: close\\r\\n\\r\\n'
cat "$snapshot"
rm -f "$snapshot"
"""


def _registry_secret(path: Path | None) -> Secret | None:
    if path is None:
        return None
    return dag.set_secret("task8-registry-config", path.read_text(encoding="utf-8"))


async def _effects(
    qualified: QualifiedEnvelope,
    service: Service,
    secret: Secret | None,
    run_id: str,
) -> tuple[LiveMetrics, QualifiedEnvelopeRef, QualifiedEnvelopeRef]:
    core = await qualified_bundle(qualified, _scan_directory)
    runner = _oras_runner(qualified, core, REPOSITORY, secret, service)
    runner.service_started = True
    adapter = OrasAdapter(runner, REPOSITORY)
    first, first_metrics = await _persist(adapter, runner, core, _attempt("attempt-one", run_id))
    second, second_metrics = await _persist(adapter, runner, core, _attempt("attempt-two", run_id))
    restore_one_id = _attempt("restore-attempt-one", run_id)
    restore_two_id = _attempt("restore-attempt-two", run_id)
    restored, restore_one = await _restore(adapter, runner, first, restore_one_id)
    repeated, restore_two = await _restore(adapter, runner, first, restore_two_id)
    stored = (first, second)
    metrics = (first_metrics, second_metrics, restore_one, restore_two)
    stdout, stderr = await _registry_logs(service)
    document = _metrics_document(stored, metrics, tuple(runner.observations), stdout, stderr)
    return document, restored, repeated


async def _persist(
    adapter: OrasAdapter,
    runner: DaggerOrasRunner,
    bundle: EnvelopeBundle,
    attempt_id: str,
) -> tuple[CoreStoredEnvelope, Metrics]:
    before = _mark(runner)
    stored = await adapter.persist(bundle, attempt_id)
    return stored, _metric_delta(runner, before)


async def _restore(
    adapter: OrasAdapter,
    runner: DaggerOrasRunner,
    stored: CoreStoredEnvelope,
    attempt_id: str,
) -> tuple[QualifiedEnvelopeRef, Metrics]:
    before = _mark(runner)
    bundle = await adapter.restore(stored.reference, attempt_id)
    validate_release_id(bundle, RELEASE_ID)
    uri = f"{stored.reference.repository}:{stored.reference.tag}"
    restored = restored_dto(runner, RELEASE_ID, uri, stored.manifest_sha256.value, bundle)
    return restored, _metric_delta(runner, before)


def _metrics_document(
    stored: tuple[CoreStoredEnvelope, CoreStoredEnvelope],
    metrics: tuple[Metrics, Metrics, Metrics, Metrics],
    observations: tuple[ProviderObservation, ...],
    stdout: str,
    stderr: str,
) -> LiveMetrics:
    first, second = stored
    first_metrics, second_metrics, restore_one, restore_two = metrics
    uri = f"{first.reference.repository}:{first.reference.tag}"
    return LiveMetrics(
        uri,
        first.manifest_sha256.value,
        second.manifest_sha256.value,
        first_metrics,
        second_metrics,
        restore_one,
        restore_two,
        observations,
        stdout,
        stderr,
    )


async def _registry_logs(service: Service) -> tuple[str, str]:
    reader = dag.container().from_(REGISTRY_IMAGE).with_service_binding("registry-logs", service)
    return await asyncio.gather(_registry_log(reader, 5101), _registry_log(reader, 5102))


async def _registry_log(container: dagger.Container, port: int) -> str:
    request = "printf 'GET / HTTP/1.0\\r\\nHost: registry-logs\\r\\n\\r\\n'"
    script = f'{request} | busybox nc -w 5 registry-logs "$1"'
    response = await container.with_exec(["sh", "-c", script, "log-reader", str(port)]).stdout()
    return response.split("\r\n\r\n", 1)[-1]


def _mark(runner: DaggerOrasRunner) -> RunnerMark:
    return RunnerMark(
        runner.execution_count,
        runner.inspection_count,
        runner.push_count,
        len(runner.observations),
    )


def _metric_delta(runner: DaggerOrasRunner, before: RunnerMark) -> Metrics:
    return Metrics(
        runner.execution_count - before.execution_count,
        runner.inspection_count - before.inspection_count,
        runner.push_count - before.push_count,
        [item.attempt_id for item in runner.observations[before.observation_count :]],
    )


def _attempt(operation: str, run_id: str) -> str:
    return f"{operation}-{run_id}"


async def _export_outputs(
    root: Path,
    qualified: QualifiedEnvelope,
    restored: QualifiedEnvelopeRef,
    repeated: QualifiedEnvelopeRef,
) -> None:
    await _export_original(root, qualified)
    await _export_restored(root, restored, repeated)


async def _export_original(root: Path, qualified: QualifiedEnvelope) -> None:
    await qualified.envelope.export(str(root / "original-build-envelope.v1.json"))
    await qualified.qualification.export(str(root / "original-qualification-record.v1.json"))
    await qualified.artifacts.export(str(root / "original-artifacts"))
    await qualified.sboms.export(str(root / "original-sboms"))
    await qualified.input_snapshot_manifest.export(str(root / "input-snapshot.v1.json"))
    evidence_path = root / "prequalification-evidence.v1.json"
    await qualified.prequalification_evidence.export(str(evidence_path))
    archive_call = PortfolioDelivery().publish_inputs(qualified)
    archive = await cast(Awaitable[File], archive_call)
    await archive.export(str(root / "publish-inputs.tar"))


async def _export_restored(
    root: Path, restored: QualifiedEnvelopeRef, repeated: QualifiedEnvelopeRef
) -> None:
    await restored.envelope.export(str(root / "build-envelope.v1.json"))
    await restored.qualification.export(str(root / "qualification-record.v1.json"))
    await restored.artifacts.export(str(root / "artifacts"))
    await restored.sboms.export(str(root / "sboms"))
    await repeated.envelope.export(str(root / "repeat-build-envelope.v1.json"))
    await repeated.qualification.export(str(root / "repeat-qualification-record.v1.json"))
    await repeated.artifacts.export(str(root / "repeat-artifacts"))
    await repeated.sboms.export(str(root / "repeat-sboms"))


def _paths() -> ProbePaths:
    parser = argparse.ArgumentParser()
    for name in ("source", "inventory", "build-input", "evidence", "artifacts", "sboms", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--registry-config", type=Path)
    parser.add_argument("--run-id", required=True)
    values = parser.parse_args()
    return ProbePaths(
        values.source,
        values.inventory,
        values.build_input,
        values.evidence,
        values.artifacts,
        values.sboms,
        values.output,
        values.registry_config,
        values.run_id,
    )


def _qualification_json(digest: str) -> str:
    return (
        '{"qualificationEvidence":[{"kind":"policy","name":"release",'
        f'"status":"passed","subject":"{digest}"}}],'
        f'"schemaVersion":"v1","subject":"{digest}"}}\n'
    )


if __name__ == "__main__":
    asyncio.run(_probe(_paths()))
