"""External project plan used only by live Dagger contract tests."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass

import dagger
from dagger import dag, field, function, object_type

PYTHON_IMAGE = (
    "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)
ORAS_IMAGE = (
    "ghcr.io/oras-project/oras@sha256:"
    "a4c54befd87d0366e0ba3ac3a9536a5288c8a3735acd3b635cdace59a2c559c8"
)
REGISTRY_IMAGE = (
    "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
)
REPOSITORY = "registry:5000/portfolio/envelopes"
RELEASE_ID = "portfolio-delivery:v0.1.0"
MAX_LOG_CHARACTERS = 131_072


@dataclass(frozen=True, slots=True)
class PublicMetrics:
    execution_count: int
    inspection_count: int
    push_count: int
    attempt_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PublicSmoke:
    envelope_uri: str
    envelope_bytes_sha256: str
    first_digest: str
    second_digest: str
    first: PublicMetrics
    second: PublicMetrics
    restore_one: PublicMetrics
    restore_two: PublicMetrics
    exact_bytes: bool
    object_ids: tuple[str, ...]
    registry_stdout: str
    registry_stderr: str


@dataclass(kw_only=True)
@object_type
class FixturePlan(
    dagger.PortfolioDeliveryBuildOutput,
    dagger.PortfolioDeliveryBuildPlan,
    dagger.PortfolioDeliveryCheckOutput,
    dagger.PortfolioDeliveryInputSnapshotPlan,
    dagger.PortfolioDeliverySigningOutput,
    dagger.PortfolioDeliverySigningPlan,
    dagger.PortfolioDeliveryVerificationPlan,
):
    input_file: dagger.File = field()
    artifact_directory: dagger.Directory = field()
    sbom_directory: dagger.Directory = field()
    check_file: dagger.File = field()

    @function
    def build(
        self, source: dagger.Directory, manifest: dagger.File, input_snapshot_sha256: str
    ) -> FixturePlan:
        return self

    @function
    def build_input(self) -> dagger.File:
        return self.input_file

    @function
    def artifacts(self) -> dagger.Directory:
        return self.artifact_directory

    @function
    def sboms(self) -> dagger.Directory:
        return self.sbom_directory

    @function
    def prequalify(
        self,
        build_input: dagger.File,
        artifacts: dagger.Directory,
        sboms: dagger.Directory,
        input_snapshot_sha256: str,
    ) -> FixturePlan:
        return self

    @function
    def qualify(self, envelope: dagger.File, envelope_sha256: str) -> FixturePlan:
        return self._qualification(envelope_sha256)

    @function
    async def passed(self) -> bool:
        return True

    @function
    def evidence(self) -> dagger.File:
        return self.check_file

    @function
    def sign(
        self, build_input: dagger.File, artifacts: dagger.Directory, sboms: dagger.Directory
    ) -> FixturePlan:
        return self

    @function
    def signature_path(self) -> str | None:
        return None

    def _qualification(self, digest: str) -> FixturePlan:
        evidence = dag.file("qualification-input.json", _qualification_json(digest))
        return FixturePlan(
            input_file=self.input_file,
            artifact_directory=self.artifact_directory,
            sbom_directory=self.sbom_directory,
            check_file=evidence,
        )


@object_type
class Task7LiveFixture:
    """Construct one external plan object for shell composition."""

    @function
    def plan(
        self,
        build_input: dagger.File,
        artifacts: dagger.Directory,
        sboms: dagger.Directory,
        prequalification_evidence: dagger.File,
        symlink_target: str | None = None,
    ) -> FixturePlan:
        return FixturePlan(
            input_file=build_input,
            artifact_directory=_artifact_directory(artifacts, symlink_target),
            sbom_directory=sboms,
            check_file=prequalification_evidence,
        )

    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]
    async def public_oras_smoke(  # noqa: PLR0913,PLR0917
        self,
        source: dagger.Directory,
        inventory: dagger.File,
        build_input: dagger.File,
        artifacts: dagger.Directory,
        sboms: dagger.Directory,
        prequalification_evidence: dagger.File,
        registry_config: dagger.Secret,
        run_id: str,
    ) -> dagger.File:
        plan = dag.task8_plan_fixture().plan(
            build_input, artifacts, sboms, prequalification_evidence
        )
        qualified = _public_qualified(source, inventory, build_input, plan)
        qualified, qualified_id = await _load_qualified(qualified)
        service = await _registry_service().start()
        try:
            smoke = await _public_effects(qualified, qualified_id, registry_config, service, run_id)
        finally:
            await service.stop()
        return dag.file("public-oras-smoke.json", json.dumps(smoke, default=_json_default))


def _public_qualified(
    source: dagger.Directory,
    inventory: dagger.File,
    build_input: dagger.File,
    plan: dagger.Task8PlanFixtureFixturePlan,
) -> dagger.PortfolioDeliveryQualifiedEnvelope:
    delivery = dag.portfolio_delivery()
    release = delivery.version(source, inventory, ["src/**"], ["__none__"], build_input)
    snapshot = delivery.snapshot(release, plan)
    unsigned = delivery.build(snapshot, plan)
    prequalified = delivery.prequalify(unsigned, plan)
    signed = delivery.sign(prequalified, plan)
    envelope = delivery.envelope(signed)
    return delivery.qualify(envelope, plan)


async def _load_qualified(
    qualified: dagger.PortfolioDeliveryQualifiedEnvelope,
) -> tuple[dagger.PortfolioDeliveryQualifiedEnvelope, str]:
    identifier = await qualified.id()
    typed = dagger.PortfolioDeliveryQualifiedEnvelopeID(identifier)
    return dag.load_portfolio_delivery_qualified_envelope_from_id(typed), identifier


async def _public_effects(
    qualified: dagger.PortfolioDeliveryQualifiedEnvelope,
    qualified_id: str,
    secret: dagger.Secret,
    service: dagger.Service,
    run_id: str,
) -> PublicSmoke:
    first, first_id = await _public_persist(qualified, secret, service, f"attempt-one-{run_id}")
    second, second_id = await _public_persist(qualified, secret, service, f"attempt-two-{run_id}")
    restored, restored_id = await _public_restore(
        first, secret, service, f"restore-attempt-one-{run_id}"
    )
    repeated, repeated_id = await _public_restore(
        first, secret, service, f"restore-attempt-two-{run_id}"
    )
    exact = await _exact_public_bytes(qualified, restored, repeated)
    envelope_sha256 = await _file_sha256(qualified.envelope())
    stdout, stderr = await _registry_logs(service)
    return await _public_document(
        (first, second),
        (restored, repeated),
        envelope_sha256,
        exact,
        (qualified_id, first_id, second_id, restored_id, repeated_id),
        stdout,
        stderr,
    )


async def _public_persist(
    qualified: dagger.PortfolioDeliveryQualifiedEnvelope,
    secret: dagger.Secret,
    service: dagger.Service,
    attempt_id: str,
) -> tuple[dagger.PortfolioDeliveryStoredEnvelope, str]:
    pending = dag.portfolio_delivery().persist_oci(
        qualified, REPOSITORY, attempt_id, registry_config=secret, registry_service=service
    )
    identifier = await pending.id()
    typed = dagger.PortfolioDeliveryStoredEnvelopeID(identifier)
    return dag.load_portfolio_delivery_stored_envelope_from_id(typed), identifier


async def _public_restore(
    stored: dagger.PortfolioDeliveryStoredEnvelope,
    secret: dagger.Secret,
    service: dagger.Service,
    attempt_id: str,
) -> tuple[dagger.PortfolioDeliveryQualifiedEnvelopeRef, str]:
    uri, digest = await asyncio.gather(stored.envelope_uri(), stored.envelope_digest())
    pending = dag.portfolio_delivery().restore_qualified(
        RELEASE_ID, uri, digest, attempt_id, registry_config=secret, registry_service=service
    )
    identifier = await pending.id()
    typed = dagger.PortfolioDeliveryQualifiedEnvelopeRefID(identifier)
    return dag.load_portfolio_delivery_qualified_envelope_ref_from_id(typed), identifier


async def _public_document(
    stored: tuple[dagger.PortfolioDeliveryStoredEnvelope, dagger.PortfolioDeliveryStoredEnvelope],
    restored: tuple[
        dagger.PortfolioDeliveryQualifiedEnvelopeRef,
        dagger.PortfolioDeliveryQualifiedEnvelopeRef,
    ],
    envelope_sha256: str,
    exact: bool,
    object_ids: tuple[str, ...],
    stdout: str,
    stderr: str,
) -> PublicSmoke:
    first, second = stored
    metrics = await asyncio.gather(*(_metrics(item) for item in (*stored, *restored)))
    uri, first_digest, second_digest = await asyncio.gather(
        first.envelope_uri(), first.envelope_digest(), second.envelope_digest()
    )
    return PublicSmoke(
        uri,
        envelope_sha256,
        first_digest,
        second_digest,
        *metrics,
        exact,
        object_ids,
        stdout,
        stderr,
    )


async def _metrics(
    item: dagger.PortfolioDeliveryStoredEnvelope | dagger.PortfolioDeliveryQualifiedEnvelopeRef,
) -> PublicMetrics:
    values = await asyncio.gather(
        item.provider_execution_count(),
        item.provider_inspection_count(),
        item.provider_push_count(),
        item.attempt_ids(),
    )
    execution, inspection, pushes, attempts = values
    return PublicMetrics(execution, inspection, pushes, tuple(attempts))


async def _exact_public_bytes(
    original: dagger.PortfolioDeliveryQualifiedEnvelope,
    restored: dagger.PortfolioDeliveryQualifiedEnvelopeRef,
    repeated: dagger.PortfolioDeliveryQualifiedEnvelopeRef,
) -> bool:
    pairs = _exact_pairs(original, restored, repeated)
    return all(await asyncio.gather(*(_same_file(left, right) for left, right in pairs)))


def _exact_pairs(
    original: dagger.PortfolioDeliveryQualifiedEnvelope,
    restored: dagger.PortfolioDeliveryQualifiedEnvelopeRef,
    repeated: dagger.PortfolioDeliveryQualifiedEnvelopeRef,
) -> tuple[tuple[dagger.File, dagger.File], ...]:
    artifact = "artifacts/portfolio_delivery-0.1.0-py3-none-any.whl"
    sbom = "sbom/package.cdx.json"
    originals = (
        original.envelope(),
        original.qualification(),
        original.artifacts(),
        original.sboms(),
    )
    return (
        (originals[0], restored.envelope()),
        (originals[0], repeated.envelope()),
        (originals[1], restored.qualification()),
        (originals[1], repeated.qualification()),
        (originals[2].file(artifact), restored.artifacts().file(artifact)),
        (originals[2].file(artifact), repeated.artifacts().file(artifact)),
        (originals[3].file(sbom), restored.sboms().file(sbom)),
        (originals[3].file(sbom), repeated.sboms().file(sbom)),
    )


async def _same_file(left: dagger.File, right: dagger.File) -> bool:
    checked = (
        dag.container()
        .from_(ORAS_IMAGE)
        .with_mounted_file("/left", left)
        .with_mounted_file("/right", right)
        .with_exec(["cmp", "-s", "/left", "/right"], expect=dagger.ReturnType.ANY)
    )
    return await checked.exit_code() == 0


async def _file_sha256(source: dagger.File) -> str:
    content = (await source.contents()).encode()
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _registry_service() -> dagger.Service:
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
    container = container.with_entrypoint(["/log-entrypoint"])
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
exec /entrypoint.sh /etc/distribution/config.yml >>/tmp/registry-logs/stdout 2>>/tmp/registry-logs/stderr
"""


def _log_server(name: str) -> str:
    return f"""#!/bin/sh
path=/tmp/registry-logs/{name}
snapshot=/tmp/registry-logs/{name}-$$
tail -c 32768 "$path" > "$snapshot"
length=$(wc -c < "$snapshot")
printf 'HTTP/1.1 200 OK\\r\\nContent-Type: text/plain\\r\\nContent-Length: %s\\r\\nConnection: close\\r\\n\\r\\n' "$length"
cat "$snapshot"
rm -f "$snapshot"
"""


async def _registry_logs(service: dagger.Service) -> tuple[str, str]:
    reader = dag.container().from_(REGISTRY_IMAGE).with_service_binding("registry-logs", service)
    stdout, stderr = await asyncio.gather(_registry_log(reader, 5101), _registry_log(reader, 5102))
    return stdout[-MAX_LOG_CHARACTERS:], stderr[-MAX_LOG_CHARACTERS:]


async def _registry_log(container: dagger.Container, port: int) -> str:
    script = "printf 'GET / HTTP/1.0\\r\\nHost: registry-logs\\r\\n\\r\\n' | busybox nc -w 5 registry-logs \"$1\""
    response = await container.with_exec(["sh", "-c", script, "log-reader", str(port)]).stdout()
    return response.split("\r\n\r\n", 1)[-1]


def _json_default(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return {name: getattr(value, name) for name in value.__dataclass_fields__}
    raise TypeError(f"cannot serialize {type(value).__name__}")


def _qualification_json(digest: str) -> str:
    return (
        '{"qualificationEvidence":[{"kind":"policy","name":"release",'
        '"status":"passed","subject":"%s"}],'
        '"schemaVersion":"v1","subject":"%s"}\n'
    ) % (
        digest,
        digest,
    )


def _artifact_directory(
    artifacts: dagger.Directory, symlink_target: str | None
) -> dagger.Directory:
    if symlink_target is None:
        return artifacts
    return (
        dag.container()
        .from_(PYTHON_IMAGE)
        .with_exec(["mkdir", "-p", "/outputs/artifacts"])
        .with_exec(["ln", "-s", symlink_target, "/outputs/artifacts/outside"])
        .directory("/outputs")
    )
