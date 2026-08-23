"""Live stable-engine contract tests for the Phase 1 Dagger module."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import pytest

ROOT: Final = Path(__file__).parents[2]
FIXTURE: Final = ROOT / "tests/fixtures/envelope/input"
LIVE_FIXTURE: Final = ROOT / "tests/dagger/live_fixture"
INTROSPECTION_QUERY: Final = (
    '{ __type(name: "PortfolioDelivery") { fields { name args { name type { name kind } } } } }'
)
RETAINED_PROVENANCE_QUERY: Final = (
    '{ qualified: __type(name: "PortfolioDeliveryQualifiedEnvelope") { fields { name } } '
    'envelope: __type(name: "PortfolioDeliveryBuildEnvelope") { fields { name } } '
    'signed: __type(name: "PortfolioDeliverySignedBuild") { fields { name } } '
    'prequalified: __type(name: "PortfolioDeliveryPrequalifiedBuild") { fields { name } } '
    'unsigned: __type(name: "PortfolioDeliveryUnsignedBuild") { fields { name } } '
    'snapshot: __type(name: "PortfolioDeliverySnapshottedSource") { fields { name } } }'
)
PROVIDER_OBSERVATION_QUERY: Final = (
    '{ stored: __type(name: "PortfolioDeliveryStoredEnvelope") { fields { name } } '
    'restored: __type(name: "PortfolioDeliveryQualifiedEnvelopeRef") { fields { name } } }'
)
DAGGER_CLI: Final = shutil.which("dagger")
PHASE_ONE_FUNCTIONS: Final = frozenset(
    {
        "check",
        "version",
        "snapshot",
        "build",
        "prequalify",
        "sign",
        "envelope",
        "qualify",
        "publish-inputs",
        "persist-oci",
        "restore-qualified",
    }
)


@dataclass(frozen=True, slots=True)
class PipelineFiles:
    source: Path
    inventory: Path
    build_input: Path
    evidence: Path
    artifacts: Path
    sboms: Path
    output: Path


def dagger_cli() -> str:
    if DAGGER_CLI is None:
        raise RuntimeError("the pinned Dagger CLI is required for live module tests")
    return DAGGER_CLI


def run_dagger_functions_json() -> object:
    result = subprocess.run(
        [dagger_cli(), "query", "--silent"],
        cwd=ROOT,
        input=INTROSPECTION_QUERY,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def run_dagger_query(query: str) -> object:
    result = subprocess.run(
        [dagger_cli(), "query", "--silent"],
        cwd=ROOT,
        input=query,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def root_function_names(result: object) -> set[str]:
    root = cast(dict[str, object], result)["__type"]
    fields = cast(dict[str, object], root)["fields"]
    declarations = cast(list[dict[str, str]], fields)
    names = (item["name"] for item in declarations if item["name"] != "id")
    return {re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", name).lower() for name in names}


def snapshot_argument_names(result: object) -> set[str]:
    root = cast(dict[str, object], result)["__type"]
    fields = cast(list[dict[str, object]], cast(dict[str, object], root)["fields"])
    snapshot = next(item for item in fields if item["name"] == "snapshot")
    arguments = cast(list[dict[str, object]], snapshot["args"])
    return {cast(str, item["name"]) for item in arguments}


def root_function(result: object, name: str) -> dict[str, object]:
    root = cast(dict[str, object], result)["__type"]
    fields = cast(list[dict[str, object]], cast(dict[str, object], root)["fields"])
    return next(item for item in fields if item["name"] == name)


def argument_type(result: object, function_name: str, argument_name: str) -> dict[str, object]:
    function = root_function(result, function_name)
    arguments = cast(list[dict[str, object]], function["args"])
    argument = next(item for item in arguments if item["name"] == argument_name)
    return cast(dict[str, object], argument["type"])


def snapshot_sha256(source: Path) -> str:
    inventory, build_input = release_files(source)
    source_ref = f"src=$(host | directory --path={shlex.quote(str(source))})"
    inventory_ref = f"inv=$(host | file --path={shlex.quote(str(inventory))})"
    input_ref = f"input=$(host | file --path={shlex.quote(str(build_input))})"
    release = (
        'release=$(version --source="$src" --inventory="$inv" --build-input="$input" '
        "--include-paths='artifacts/**' --exclude-paths='artifacts/excluded.txt')"
    )
    pipeline = 'snapshot --release="$release" --plan="$release" | input-snapshot-sha-256'
    command = [
        dagger_cli(),
        "shell",
        "-s",
        "-c",
        "; ".join((source_ref, inventory_ref, input_ref, release, pipeline)),
    ]
    result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def release_files(source: Path) -> tuple[Path, Path]:
    entries = [
        inventory_entry(path, source) for path in sorted(source.rglob("*")) if not path.is_dir()
    ]
    inventory = source.parent / "source-inventory.v1.json"
    content = json.dumps({"entries": entries}, sort_keys=True, separators=(",", ":")) + "\n"
    inventory.write_text(content, encoding="utf-8")
    digest = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    document = json.loads((source / "build-input.json").read_text(encoding="utf-8"))
    document["source"]["sourceTreeSha256"] = digest
    for evidence in document["prequalificationEvidence"]:
        evidence["subject"] = digest
    build_input = source.parent / "build-input.json"
    build_input.write_text(json.dumps(document), encoding="utf-8")
    return inventory, build_input


def inventory_entry(path: Path, root: Path) -> dict[str, str | int]:
    link = path.is_symlink()
    content = os.readlink(path).encode() if link else path.read_bytes()
    return {
        "kind": "symlink" if link else "regular",
        "mode": "120000" if link else "100644",
        "path": path.relative_to(root).as_posix(),
        "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
        "size": len(content),
    }


def copied_fixture(tmp_path: Path) -> Path:
    source = tmp_path / "input"
    shutil.copytree(FIXTURE, source)
    return source


@pytest.fixture(scope="session")
def live_fixture() -> Path:
    subprocess.run([dagger_cli(), "develop"], cwd=LIVE_FIXTURE, check=True, capture_output=True)
    return LIVE_FIXTURE


def pipeline_files(tmp_path: Path) -> PipelineFiles:
    source = tmp_path / "source"
    artifacts = tmp_path / "outputs"
    sboms = tmp_path / "sboms"
    _write_pipeline_bytes(source, artifacts, sboms)
    inventory, digest = _pipeline_inventory(source, tmp_path)
    build_input = _pipeline_document(tmp_path, digest, artifacts, sboms)
    evidence = _pipeline_evidence(tmp_path, digest)
    return PipelineFiles(
        source,
        inventory,
        build_input,
        evidence,
        artifacts,
        sboms,
        tmp_path / "publish-inputs.tar",
    )


def _write_pipeline_bytes(source: Path, artifacts: Path, sboms: Path) -> None:
    (source / "src").mkdir(parents=True)
    (artifacts / "artifacts").mkdir(parents=True)
    (sboms / "sbom").mkdir(parents=True)
    (source / "src/app.py").write_bytes(b"app")
    (artifacts / "artifacts/package.whl").write_bytes(b"wheel")
    (sboms / "sbom/package.cdx.json").write_bytes(b'{"bomFormat":"CycloneDX"}\n')


def _pipeline_inventory(source: Path, tmp_path: Path) -> tuple[Path, str]:
    entry = inventory_entry(source / "src/app.py", source)
    content = json.dumps({"entries": [entry]}, sort_keys=True, separators=(",", ":")) + "\n"
    inventory = tmp_path / "source-inventory.v1.json"
    inventory.write_text(content, encoding="utf-8")
    digest = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    return inventory, digest


def _pipeline_document(tmp_path: Path, digest: str, artifacts: Path, sboms: Path) -> Path:
    document = json.loads((FIXTURE / "build-input.json").read_text(encoding="utf-8"))
    document["source"]["sourceTreeSha256"] = digest
    document["prequalificationEvidence"][0]["subject"] = digest
    document["artifacts"] = [_artifact_declaration(artifacts / "artifacts/package.whl")]
    document["sboms"] = [_sbom_declaration(sboms / "sbom/package.cdx.json")]
    build_input = tmp_path / "build-input.json"
    build_input.write_text(json.dumps(document), encoding="utf-8")
    return build_input


def _pipeline_evidence(tmp_path: Path, digest: str) -> Path:
    document = {
        "evidence": [{"kind": "test", "name": "unit", "status": "passed", "subject": digest}],
        "schemaVersion": "v1",
    }
    evidence = tmp_path / "prequalification-evidence.v1.json"
    evidence.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    return evidence


def _artifact_declaration(path: Path) -> dict[str, str | int]:
    return {
        "name": "package",
        "path": "artifacts/package.whl",
        "mediaType": "application/octet-stream",
        "size": path.stat().st_size,
        "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _sbom_declaration(path: Path) -> dict[str, str]:
    return {
        "artifactPath": "artifacts/package.whl",
        "path": "sbom/package.cdx.json",
        "mediaType": "application/vnd.cyclonedx+json",
        "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def run_pipeline(
    files: PipelineFiles, fixture: Path, symlink_target: str | None = None
) -> subprocess.CompletedProcess[str]:
    command = _pipeline_shell(files, symlink_target)
    quiet = [] if symlink_target else ["-s"]
    return subprocess.run(
        [dagger_cli(), "shell", *quiet, "-c", command],
        cwd=fixture,
        check=False,
        capture_output=True,
        text=True,
    )


def _pipeline_shell(files: PipelineFiles, symlink_target: str | None) -> str:
    references = _pipeline_references(files)
    plan = _plan_shell(symlink_target)
    stages = (
        'release=$(portfolio-delivery | version --source="$src" --inventory="$inv" '
        '--include-paths="src/**" --exclude-paths="__none__" --build-input="$input")',
        'snap=$(portfolio-delivery | snapshot --release="$release" --plan="$release")',
        'unsigned=$(portfolio-delivery | build --source="$snap" --plan="$plan")',
        'checked=$(portfolio-delivery | prequalify --build="$unsigned" --plan="$plan")',
        'signed=$(portfolio-delivery | sign --build="$checked" --plan="$plan")',
        'envelope=$(portfolio-delivery | envelope --build="$signed")',
        'qualified=$(portfolio-delivery | qualify --envelope="$envelope" --plan="$plan")',
        'portfolio-delivery | publish-inputs --envelope="$qualified" '
        f"| export --path={files.output}",
    )
    return "; ".join((*references, plan, *stages))


def _pipeline_references(files: PipelineFiles) -> tuple[str, ...]:
    return (
        f"src=$(host | directory --path={files.source})",
        f"inv=$(host | file --path={files.inventory})",
        f"input=$(host | file --path={files.build_input})",
        f"evidence=$(host | file --path={files.evidence})",
        f"arts=$(host | directory --path={files.artifacts})",
        f"sboms=$(host | directory --path={files.sboms})",
    )


def _plan_shell(symlink_target: str | None) -> str:
    target = "" if symlink_target is None else f" --symlink-target={shlex.quote(symlink_target)}"
    return (
        'plan=$(plan --build-input="$input" --artifacts="$arts" --sboms="$sboms" '
        '--prequalification-evidence="$evidence"' + target + ")"
    )


def archive_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    extracted = archive.extractfile(name)
    if extracted is None:
        raise AssertionError(f"archive member is not a regular file: {name}")
    return extracted.read()


def run_version(files: PipelineFiles) -> subprocess.CompletedProcess[str]:
    command = [
        dagger_cli(),
        "call",
        "--silent",
        "version",
        f"--source={files.source}",
        f"--inventory={files.inventory}",
        f"--build-input={files.build_input}",
        "--include-paths=src/**",
        "--exclude-paths=__none__",
        "project",
    ]
    return subprocess.run(command, cwd=ROOT, check=False, capture_output=True, text=True)


def rewrite_inventory(files: PipelineFiles, entries: list[dict[str, str | int]]) -> None:
    content = json.dumps({"entries": entries}, sort_keys=True, separators=(",", ":")) + "\n"
    files.inventory.write_text(content, encoding="utf-8")
    document = json.loads(files.build_input.read_text(encoding="utf-8"))
    digest = "sha256:" + hashlib.sha256(content.encode()).hexdigest()
    document["source"]["sourceTreeSha256"] = digest
    document["prequalificationEvidence"][0]["subject"] = digest
    files.build_input.write_text(json.dumps(document), encoding="utf-8")


def bounded_entry(path: str, size: int = 0) -> dict[str, str | int]:
    return {
        "kind": "regular",
        "mode": "100644",
        "path": path,
        "sha256": "sha256:" + "0" * 64,
        "size": size,
    }


def actual_entry(files: PipelineFiles) -> dict[str, str | int]:
    return inventory_entry(files.source / "src/app.py", files.source)


def test_should_expose_phase_one_functions_when_module_is_introspected() -> None:
    # When
    result = run_dagger_functions_json()

    # Then
    assert root_function_names(result) == PHASE_ONE_FUNCTIONS


def test_should_require_typed_release_and_plan_when_snapshot_is_introspected() -> None:
    # When
    result = run_dagger_functions_json()

    # Then
    assert snapshot_argument_names(result) == {"release", "plan"}


def test_should_accept_optional_service_when_restore_is_introspected() -> None:
    # When
    result = run_dagger_functions_json()

    # Then
    service = argument_type(result, "restoreQualified", "registryService")
    assert service == {"kind": "SCALAR", "name": "ID"}


def test_should_require_attempt_id_when_restore_is_introspected() -> None:
    # When
    result = run_dagger_functions_json()

    # Then
    attempt = argument_type(result, "restoreQualified", "attemptId")
    assert attempt == {"kind": "NON_NULL", "name": None}


def test_should_expose_bounded_provider_observations_for_live_conformance() -> None:
    # When
    result = cast(dict[str, object], run_dagger_query(PROVIDER_OBSERVATION_QUERY))

    # Then
    expected = {
        "providerExecutionCount",
        "providerInspectionCount",
        "providerPushCount",
        "attemptIds",
    }
    assert expected <= _field_names(cast(dict[str, object], result["stored"]))
    assert expected <= _field_names(cast(dict[str, object], result["restored"]))


def test_should_retain_exact_oras_provenance_when_qualified_is_introspected() -> None:
    # When
    result = cast(dict[str, object], run_dagger_query(RETAINED_PROVENANCE_QUERY))
    qualified = cast(dict[str, object], result["qualified"])
    envelope = cast(dict[str, object], result["envelope"])
    retained = (
        qualified,
        envelope,
        *(
            cast(dict[str, object], result[name])
            for name in ("signed", "prequalified", "unsigned", "snapshot")
        ),
    )

    # Then
    qualified_names = _field_names(qualified)
    envelope_names = _field_names(envelope)
    assert {"inputSnapshotSha256", "signingDisposition", "signaturePath"} <= qualified_names
    assert "signingDisposition" in envelope_names
    assert all("inputSnapshotManifest" in _field_names(item) for item in retained)


def _field_names(type_result: dict[str, object]) -> set[str]:
    fields = cast(list[dict[str, str]], type_result["fields"])
    return {item["name"] for item in fields}


def test_should_preserve_snapshot_sha256_when_excluded_file_changes(tmp_path: Path) -> None:
    # Given
    source = copied_fixture(tmp_path)
    (source / "artifacts/excluded.txt").write_text("first", encoding="utf-8")
    expected = snapshot_sha256(source)

    # When
    (source / "artifacts/excluded.txt").write_text("second", encoding="utf-8")

    # Then
    assert snapshot_sha256(source) == expected


def test_should_change_snapshot_sha256_when_included_artifact_changes(tmp_path: Path) -> None:
    # Given
    source = copied_fixture(tmp_path)
    original = snapshot_sha256(source)

    # When
    (source / "artifacts/package.whl").write_bytes(b"changed artifact bytes")

    # Then
    assert snapshot_sha256(source) != original


@pytest.mark.parametrize("target", ["/etc/os-release", "package.whl", "missing"])
def test_should_reject_selected_symlink_before_snapshot_reads(tmp_path: Path, target: str) -> None:
    # Given
    source = copied_fixture(tmp_path)
    (source / "artifacts/outside").symlink_to(target)

    # When / Then
    with pytest.raises(subprocess.CalledProcessError) as error:
        snapshot_sha256(source)
    assert "selected source inventory entries must be regular files" in error.value.stderr


def test_should_publish_exact_validated_bytes_and_records(
    tmp_path: Path, live_fixture: Path
) -> None:
    # Given
    files = pipeline_files(tmp_path)

    # When
    result = run_pipeline(files, live_fixture)

    # Then
    assert result.returncode == 0, result.stderr
    with tarfile.open(files.output) as archive:
        _assert_archive(archive, files)


def _assert_archive(archive: tarfile.TarFile, files: PipelineFiles) -> None:
    expected = {
        "artifacts/package.whl",
        "sbom/package.cdx.json",
        "records/build-envelope.v1.json",
        "records/qualification-record.v1.json",
        "checksums.sha256",
    }
    assert set(archive.getnames()) == expected
    assert archive_bytes(archive, "artifacts/package.whl") == b"wheel"
    assert archive_bytes(archive, "sbom/package.cdx.json") == b'{"bomFormat":"CycloneDX"}\n'
    _assert_records(archive, files)
    _assert_checksums(archive, expected - {"checksums.sha256"})


def _assert_records(archive: tarfile.TarFile, files: PipelineFiles) -> None:
    envelope_bytes = archive_bytes(archive, "records/build-envelope.v1.json")
    qualification_bytes = archive_bytes(archive, "records/qualification-record.v1.json")
    envelope = json.loads(envelope_bytes)
    qualification = json.loads(qualification_bytes)
    digest = "sha256:" + hashlib.sha256(envelope_bytes).hexdigest()
    assert envelope["artifacts"][0]["sha256"] == "sha256:" + hashlib.sha256(b"wheel").hexdigest()
    expected_evidence = json.loads(files.evidence.read_bytes())["evidence"]
    assert envelope["prequalificationEvidence"] == expected_evidence
    assert qualification["subject"] == digest
    assert qualification["qualificationEvidence"][0]["subject"] == digest


def _assert_checksums(archive: tarfile.TarFile, names: set[str]) -> None:
    lines = archive_bytes(archive, "checksums.sha256").decode().splitlines()
    expected = {
        f"{hashlib.sha256(archive_bytes(archive, name)).hexdigest()}  {name}" for name in names
    }
    assert set(lines) == expected


@pytest.mark.parametrize("mismatch", ["artifact", "extra", "missing", "sbom", "source", "evidence"])
def test_should_reject_incoherent_pipeline_bytes(
    tmp_path: Path, live_fixture: Path, mismatch: str
) -> None:
    # Given
    files = pipeline_files(tmp_path)
    _introduce_mismatch(files, mismatch)

    # When
    result = run_pipeline(files, live_fixture)

    # Then
    assert result.returncode != 0
    expected = "bound source identity" if mismatch == "evidence" else "match"
    assert expected in result.stderr


def _introduce_mismatch(files: PipelineFiles, mismatch: str) -> None:
    if mismatch == "artifact":
        (files.artifacts / "artifacts/package.whl").write_bytes(b"changed")
        return
    if mismatch == "extra":
        (files.artifacts / "artifacts/extra").write_bytes(b"extra")
        return
    if mismatch == "missing":
        (files.artifacts / "artifacts/package.whl").unlink()
        return
    if mismatch == "sbom":
        (files.sboms / "sbom/package.cdx.json").write_bytes(b"changed")
        return
    if mismatch == "source":
        (files.source / "src/app.py").write_bytes(b"changed")
        return
    document = json.loads(files.build_input.read_text(encoding="utf-8"))
    document["prequalificationEvidence"][0]["subject"] = "sha256:" + "0" * 64
    files.build_input.write_text(json.dumps(document), encoding="utf-8")


def test_should_reject_output_symlink_before_envelope_or_archive_reads(
    tmp_path: Path, live_fixture: Path
) -> None:
    # Given
    files = pipeline_files(tmp_path)

    # When
    result = run_pipeline(files, live_fixture, "/etc/os-release")

    # Then
    assert result.returncode != 0
    assert "symbolic links are forbidden" in result.stderr


def test_should_reject_oversized_json_before_reading_contents(tmp_path: Path) -> None:
    # Given
    files = pipeline_files(tmp_path)
    files.build_input.write_text('{"payload":"' + "x" * 1_048_576 + '"}', encoding="utf-8")

    # When
    result = run_version(files)

    # Then
    assert result.returncode != 0
    assert "configured JSON byte limit" in result.stderr


@pytest.mark.parametrize(
    ("kind", "mode", "message"),
    [
        ("regular", "120000", "canonical Git kind and mode"),
        ("regular", "100600", "canonical Git kind and mode"),
        ("symlink", "100644", "canonical Git kind and mode"),
        ("submodule", "100644", "canonical Git kind and mode"),
        ("submodule", "160000", "selected source inventory entries must be regular"),
        ("device", "100644", "canonical Git kind and mode"),
    ],
)
def test_should_reject_noncanonical_git_kind_mode_combinations(
    tmp_path: Path, kind: str, mode: str, message: str
) -> None:
    # Given
    files = pipeline_files(tmp_path)
    entry = actual_entry(files)
    entry.update({"kind": kind, "mode": mode})
    rewrite_inventory(files, [entry])

    # When
    result = run_version(files)

    # Then
    assert result.returncode != 0
    assert message in result.stderr


def test_should_accept_executable_regular_git_mode(tmp_path: Path) -> None:
    # Given
    files = pipeline_files(tmp_path)
    entry = actual_entry(files)
    entry["mode"] = "100755"
    rewrite_inventory(files, [entry])

    # When
    result = run_version(files)

    # Then
    assert result.returncode == 0, result.stderr


def test_should_reject_noncanonical_inventory_order(tmp_path: Path) -> None:
    # Given
    files = pipeline_files(tmp_path)
    second = files.source / "src/second.py"
    second.write_bytes(b"second")
    entries = [inventory_entry(second, files.source), actual_entry(files)]
    rewrite_inventory(files, entries)

    # When
    result = run_version(files)

    # Then
    assert result.returncode != 0
    assert "canonical path order" in result.stderr


def test_should_reject_duplicate_inventory_path(tmp_path: Path) -> None:
    # Given
    files = pipeline_files(tmp_path)
    entry = actual_entry(files)
    rewrite_inventory(files, [entry, entry])

    # When
    result = run_version(files)

    # Then
    assert result.returncode != 0
    assert "unique" in result.stderr


@pytest.mark.parametrize(
    "mutation", ["empty", "malformed", "subject", "status", "name", "extra", "missing"]
)
def test_should_reject_detached_prequalification_evidence_mismatch(
    tmp_path: Path, live_fixture: Path, mutation: str
) -> None:
    # Given
    files = pipeline_files(tmp_path)
    _mutate_evidence(files, mutation)

    # When
    result = run_pipeline(files, live_fixture)

    # Then
    assert result.returncode != 0
    assert "evidence" in result.stderr.lower()


def _mutate_evidence(files: PipelineFiles, mutation: str) -> None:
    if mutation == "malformed":
        files.evidence.write_text("{", encoding="utf-8")
        return
    document = json.loads(files.evidence.read_text(encoding="utf-8"))
    records = document["evidence"]
    if mutation == "empty":
        document = {}
    elif mutation == "subject":
        records[0]["subject"] = "sha256:" + "0" * 64
    elif mutation == "status":
        records[0]["status"] = "failed"
    elif mutation == "name":
        records[0]["name"] = "different"
    elif mutation == "extra":
        records.append({**records[0], "name": "extra"})
    else:
        document["evidence"] = []
    files.evidence.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


@pytest.mark.parametrize("bound", ["count", "path", "file", "total"])
def test_should_reject_hostile_source_inventory_bounds(tmp_path: Path, bound: str) -> None:
    # Given
    files = pipeline_files(tmp_path)
    rewrite_inventory(files, _hostile_entries(bound))

    # When
    result = run_version(files)

    # Then
    assert result.returncode != 0
    assert "configured" in result.stderr


def _hostile_entries(bound: str) -> list[dict[str, str | int]]:
    if bound == "count":
        paths = sorted(f"src/{index}" for index in range(4_097))
        return [bounded_entry(path) for path in paths]
    if bound == "path":
        return [bounded_entry("src/" + "x" * 1_024)]
    if bound == "file":
        return [bounded_entry("src/large", 67_108_865)]
    return [bounded_entry(f"src/{index}", 60_000_000) for index in range(9)]
