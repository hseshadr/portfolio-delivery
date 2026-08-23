"""Executable in-memory ORAS registry used by adapter behavior tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256

from portfolio_delivery.domain.stages import (
    OrasInvocation,
    OrasOutcome,
    OrasResult,
    validate_attempt_id,
)

_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
_TITLE = "org.opencontainers.image.title"


@dataclass(frozen=True, slots=True)
class FakeFile:
    path: str
    content: bytes


class FakeOrasRunner:
    """Execute the adapter's stable ORAS command subset against registry state."""

    def __init__(self, files: tuple[FakeFile, ...] = ()) -> None:
        self.files = {item.path: item.content for item in files}
        self.invocations: list[tuple[OrasInvocation, str]] = []
        self.manifests: dict[str, bytes] = {}
        self.blobs: dict[str, bytes] = {}
        self.write_count = 0
        self.observation_count = 0
        self._initialize_controls()
        self._initialize_outputs()

    def _initialize_controls(self) -> None:
        self.timeout_before_write = False
        self.timeout_after_write = False
        self.overwrite_after_push = False
        self.omit_exported_file = False

    def _initialize_outputs(self) -> None:
        self.digest_manifest_override: bytes | None = None
        self.push_stdout = b"pushed"
        self.push_stderr = b""
        self.exported_file_override: bytes | None = None
        self.manifest_exported_file_bytes: bytes | None = None
        self.blob_exported_file_bytes: bytes | None = None
        self.missing_outcome = OrasOutcome.NOT_FOUND
        self.missing_stdout = b""
        self.missing_stderr = b"manifest unavailable"

    async def run(self, invocation: OrasInvocation, attempt_id: str) -> OrasResult:
        validate_attempt_id(attempt_id)
        self.invocations.append((invocation, attempt_id))
        command = invocation.argv[1:3]
        if invocation.argv[1] == "push":
            return self._push(invocation)
        if command == ("manifest", "fetch"):
            return self._fetch_manifest(invocation.argv[-1])
        if command == ("blob", "fetch"):
            return self._fetch_blob(invocation.argv[-1])
        return OrasResult(2, OrasOutcome.FAILURE, b"", b"unsupported fake ORAS command")

    def put_manifest(self, reference: str, content: bytes) -> None:
        self.manifests[reference] = content
        if "@" not in reference:
            repository = reference.rsplit(":", 1)[0]
            digest = f"sha256:{sha256(content).hexdigest()}"
            self.manifests[f"{repository}@{digest}"] = content

    def _push(self, invocation: OrasInvocation) -> OrasResult:
        if self.timeout_before_write:
            return OrasResult(124, OrasOutcome.TIMEOUT, b"", b"provider timed out")
        target = _push_target(invocation.argv)
        contents = self._input_contents(invocation)
        manifest = _manifest_bytes(invocation.argv, contents)
        self._store(target, manifest, invocation.argv, contents)
        if self.overwrite_after_push:
            self.put_manifest(target, _overwrite_manifest(manifest))
        if self.timeout_after_write:
            self.timeout_after_write = False
            return OrasResult(124, OrasOutcome.TIMEOUT, b"", b"provider timed out")
        exported = _exported_file(self, manifest)
        return OrasResult(0, OrasOutcome.SUCCESS, self.push_stdout, self.push_stderr, exported)

    def _input_contents(self, invocation: OrasInvocation) -> tuple[bytes, ...]:
        planned = dict(zip(_planned_input_paths(), invocation.input_bytes, strict=True))
        paths = _push_paths(invocation.argv)
        return tuple(_file_content(path, planned, self.files) for path in paths)

    def _store(
        self, target: str, manifest: bytes, argv: tuple[str, ...], contents: tuple[bytes, ...]
    ) -> None:
        repository = target.rsplit(":", 1)[0]
        digest = f"sha256:{sha256(manifest).hexdigest()}"
        self.manifests[target] = manifest
        self.manifests[f"{repository}@{digest}"] = manifest
        for _path, content in zip(_push_paths(argv), contents, strict=True):
            self.blobs[f"{repository}@sha256:{sha256(content).hexdigest()}"] = content
        self.write_count += 1

    def _fetch_manifest(self, reference: str) -> OrasResult:
        self.observation_count += 1
        content = self.manifests.get(reference)
        if content is None:
            return OrasResult(
                _failure_code(self.missing_outcome),
                self.missing_outcome,
                self.missing_stdout,
                self.missing_stderr,
            )
        if "@sha256:" in reference and self.digest_manifest_override is not None:
            content = self.digest_manifest_override
        return OrasResult(0, OrasOutcome.SUCCESS, content, b"", self.manifest_exported_file_bytes)

    def _fetch_blob(self, reference: str) -> OrasResult:
        self.observation_count += 1
        content = self.blobs.get(reference)
        if content is None:
            return OrasResult(1, OrasOutcome.NOT_FOUND, b"", b"blob unavailable")
        return OrasResult(0, OrasOutcome.SUCCESS, content, b"", self.blob_exported_file_bytes)


def _planned_input_paths() -> tuple[str, ...]:
    return (
        "config.v1.json",
        "build-envelope.v1.json",
        "qualification-record.v1.json",
    )


def _file_content(path: str, planned: dict[str, bytes], mounted: dict[str, bytes]) -> bytes:
    if path in planned:
        return planned[path]
    return mounted[path]


def _push_target(argv: tuple[str, ...]) -> str:
    return argv[argv.index("manifest.json") + 1]


def _push_specs(argv: tuple[str, ...]) -> tuple[str, ...]:
    target_index = argv.index("manifest.json") + 1
    return argv[target_index + 1 :]


def _push_paths(argv: tuple[str, ...]) -> tuple[str, ...]:
    return ("config.v1.json", *tuple(spec.rsplit(":", 1)[0] for spec in _push_specs(argv)))


def _manifest_bytes(argv: tuple[str, ...], contents: tuple[bytes, ...]) -> bytes:
    config = _descriptor(argv[5].rsplit(":", 1)[1], contents[0], None)
    document = {
        "artifactType": argv[3],
        "config": config,
        "layers": _layer_descriptors(argv, contents[1:]),
        "mediaType": _MANIFEST_MEDIA_TYPE,
        "schemaVersion": 2,
        "annotations": _manifest_annotations(argv),
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _layer_descriptors(argv: tuple[str, ...], contents: tuple[bytes, ...]) -> tuple[object, ...]:
    return tuple(
        _descriptor(spec.rsplit(":", 1)[1], content, _title(spec))
        for spec, content in zip(_push_specs(argv), contents, strict=True)
    )


def _descriptor(media_type: str, content: bytes, title: str | None) -> object:
    descriptor = {
        "digest": f"sha256:{sha256(content).hexdigest()}",
        "mediaType": media_type,
        "size": len(content),
    }
    if title is not None:
        descriptor["annotations"] = {_TITLE: title}
    return descriptor


def _title(spec: str) -> str:
    return spec.rsplit(":", 1)[0]


def _manifest_annotations(argv: tuple[str, ...]) -> object:
    annotation = argv[argv.index("--annotation") + 1]
    key, value = annotation.split("=", 1)
    return {key: value}


def _failure_code(outcome: OrasOutcome) -> int:
    if outcome is OrasOutcome.TIMEOUT:
        return 124
    return 1


def _exported_file(runner: FakeOrasRunner, manifest: bytes) -> bytes | None:
    if runner.omit_exported_file:
        return None
    if runner.exported_file_override is not None:
        return runner.exported_file_override
    return manifest


def _overwrite_manifest(content: bytes) -> bytes:
    document = json.loads(content)
    document["annotations"]["org.opencontainers.image.created"] = "2025-01-01T00:00:00Z"
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
