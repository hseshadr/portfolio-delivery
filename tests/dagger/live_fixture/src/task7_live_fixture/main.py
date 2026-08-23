"""External project plan used only by live Dagger contract tests."""

from __future__ import annotations

from dataclasses import dataclass

import dagger
from dagger import dag, field, function, object_type

PYTHON_IMAGE = (
    "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)


@dataclass(kw_only=True)
@object_type
class FixturePlan(
    dagger.PortfolioDeliveryBuildOutput,
    dagger.PortfolioDeliveryBuildPlan,
    dagger.PortfolioDeliveryCheckOutput,
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
        symlink_target: str | None = None,
    ) -> FixturePlan:
        return FixturePlan(
            input_file=build_input,
            artifact_directory=_artifact_directory(artifacts, symlink_target),
            sbom_directory=sboms,
            check_file=dag.file("prequalification.json", "{}"),
        )


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
