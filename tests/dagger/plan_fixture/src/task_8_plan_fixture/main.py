"""Return a cross-module build plan implementing the stable production interfaces."""

from __future__ import annotations

from dataclasses import dataclass

import dagger
from dagger import dag, field, function, object_type


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
    def include_paths(self) -> list[str]:
        return ["src/**"]

    @function
    def exclude_paths(self) -> list[str]:
        return ["__none__"]

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
        evidence = dag.file("qualification-input.json", _qualification_json(envelope_sha256))
        return FixturePlan(
            input_file=self.input_file,
            artifact_directory=self.artifact_directory,
            sbom_directory=self.sbom_directory,
            check_file=evidence,
        )

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


@object_type
class Task8PlanFixture:
    """Produce a Dagger-native plan object from a separate dependency module."""

    @function
    def plan(
        self,
        build_input: dagger.File,
        artifacts: dagger.Directory,
        sboms: dagger.Directory,
        evidence: dagger.File,
    ) -> FixturePlan:
        return FixturePlan(
            input_file=build_input,
            artifact_directory=artifacts,
            sbom_directory=sboms,
            check_file=evidence,
        )


def _qualification_json(digest: str) -> str:
    return (
        '{"qualificationEvidence":[{"kind":"policy","name":"release",'
        f'"status":"passed","subject":"{digest}"}}],'
        f'"schemaVersion":"v1","subject":"{digest}"}}\n'
    )
