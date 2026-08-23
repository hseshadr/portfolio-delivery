#!/usr/bin/env python3
"""Build a deterministic CycloneDX 1.6 SBOM for a Python wheel."""

from __future__ import annotations

import argparse
import hashlib
import zipfile
from datetime import UTC, datetime
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import cast
from uuid import NAMESPACE_URL, uuid5

from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot6
from packageurl import PackageURL


def _arguments() -> tuple[Path, Path, int]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    arguments = parser.parse_args()
    wheel = Path(cast(str, arguments.wheel))
    output = Path(cast(str, arguments.output))
    return wheel, output, cast(int, arguments.source_date_epoch)


def _metadata_bytes(wheel: zipfile.ZipFile) -> bytes:
    paths = tuple(name for name in wheel.namelist() if name.endswith(".dist-info/METADATA"))
    if len(paths) != 1:
        raise ValueError("wheel must contain exactly one dist-info/METADATA")
    return wheel.read(paths[0])


def _identity(wheel_path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(wheel_path) as wheel:
        metadata = BytesParser(policy=default).parsebytes(_metadata_bytes(wheel))
    name, version = metadata["Name"], metadata["Version"]
    if not isinstance(name, str) or not isinstance(version, str):
        raise ValueError("wheel metadata requires string Name and Version")
    return name, version


def _component(wheel_path: Path) -> tuple[Component, str]:
    name, version = _identity(wheel_path)
    digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    purl = PackageURL(type="pypi", name=name, version=version)
    component = Component(
        name=name,
        version=version,
        type=ComponentType.LIBRARY,
        bom_ref=purl.to_string(),
        purl=purl,
        hashes=(HashType(alg=HashAlgorithm.SHA_256, content=digest),),
    )
    return component, digest


def _sbom_bytes(wheel_path: Path, source_date_epoch: int) -> bytes:
    component, digest = _component(wheel_path)
    metadata = BomMetaData(
        component=component,
        timestamp=datetime.fromtimestamp(source_date_epoch, tz=UTC),
    )
    serial = uuid5(NAMESPACE_URL, f"{component.purl}#sha256:{digest}")
    document = JsonV1Dot6(Bom(serial_number=serial, metadata=metadata))
    return (document.output_as_string(indent=None) + "\n").encode()


def main() -> None:
    wheel, output, source_date_epoch = _arguments()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_sbom_bytes(wheel, source_date_epoch))


if __name__ == "__main__":
    main()
