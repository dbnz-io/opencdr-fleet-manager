#!/usr/bin/env python3
"""Build an allowlisted, reproducible Lambda ZIP from hash-locked wheels."""

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vendor",
        type=Path,
        help="dependencies previously installed with --require-hashes from requirements.lock",
    )
    args = parser.parse_args()
    contracts = ROOT / "src/opencdr_fleet/_contracts"
    pin_path = contracts / "contracts-pin.json"
    pin = json.loads(pin_path.read_text())
    if hashlib.sha256((contracts / "detection_query.py").read_bytes()).hexdigest() != pin["sha256"]:
        raise RuntimeError("Shared detection contract differs from its reviewed pin")
    if (
        hashlib.sha256((contracts / "detection_handling.py").read_bytes()).hexdigest()
        != pin["handling_sha256"]
    ):
        raise RuntimeError("Shared handling contract differs from its reviewed pin")
    for name in (
        "case_contract",
        "case_store",
        "case_api",
        "case_integrations",
        "case_extensions",
        "library_contract",
        "library_store",
        "library_api",
        "library_quality",
        "library_imports",
        "delegation",
        "identity_store",
        "approval_contract",
        "approval_store",
        "approval_authority",
        "approval_api",
        "case_routing",
        "routing_execution",
        "routing_api",
        "routing_delivery",
        "case_mutations",
        "case_tuning",
        "mutation_execution",
        "configuration_flags",
    ):
        if (
            hashlib.sha256((contracts / (name + ".py")).read_bytes()).hexdigest()
            != pin[name + "_sha256"]
        ):
            raise RuntimeError("Shared case contract differs from its reviewed pin")
    for name, expected in pin["evaluator_sources"].items():
        if (
            hashlib.sha256(
                (ROOT / "src/opencdr_fleet/_evaluator" / (name + ".py")).read_bytes()
            ).hexdigest()
            != expected
        ):
            raise RuntimeError("Native evaluator differs from its reviewed pin")
    target = ROOT / "build" / "fleet-manager.zip"
    target.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="opencdr-fleet-package-") as directory:
        vendor = args.vendor.resolve() if args.vendor else Path(directory)
        if not args.vendor:
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-compile",
                    "--require-hashes",
                    "--only-binary=:all:",
                    "--platform=manylinux2014_aarch64",
                    "--python-version=3.12",
                    "--implementation=cp",
                    "--abi=cp312",
                    "--target",
                    str(vendor),
                    "-r",
                    str(ROOT / "requirements.lock"),
                ],
                check=True,
            )
        extensions = list((vendor / "regex").glob("_regex*.so"))
        if len(extensions) != 1 or "cpython-312" not in extensions[0].name:
            raise RuntimeError("Fleet needs the locked CPython 3.12 Linux ARM64 regex wheel")
        header = extensions[0].read_bytes()[:20]
        if (
            header[:4] != b"\x7fELF"
            or header[4:6] != b"\x02\x01"
            or int.from_bytes(header[18:20], "little") != 183
        ):
            raise RuntimeError("Native evaluator extension is not Linux ARM64")
        files = {
            str(path.relative_to(vendor)): path
            for path in vendor.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
            and path.relative_to(vendor).parts[0] != "bin"
            and path.name not in {"RECORD", "INSTALLER", "REQUESTED", "direct_url.json"}
        }
        files.update(
            {
                str(path.relative_to(ROOT / "src")): path
                for path in (ROOT / "src" / "opencdr_fleet").rglob("*.py")
            }
        )
        files["opencdr_fleet/_contracts/contracts-pin.json"] = pin_path
        files["opencdr_fleet/LICENSE"] = ROOT / "LICENSE"
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, path in sorted(files.items()):
                info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
                info.external_attr = 0o644 << 16
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, path.read_bytes(), compresslevel=9)
    print(f"{target.name} sha256={hashlib.sha256(target.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
