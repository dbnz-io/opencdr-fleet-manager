#!/usr/bin/env python3
"""Build an allowlisted, reproducible Lambda ZIP from hash-locked wheels."""

import hashlib
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    target = ROOT / "build" / "fleet-manager.zip"
    target.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="opencdr-fleet-package-") as directory:
        vendor = Path(directory)
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
                "--target",
                str(vendor),
                "-r",
                str(ROOT / "requirements.lock"),
            ],
            check=True,
        )
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
