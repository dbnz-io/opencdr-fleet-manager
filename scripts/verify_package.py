#!/usr/bin/env python3
"""Verify repeated artifact hashes, allowlisted contents and isolated runtime imports."""

import hashlib
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    artifact = ROOT / "build/fleet-manager.zip"
    digests = []
    for _ in range(2):
        subprocess.run([sys.executable, str(ROOT / "scripts/package.py")], check=True)
        digests.append(hashlib.sha256(artifact.read_bytes()).hexdigest())
    if digests[0] != digests[1]:
        raise RuntimeError("Repeated builds produced different artifacts")
    roots = {
        "opencdr_fleet",
        "boto3",
        "botocore",
        "dateutil",
        "jmespath",
        "s3transfer",
        "six.py",
        "urllib3",
    }
    with zipfile.ZipFile(artifact) as archive:
        for name in archive.namelist():
            path = Path(name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Unsafe archive member")
            if path.parts[0] not in roots and not path.parts[0].endswith(".dist-info"):
                raise RuntimeError("Unexpected artifact content")
        with tempfile.TemporaryDirectory(prefix="opencdr-fleet-smoke-") as directory:
            archive.extractall(directory)
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-c",
                    "import sys; sys.path.insert(0, sys.argv[1]); import opencdr_fleet.handlers; "
                    "print('Isolated Lambda runtime import passed')",
                    directory,
                ],
                check=True,
            )
    print(f"Repeated artifact SHA-256 verified: {digests[0]}")


if __name__ == "__main__":
    main()
