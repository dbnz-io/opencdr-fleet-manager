#!/usr/bin/env python3
"""Refresh hashes for the explicitly reviewed runtime versions from official PyPI."""

import json
from pathlib import Path
from urllib.request import urlopen

VERSIONS = {
    "boto3": "1.43.119",
    "botocore": "1.43.119",
    "s3transfer": "0.19.3",
    "jmespath": "1.1.0",
    "python-dateutil": "2.9.0.post0",
    "six": "1.17.0",
    "urllib3": "2.8.0",
}


def main():
    rows = ["# Reviewed runtime versions; all artifacts verified by SHA-256.\n"]
    for name, version in sorted(VERSIONS.items()):
        with urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=20) as response:
            release = json.load(response)
        hashes = sorted(
            {
                item["digests"]["sha256"]
                for item in release["urls"]
                if item["packagetype"] == "bdist_wheel" and not item["yanked"]
            }
        )
        if not hashes:
            raise RuntimeError(f"No non-yanked wheel for {name} {version}")
        continuation = " " + chr(92) + chr(10)
        rows.append(
            f"{name}=={version}"
            + continuation
            + continuation.join(f"    --hash=sha256:{digest}" for digest in hashes)
            + chr(10)
        )
    (Path(__file__).resolve().parents[1] / "requirements.lock").write_text("".join(rows))


if __name__ == "__main__":
    main()
