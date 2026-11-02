#!/usr/bin/env python3
"""Check PyPI artifacts include usable service source and exclude local artifacts."""

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels, sources = list(root.glob("*.whl")), list(root.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise SystemExit("Expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as archive:
        wheel_files = set(archive.namelist())
    if not {"opencdr_fleet/handlers.py", "opencdr_fleet/__init__.py"} <= wheel_files:
        raise SystemExit("Wheel is missing service runtime modules")
    if not any(name.endswith("/licenses/LICENSE") for name in wheel_files):
        raise SystemExit("Wheel is missing the Mozilla license")
    with tarfile.open(sources[0]) as archive:
        names = [PurePosixPath(item.name) for item in archive.getmembers()]
    source_files = {str(PurePosixPath(*path.parts[1:])) for path in names if len(path.parts) > 1}
    required = {
        "serverless.yml",
        "requirements.lock",
        "package.json",
        "package-lock.json",
        "scripts/package.py",
        "scripts/deploy.py",
        "scripts/fleet.py",
        "scripts/bootstrap_agent.py",
        "src/opencdr_fleet/handlers.py",
        "README.md",
        "LICENSE",
    }
    if not required <= source_files:
        raise SystemExit(f"Source distribution is missing {sorted(required - source_files)}")
    for name in wheel_files | source_files:
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or any(
                part in {".git", ".serverless", ".venv", "__pycache__", "node_modules", "build"}
                or part.startswith(".env")
                for part in path.parts
            )
            or name.endswith((".zip", ".pyc"))
            or path.name == ".opencdr.json"
        ):
            raise SystemExit(f"Unexpected distribution artifact: {name}")
    print("Wheel/source contents and Mozilla license verified")


if __name__ == "__main__":
    main()
