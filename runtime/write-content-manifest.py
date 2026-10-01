#!/usr/bin/env python3
"""Record the tool and package content actually present in a built image."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def manifest(lock, version_reader, package_list):
    tools = {}
    for name, wanted in {**lock["required"], **lock["optional"]}.items():
        observed = version_reader(name)
        tools[name] = {"pinned": wanted, "available": observed is not None, "version_output": observed}
    missing = [name for name in lock["required"] if not tools[name]["available"]]
    if missing:
        raise RuntimeError("required scanner binaries missing: " + ", ".join(missing))
    return {
        "schema_version": 1,
        "lock": lock,
        "tools": tools,
        "dpkg_list_sha256": hashlib.sha256(package_list.encode()).hexdigest(),
        "dpkg_package_count": len(package_list.splitlines()),
    }


def installed_version(name):
    path = shutil.which(name)
    if path is None:
        return None
    try:
        result = subprocess.run((path, "--version"), capture_output=True, text=True, timeout=15, check=False)
        return (result.stdout + result.stderr).strip().splitlines()[:3]
    except (OSError, subprocess.TimeoutExpired):
        return []


if __name__ == "__main__":
    lock = json.loads(Path(sys.argv[1]).read_text())
    packages = subprocess.run(("dpkg-query", "-W", "-f=${Package}=${Version}\n"),
                              check=True, capture_output=True, text=True).stdout
    Path(sys.argv[2]).write_text(json.dumps(manifest(lock, installed_version, packages), indent=2) + "\n")
