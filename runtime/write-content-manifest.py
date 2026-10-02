#!/usr/bin/env python3
"""Record the tool and package content actually present in a built image."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def manifest(lock, version_reader, package_list):
    tools = {}
    for name, wanted in {**lock["required"], **lock["optional"]}.items():
        observed = version_reader(name)
        tools[name] = {"pinned": wanted, "available": observed is not None, "version_output": observed, "version_source": lock.get("version_sources", {}).get(name, "CLI version command")}
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


def installed_version(name, args=None, exit_codes=(0,), env_overrides=None, command=None):
    path = shutil.which(name)
    if path is None:
        return None
    try:
        result = subprocess.run(command or (path, *(args or ["--version"])), capture_output=True, text=True, timeout=60, check=False, stdin=subprocess.DEVNULL, env={**os.environ, **(env_overrides or {})})
        if result.returncode not in exit_codes:
            return None
        return (result.stdout + result.stderr).strip().splitlines()[:3]
    except (OSError, subprocess.TimeoutExpired):
        return None


if __name__ == "__main__":
    lock = json.loads(Path(sys.argv[1]).read_text())
    packages = subprocess.run(("dpkg-query", "-W", "-f=${Package}=${Version}\n"),
                              check=True, capture_output=True, text=True).stdout
    Path(sys.argv[2]).write_text(json.dumps(manifest(lock, lambda name: installed_version(name, lock.get("version_args", {}).get(name), lock.get("version_exit_codes", {}).get(name, [0]), lock.get("version_env", {}).get(name), lock.get("version_commands", {}).get(name)), packages), indent=2) + "\n")
