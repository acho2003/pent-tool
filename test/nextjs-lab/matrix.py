#!/usr/bin/env python3
"""Run isolated, pinned compatibility fixtures; all application traffic is loopback."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent.parent
CASES = (("16.4.3", ""), ("16.4.3", "/tenant"), ("15.5.24", ""))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", type=Path)
    parser.add_argument("--results", type=Path, default=LAB / "matrix-results")
    parser.add_argument("--case", action="append", choices=[version + ("-tenant" if prefix else "-root") for version, prefix in CASES], help="rerun selected compatibility cases")
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=True)
    summary = []
    for version, prefix in CASES:
        label = version + ("-tenant" if prefix else "-root")
        if args.case and label not in args.case:
            continue
        with tempfile.TemporaryDirectory(prefix="xalgorix-nextjs-matrix-") as directory:
            fixture = Path(directory) / "fixture"
            shutil.copytree(LAB, fixture, ignore=shutil.ignore_patterns("node_modules", ".next*", "matrix-results", "__pycache__", "*.log", "lab-results.json"))
            package = json.loads((fixture / "package.json").read_text())
            package["dependencies"]["next"] = version
            if version.startswith("15."):
                package["scripts"]["build"] = "next build"
                proxy = fixture / "proxy.js"
                (fixture / "middleware.js").write_text(proxy.read_text().replace("export function proxy(", "export function middleware("))
                proxy.unlink()
                shutil.copyfile(LAB / "locks" / ("next-" + version + ".package-lock.json"), fixture / "package-lock.json")
            (fixture / "package.json").write_text(json.dumps(package, indent=2) + "\n")
            result = (args.results / (label + ".json")).resolve()
            command = ["python3", str(fixture / "run.py"), "--base-path", prefix, "--results", str(result)]
            if args.browser:
                command += ["--browser", str(args.browser.resolve(strict=True))]
            subprocess.run(command, env={**os.environ, "XALGORIX_LAB_REPO_ROOT": str(ROOT)}, check=True)
            score = json.loads(result.read_text())
            summary.append({"nextjs": version, "base_path": prefix, "passed": score["passed"], "cases": len(score["cases"])})
    (args.results / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
