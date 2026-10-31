#!/usr/bin/env python3
"""Build and test owned loopback-only production Next.js counterparts."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent.parent


def unused_port(used):
    while True:
        with socket.socket() as connection:
            connection.bind(("127.0.0.1", 0))
            port = connection.getsockname()[1]
        if port not in used:
            used.add(port)
            return port


def wait_ready(url, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("owned lab process exited before readiness")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, TimeoutError):
            pass
        time.sleep(0.1)
    raise RuntimeError("owned lab readiness deadline exceeded")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-build", action="store_true", help="use already-built pinned variants")
    parser.add_argument("--results", type=Path, default=LAB / "lab-results.json")
    args = parser.parse_args()
    if not args.skip_build:
        subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=LAB, check=True)
        for variant in ("vulnerable", "patched"):
            subprocess.run(["npm", "run", "build"], cwd=LAB, env={**os.environ, "LAB_VARIANT": variant, "NEXT_TELEMETRY_DISABLED": "1"}, check=True)
    for variant in ("vulnerable", "patched"):
        if not (LAB / f".next-{variant}" / "BUILD_ID").is_file():
            raise RuntimeError(f"missing {variant} production build")
    used = set()
    ports = {name: unused_port(used) for name in ("collector", "vulnerable", "patched")}
    origins = {name: f"http://127.0.0.1:{port}" for name, port in ports.items()}
    processes = []
    logs = []
    with tempfile.TemporaryDirectory(prefix="xalgorix-nextjs-lab-") as temporary:
        try:
            for name in ("collector", "vulnerable", "patched"):
                log = open(Path(temporary) / f"{name}.log", "w+")
                logs.append((name, log))
                command = ["node", "collector.mjs"] if name == "collector" else ["node", "node_modules/next/dist/bin/next", "start", "--hostname", "127.0.0.1", "--port", str(ports[name])]
                environment = {**os.environ, "PORT": str(ports[name]), "LAB_VARIANT": name, "LAB_CALLBACK_ORIGIN": origins["collector"], "NEXT_TELEMETRY_DISABLED": "1"}
                process = subprocess.Popen(command, cwd=LAB, env=environment, stdout=log, stderr=subprocess.STDOUT)
                processes.append(process)
                wait_ready(origins[name] + ("/health" if name == "collector" else "/api/lab-info"), process)
            environment = {**os.environ, "CGO_ENABLED": "0", "XALGORIX_NEXTJS_LAB_RESULTS": str(args.results.resolve())}
            for name, origin in origins.items():
                environment[f"XALGORIX_NEXTJS_LAB_{name.upper()}_URL"] = origin
            args.results.parent.mkdir(parents=True, exist_ok=True)
            args.results.unlink(missing_ok=True)
            completed = subprocess.run(["go", "test", "./internal/scanner", "-run", "^TestNextjsFrameworkAcceptance$", "-count=1", "-v"], cwd=ROOT, env=environment)
            if args.results.is_file():
                score = json.loads(args.results.read_text())
                print(json.dumps({"passed": score["passed"], "cases": len(score["cases"]), "nextjs": score["nextjs"], "results": str(args.results)}, indent=2))
            return completed.returncode
        except Exception:
            for name, log in logs:
                log.flush()
                log.seek(0)
                print(f"{name} startup log:\n{log.read()[-4000:]}")
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            for _, log in logs:
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
