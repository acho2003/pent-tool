#!/usr/bin/env python3
"""Run the local lab against an already-running, already-built Xalgorix image.

Raw reports stay in a private output directory. No image is built or pulled.
"""

import argparse
import getpass
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
LAB_COMPOSE = ROOT / "test/lab/compose.yaml"
MANIFEST = ROOT / "test/lab/manifest.v1.json"
TOOLS = ("xalgorix", "nuclei", "trivy", "semgrep", "gitleaks", "osv-scanner", "katana", "nikto")


def docker(*args, capture=True):
    return subprocess.run(("docker", *args), check=True, text=True, capture_output=capture)


def image_id(name):
    return docker("image", "inspect", name, "--format", "{{.Id}}").stdout.strip()


def container_image_id(name):
    return docker("inspect", name, "--format", "{{.Image}}").stdout.strip()


def lab_images():
    return {
        service: image_id("xalgorix-assessment-lab-" + service + ":latest")
        for service in ("app-a-vulnerable", "app-a-fixed", "app-b-vulnerable")
    }


def installed_versions(container):
    versions = {}
    for tool in TOOLS:
        result = subprocess.run(
            ("docker", "exec", container, "sh", "-c", 'command -v "$1" >/dev/null && "$1" --version 2>&1 | head -n 3', "sh", tool),
            text=True, capture_output=True, timeout=15, check=False,
        )
        versions[tool] = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout.strip()) if result.returncode == 0 else "unavailable"
    return versions


def zap_content(container):
    urls = {
        "version": '"$XALGORIX_ZAP_URL/JSON/core/view/version/?apikey=$XALGORIX_ZAP_API_KEY"',
        "addons": '"$XALGORIX_ZAP_URL/JSON/autoupdate/view/installedAddons/?apikey=$XALGORIX_ZAP_API_KEY"',
    }
    content = {}
    for name, url in urls.items():
        result = subprocess.run(("docker", "exec", container, "sh", "-c", "curl -fsS --max-time 10 " + url),
                                capture_output=True, text=True, timeout=15, check=False)
        if result.returncode == 0:
            try:
                content[name] = json.loads(result.stdout)
            except json.JSONDecodeError:
                content[name] = "unavailable"
        else:
            content[name] = "unavailable"
    return content


def memory_bytes(usage):
    amount = usage.split("/", 1)[0].strip().replace(" ", "")
    match = re.fullmatch(r"([0-9.]+)([KMGT]?i?B|B)", amount)
    if not match:
        raise ValueError("unrecognized docker stats memory format: " + amount)
    suffix = match.group(2)
    power = "BKMGT".index(suffix[0]) if suffix != "B" else 0
    return int(float(match.group(1)) * (1024 if "i" in suffix else 1000) ** power)


def peak_memory(containers):
    total = 0
    for container in containers:
        usage = docker("stats", "--no-stream", "--format", "{{.MemUsage}}", container).stdout.strip()
        total += memory_bytes(usage)
    return total


class API:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method, path, value=None):
        body = None if value is None else json.dumps(value).encode()
        request = urllib.request.Request(self.base + path, data=body, method=method)
        request.add_header("Origin", self.base)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise APIError(exc.code, f"{method} {path}: HTTP {exc.code}") from exc
        return json.loads(raw) if raw else None


class APIError(RuntimeError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def wait_for_scan(api, instance_id, containers, max_seconds):
    start = time.monotonic()
    peak = 0
    while time.monotonic() - start < max_seconds:
        try:
            state = api.request("GET", "/api/instances/" + instance_id)
        except APIError as exc:
            if exc.status == 404 and time.monotonic() - start < 30:
                time.sleep(2)  # queue registration follows the /api/scan ack
                continue
            raise
        peak = max(peak, peak_memory(containers))
        if state["status"] in ("finished", "stopped", "failed", "cancelled"):
            return state, peak, int((time.monotonic() - start) * 1000)
        time.sleep(5)
    raise TimeoutError(f"instance {instance_id} did not finish within {max_seconds}s")


def read_report(container, instance_id):
    path = "/data/_assessments/" + hashlib.sha256(instance_id.encode()).hexdigest()[:32] + "/report.json"
    return json.loads(docker("exec", container, "cat", path).stdout)


def run_one(api, app, output, container, zap_container, max_seconds):
    app_id = app["id"]
    port = app["base_url"].rsplit(":", 1)[1]
    local = "http://127.0.0.1:" + port
    target = "http://host.docker.internal:" + port
    headers = {"X-Lab-Control": "local-only"}
    for suffix in ("/__lab/reset",):
        request = urllib.request.Request(local + suffix, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=10):
            pass
    values = {"login_url": target + "/login", "username": "lab-user", "password": "lab-password", "csrf_field": "csrf"}
    credential = api.request("POST", "/api/credentials", {
        "name": "temporary lab baseline", "kind": "FORM_LOGIN", "target_ids": ["app"], "values": values,
    })
    credential_id = credential["id"]
    instance_id = None
    terminal = False
    try:
        assessment = {
            "assessment_mode": "GRAY_BOX", "assessment_types": ["WEB_APPLICATION", "API"],
            "assessment_targets": [{"id": "app", "type": "URL", "value": target}],
            "profile": "web-gentle",
            "access": [{"target_ids": ["app"], "kind": "FORM_LOGIN", "credential_id": credential_id,
                        "verify_url": target + "/private", "verify_marker": "LAB_AUTHENTICATED_MARKER"}],
            "scanner_selection": {"mode": "auto"},
        }
        plan = api.request("POST", "/api/scans/plan", assessment)
        if plan.get("errors"):
            raise RuntimeError("assessment preflight has blocking errors: " + json.dumps(plan["errors"]))
        started = api.request("POST", "/api/scan", {
            "assessment": assessment, "targets": [target], "profile": "web-gentle",
            "scan_mode": "single", "name": "lab baseline " + app_id,
            "plan_fingerprint": plan["fingerprint"],
        })
        instance_id = started["instance_id"]
        state, peak, duration = wait_for_scan(api, instance_id, (container, zap_container), max_seconds)
        terminal = True
        report = read_report(container, instance_id)
        with urllib.request.urlopen(urllib.request.Request(local + "/__lab/metrics", headers=headers), timeout=10) as response:
            metrics = json.load(response)
        folder = output / app_id
        folder.mkdir(mode=0o700)
        (folder / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        (folder / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
        return ({"application_id": app_id, "target_url": target, "result_path": f"{app_id}/report.json",
                 "metrics_path": f"{app_id}/metrics.json", "duration_ms": duration,
                 "peak_memory_bytes": peak},
                {"application_id": app_id, "instance_status": state["status"],
                 "coverage_state": (report.get("assessment_coverage") or {}).get("state", "unknown"),
                 "coverage_gaps": len((report.get("assessment_coverage") or {}).get("gaps", [])),
                 "scanner_failures": [r.get("scanner") + ": " + r.get("status", "unknown")
                                      for r in report.get("source_runs", []) if r.get("status") in ("failed", "cancelled")]})
    finally:
        if instance_id and not terminal:
            try:
                api.request("POST", "/api/instances/" + instance_id + "/stop")
            except (APIError, RuntimeError):
                pass
        api.request("DELETE", "/api/credentials/" + credential_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="new private raw-results directory")
    parser.add_argument("--url", default="http://127.0.0.1:9137")
    parser.add_argument("--container", default="xalgorix-xalgorix-1")
    parser.add_argument("--zap-container", default="xalgorix-zap-1")
    parser.add_argument("--max-seconds", type=int, default=2400)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    cached_images = {"xalgorix": image_id("xalgorix:local"), **lab_images()}
    docker("compose", "-f", str(LAB_COMPOSE), "up", "-d", "--no-build", "--pull", "never", "--wait")
    images = {"xalgorix": container_image_id(args.container)}
    for service in ("app-a-vulnerable", "app-a-fixed", "app-b-vulnerable"):
        images[service] = container_image_id("xalgorix-assessment-lab-" + service + "-1")
    api = API(args.url)
    password = os.getenv("XALGORIX_BENCH_PASSWORD") or getpass.getpass("Xalgorix dashboard password: ")
    api.request("POST", "/api/auth/login", {"username": os.getenv("XALGORIX_BENCH_USER", "admin"), "password": password})
    del password
    manifest = json.loads(MANIFEST.read_text())
    observations, outcomes = [], []
    try:
        for app in manifest["applications"]:
            observation, outcome = run_one(api, app, args.output, args.container, args.zap_container, args.max_seconds)
            observations.append(observation)
            outcomes.append(outcome)
            print(app["id"] + ": " + outcome["coverage_state"], flush=True)
    finally:
        (args.output / "observations.json").write_text(json.dumps({"schema_version": 1, "runs": observations}, indent=2) + "\n")
        summary = {"schema_version": 1, "source_revision": "unknown: cached image has no Xalgorix commit label",
                   "images": images, "cached_image_ids": cached_images,
                   "running_image_matches_cache": images == cached_images,
                   "versions": installed_versions(args.container), "zap_content": zap_content(args.container),
                   "profile": "web-gentle",
                   "applications": outcomes, "baseline_complete": len(observations) == len(manifest["applications"])}
        (args.output / "baseline.json").write_text(json.dumps(summary, indent=2) + "\n")
    if len(observations) == len(manifest["applications"]):
        score = subprocess.run(("go", "run", "./test/lab/scorecard", "--observations", str(args.output / "observations.json")),
                               cwd=ROOT, check=True, capture_output=True, text=True)
        (args.output / "scorecard.json").write_text(score.stdout)
        summary = json.loads((args.output / "baseline.json").read_text())
        summary["scorecard"] = json.loads(score.stdout)
        (args.output / "baseline.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(score.stdout)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError, TimeoutError, ValueError) as exc:
        print("baseline failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
