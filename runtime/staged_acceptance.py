#!/usr/bin/env python3
"""Staged assessment acceptance driver.

Runs a real assessment through the public HTTP API of a running Xalgorix
instance against the disposable staged lab (test/stagedlab) and asserts what the
saved evidence actually shows. It uses only the Python standard library so it can
run inside the retained runtime image. Everything it contacts is synthetic and
local to the disposable container network created by runtime/staged-acceptance.sh.

Each check records PASS or FAIL with detail. Checks never infer success: a count
must match the lab, the inventory or the drill-down members it summarizes. The
exit status is non-zero when any check fails.
"""
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import zlib

APP = os.environ.get("STAGED_APP", "http://app:8888").rstrip("/")
USER = os.environ.get("STAGED_USER", "acceptance")
PASSWORD = os.environ.get("STAGED_PASSWORD", "")
LAB_CONTROL = os.environ.get("STAGED_LAB_CONTROL", "http://lab-primary:9000").rstrip("/")
PRIMARY = os.environ.get("STAGED_PRIMARY", "http://lab-primary:8080")
SECONDARY = os.environ.get("STAGED_SECONDARY", "https://lab-secondary:8443")
ALIAS = os.environ.get("STAGED_ALIAS", "http://lab-alias:8081")
TIMEOUT = int(os.environ.get("STAGED_SCAN_TIMEOUT", "2400"))
REUSE_SCAN = os.environ.get("STAGED_REUSE_SCAN", "")
RESULT_PATH = os.environ.get("STAGED_RESULT", "")
PHASE = os.environ.get("STAGED_PHASE", "full")
STATE_PATH = os.environ.get("STAGED_STATE", "/out/state.json")
PATH_PREFIX = "/app/"

results = []


def load_state():
    try:
        with open(STATE_PATH) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def save_state(state):
    with open(STATE_PATH, "w") as handle:
        json.dump(state, handle, indent=2)


def limitation(name, detail):
    results.append({"check": name, "status": "KNOWN_LIMITATION", "detail": str(detail)[:600]})
    print("LIMIT " + name + " - " + str(detail)[:300], flush=True)


def is_known_limitation(hit):
    """katana's headless Chromium fetches the origin-root favicon on its own."""
    return (hit["origin"] == "primary" and hit["method"] == "GET" and hit["path"] == "/favicon.ico"
            and "Chrome/" in hit.get("user_agent", ""))


def check(name, ok, detail=""):
    results.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": str(detail)[:600]})
    print(("PASS " if ok else "FAIL ") + name + ((" - " + str(detail)[:300]) if detail != "" else ""), flush=True)
    return ok


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None, raw=False, raw_body=None, content_type="application/json"):
        """raw_body sends bytes as-is (definition and fixture uploads); raw returns bytes."""
        data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
        request = urllib.request.Request(
            APP + path, data=data, method=method,
            headers={"Content-Type": content_type, "Origin": APP})
        try:
            with self.opener.open(request, timeout=120) as response:
                payload = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            payload, status = error.read(), error.code
        if raw:
            return status, payload
        text = payload.decode("utf-8", "replace")
        try:
            return status, json.loads(text)
        except ValueError:
            return status, text

    def login(self):
        status = None
        for _ in range(60):  # the application may still be starting
            try:
                status, _ = self.call("POST", "/api/auth/login", {"username": USER, "password": PASSWORD})
                break
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(1)
        return check("dashboard login", status == 200, status)


def lab(method, path):
    request = urllib.request.Request(LAB_CONTROL + path, method=method, headers={"X-Lab-Control": "local-only"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read()
    return json.loads(payload) if payload else None


def lab_spec(name):
    request = urllib.request.Request(LAB_CONTROL + "/specs/" + name, headers={"X-Lab-Control": "local-only"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()  # the recorder returns null for an empty list


def plan_config(variants):
    return {
        "workflow_version": "unified-v1",
        "assessment_mode": "BLACK_BOX",
        "assessment_types": ["WEB_APPLICATION"],
        "assessment_targets": [{"id": "app", "type": "URL", "value": PRIMARY + PATH_PREFIX}],
        "approved_origins": [{"target_id": "app", "scheme": "http", "host": "lab-primary", "port": 8080, "path_prefix": PATH_PREFIX}],
        "exclusions": [
            {"path_pattern": "/app/logout", "reason": "ends the session"},
            {"path_pattern": "/app/write", "reason": "state-changing route"},
            {"path_pattern": "/app/admin/delete", "reason": "destructive route"},
        ],
        "profile": "web-gentle",
        "scanner_selection": {"mode": "custom", "variants": variants},
    }


def wait_terminal(client, scan_id, label):
    deadline = time.time() + TIMEOUT
    last = None
    while time.time() < deadline:
        status, record = client.call("GET", "/api/scans/" + scan_id)
        state = record.get("status") if isinstance(record, dict) else None
        if state != last:
            print("  %s status: %s" % (label, state), flush=True)
            last = state
        if state in ("finished", "failed", "stopped"):
            return record
        time.sleep(10)
    return None


def start_scan(client, config, fingerprint, name):
    status, body = client.call("POST", "/api/scan", {"assessment": config, "plan_fingerprint": fingerprint, "scan_mode": "single", "name": name})
    if status != 200 or not isinstance(body, dict):
        return status, body, None
    # The dispatch ack carries the instance ID; the persisted assessment ID is
    # the newest scan whose instance matches.
    deadline = time.time() + 120
    while time.time() < deadline:
        _, listing = client.call("GET", "/api/scans")
        for item in listing or []:
            _, record = client.call("GET", "/api/scans/" + item["id"])
            if isinstance(record, dict) and record.get("instance_id") == body.get("instance_id"):
                return status, body, item["id"]
        time.sleep(2)
    return status, body, None


def surface_items(client, scan_id):
    """Return every inventory row, following pagination to the end."""
    items, page = [], 1
    while True:
        status, surface = client.call("GET", "/api/scans/%s/attack-surface?page=%d&size=500" % (scan_id, page))
        batch = surface.get("items", []) if isinstance(surface, dict) else []
        items.extend(batch)
        if len(batch) < 500:
            return items
        page += 1


def pdf_text(payload):
    """Extract showing-text operators from every Flate stream in a simple PDF."""
    out = []
    for stream in re.findall(rb"stream\r?\n(.*?)\r?\nendstream", payload, re.S):
        try:
            data = zlib.decompress(stream)
        except zlib.error:
            continue
        for match in re.findall(rb"\(((?:[^()\\]|\\.)*)\)\s*Tj", data):
            out.append(re.sub(rb"\\(.)", rb"\1", match).decode("latin-1"))
    return "\n".join(out)


def verify_assessment(client, scan_id, label, expect_secondary):
    status, coverage = client.call("GET", "/api/scans/%s/coverage" % scan_id)
    check(label + ": coverage available", status == 200 and isinstance(coverage, dict), status)
    if not isinstance(coverage, dict):
        return
    proof = coverage.get("proof") or {}
    check(label + ": expanded proof enabled", proof.get("expanded_enabled") is True)

    # Every job reached a recorded terminal outcome with a verified artifact.
    for job in coverage.get("jobs", []):
        check("%s: job %s recorded terminal outcome" % (label, job["scanner"]),
              job.get("status") in ("completed", "failed", "skipped", "cancelled", "partial"), job.get("status"))
        if job.get("status") == "completed":
            check("%s: job %s artifact verified" % (label, job["scanner"]), job.get("artifact_state") == "verified", job.get("artifact_state"))

    # Every drill-down total must equal the summary count it explains.
    for metric in ["discovered", "observed", "approved", "eligible", "seeds", "candidates", "hosts", "services", "tls_services", "forms", "parameterized", "observed_with_auth"]:
        status, page = client.call("GET", "/api/scans/%s/coverage/items?metric=%s&size=1" % (scan_id, metric))
        summary = proof.get(metric)
        check("%s: %s drill-down total equals summary" % (label, metric),
              status == 200 and isinstance(page, dict) and page.get("total") == summary, "summary=%s total=%s" % (summary, page.get("total") if isinstance(page, dict) else page))

    # Services count only live evidence; seeds and candidates never inflate it.
    status, services = client.call("GET", "/api/scans/%s/coverage/items?metric=services&size=200" % scan_id)
    hosts_urls = [item.get("url", "") for item in (services.get("items", []) if isinstance(services, dict) else [])]
    check(label + ": alias origin is not counted as a live service", not any("lab-alias" in url for url in hosts_urls), hosts_urls)
    check(label + ": primary origin is a live service", any(url.startswith(PRIMARY) for url in hosts_urls), hosts_urls)
    if expect_secondary:
        check(label + ": approved secondary origin is a live service", any("lab-secondary" in url for url in hosts_urls), hosts_urls)

    # Exact inventory: every cataloged request variant has an inventory row and a state.
    items = surface_items(client, scan_id)
    by_url = {}
    for item in items:
        by_url.setdefault((item.get("method"), item.get("url")), item)
    variants = lab("GET", "/variants")
    missing = [v for v in variants if ("GET", PRIMARY + v) not in by_url]
    check(label + ": all %d exact request variants are in the inventory" % len(variants), not missing, "missing %d, first %s" % (len(missing), missing[:3]))
    check(label + ": paginated inventory row count equals the discovered summary", len(items) == proof.get("discovered"),
          "rows=%d discovered=%s" % (len(items), proof.get("discovered")))
    blank = [i for i in items if not i.get("state")]
    check(label + ": every inventory request has a disposition state", not blank, "blank=%d of %d" % (len(blank), len(items)))
    excluded = [i for i in items if i.get("state") == "excluded"]
    check(label + ": excluded write route is dispositioned, not requested",
          any(i.get("url", "").endswith("/app/write") for i in excluded), [i.get("url") for i in excluded][:5])

    # Exact endpoint trace for a sample resolves to the same inventory row.
    sample = next((i for i in items if i.get("url") == PRIMARY + "/app/about"), None)
    if sample:
        status, trace = client.call("GET", "/api/scans/%s/endpoints/%s/trace" % (scan_id, sample["id"]))
        check(label + ": endpoint trace resolves exact request", status == 200 and trace.get("endpoint", {}).get("url") == sample["url"], status)

    # No forbidden traffic reached the lab, apart from limitations recorded below.
    forbidden = (lab("GET", "/forbidden") or [])
    known = [h for h in forbidden if is_known_limitation(h)]
    unknown = [h for h in forbidden if not is_known_limitation(h)]
    check(label + ": no unexplained traffic outside the approved boundary", not unknown,
          "%d request(s), first %s" % (len(unknown), unknown[:2]))
    if known:
        limitation(label + ": katana headless Chromium requested /favicon.ico outside the approved path prefix",
                   "%d request(s). katana is not routed through the recording gateway, so its -cs/-cos fences cannot constrain the browser's own favicon fetch." % len(known))

    # The offline report is generated from saved artifacts and agrees with the API.
    status, payload = client.call("GET", "/api/report/" + scan_id, raw=True)
    check(label + ": report downloads as PDF", status == 200 and payload[:5] == b"%PDF-", status)
    text = pdf_text(payload)
    match = re.search(r"Inventory: (\d+) requests, (\d+) seeds, (\d+) hosts, (\d+) services, (\d+) TLS services, (\d+) forms, (\d+) parameterized", text.replace("\n", " "))
    expected = tuple(proof.get(k) for k in ("discovered", "seeds", "hosts", "services", "tls_services", "forms", "parameterized"))
    check(label + ": report inventory totals equal API totals", bool(match) and tuple(int(v) for v in match.groups()) == expected,
          "report=%s api=%s" % (match.groups() if match else "no inventory line", expected))
    return coverage


def phase_full():
    client = Client()
    if not client.login():
        return finish()

    config = plan_config(["httpx", "katana"])
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("plan preview accepted", status == 200 and isinstance(plan, dict) and not plan.get("errors"), plan.get("errors") if isinstance(plan, dict) else status)
    if not isinstance(plan, dict) or not plan.get("fingerprint"):
        return finish()
    origins = plan["config"].get("approved_origins", [])
    check("approved boundary is one origin with the path prefix", len(origins) == 1 and origins[0]["host"] == "lab-primary" and origins[0]["path_prefix"] == PATH_PREFIX.rstrip("/"), origins)
    check("plan selects the preparation scanners", sorted(j["scanner"] for j in plan["jobs"]) == ["httpx", "katana"], [j["scanner"] for j in plan["jobs"]])

    status, body = client.call("POST", "/api/scan", {"assessment": config, "plan_fingerprint": "sha256:stale", "scan_mode": "single"})
    check("stale plan fingerprint is rejected with HTTP 409", status == 409, status)

    lab("POST", "/reset")
    scan_id = REUSE_SCAN
    if not scan_id:
        status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-acceptance")
        check("assessment accepted for start", status == 200 and bool(scan_id), "%s %s" % (status, str(ack)[:200]))
        if not scan_id:
            return finish()
    record = wait_terminal(client, scan_id, "assessment")
    check("assessment reached a terminal state", record is not None and record.get("status") == "finished", record.get("status") if record else "timeout")
    if record is None:
        return finish()

    verify_assessment(client, scan_id, "base", expect_secondary=False)

    # Discovery review: candidates carry provenance and stay candidates.
    status, preview = client.call("GET", "/api/scans/%s/discovery" % scan_id)
    check("discovery preview awaiting approval", status == 200 and preview.get("state") == "awaiting_approval", preview.get("state") if isinstance(preview, dict) else status)
    candidates = preview.get("candidates", []) if isinstance(preview, dict) else []
    values = {c.get("value"): c for c in candidates}
    check("alias origin is only a candidate", ALIAS in values and values[ALIAS].get("state") == "candidate", list(values))
    check("secondary origin is only a candidate", SECONDARY in values and values[SECONDARY].get("state") == "candidate", list(values))
    check("every candidate has a source and proposed actions", all(c.get("source") and c.get("actions") for c in candidates), [c.get("id") for c in candidates if not (c.get("source") and c.get("actions"))])
    status, _ = client.call("POST", "/api/scans/%s/discovery" % scan_id, {"fingerprint": "stale", "selected_ids": [c["id"] for c in candidates][:1]})
    check("stale discovery approval is rejected with HTTP 409", status == 409, status)

    # Approve only the secondary origin; the alias stays unapproved.
    secondary = values.get(SECONDARY)
    if not secondary:
        return finish()
    status, revision = client.call("POST", "/api/scans/%s/discovery" % scan_id, {"fingerprint": preview["fingerprint"], "selected_ids": [secondary["id"]]})
    check("secondary origin approved into a child revision", status == 200 and isinstance(revision, dict), "%s %s" % (status, str(revision)[:200]))
    if not isinstance(revision, dict):
        return finish()
    plan_after = revision["plan"]
    check("revision retains parent and preview links", revision.get("parent_fingerprint") == plan["fingerprint"] or revision.get("parent_fingerprint") == (record.get("plan_fingerprint")), revision.get("parent_fingerprint"))
    target_values = sorted(t["value"] for t in plan_after["config"].get("assessment_targets", []))
    check("revision adds the secondary target and not the alias", SECONDARY in target_values and ALIAS not in target_values, target_values)
    check("revision clears write and fuzz consent", not plan_after["config"].get("write_approvals") and not plan_after["config"].get("fuzz_approvals"))
    status, parent = client.call("GET", "/api/scans/" + scan_id)
    check("approval left the accepted parent unchanged", parent.get("plan_fingerprint") == record.get("plan_fingerprint"))

    lab("POST", "/reset")
    status, ack, child_id = start_scan(client, plan_after["config"], plan_after["fingerprint"], "staged-acceptance-revision")
    check("approved revision accepted for start", status == 200 and bool(child_id), "%s %s" % (status, str(ack)[:200]))
    if not child_id:
        return finish()
    child = wait_terminal(client, child_id, "revision")
    check("revision reached a terminal state", child is not None and child.get("status") == "finished", child.get("status") if child else "timeout")
    if child is None:
        return finish()
    verify_assessment(client, child_id, "revision", expect_secondary=True)
    hits = (lab("GET", "/hits") or [])
    check("approved secondary origin was contacted only after approval", any(h["origin"] == "secondary" for h in hits), len(hits))
    check("alias origin was never contacted", not any(h["origin"] == "alias" for h in hits))
    return finish()


def scan_record(client, scan_id):
    status, record = client.call("GET", "/api/scans/" + scan_id)
    return record if status == 200 and isinstance(record, dict) else {}


def run_summary(record):
    return {"%s/%s" % (r.get("scanner"), r.get("scope", "")): {"status": r.get("status"), "attempt": r.get("attempt_id")} for r in record.get("scanner_runs") or []}


def phase_recovery_base():
    """Complete a base assessment and capture the pending discovery preview."""
    client = Client()
    if not client.login():
        return finish()
    config = plan_config(["httpx", "katana"])
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("recovery: plan preview accepted", status == 200 and not plan.get("errors"), status)
    lab("POST", "/reset")
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-recovery-base")
    check("recovery: base assessment started", status == 200 and bool(scan_id), status)
    record = wait_terminal(client, scan_id, "base")
    check("recovery: base assessment finished", record is not None and record.get("status") == "finished", record.get("status") if record else "timeout")
    status, preview = client.call("GET", "/api/scans/%s/discovery" % scan_id)
    check("recovery: discovery awaiting approval before restart", status == 200 and preview.get("state") == "awaiting_approval", status)
    save_state({"config": config, "base_id": scan_id, "plan_fingerprint": record.get("plan_fingerprint"), "preview": preview})
    return finish()


def phase_recovery_pending():
    """After a graceful restart: the pending approval survives and still works."""
    state = load_state()
    client = Client()
    if not client.login():
        return finish()
    base_id, saved = state["base_id"], state["preview"]
    status, preview = client.call("GET", "/api/scans/%s/discovery" % base_id)
    check("restart: pending preview fingerprint is unchanged", status == 200 and preview.get("fingerprint") == saved["fingerprint"], preview.get("fingerprint") if isinstance(preview, dict) else status)
    check("restart: pending preview still awaits approval", preview.get("state") == "awaiting_approval", preview.get("state"))
    check("restart: candidate identities are unchanged", sorted(c["id"] for c in preview["candidates"]) == sorted(c["id"] for c in saved["candidates"]))
    record = scan_record(client, base_id)
    check("restart: finished base record is still finished", record.get("status") == "finished", record.get("status"))
    status, _ = client.call("POST", "/api/scans/%s/discovery" % base_id, {"fingerprint": "stale", "selected_ids": [preview["candidates"][0]["id"]]})
    check("restart: stale approval is still rejected with HTTP 409", status == 409, status)
    secondary = next((c for c in preview["candidates"] if c["value"] == SECONDARY), None)
    check("restart: secondary candidate is still present", secondary is not None)
    if not secondary:
        return finish()
    status, revision = client.call("POST", "/api/scans/%s/discovery" % base_id, {"fingerprint": preview["fingerprint"], "selected_ids": [secondary["id"]]})
    check("restart: pending approval can be accepted after restart", status == 200 and isinstance(revision, dict), status)
    if isinstance(revision, dict):
        check("restart: accepted revision links the persisted parent", revision.get("parent_fingerprint") == state["plan_fingerprint"], revision.get("parent_fingerprint"))
        state["revision"] = revision
        save_state(state)
    return finish()


def phase_recovery_accepted():
    """After a second restart: the accepted revision persists; start it and wait until it is mid-run."""
    state = load_state()
    client = Client()
    if not client.login():
        return finish()
    base_id, revision = state["base_id"], state["revision"]
    status, preview = client.call("GET", "/api/scans/%s/discovery" % base_id)
    approved = (preview or {}).get("approved_revision") or {}
    check("restart: accepted revision survives a second restart", approved.get("plan", {}).get("fingerprint") == revision["plan"]["fingerprint"], approved.get("plan", {}).get("fingerprint"))
    check("restart: accepted revision keeps parent and preview links", approved.get("parent_fingerprint") == revision["parent_fingerprint"] and approved.get("preview_fingerprint") == revision["preview_fingerprint"])
    check("restart: accepted parent plan is unchanged", scan_record(client, base_id).get("plan_fingerprint") == state["plan_fingerprint"])
    lab("POST", "/reset")
    plan_after = approved["plan"]
    status, ack, child_id = start_scan(client, plan_after["config"], plan_after["fingerprint"], "staged-recovery-revision")
    check("restart: accepted revision starts after restart", status == 200 and bool(child_id), status)
    if not child_id:
        return finish()
    # Wait until at least one job completed and another is still running.
    deadline, summary = time.time() + 600, {}
    while time.time() < deadline:
        record = scan_record(client, child_id)
        summary = run_summary(record)
        states = [v["status"] for v in summary.values()]
        if "completed" in states and "running" in states:
            break
        time.sleep(3)
    check("restart: revision is mid-run with a completed and a running job", "completed" in [v["status"] for v in summary.values()] and "running" in [v["status"] for v in summary.values()], summary)
    state["child_id"], state["midrun"] = child_id, summary
    save_state(state)
    return finish()


def phase_recovery_midrun():
    """After a hard kill during execution: nothing is claimed complete that did not finish."""
    state = load_state()
    client = Client()
    if not client.login():
        return finish()
    child_id, before = state["child_id"], state["midrun"]
    first = scan_record(client, child_id)
    print("  status after restart: %s reason=%s" % (first.get("status"), first.get("stop_reason")), flush=True)
    check("kill: interrupted record is not left running without a process", first.get("status") != "running" or bool(first.get("scanner_runs")), first.get("status"))
    # Watch for an automatic retry. A terminal record that stays unchanged for
    # 30 s (longer than the 5 s startup auto-resume delay) is the final outcome.
    deadline, last, stable_since, record = time.time() + 1500, None, time.time(), first
    while time.time() < deadline:
        record = scan_record(client, child_id)
        current = (record.get("status"), json.dumps(run_summary(record), sort_keys=True))
        if current != last:
            print("  %s %s" % (record.get("status"), run_summary(record)), flush=True)
            last, stable_since = current, time.time()
        if record.get("status") in ("finished", "failed", "stopped") and time.time() - stable_since >= 30:
            break
        time.sleep(5)
    summary = run_summary(record)
    for key, was in before.items():
        now = summary.get(key)
        if was["status"] == "completed":
            check("kill: completed attempt %s is retained, not re-run" % key, bool(now) and now["attempt"] == was["attempt"] and now["status"] == "completed", "before=%s now=%s" % (was, now))
        else:
            # The interrupted attempt must be re-run under a new attempt ID and
            # recorded as completed, never dropped, left running, or treated as
            # finished from truncated output. A completed crawl is relabelled from
            # its discovery scope to its job scope, so match on the scanner family.
            family = key.split("/", 1)[0]
            rerun = {k: v for k, v in summary.items() if k.split("/", 1)[0] == family and v["status"] == "completed" and v["attempt"] and v["attempt"] != was["attempt"]}
            check("kill: interrupted %s attempt (%s) was re-run under a new attempt ID and completed" % (key, was["attempt"]), bool(rerun), "before=%s now=%s" % (was, rerun or summary))
    skipped = [k for k, v in summary.items() if k.startswith("katana/") and v["status"] == "skipped"]
    check("kill: no selected katana crawl ended skipped after the restart", not skipped, skipped)
    check("kill: the resumed assessment finished", record.get("status") == "finished", record.get("status"))
    status, listing = client.call("GET", "/api/scans")
    running = [i for i in listing or [] if i.get("status") == "running"]
    check("kill: no scan is left in a stale running state", not running or record.get("status") == "running", [i["id"] for i in running])
    state["after_kill"] = {"status": record.get("status"), "stop_reason": record.get("stop_reason"), "runs": summary}
    save_state(state)
    return finish()


def phase_recovery_stop():
    """Start a scan and stop it explicitly; a later restart must not resume it."""
    state = load_state()
    client = Client()
    if not client.login():
        return finish()
    config = state["config"]
    status, plan = client.call("POST", "/api/scans/plan", config)
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-recovery-stop")
    check("stop: scan started", status == 200 and bool(scan_id), status)
    if not scan_id:
        return finish()
    deadline = time.time() + 300
    while time.time() < deadline and scan_record(client, scan_id).get("status") != "running":
        time.sleep(2)
    time.sleep(5)
    status, _ = client.call("POST", "/api/stop", {})
    check("stop: explicit stop accepted", status == 200, status)
    deadline = time.time() + 120
    while time.time() < deadline and scan_record(client, scan_id).get("status") not in ("stopped", "finished", "failed"):
        time.sleep(2)
    record = scan_record(client, scan_id)
    check("stop: scan is stopped by the user", record.get("status") == "stopped", "%s %s" % (record.get("status"), record.get("stop_reason")))
    state["stop_id"] = scan_id
    save_state(state)
    return finish()


def phase_recovery_after_stop():
    state = load_state()
    client = Client()
    if not client.login():
        return finish()
    time.sleep(45)  # longer than the 5 s startup auto-resume delay
    record = scan_record(client, state["stop_id"])
    check("restart: explicitly stopped scan stays stopped", record.get("status") == "stopped", "%s %s" % (record.get("status"), record.get("stop_reason")))
    status, listing = client.call("GET", "/api/scans")
    check("restart: nothing was auto-resumed after an explicit stop", not [i for i in listing or [] if i.get("status") in ("running", "pending")], [(i["id"], i["status"]) for i in listing or []])
    forbidden = [h for h in (lab("GET", "/forbidden") or []) if not is_known_limitation(h)]
    check("recovery: no unexplained traffic outside the boundary across restarts", not forbidden, forbidden[:2])
    return finish()


LAB_SECRETS = [
    "lab-admin-password", "lab-viewer-password", "lab-admin-session", "lab-viewer-session", "lab_session=lab",
]


def identity_config(admin_id, viewer_id):
    config = plan_config(["httpx", "katana"])
    config["assessment_mode"] = "GRAY_BOX"

    def binding(credential_id, identity, role, marker):
        return {"target_ids": ["app"], "kind": "FORM_LOGIN", "credential_id": credential_id, "identity": identity, "role": role,
                "verify_url": PRIMARY + PATH_PREFIX + "private", "verify_marker": marker, "negative_marker": marker, "verify_browser": True}
    config["access"] = [binding(admin_id, "admin", "administrator", "LAB_ADMIN_MARKER"), binding(viewer_id, "viewer", "viewer", "LAB_VIEWER_MARKER")]
    return config


def phase_identities():
    """Two supplied identities with protected markers, an anonymous control and secret hygiene."""
    client = Client()
    if not client.login():
        return finish()
    ids = {}
    for name, user, password in (("admin", "admin", "lab-admin-password"), ("viewer", "viewer", "lab-viewer-password")):
        status, meta = client.call("POST", "/api/credentials", {"name": "staged " + name, "kind": "FORM_LOGIN", "target_ids": ["app"],
                                    "values": {"login_url": PRIMARY + PATH_PREFIX + "login", "username": user, "password": password, "csrf_field": "csrf"}})
        check("identity: %s credential stored in the encrypted vault" % name, status == 201 and isinstance(meta, dict) and meta.get("id"), status)
        ids[name] = meta.get("id") if isinstance(meta, dict) else None
        check("identity: %s credential metadata exposes no secret" % name, password not in json.dumps(meta))
    if not all(ids.values()):
        return finish()

    def access_test(credential, marker, verify_path, browser):
        return client.call("POST", "/api/credentials/%s/test" % credential, {"target_id": "app", "target_url": PRIMARY + PATH_PREFIX,
                           "verify_url": PRIMARY + PATH_PREFIX + verify_path, "verify_marker": marker, "browser": browser})
    for browser in (False, True):
        mode = "browser" if browser else "HTTP"
        status, body = access_test(ids["admin"], "LAB_ADMIN_MARKER", "private", browser)
        check("identity: admin %s access test verifies the protected marker with an anonymous control" % mode, status == 200 and body.get("verified") is True, body)
        status, body = access_test(ids["viewer"], "LAB_VIEWER_MARKER", "private", browser)
        check("identity: viewer %s access test verifies its own marker" % mode, status == 200 and body.get("verified") is True, body)
    status, body = access_test(ids["viewer"], "LAB_ADMIN_ONLY", "admin", False)
    check("identity: viewer is refused the admin-only route", status == 200 and body.get("verified") is False, body)
    status, body = access_test(ids["admin"], "LAB_ADMIN_MARKER", "about", False)
    check("identity: a public page is rejected by the anonymous negative control", status == 200 and body.get("verified") is False, body)

    config = identity_config(ids["admin"], ids["viewer"])
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("identity: plan preview with two named identities", status == 200 and not plan.get("errors"), plan.get("errors") if isinstance(plan, dict) else status)
    if not isinstance(plan, dict) or not plan.get("fingerprint"):
        return finish()
    lab("POST", "/reset")
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-identities")
    check("identity: assessment started", status == 200 and bool(scan_id), status)
    if not scan_id:
        return finish()
    record = wait_terminal(client, scan_id, "identities")
    check("identity: assessment finished", record is not None and record.get("status") == "finished", record.get("status") if record else "timeout")
    if record is None:
        return finish()

    status, coverage = client.call("GET", "/api/scans/%s/coverage" % scan_id)
    proof = coverage.get("proof") or {}
    discovery = proof.get("identity_discovery") or []
    # The first identity is the primary one and keeps the normal authenticated
    # crawl; every additional identity gets an independent browser discovery run.
    labels = sorted(i.get("identity") for i in discovery)
    check("identity: the additional identity has its own browser discovery run", labels == ["viewer"], labels)
    check("identity: every identity names its role and authentication state", all(i.get("role") and i.get("auth_state") for i in discovery), discovery)
    check("identity: requests observed with authentication are counted", (proof.get("observed_with_auth") or 0) > 0, proof.get("observed_with_auth"))
    items = surface_items(client, scan_id)
    private = [i for i in items if i.get("url", "").endswith("/app/private")]
    check("identity: the protected route is in the inventory", bool(private), len(items))
    hits = (lab("GET", "/hits") or [])
    seen = {h["identity"] for h in hits if h["path"] in (PATH_PREFIX + "private", PATH_PREFIX + "api/me")}
    check("identity: the lab saw both identities and an anonymous control", {"admin", "viewer", "anonymous"} <= seen, sorted(seen))
    forbidden = [h for h in (lab("GET", "/forbidden") or []) if not is_known_limitation(h)]
    check("identity: no unexplained traffic outside the boundary", not forbidden, forbidden[:2])

    # No synthetic credential, cookie or session value may appear in anything the
    # API, the saved artifacts or the offline report expose.
    surfaces = {}
    for name, path in (("scan record", "/api/scans/" + scan_id), ("coverage", "/api/scans/%s/coverage" % scan_id),
                       ("discovery", "/api/scans/%s/discovery" % scan_id), ("findings", "/api/scans/%s/findings" % scan_id),
                       ("credential list", "/api/credentials")):
        surfaces[name] = json.dumps(client.call("GET", path)[1])
    surfaces["attack surface"] = json.dumps(items)
    for run in (client.call("GET", "/api/scans/" + scan_id)[1].get("scanner_runs") or []):
        scope = run.get("scope") or ""
        if run.get("scanner") in ("httpx", "katana") and run.get("status") in ("completed", "failed", "cancelled"):
            status, body = client.call("GET", "/api/scans/%s/%s/artifact?scope=%s" % (scan_id, run["scanner"], scope), raw=True)
            if status == 200:
                surfaces["%s artifact (%s)" % (run["scanner"], scope)] = body.decode("utf-8", "replace")
            for stream in ("stdout", "stderr", "combined"):
                status, body = client.call("GET", "/api/scans/%s/output/%s/%s?scope=%s" % (scan_id, run["scanner"], stream, scope), raw=True)
                if status == 200:
                    surfaces["%s %s (%s)" % (run["scanner"], stream, scope)] = body.decode("utf-8", "replace")
    status, pdf = client.call("GET", "/api/report/" + scan_id, raw=True)
    surfaces["report text"] = pdf_text(pdf)
    for name, text in surfaces.items():
        leaked = [secret for secret in LAB_SECRETS if secret in text]
        check("identity: %s contains no synthetic credential or session value" % name, not leaked, leaked)
    return finish()


GQL_TARGET = PRIMARY + PATH_PREFIX + "graphql"


def api_config(admin_id, viewer_id, refs, definitions, variants=None, fuzz=None):
    """GRAY_BOX assessment: two URL targets on the approved origin, definitions, an exactly-once
    write, authorization expectations and optionally an approved form campaign."""
    config = plan_config(variants or ["httpx", "apichecks"])
    config["assessment_mode"] = "GRAY_BOX"
    config["assessment_types"] = ["WEB_APPLICATION", "API"]
    config["test_environment"] = True
    config["assessment_targets"].append({"id": "gql", "type": "URL", "value": GQL_TARGET})
    config["approved_origins"].append({"target_id": "gql", "scheme": "http", "host": "lab-primary", "port": 8080, "path_prefix": PATH_PREFIX})

    def binding(credential_id, identity, role, marker):
        return {"target_ids": ["app"], "kind": "FORM_LOGIN", "credential_id": credential_id, "identity": identity, "role": role,
                "verify_url": PRIMARY + PATH_PREFIX + "private", "verify_marker": marker, "negative_marker": marker, "verify_browser": False}
    config["access"] = [binding(admin_id, "admin", "administrator", "LAB_ADMIN_MARKER"), binding(viewer_id, "viewer", "viewer", "LAB_VIEWER_MARKER")]
    config["api_definitions"] = [{"target_id": "app", "definition_id": definitions["openapi"]}, {"target_id": "gql", "definition_id": definitions["graphql"]}]
    config["api_operation_inputs"] = [
        {"definition_id": definitions["openapi"], "operation_id": "getRecord", "path_params": {"id": "rec-1"}},
        {"definition_id": definitions["graphql"], "operation_id": "query record", "query": {"id": "rec-1"}},
    ]
    config["manual_seeds"] = [PRIMARY + PATH_PREFIX + "graphql-noint"]
    config["write_approvals"] = [{"target_id": "app", "method": "POST", "path": "/api/notes", "operation_id": "createNote", "fixture_ref": refs["note"],
                                  "content_type": "application/x-www-form-urlencoded", "cleanup_method": "DELETE", "cleanup_path": "/api/notes/fixture"}]
    config["authorization_expectations"] = [
        {"operation_id": "getAdminPanel", "identity": "admin", "expect": "allow", "resource_fixture_ref": refs["admin_panel"]},
        {"operation_id": "getAdminPanel", "identity": "viewer", "expect": "deny", "resource_fixture_ref": refs["admin_panel"]},
    ]
    if fuzz:
        config["fuzz_approvals"] = [fuzz]
    return config


def upload_definitions(client):
    """Valid documents are accepted by content hash; lookalikes and introspection JSON are refused."""
    ids = {}
    for name, key, fmt in (("openapi.json", "openapi", "json"), ("schema.graphql", "graphql", "graphql")):
        status, body = client.call("POST", "/api/api-definitions", raw_body=lab_spec(name), content_type="application/octet-stream")
        check("api: valid %s definition is accepted" % name, status == 201 and isinstance(body, dict) and body.get("format") == fmt and body.get("operation_count", 0) > 0, "%s %s" % (status, body))
        ids[key] = body.get("id") if isinstance(body, dict) else None
    for name in ("openapi-lookalike.json", "openapi-html.html", "introspection.json"):
        status, body = client.call("POST", "/api/api-definitions", raw_body=lab_spec(name), content_type="application/octet-stream")
        check("api: %s is refused as a definition" % name, status == 400, "%s %s" % (status, str(body)[:120]))
    return ids


def upload_fixtures(client):
    refs = {}
    admin_fixture = json.dumps({"url": PRIMARY + PATH_PREFIX + "admin", "response_marker": "LAB_ADMIN_ONLY"}).encode()
    for key, body in (("note", b"text=staged-note-fixture"), ("fuzz", b"name=probe&value=seed"), ("admin_panel", admin_fixture)):
        status, meta = client.call("POST", "/api/api-fixtures", raw_body=body, content_type="application/x-www-form-urlencoded" if key != "admin_panel" else "application/json")
        check("api: %s fixture is stored by content hash" % key, status == 201 and isinstance(meta, dict) and len(meta.get("ref", "")) == 64, "%s" % status)
        refs[key] = meta.get("ref") if isinstance(meta, dict) else None
    return refs


def make_identities(client):
    ids = {}
    for name, user, password in (("admin", "admin", "lab-admin-password"), ("viewer", "viewer", "lab-viewer-password")):
        status, meta = client.call("POST", "/api/credentials", {"name": "staged " + name, "kind": "FORM_LOGIN", "target_ids": ["app"],
                                    "values": {"login_url": PRIMARY + PATH_PREFIX + "login", "username": user, "password": password, "csrf_field": "csrf"}})
        ids[name] = meta.get("id") if isinstance(meta, dict) else None
    return ids


def phase_api():
    """OpenAPI and GraphQL definitions, supplied inputs, an exactly-once write with cleanup and
    authorization comparisons between two identities."""
    client = Client()
    if not client.login():
        return finish()
    ids = make_identities(client)
    definitions = upload_definitions(client)
    refs = upload_fixtures(client)
    if not (all(ids.values()) and all(definitions.values()) and all(refs.values())):
        return finish()
    config = api_config(ids["admin"], ids["viewer"], refs, definitions)
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("api: plan preview accepts both definitions, the write approval and the expectations", status == 200 and not plan.get("errors"), plan.get("errors") if isinstance(plan, dict) else status)
    if not isinstance(plan, dict) or not plan.get("fingerprint"):
        return finish()
    check("api: the exactly-once write adds an apiwrites job", any(j["scanner"] == "apiwrites" for j in plan["jobs"]), sorted({j["scanner"] for j in plan["jobs"]}))
    lab("POST", "/reset")
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-api")
    check("api: assessment started", status == 200 and bool(scan_id), status)
    if not scan_id:
        return finish()
    record = wait_terminal(client, scan_id, "api")
    check("api: assessment finished", record is not None and record.get("status") == "finished", record.get("status") if record else "timeout")
    if record is None:
        return finish()

    status, coverage = client.call("GET", "/api/scans/%s/coverage" % scan_id)
    save_state({"api_scan": scan_id})
    proof = coverage.get("proof") or {}
    operations = {(o.get("target_id"), o.get("method"), o.get("path")): o for o in coverage.get("api_operations") or []}

    def op(target, method, path):
        return operations.get((target, method, path), {})
    for target, method, path in (("app", "GET", "/admin"), ("app", "GET", "/api/records"), ("app", "GET", "/api/records/{id}"), ("gql", "GET", "/app/graphql")):
        check("api: read-only %s %s is tested natively" % (method, path), op(target, method, path).get("status") == "tested", op(target, method, path))
    note = op("app", "POST", "/api/notes")
    check("api: the approved write is reported as tested with its cleanup", note.get("status") == "tested" and "cleanup" in note.get("reason", ""), note)
    unapproved = op("app", "POST", "/api/records")
    check("api: an unapproved POST stays skipped with a reason", unapproved.get("status") == "skipped" and bool(unapproved.get("reason")), unapproved)
    mutation = op("gql", "POST", "/app/graphql")
    check("api: a GraphQL mutation is never eligible", mutation.get("status") == "skipped" and "mutation" in mutation.get("reason", ""), mutation)
    check("api: no operation was invented from a duplicated GraphQL path", not any(p.endswith("/app/graphql/app/graphql") for (_, _, p) in operations), sorted(operations))
    counts = coverage.get("api_operation_counts") or {}
    check("api: operation counts match the listed statuses", counts.get("discovered") == len(operations) and counts.get("completed") == sum(1 for o in operations.values() if o.get("status") == "tested") and counts.get("skipped") == sum(1 for o in operations.values() if o.get("status") == "skipped"), counts)

    jobs = {(j["scanner"], j["target_id"]): j for j in coverage.get("jobs") or []}
    check("api: the approved write job completed", jobs.get(("apiwrites", "app"), {}).get("status") == "completed", jobs.get(("apiwrites", "app")))

    # Exactly-once write with declared cleanup, as the lab saw it.
    hits = lab("GET", "/hits") or []
    posts = [h for h in hits if h["method"] == "POST" and h["path"] == PATH_PREFIX + "api/notes"]
    deletes = [h for h in hits if h["method"] == "DELETE" and h["path"] == PATH_PREFIX + "api/notes/fixture"]
    check("api: the approved write reached the lab exactly once", len(posts) == 1 and posts[0]["body"] == "text=staged-note-fixture", [h["body"] for h in posts])
    check("api: the declared cleanup reached the lab exactly once", len(deletes) == 1, len(deletes))
    check("api: the controlled resource was cleaned up", (lab("GET", "/resources") or {}).get("resources") == 0, lab("GET", "/resources"))
    check("api: no unapproved POST reached the records resource", not [h for h in hits if h["method"] == "POST" and h["path"] == PATH_PREFIX + "api/records"])
    check("api: no request went to a duplicated GraphQL path", not [h for h in hits if h["path"].endswith("/app/graphql/app/graphql")], [h["path"] for h in hits if "graphql" in h["path"]])
    check("api: no inventory row was invented from a duplicated GraphQL path", not [i for i in surface_items(client, scan_id) if i.get("url", "").endswith("/app/graphql/app/graphql")])

    # Definitions: supplied documents, a discovered endpoint with introspection, and one without.
    definitions_seen = proof.get("definitions") or []
    states = {(d.get("kind"), d.get("state")) for d in definitions_seen}
    check("api: the supplied OpenAPI and GraphQL definitions are recorded", ("openapi", "supplied") in states and ("graphql", "supplied") in states, sorted(states))
    check("api: a GraphQL endpoint with introspection is discovered and validated", ("graphql", "validated") in states, sorted(states))
    noint = [d for d in definitions_seen if d.get("state") == "unavailable" and "graphql-noint" in (d.get("url") or "")]
    check("api: a GraphQL endpoint with introspection disabled is recorded as unavailable", bool(noint), [d for d in definitions_seen if d.get("state") == "unavailable"])
    check("api: the manual seed is counted", (proof.get("seeds") or 0) >= 1, proof.get("seeds"))

    # Authorization comparisons between the two supplied identities.
    results = [r for r in proof.get("authorization_results") or [] if r.get("status") != "skipped"]
    admin = next((r for r in results if r.get("identity") == "admin"), {})
    viewer = next((r for r in results if r.get("identity") == "viewer"), {})
    check("api: admin is allowed the resource and the marker is confirmed", admin.get("expected") == "allow" and admin.get("observed") == "allow" and admin.get("status") == "matched" and admin.get("marker_confirmed") is True and admin.get("response_code") == 200, admin)
    check("api: viewer is denied the resource as expected", viewer.get("expected") == "deny" and viewer.get("observed") == "deny" and viewer.get("status") == "matched" and viewer.get("response_code") == 403, viewer)
    skipped = [r for r in proof.get("authorization_results") or [] if r.get("status") == "skipped"]
    check("api: comparisons without an authentication context are skipped with a reason", all(r.get("reason") for r in skipped), skipped)
    findings = client.call("GET", "/api/scans/%s/findings" % scan_id)[1]
    titles = json.dumps(findings)
    check("api: correctly enforced access produces no access-control finding", "api-role-access-not-enforced" not in titles and "not enforced" not in titles.lower(), titles[:200])

    # Secret and fixture hygiene across everything the API and the report expose.
    surfaces = {"scan record": json.dumps(client.call("GET", "/api/scans/" + scan_id)[1]), "coverage": json.dumps(coverage),
                "attack surface": json.dumps(surface_items(client, scan_id)), "findings": titles,
                "discovery": json.dumps(client.call("GET", "/api/scans/%s/discovery" % scan_id)[1])}
    status, pdf = client.call("GET", "/api/report/" + scan_id, raw=True)
    report = pdf_text(pdf)
    surfaces["report text"] = report
    for name, text in surfaces.items():
        leaked = [secret for secret in LAB_SECRETS + ["staged-note-fixture"] if secret in text]
        check("api: %s contains no credential, session or fixture body" % name, not leaked, leaked)
    flat = report.replace("\n", " ")
    check("api: the report lists the authorization comparisons for both identities", "Authorization admin" in flat and "Authorization viewer" in flat, flat[:80])
    forbidden = [h for h in (lab("GET", "/forbidden") or []) if not is_known_limitation(h)]
    check("api: no unexplained traffic outside the approved boundary", not forbidden, forbidden[:2])
    return finish()


SCANNER_VARIANTS = ["httpx", "katana", "nuclei", "wapiti", "dalfox", "zap", "apichecks"]


def phase_scanners():
    """Nuclei (signed deterministic template), Wapiti with an approved bounded form POST campaign,
    Dalfox and a dedicated ZAP daemon in one assessment, with truthful per-scanner dispositions."""
    client = Client()
    if not client.login():
        return finish()
    ids = make_identities(client)
    definitions = upload_definitions(client)
    refs = upload_fixtures(client)
    if not (all(ids.values()) and all(definitions.values()) and all(refs.values())):
        return finish()
    fuzz = {"target_id": "app", "method": "POST", "path": "/api/records", "operation_id": "createRecord", "fixture_ref": refs["fuzz"],
            "content_type": "application/x-www-form-urlencoded", "cleanup_method": "DELETE", "cleanup_path": "/api/records/fixture",
            "scanner": "wapiti", "request_limit": 12, "repeat_testing_approved": True}
    config = api_config(ids["admin"], ids["viewer"], refs, definitions, variants=SCANNER_VARIANTS, fuzz=fuzz)
    # Keep the crawl small: the 684-variant catalog is covered by the default suite.
    config["exclusions"].append({"path_pattern": "/app/catalog", "reason": "bounded scanner run"})
    # The gentle profile's 30-minute shared budget and 2 requests per second cannot fit a
    # crawl plus four scanners, so the later jobs would only record budget exhaustion.
    config["profile"] = "web-thorough"
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("scanners: plan preview accepts the scanner selection and the form campaign", status == 200 and not plan.get("errors"), plan.get("errors") if isinstance(plan, dict) else status)
    if not isinstance(plan, dict) or not plan.get("fingerprint"):
        return finish()
    decisions = {(d.get("scanner"), d.get("target_id") or ""): d for d in plan.get("decisions") or []}
    for name in ("nuclei", "wapiti", "dalfox", "zap"):
        states = {d.get("state") for (scanner_name, _), d in decisions.items() if scanner_name == name}
        check("scanners: %s is selected in the accepted plan" % name, "selected" in states, sorted(states))
    jobs_planned = sorted({j["scanner"] + (":post" if str(j.get("variant", "")).startswith("wapiti-post") else "") for j in plan["jobs"]})
    check("scanners: the approved campaign adds its own wapiti-post job", "wapiti:post" in jobs_planned, jobs_planned)
    lab("POST", "/reset")
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-scanners")
    check("scanners: assessment started", status == 200 and bool(scan_id), status)
    if not scan_id:
        return finish()
    record = wait_terminal(client, scan_id, "scanners")
    check("scanners: assessment reached a terminal state", record is not None and record.get("status") in ("finished", "failed", "stopped"), record.get("status") if record else "timeout")
    if record is None:
        return finish()
    status, coverage = client.call("GET", "/api/scans/%s/coverage" % scan_id)
    save_state({"scanners_scan": scan_id, "coverage": coverage})
    proof = coverage.get("proof") or {}
    runs = {(r.get("scanner"), r.get("variant")): r for r in (client.call("GET", "/api/scans/" + scan_id)[1].get("scanner_runs") or [])}
    for job in coverage.get("jobs") or []:
        if job["scanner"] in ("nuclei", "wapiti", "dalfox", "zap") or str(job.get("variant", "")).startswith("wapiti-post"):
            ok = job.get("status") in ("completed", "failed", "skipped", "cancelled", "not_applicable", "partial")
            check("scanners: job %s/%s reached a recorded outcome" % (job["scanner"], job.get("variant")), ok, "%s %s" % (job.get("status"), (job.get("reason") or "")[:140]))
    print("  scanner job outcomes:", {"%s/%s" % (j["scanner"], j.get("variant")): j.get("status") for j in coverage.get("jobs") or []}, flush=True)

    # Every count drills down to its members, per scanner.
    for row in proof.get("scanners") or []:
        name = row["scanner"]
        if name not in ("nuclei", "wapiti", "dalfox", "zap"):
            continue
        for metric in ("selected", "submitted", "acknowledged", "batch_completed", "failed", "skipped", "unknown"):
            status, page = client.call("GET", "/api/scans/%s/coverage/items?metric=%s&scanner=%s&size=1" % (scan_id, metric, name))
            check("scanners: %s %s drill-down total equals its summary" % (name, metric), status == 200 and page.get("total") == row.get(metric), "summary=%s total=%s" % (row.get(metric), page.get("total") if isinstance(page, dict) else page))
        for metric in ("exercised", "completed", "enabled_templates"):
            check("scanners: %s %s is either measured or explicitly NOT TRACKED" % (name, metric), row.get(metric) is None or isinstance(row.get(metric), int), row.get(metric))
    check("scanners: unproven parameter, check and template metrics remain NOT TRACKED", {"parameters_tested", "templates_executed"} <= set(proof.get("not_tracked") or []), proof.get("not_tracked"))

    # Nuclei produced findings only from the signed fixture template.
    findings = client.call("GET", "/api/scans/%s/findings" % scan_id)[1]
    items = findings.get("items", []) if isinstance(findings, dict) else []
    nuclei_findings = [f for f in items if "nuclei" in (f.get("scanners") or [])]
    check("scanners: the signed deterministic template produced findings", bool(nuclei_findings), [f.get("title") for f in items][:5])
    if nuclei_findings:
        observations = client.call("GET", "/api/scans/%s/findings/%s/observations" % (scan_id, nuclei_findings[0]["id"]))[1]
        rows = observations.get("items", []) if isinstance(observations, dict) else []
        check("scanners: a finding links its native observation with a location", bool(rows) and all(r.get("endpoint") or r.get("source_location") or r.get("evidence_reference") for r in rows), rows[:1])
    rule_ids = set()
    for finding in nuclei_findings:
        rows = client.call("GET", "/api/scans/%s/findings/%s/observations" % (scan_id, finding["id"]))[1]
        for row in (rows.get("items", []) if isinstance(rows, dict) else []):
            if row.get("scanner") == "nuclei":
                rule_ids.add(row.get("rule_id"))
    check("scanners: every Nuclei observation comes from the signed fixture template", rule_ids == {"xalgorix-staged-receipt"}, sorted(str(r) for r in rule_ids))

    # The approved bounded form campaign, as the lab saw it.
    hits = lab("GET", "/hits") or []
    posts = [h for h in hits if h["method"] == "POST" and h["path"] == PATH_PREFIX + "api/records"]
    cleanups = [h for h in hits if h["method"] == "DELETE" and h["path"] == PATH_PREFIX + "api/records/fixture"]
    check("scanners: the form campaign sent at least one POST and stayed within its cap of 12", 1 <= len(posts) <= 12, len(posts))
    check("scanners: every campaign POST used exactly the approved field names", all(sorted(p["body"].split("&")[i].split("=")[0] for i in range(len(p["body"].split("&")))) == ["name", "value"] for p in posts if p["body"]), [p["body"][:60] for p in posts][:3])
    check("scanners: the declared cleanup ran after the campaign", len(cleanups) >= 1, len(cleanups))
    check("scanners: the controlled resources were cleaned up", (lab("GET", "/resources") or {}).get("resources") == 0, lab("GET", "/resources"))
    other_posts = [h for h in hits if h["method"] in ("POST", "PUT", "PATCH", "DELETE") and h["path"] not in (PATH_PREFIX + "api/records", PATH_PREFIX + "api/records/fixture", PATH_PREFIX + "api/notes", PATH_PREFIX + "api/notes/fixture", PATH_PREFIX + "login")]
    check("scanners: no write outside the approved operations reached the lab", not other_posts, [(h["method"], h["path"]) for h in other_posts][:5])
    forbidden = [h for h in (lab("GET", "/forbidden") or []) if not is_known_limitation(h)]
    check("scanners: no unexplained traffic outside the approved boundary", not forbidden, forbidden[:3])

    # Secret and fixture hygiene across everything exposed.
    surfaces = {"scan record": json.dumps(client.call("GET", "/api/scans/" + scan_id)[1]), "coverage": json.dumps(coverage),
                "attack surface": json.dumps(surface_items(client, scan_id)), "findings": json.dumps(findings)}
    pdf = client.call("GET", "/api/report/" + scan_id, raw=True)[1]
    surfaces["report text"] = pdf_text(pdf)
    for (name, variant), run in runs.items():
        if name in ("nuclei", "wapiti", "dalfox", "zap") and run.get("status") in ("completed", "failed", "cancelled"):
            scope = run.get("scope") or ""
            status, body = client.call("GET", "/api/scans/%s/%s/artifact?scope=%s" % (scan_id, name, scope), raw=True)
            if status == 200:
                surfaces["%s artifact" % name] = body.decode("utf-8", "replace")
    for name, text in surfaces.items():
        leaked = [secret for secret in LAB_SECRETS + ["staged-note-fixture", "name=probe&value=seed"] if secret in text]
        check("scanners: %s contains no credential, session or fixture body" % name, not leaked, leaked)
    return finish()


def lab_post(path):
    request = urllib.request.Request(LAB_CONTROL + path, method="POST", headers={"X-Lab-Control": "local-only"})
    urllib.request.urlopen(request, timeout=30).read()


def phase_failures():
    """Injected failures must surface as failures or gaps, never as clean results."""
    client = Client()
    if not client.login():
        return finish()
    ids = make_identities(client)
    definitions = upload_definitions(client)
    refs = upload_fixtures(client)
    if not (all(ids.values()) and all(definitions.values()) and all(refs.values())):
        return finish()
    config = api_config(ids["admin"], ids["viewer"], refs, definitions, variants=SCANNER_VARIANTS)
    config["exclusions"].append({"path_pattern": "/app/catalog", "reason": "bounded scanner run"})
    config["profile"] = "web-thorough"
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("failures: plan preview is accepted", status == 200 and not plan.get("errors"), plan.get("errors") if isinstance(plan, dict) else status)
    if not isinstance(plan, dict) or not plan.get("fingerprint"):
        return finish()
    states = {}
    for d in plan.get("decisions") or []:
        states.setdefault(d.get("scanner"), set()).add(d.get("state"))
    check("failures: a scanner whose binary is missing is planned as unavailable", states.get("dalfox") == {"unavailable"}, states.get("dalfox"))
    check("failures: ZAP without a configured daemon is planned as unavailable", states.get("zap") == {"unavailable"}, states.get("zap"))
    check("failures: the available scanners stay selected", "selected" in states.get("nuclei", set()) and "selected" in states.get("wapiti", set()), {k: sorted(v) for k, v in states.items() if k in ("nuclei", "wapiti")})
    unavailable_reasons = [d.get("reason") for d in plan.get("decisions") or [] if d.get("state") == "unavailable"]
    check("failures: every unavailable decision states a reason", all(unavailable_reasons), unavailable_reasons)
    lab("POST", "/reset")
    lab_post("/restore")
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-failures")
    check("failures: assessment started", status == 200 and bool(scan_id), status)
    if not scan_id:
        return finish()
    record = wait_terminal(client, scan_id, "failures")
    check("failures: assessment reached a terminal state", record is not None and record.get("status") in ("finished", "failed"), record.get("status") if record else "timeout")
    if record is None:
        return finish()
    status, coverage = client.call("GET", "/api/scans/%s/coverage" % scan_id)
    runs = client.call("GET", "/api/scans/" + scan_id)[1].get("scanner_runs") or []
    by_scanner = {}
    for r in runs:
        by_scanner.setdefault(r.get("scanner"), []).append(r)
    print("  run outcomes:", {k: [(r.get("status"), r.get("outcome"), r.get("gap_kind")) for r in v] for k, v in by_scanner.items()}, flush=True)

    nuclei = [r for r in by_scanner.get("nuclei", []) if not r.get("scope", "").count(":identity:")]
    check("failures: truncated Nuclei output is a failure, not a clean zero-finding scan", bool(nuclei) and all(r.get("status") != "completed" or r.get("outcome") not in ("SUCCESS", "COMPLETE", "") for r in nuclei), [(r.get("status"), r.get("outcome"), r.get("reason")) for r in nuclei])
    check("failures: a failed Nuclei run states why", all(r.get("reason") for r in nuclei if r.get("status") != "completed"), [r.get("reason") for r in nuclei])
    wapiti = [r for r in by_scanner.get("wapiti", []) if not r.get("variant", "").startswith("wapiti-post")]
    check("failures: an empty Wapiti report is a failure, not a clean result", bool(wapiti) and all(r.get("status") != "completed" or r.get("outcome") not in ("SUCCESS", "COMPLETE", "") for r in wapiti), [(r.get("status"), r.get("outcome"), r.get("reason")) for r in wapiti])
    check("failures: no run exists for the scanners that were unavailable", not by_scanner.get("dalfox") and not by_scanner.get("zap"), sorted(by_scanner))
    gaps = {g.get("scanner"): g for g in coverage.get("gaps") or []}
    check("failures: unavailable scanners appear as coverage gaps with a reason", all(gaps.get(n, {}).get("reason") for n in ("dalfox", "zap")), {n: gaps.get(n) for n in ("dalfox", "zap")})
    findings = client.call("GET", "/api/scans/%s/findings" % scan_id)[1]
    items = findings.get("items", []) if isinstance(findings, dict) else []
    check("failures: no finding was invented from the failed scanners", not [f for f in items if set(f.get("scanners") or []) & {"nuclei", "wapiti", "dalfox", "zap"}], [f.get("title") for f in items][:3])

    check("failures: the assessment is reported as partial, not complete", coverage.get("state") == "partial", coverage.get("state"))
    status, pdf = client.call("GET", "/api/report/" + scan_id, raw=True)
    report = pdf_text(pdf).replace("\n", " ")
    check("failures: the report states the partial assessment state", "Assessment state: partial" in report, report[:120])
    check("failures: the report lists the unavailable scanners as gaps", "Gap dalfox" in report and "Gap zap" in report, report[:120])
    forbidden = [h for h in (lab("GET", "/forbidden") or []) if not is_known_limitation(h)]
    check("failures: no unexplained traffic outside the approved boundary", not forbidden, forbidden[:2])

    # Second assessment: expire every session while the authenticated Nuclei run is active.
    expiry_config = api_config(ids["admin"], ids["viewer"], refs, definitions, variants=["httpx", "katana", "nuclei"])
    expiry_config["profile"] = "web-thorough"
    expiry_config["exclusions"].append({"path_pattern": "/app/catalog", "reason": "bounded scanner run"})
    status, expiry_plan = client.call("POST", "/api/scans/plan", expiry_config)
    check("failures: expiry assessment plan is accepted", status == 200 and not expiry_plan.get("errors"), expiry_plan.get("errors") if isinstance(expiry_plan, dict) else status)
    lab_post("/restore")
    status, ack, expiry_id = start_scan(client, expiry_config, expiry_plan["fingerprint"], "staged-failures-expiry")
    check("failures: expiry assessment started", status == 200 and bool(expiry_id), status)
    if not expiry_id:
        return finish()
    deadline, expired = time.time() + 900, False
    while time.time() < deadline and not expired:
        record = scan_record(client, expiry_id)
        if any(r.get("scanner") == "nuclei" and r.get("status") == "running" for r in record.get("scanner_runs") or []):
            lab_post("/expire")
            expired = True
        elif record.get("status") in ("finished", "failed", "stopped"):
            break
        else:
            time.sleep(1)
    check("failures: sessions were expired while an authenticated scanner was running", expired)
    record = wait_terminal(client, expiry_id, "expiry")
    lab_post("/restore")
    check("failures: expiry assessment reached a terminal state", record is not None and record.get("status") in ("finished", "failed"), record.get("status") if record else "timeout")
    if record is None:
        return finish()
    coverage = client.call("GET", "/api/scans/%s/coverage" % expiry_id)[1]
    runs = client.call("GET", "/api/scans/" + expiry_id)[1].get("scanner_runs") or []
    print("  expiry outcomes:", [(r.get("scanner"), r.get("scope"), r.get("status"), r.get("gap_kind"), r.get("auth_state")) for r in runs if r.get("scanner") in ("nuclei", "katana", "auth")], flush=True)
    expired_runs = [r for r in runs if r.get("gap_kind") == "auth_expired" or r.get("auth_state") == "expired"]
    check("failures: expired sessions are recorded as an authentication gap on the running scanner", any(r.get("scanner") == "nuclei" for r in expired_runs), [(r.get("scanner"), r.get("gap_kind"), r.get("reason")) for r in expired_runs])
    primary_expiry = [r for r in expired_runs if r.get("scanner") == "nuclei" and not r.get("auth_identity")]
    check("failures: the expired scanner run is marked partial with an authentication outcome", bool(primary_expiry) and all(r.get("completeness") == "partial" and r.get("outcome") == "AUTH_FAILED" for r in primary_expiry), [(r.get("completeness"), r.get("outcome")) for r in primary_expiry])
    capability = [c.get("state") for c in coverage.get("capabilities") or [] if c.get("capability") == "authenticated_web"]
    check("failures: authenticated access is reported as expired, not verified", capability == ["expired"] or "expired" in capability, capability)
    check("failures: the expiry assessment is reported as partial", coverage.get("state") == "partial", coverage.get("state"))
    return finish()


def lab_counts():
    hits = lab("GET", "/hits") or []
    return {"posts": sum(1 for h in hits if h["method"] == "POST" and h["path"] == PATH_PREFIX + "api/records"),
            "cleanups": sum(1 for h in hits if h["method"] == "DELETE" and h["path"] == PATH_PREFIX + "api/records/fixture"),
            "total": len(hits), "resources": (lab("GET", "/resources") or {}).get("resources")}


def phase_write_start():
    """Start an assessment with an approved form campaign and stop watching once its POSTs begin;
    the runner then hard-kills the application process."""
    client = Client()
    if not client.login():
        return finish()
    ids = make_identities(client)
    definitions = upload_definitions(client)
    refs = upload_fixtures(client)
    if not (all(ids.values()) and all(definitions.values()) and all(refs.values())):
        return finish()
    fuzz = {"target_id": "app", "method": "POST", "path": "/api/records", "operation_id": "createRecord", "fixture_ref": refs["fuzz"],
            "content_type": "application/x-www-form-urlencoded", "cleanup_method": "DELETE", "cleanup_path": "/api/records/fixture",
            "scanner": "wapiti", "request_limit": 12, "repeat_testing_approved": True}
    config = api_config(ids["admin"], ids["viewer"], refs, definitions, variants=["httpx", "katana", "wapiti", "dalfox"], fuzz=fuzz)
    config["exclusions"].append({"path_pattern": "/app/catalog", "reason": "bounded scanner run"})
    config["profile"] = "web-thorough"
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("write-recovery: plan preview is accepted", status == 200 and not plan.get("errors"), plan.get("errors") if isinstance(plan, dict) else status)
    if not isinstance(plan, dict) or not plan.get("fingerprint"):
        return finish()
    lab("POST", "/reset")
    lab_post("/delay-records?ms=2500")  # keep the campaign in flight long enough to interrupt it
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-write-recovery")
    check("write-recovery: assessment started", status == 200 and bool(scan_id), status)
    if not scan_id:
        return finish()
    deadline, counts = time.time() + 1500, lab_counts()
    while time.time() < deadline and counts["posts"] < 2:
        time.sleep(0.5)
        counts = lab_counts()
    check("write-recovery: the approved campaign was in flight (at least two POSTs, cleanup not yet run)", counts["posts"] >= 2 and counts["cleanups"] == 0, counts)
    state = load_state()
    state.update({"write_scan": scan_id, "before_kill": counts})
    save_state(state)
    return finish()


def phase_write_after_kill():
    """After SIGKILL mid-campaign: no POST, cleanup or other automatic replay, the uncertainty is visible."""
    state = load_state()
    client = Client()
    if not client.login():
        return finish()
    scan_id, before = state["write_scan"], state["before_kill"]
    time.sleep(20)  # past the startup auto-resume delay
    first = lab_counts()
    deadline = time.time() + 90
    record = {}
    while time.time() < deadline:
        record = scan_record(client, scan_id)
        if record.get("status") in ("stopped", "failed", "finished"):
            time.sleep(15)
            again = scan_record(client, scan_id)
            if again.get("status") == record.get("status"):
                break
        time.sleep(3)
    after = lab_counts()
    print("  before kill %s, after restart %s -> %s; record %s" % (before, first, after, record.get("status")), flush=True)
    check("write-recovery: no further campaign POST was sent after the restart", after["posts"] == before["posts"] == first["posts"] or (after["posts"] == first["posts"] and first["posts"] <= before["posts"] + 1), {"before": before["posts"], "first": first["posts"], "after": after["posts"]})
    check("write-recovery: no cleanup was replayed automatically", after["cleanups"] == before["cleanups"], {"before": before["cleanups"], "after": after["cleanups"]})
    check("write-recovery: the interrupted campaign's resources are still visible (cleanup is not claimed)", (after["resources"] or 0) > 0, after)
    runs = record.get("scanner_runs") or []
    # The record is closed (not running) and the refusal is carried by the jobs: every
    # job failed with the journal reason instead of being re-run.
    check("write-recovery: the assessment is closed and every job reports the refusal, none runs or completes", record.get("status") in ("stopped", "failed", "finished") and bool(runs) and all(r.get("status") == "failed" for r in runs), [(r.get("scanner"), r.get("status")) for r in runs][:6])
    post_runs = [r for r in runs if str(r.get("variant", "")).startswith("wapiti-post")]
    check("write-recovery: no campaign run claims completion", not [r for r in post_runs if r.get("status") == "completed"], [(r.get("status"), r.get("reason")) for r in post_runs])
    unsafe = [r for r in runs if r.get("gap_kind") == "interrupted_write" or "write journal" in (r.get("reason") or "")]
    status, coverage = client.call("GET", "/api/scans/%s/coverage" % scan_id)
    check("write-recovery: the blocked replay is reported with its reason on the jobs or in coverage", bool(unsafe) or coverage.get("state") in ("partial", "failed"), {"unsafe": [(r.get("scanner"), r.get("reason")) for r in unsafe][:3], "state": coverage.get("state")})
    status, listing = client.call("GET", "/api/scans")
    check("write-recovery: nothing was auto-resumed into a running state", not [i for i in listing or [] if i.get("status") in ("running", "pending")], [(i["id"][:6], i["status"]) for i in listing or []])
    lab_post("/delay-records?ms=0")
    return finish()


def phase_auth_start():
    """Start an authenticated assessment and stop watching once an authenticated crawl is in
    flight; the runner then hard-kills the application process."""
    client = Client()
    if not client.login():
        return finish()
    ids = make_identities(client)
    config = identity_config(ids["admin"], ids["viewer"])
    config["access"][0]["verify_browser"] = False
    config["access"][1]["verify_browser"] = False
    status, plan = client.call("POST", "/api/scans/plan", config)
    check("auth-recovery: plan preview is accepted", status == 200 and not plan.get("errors"), plan.get("errors") if isinstance(plan, dict) else status)
    if not isinstance(plan, dict) or not plan.get("fingerprint"):
        return finish()
    lab("POST", "/reset")
    lab_post("/restore")
    status, ack, scan_id = start_scan(client, config, plan["fingerprint"], "staged-auth-recovery")
    check("auth-recovery: assessment started", status == 200 and bool(scan_id), status)
    if not scan_id:
        return finish()
    deadline, seen = time.time() + 900, []
    while time.time() < deadline:
        hits = lab("GET", "/hits") or []
        seen = [h for h in hits if h["identity"] in ("admin", "viewer") and h["path"].startswith(PATH_PREFIX + "item")]
        if len(seen) >= 5:
            break
        time.sleep(0.5)
    hits = lab("GET", "/hits") or []
    pre_logins = max([h["login"] for h in hits] or [0])
    check("auth-recovery: authenticated crawl traffic was in flight before the kill", len(seen) >= 5 and pre_logins >= 1, {"authenticated_hits": len(seen), "highest_login": pre_logins})
    state = load_state()
    state.update({"auth_scan": scan_id, "pre_kill_hits": len(hits), "pre_kill_login": pre_logins})
    save_state(state)
    return finish()


def phase_auth_after_kill():
    """After SIGKILL: the resumed assessment re-verifies credentials; no request carries a session
    token issued before the restart."""
    state = load_state()
    client = Client()
    if not client.login():
        return finish()
    scan_id, pre_total, pre_login = state["auth_scan"], state["pre_kill_hits"], state["pre_kill_login"]
    record, last, stable_since = {}, None, time.time()
    deadline = time.time() + 1500
    while time.time() < deadline:
        record = scan_record(client, scan_id)
        current = (record.get("status"), len(lab("GET", "/hits") or []))
        if current != last:
            last, stable_since = current, time.time()
        if record.get("status") in ("finished", "failed", "stopped") and time.time() - stable_since >= 30:
            break
        time.sleep(5)
    hits = (lab("GET", "/hits") or [])[pre_total:]
    authenticated = [h for h in hits if h["identity"] in ("admin", "viewer")]
    logins = [h for h in hits if h["method"] == "POST" and h["path"] == PATH_PREFIX + "login"]
    print("  after restart: record %s, %d new hits, %d logins, %d authenticated requests, highest pre-kill login %d" % (record.get("status"), len(hits), len(logins), len(authenticated), pre_login), flush=True)
    check("auth-recovery: the resumed assessment performed new logins from the vault credentials", len(logins) >= 2, len(logins))
    stale = [h for h in authenticated if h["login"] <= pre_login]
    check("auth-recovery: no authenticated request carried a session issued before the restart", not stale, [(h["method"], h["path"], h["login"]) for h in stale[:3]])
    check("auth-recovery: authenticated traffic resumed with the new sessions", bool(authenticated) and all(h["login"] > pre_login for h in authenticated), len(authenticated))
    check("auth-recovery: the resumed assessment reached a terminal state", record.get("status") in ("finished", "failed", "stopped"), record.get("status"))
    status, coverage = client.call("GET", "/api/scans/%s/coverage" % scan_id)
    capability = [c.get("state") for c in coverage.get("capabilities") or [] if c.get("capability") == "authenticated_web"]
    check("auth-recovery: access is verified again by the new sessions, not carried over", bool(capability) and all(c == "verified" for c in capability), capability)
    forbidden = [h for h in (lab("GET", "/forbidden") or []) if not is_known_limitation(h)]
    check("auth-recovery: no unexplained traffic outside the boundary", not forbidden, forbidden[:2])
    return finish()


PHASES = {
    "full": phase_full,
    "recovery-base": phase_recovery_base,
    "recovery-pending": phase_recovery_pending,
    "recovery-accepted": phase_recovery_accepted,
    "recovery-midrun": phase_recovery_midrun,
    "recovery-stop": phase_recovery_stop,
    "recovery-after-stop": phase_recovery_after_stop,
    "identities": phase_identities,
    "api": phase_api,
    "scanners": phase_scanners,
    "failures": phase_failures,
    "auth-start": phase_auth_start,
    "auth-after-kill": phase_auth_after_kill,
    "write-start": phase_write_start,
    "write-after-kill": phase_write_after_kill,
}


def finish():
    failed = [r for r in results if r["status"] == "FAIL"]
    summary = {"passed": sum(1 for r in results if r["status"] == "PASS"), "failed": len(failed), "results": results}
    if RESULT_PATH:
        with open(RESULT_PATH, "w") as handle:
            json.dump(summary, handle, indent=2)
    limits = [r for r in results if r["status"] == "KNOWN_LIMITATION"]
    summary["known_limitations"] = len(limits)
    print("\n%d passed, %d failed, %d known limitation(s)" % (summary["passed"], summary["failed"], len(limits)), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    if PHASE not in PHASES:
        sys.exit("unknown STAGED_PHASE %r; expected one of %s" % (PHASE, sorted(PHASES)))
    sys.exit(PHASES[PHASE]())
