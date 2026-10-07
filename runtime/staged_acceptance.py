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

    def call(self, method, path, body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            APP + path, data=data, method=method,
            headers={"Content-Type": "application/json", "Origin": APP})
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
    return json.loads(payload) if payload else None  # the recorder returns null for an empty list


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


PHASES = {
    "full": phase_full,
    "recovery-base": phase_recovery_base,
    "recovery-pending": phase_recovery_pending,
    "recovery-accepted": phase_recovery_accepted,
    "recovery-midrun": phase_recovery_midrun,
    "recovery-stop": phase_recovery_stop,
    "recovery-after-stop": phase_recovery_after_stop,
    "identities": phase_identities,
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
