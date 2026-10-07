// Real-browser acceptance of the assessment workflow UI against the staged lab.
//
// Runs inside the retained runtime image on the disposable internal network
// created by runtime/staged-acceptance.sh. It drives the built dashboard with
// playwright-core and the image's own Chromium, then compares what the page
// shows with the same saved evidence returned by the API. Everything contacted
// is synthetic and local. Each check records PASS or FAIL; the exit status is
// non-zero when any check fails.
import fs from "node:fs";
import { chromium } from "playwright-core";

const BASE = (process.env.UI_BASE || "http://app:8888").replace(/\/$/, "");
const USER = process.env.UI_USER || "acceptance";
const PASSWORD = process.env.UI_PASSWORD || "";
const STATE = process.env.UI_STATE || "/out/state.json";
const LAB = (process.env.UI_LAB_CONTROL || "http://lab-primary:9000").replace(/\/$/, "");
const RESULT = process.env.UI_RESULT || "";
const PRIMARY = process.env.UI_PRIMARY || "http://lab-primary:8080";
const SECONDARY = process.env.UI_SECONDARY || "https://lab-secondary:8443";
const ALIAS = process.env.UI_ALIAS || "http://lab-alias:8081";

const results = [];
function check(name, ok, detail = "") {
  results.push({ check: name, status: ok ? "PASS" : "FAIL", detail: String(detail).slice(0, 600) });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail === "" ? "" : " - " + String(detail).slice(0, 300)}`);
  return ok;
}
async function step(name, body) {
  try {
    await body();
  } catch (error) {
    check(name, false, String(error && error.message ? error.message : error).split("\n")[0]);
  }
}

const state = JSON.parse(fs.readFileSync(STATE, "utf8"));
const baseId = state.base_id;

const browser = await chromium.launch({ executablePath: process.env.UI_CHROMIUM || "/usr/bin/chromium", args: ["--no-sandbox", "--disable-dev-shm-usage"] });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();
page.setDefaultTimeout(30000);
const pageErrors = [];
page.on("pageerror", (error) => pageErrors.push(String(error.message || error)));

const api = async (path, options) => {
  const response = await context.request.fetch(BASE + path, options);
  const text = await response.text();
  let body = text;
  try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status(), body };
};
const jobRow = (scanner) => page.locator('div[class*="bg-background/40"]').filter({ has: page.locator("span.text-sm.font-medium", { hasText: new RegExp(`^${scanner}$`) }) });
const lab = async (path) => (await fetch(LAB + path, { headers: { "X-Lab-Control": "local-only" } })).json();

async function login(username, password) {
  await page.getByLabel("Username").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /^Sign in/ }).click();
}

// 1. Authentication gate.
await step("authentication", async () => {
  await page.goto(`${BASE}/scans/${baseId}`);
  await page.waitForURL(/\/login/);
  check("anonymous visit to a scan is redirected to login", true, page.url());
  await login(USER, "definitely-not-the-password");
  await page.getByText(/invalid/i).first().waitFor();
  check("a wrong password is rejected with a visible error", true);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: /^Sign in/ }).click();
  await page.waitForURL((url) => !url.pathname.startsWith("/login"));
  check("valid credentials reach the dashboard", true, page.url());
});

// 2. Scan detail: workflow card, limitations and recorded coverage.
await step("scan detail", async () => {
  await page.goto(`${BASE}/scans/${baseId}`);
  await page.getByText("Assessment workflow").first().waitFor();
  check("assessment workflow card is shown", true);

  const katana = jobRow("katana").first();
  await katana.waitFor();
  check("katana job row shows the not-gateway-enforced limitation", /Limitation ·.*recording gateway/s.test(await katana.innerText()), (await katana.innerText()).slice(0, 200));

  const coverage = (await api(`/api/scans/${baseId}/coverage`)).body.proof;
  await page.getByText("Recorded coverage").first().waitFor();
  const tiles = {
    "Inventory requests": "discovered", "Observed requests": "observed", "Approved requests": "approved", "Eligible requests": "eligible",
    "Supplied seeds": "seeds", "Candidate hosts": "candidates", "Observed hosts": "hosts", Services: "services", "TLS services": "tls_services",
    Forms: "forms", "Parameterized requests": "parameterized", "Observed with auth": "observed_with_auth",
  };
  for (const [label, key] of Object.entries(tiles)) {
    const tile = page.getByRole("button", { name: new RegExp(`^${label} \\d+$`) }).first();
    const shown = Number((await tile.innerText()).split("\n").pop().trim());
    check(`coverage tile "${label}" equals the saved summary`, shown === coverage[key], `ui=${shown} api=${coverage[key]}`);
  }
  await page.getByRole("button", { name: /^Services \d+$/ }).first().click();
  const dialog = page.getByRole("dialog").first();
  await dialog.waitFor();
  const text = await dialog.innerText();
  check("services drill-down lists the members behind the count", new RegExp(`${coverage.services} saved inventory or evidence items`).test(text) && text.includes("lab-primary"), text.slice(0, 160));
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
});

// 3. Attack surface and the exact endpoint trace.
await step("attack surface", async () => {
  await page.getByLabel("Search endpoints").fill("/app/about");
  const row = page.getByRole("row", { name: /\/app\/about/ }).first();
  await row.waitFor();
  await row.getByRole("button", { name: "Trace" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText("/app/about").first().waitFor();
  const text = await dialog.innerText();
  check("endpoint trace opens the exact request", text.includes("Endpoint evidence trace") && text.includes("/app/about"), text.slice(0, 160));
  await page.keyboard.press("Escape");
  await dialog.waitFor({ state: "hidden" });
});

// 4. Offline report download.
await step("report", async () => {
  const href = await page.locator('a[href^="/api/report/"]').first().getAttribute("href");
  const response = await context.request.get(BASE + href);
  const body = await response.body();
  check("report downloads as a PDF from saved artifacts", response.status() === 200 && body.subarray(0, 5).toString() === "%PDF-", `${response.status()} ${response.headers()["content-type"]}`);
});

// 5. Discovery review: approve only the secondary origin and start the revision.
let childId = "";
await step("discovery approval", async () => {
  await page.getByText("Review discovered destinations").first().waitFor();
  const labelFor = (value) => page.locator("label").filter({ hasText: value }).first();
  await labelFor(ALIAS).waitFor();
  check("alias candidate is listed but not preselected", !(await labelFor(ALIAS).locator("input[type=checkbox]").isChecked()));
  await labelFor(SECONDARY).locator("input[type=checkbox]").check();
  await page.getByRole("button", { name: "Approve and preview revised plan" }).click();
  await page.getByText("Approved revision", { exact: true }).first().waitFor();
  const approved = (await api(`/api/scans/${baseId}/discovery`)).body.approved_revision;
  const shown = await page.locator("p.break-all").filter({ hasText: approved.plan.fingerprint }).count();
  check("approved revision fingerprint matches the saved revision", shown > 0, approved.plan.fingerprint);
  check("approved revision keeps the parent link", approved.parent_fingerprint === state.plan_fingerprint);
  await page.getByRole("button", { name: "Start approved revision" }).click();
  await page.getByText(/Approved revision queued:/).first().waitFor();
  const queued = (await page.getByText(/Approved revision queued:/).first().innerText()).replace(/.*queued:\s*/, "").trim();
  childId = queued;
  check("approved revision is queued from the UI", childId.length > 0, queued);
});

// 6. Per-tool stop and assessment stop on the running revision.
await step("stop controls", async () => {
  let scanId = "";
  for (let i = 0; i < 60 && !scanId; i += 1) {
    const list = (await api("/api/scans")).body;
    for (const item of list || []) {
      const detail = (await api(`/api/scans/${item.id}`)).body;
      if (item.id === childId || detail.instance_id === childId) scanId = item.id;
    }
    if (!scanId) await new Promise((r) => setTimeout(r, 2000));
  }
  check("revision scan record exists", scanId !== "", scanId);
  await page.goto(`${BASE}/scans/${scanId}`);
  const row = jobRow("katana").filter({ has: page.getByRole("button", { name: "Stop", exact: true }) }).first();
  await row.waitFor({ timeout: 300000 });

  // Inactivity prompt: advance a virtual clock past ten minutes on a second page.
  // The scan keeps running for real; only this page's timers move.
  const clockPage = await context.newPage();
  await clockPage.clock.install();
  await clockPage.goto(`${BASE}/scans/${scanId}`);
  await clockPage.getByText("Assessment workflow").first().waitFor();
  const prompt = clockPage.getByRole("dialog").filter({ hasText: "no progress" });
  for (let i = 0; i < 14 && !(await prompt.count()); i += 1) {
    await clockPage.clock.runFor("01:00");
    await clockPage.waitForTimeout(1500);
  }
  check("ten-minute inactivity prompt offers keep or stop", (await prompt.count()) > 0 && (await prompt.getByRole("button", { name: "Keep running" }).count()) > 0 && (await prompt.getByRole("button", { name: "Stop this scanner" }).count()) > 0);
  if (await prompt.count()) {
    await prompt.getByRole("button", { name: "Keep running" }).click();
    await prompt.waitFor({ state: "hidden" });
    const still = (await api(`/api/scans/${scanId}`)).body.status;
    check("keeping the scanner running leaves the assessment running", still === "running", still);
  }
  await clockPage.close();

  await row.getByRole("button", { name: "Stop", exact: true }).click();
  let stopped = false;
  for (let i = 0; i < 60 && !stopped; i += 1) {
    const runs = (await api(`/api/scans/${scanId}`)).body.scanner_runs || [];
    stopped = runs.some((run) => run.scanner === "katana" && run.status === "cancelled");
    if (!stopped) await new Promise((r) => setTimeout(r, 2000));
  }
  check("per-tool Stop cancels exactly the running katana attempt", stopped);
  await page.getByRole("button", { name: "Stop all" }).click();
  let assessmentStopped = false;
  for (let i = 0; i < 60 && !assessmentStopped; i += 1) {
    assessmentStopped = (await api(`/api/scans/${scanId}`)).body.status === "stopped";
    if (!assessmentStopped) await new Promise((r) => setTimeout(r, 2000));
  }
  check("assessment Stop is terminal", assessmentStopped);
});

// 7. New assessment wizard: boundary, exclusions and plan preview.
await step("new assessment wizard", async () => {
  await page.goto(`${BASE}/scans/new`);
  await page.getByLabel("URLs or hosts").fill(`${PRIMARY}/app/`);
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByLabel("Request exclusions").fill("* /app/logout\n* /app/write\n* /app/admin/delete");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Continue" }).click();
  const planResponse = page.waitForResponse((r) => r.url().includes("/api/scans/plan") && r.request().method() === "POST");
  await page.getByRole("button", { name: /Preview workflow/ }).click();
  const response = await planResponse;
  const plan = await response.json();
  const body = response.request().postDataJSON();
  check("wizard sends the typed path boundary and exclusions", body.approved_origins?.[0]?.path_prefix === "/app" || body.assessment_targets?.[0]?.value === `${PRIMARY}/app/`, JSON.stringify(body.assessment_targets));
  check("wizard exclusions reach the plan", (plan.config.exclusions || []).length >= 3, JSON.stringify(plan.config.exclusions));
  const shown = await page.getByText(/^Plan /).first().innerText();
  check("preview shows the plan fingerprint prefix", shown.includes(String(plan.fingerprint).slice(0, 24)), shown);
  check("Start assessment is enabled for a valid plan", await page.getByRole("button", { name: "Start assessment" }).isEnabled());
});

// 8. No forbidden traffic reached the lab during the whole UI run.
await step("boundary", async () => {
  const forbidden = (await lab("/forbidden")).filter((hit) => !(hit.origin === "primary" && hit.path === "/favicon.ico" && /Chrome\//.test(hit.user_agent)));
  check("no unexplained traffic outside the approved boundary during the UI run", forbidden.length === 0, JSON.stringify(forbidden.slice(0, 2)));
  const alias = (await lab("/hits")).filter((hit) => hit.origin === "alias");
  check("alias origin was never contacted", alias.length === 0);
});

check("the browser reported no uncaught page errors", pageErrors.length === 0, pageErrors.slice(0, 2).join(" | "));
await browser.close();
const failed = results.filter((r) => r.status === "FAIL").length;
const summary = { passed: results.filter((r) => r.status === "PASS").length, failed, results };
if (RESULT) fs.writeFileSync(RESULT, JSON.stringify(summary, null, 2));
console.log(`\n${summary.passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
