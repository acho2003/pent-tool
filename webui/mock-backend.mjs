import http from "node:http";
import { WebSocketServer } from "ws";

const json = (res, body, status = 200) => {
  res.writeHead(status, {
    "content-type": "application/json",
    "access-control-allow-origin": "*",
  });
  res.end(JSON.stringify(body));
};

const now = new Date().toISOString();

const instances = [
  {
    id: "inst_01",
    name: "Acme Corp pentest",
    targets: "acme.com",
    parent_target: "acme.com",
    status: "running",
    started_at: now,
    iterations: 42,
    tool_calls: 188,
    vuln_count: 7,
    total_tokens: 124000,
    scan_mode: "deep",
    instruction: "Standard recon + active probing",
    severity_filter: ["high", "critical"],
    phases: [1, 2, 3, 4],
    company_name: "Acme",
    current_phase: 3,
    vulns: [
      { id: "v1", title: "SQL Injection in /search", severity: "critical" },
      { id: "v2", title: "Reflected XSS in /login", severity: "high" },
      { id: "v3", title: "Open Redirect on /go", severity: "medium" },
    ],
  },
  {
    id: "inst_02",
    name: "Globex bounty",
    targets: "globex.io",
    parent_target: "globex.io",
    status: "finished",
    started_at: now,
    finished_at: now,
    iterations: 80,
    tool_calls: 412,
    vuln_count: 2,
    total_tokens: 256000,
    scan_mode: "balanced",
    company_name: "Globex",
    vulns: [],
  },
];

const scans = [
  {
    id: "scan_01",
    name: "Acme nightly",
    target: "acme.com",
    parent_target: "acme.com",
    started_at: now,
    status: "running",
    scan_mode: "deep",
    instruction: "Standard",
    severity_filter: ["high", "critical"],
    vuln_count: 7,
    iterations: 42,
    tool_calls: 188,
    total_tokens: 124000,
  },
  {
    id: "scan_02",
    name: "Globex weekly",
    target: "globex.io",
    started_at: now,
    finished_at: now,
    status: "finished",
    scan_mode: "balanced",
    vuln_count: 2,
    iterations: 80,
    tool_calls: 412,
    total_tokens: 256000,
  },
];

const handlers = {
  "GET /api/auth/status": (req, res) =>
    json(res, { auth_enabled: false, authenticated: true }),
  "GET /api/status": (req, res) =>
    json(res, { running: true, current_target: "acme.com" }),
  "GET /api/version": (req, res) => json(res, { version: "4.2.9", commit: "dev" }),
  "GET /api/instances": (req, res) => json(res, { instances }),
  "GET /api/scans": (req, res) => json(res, scans),
  "GET /api/queue/status": (req, res) =>
    json(res, {
      active: true,
      queued: 1,
      current_target: "acme.com",
      current_idx: 0,
      total: 2,
    }),
  "GET /api/settings/rate-limit": (req, res) =>
    json(res, { requests: 60, window_seconds: 60 }),
  "GET /api/settings/agentmail": (req, res) =>
    json(res, { pod: "ops-pod-1", hasApiKey: true }),
};

const server = http.createServer((req, res) => {
  const key = `${req.method} ${req.url.split("?")[0]}`;
  const h = handlers[key];
  if (h) return h(req, res);
  const instMatch = req.url.match(/^\/api\/instances\/([^/?]+)$/);
  if (instMatch) {
    const inst = instances.find((i) => i.id === instMatch[1]);
    return inst ? json(res, inst) : json(res, { error: "not found" }, 404);
  }
  const scanMatch = req.url.match(/^\/api\/scans\/([^/?]+)$/);
  if (scanMatch) {
    const sc = scans.find((s) => s.id === scanMatch[1]);
    if (!sc) return json(res, { error: "not found" }, 404);
    const vulns =
      sc.id === "scan_01"
        ? [
            { id: "v1", title: "SQL Injection in /search", severity: "critical", endpoint: "https://acme.com/search?q=", cvss: 9.8, cve: "CVE-2024-1234" },
            { id: "v2", title: "Reflected XSS in /login", severity: "high", endpoint: "https://acme.com/login", cvss: 7.5 },
            { id: "v3", title: "Open Redirect on /go", severity: "medium", endpoint: "https://acme.com/go", cvss: 4.3 },
            { id: "v4", title: "Verbose error in /api/v1/users", severity: "low", endpoint: "https://acme.com/api/v1/users", cvss: 2.0 },
            { id: "v5", title: "Missing security headers", severity: "info", endpoint: "https://acme.com/", cvss: 0 },
          ]
        : [
            { id: "v6", title: "S3 bucket misconfiguration", severity: "high", endpoint: "https://cdn.globex.io", cvss: 7.1 },
            { id: "v7", title: "Outdated jQuery 1.4.2", severity: "low", endpoint: "https://globex.io/static/jquery.js", cvss: 3.1 },
          ];
    return json(res, { ...sc, events: [], vulns });
  }
  // Real client posts to /api/scan; legacy/curl users sometimes hit /api/start.
  // Accept both so the dashboard's "New scan" flow works against the mock.
  if (
    req.method === "POST" &&
    (req.url === "/api/scan" || req.url === "/api/start")
  ) {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () =>
      json(res, { status: "started", instance_id: "inst_01", id: "scan_01", ok: true }),
    );
    return;
  }
  json(res, { ok: true });
});

const port = Number(process.env.PORT || 8080);
server.listen(port, () => console.log(`mock backend on ${port}`));

const wss = new WebSocketServer({ server, path: "/ws" });
wss.on("connection", (ws) => {
  let i = 0;
  const send = () => {
    ws.send(
      JSON.stringify({
        type: i % 5 === 0 ? "email_received" : "tool_call",
        content:
          i % 5 === 0
            ? "Email from attacker@evil.test triaged"
            : `nmap -sV target ${i}`,
        tool_name: i % 5 === 0 ? "agentmail" : "nmap",
        timestamp: new Date().toISOString(),
        agent_id: "inst_01",
      }),
    );
    i++;
  };
  const t = setInterval(send, 1500);
  ws.on("close", () => clearInterval(t));
});
