import type {
  AuthStatus,
  AgentMailSettings,
  InstancesResponse,
  QueueStatus,
  RateLimitSettings,
  ScanInstance,
  ScanListItem,
  ScanRecord,
  ScanRequest,
  StatusResponse,
} from "@/types/api";

// Auth session expiry handling. When any API call returns 401 we dispatch a
// global event so the auth store (in store/auth.ts) can flip the user back
// to the login screen without each component having to handle it.
// We avoid importing the store directly to keep this module free of
// circular deps with the rest of the app.
const AUTH_EXPIRED_EVENT = "xalgorix:auth-expired"
let lastAuthExpiredDispatch = 0

function dispatchAuthExpired() {
  // Debounce: when multiple SWR keys fail at once we'd otherwise fire
  // dozens of events in a single tick.
  const now = Date.now()
  if (now - lastAuthExpiredDispatch < 1000) return
  lastAuthExpiredDispatch = now
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT))
  }
}

export const AUTH_EXPIRED = AUTH_EXPIRED_EVENT

async function http<T>(
  path: string,
  init?: RequestInit & { json?: unknown },
): Promise<T> {
  const headers: HeadersInit = {
    Accept: "application/json",
    ...(init?.headers || {}),
  }
  let body = init?.body
  if (init?.json !== undefined) {
    body = JSON.stringify(init.json)
    ;(headers as Record<string, string>)["Content-Type"] = "application/json"
  }
  const res = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers,
    body,
  })
  if (!res.ok) {
    // Surface session expiry / auth failure to the rest of the app, but
    // never on the login endpoint itself (that 401 is just "bad password"
    // and the form already shows the error inline).
    if (res.status === 401 && path !== "/api/auth/login") {
      dispatchAuthExpired()
    }
    let detail = ""
    try {
      detail = await res.text()
    } catch {
      /* ignore */
    }
    throw new Error(
      `HTTP ${res.status} ${res.statusText}${detail ? `: ${detail}` : ""}`,
    )
  }
  const ct = res.headers.get("content-type") || ""
  if (ct.includes("application/json")) {
    return (await res.json()) as T
  }
  return (await res.text()) as unknown as T
}

export const api = {
  authStatus: () => http<AuthStatus>("/api/auth/status"),
  login: (username: string, password: string) =>
    http<{ status: string }>("/api/auth/login", {
      method: "POST",
      json: { username, password },
    }),
  logout: () => http<{ status: string }>("/api/auth/logout", { method: "POST" }),

  status: () => http<StatusResponse>("/api/status"),
  version: () => http<{ version: string }>("/api/version"),

  listScans: () => http<ScanListItem[] | null>("/api/scans"),
  getScan: (id: string) => http<ScanRecord | null>(`/api/scans/${id}`),
  deleteScan: (id: string) =>
    http<{ status: string }>(`/api/scans/${id}`, { method: "DELETE" }),

  instances: () => http<InstancesResponse>("/api/instances"),
  instance: (id: string) => http<ScanInstance>(`/api/instances/${id}`),
  stopInstance: (id: string) =>
    http<{ status: string }>(`/api/instances/${id}/stop`, { method: "POST" }),
  restartInstance: (id: string) =>
    http<{ status: string }>(`/api/instances/${id}/restart`, {
      method: "POST",
    }),
  startSavedInstance: (id: string) =>
    http<{ status: string }>(`/api/instances/${id}/start`, { method: "POST" }),

  startScan: (req: ScanRequest) =>
    http<{ status: string; instance_id: string }>("/api/scan", {
      method: "POST",
      json: req,
    }),
  stopAll: () =>
    http<{ status: string }>("/api/stop", { method: "POST" }),

  queueStatus: () => http<QueueStatus>("/api/queue/status"),
  queueResume: () =>
    http<{ status: string; from_index?: number; targets_left?: number; error?: string }>(
      "/api/queue/resume",
      { method: "POST" },
    ),
  queueClear: () =>
    http<{ status: string }>("/api/queue/clear", { method: "POST" }),

  rateLimit: () => http<RateLimitSettings>("/api/settings/rate-limit"),
  updateRateLimit: (req: RateLimitSettings) =>
    http<RateLimitSettings>("/api/settings/rate-limit", {
      method: "POST",
      json: req,
    }),

  agentMail: () => http<AgentMailSettings>("/api/settings/agentmail"),
  updateAgentMail: (req: { pod: string; apiKey: string }) =>
    http<AgentMailSettings>("/api/settings/agentmail", {
      method: "POST",
      json: req,
    }),

  reportUrl: (scanId: string) => `/api/report/${scanId}`,

  chat: (message: string, instanceId?: string) =>
    http<{ reply?: string; error?: string }>("/api/chat", {
      method: "POST",
      json: { message, instance_id: instanceId },
    }),
};
