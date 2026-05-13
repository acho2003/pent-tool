import { create } from "zustand"
import { api, AUTH_EXPIRED } from "@/api/client"

type Status = "loading" | "anon" | "authed" | "disabled"

export interface AuthState {
  status: Status
  // Whether the backend has auth configured. When `false`, requests still
  // succeed but we don't show login UI.
  authEnabled: boolean
  refresh: () => Promise<void>
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

export const useAuth = create<AuthState>((set) => ({
  status: "loading",
  authEnabled: false,
  refresh: async () => {
    try {
      const res = await api.authStatus()
      if (!res.auth_enabled) {
        set({ status: "disabled", authEnabled: false })
        return
      }
      set({
        status: res.authenticated ? "authed" : "anon",
        authEnabled: true,
      })
    } catch {
      // If we can't reach the API, treat as anon so the login screen renders.
      set({ status: "anon", authEnabled: true })
    }
  },
  login: async (username, password) => {
    await api.login(username, password)
    set({ status: "authed", authEnabled: true })
  },
  logout: async () => {
    try {
      await api.logout()
    } catch {
      /* ignore */
    }
    set({ status: "anon", authEnabled: true })
  },
}))

// Listen for global auth-expired events emitted by the API client whenever
// any request returns 401. Without this, an expired session would just
// surface as a generic toast on whichever screen the user happened to be
// on — they'd have to refresh manually to get the login form back.
if (typeof window !== "undefined") {
  window.addEventListener(AUTH_EXPIRED, () => {
    const { status, authEnabled } = useAuth.getState()
    // Only react if we currently think we're logged in. Avoids fighting
    // with the initial /api/auth/status probe when the app first loads.
    if (status === "authed" || authEnabled) {
      useAuth.setState({ status: "anon", authEnabled: true })
    }
  })
}
