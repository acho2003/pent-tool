import { create } from "zustand"
import { api } from "@/api/client"

type Status = "loading" | "anon" | "authed" | "disabled"

interface AuthState {
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
