import { create } from "zustand"
import { api } from "@/api/client"
import type { User } from "@/types/api"

interface AuthState {
  user: User | null
  csrf: string | null
  status: "loading" | "authed" | "anon"
  setSession: (user: User, csrf: string) => void
  clearSession: () => void
  refresh: () => Promise<void>
  logout: () => Promise<void>
}

export const useAuth = create<AuthState>((set) => ({
  user: null,
  csrf: null,
  status: "loading",
  setSession: (user, csrf) => {
    api.setCsrf(csrf)
    set({ user, csrf, status: "authed" })
  },
  clearSession: () => {
    api.setCsrf(null)
    set({ user: null, csrf: null, status: "anon" })
  },
  refresh: async () => {
    try {
      const res = await api.me()
      if (res.authenticated && res.user) {
        api.setCsrf(res.csrf_token ?? null)
        set({ user: res.user, csrf: res.csrf_token ?? null, status: "authed" })
      } else {
        api.setCsrf(null)
        set({ user: null, csrf: null, status: "anon" })
      }
    } catch {
      api.setCsrf(null)
      set({ user: null, csrf: null, status: "anon" })
    }
  },
  logout: async () => {
    try {
      await api.logout()
    } catch {
      // ignore
    }
    api.setCsrf(null)
    set({ user: null, csrf: null, status: "anon" })
  },
}))
