import { useEffect } from "react"
import { Navigate, Outlet, useLocation } from "react-router-dom"
import { useAuth } from "@/store/auth"
import { useWS } from "@/store/ws"
import AppShell from "@/layout/app-shell"
import CommandPalette from "@/components/command-palette"

export function AuthBootstrap({ children }: { children: React.ReactNode }) {
  const refresh = useAuth((s) => s.refresh)
  const status = useAuth((s) => s.status)
  useEffect(() => {
    void refresh()
  }, [refresh])
  if (status === "loading") {
    return (
      <div className="grid min-h-screen place-items-center bg-background">
        <div className="font-mono text-xs uppercase tracking-wider text-muted-foreground">Loading…</div>
      </div>
    )
  }
  return <>{children}</>
}

export function RequireAuth() {
  const status = useAuth((s) => s.status)
  const location = useLocation()
  const connect = useWS((s) => s.connect)

  useEffect(() => {
    if (status === "authed") connect()
  }, [status, connect])

  if (status === "anon") {
    return <Navigate to="/login" state={{ from: location.pathname + location.search }} replace />
  }
  return (
    <AppShell>
      <Outlet />
      <CommandPalette />
    </AppShell>
  )
}

export function RedirectIfAuthed({ children }: { children: React.ReactNode }) {
  const status = useAuth((s) => s.status)
  if (status === "authed") return <Navigate to="/" replace />
  return <>{children}</>
}
