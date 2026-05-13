import { useEffect, type ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth, type AuthState } from "@/store/auth";
import { AppShell } from "@/layout/app-shell";

export function AuthBootstrap({ children }: { children: ReactNode }) {
  const refresh = useAuth((s: AuthState) => s.refresh);
  const status = useAuth((s: AuthState) => s.status);
  useEffect(() => {
    void refresh();
  }, [refresh]);
  if (status === "loading") {
    return (
      <div className="grid min-h-screen place-items-center bg-background">
        <div className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
          Loading…
        </div>
      </div>
    );
  }
  return <>{children}</>;
}

export function RequireAuth() {
  const status = useAuth((s: AuthState) => s.status);
  const location = useLocation();

  if (status === "anon") {
    return (
      <Navigate
        to="/login"
        state={{ from: location.pathname + location.search }}
        replace
      />
    );
  }
  return <AppShell />;
}

export function RedirectIfAuthed({ children }: { children: ReactNode }) {
  const status = useAuth((s: AuthState) => s.status);
  if (status === "authed") return <Navigate to="/" replace />;
  return <>{children}</>;
}
