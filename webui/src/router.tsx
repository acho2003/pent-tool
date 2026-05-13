import { createBrowserRouter, Navigate } from "react-router-dom"
import { AuthBootstrap, RequireAuth, RedirectIfAuthed } from "@/app"
import OverviewPage from "@/pages/overview"
import ScansPage from "@/pages/scans"
import ScanDetailPage from "@/pages/scan-detail"
import LivePage from "@/pages/live"
import InstancesPage from "@/pages/instances"
import EmailTriagePage from "@/pages/email-triage"
import SettingsPage from "@/pages/settings"
import LoginPage from "@/pages/login"
import NotFoundPage from "@/pages/not-found"

function Root({ children }: { children: React.ReactNode }) {
  return <AuthBootstrap>{children}</AuthBootstrap>
}

export const router = createBrowserRouter([
  {
    path: "/login",
    element: (
      <Root>
        <RedirectIfAuthed>
          <LoginPage />
        </RedirectIfAuthed>
      </Root>
    ),
  },
  {
    path: "/",
    element: (
      <Root>
        <RequireAuth />
      </Root>
    ),
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "scans", element: <ScansPage /> },
      { path: "scans/:scanId", element: <ScanDetailPage /> },
      { path: "live", element: <LivePage /> },
      { path: "instances", element: <InstancesPage /> },
      { path: "email", element: <EmailTriagePage /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "404", element: <NotFoundPage /> },
      { path: "*", element: <Navigate to="/404" replace /> },
    ],
  },
])
