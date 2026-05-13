import { createBrowserRouter, Navigate } from "react-router-dom";
import { AppShell } from "./layout/app-shell";
import { OverviewPage } from "./pages/overview";
import { NewScanPage } from "./pages/new-scan";
import { ScansPage } from "./pages/scans";
import { ScanDetailPage } from "./pages/scan-detail";
import { FindingsPage } from "./pages/findings";
import { FindingDetailPage } from "./pages/finding-detail";
import { LiveFeedPage } from "./pages/live";
import { ReportsPage } from "./pages/reports";
import { IntegrationsPage } from "./pages/integrations";
import { SettingsPage } from "./pages/settings";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: "scans/new", element: <NewScanPage /> },
      { path: "scans", element: <ScansPage /> },
      { path: "scans/:id", element: <ScanDetailPage /> },
      { path: "scans/:id/findings/:fid", element: <FindingDetailPage /> },
      { path: "findings", element: <FindingsPage /> },
      { path: "findings/:scanId/:fid", element: <FindingDetailPage /> },
      { path: "live", element: <LiveFeedPage /> },
      { path: "reports", element: <ReportsPage /> },
      { path: "integrations", element: <IntegrationsPage /> },
      { path: "settings", element: <SettingsPage /> },
      { path: "*", element: <Navigate to="/" replace /> },
    ],
  },
]);
