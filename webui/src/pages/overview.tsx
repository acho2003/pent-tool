import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Activity, CheckCircle2, Plus, Server } from "lucide-react";
import { api } from "@/api/client";
import { useScansList } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanStatusPill } from "@/components/scan-status-pill";

export default function OverviewPage() {
  const scans = useScansList();
  const health = useQuery({ queryKey: ["scanner-status"], queryFn: api.scannerStatus, refetchInterval: 30000 });
  const items = scans.data ?? [];
  // Treat an incomplete health response as no configured scanners. This keeps
  // the dashboard usable while an older server is being replaced or a proxy
  // strips an optional response field.
  const scannerHealth = health.data?.scanners ?? [];
  const available = scannerHealth.filter((s) => s.available).length;
  const totalScanners = scannerHealth.length;
  const running = items.filter((s) => ["running", "pending"].includes((s.status || "").toLowerCase())).length;
  return <div className="space-y-6">
    <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div><h1 className="text-2xl font-semibold">Scanner overview</h1><p className="mt-1 text-sm text-muted-foreground">Recon, per-host web and server scanning, and source-code analysis, with report-only AI.</p></div><Button asChild><Link to="/scans/new"><Plus className="h-4 w-4" /> New scan</Link></Button></header>
    <div className="grid gap-3 sm:grid-cols-3"><Metric icon={Server} label="Scanners available" value={`${available}/${totalScanners || "—"}`} /><Metric icon={Activity} label="Active scans" value={running} /><Metric icon={CheckCircle2} label="Stored scans" value={items.length} /></div>
    <Card><CardHeader><CardTitle>Scanner health</CardTitle></CardHeader><CardContent><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{scannerHealth.map((s) => <div key={s.name} className="rounded-md border p-3"><p className="font-medium capitalize">{s.name}</p><p className="mt-0.5 text-[10px] uppercase tracking-wider text-muted-foreground">{s.phase === "sast" ? "source code" : s.phase}</p><p className={`mt-2 text-xs ${s.available ? "text-emerald-400" : "text-red-400"}`}>{s.available ? "available" : "unavailable"}</p><p className="mt-1 truncate text-[10px] text-muted-foreground">{s.path || (s.endpoint_configured ? "service configured" : "service not configured")}</p></div>)}</div></CardContent></Card>
    <Card><CardHeader><CardTitle>Recent scans</CardTitle></CardHeader><CardContent className="space-y-2">{items.slice(0, 8).map((s) => <Link key={s.id} to={`/scans/${s.id}`} className="flex items-center justify-between rounded-md border p-3 hover:bg-muted/30"><div><p className="font-mono text-sm">{s.target}</p><p className="mt-1 text-xs text-muted-foreground">{s.scan_mode || "single"} · {new Date(s.started_at).toLocaleString()}</p></div><ScanStatusPill status={s.status} /></Link>)}{!items.length && <p className="py-8 text-center text-sm text-muted-foreground">No scans yet.</p>}</CardContent></Card>
  </div>;
}
function Metric({ icon: Icon, label, value }: { icon: typeof Server; label: string; value: string | number }) { return <Card><CardContent className="flex items-center gap-3 p-4"><Icon className="h-5 w-5 text-muted-foreground" /><div><p className="text-xs text-muted-foreground">{label}</p><p className="text-xl font-semibold">{value}</p></div></CardContent></Card>; }
