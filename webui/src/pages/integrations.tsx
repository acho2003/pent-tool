import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function IntegrationsPage() {
  const health = useQuery({ queryKey: ["scanner-status"], queryFn: api.scannerStatus, refetchInterval: 30000 });
  return <div className="space-y-6"><header><h1 className="text-2xl font-semibold">Scanner integrations</h1><p className="mt-1 text-sm text-muted-foreground">Execution integrations are fixed. Report AI is optional and isolated from scanning.</p></header><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{(health.data?.scanners ?? []).map((s) => <Card key={s.name}><CardHeader><CardTitle className="capitalize">{s.name}</CardTitle></CardHeader><CardContent><p className={s.available ? "text-sm text-emerald-400" : "text-sm text-red-400"}>{s.available ? "Available" : "Unavailable"}</p><p className="mt-1 text-xs text-muted-foreground">{s.summary}</p><p className="mt-2 text-xs text-muted-foreground">{s.path || (s.endpoint_configured ? "Internal service configured" : "Service not configured")}</p></CardContent></Card>)}</div><Card><CardHeader><CardTitle>Report AI</CardTitle></CardHeader><CardContent className="flex items-center justify-between gap-3"><p className="text-sm text-muted-foreground">Used only after all scanner attempts finish. Offline operation uses a deterministic fallback report.</p><Button asChild variant="outline"><Link to="/settings?tab=llm">Configure</Link></Button></CardContent></Card></div>;
}
