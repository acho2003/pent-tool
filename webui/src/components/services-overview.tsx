import type { ServiceOverview } from "@/types/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const SEVERITIES = [
  { key: "critical", label: "C", tone: "text-red-400" },
  { key: "high", label: "H", tone: "text-orange-400" },
  { key: "medium", label: "M", tone: "text-amber-300" },
  { key: "low", label: "L", tone: "text-emerald-300" },
  { key: "info", label: "I", tone: "text-sky-300" },
] as const;

// Per-service overview of a microservice assessment, from the same saved
// plan, runs and findings the report uses.
export function ServicesOverviewCard({ services }: { services?: ServiceOverview[] }) {
  if (!services?.length) return null;
  return <Card>
    <CardHeader>
      <CardTitle>Services</CardTitle>
      <p className="text-xs text-muted-foreground">Active findings, authentication and scanner outcomes per service. "Token applied, not verified" means the shared login token was sent but no protected path proved it was accepted.</p>
    </CardHeader>
    <CardContent className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-sm">
        <thead><tr className="border-b text-left text-xs uppercase tracking-wide text-muted-foreground"><th className="py-2 pr-3">Service</th>{SEVERITIES.map((s) => <th key={s.key} className="w-8 py-2 text-center" title={s.key}>{s.label}</th>)}<th className="py-2 pl-3">Authentication</th><th className="py-2 pl-3">Runs ok / failed / skipped</th></tr></thead>
        <tbody>{services.map((service) => <tr key={service.id || service.name} className="border-b border-border/50 align-top">
          <td className="py-2 pr-3"><p className="font-medium">{service.name}</p><p className="break-all font-mono text-xs text-muted-foreground">{service.targets.join(", ") || "—"}</p></td>
          {SEVERITIES.map((s) => <td key={s.key} className={`py-2 text-center tabular-nums ${service.counts[s.key] ? s.tone : "text-muted-foreground"}`}>{service.counts[s.key] ?? 0}</td>)}
          <td className={`py-2 pl-3 text-xs ${service.auth.includes("failed") || service.auth.includes("expired") ? "text-destructive" : service.auth === "verified" ? "text-emerald-300" : "text-amber-200"}`}>{service.auth}</td>
          <td className="py-2 pl-3 text-xs tabular-nums">{service.completed} / {service.failed} / {service.skipped}</td>
        </tr>)}</tbody>
      </table>
    </CardContent>
  </Card>;
}
