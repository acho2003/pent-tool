import { useState, type FormEvent } from "react";
import { Play, Plus, Trash2 } from "lucide-react";
import { useCreateSchedule, useDeleteSchedule, useSchedulesList, useTriggerSchedule, useUpdateSchedule } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScanStatusPill } from "@/components/scan-status-pill";

export default function SchedulesPage() {
  const list = useSchedulesList();
  const create = useCreateSchedule();
  const update = useUpdateSchedule();
  const remove = useDeleteSchedule();
  const trigger = useTriggerSchedule();
  const [name, setName] = useState("");
  const [targets, setTargets] = useState("");
  const [interval, setInterval] = useState("daily");
  const [mode, setMode] = useState("single");
  const [runAt, setRunAt] = useState("");
  const [runDay, setRunDay] = useState("0");
  const [timezone, setTimezone] = useState("");
  const [artifactKind, setArtifactKind] = useState("none");
  const [artifactRef, setArtifactRef] = useState("");
  const [vulsHost, setVulsHost] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [logoPath, setLogoPath] = useState("");
  const [error, setError] = useState<string | null>(null);

  // run_at applies to daily/weekly/monthly (minutes only for hourly);
  // run_day is a weekday for weekly and a day-of-month for monthly.
  const showRunAt = interval !== "hourly";
  const showRunDay = interval === "weekly" || interval === "monthly";

  async function submit(e: FormEvent) {
    e.preventDefault(); setError(null);
    const targetList = targets.split(/[\n,]/).map((v) => v.trim()).filter(Boolean);
    if (!targetList.length && (artifactKind === "none" || !artifactRef.trim())) { setError("Add a target or a source artifact."); return; }
    try {
      await create.mutateAsync({
        name: name.trim() || "Scheduled scan", interval, enabled: true, targets: targetList,
        scan_mode: mode,
        run_at: runAt.trim() || undefined,
        run_day: showRunDay ? Number(runDay) : undefined,
        timezone: timezone.trim() || undefined,
        company_name: companyName.trim() || undefined,
        logo_path: logoPath.trim() || undefined,
        artifact: artifactKind !== "none" && artifactRef.trim() ? { kind: artifactKind, ref: artifactRef.trim() } : undefined,
        vuls_ssh_host: vulsHost.trim() || undefined,
      });
      setName(""); setTargets(""); setArtifactRef(""); setVulsHost("");
      setRunAt(""); setRunDay("0"); setTimezone(""); setCompanyName(""); setLogoPath("");
    } catch (e) { setError(e instanceof Error ? e.message : "Failed to create schedule"); }
  }

  const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

  return <div className="space-y-6">
    <header><h1 className="text-2xl font-semibold">Deterministic schedules</h1><p className="mt-1 text-sm text-muted-foreground">Every scheduled run uses the same deterministic pipeline (recon, per-host web and server scanners, source-code analysis) and report-only AI boundary.</p></header>
    <Card><CardHeader><CardTitle className="flex items-center gap-2"><Plus className="h-4 w-4" /> New schedule</CardTitle></CardHeader><CardContent><form onSubmit={submit} className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label>Name</Label><Input value={name} onChange={(e) => setName(e.target.value)} /></div><div className="space-y-2"><Label>Targets</Label><Input value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="https://example.com, api.example.com" /></div></div>
      <div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label>Interval</Label><Select value={interval} onValueChange={setInterval}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="hourly">Hourly</SelectItem><SelectItem value="daily">Daily</SelectItem><SelectItem value="weekly">Weekly</SelectItem><SelectItem value="monthly">Monthly</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label>Mode</Label><Select value={mode} onValueChange={setMode}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="single">Single</SelectItem><SelectItem value="wildcard">Wildcard</SelectItem></SelectContent></Select></div></div>
      <div className="grid gap-3 sm:grid-cols-3">
        {showRunAt && <div className="space-y-2"><Label>Run at {interval === "hourly" ? "(minute)" : "(time)"}</Label><Input type="time" value={runAt} onChange={(e) => setRunAt(e.target.value)} /></div>}
        {showRunDay && interval === "weekly" && <div className="space-y-2"><Label>Weekday</Label><Select value={runDay} onValueChange={setRunDay}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{WEEKDAYS.map((d, i) => <SelectItem key={d} value={String(i)}>{d}</SelectItem>)}</SelectContent></Select></div>}
        {showRunDay && interval === "monthly" && <div className="space-y-2"><Label>Day of month</Label><Input type="number" min={1} max={31} value={runDay} onChange={(e) => setRunDay(e.target.value)} /></div>}
        {showRunAt && <div className="space-y-2"><Label>Timezone</Label><Input value={timezone} onChange={(e) => setTimezone(e.target.value)} placeholder="e.g. America/New_York" /></div>}
      </div>
      <div className="grid gap-3 sm:grid-cols-3"><div className="space-y-2"><Label>Artifact kind</Label><Select value={artifactKind} onValueChange={setArtifactKind}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="none">None</SelectItem><SelectItem value="filesystem">Filesystem</SelectItem><SelectItem value="repository">Repository</SelectItem><SelectItem value="image">Image</SelectItem><SelectItem value="sbom">SBOM</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label>Artifact ref</Label><Input value={artifactRef} onChange={(e) => setArtifactRef(e.target.value)} /></div><div className="space-y-2"><Label>Vuls SSH alias</Label><Input value={vulsHost} onChange={(e) => setVulsHost(e.target.value)} /></div></div>
      <div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label>Report company</Label><Input value={companyName} onChange={(e) => setCompanyName(e.target.value)} /></div><div className="space-y-2"><Label>Report logo path</Label><Input value={logoPath} onChange={(e) => setLogoPath(e.target.value)} /></div></div>
      {error && <p className="text-sm text-destructive">{error}</p>}<Button type="submit" disabled={create.isPending}>Create schedule</Button>
    </form></CardContent></Card>
    <div className="space-y-3">{(list.data ?? []).map((s) => <Card key={s.id}><CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex items-center gap-2"><p className="font-medium">{s.name}</p><ScanStatusPill status={s.enabled ? "running" : "stopped"} /></div><p className="mt-1 text-xs text-muted-foreground">{s.interval} · {s.scan_mode} · {(s.targets ?? []).join(", ") || "artifact only"} · next {s.next_run ? new Date(s.next_run).toLocaleString() : "pending"}</p></div><div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => update.mutate({ id: s.id, schedule: { ...s, enabled: !s.enabled } })}>{s.enabled ? "Disable" : "Enable"}</Button><Button size="sm" variant="outline" onClick={() => trigger.mutate(s.id)}><Play className="h-4 w-4" /> Run now</Button><Button size="sm" variant="ghost" onClick={() => remove.mutate(s.id)}><Trash2 className="h-4 w-4" /></Button></div></CardContent></Card>)}</div>
  </div>;
}
