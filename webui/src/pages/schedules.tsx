import { useState, type FormEvent } from "react";
import { Play, Plus, Trash2 } from "lucide-react";
import { useCreateSchedule, useDeleteSchedule, useSchedulesList, useTriggerSchedule, useUpdateSchedule } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { api } from "@/api/client";
import type { AssessmentConfig, AssessmentMode, AssessmentPlan, AssessmentType } from "@/types/api";

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
  const [typedAssessment, setTypedAssessment] = useState(false);
  const [assessmentMode, setAssessmentMode] = useState<AssessmentMode>("BLACK_BOX");
  const [assessmentTypes, setAssessmentTypes] = useState<AssessmentType[]>(["WEB_APPLICATION"]);
  const [plan, setPlan] = useState<AssessmentPlan | null>(null);
  const [planning, setPlanning] = useState(false);

  function buildAssessment(target: string): AssessmentConfig {
    return {
      assessment_mode: assessmentMode,
      assessment_types: assessmentTypes,
      assessment_targets: [{ id: "scheduled-app", type: /^https?:\/\//i.test(target) ? "URL" : "DOMAIN", value: target }],
      profile: "web-gentle",
    };
  }

  async function previewAssessment() {
    const target = targets.trim();
    if (!target || /[\n,;]/.test(target)) { setError("Typed assessment schedules currently require one URL or domain target."); return; }
    setError(null); setPlanning(true); setPlan(null);
    try {
      const result = await api.planAssessment(buildAssessment(target));
      setPlan(result);
      if (result.errors?.some((item) => item.blocking)) setError("Resolve the blocking plan errors before saving this schedule.");
    } catch (e) { setError(e instanceof Error ? e.message : "Could not preview the assessment plan"); }
    finally { setPlanning(false); }
  }

  // run_at applies to daily/weekly/monthly (minutes only for hourly);
  // run_day is a weekday for weekly and a day-of-month for monthly.
  const showRunAt = interval !== "hourly";
  const showRunDay = interval === "weekly" || interval === "monthly";

  async function submit(e: FormEvent) {
    e.preventDefault(); setError(null);
    const targetList = targets.split(/[\n,]/).map((v) => v.trim()).filter(Boolean);
    if (typedAssessment && (!plan || plan.errors?.some((item) => item.blocking) || plan.config.assessment_targets[0]?.value !== targets.trim())) { setError("Preview the current assessment plan before saving this schedule."); return; }
    if (!targetList.length && (artifactKind === "none" || !artifactRef.trim())) { setError("Add a target or a source artifact."); return; }
    try {
      await create.mutateAsync({
        name: name.trim() || "Scheduled scan", interval, enabled: true, targets: targetList,
        assessment: typedAssessment && targets.trim() ? buildAssessment(targets.trim()) : undefined,
        profile: typedAssessment ? "web-gentle" : undefined,
        plan_fingerprint: typedAssessment ? plan?.fingerprint : undefined,
        scan_mode: mode,
        run_at: runAt.trim() || undefined,
        run_day: showRunDay ? Number(runDay) : undefined,
        timezone: timezone.trim() || undefined,
        company_name: companyName.trim() || undefined,
        logo_path: logoPath.trim() || undefined,
        artifact: artifactKind !== "none" && artifactRef.trim() ? { kind: artifactKind, ref: artifactRef.trim() } : undefined,
        vuls_ssh_host: vulsHost.trim() || undefined,
      });
      setName(""); setTargets(""); setArtifactRef(""); setVulsHost(""); setPlan(null);
      setRunAt(""); setRunDay("0"); setTimezone(""); setCompanyName(""); setLogoPath("");
    } catch (e) { setError(e instanceof Error ? e.message : "Failed to create schedule"); }
  }

  const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

  return <div className="space-y-6">
    <header><h1 className="text-2xl font-semibold">Deterministic schedules</h1><p className="mt-1 text-sm text-muted-foreground">Schedule a legacy scan or a reviewed typed assessment plan.</p></header>
    <Card><CardHeader><CardTitle className="flex items-center gap-2"><Plus className="h-4 w-4" /> New schedule</CardTitle></CardHeader><CardContent><form onSubmit={submit} className="space-y-4">
      <label className="flex items-start gap-2 rounded-md border p-3 text-sm"><input type="checkbox" checked={typedAssessment} onChange={(e) => { setTypedAssessment(e.target.checked); setPlan(null); setError(null); }} className="mt-0.5" /><span>Use capability-planned web assessment<p className="mt-1 text-xs text-muted-foreground">Uses a reviewed backend plan and rechecks its fingerprint when the schedule runs. One URL or domain is supported in this form.</p></span></label>
      <div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label>Name</Label><Input value={name} onChange={(e) => setName(e.target.value)} /></div><div className="space-y-2"><Label>{typedAssessment ? "Application URL or domain" : "Targets"}</Label><Input value={targets} onChange={(e) => { setTargets(e.target.value); setPlan(null); }} placeholder={typedAssessment ? "https://example.com/app/" : "https://example.com, api.example.com"} /></div></div>
      {typedAssessment && <div className="space-y-3 rounded-md border p-3"><div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label>Assessment mode</Label><Select value={assessmentMode} onValueChange={(value) => { setAssessmentMode(value as AssessmentMode); setPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="BLACK_BOX">Black Box</SelectItem><SelectItem value="GRAY_BOX">Gray Box</SelectItem><SelectItem value="WHITE_BOX">White Box</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label>Coverage</Label><div className="flex gap-3 pt-2 text-xs">{(["WEB_APPLICATION", "API"] as AssessmentType[]).map((type) => <label key={type} className="flex items-center gap-1"><input type="checkbox" checked={assessmentTypes.includes(type)} onChange={() => { setAssessmentTypes((old) => old.includes(type) ? old.filter((item) => item !== type) : [...old, type]); setPlan(null); }} />{type.replaceAll("_", " ")}</label>)}</div></div></div><Button type="button" variant="outline" onClick={() => void previewAssessment()} disabled={planning || assessmentTypes.length === 0}>{planning ? "Planning…" : "Preview schedule plan"}</Button>{plan && <div className="space-y-2 text-xs"><p className="font-mono">Plan {plan.fingerprint} · {plan.jobs.length} job(s)</p>{plan.coverage.map((item) => <p key={item.type} className="text-muted-foreground">{item.type}: {item.state} — {item.reason}</p>)}{plan.decisions.filter((item) => item.state !== "selected" && item.state !== "conditional").map((item, i) => <p key={`${item.scanner}-${item.target_id}-${i}`} className="text-muted-foreground">{item.scanner}: {item.state} — {item.reason}</p>)}</div>}</div>}
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
    <div className="space-y-3">{(list.data ?? []).map((s) => <Card key={s.id}><CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex items-center gap-2"><p className="font-medium">{s.name}</p><ScanStatusPill status={s.enabled ? "running" : "stopped"} />{s.assessment && <span className="rounded border px-2 py-0.5 text-[10px]">{s.assessment.assessment_mode.replaceAll("_", " ")} · {s.profile || "web-gentle"}</span>}</div><p className="mt-1 text-xs text-muted-foreground">{s.interval} · {s.scan_mode} · {(s.targets ?? []).join(", ") || "artifact only"} · next {s.next_run ? new Date(s.next_run).toLocaleString() : "pending"}</p></div><div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => update.mutate({ id: s.id, schedule: { ...s, enabled: !s.enabled } })}>{s.enabled ? "Disable" : "Enable"}</Button><Button size="sm" variant="outline" onClick={() => trigger.mutate(s.id)}><Play className="h-4 w-4" /> Run now</Button><Button size="sm" variant="ghost" onClick={() => remove.mutate(s.id)}><Trash2 className="h-4 w-4" /></Button></div></CardContent></Card>)}</div>
  </div>;
}
