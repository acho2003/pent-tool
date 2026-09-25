import { useMemo, useState, type ChangeEvent, type FormEvent } from "react";
import { ChevronLeft, Play, Save, Upload } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useStartScan } from "@/api/queries";
import { api } from "@/api/client";
import type { ToolInfo } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function NewScanPage() {
  const nav = useNavigate();
  const start = useStartScan();
  const [targetsText, setTargetsText] = useState("");
  const [name, setName] = useState("");
  const [mode, setMode] = useState("single");
  const [artifactKind, setArtifactKind] = useState("none");
  const [artifactRef, setArtifactRef] = useState("");
  const [vulsHost, setVulsHost] = useState("");
  const [targetAuth, setTargetAuth] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [logoPath, setLogoPath] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const health = useQuery({ queryKey: ["scanner-status"], queryFn: api.scannerStatus, refetchInterval: 30000 });
  const tools: ToolInfo[] = health.data?.scanners ?? [];
  const selectable = useMemo(() => tools.filter((t) => t.selectable), [tools]);
  const recon = useMemo(() => tools.filter((t) => !t.selectable), [tools]);
  // null = default (every selectable tool); a list once the operator changes it.
  const [picked, setPicked] = useState<string[] | null>(null);
  const scanners = picked ?? selectable.map((t) => t.name);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const targets = useMemo(() => targetsText.split(/[\n,]/).map((v) => v.trim()).filter(Boolean), [targetsText]);

  function toggleSeverity(sev: string) {
    setSeverities((prev) => (prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]));
  }

  function toggleScanner(name: string) {
    setPicked((prev) => {
      const cur = prev ?? selectable.map((t) => t.name);
      return cur.includes(name) ? cur.filter((s) => s !== name) : [...cur, name];
    });
  }

  async function onLogoFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // allow re-selecting the same file
    if (!file) return;
    setError(null);
    setUploadingLogo(true);
    try {
      const res = await api.uploadLogo(file);
      setLogoPath(res.path);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Logo upload failed");
    } finally {
      setUploadingLogo(false);
    }
  }

  async function submit(saveOnly: boolean) {
    setError(null);
    if (!targets.length && (artifactKind === "none" || !artifactRef.trim())) {
      setError("Add at least one target or a source artifact.");
      return;
    }
    if (picked !== null && !picked.length) {
      setError("Select at least one scanner.");
      return;
    }
    try {
      const res = await start.mutateAsync({
        targets,
        name: name.trim() || undefined,
        scan_mode: mode,
        artifact: artifactKind !== "none" && artifactRef.trim() ? { kind: artifactKind, ref: artifactRef.trim() } : undefined,
        vuls_ssh_host: vulsHost.trim() || undefined,
        target_auth: targetAuth.trim() || undefined,
        company_name: companyName.trim() || undefined,
        logo_path: logoPath.trim() || undefined,
        severity_filter: severities.length ? severities : undefined,
        // Every selectable tool (or an unchanged default) sends nothing, so the
        // scan is not pinned to today's pipeline membership.
        scanners: picked === null || picked.length === selectable.length ? undefined : picked,
        save_only: saveOnly || undefined,
      });
      const id = (res as { instance_id?: string; id?: string }).instance_id || (res as { id?: string }).id;
      nav(id ? `/scans/${id}` : "/scans");
    } catch (e) { setError(e instanceof Error ? e.message : "Failed to submit scan"); }
  }

  function onSubmit(e: FormEvent) { e.preventDefault(); void submit(false); }
  return <div className="mx-auto max-w-3xl space-y-5">
    <div>
      <Button variant="ghost" size="sm" onClick={() => nav(-1)}><ChevronLeft className="h-4 w-4" /> Back</Button>
      <h1 className="mt-2 text-2xl font-semibold">Start deterministic scan</h1>
      <p className="mt-1 text-sm text-muted-foreground">Recon, then per-host web and server scanners, then source-code analysis. Report AI runs only after scanning is complete.</p>
    </div>
    <form onSubmit={onSubmit} className="space-y-5">
      <Card><CardHeader><CardTitle>Target and mode</CardTitle></CardHeader><CardContent className="space-y-4">
        <div className="space-y-2"><Label htmlFor="name">Scan name</Label><Input id="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Quarterly external scan" /></div>
        <div className="space-y-2"><Label htmlFor="targets">Hosts or URLs</Label><Textarea id="targets" value={targetsText} onChange={(e) => setTargetsText(e.target.value)} placeholder={"https://example.com\napi.example.com"} rows={4} /><p className="text-xs text-muted-foreground">One per line. Recon discovers live hosts; each host is scanned on its web and/or server track.</p></div>
        <div className="space-y-2"><Label>Mode</Label><Select value={mode} onValueChange={setMode}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="single">Single target</SelectItem><SelectItem value="wildcard">Wildcard discovery</SelectItem></SelectContent></Select></div>
        <div className="space-y-2"><Label>Report severity filter</Label><div className="flex flex-wrap gap-3">{SEVERITIES.map((sev) => (<label key={sev} className="flex items-center gap-1.5 text-sm capitalize"><input type="checkbox" checked={severities.includes(sev)} onChange={() => toggleSeverity(sev)} className="h-3.5 w-3.5 rounded border-border" />{sev}</label>))}</div><p className="text-xs text-muted-foreground">Leave all unchecked to report every severity.</p></div>
      </CardContent></Card>
      <Card><CardHeader><CardTitle>Scanners</CardTitle></CardHeader><CardContent className="space-y-4">
        {health.isLoading && <p className="text-xs text-muted-foreground">Loading scanners…</p>}
        {health.isError && !health.data && <p className="text-xs text-destructive">Could not load the scanner list. The scan will run every scanner.</p>}
        {recon.length > 0 && <p className="text-xs text-muted-foreground">Always runs: {recon.map((t) => t.name).join(", ")} (recon).</p>}
        {([["web", "Web"], ["server", "Server"], ["sast", "Source code"]] as const).map(([phase, label]) => {
          const group = selectable.filter((t) => t.phase === phase);
          if (!group.length) return null;
          return <div key={phase} className="space-y-2">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
            <div className="grid gap-2 sm:grid-cols-2">{group.map((t) => <label key={t.name} className="flex items-start gap-2 rounded-lg border p-3 text-sm">
              <input type="checkbox" checked={scanners.includes(t.name)} onChange={() => toggleScanner(t.name)} className="mt-0.5 h-3.5 w-3.5 rounded border-border" />
              <span className="min-w-0">
                <span className="flex items-center gap-2"><span className="font-medium capitalize">{t.name}</span>{t.available ? <span className="text-xs text-emerald-400">installed</span> : <span className="text-xs text-red-400">not found</span>}</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">{t.summary}</span>
              </span>
            </label>)}</div>
          </div>;
        })}
        <p className="text-xs text-muted-foreground">Deselected scanners are recorded as <span className="font-mono">skipped</span> on every scope, so the report still shows what was not attempted. Scanners that do not apply to a scope are recorded <span className="font-mono">not applicable</span>.</p>
      </CardContent></Card>
      <Card><CardHeader><CardTitle>Optional scanner inputs</CardTitle></CardHeader><CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2"><div className="space-y-2"><Label>Source / artifact kind</Label><Select value={artifactKind} onValueChange={setArtifactKind}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="none">No artifact</SelectItem><SelectItem value="filesystem">Filesystem</SelectItem><SelectItem value="repository">Repository</SelectItem><SelectItem value="image">Image</SelectItem><SelectItem value="sbom">SBOM</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label htmlFor="artifact">Artifact reference</Label><Input id="artifact" value={artifactRef} onChange={(e) => setArtifactRef(e.target.value)} placeholder="./repo or alpine:3.20" /></div></div>
        <div className="space-y-2"><Label htmlFor="vuls">Vuls SSH host alias</Label><Input id="vuls" value={vulsHost} onChange={(e) => setVulsHost(e.target.value)} placeholder="prod-web" /><p className="text-xs text-muted-foreground">Must reference an operator-managed SSH configuration. Private key material is never stored in scan records.</p></div>
        <div className="space-y-2"><Label htmlFor="auth">Web authentication headers</Label><Textarea id="auth" value={targetAuth} onChange={(e) => setTargetAuth(e.target.value)} placeholder="Authorization: Bearer …" rows={3} /></div>
      </CardContent></Card>
      <Card><CardHeader><CardTitle>Report branding</CardTitle></CardHeader><CardContent className="grid gap-4 sm:grid-cols-2"><div className="space-y-2"><Label htmlFor="company">Company</Label><Input id="company" value={companyName} onChange={(e) => setCompanyName(e.target.value)} /></div><div className="space-y-2"><Label htmlFor="logo">Logo</Label><div className="flex gap-2"><Input id="logo" value={logoPath} onChange={(e) => setLogoPath(e.target.value)} placeholder="Upload or paste a path" /><Button type="button" variant="outline" size="sm" asChild disabled={uploadingLogo}><label className="cursor-pointer"><Upload className="h-4 w-4" /> {uploadingLogo ? "Uploading…" : "Upload"}<input type="file" accept="image/*" className="hidden" onChange={onLogoFile} /></label></Button></div></div></CardContent></Card>
      {error && <p className="text-sm text-destructive">{error}</p>}
      <div className="flex justify-end gap-2"><Button type="button" variant="outline" onClick={() => void submit(true)} disabled={start.isPending}><Save className="h-4 w-4" /> Save</Button><Button type="submit" disabled={start.isPending}><Play className="h-4 w-4" /> Start scan</Button></div>
    </form>
  </div>;
}
