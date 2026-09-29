import { useMemo, useState, type ChangeEvent, type FormEvent } from "react";
import { ChevronLeft, Play, Save, Upload } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useStartScan } from "@/api/queries";
import { api } from "@/api/client";
import type { AssessmentMode, AssessmentPlan, AssessmentType, AssessmentScannerDefinition, ToolInfo } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const ASSESSMENT_TYPES: AssessmentType[] = ["NETWORK", "WEB_APPLICATION", "API", "SOURCE_CODE", "DEPENDENCIES", "CONTAINER", "HOST", "CLOUD", "KUBERNETES", "INFRASTRUCTURE_AS_CODE", "COMPLIANCE"];

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
  const [assessmentMode, setAssessmentMode] = useState<AssessmentMode>("BLACK_BOX");
  const [assessmentTypes, setAssessmentTypes] = useState<AssessmentType[]>(["WEB_APPLICATION"]);
  const [optionalAssessmentScanners, setOptionalAssessmentScanners] = useState<string[]>([]);
  const [subdomainDiscovery, setSubdomainDiscovery] = useState(false);
  const [assessmentPlan, setAssessmentPlan] = useState<AssessmentPlan | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [planning, setPlanning] = useState(false);
  const [apiDefinitionId, setAPIDefinitionId] = useState("");
  const [apiDefinitionInfo, setAPIDefinitionInfo] = useState("");
  const [apiTargetId, setAPITargetId] = useState("");
  const [uploadingDefinition, setUploadingDefinition] = useState(false);
  const [credentialId, setCredentialId] = useState("");
  const [credentialTargetId, setCredentialTargetId] = useState("target-1");
  const [credentialKind, setCredentialKind] = useState<"APPLICATION_HEADERS" | "FORM_LOGIN">("APPLICATION_HEADERS");
  const [credentialName, setCredentialName] = useState("Web scan credential");
  const [headerName, setHeaderName] = useState("Authorization");
  const [headerValue, setHeaderValue] = useState("");
  const [loginURL, setLoginURL] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginUsernameField, setLoginUsernameField] = useState("username");
  const [loginPasswordField, setLoginPasswordField] = useState("password");
  const [loginCSRFField, setLoginCSRFField] = useState("");
  const [savingCredential, setSavingCredential] = useState(false);
  const [credentialSaved, setCredentialSaved] = useState(false);
  const [authVerifyURL, setAuthVerifyURL] = useState("");
  const [authVerifyMarker, setAuthVerifyMarker] = useState("");
  const health = useQuery({ queryKey: ["scanner-status"], queryFn: api.scannerStatus, refetchInterval: 30000 });
  const registryQuery = useQuery({ queryKey: ["assessment-scanner-registry"], queryFn: api.scannerRegistry, refetchInterval: 30000 });
  const registry: AssessmentScannerDefinition[] = registryQuery.data?.scanners ?? [];
  const optionalDefinitions = registry.filter((definition) => ["optional", "explicit_opt_in"].includes(definition.default_selection) && definition.assessment_types.some((type) => assessmentTypes.includes(type)));
  const tools: ToolInfo[] = health.data?.scanners ?? [];
  const selectable = useMemo(() => tools.filter((t) => t.selectable), [tools]);
  const recon = useMemo(() => tools.filter((t) => !t.selectable), [tools]);
  // null = default (every selectable tool); a list once the operator changes it.
  const [picked, setPicked] = useState<string[] | null>(null);
  const scanners = picked ?? selectable.map((t) => t.name);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const targets = useMemo(() => targetsText.split(/[\n,]/).map((v) => v.trim()).filter(Boolean), [targetsText]);

  function toggleAssessmentType(type: AssessmentType) {
    setAssessmentTypes((prev) => prev.includes(type) ? prev.filter((item) => item !== type) : [...prev, type]);
    setAssessmentPlan(null);
  }

  async function previewAssessmentPlan() {
    setPlanError(null);
    setAssessmentPlan(null);
    if (!targets.length || !assessmentTypes.length) {
      setPlanError("Add at least one URL or host and select an assessment type.");
      return;
    }
    setPlanning(true);
    try {
      const plan = await api.planAssessment({
        assessment_mode: assessmentMode,
        assessment_types: assessmentTypes,
        assessment_targets: targets.map((value, i) => ({ id: `target-${i + 1}`, type: inferTargetKind(value), value })),
        profile: "web-gentle",
        subdomain_discovery: subdomainDiscovery,
        access: credentialId ? [{ target_ids: [credentialTargetId], kind: credentialKind, credential_id: credentialId, verify_url: authVerifyURL, verify_marker: authVerifyMarker }] : undefined,
        api_definitions: apiDefinitionId ? [{ target_id: apiTargetId || "target-1", definition_id: apiDefinitionId }] : undefined,
        scanner_selection: optionalAssessmentScanners.length > 0 || (picked !== null && picked.length !== selectable.length)
          ? { mode: "custom", variants: [...new Set([...(picked ?? selectable.map((tool) => tool.name)), ...optionalAssessmentScanners])] }
          : { mode: "auto" },
      });
      setAssessmentPlan(plan);
    } catch (err) {
      setPlanError(err instanceof Error ? err.message : "Could not create assessment plan");
    } finally {
      setPlanning(false);
    }
  }

  async function saveCredential() {
    setPlanError(null);
    if (!targets.length || (credentialKind === "APPLICATION_HEADERS" && (!headerName.trim() || !headerValue)) || (credentialKind === "FORM_LOGIN" && (!loginURL.trim() || !loginUsername || !loginPassword))) {
      setPlanError(credentialKind === "FORM_LOGIN" ? "Add a target, login URL, username, and password before saving the credential." : "Add a target, header name, and header value before saving the credential.");
      return;
    }
    const credentialTargetIndex = Number(credentialTargetId.replace("target-", "")) - 1;
    if (!/^https?:\/\//i.test(targets[credentialTargetIndex] ?? "")) {
      setPlanError("Application credentials must be bound to an explicit HTTP(S) URL target.");
      return;
    }
    setSavingCredential(true);
    try {
      const credential = await api.createCredential({
        name: credentialName.trim() || "Web scan credential",
        kind: credentialKind,
        target_ids: [credentialTargetId],
        values: credentialKind === "FORM_LOGIN"
          ? { login_url: loginURL.trim(), username: loginUsername, password: loginPassword, username_field: loginUsernameField.trim() || "username", password_field: loginPasswordField.trim() || "password", ...(loginCSRFField.trim() ? { csrf_field: loginCSRFField.trim() } : {}) }
          : { [headerName.trim()]: headerValue },
      });
      setCredentialId(credential.id);
      setAuthVerifyURL(targets[credentialTargetIndex]);
      setHeaderValue("");
      setLoginPassword("");
      setAssessmentPlan(null);
      setCredentialSaved(true);
    } catch (err) {
      setPlanError(err instanceof Error ? err.message : "Could not save credential");
    } finally {
      setSavingCredential(false);
    }
  }

  async function uploadAPIDefinition(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      setPlanError("API definition must be 5 MiB or smaller.");
      return;
    }
    setPlanError(null);
    setAssessmentPlan(null);
    setUploadingDefinition(true);
    try {
      const result = await api.uploadAPIDefinition(file);
      setAPIDefinitionId(result.id);
      setAPIDefinitionInfo(`${result.operation_count} operations · ${result.format} · ${result.size_bytes} bytes`);
      setAPITargetId("target-1");
    } catch (err) {
      setPlanError(err instanceof Error ? err.message : "API definition upload failed");
    } finally {
      setUploadingDefinition(false);
    }
  }

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
    if (!assessmentPlan) {
      setError("Preview the assessment plan after your last configuration change before saving or starting.");
      return;
    }
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
        assessment: assessmentPlan.config,
        plan_fingerprint: assessmentPlan.fingerprint,
        profile: "web-gentle",
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
      <h1 className="mt-2 text-2xl font-semibold">New Assessment</h1>
      <p className="mt-1 text-sm text-muted-foreground">Choose a mode and coverage, review the server-generated scanner plan, then start the accepted assessment.</p>
    </div>
    <Card><CardHeader><CardTitle>Assessment plan preview</CardTitle></CardHeader><CardContent className="space-y-4">
      <p className="text-sm text-muted-foreground">Review mode, requested coverage, scanner choices, and gaps. Preview does not contact targets or start a scan. The accepted plan fingerprint is checked again when execution is queued.</p>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2"><Label>Assessment mode</Label><Select value={assessmentMode} onValueChange={(value) => { setAssessmentMode(value as AssessmentMode); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="BLACK_BOX">Black Box</SelectItem><SelectItem value="GRAY_BOX">Gray Box</SelectItem><SelectItem value="WHITE_BOX">White Box</SelectItem></SelectContent></Select></div>
        <div className="space-y-2"><Label>Profile</Label><Input value="web-gentle" disabled /><p className="text-xs text-muted-foreground">Production-safe default for web coverage.</p></div>
      </div>
      <div className="space-y-2"><Label>Assessment types</Label><div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{ASSESSMENT_TYPES.map((type) => <label key={type} className="flex items-center gap-2 rounded-md border p-2 text-xs"><input type="checkbox" checked={assessmentTypes.includes(type)} onChange={() => toggleAssessmentType(type)} />{type.replaceAll("_", " ")}</label>)}</div></div>
      {optionalDefinitions.length > 0 && <div className="space-y-3 rounded-md border p-3"><div><p className="text-sm font-medium">Advanced optional scanners</p><p className="mt-1 text-xs text-muted-foreground">These scanners are off unless you select them. Availability and target compatibility are checked by the backend planner.</p></div>{optionalDefinitions.map((definition) => <label key={definition.id} className={`flex items-start gap-2 rounded-md border p-3 text-xs ${definition.available ? "cursor-pointer" : "opacity-60"}`}><input type="checkbox" checked={optionalAssessmentScanners.includes(definition.id)} disabled={!definition.available} onChange={() => { setOptionalAssessmentScanners((current) => current.includes(definition.id) ? current.filter((id) => id !== definition.id) : [...current, definition.id]); setAssessmentPlan(null); }} className="mt-0.5" /><span><span className="font-medium">{definition.name} · {definition.risk} risk · {definition.available ? "available" : "unavailable"}</span><span className="mt-1 block text-muted-foreground">{definition.summary}</span></span></label>)}</div>}
      <label className="flex items-start gap-2 rounded-md border p-3 text-sm"><input type="checkbox" checked={subdomainDiscovery} onChange={(e) => { setSubdomainDiscovery(e.target.checked); setAssessmentPlan(null); }} className="mt-0.5" /><span>Authorize subdomain discovery for domain targets<p className="mt-1 text-xs text-muted-foreground">Off by default. This adds Subfinder coverage to the plan when a domain target is supplied.</p></span></label>
      <div className="space-y-3 rounded-md border p-3"><div className="space-y-1"><Label htmlFor="api-definition">OpenAPI / Swagger definition</Label><Input id="api-definition" type="file" accept=".json,.yaml,.yml,application/json" onChange={(e) => void uploadAPIDefinition(e)} disabled={uploadingDefinition} /><p className="text-xs text-muted-foreground">Definitions are size-limited, external references are rejected, and spec server URLs do not change target scope.</p></div>{apiDefinitionId && <><p className="break-all font-mono text-xs text-muted-foreground">Uploaded {apiDefinitionInfo} · {apiDefinitionId}</p><div className="space-y-2"><Label>Map this definition to a target</Label><Select value={apiTargetId || "target-1"} onValueChange={(value) => { setAPITargetId(value); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{targets.map((target, i) => <SelectItem key={i} value={`target-${i + 1}`}>{target}</SelectItem>)}</SelectContent></Select><p className="text-xs text-muted-foreground">The selected target must be an explicit HTTP(S) URL.</p></div></>}</div>
      <div className="space-y-3 rounded-md border p-3">
        <div>
          <p className="text-sm font-medium">Target-bound web authentication</p>
          <p className="mt-1 text-xs text-muted-foreground">Credentials are encrypted. At scan start, Xalgorix verifies the selected account page before sharing the scoped header or session cookie with the dedicated ZAP scan.</p>
        </div>
        {credentialSaved && <p className="text-xs text-emerald-400">Encrypted credential saved. Set an authenticated verification URL and a response marker before previewing the plan.</p>}
        {credentialId ? <p className="break-all font-mono text-xs text-muted-foreground">Credential reference: {credentialId}</p> : <>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-2"><Label>Credential type</Label><Select value={credentialKind} onValueChange={(value) => { setCredentialKind(value as "APPLICATION_HEADERS" | "FORM_LOGIN"); setCredentialId(""); setCredentialSaved(false); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="APPLICATION_HEADERS">HTTP headers</SelectItem><SelectItem value="FORM_LOGIN">Form login</SelectItem></SelectContent></Select></div>
            <div className="space-y-2"><Label>Bind to target</Label><Select value={credentialTargetId} onValueChange={(value) => { setCredentialTargetId(value); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{targets.map((target, i) => <SelectItem key={i} value={"target-" + (i + 1)}>{target}</SelectItem>)}</SelectContent></Select></div>
          </div>
          <div className="space-y-2"><Label htmlFor="credential-name">Credential name</Label><Input id="credential-name" value={credentialName} onChange={(e) => setCredentialName(e.target.value)} /></div>
          {credentialKind === "APPLICATION_HEADERS" ? <>
            <div className="space-y-2"><Label htmlFor="auth-header-name">Header name</Label><Input id="auth-header-name" value={headerName} onChange={(e) => setHeaderName(e.target.value)} /></div>
            <div className="space-y-2"><Label htmlFor="auth-header-value">Header value</Label><Input id="auth-header-value" type="password" autoComplete="new-password" value={headerValue} onChange={(e) => setHeaderValue(e.target.value)} placeholder="Bearer token or cookie value" /></div>
          </> : <>
            <div className="space-y-2"><Label htmlFor="login-url">Login page URL</Label><Input id="login-url" value={loginURL} onChange={(e) => setLoginURL(e.target.value)} placeholder="https://app.example.test/login" /><p className="text-xs text-muted-foreground">Must stay within the selected application's origin and path boundary.</p></div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-2"><Label htmlFor="login-username">Username</Label><Input id="login-username" value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)} autoComplete="username" /></div>
              <div className="space-y-2"><Label htmlFor="login-password">Password</Label><Input id="login-password" type="password" autoComplete="new-password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} /></div>
            </div>
            <div className="grid gap-3 sm:grid-cols-3">
              <div className="space-y-2"><Label htmlFor="username-field">Username field</Label><Input id="username-field" value={loginUsernameField} onChange={(e) => setLoginUsernameField(e.target.value)} /></div>
              <div className="space-y-2"><Label htmlFor="password-field">Password field</Label><Input id="password-field" value={loginPasswordField} onChange={(e) => setLoginPasswordField(e.target.value)} /></div>
              <div className="space-y-2"><Label htmlFor="csrf-field">CSRF field (optional)</Label><Input id="csrf-field" value={loginCSRFField} onChange={(e) => setLoginCSRFField(e.target.value)} placeholder="csrf" /></div>
            </div>
          </>}
          <Button type="button" variant="outline" onClick={() => void saveCredential()} disabled={savingCredential || (credentialKind === "FORM_LOGIN" ? !loginURL || !loginUsername || !loginPassword : !headerValue)}>{savingCredential ? "Encrypting…" : "Save encrypted credential"}</Button>
        </>}
        {credentialId && <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-2"><Label htmlFor="auth-verify-url">Authenticated verification URL</Label><Input id="auth-verify-url" value={authVerifyURL} onChange={(e) => { setAuthVerifyURL(e.target.value); setAssessmentPlan(null); }} placeholder="https://app.example.test/account" /></div>
          <div className="space-y-2"><Label htmlFor="auth-verify-marker">Expected response marker</Label><Input id="auth-verify-marker" value={authVerifyMarker} onChange={(e) => { setAuthVerifyMarker(e.target.value); setAssessmentPlan(null); }} placeholder="A phrase present only when logged in" /></div>
        </div>}
      </div>
      <Button type="button" variant="outline" onClick={() => void previewAssessmentPlan()} disabled={planning}>{planning ? "Planning…" : "Preview plan"}</Button>
      {planError && <p className="text-sm text-destructive">{planError}</p>}
      {assessmentPlan && <div className="space-y-4 border-t pt-4">
        <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-medium">Coverage preview · registry {assessmentPlan.registry_version}</p><p className="font-mono text-xs text-muted-foreground">{assessmentPlan.fingerprint.slice(0, 24)}…</p></div>
        <div className="grid gap-2 sm:grid-cols-2">{assessmentPlan.coverage.map((item) => <div key={item.type} className="rounded-md border p-3"><p className="text-xs font-medium">{item.type.replaceAll("_", " ")} · {item.state}</p><p className="mt-1 text-xs text-muted-foreground">{item.reason}</p></div>)}</div>
        {assessmentPlan.capabilities.filter((item) => item.capability === "authenticated_web").length > 0 && <div><p className="mb-2 text-sm font-medium">Authentication readiness</p><ul className="space-y-1 text-xs">{assessmentPlan.capabilities.filter((item) => item.capability === "authenticated_web").map((item, i) => <li key={`${item.target_id}-${i}`} className="font-mono">{item.target_id} · {item.state}: {item.reason}</li>)}</ul></div>}
        <div><p className="mb-2 text-sm font-medium">Planned jobs ({assessmentPlan.jobs.length})</p>{assessmentPlan.jobs.length ? <ul className="space-y-1 text-xs">{assessmentPlan.jobs.map((job) => <li key={job.id} className="font-mono">{job.scanner} · {(job.assessment_types ?? [job.assessment_type]).join(" + ")} · {job.state} · {job.target}</li>)}</ul> : <p className="text-xs text-muted-foreground">No runnable jobs are available for these inputs.</p>}</div>
        {assessmentPlan.api_endpoints?.length ? <div><p className="mb-2 text-sm font-medium">API operations in the definition ({assessmentPlan.api_endpoints.length})</p><p className="mb-2 text-xs text-muted-foreground">Only resolved GET and HEAD routes are seeded into the scoped ZAP scan. Mutating operations and routes needing values remain untested with a reason.</p><ul className="space-y-1 text-xs">{assessmentPlan.api_endpoints.map((endpoint, i) => <li key={`${endpoint.target_id}-${endpoint.method}-${endpoint.path}-${i}`} className="font-mono">{endpoint.method} {endpoint.path} · {endpoint.eligible ? "eligible" : "untested"}{endpoint.reason ? ` · ${endpoint.reason}` : ""}</li>)}</ul></div> : null}
        <details><summary className="cursor-pointer text-xs font-medium">Scanner decisions ({assessmentPlan.decisions.length})</summary><ul className="mt-2 space-y-2">{assessmentPlan.decisions.map((decision, i) => <li key={`${decision.scanner}-${decision.target_id ?? "all"}-${i}`} className="border-l-2 pl-3 text-xs"><span className="font-medium">{decision.scanner} · {decision.state}</span><p className="text-muted-foreground">{decision.reason}</p></li>)}</ul></details>
      </div>}
    </CardContent></Card>
    <form onSubmit={onSubmit} className="space-y-5">
      <Card><CardHeader><CardTitle>Target and mode</CardTitle></CardHeader><CardContent className="space-y-4">
        <div className="space-y-2"><Label htmlFor="name">Scan name</Label><Input id="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Quarterly external scan" /></div>
        <div className="space-y-2"><Label htmlFor="targets">Hosts or URLs</Label><Textarea id="targets" value={targetsText} onChange={(e) => { setTargetsText(e.target.value); setAssessmentPlan(null); setCredentialId(""); setCredentialTargetId("target-1"); setCredentialSaved(false); }} placeholder={"https://example.com\napi.example.com"} rows={4} /><p className="text-xs text-muted-foreground">One explicit target per line. The selected scanners receive the exact supplied application URL or host scope.</p></div>
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

function inferTargetKind(value: string): string {
  if (/^https?:\/\//i.test(value)) return "URL";
  if (value.includes("/")) return "CIDR";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || (/^[0-9a-fA-F:]+$/.test(value) && value.includes(":"))) return "IP";
  return "DOMAIN";
}
