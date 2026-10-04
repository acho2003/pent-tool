import { useMemo, useState, type ChangeEvent, type FormEvent } from "react";
import { Box, ChevronLeft, Check, CircleDot, Cloud, Code2, FileCode2, FileText, Globe2, Network, Package, Play, Save, Server, ShieldCheck, Upload, type LucideIcon } from "lucide-react";
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

const MODE_STEPS = ["Mode & target", "Coverage", "Access & inputs", "Review & start"] as const;

// Scanner groups (mirrors the backend registry Group field) for the New
// Assessment catalog. Order is the display order; the fallback label handles any
// future group the backend adds before this map is updated.
const TYPE_LABELS: Record<AssessmentType, string> = {
  NETWORK: "Network services", WEB_APPLICATION: "Web application", API: "API",
  SOURCE_CODE: "Source code", DEPENDENCIES: "Dependencies", CONTAINER: "Container image",
  HOST: "Host configuration", CLOUD: "Cloud account", KUBERNETES: "Kubernetes", INFRASTRUCTURE_AS_CODE: "Infrastructure as code", COMPLIANCE: "Compliance",
};

const TYPE_ICONS: Record<AssessmentType, LucideIcon> = {
  NETWORK: Network, WEB_APPLICATION: Globe2, API: Code2,
  SOURCE_CODE: FileCode2, DEPENDENCIES: Package, CONTAINER: Box,
  HOST: Server, CLOUD: Cloud, KUBERNETES: CircleDot,
  INFRASTRUCTURE_AS_CODE: FileText, COMPLIANCE: ShieldCheck,
};

type SavedAccess = {
  targetId: string;
  kind: "APPLICATION_HEADERS" | "FORM_LOGIN";
  credentialId: string;
  name: string;
  verifyURL: string;
  verifyMarker: string;
};

export default function NewScanPage() {
  const nav = useNavigate();
  const start = useStartScan();
  const [targetsText, setTargetsText] = useState("");
  const [name, setName] = useState("");
  const [mode, setMode] = useState("single");
  const [artifactKind, setArtifactKind] = useState("none");
  const [artifactRef, setArtifactRef] = useState("");
  // Read-only token for private repositories, saved to the encrypted vault and
  // bound to every repository artifact target.
  const [repoToken, setRepoToken] = useState("");
  const [repoCredentialId, setRepoCredentialId] = useState("");
  const [repoCredentialError, setRepoCredentialError] = useState<string | null>(null);
  const [savingRepoToken, setSavingRepoToken] = useState(false);
  const [vulsHost, setVulsHost] = useState("");
  const [companyName, setCompanyName] = useState("");
  const [logoPath, setLogoPath] = useState("");
  const [severities, setSeverities] = useState<string[]>([]);
  const [assessmentMode, setAssessmentMode] = useState<AssessmentMode>("BLACK_BOX");
  const [step, setStep] = useState(0);
  const [profile, setProfile] = useState<"web-gentle" | "web-thorough">("web-gentle");
  const [assessmentTypes, setAssessmentTypes] = useState<AssessmentType[]>(["WEB_APPLICATION"]);
  const [optionalAssessmentScanners, setOptionalAssessmentScanners] = useState<string[]>([]);
  const [subdomainDiscovery, setSubdomainDiscovery] = useState(false);
  const [amassEnrichment, setAmassEnrichment] = useState(false);
  const [historicalProvider, setHistoricalProvider] = useState<"none" | "gau" | "waybackurls">("none");
  const [tlsProvider, setTlsProvider] = useState<"default" | "testssl" | "sslyze">("default");
  const [assessmentPlan, setAssessmentPlan] = useState<AssessmentPlan | null>(null);
  const [planError, setPlanError] = useState<string | null>(null);
  const [planning, setPlanning] = useState(false);
  const [apiDefinitionId, setAPIDefinitionId] = useState("");
  const [apiDefinitionInfo, setAPIDefinitionInfo] = useState("");
  const [apiTargetId, setAPITargetId] = useState("");
  const [uploadingDefinition, setUploadingDefinition] = useState(false);
  // One saved, target-bound credential per target (e.g. a frontend and its API).
  const [savedAccess, setSavedAccess] = useState<SavedAccess[]>([]);
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
  // "json" = the page script POSTs a JSON body to an API route (React/Next/Vue sign-in).
  const [loginSubmitFormat, setLoginSubmitFormat] = useState<"form" | "json">("form");
  const [loginSubmitURL, setLoginSubmitURL] = useState("");
  const [savingCredential, setSavingCredential] = useState(false);
  // Kept apart from planError so Preview can't overwrite why a save failed.
  const [credentialError, setCredentialError] = useState<string | null>(null);
  const health = useQuery({ queryKey: ["scanner-status"], queryFn: api.scannerStatus, refetchInterval: 30000 });
  const registryQuery = useQuery({ queryKey: ["assessment-scanner-registry"], queryFn: api.scannerRegistry, refetchInterval: 30000 });
  const registry: AssessmentScannerDefinition[] = registryQuery.data?.scanners ?? [];
  const tools: ToolInfo[] = health.data?.scanners ?? [];
  const selectable = useMemo(() => tools.filter((t) => t.selectable), [tools]);
  const [uploadingLogo, setUploadingLogo] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const targets = useMemo(() => targetsText.split(/[\n,]/).map((v) => v.trim()).filter(Boolean), [targetsText]);
  const optionalDefinitions = registry.filter((definition) => ["optional", "explicit_opt_in"].includes(definition.default_selection) && definition.assessment_types.some((type) => assessmentTypes.includes(type)) && definition.target_types.some((kind) => [...targets.map(inferTargetKind), ...(artifactKind !== "none" && artifactRef ? [artifactTargetKind(artifactKind)] : [])].includes(kind)));
  const webTargets = useMemo(() => targets.map((value, index) => ({ value, id: `target-${index + 1}` })).filter((target) => inferTargetKind(target.value) === "URL"), [targets]);

  const coverageOptions = useMemo(() => {
    const kinds = targets.map(inferTargetKind);
    const options = new Set<AssessmentType>();
    if (kinds.some((kind) => ["URL", "DOMAIN", "HOST"].includes(kind))) {
      options.add("WEB_APPLICATION"); options.add("API");
    }
    if (kinds.some((kind) => ["IP", "CIDR", "HOST", "DOMAIN", "URL"].includes(kind))) options.add("NETWORK");
    if (kinds.includes("DOMAIN")) options.add("HOST");
    if (assessmentMode === "WHITE_BOX" && artifactKind !== "none" && artifactRef.trim()) {
      const resourceKind = artifactTargetKind(artifactKind);
      for (const definition of registry) if (definition.target_types.includes(resourceKind)) definition.assessment_types.forEach((type) => options.add(type));
      if (artifactKind === "filesystem" || artifactKind === "repository") options.add("SOURCE_CODE");
      if (artifactKind === "repository" || artifactKind === "sbom") options.add("DEPENDENCIES");
      if (artifactKind === "image") { options.add("CONTAINER"); options.add("DEPENDENCIES"); }
      if (artifactKind === "filesystem" || artifactKind === "repository") options.add("INFRASTRUCTURE_AS_CODE");
    }
    const rank: AssessmentType[] = ["WEB_APPLICATION", "API", "NETWORK", "HOST", "SOURCE_CODE", "DEPENDENCIES", "CONTAINER", "INFRASTRUCTURE_AS_CODE", "COMPLIANCE", "CLOUD", "KUBERNETES"];
    return rank.filter((type) => options.has(type));
  }, [targets, assessmentMode, artifactKind, artifactRef, registry]);

  const artifactRefs = useMemo(() => {
    const raw = artifactRef.trim();
    if (!raw) return [];
    // Repository URLs never contain spaces; local paths might, so they split on commas/new lines only.
    const separator = artifactKind === "repository" ? /[\s,]+/ : artifactKind === "filesystem" ? /[\n,]+/ : null;
    return separator ? [...new Set(raw.split(separator).map((ref) => ref.trim()).filter(Boolean))] : [raw];
  }, [artifactKind, artifactRef]);

  const assessmentTargets = useMemo(() => [
    ...targets.map((value, i) => ({ id: `target-${i + 1}`, type: inferTargetKind(value), value })),
    ...(assessmentMode === "WHITE_BOX" && artifactKind !== "none"
      ? artifactRefs.map((ref, i) => ({ id: `artifact-${i + 1}`, type: artifactTargetKind(artifactKind), value: ref }))
      : []),
  ], [targets, assessmentMode, artifactKind, artifactRefs]);

  function onAssessmentModeChange(next: AssessmentMode) {
    setAssessmentMode(next);
    setAssessmentPlan(null);
    setOptionalAssessmentScanners([]);
    if (next !== "WHITE_BOX") { setArtifactKind("none"); setArtifactRef(""); setRepoToken(""); setRepoCredentialId(""); setRepoCredentialError(null); }
    if (next === "BLACK_BOX") { setAPIDefinitionId(""); setAPIDefinitionInfo(""); setAPITargetId(""); }
    if (next === "BLACK_BOX") {
      setSavedAccess([]); setCredentialError(null); setHeaderValue(""); setLoginPassword("");
      setVulsHost("");
    }
    setAssessmentTypes((current) => current.filter((type) => next === "WHITE_BOX" || !["SOURCE_CODE", "DEPENDENCIES", "CONTAINER", "INFRASTRUCTURE_AS_CODE", "CLOUD", "KUBERNETES", "COMPLIANCE"].includes(type)));
  }

  function onTargetsChange(value: string) {
    setTargetsText(value);
    setAssessmentPlan(null);
    setSavedAccess([]); setCredentialError(null); setCredentialTargetId("target-1");
    setAPIDefinitionId(""); setAPIDefinitionInfo(""); setAPITargetId("");
  }

  function toggleAssessmentType(type: AssessmentType) {
    setAssessmentTypes((prev) => prev.includes(type) ? prev.filter((item) => item !== type) : [...prev, type]);
    setAssessmentPlan(null);
  }

  function toggleSeverity(severity: string) {
    setSeverities((current) => current.includes(severity) ? current.filter((item) => item !== severity) : [...current, severity]);
  }

  function targetLabel(targetId: string): string {
    return targets[Number(targetId.replace("target-", "")) - 1] ?? targetId;
  }

  function updateSavedAccess(targetId: string, patch: Partial<SavedAccess>) {
    setSavedAccess((current) => current.map((access) => access.targetId === targetId ? { ...access, ...patch } : access));
    setAssessmentPlan(null);
  }

  function removeSavedAccess(targetId: string) {
    setSavedAccess((current) => current.filter((access) => access.targetId !== targetId));
    setCredentialTargetId(targetId);
    setAssessmentPlan(null);
  }

  function authenticationSetupError(): string | null {
    if (repoToken.trim() && !repoCredentialId) {
      return "Save the repository access token before previewing the assessment.";
    }
    if (credentialError && !savedAccess.some((access) => access.targetId === credentialTargetId)) {
      return `Credential was not saved: ${credentialError}`;
    }
    if (loginPassword || headerValue) {
      return "Save the credential you entered (Save encrypted credential) before previewing an authenticated assessment.";
    }
    if (credentialKind === "FORM_LOGIN" && !savedAccess.length) {
      return "Save the form-login credential before previewing an authenticated assessment.";
    }
    const unverified = savedAccess.find((access) => !access.verifyURL.trim() || !access.verifyMarker.trim());
    if (unverified) {
      return `Add a protected verification URL and a response marker that appears only after login for ${targetLabel(unverified.targetId)}.`;
    }
    return null;
  }

  async function previewAssessmentPlan() {
    setPlanError(null);
    setAssessmentPlan(null);
    if (!assessmentTargets.length || !assessmentTypes.length) {
      setPlanError("Add a target or supported artifact and select a coverage type.");
      return;
    }
	const authError = authenticationSetupError();
	if (authError) {
	  setPlanError(authError);
	  return;
	}
    const repoTargetIds = assessmentTargets.filter((target) => target.id.startsWith("artifact-")).map((target) => target.id);
    const planAccess = [
      ...savedAccess.map((access) => ({ target_ids: [access.targetId], kind: access.kind, credential_id: access.credentialId, verify_url: access.verifyURL.trim(), verify_marker: access.verifyMarker })),
      ...(repoCredentialId && artifactKind === "repository" && repoTargetIds.length ? [{ target_ids: repoTargetIds, kind: "REPOSITORY_CREDENTIALS", credential_id: repoCredentialId }] : []),
    ];
    setPlanning(true);
    try {
      const plan = await api.planAssessment({
        assessment_mode: assessmentMode,
        assessment_types: assessmentTypes.filter((type) => coverageOptions.includes(type)),
        assessment_targets: assessmentTargets,
        profile,
        subdomain_discovery: subdomainDiscovery,
        discovery_providers: subdomainDiscovery || historicalProvider !== "none" || tlsProvider !== "default" ? {
          ...(subdomainDiscovery ? { subdomain: amassEnrichment ? ["subfinder", "amass"] : ["subfinder"] } : {}),
          ...(historicalProvider !== "none" ? { historical: historicalProvider } : {}),
          ...(tlsProvider !== "default" ? { tls: tlsProvider } : {}),
        } : undefined,
        access: planAccess.length ? planAccess : undefined,
        api_definitions: apiDefinitionId ? [{ target_id: apiTargetId || "target-1", definition_id: apiDefinitionId }] : undefined,
        scanner_selection: optionalAssessmentScanners.length > 0
          ? { mode: "custom", variants: [...new Set([...selectable.map((tool) => tool.name), ...optionalAssessmentScanners])] }
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
    setCredentialError(null);
    if (!targets.length || (credentialKind === "APPLICATION_HEADERS" && (!headerName.trim() || !headerValue)) || (credentialKind === "FORM_LOGIN" && (!loginURL.trim() || !loginUsername || !loginPassword))) {
      setCredentialError(credentialKind === "FORM_LOGIN" ? "Add a target, login URL, username, and password before saving the credential." : "Add a target, header name, and header value before saving the credential.");
      return;
    }
    const credentialTargetIndex = Number(credentialTargetId.replace("target-", "")) - 1;
    if (!/^https?:\/\//i.test(targets[credentialTargetIndex] ?? "")) {
      setCredentialError("Application credentials must be bound to an explicit HTTP(S) URL target.");
      return;
    }
    setSavingCredential(true);
    try {
      const credential = await api.createCredential({
        name: credentialName.trim() || "Web scan credential",
        kind: credentialKind,
        target_ids: [credentialTargetId],
        values: credentialKind === "FORM_LOGIN"
          ? { login_url: loginURL.trim(), username: loginUsername, password: loginPassword, username_field: loginUsernameField.trim() || "username", password_field: loginPasswordField.trim() || "password", ...(loginSubmitFormat === "json" ? { submit_format: "json" } : {}), ...(loginSubmitURL.trim() ? { submit_url: loginSubmitURL.trim() } : {}), ...(loginSubmitFormat === "form" && loginCSRFField.trim() ? { csrf_field: loginCSRFField.trim() } : {}) }
          : { [headerName.trim()]: headerValue },
      });
      const saved: SavedAccess = { targetId: credentialTargetId, kind: credentialKind, credentialId: credential.id, name: credential.name, verifyURL: "", verifyMarker: "" };
      const nextAccess = [...savedAccess.filter((access) => access.targetId !== credentialTargetId), saved];
      setSavedAccess(nextAccess);
      const nextIndex = targets.findIndex((_, i) => !nextAccess.some((access) => access.targetId === `target-${i + 1}`));
      if (nextIndex >= 0) setCredentialTargetId(`target-${nextIndex + 1}`);
      setHeaderValue("");
      setLoginPassword("");
      setAssessmentPlan(null);
    } catch (err) {
      setCredentialError(err instanceof Error ? err.message : "Could not save credential");
    } finally {
      setSavingCredential(false);
    }
  }

  async function saveRepoToken() {
    setRepoCredentialError(null);
    const repoTargetIds = assessmentTargets.filter((target) => target.id.startsWith("artifact-")).map((target) => target.id);
    if (artifactKind !== "repository" || !repoTargetIds.length || !repoToken.trim()) {
      setRepoCredentialError("Add the repository URL(s) and a token before saving.");
      return;
    }
    setSavingRepoToken(true);
    try {
      const credential = await api.createCredential({ name: "Repository access token", kind: "REPOSITORY_CREDENTIALS", target_ids: repoTargetIds, values: { token: repoToken.trim() } });
      setRepoCredentialId(credential.id);
      setRepoToken("");
      setAssessmentPlan(null);
    } catch (err) {
      setRepoCredentialError(err instanceof Error ? err.message : "Could not save repository token");
    } finally {
      setSavingRepoToken(false);
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
      setAPITargetId(webTargets[0]?.id || "target-1");
    } catch (err) {
      setPlanError(err instanceof Error ? err.message : "API definition upload failed");
    } finally {
      setUploadingDefinition(false);
    }
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
	const authError = authenticationSetupError();
	if (authError) {
	  setError(authError);
	  return;
	}
    if (!assessmentPlan) {
      setError("Preview the assessment plan after your last configuration change before saving or starting.");
      return;
    }
	if (savedAccess.some((access) => !assessmentPlan.config.access?.some((binding) => binding.credential_id === access.credentialId && binding.target_ids.includes(access.targetId)))) {
	  setError("The previewed plan does not include this login credential. Preview the plan again before starting.");
	  return;
	}
    if (!targets.length && (artifactKind === "none" || !artifactRef.trim())) {
      setError("Add at least one target or a source artifact.");
      return;
    }
    try {
      const res = await start.mutateAsync({
        targets: assessmentPlan.config.assessment_targets.map((target) => target.value),
        assessment: assessmentPlan.config,
        plan_fingerprint: assessmentPlan.fingerprint,
        profile,
        name: name.trim() || undefined,
        scan_mode: mode,
        artifact: artifactKind !== "none" && artifactRefs.length ? { kind: artifactKind, ref: artifactRefs[0] } : undefined,
        vuls_ssh_host: vulsHost.trim() || undefined,
        company_name: companyName.trim() || undefined,
        logo_path: logoPath.trim() || undefined,
        severity_filter: severities.length ? severities : undefined,
        scanners: undefined,
        save_only: saveOnly || undefined,
      });
      const id = (res as { instance_id?: string; id?: string }).instance_id || (res as { id?: string }).id;
      nav(id ? `/scans/${id}` : "/scans");
    } catch (e) { setError(e instanceof Error ? e.message : "Failed to submit scan"); }
  }

  function onSubmit(e: FormEvent) { e.preventDefault(); void submit(false); }
  const modeText: Record<AssessmentMode, string> = {
    BLACK_BOX: "External testing with no application credentials or internal source inputs.",
    GRAY_BOX: "External testing with target bound access, API definitions, or supported host access.",
    WHITE_BOX: "Testing with internal source, dependency, container, and supported infrastructure inputs.",
  };
  const selectedTypes = assessmentTypes.filter((type) => coverageOptions.includes(type));
  function nextStep() {
    if (step === 0 && !assessmentTargets.length) { setError("Add an in-scope URL, host, or supported artifact first."); return; }
    setError(null);
    setAssessmentTypes((current) => current.filter((type) => coverageOptions.includes(type)));
    setStep((current) => Math.min(current + 1, MODE_STEPS.length - 1));
  }
  const previewJobs = assessmentPlan?.jobs ?? [];
  const workflowGroups = [
    { title: "Discovery and preparation", jobs: [] as typeof previewJobs },
    { title: "Security testing", jobs: [] as typeof previewJobs },
    { title: "Results", jobs: [] as typeof previewJobs },
  ];
  previewJobs.forEach((job) => {
    const definition = registry.find((item) => item.id === job.scanner);
    if (["recon"].includes(definition?.category ?? "")) workflowGroups[0].jobs.push(job);
    else workflowGroups[1].jobs.push(job);
  });
  return <div className="mx-auto max-w-4xl space-y-6">
    <header><Button variant="ghost" size="sm" onClick={() => nav(-1)}><ChevronLeft className="h-4 w-4" /> Back</Button><p className="mt-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Assessment setup</p><h1 className="mt-1 text-3xl font-semibold tracking-tight">New assessment</h1><p className="mt-2 text-sm text-muted-foreground">Choose a testing mode. Xalgorix will show the inputs and tools that apply to your scope.</p></header>
    <nav aria-label="Assessment setup steps" className="grid grid-cols-2 gap-2 sm:grid-cols-4">{MODE_STEPS.map((title, index) => <button type="button" key={title} onClick={() => { setError(null); setStep(index); }} aria-current={step === index ? "step" : undefined} className={`rounded-lg border p-3 text-left transition-colors ${step === index ? "border-primary/60 bg-primary/5" : "bg-card/50 hover:bg-muted/20"}`}><p className="flex items-center gap-2 text-sm font-medium">{index < step ? <Check className="h-4 w-4 text-emerald-400" /> : <span className="font-mono text-xs text-muted-foreground">0{index + 1}</span>}{title}</p></button>)}</nav>

    <form onSubmit={onSubmit} className="space-y-5">
      {step === 0 && <>
        <Card><CardHeader><CardTitle>Choose an assessment mode</CardTitle></CardHeader><CardContent className="grid gap-3 md:grid-cols-3">{(["BLACK_BOX", "GRAY_BOX", "WHITE_BOX"] as AssessmentMode[]).map((value) => <button type="button" key={value} onClick={() => onAssessmentModeChange(value)} aria-pressed={assessmentMode === value} className={`rounded-lg border p-4 text-left transition-colors ${assessmentMode === value ? "border-primary bg-primary/5" : "hover:bg-muted/20"}`}><span className="text-sm font-semibold">{value.replace("_", " ")}</span><span className="mt-2 block text-xs leading-relaxed text-muted-foreground">{modeText[value]}</span></button>)}</CardContent></Card>
        <Card><CardHeader><CardTitle>Target and scope</CardTitle></CardHeader><CardContent className="space-y-4"><div className="space-y-2"><Label htmlFor="name">Assessment name</Label><Input id="name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Quarterly external assessment" /></div><div className="space-y-2"><Label htmlFor="targets">URLs or hosts</Label><Textarea id="targets" value={targetsText} onChange={(e) => onTargetsChange(e.target.value)} placeholder={"https://example.com\napi.example.com"} rows={4} /><p className="text-xs text-muted-foreground">One approved target per line. Wildcard discovery requires explicit authorization in the next step.</p></div>{assessmentMode === "WHITE_BOX" && <div className="grid gap-4 rounded-lg border p-3 sm:grid-cols-2"><div className="space-y-2"><Label>Internal resource type</Label><Select value={artifactKind} onValueChange={(value) => { setArtifactKind(value); setRepoCredentialId(""); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="none">No internal resource</SelectItem><SelectItem value="filesystem">Local source directory</SelectItem><SelectItem value="repository">Repository</SelectItem><SelectItem value="image">Container image</SelectItem><SelectItem value="sbom">SBOM file</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label htmlFor="artifact">Resource reference</Label><Input id="artifact" value={artifactRef} onChange={(e) => { setArtifactRef(e.target.value); setRepoCredentialId(""); setAssessmentPlan(null); }} placeholder={artifactKind === "repository" ? "https://github.com/org/api.git, https://github.com/org/web.git" : "/src/project, image@sha256:…, or /src/bom.json"} />{(artifactKind === "repository" || artifactKind === "filesystem") && <p className="text-xs text-muted-foreground">Separate multiple {artifactKind === "repository" ? "repositories" : "directories"} with commas{artifactKind === "repository" ? ", spaces," : ""} or new lines; each is scanned as its own target.{artifactRefs.length > 1 ? ` ${artifactRefs.length} detected.` : ""}</p>}</div>{artifactKind === "repository" && <div className="space-y-2 sm:col-span-2"><Label htmlFor="repo-token">Access token for private repositories (optional)</Label>{repoCredentialId ? <p className="rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3 text-sm text-emerald-300">Token saved (encrypted) and bound to {artifactRefs.length === 1 ? "the repository" : `all ${artifactRefs.length} repositories`}. <span className="break-all font-mono text-xs">{repoCredentialId}</span></p> : <div className="flex flex-wrap gap-2"><Input id="repo-token" className="min-w-0 flex-1" type="password" autoComplete="new-password" value={repoToken} onChange={(e) => setRepoToken(e.target.value)} placeholder="Read-only token, e.g. a GitHub fine-grained token with Contents: read" /><Button type="button" variant="outline" onClick={() => void saveRepoToken()} disabled={savingRepoToken || !repoToken.trim() || !artifactRefs.length}>{savingRepoToken ? "Encrypting…" : "Save token"}</Button></div>}{repoCredentialError && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{repoCredentialError}</p>}<p className="text-xs text-muted-foreground">Used only to clone; passed to git as a header, never stored in the checkout, logs, or reports.</p></div>}</div>}<div className="grid gap-4 sm:grid-cols-2"><div className="space-y-2"><Label>Scope mode</Label><Select value={mode} onValueChange={(value) => setMode(value)}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="single">Supplied targets only</SelectItem><SelectItem value="wildcard">Authorized wildcard discovery</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label>Web profile</Label><Select value={profile} onValueChange={(value) => { setProfile(value as typeof profile); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="web-gentle">Gentle · production</SelectItem><SelectItem value="web-thorough">Thorough · lab or staging</SelectItem></SelectContent></Select><p className="text-xs text-muted-foreground">Thorough profile allows higher request rates and larger endpoint budgets.</p></div></div></CardContent></Card>
      </>}

      {step === 1 && <Card><CardHeader><CardTitle>Choose coverage</CardTitle><p className="text-sm text-muted-foreground">Options reflect your mode and target. The planner will confirm which scanners can provide each type.</p></CardHeader><CardContent className="space-y-4">{coverageOptions.length ? <div className="grid gap-2 sm:grid-cols-2">{coverageOptions.map((type) => { const Icon = TYPE_ICONS[type]; const checked = assessmentTypes.includes(type); return <label key={type} className={`flex cursor-pointer items-start gap-3 rounded-lg border p-3 hover:bg-muted/20 ${checked ? "border-primary/60 bg-primary/5" : ""}`}><input type="checkbox" checked={checked} onChange={() => toggleAssessmentType(type)} className="mt-1" /><Icon className={`mt-0.5 h-4 w-4 shrink-0 ${checked ? "text-primary" : "text-muted-foreground"}`} aria-hidden /><span><span className="text-sm font-medium">{TYPE_LABELS[type]}</span><span className="mt-1 block text-xs text-muted-foreground">{coverageDescription(type)}</span></span></label>; })}</div> : <div className="rounded-md border border-dashed p-5 text-sm text-muted-foreground">No coverage options match yet. Add an applicable target first, or <button type="button" className="underline underline-offset-2 hover:text-foreground" onClick={() => setStep(2)}>configure a White Box resource input</button>, then return here.</div>}
        {coverageOptions.some((type) => ["WEB_APPLICATION", "API"].includes(type)) && <label className="flex items-start gap-3 rounded-lg border p-3"><input type="checkbox" checked={subdomainDiscovery} onChange={(e) => { setSubdomainDiscovery(e.target.checked); setAssessmentPlan(null); }} className="mt-1" /><span className="text-sm">Authorize subdomain discovery<p className="mt-1 text-xs text-muted-foreground">Adds Subfinder for domain targets. Leave off unless you have permission to enumerate subdomains.</p></span></label>}
        {coverageOptions.some((type) => ["WEB_APPLICATION", "API"].includes(type)) && <Card><CardHeader><CardTitle>Optional web discovery and TLS providers</CardTitle></CardHeader><CardContent className="space-y-4"><div className="grid gap-4 sm:grid-cols-2"><div className="space-y-2"><Label>Historical URL provider</Label><Select value={historicalProvider} onValueChange={(value) => { setHistoricalProvider(value as typeof historicalProvider); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="none">Disabled</SelectItem><SelectItem value="gau">gau</SelectItem><SelectItem value="waybackurls">waybackurls</SelectItem></SelectContent></Select><p className="text-xs text-muted-foreground">Queries public archives for URL candidates. Candidates are scoped and revalidated before use.</p></div><div className="space-y-2"><Label>TLS provider</Label><Select value={tlsProvider} onValueChange={(value) => { setTlsProvider(value as typeof tlsProvider); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="default">Default provider</SelectItem><SelectItem value="testssl">testssl.sh</SelectItem><SelectItem value="sslyze">SSLyze</SelectItem></SelectContent></Select><p className="text-xs text-muted-foreground">Select one TLS provider per approved HTTPS service.</p></div></div>{subdomainDiscovery && <label className="flex items-start gap-3 rounded-lg border p-3"><input type="checkbox" checked={amassEnrichment} onChange={(event) => { setAmassEnrichment(event.target.checked); setAssessmentPlan(null); }} className="mt-1" /><span className="text-sm">Add Amass passive enrichment<p className="mt-1 text-xs text-muted-foreground">Runs alongside Subfinder. Results remain candidate evidence and never expand scan scope.</p></span></label>}</CardContent></Card>}
        <details className="rounded-lg border p-3"><summary className="cursor-pointer text-sm font-medium">Customize optional tools <span className="font-normal text-muted-foreground">({optionalDefinitions.length} applicable)</span></summary><p className="mt-2 text-xs text-muted-foreground">Automatic selection includes the required tools. Select an optional tool only when you want that additional test.</p><div className="mt-3 space-y-2">{optionalDefinitions.map((definition) => <label key={definition.id} className={`flex items-start gap-3 rounded-md border p-3 ${definition.available ? "cursor-pointer" : "opacity-60"}`}><input type="checkbox" checked={optionalAssessmentScanners.includes(definition.id)} disabled={!definition.available} onChange={() => { setOptionalAssessmentScanners((current) => current.includes(definition.id) ? current.filter((id) => id !== definition.id) : [...current, definition.id]); setAssessmentPlan(null); }} className="mt-1" /><span><span className="text-sm font-medium">{definition.name} · {definition.risk} risk · {definition.available ? "available" : "unavailable"}</span><span className="mt-1 block text-xs text-muted-foreground">{definition.summary}</span>{definition.default_selection === "explicit_opt_in" && <span className="mt-1 block text-xs text-amber-300">Explicit opt in required. Selecting this tool records that choice in the plan.</span>}{!definition.available && <span className="mt-1 block text-xs text-muted-foreground">Unavailable: required tool or service is not configured.</span>}</span></label>)}{!optionalDefinitions.length && <p className="text-xs text-muted-foreground">No optional tools apply to the selected coverage and target.</p>}</div></details>
      </CardContent></Card>}

      {step === 2 && <div className="space-y-4">
        {(assessmentMode === "GRAY_BOX" || assessmentMode === "WHITE_BOX") && <Card><CardHeader><CardTitle>Target access</CardTitle><p className="text-sm text-muted-foreground">Saving credentials configures access. Xalgorix reports them as verified only after the protected URL and response marker are checked at scan start.</p></CardHeader><CardContent className="space-y-4">{savedAccess.map((access) => <div key={access.targetId} className="space-y-3 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm text-emerald-300">{access.kind === "FORM_LOGIN" ? "Form login" : "HTTP header"} saved and bound to <span className="font-mono">{targetLabel(access.targetId)}</span>. Verification is still pending.</p><Button type="button" size="sm" variant="outline" onClick={() => removeSavedAccess(access.targetId)}>Remove</Button></div><p className="break-all font-mono text-xs text-muted-foreground">Credential reference: {access.credentialId}</p><div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label htmlFor={`auth-verify-url-${access.targetId}`}>Protected verification URL</Label><Input id={`auth-verify-url-${access.targetId}`} value={access.verifyURL} onChange={(e) => updateSavedAccess(access.targetId, { verifyURL: e.target.value })} placeholder={`${targetLabel(access.targetId).replace(/\/+$/, "")}/a-page-that-needs-login`} /></div><div className="space-y-2"><Label htmlFor={`auth-verify-marker-${access.targetId}`}>Expected response marker</Label><Input id={`auth-verify-marker-${access.targetId}`} value={access.verifyMarker} onChange={(e) => updateSavedAccess(access.targetId, { verifyMarker: e.target.value })} placeholder="Text only visible after login" /></div></div></div>)}{savedAccess.length < targets.length && <>{savedAccess.length > 0 && <p className="text-sm font-medium">Add a credential for another target</p>}<div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label>Credential type</Label><Select value={credentialKind} onValueChange={(value) => { setCredentialKind(value as "APPLICATION_HEADERS" | "FORM_LOGIN"); setCredentialError(null); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="APPLICATION_HEADERS">HTTP header or token</SelectItem><SelectItem value="FORM_LOGIN">Form login</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label>Bind to target</Label><Select value={credentialTargetId} onValueChange={(value) => { setCredentialTargetId(value); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{targets.map((target, i) => ({ target, id: `target-${i + 1}` })).filter(({ id }) => !savedAccess.some((access) => access.targetId === id)).map(({ target, id }) => <SelectItem key={id} value={id}>{target}</SelectItem>)}</SelectContent></Select></div></div><div className="space-y-2"><Label htmlFor="credential-name">Credential name</Label><Input id="credential-name" value={credentialName} onChange={(e) => setCredentialName(e.target.value)} /></div>{credentialKind === "APPLICATION_HEADERS" ? <><div className="space-y-2"><Label htmlFor="auth-header-name">Header name</Label><Input id="auth-header-name" value={headerName} onChange={(e) => setHeaderName(e.target.value)} /></div><div className="space-y-2"><Label htmlFor="auth-header-value">Header value</Label><Input id="auth-header-value" type="password" autoComplete="new-password" value={headerValue} onChange={(e) => setHeaderValue(e.target.value)} placeholder="Bearer token or cookie value" /></div></> : <><div className="space-y-2"><Label htmlFor="login-url">Login page URL</Label><Input id="login-url" value={loginURL} onChange={(e) => setLoginURL(e.target.value)} placeholder="https://app.example.test/login" /></div><div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label>Login is submitted as</Label><Select value={loginSubmitFormat} onValueChange={(value) => setLoginSubmitFormat(value as "form" | "json")}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="form">HTML form post</SelectItem><SelectItem value="json">JSON API (page script calls an API)</SelectItem></SelectContent></Select></div><div className="space-y-2"><Label htmlFor="login-submit-url">{loginSubmitFormat === "json" ? "Login API URL" : "Submit URL (optional)"}</Label><Input id="login-submit-url" value={loginSubmitURL} onChange={(e) => setLoginSubmitURL(e.target.value)} placeholder={loginSubmitFormat === "json" ? "https://app.example.test/api/auth/login" : "Defaults to the form action"} /></div></div>{loginSubmitFormat === "json" && <p className="text-xs text-muted-foreground">Use this when the sign-in page logs in with JavaScript (DevTools → Network shows a JSON POST). Xalgorix sends {"{"}username field: username, password field: password{"}"} to the API URL and keeps the session cookie it returns.</p>}<div className="grid gap-3 sm:grid-cols-2"><div className="space-y-2"><Label htmlFor="login-username">Username</Label><Input id="login-username" value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)} autoComplete="username" /></div><div className="space-y-2"><Label htmlFor="login-password">Password</Label><Input id="login-password" type="password" autoComplete="new-password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)} /></div></div><div className={loginSubmitFormat === "json" ? "grid gap-3 sm:grid-cols-2" : "grid gap-3 sm:grid-cols-3"}><div className="space-y-2"><Label htmlFor="username-field">Username field</Label><Input id="username-field" value={loginUsernameField} onChange={(e) => setLoginUsernameField(e.target.value)} /></div><div className="space-y-2"><Label htmlFor="password-field">Password field</Label><Input id="password-field" value={loginPasswordField} onChange={(e) => setLoginPasswordField(e.target.value)} /></div>{loginSubmitFormat === "form" && <div className="space-y-2"><Label htmlFor="csrf-field">CSRF field (optional)</Label><Input id="csrf-field" value={loginCSRFField} onChange={(e) => setLoginCSRFField(e.target.value)} placeholder="csrf" /></div>}</div></>}<Button type="button" variant="outline" onClick={() => void saveCredential()} disabled={savingCredential || (credentialKind === "FORM_LOGIN" ? !loginURL || !loginUsername || !loginPassword : !headerValue)}>{savingCredential ? "Encrypting…" : "Save encrypted credential"}</Button>{credentialError && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{credentialError}</p>}</>}</CardContent></Card>}
        {assessmentMode === "GRAY_BOX" && <Card><CardHeader><CardTitle>Supported host access</CardTitle><p className="text-xs text-muted-foreground">Optional. Uses an operator managed SSH alias where a selected host scanner supports it.</p></CardHeader><CardContent><Label htmlFor="vuls">SSH host alias</Label><Input id="vuls" className="mt-2" value={vulsHost} onChange={(e) => setVulsHost(e.target.value)} placeholder="prod-web" /></CardContent></Card>}
        {(assessmentMode === "GRAY_BOX" || assessmentMode === "WHITE_BOX") && <Card><CardHeader><CardTitle>API definition</CardTitle><p className="text-xs text-muted-foreground">Optional OpenAPI or Swagger file. Its server URLs do not expand assessment scope.</p></CardHeader><CardContent className="space-y-3"><Input id="api-definition" type="file" accept=".json,.yaml,.yml,application/json" onChange={(e) => void uploadAPIDefinition(e)} disabled={uploadingDefinition} />{apiDefinitionId && <><p className="break-all font-mono text-xs text-muted-foreground">{apiDefinitionInfo} · {apiDefinitionId}</p><div className="space-y-2"><Label>Map definition to target</Label><Select value={apiTargetId || "target-1"} onValueChange={(value) => { setAPITargetId(value); setAssessmentPlan(null); }}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent>{targets.map((target, i) => <SelectItem key={i} value={`target-${i + 1}`}>{target}</SelectItem>)}</SelectContent></Select></div></>}</CardContent></Card>}
      </div>}

      {step === 3 && <div className="space-y-4"><Card><CardHeader><CardTitle>Review assessment workflow</CardTitle><p className="text-sm text-muted-foreground">Preview checks the configuration only. It does not contact the target or verify credentials. Some scanner jobs may run in parallel.</p></CardHeader><CardContent className="space-y-4">{planError && <p role="alert" className="text-sm text-destructive">{planError}</p>}<Button type="button" variant="outline" onClick={() => void previewAssessmentPlan()} disabled={planning || !selectedTypes.length}>{planning ? "Building workflow…" : assessmentPlan ? "Refresh workflow preview" : "Preview workflow"}</Button>{assessmentPlan && <div className="space-y-5 border-t pt-4"><p className="font-mono text-xs text-muted-foreground">Plan {assessmentPlan.fingerprint.slice(0, 24)}… · registry {assessmentPlan.registry_version}</p>{assessmentPlan.errors?.map((item) => <p key={item.code} role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{item.message}</p>)}<div className="grid gap-2 sm:grid-cols-2">{assessmentPlan.coverage.map((item) => <div key={item.type} className="rounded-md border p-3"><p className="text-sm font-medium">{TYPE_LABELS[item.type] ?? item.type} · {item.state}</p><p className="mt-1 text-xs text-muted-foreground">{item.reason}</p></div>)}</div>{assessmentPlan.capabilities.filter((item) => item.capability === "authenticated_web" || item.capability === "ssh").map((item, index) => <div key={`${item.target_id}-${item.capability}-${index}`} className="flex items-start gap-2 rounded-md border p-3 text-xs"><span className={`rounded border px-2 py-0.5 ${item.state === "verified" ? "text-emerald-300" : item.state === "available" || item.state === "declared" ? "text-amber-300" : "text-red-300"}`}>{item.state === "verified" ? "verified" : item.state === "available" || item.state === "declared" ? "configured" : "failed"}</span><span><strong>{item.target_id} · {item.capability}</strong><span className="mt-1 block text-muted-foreground">{item.reason}</span></span></div>)}<div className="space-y-3">{workflowGroups.map((group) => <section key={group.title} className="rounded-lg border p-3"><h3 className="text-sm font-semibold">{group.title}</h3>{group.title === "Discovery and preparation" && assessmentTargets.some((target) => ["URL", "DOMAIN", "HOST"].includes(target.type)) && <div className="mt-3 grid gap-2 sm:grid-cols-2"><WorkflowStep title="HTTP reachability" description="Checks which supplied web targets respond." status="pipeline" /><WorkflowStep title="Katana crawl" description="Discovers in-scope pages and API routes for later tests." status="pipeline" /></div>}{group.jobs.length ? <div className="mt-3 space-y-2">{group.jobs.map((job) => { const definition = registry.find((item) => item.id === job.scanner); return <WorkflowStep key={job.id} title={job.scanner} description={`${definition?.summary ?? "Selected scanner"} · ${job.target} · ${(job.assessment_types ?? [job.assessment_type]).map((type) => TYPE_LABELS[type] ?? type).join(", ")}`} status={job.state} />; })}</div> : group.title === "Results" ? <div className="mt-3"><WorkflowStep title="Correlate findings and prepare report" description="The completed scan results are normalized for the assessment report." status="pipeline" /></div> : !assessmentTargets.some((target) => ["URL", "DOMAIN", "HOST"].includes(target.type)) && <p className="mt-2 text-xs text-muted-foreground">No separate web discovery step applies to these resources.</p>}</section>)}</div><details className="rounded-md border p-3"><summary className="cursor-pointer text-sm font-medium">Coverage gaps and scanner decisions ({assessmentPlan.decisions.filter((decision) => !["selected", "conditional"].includes(decision.state)).length})</summary><div className="mt-3 space-y-2">{assessmentPlan.decisions.filter((decision) => !["selected", "conditional"].includes(decision.state)).map((decision, index) => <p key={`${decision.scanner}-${decision.target_id ?? "all"}-${index}`} className="border-l-2 pl-3 text-xs"><span className="font-medium">{decision.scanner} · {decision.target_id ?? "assessment"} · {decision.state}</span><span className="mt-1 block text-muted-foreground">{decision.reason}</span></p>)}</div></details>{assessmentPlan.warnings?.map((warning) => <p key={warning.code} className="text-xs text-amber-300">{warning.message}</p>)}{assessmentPlan.api_endpoints?.length ? <details className="rounded-md border p-3"><summary className="cursor-pointer text-sm font-medium">API operations ({assessmentPlan.api_endpoints.length})</summary><p className="my-2 text-xs text-muted-foreground">Only safe resolved routes are eligible. Mutating operations remain untested with a reason.</p>{assessmentPlan.api_endpoints.map((endpoint, index) => <p key={`${endpoint.method}-${endpoint.path}-${index}`} className="font-mono text-xs">{endpoint.method} {endpoint.path} · {endpoint.eligible ? "eligible" : endpoint.reason || "not eligible"}</p>)}</details> : null}</div>}</CardContent></Card>
        <Card><CardHeader><CardTitle>Report options</CardTitle></CardHeader><CardContent className="space-y-4"><div className="grid gap-4 sm:grid-cols-2"><div className="space-y-2"><Label htmlFor="company">Company name</Label><Input id="company" value={companyName} onChange={(e) => setCompanyName(e.target.value)} /></div><div className="space-y-2"><Label htmlFor="logo">Report logo</Label><div className="flex gap-2"><Input id="logo" value={logoPath} onChange={(e) => setLogoPath(e.target.value)} placeholder="Upload or paste a path" /><Button type="button" variant="outline" size="sm" asChild disabled={uploadingLogo}><label className="cursor-pointer"><Upload className="h-4 w-4" />{uploadingLogo ? "Uploading…" : "Upload"}<input type="file" accept="image/*" className="hidden" onChange={onLogoFile} /></label></Button></div></div></div><fieldset><legend className="text-sm font-medium">Report severity filter</legend><div className="mt-2 flex flex-wrap gap-4">{["critical", "high", "medium", "low", "info"].map((severity) => <label key={severity} className="flex items-center gap-2 text-xs capitalize"><input type="checkbox" checked={severities.includes(severity)} onChange={() => toggleSeverity(severity)} />{severity}</label>)}</div><p className="mt-2 text-xs text-muted-foreground">Leave all unchecked to include every severity.</p></fieldset></CardContent></Card>
      </div>}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <div className="flex items-center justify-between border-t pt-4"><Button type="button" variant="outline" onClick={() => { setError(null); setStep((current) => Math.max(0, current - 1)); }} disabled={step === 0}><ChevronLeft className="h-4 w-4" /> Back</Button>{step < MODE_STEPS.length - 1 ? <Button type="button" onClick={nextStep}>Continue</Button> : <div className="flex gap-2"><Button type="button" variant="outline" onClick={() => void submit(true)} disabled={start.isPending}><Save className="h-4 w-4" /> Save</Button><Button type="submit" disabled={start.isPending || !assessmentPlan || !!assessmentPlan.errors?.some((item) => item.blocking)}><Play className="h-4 w-4" /> Start assessment</Button></div>}</div>
    </form>
  </div>;
}

function inferTargetKind(value: string): string {
  if (/^https?:\/\//i.test(value)) return "URL";
  if (value.includes("/")) return "CIDR";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || (/^[0-9a-fA-F:]+$/.test(value) && value.includes(":"))) return "IP";
  return "DOMAIN";
}

function artifactTargetKind(kind: string): string {
  switch (kind) {
    case "filesystem": return "LOCAL_SOURCE_PATH";
    case "repository": return "REPOSITORY";
    case "image": return "DOCKER_IMAGE";
    case "sbom": return "SBOM";
    default: return "";
  }
}

function coverageDescription(type: AssessmentType): string {
  switch (type) {
    case "WEB_APPLICATION": return "Crawl and test in-scope web pages.";
    case "API": return "Test API routes and optionally seed operations from a schema.";
    case "NETWORK": return "Discover exposed services and check network vulnerabilities.";
    case "HOST": return "Review supported host configuration and packages.";
    case "SOURCE_CODE": return "Inspect source files for code security issues.";
    case "DEPENDENCIES": return "Check dependency manifests or an SBOM for known vulnerabilities.";
    case "CONTAINER": return "Inspect a container image and its packages.";
    case "INFRASTRUCTURE_AS_CODE": return "Check supported infrastructure configuration files.";
    default: return "The planner will report whether a scanner is available for this coverage.";
  }
}

function WorkflowStep({ title, description, status }: { title: string; description: string; status: string }) {
  const pipeline = status === "pipeline";
  const complete = status === "selected" || status === "conditional" || status === "completed";
  return <div className="flex items-start gap-3 rounded-md border bg-background/40 p-3"><span className={`mt-0.5 inline-flex h-6 min-w-6 items-center justify-center rounded-full border px-1 text-[10px] font-medium ${complete ? "border-emerald-500/40 text-emerald-300" : status === "unavailable" || status === "failed" ? "border-red-500/40 text-red-300" : "text-muted-foreground"}`}>{pipeline ? "•" : complete ? "✓" : "·"}</span><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-medium">{title}</p><span className="rounded border px-2 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">{pipeline ? "pipeline stage" : status}</span></div><p className="mt-1 break-words text-xs text-muted-foreground">{description}</p></div></div>;
}
