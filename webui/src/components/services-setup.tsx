import { useRef, useState, type ChangeEvent } from "react";
import { Download, Plus, Trash2, Upload } from "lucide-react";
import { api, type GitHubRepository } from "@/api/client";
import { GitHubOrganization } from "@/components/github-organization";
import type { AssessmentService, AssessmentTarget } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// One microservice: its URL(s) (";"-separated), optional container image,
// optional repository URL or absolute server source path, and an optional
// protected path used to verify the shared login token on this service.
// repoGitHubId/repoBranch are set when the repository was picked from a
// discovered GitHub organization; repo then holds its clone URL.
export type ServiceRow = { name: string; urls: string; image: string; repo: string; protectedPath: string; apiDefinitionId?: string; apiDefinitionInfo?: string; repoGitHubId?: number; repoBranch?: string };

export type ServiceURLTarget = { id: string; value: string; service: string; protectedPath: string };
export type ServiceImageTarget = { id: string; value: string; service: string };

export type ServiceSet = {
  targets: AssessmentTarget[];
  services: AssessmentService[];
  urlTargets: ServiceURLTarget[];
  imageTargets: ServiceImageTarget[];
  apiDefinitions: Array<{ target_id: string; definition_id: string }>;
  // Target IDs of repositories picked from a discovered GitHub organization;
  // the organization's encrypted token is bound to these.
  githubRepoTargetIds: string[];
  ignoredInternal: number;
};

export const emptyServiceRow = (): ServiceRow => ({ name: "", urls: "", image: "", repo: "", protectedPath: "" });

function splitURLs(value: string): string[] {
  return [...new Set(value.split(/[;\s]+/).map((part) => part.trim()).filter(Boolean))];
}

// serviceTargets turns table rows into assessment targets plus the services
// grouping. Images and source are internal resources, so they are only
// included in White Box mode (the count of skipped ones is reported).
export function serviceTargets(rows: ServiceRow[], whiteBox: boolean): ServiceSet {
  const set: ServiceSet = { targets: [], services: [], urlTargets: [], imageTargets: [], apiDefinitions: [], githubRepoTargetIds: [], ignoredInternal: 0 };
  rows.forEach((row, index) => {
    const name = row.name.trim();
    if (!name) return;
    const n = index + 1;
    const ids: string[] = [];
    splitURLs(row.urls).forEach((value, k) => {
      const id = `svc-${n}-url-${k + 1}`;
      set.targets.push({ id, type: "URL", value });
      set.urlTargets.push({ id, value, service: name, protectedPath: row.protectedPath.trim() });
      ids.push(id);
    });
    // An uploaded OpenAPI/GraphQL definition belongs to the service's first URL.
    if (row.apiDefinitionId && ids.length) set.apiDefinitions.push({ target_id: ids[0], definition_id: row.apiDefinitionId });
    const image = row.image.trim();
    const repo = row.repo.trim();
    if (whiteBox && image) {
      const id = `svc-${n}-image`;
      set.targets.push({ id, type: "DOCKER_IMAGE", value: image });
      set.imageTargets.push({ id, value: image, service: name });
      ids.push(id);
    }
    if (whiteBox && repo && row.repoGitHubId) {
      // Same target ID the organization discovery bound its token to.
      const id = `artifact-github-${row.repoGitHubId}`;
      set.targets.push({ id, type: "REPOSITORY", value: repo, branch: row.repoBranch || undefined });
      set.githubRepoTargetIds.push(id);
      ids.push(id);
    } else if (whiteBox && repo) {
      const id = `svc-${n}-repo`;
      set.targets.push({ id, type: repo.startsWith("/") ? "LOCAL_SOURCE_PATH" : "REPOSITORY", value: repo });
      ids.push(id);
    }
    if (!whiteBox) set.ignoredInternal += (image ? 1 : 0) + (repo ? 1 : 0);
    if (ids.length) set.services.push({ id: `svc-${n}`, name, target_ids: ids });
  });
  return set;
}

// protectedPathURL resolves a service's protected path against its URL.
export function protectedPathURL(target: ServiceURLTarget): string | undefined {
  if (!target.protectedPath) return undefined;
  try {
    return new URL(target.protectedPath, target.value).toString();
  } catch {
    return undefined;
  }
}

function csvCell(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function servicesToCSV(rows: ServiceRow[]): string {
  const lines = ["name,url,image,repo,protected_path"];
  for (const row of rows) {
    if (!row.name.trim()) continue;
    lines.push([row.name, splitURLs(row.urls).join(";"), row.image, row.repo, row.protectedPath].map((v) => csvCell(v.trim())).join(","));
  }
  return lines.join("\n") + "\n";
}

export function ServicesSetup({ rows, onChange, whiteBox, allowAPI, repoPool, onRepoPool }: {
  rows: ServiceRow[];
  onChange: (rows: ServiceRow[]) => void;
  whiteBox: boolean;
  allowAPI: boolean;
  repoPool: GitHubRepository[];
  onRepoPool: (repos: GitHubRepository[], credentialId: string) => void;
}) {
  const fileInput = useRef<HTMLInputElement>(null);
  const [uploadingRow, setUploadingRow] = useState<number | null>(null);
  const [importing, setImporting] = useState(false);
  const [importErrors, setImportErrors] = useState<string[]>([]);
  const [importNote, setImportNote] = useState<string | null>(null);
  const set = serviceTargets(rows, whiteBox);

  function update(index: number, patch: Partial<ServiceRow>) {
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }

  async function uploadDefinition(index: number, event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setUploadingRow(index);
    try {
      const result = await api.uploadAPIDefinition(file);
      update(index, { apiDefinitionId: result.id, apiDefinitionInfo: `${file.name}: ${result.operation_count} operation${result.operation_count === 1 ? "" : "s"} (${result.format})` });
    } catch (err) {
      update(index, { apiDefinitionId: undefined, apiDefinitionInfo: err instanceof Error ? `Upload failed: ${err.message}` : "Upload failed" });
    } finally {
      setUploadingRow(null);
    }
  }

  async function onImport(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setImporting(true);
    setImportErrors([]);
    setImportNote(null);
    try {
      const text = await file.text();
      const lower = file.name.toLowerCase();
      const format = lower.endsWith(".csv") ? "csv" : lower.endsWith(".yaml") || lower.endsWith(".yml") ? "yaml" : undefined;
      const result = await api.parseServices(text, format);
      const imported: ServiceRow[] = result.services.map((service) => ({ name: service.name, urls: service.urls.join("; "), image: service.image ?? "", repo: service.repo ?? "", protectedPath: service.protected_path ?? "" }));
      const kept = rows.filter((row) => row.name.trim() || row.urls.trim() || row.image.trim() || row.repo.trim());
      onChange([...kept, ...imported]);
      setImportNote(`Imported ${imported.length} service${imported.length === 1 ? "" : "s"} from ${file.name}.`);
      setImportErrors(result.errors.map((e) => `Row ${e.row}: ${e.message}`));
    } catch (err) {
      setImportErrors([err instanceof Error ? err.message : "Could not import the services file"]);
    } finally {
      setImporting(false);
    }
  }

  function onExport() {
    const blob = new Blob([servicesToCSV(rows)], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "services.csv";
    link.click();
    URL.revokeObjectURL(url);
  }

  return <Card>
    <CardHeader>
      <CardTitle>Services</CardTitle>
      <p className="text-sm text-muted-foreground">For an application made of many services, list each one with its URL(s) and, in White Box mode, its container image and source. Every service is scanned in this one assessment and the report groups results by service. Import a CSV (<span className="font-mono">name,url,image,repo,protected_path</span>; separate several URLs with <span className="font-mono">;</span>) or YAML list.</p>
    </CardHeader>
    <CardContent className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => onChange([...rows, emptyServiceRow()])}><Plus className="h-4 w-4" /> Add service</Button>
        <Button type="button" variant="outline" size="sm" onClick={() => fileInput.current?.click()} disabled={importing}><Upload className="h-4 w-4" /> {importing ? "Importing…" : "Import CSV/YAML"}</Button>
        <Button type="button" variant="outline" size="sm" onClick={onExport} disabled={!set.services.length}><Download className="h-4 w-4" /> Export CSV</Button>
        <input ref={fileInput} type="file" accept=".csv,.yaml,.yml,.txt,text/csv" hidden onChange={(e) => void onImport(e)} />
      </div>
      {importNote && <p role="status" className="text-xs text-emerald-300">{importNote}</p>}
      {importErrors.length > 0 && <div role="alert" className="rounded-md border border-amber-500/40 p-3 text-xs text-amber-200"><p className="font-medium">Some rows were not imported:</p><ul className="mt-1 list-disc pl-4">{importErrors.slice(0, 20).map((e) => <li key={e}>{e}</li>)}</ul></div>}
      {whiteBox && <details className="rounded-lg border p-3" open={repoPool.length > 0}>
        <summary className="cursor-pointer text-sm font-medium">Pick repositories from a GitHub organization {repoPool.length > 0 ? `(${repoPool.length} available)` : ""}</summary>
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <GitHubOrganization onChange={onRepoPool} note="Discover the organization's repositories, then choose one for each service below. Only repositories assigned to a service are scanned; the token is encrypted on the server and used only to clone those repositories." />
        </div>
      </details>}
      {rows.length === 0 && <p className="text-xs text-muted-foreground">No services yet. Single-application scans can leave this empty and use the URL box above.</p>}
      {rows.map((row, index) => <div key={index} className="grid gap-2 rounded-lg border p-3 sm:grid-cols-12">
        <div className="space-y-1 sm:col-span-3"><Label htmlFor={`svc-name-${index}`} className="text-xs">Service name</Label><Input id={`svc-name-${index}`} value={row.name} onChange={(e) => update(index, { name: e.target.value })} placeholder="Auth Service" /></div>
        <div className="space-y-1 sm:col-span-5"><Label htmlFor={`svc-urls-${index}`} className="text-xs">URL(s)</Label><Input id={`svc-urls-${index}`} value={row.urls} onChange={(e) => update(index, { urls: e.target.value })} placeholder="http://10.0.0.5:30862; http://10.0.0.5:30863" /></div>
        <div className="space-y-1 sm:col-span-3"><Label htmlFor={`svc-protected-${index}`} className="text-xs">Protected path (optional)</Label><Input id={`svc-protected-${index}`} value={row.protectedPath} onChange={(e) => update(index, { protectedPath: e.target.value })} placeholder="/api/me" /></div>
        <div className="flex items-end sm:col-span-1"><Button type="button" variant="ghost" size="sm" aria-label={`Remove ${row.name || "service"}`} onClick={() => onChange(rows.filter((_, i) => i !== index))}><Trash2 className="h-4 w-4" /></Button></div>
        <div className="space-y-1 sm:col-span-6"><Label htmlFor={`svc-image-${index}`} className="text-xs">Container image {whiteBox ? "(optional)" : "(White Box only)"}</Label><Input id={`svc-image-${index}`} value={row.image} onChange={(e) => update(index, { image: e.target.value })} placeholder="registry.example/team/auth-service:6" /></div>
        <div className="space-y-1 sm:col-span-6"><Label htmlFor={`svc-repo-${index}`} className="text-xs">Repository or source path {whiteBox ? "(optional)" : "(White Box only)"}</Label>
          {whiteBox && repoPool.length > 0 && <select aria-label={`Repository for ${row.name || "service"}`} className="mb-1 w-full rounded border bg-background p-2 text-sm" value={row.repoGitHubId ? String(row.repoGitHubId) : row.repo ? "manual" : ""} onChange={(e) => {
            const value = e.target.value;
            if (value === "" ) { update(index, { repo: "", repoGitHubId: undefined, repoBranch: undefined }); return; }
            if (value === "manual") { update(index, { repoGitHubId: undefined, repoBranch: undefined }); return; }
            const picked = repoPool.find((repo) => String(repo.id) === value);
            if (picked) update(index, { repo: picked.clone_url, repoGitHubId: picked.id, repoBranch: picked.default_branch });
          }}>
            <option value="">No repository</option>
            {repoPool.map((repo) => <option key={repo.id} value={String(repo.id)} disabled={rows.some((other, i) => i !== index && other.repoGitHubId === repo.id)}>{repo.full_name}{repo.private ? " · private" : ""}{repo.default_branch ? ` · ${repo.default_branch}` : ""}</option>)}
            <option value="manual">Enter a URL or server path…</option>
          </select>}
          {(!row.repoGitHubId) && <Input id={`svc-repo-${index}`} value={row.repo} onChange={(e) => update(index, { repo: e.target.value, repoGitHubId: undefined, repoBranch: undefined })} placeholder="https://git.example/team/auth.git or /src/auth" />}
          {row.repoGitHubId && <p className="break-all font-mono text-xs text-muted-foreground">{row.repo}{row.repoBranch ? ` @ ${row.repoBranch}` : ""}</p>}
        </div>
        {allowAPI && <div className="flex flex-wrap items-center gap-2 sm:col-span-12">
          <label className="cursor-pointer rounded-md border px-2 py-1 text-xs hover:bg-muted/30">{uploadingRow === index ? "Uploading…" : row.apiDefinitionId ? "Replace OpenAPI file" : "Upload OpenAPI / Swagger file (optional)"}<input type="file" accept=".json,.yaml,.yml,.graphql,.gql" hidden disabled={uploadingRow === index} onChange={(e) => void uploadDefinition(index, e)} /></label>
          {row.apiDefinitionInfo && <span className={`text-xs ${row.apiDefinitionId ? "text-emerald-300" : "text-destructive"}`}>{row.apiDefinitionInfo}</span>}
          {row.apiDefinitionId && <button type="button" className="text-xs underline" onClick={() => update(index, { apiDefinitionId: undefined, apiDefinitionInfo: undefined })}>Remove</button>}
        </div>}
      </div>)}
      {set.services.length > 0 && <p className="text-xs text-muted-foreground">{set.services.length} service{set.services.length === 1 ? "" : "s"} · {set.urlTargets.length} URL target{set.urlTargets.length === 1 ? "" : "s"} · {set.imageTargets.length} image{set.imageTargets.length === 1 ? "" : "s"}. The protected path is a page that only works when logged in; it lets the shared login prove access per service.</p>}
      {allowAPI && <p className="text-xs text-muted-foreground">Without an uploaded file, Xalgorix still looks for a published schema on each service (/openapi.json, /swagger.json, /v3/api-docs, /api-docs, and the NestJS /api-json, /docs-json, /api/docs-json). Select API coverage so the endpoints are tested.</p>}
      {set.ignoredInternal > 0 && <p className="text-xs text-amber-200">{set.ignoredInternal} image/source entr{set.ignoredInternal === 1 ? "y is" : "ies are"} ignored outside White Box mode. Choose White Box to scan images and source.</p>}
    </CardContent>
  </Card>;
}
