import { useEffect, useState } from "react";
import { Boxes, Save, Trash2, Wand2 } from "lucide-react";
import { api } from "@/api/client";
import type { SystemTemplate } from "@/types/api";
import type { ServiceRow } from "@/components/services-setup";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

// A reusable microservice-system template (one base host, services at a path
// prefix, one shared token). Expanding it over a pasted list of service names
// produces services-table rows, which the shared-login card then authenticates.
const BLANK: SystemTemplate = {
  name: "",
  base_url: "",
  path_template: "/svc/{name}",
  verify_template: "/svc/{name}/health",
  spec_mode: "auto",
};

export function SystemTemplateSetup({ onRows }: { onRows: (rows: ServiceRow[]) => void }) {
  const [templates, setTemplates] = useState<SystemTemplate[]>([]);
  const [draft, setDraft] = useState<SystemTemplate>(BLANK);
  const [names, setNames] = useState("");
  const [baseOverride, setBaseOverride] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listSystemTemplates().then(setTemplates).catch(() => {});
  }, []);

  function set<K extends keyof SystemTemplate>(key: K, value: SystemTemplate[K]) {
    setDraft((d) => ({ ...d, [key]: value }));
  }

  function selectTemplate(id: string) {
    if (id === "new") { setDraft(BLANK); return; }
    const found = templates.find((t) => t.id === id);
    if (found) setDraft(found);
  }

  async function save() {
    setBusy(true); setError(null); setNote(null);
    try {
      const saved = await api.saveSystemTemplate(draft);
      setDraft(saved);
      setTemplates((prev) => [saved, ...prev.filter((t) => t.id !== saved.id)]);
      setNote(`Saved template “${saved.name}”.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the template");
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!draft.id) return;
    setBusy(true); setError(null); setNote(null);
    try {
      await api.deleteSystemTemplate(draft.id);
      setTemplates((prev) => prev.filter((t) => t.id !== draft.id));
      setDraft(BLANK);
      setNote("Template deleted.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the template");
    } finally {
      setBusy(false);
    }
  }

  async function expand() {
    const serviceNames = names.split(/[\s,]+/).map((n) => n.trim()).filter(Boolean);
    if (serviceNames.length === 0) { setError("Enter at least one service name."); return; }
    setBusy(true); setError(null); setNote(null);
    try {
      const input = draft.id
        ? { template_id: draft.id, service_names: serviceNames, base_override: baseOverride || undefined }
        : { template: draft, service_names: serviceNames, base_override: baseOverride || undefined };
      const result = await api.expandSystem(input);
      const rows: ServiceRow[] = result.services.map((s) => ({
        name: s.name, urls: s.urls.join("; "), image: "", repo: "", protectedPath: s.protected_path ?? "",
      }));
      onRows(rows);
      setNote(`Added ${rows.length} service${rows.length === 1 ? "" : "s"} to the table below. Now paste the shared token in “Access & inputs”.`);
      if (result.errors.length) setError(result.errors.map((e) => e.message).join("; "));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not expand the template");
    } finally {
      setBusy(false);
    }
  }

  const serviceCount = names.split(/[\s,]+/).map((n) => n.trim()).filter(Boolean).length;

  return <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2"><Boxes className="h-4 w-4" /> Microservice system template</CardTitle>
      <p className="text-sm text-muted-foreground">For a system where many services share one host and one login (for example NestJS services at <span className="font-mono">/svc/&lt;name&gt;</span>), save the shape once and expand it over a list of service names. Each service becomes a path-scoped target with a verify path; the shared token is entered once in the next step.</p>
    </CardHeader>
    <CardContent className="space-y-3">
      <div className="space-y-2">
        <Label htmlFor="tpl-select">Saved template</Label>
        <select id="tpl-select" className="w-full rounded-md border bg-background p-2 text-sm" value={draft.id ?? "new"} onChange={(e) => selectTemplate(e.target.value)}>
          <option value="new">New template…</option>
          {templates.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1"><Label htmlFor="tpl-name">Name</Label><Input id="tpl-name" value={draft.name} onChange={(e) => set("name", e.target.value)} placeholder="EMIS NestJS" /></div>
        <div className="space-y-1"><Label htmlFor="tpl-base">Base URL</Label><Input id="tpl-base" value={draft.base_url} onChange={(e) => set("base_url", e.target.value)} placeholder="https://dev-emis.systems.gov.bt" /></div>
        <div className="space-y-1"><Label htmlFor="tpl-path">Path template</Label><Input id="tpl-path" value={draft.path_template} onChange={(e) => set("path_template", e.target.value)} placeholder="/svc/{name}" /></div>
        <div className="space-y-1"><Label htmlFor="tpl-verify">Verify path template</Label><Input id="tpl-verify" value={draft.verify_template ?? ""} onChange={(e) => set("verify_template", e.target.value)} placeholder="/svc/{name}/health" /></div>
      </div>
      {!draft.verify_template && <p className="text-xs text-amber-600 dark:text-amber-500">Without a verify path, services are applied but reported “not verified”, and authenticated OpenAPI discovery will not run for them.</p>}

      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => void save()} disabled={busy || !draft.name || !draft.base_url}><Save className="h-4 w-4" /> {draft.id ? "Update" : "Save"} template</Button>
        {draft.id && <Button type="button" variant="outline" size="sm" onClick={() => void remove()} disabled={busy}><Trash2 className="h-4 w-4" /> Delete</Button>}
      </div>

      <div className="space-y-2 rounded-lg border p-3">
        <Label htmlFor="tpl-names">Service names</Label>
        <Textarea id="tpl-names" value={names} onChange={(e) => setNames(e.target.value)} rows={3} placeholder={"common\nacademic\nstudent"} />
        <p className="text-xs text-muted-foreground">One name per line (or comma-separated). Each expands to <span className="font-mono">{draft.base_url || "<base>"}{(draft.path_template || "/svc/{name}").replace("{name}", "<name>")}</span>.</p>
        <div className="space-y-1"><Label htmlFor="tpl-override">Base override (optional)</Label><Input id="tpl-override" value={baseOverride} onChange={(e) => setBaseOverride(e.target.value)} placeholder="https://staging.example (leave blank to use the template base)" /></div>
        <Button type="button" size="sm" onClick={() => void expand()} disabled={busy || serviceCount === 0}><Wand2 className="h-4 w-4" /> {busy ? "Expanding…" : `Expand ${serviceCount || ""} service${serviceCount === 1 ? "" : "s"}`.trim()}</Button>
      </div>

      {note && <p className="text-sm text-emerald-600 dark:text-emerald-500">{note}</p>}
      {error && <p className="text-sm text-destructive">{error}</p>}
    </CardContent>
  </Card>;
}
