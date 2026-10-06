import { useState } from "react";
import { api } from "@/api/client";
import type { AssessmentConfig } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type Approvals = NonNullable<AssessmentConfig["fuzz_approvals"]>;
export function FormFuzzSetup({ targetId, definitionAvailable, testEnvironment, onTestEnvironment, value, onChange }: {
  targetId: string; definitionAvailable: boolean; testEnvironment: boolean;
  onTestEnvironment: (value: boolean) => void; value: Approvals; onChange: (value: Approvals) => void;
}) {
  const [operation, setOperation] = useState("");
  const [path, setPath] = useState("");
  const [body, setBody] = useState("");
  const [cleanup, setCleanup] = useState("");
  const [limit, setLimit] = useState(20);
  const [consent, setConsent] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const safePath = (value: string) => value.startsWith("/") && !/[?#{}\\\r\n\x00]/.test(value) && !value.split("/").some(part => part === "." || part === "..");
  const exactForm = (value: string) => {
    const names = new Set<string>();
    return value.split("&").every(pair => { const parts = pair.split("="); if (parts.length !== 2 || !/^[a-z\d._~-]+$/i.test(parts[0]) || !/^[a-z\d._~-]*$/i.test(parts[1]) || names.has(parts[0])) return false; names.add(parts[0]); return true; });
  };
  async function save() {
    setError(null);
    if (!definitionAvailable || !testEnvironment || !consent || !operation.trim() || !safePath(path.trim()) || !safePath(cleanup.trim()) || !Number.isInteger(limit) || limit < 1 || limit > 1000 || !exactForm(body) || new TextEncoder().encode(body).length > 65536 || !new URLSearchParams(body).size) {
      setError("Upload a matching API definition, declare a test environment, provide an operation ID, exact operation and cleanup paths, a URL-encoded fixture, and explicit consent for 1–1000 POST requests.");
      return;
    }
    setSaving(true);
    try {
      const fixture = await api.uploadAPIFixture(body, "application/x-www-form-urlencoded");
      const approval: Approvals[number] = { target_id: targetId, method: "POST", path: path.trim(), operation_id: operation.trim(), fixture_ref: fixture.ref, content_type: "application/x-www-form-urlencoded", cleanup_method: "DELETE", cleanup_path: cleanup.trim(), scanner: "wapiti", request_limit: limit, repeat_testing_approved: true };
      onChange([...value.filter(item => !(item.target_id === targetId && item.path === approval.path)), approval]);
      setBody(""); setConsent(false);
    } catch (error) { setError(error instanceof Error ? error.message : String(error)); }
    finally { setSaving(false); }
  }
  return <Card><CardHeader><CardTitle>Approved form testing</CardTitle><p className="text-xs text-muted-foreground">Requires the expanded workflow. Wapiti uses a supplied URL-encoded POST fixture and the default target identity. This Wapiti version requires unique fields with plain letters, digits, dots, underscores, tildes or hyphens. Repeated or encoded values, JSON, multipart and other methods need a capable API adapter.</p></CardHeader><CardContent className="space-y-3">
    <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={testEnvironment} onChange={event => { onTestEnvironment(event.target.checked); if (!event.target.checked) { onChange([]); setConsent(false); } }} />This is an authorized test environment</label>
    <p className="text-xs text-muted-foreground">Operation paths are relative to the target base. Use controlled test resources with known cleanup paths. Definition matching, scope and exclusions are checked again before execution.</p>
    <div className="grid gap-3 sm:grid-cols-2">
      <div className="space-y-1"><Label htmlFor="fuzz-operation">Form operation ID</Label><Input id="fuzz-operation" value={operation} onChange={event => setOperation(event.target.value)} /></div>
      <div className="space-y-1"><Label htmlFor="fuzz-path">POST operation path</Label><Input id="fuzz-path" value={path} onChange={event => setPath(event.target.value)} placeholder="/test-items" /></div>
      <div className="space-y-1"><Label htmlFor="fuzz-cleanup">DELETE cleanup path</Label><Input id="fuzz-cleanup" value={cleanup} onChange={event => setCleanup(event.target.value)} placeholder="/test-items/controlled-fixture" /></div>
      <div className="space-y-1"><Label htmlFor="fuzz-limit">Maximum POST requests</Label><Input id="fuzz-limit" type="number" min={1} max={1000} value={limit} onChange={event => setLimit(Number(event.target.value))} /></div>
    </div>
    <div className="space-y-1"><Label htmlFor="fuzz-body">URL-encoded test fixture</Label><textarea id="fuzz-body" value={body} onChange={event => setBody(event.target.value)} className="min-h-20 w-full rounded-md border bg-background p-2 font-mono text-sm" placeholder="name=controlled-fixture" /></div>
    <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} />I approve up to {limit} POST requests with scanner payloads and the declared DELETE cleanup.</label>
    <Button type="button" disabled={saving} onClick={() => void save()}>{saving ? "Saving…" : "Save bounded POST approval"}</Button>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {value.map(item => <div key={`${item.target_id}:${item.path}`} className="rounded-md border p-2 text-xs"><p>{item.target_id} · POST {item.path} · {item.request_limit} requests · DELETE {item.cleanup_path}</p><p className="mt-1 text-muted-foreground">Journaled consent cannot be replayed after a restart.</p><Button type="button" variant="outline" size="sm" className="mt-2" onClick={() => onChange(value.filter(value => value !== item))}>Remove POST approval</Button></div>)}
  </CardContent></Card>;
}
