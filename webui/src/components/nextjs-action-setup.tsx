import { useState } from "react";
import { api } from "@/api/client";
import type { AssessmentConfig, AssessmentTarget } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

type Approvals = NonNullable<AssessmentConfig["nextjs_action_approvals"]>;
type Identity = { identity: string; targetId: string; role: string };

export function NextjsActionSetup({ targets, identities, value, onChange, testEnvironment, onTestEnvironment }: {
  targets: AssessmentTarget[]; identities: Identity[]; value: Approvals; onChange: (value: Approvals) => void;
  testEnvironment: boolean; onTestEnvironment: (value: boolean) => void;
}) {
  const [targetId, setTargetId] = useState("");
  const [id, setID] = useState("");
  const [url, setURL] = useState("");
  const [actionID, setActionID] = useState("");
  const [contentType, setContentType] = useState("text/plain;charset=UTF-8");
  const [body, setBody] = useState("");
  const [verificationURL, setVerificationURL] = useState("");
  const [readyMarker, setReadyMarker] = useState("");
  const [changedMarker, setChangedMarker] = useState("");
  const [cleanupURL, setCleanupURL] = useState("");
  const [cleanupMethod, setCleanupMethod] = useState("DELETE");
  const [cleanupBody, setCleanupBody] = useState("");
  const [cleanupType, setCleanupType] = useState("application/json");
  const [owner, setOwner] = useState("");
  const [denied, setDenied] = useState("anonymous");
  const [crossOrigin, setCrossOrigin] = useState(false);
  const [approved, setApproved] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const urlTargets = targets.filter(target => target.type === "URL");
  const target = urlTargets.find(target => target.id === targetId) ?? urlTargets[0];
  const named = identities.filter(identity => identity.targetId === target?.id && identity.identity);

  async function save() {
    setError(null);
    if (!target || !testEnvironment || !approved || !/^[A-Za-z0-9_-]{1,64}$/.test(id.trim()) || !/^[a-fA-F0-9]{40,64}$/.test(actionID.trim())) {
      setError("Choose a URL target, declare a test environment, approve the finite campaign, and supply a campaign ID and an observed hexadecimal Next-Action ID."); return;
    }
    if (!named.some(identity => identity.identity === owner) || owner === denied || (denied !== "anonymous" && !named.some(identity => identity.identity === denied))) {
      setError("Choose a named owner and a different denied identity or anonymous access."); return;
    }
    if (readyMarker.length < 8 || changedMarker.length < 8 || readyMarker.includes(changedMarker) || changedMarker.includes(readyMarker)) {
      setError("Use distinct, non-overlapping ready and changed markers of at least eight characters."); return;
    }
    const bytes = (value: string) => new TextEncoder().encode(value).length;
    if (!body || bytes(body) > 65536 || bytes(cleanupBody) > 65536 || (cleanupMethod !== "DELETE" && !cleanupBody)) {
      setError("Supply the exact action body and any required cleanup body, each no larger than 64 KiB."); return;
    }
    try {
      const origin = new URL(target.value).origin;
      for (const raw of [url, verificationURL, cleanupURL]) {
        const destination = new URL(raw.trim());
        if (destination.origin !== origin || destination.username || destination.password || destination.hash) throw new Error("Action, state verification, and cleanup URLs must belong to the original target origin without embedded credentials or fragments.");
      }
      setSaving(true);
      const request = await api.uploadAPIFixture(body, contentType);
      const cleanup = cleanupBody ? await api.uploadAPIFixture(cleanupBody, cleanupType) : undefined;
      const manifest = await api.uploadAPIFixture(JSON.stringify({
        url: url.trim(), action_id: actionID.trim(), body_ref: request.ref, content_type: contentType,
        verification_url: verificationURL.trim(), ready_marker: readyMarker, changed_marker: changedMarker,
        cleanup_url: cleanupURL.trim(), cleanup_method: cleanupMethod,
        cleanup_body_ref: cleanup?.ref, cleanup_content_type: cleanup ? cleanupType : undefined,
      }));
      const cases: Approvals[number]["cases"] = [
        { id: "baseline", identity: owner, expect: "allow" },
        { id: "denied-identity", identity: denied, expect: "deny" },
      ];
      if (crossOrigin) cases.push({ id: "foreign-origin", identity: owner, expect: "deny", cross_origin: true });
      const campaign: Approvals[number] = { id: id.trim(), target_id: target.id, owner_identity: owner, fixture_ref: manifest.ref, cases };
      onChange([...value.filter(item => item.id !== campaign.id || item.target_id !== campaign.target_id), campaign]);
      setBody(""); setCleanupBody(""); setReadyMarker(""); setChangedMarker(""); setApproved(false);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not save the controlled action campaign"); }
    finally { setSaving(false); }
  }

  return <Card><CardHeader><CardTitle>Controlled Server Action tests</CardTitle><p className="text-xs text-muted-foreground">Run an allowed-owner baseline and explicitly denied cases once each. A separate GET must prove the controlled resource changed, and cleanup must restore it after every case. Requires the expanded workflow and disposable test data.</p></CardHeader><CardContent className="space-y-3">
    <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={testEnvironment} onChange={event => onTestEnvironment(event.target.checked)} /><span>This target is a declared test environment.</span></label>
    <details className="rounded border p-3"><summary className="cursor-pointer text-sm font-medium">Set up an observed action and controlled fixture</summary><div className="mt-3 space-y-3">
      <Label htmlFor="action-target">URL target</Label><select id="action-target" className="w-full rounded border bg-background p-2" value={target?.id ?? ""} onChange={event => { setTargetId(event.target.value); setOwner(""); setDenied("anonymous"); setApproved(false); }}>{urlTargets.map(target => <option key={target.id} value={target.id}>{target.value}</option>)}</select>
      <Label htmlFor="action-campaign-id">Campaign ID</Label><Input id="action-campaign-id" value={id} maxLength={64} onChange={event => setID(event.target.value)} placeholder="controlled-profile-update" />
      <Label htmlFor="action-url">Exact action URL</Label><Input id="action-url" value={url} onChange={event => setURL(event.target.value)} placeholder="https://app.example.test/account" />
      <Label htmlFor="action-header-id">Observed Next-Action header</Label><Input id="action-header-id" value={actionID} maxLength={64} onChange={event => setActionID(event.target.value)} placeholder="Copy the exact ID from an observed action request" />
      <Label htmlFor="action-content-type">Observed request format</Label><select id="action-content-type" className="w-full rounded border bg-background p-2" value={contentType} onChange={event => setContentType(event.target.value)}><option value="text/plain;charset=UTF-8">Text action arguments</option><option value="application/x-www-form-urlencoded">URL-encoded action arguments</option></select>
      <Label htmlFor="action-body">Exact controlled action body</Label><Textarea id="action-body" value={body} maxLength={65536} onChange={event => setBody(event.target.value)} placeholder='["controlled-test-record"]' />
      <Label htmlFor="action-owner">Allowed owner</Label><select id="action-owner" className="w-full rounded border bg-background p-2" value={owner} onChange={event => setOwner(event.target.value)}><option value="">Choose a named identity</option>{named.map(identity => <option key={identity.identity} value={identity.identity}>{identity.identity} · {identity.role || "role not specified"}</option>)}</select>
      <Label htmlFor="action-denied">Denied identity</Label><select id="action-denied" className="w-full rounded border bg-background p-2" value={denied} onChange={event => setDenied(event.target.value)}><option value="anonymous">Anonymous · no credentials</option>{named.filter(identity => identity.identity !== owner).map(identity => <option key={identity.identity} value={identity.identity}>{identity.identity}</option>)}</select>
      <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={crossOrigin} onChange={event => setCrossOrigin(event.target.checked)} /><span>Also test the owner with the disallowed Origin https://xalgorix.invalid. This changes a request header; it does not contact that origin.</span></label>
      <Label htmlFor="action-state-url">Controlled state verification URL (GET)</Label><Input id="action-state-url" value={verificationURL} onChange={event => setVerificationURL(event.target.value)} placeholder="https://app.example.test/test-fixtures/state" />
      <Label htmlFor="action-ready-marker">Nonsecret marker proving the resource is ready</Label><Input id="action-ready-marker" value={readyMarker} minLength={8} maxLength={2000} onChange={event => setReadyMarker(event.target.value)} placeholder="CONTROLLED_READY_42" />
      <Label htmlFor="action-changed-marker">Nonsecret marker proving the action changed it</Label><Input id="action-changed-marker" value={changedMarker} minLength={8} maxLength={2000} onChange={event => setChangedMarker(event.target.value)} placeholder="CONTROLLED_CHANGED_42" />
      <Label htmlFor="action-cleanup-url">Exact cleanup URL</Label><Input id="action-cleanup-url" value={cleanupURL} onChange={event => setCleanupURL(event.target.value)} placeholder="https://app.example.test/test-fixtures/reset" />
      <Label htmlFor="action-cleanup-method">Cleanup method</Label><select id="action-cleanup-method" className="w-full rounded border bg-background p-2" value={cleanupMethod} onChange={event => setCleanupMethod(event.target.value)}><option>DELETE</option><option>PUT</option><option>PATCH</option></select>
      <Label htmlFor="action-cleanup-body">Exact cleanup body (optional for DELETE)</Label><Textarea id="action-cleanup-body" value={cleanupBody} maxLength={65536} onChange={event => setCleanupBody(event.target.value)} />
      <Label htmlFor="action-cleanup-type">Cleanup body content type</Label><Input id="action-cleanup-type" value={cleanupType} onChange={event => setCleanupType(event.target.value)} />
      <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)} /><span>Approve {crossOrigin ? "three" : "two"} one-shot POST cases and their declared cleanup requests for this controlled fixture.</span></label>
      <Button type="button" variant="outline" disabled={saving || !testEnvironment || !approved || !named.length || value.length >= 20} onClick={() => void save()}>{saving ? "Saving fixtures…" : "Save approved action campaign"}</Button>
    </div></details>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {value.map(campaign => <p className="break-all text-xs" key={`${campaign.target_id}:${campaign.id}`}>{campaign.id} · {campaign.target_id} · {campaign.cases.length} one-shot cases · fixture {campaign.fixture_ref}</p>)}
    {value.length > 0 && <Button type="button" variant="outline" size="sm" onClick={() => onChange([])}>Clear action campaigns</Button>}
  </CardContent></Card>;
}
