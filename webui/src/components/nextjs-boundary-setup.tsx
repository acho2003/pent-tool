import { useState } from "react";
import { api } from "@/api/client";
import type { AssessmentConfig, AssessmentTarget } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

type Approvals = NonNullable<AssessmentConfig["nextjs_boundary_approvals"]>;
type Origins = NonNullable<AssessmentConfig["approved_origins"]>;
type Identity = { identity: string; targetId: string; role: string };

export function NextjsBoundarySetup({ targets, identities, value, scopes, onChange, testEnvironment, onTestEnvironment }: {
  targets: AssessmentTarget[]; identities: Identity[]; value: Approvals; scopes: Record<string, Origins>; onChange: (value: Approvals, scopes: Record<string, Origins>) => void;
  testEnvironment: boolean; onTestEnvironment: (value: boolean) => void;
}) {
  const [kind, setKind] = useState<"cache" | "redirect" | "proxy">("cache");
  const [targetId, setTargetId] = useState("");
  const [id, setID] = useState("");
  const [url, setURL] = useState("");
  const [identity, setIdentity] = useState("anonymous");
  const [owner, setOwner] = useState("");
  const [representation, setRepresentation] = useState("pages-json");
  const [consumerRepresentation, setConsumerRepresentation] = useState("pages-json");
  const [privateMarker, setPrivateMarker] = useState("");
  const [deniedMarker, setDeniedMarker] = useState("");
  const [bypassURL, setBypassURL] = useState("");
  const [cleanupURL, setCleanupURL] = useState("");
  const [cleanupMethod, setCleanupMethod] = useState("DELETE");
  const [cleanupBody, setCleanupBody] = useState("");
  const [cleanupType, setCleanupType] = useState("application/json");
  const [parameter, setParameter] = useState("");
  const [controlValue, setControlValue] = useState("");
  const [destinationURL, setDestinationURL] = useState("");
  const [eventsURL, setEventsURL] = useState("");
  const [approved, setApproved] = useState(false);
  const [isolated, setIsolated] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const urlTargets = targets.filter(target => target.type === "URL");
  const target = urlTargets.find(target => target.id === targetId) ?? urlTargets[0];
  const named = identities.filter(identity => identity.targetId === target?.id && identity.identity);
  const formats = <><option value="html">HTML</option><option value="pages-json">Page JSON</option><option value="rsc">RSC</option></>;

  async function save() {
    setError(null);
    if (!target || !approved || !testEnvironment || !/^[A-Za-z0-9_-]{1,64}$/.test(id.trim())) { setError("Choose a URL target, a bounded probe ID, a test environment, and explicit approval."); return; }
    if (identity !== "anonymous" && !named.some(item => item.identity === identity)) { setError("Choose an identity bound to the selected target."); return; }
    try {
      const base = new URL(target.value);
      const parse = (raw: string) => { const u = new URL(raw.trim()); if (!["http:", "https:"].includes(u.protocol) || u.username || u.password || u.hash) throw new Error("Use exact HTTP(S) URLs without embedded credentials or fragments."); return u; };
      const resource = parse(url);
      if (resource.origin !== base.origin) throw new Error("The observed resource URL must use the original target origin.");
      const manifest: Record<string, unknown> = { kind, url: resource.href };
      let origins: Origins = [];
      if (kind === "cache") {
        if (!isolated || !named.some(item => item.identity === owner) || owner === identity) throw new Error("Declare isolated controlled test data and choose a named owner different from the denied identity.");
        if (privateMarker.length < 8 || deniedMarker.length < 8 || privateMarker.includes(deniedMarker) || deniedMarker.includes(privateMarker)) throw new Error("Use non-overlapping private and denied markers of at least eight characters.");
        const bypass = parse(bypassURL), cleanup = parse(cleanupURL);
        if (bypass.origin !== base.origin || cleanup.origin !== base.origin || bypass.pathname !== resource.pathname || bypass.search === resource.search) throw new Error("The uncached control must use the same path with a distinct supplied query. Cleanup must remain on the original origin.");
        if (new TextEncoder().encode(cleanupBody).length > 65536 || (cleanupMethod !== "DELETE" && !cleanupBody)) throw new Error("PUT/PATCH reset needs an exact body; reset bodies are limited to 64 KiB.");
        const body = cleanupBody ? await api.uploadAPIFixture(cleanupBody, cleanupType) : undefined;
        Object.assign(manifest, { representation, consumer_representation: consumerRepresentation, private_marker: privateMarker, denied_marker: deniedMarker, bypass_url: bypass.href, isolated: true, cleanup_url: cleanup.href, cleanup_method: cleanupMethod, cleanup_body_ref: body?.ref, cleanup_content_type: body ? cleanupType : undefined });
      } else {
        if (!parameter.trim() || resource.searchParams.getAll(parameter.trim()).length !== 1) throw new Error("Supply one exact query parameter from an observed request.");
        const destination = parse(destinationURL);
        if (destination.origin === base.origin || destination.search) throw new Error("The controlled external destination must be on another origin and have no query string.");
        const scoped = [destination];
        if (kind === "proxy") {
          const events = parse(eventsURL);
          if (events.origin !== destination.origin || events.pathname === destination.pathname || events.search) throw new Error("The anonymous event feed must be a distinct query-free path on the same callback origin.");
          Object.assign(manifest, { parameter: parameter.trim(), callback_url: destination.href, events_url: events.href }); scoped.push(events);
        } else {
          if (resource.searchParams.get(parameter.trim()) !== controlValue || new URL(controlValue, resource).origin !== base.origin) throw new Error("The local control must exactly match the observed parameter value.");
          Object.assign(manifest, { parameter: parameter.trim(), control_value: controlValue, destination_url: destination.href });
        }
        const origin = (u: URL): Origins[number] => ({ target_id: target.id, scheme: u.protocol.slice(0, -1), host: u.hostname.replace(/^\[|\]$/g, ""), port: u.port ? Number(u.port) : undefined, path_prefix: decodeURIComponent(u.pathname) || "/" });
        origins = [origin(base), ...scoped.map(origin)];
      }
      setSaving(true);
      const fixture = await api.uploadAPIFixture(JSON.stringify(manifest));
      const probe: Approvals[number] = { id: id.trim(), target_id: target.id, kind, fixture_ref: fixture.ref, identity, owner_identity: kind === "cache" ? owner : undefined };
      const next = [...value.filter(item => item.id !== probe.id || item.target_id !== probe.target_id), probe];
      const nextScopes = { ...scopes, [`${probe.target_id}:${probe.id}`]: origins };
      onChange(next, nextScopes);
      setPrivateMarker(""); setDeniedMarker(""); setCleanupBody(""); setApproved(false);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not save controlled boundary probe"); }
    finally { setSaving(false); }
  }

  return <Card><CardHeader><CardTitle>Controlled cache and URL boundaries</CardTitle><p className="text-xs text-muted-foreground">Test isolated cache identity boundaries, paired redirects, or one disallowed callback destination. Cache fills require verified reset. Missing callback events are inconclusive. Requires the expanded workflow.</p></CardHeader><CardContent className="space-y-3">
    <label className="flex gap-2 text-sm"><input type="checkbox" checked={testEnvironment} onChange={event => onTestEnvironment(event.target.checked)} /><span>This target is a declared test environment.</span></label>
    <details className="rounded border p-3"><summary className="cursor-pointer text-sm font-medium">Set up a controlled boundary probe</summary><div className="mt-3 space-y-3">
      <Label htmlFor="boundary-kind">Check</Label><select id="boundary-kind" className="w-full rounded border bg-background p-2" value={kind} onChange={event => { setKind(event.target.value as typeof kind); setApproved(false); }}><option value="cache">Cache identity isolation</option><option value="redirect">External redirect policy</option><option value="proxy">Image/proxy URL-fetch policy</option></select>
      <Label htmlFor="boundary-target">URL target</Label><select id="boundary-target" className="w-full rounded border bg-background p-2" value={target?.id ?? ""} onChange={event => { setTargetId(event.target.value); setOwner(""); setIdentity("anonymous"); setApproved(false); }}>{urlTargets.map(item => <option key={item.id} value={item.id}>{item.value}</option>)}</select>
      <Label htmlFor="boundary-id">Probe ID</Label><Input id="boundary-id" value={id} maxLength={64} onChange={event => setID(event.target.value)} placeholder="controlled-cache-record" />
      <Label htmlFor="boundary-url">Exact observed URL</Label><Input id="boundary-url" value={url} onChange={event => setURL(event.target.value)} placeholder="https://app.example.test/account" />
      <Label htmlFor="boundary-identity">{kind === "cache" ? "Denied identity" : "Acting identity"}</Label><select id="boundary-identity" className="w-full rounded border bg-background p-2" value={identity} onChange={event => setIdentity(event.target.value)}><option value="anonymous">Anonymous · no credentials</option>{named.map(item => <option key={item.identity} value={item.identity}>{item.identity}</option>)}</select>
      {kind === "cache" ? <>
        <Label htmlFor="cache-owner">Allowed owner</Label><select id="cache-owner" className="w-full rounded border bg-background p-2" value={owner} onChange={event => setOwner(event.target.value)}><option value="">Choose a named owner</option>{named.filter(item => item.identity !== identity).map(item => <option key={item.identity} value={item.identity}>{item.identity}</option>)}</select>
        <Label htmlFor="cache-owner-format">Owner response format</Label><select id="cache-owner-format" className="w-full rounded border bg-background p-2" value={representation} onChange={event => setRepresentation(event.target.value)}>{formats}</select>
        <Label htmlFor="cache-denied-format">Denied-user response format</Label><select id="cache-denied-format" className="w-full rounded border bg-background p-2" value={consumerRepresentation} onChange={event => setConsumerRepresentation(event.target.value)}>{formats}</select>
        <Label htmlFor="cache-private-marker">Nonsecret marker from the owner's private test record</Label><Input id="cache-private-marker" value={privateMarker} maxLength={2000} onChange={event => setPrivateMarker(event.target.value)} placeholder="PRIVATE_CONTROLLED_42" />
        <Label htmlFor="cache-denied-marker">Nonsecret denied/public response marker</Label><Input id="cache-denied-marker" value={deniedMarker} maxLength={2000} onChange={event => setDeniedMarker(event.target.value)} placeholder="DENIED_CONTROLLED_42" />
        <Label htmlFor="cache-bypass-url">Supplied uncached control URL (same path, different query)</Label><Input id="cache-bypass-url" value={bypassURL} onChange={event => setBypassURL(event.target.value)} placeholder="https://app.example.test/account?controlled_bypass=1" />
        <Label htmlFor="cache-cleanup-url">Exact cache reset URL</Label><Input id="cache-cleanup-url" value={cleanupURL} onChange={event => setCleanupURL(event.target.value)} />
        <Label htmlFor="cache-cleanup-method">Reset method</Label><select id="cache-cleanup-method" className="w-full rounded border bg-background p-2" value={cleanupMethod} onChange={event => setCleanupMethod(event.target.value)}><option>DELETE</option><option>PUT</option><option>PATCH</option></select>
        <Label htmlFor="cache-cleanup-body">Exact reset body (optional for DELETE)</Label><Textarea id="cache-cleanup-body" value={cleanupBody} maxLength={65536} onChange={event => setCleanupBody(event.target.value)} />
        <Label htmlFor="cache-cleanup-type">Reset body content type</Label><Input id="cache-cleanup-type" value={cleanupType} onChange={event => setCleanupType(event.target.value)} />
        <label className="flex gap-2 text-sm"><input type="checkbox" checked={isolated} onChange={event => setIsolated(event.target.checked)} /><span>This resource contains isolated synthetic data and has a dedicated cache reset.</span></label>
      </> : <>
        <Label htmlFor="boundary-parameter">Observed URL query parameter</Label><Input id="boundary-parameter" value={parameter} maxLength={128} onChange={event => setParameter(event.target.value)} placeholder={kind === "proxy" ? "url" : "next"} />
        {kind === "redirect" && <><Label htmlFor="redirect-control-value">Exact local control value</Label><Input id="redirect-control-value" value={controlValue} onChange={event => setControlValue(event.target.value)} placeholder="/account" /></>}
        <Label htmlFor="boundary-destination">{kind === "proxy" ? "Controlled callback URL (expected to be denied)" : "Controlled external redirect destination (expected to be denied)"}</Label><Input id="boundary-destination" value={destinationURL} onChange={event => setDestinationURL(event.target.value)} placeholder="https://collector.example.test/hit" />
        {kind === "proxy" && <><Label htmlFor="callback-events-url">Anonymous correlation event feed on the same callback origin</Label><Input id="callback-events-url" value={eventsURL} onChange={event => setEventsURL(event.target.value)} placeholder="https://collector.example.test/events" /><p className="text-xs text-muted-foreground">The scanner reads the feed with a fresh scan_token query. It must return JSON with matching token, count, and method fields. It never requests the callback URL itself.</p></>}
      </>}
      <label className="flex gap-2 text-sm"><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)} /><span>{kind === "cache" ? "Approve the cold/owner/warm comparison, uncached controls, and declared reset for this isolated resource." : "Approve this controlled URL-input test and authorize the listed external destination paths within this target's reviewed scope."}</span></label>
      <Button type="button" variant="outline" disabled={saving || !approved || !testEnvironment || value.length >= 20} onClick={() => void save()}>{saving ? "Saving fixture…" : "Save approved boundary probe"}</Button>
    </div></details>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {value.map(item => <p className="break-all text-xs" key={`${item.target_id}:${item.id}`}>{item.id} · {item.kind} · {item.target_id} · fixture {item.fixture_ref}</p>)}
    {value.length > 0 && <Button type="button" variant="outline" size="sm" onClick={() => onChange([], {})}>Clear boundary probes and their added scopes</Button>}
  </CardContent></Card>;
}
