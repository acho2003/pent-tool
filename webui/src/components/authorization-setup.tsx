import { useState } from "react";
import { api } from "@/api/client";
import type { AssessmentConfig } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type Expectations = NonNullable<AssessmentConfig["authorization_expectations"]>;
type Identity = { identity: string; role: string; targetId: string };

export function AuthorizationSetup({ identities, value, onChange }: {
  identities: Identity[]; value: Expectations; onChange: (value: Expectations) => void;
}) {
  const [operation, setOperation] = useState("");
  const [url, setURL] = useState("");
  const [marker, setMarker] = useState("");
  const [allow, setAllow] = useState("");
  const [deny, setDeny] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const named = identities.filter(identity => identity.identity);
  async function save() {
    setError(null);
    const allowed = named.find(identity => `${identity.targetId}:${identity.identity}` === allow);
    const denied = named.find(identity => `${identity.targetId}:${identity.identity}` === deny);
    if (!operation.trim() || !url.trim() || !marker || !allowed || !denied || allowed.targetId !== denied.targetId || allowed.identity === denied.identity) {
      setError("Choose two different identities on the same target, an API operation ID, its exact resource URL, and a response marker.");
      return;
    }
    try {
      const resource = new URL(url.trim());
      if (!["http:", "https:"].includes(resource.protocol) || resource.username || resource.password || resource.hash) throw new Error("Use an HTTP(S) resource URL without embedded credentials or fragments.");
      setSaving(true);
      const fixture = await api.uploadAPIFixture(JSON.stringify({ url: url.trim(), response_marker: marker }));
      const added: Expectations = [
        { operation_id: operation.trim(), identity: allowed.identity, expect: "allow", resource_fixture_ref: fixture.ref },
        { operation_id: operation.trim(), identity: denied.identity, expect: "deny", resource_fixture_ref: fixture.ref },
      ];
      onChange([...value.filter(item => item.operation_id !== operation.trim()), ...added]);
      setMarker("");
    } catch (err) { setError(err instanceof Error ? err.message : "Could not save resource fixture"); }
    finally { setSaving(false); }
  }
  return <Card><CardHeader><CardTitle>Role access expectations</CardTitle><p className="text-xs text-muted-foreground">Optional read-only comparison. Use an API operation and a controlled resource that one supplied identity may read and another must not. Only matching, materialized GET operations within the original target are checked. Requires the expanded workflow.</p></CardHeader><CardContent className="space-y-3">
    <Label htmlFor="role-operation">API operation ID</Label><Input id="role-operation" value={operation} onChange={e=>setOperation(e.target.value)} placeholder="getRecord" />
    <Label htmlFor="role-resource">Exact resource URL</Label><Input id="role-resource" value={url} onChange={e=>setURL(e.target.value)} placeholder="https://app.example.test/api/records/controlled-record" />
    <Label htmlFor="role-marker">Nonsecret text identifying the returned resource</Label><Input id="role-marker" maxLength={2000} value={marker} onChange={e=>setMarker(e.target.value)} placeholder="A unique name from your controlled test record" />
    {([['Allowed identity',allow,setAllow],['Denied identity',deny,setDeny]] as const).map(([label,selected,setSelected])=><label className="block space-y-1 text-sm" key={label}><span>{label}</span><select className="w-full rounded border bg-background p-2" value={selected} onChange={e=>setSelected(e.target.value)}><option value="">Choose a named identity</option>{named.map(identity=><option key={`${identity.targetId}:${identity.identity}`} value={`${identity.targetId}:${identity.identity}`}>{identity.identity} · {identity.role || 'role not specified'} · {identity.targetId}</option>)}</select></label>)}
    <Button type="button" variant="outline" disabled={saving || named.length<2} onClick={()=>void save()}>{saving ? "Saving…" : "Save resource and expectations"}</Button>
    {named.length<2 && <p className="text-xs text-muted-foreground">Save two named credentials for the same target first.</p>}
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {value.map(item=><p className="break-all text-xs" key={`${item.operation_id}:${item.identity}`}>{item.operation_id} · {item.identity}: {item.expect} · fixture {item.resource_fixture_ref}</p>)}
    {value.length>0 && <Button type="button" variant="outline" size="sm" onClick={()=>onChange([])}>Clear expectations</Button>}
  </CardContent></Card>;
}
