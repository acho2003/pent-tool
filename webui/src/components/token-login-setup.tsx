import { useState } from "react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { protectedPathURL, type ServiceURLTarget } from "@/components/services-setup";

// A saved shared login: one encrypted vault credential bound to the ticked
// service URL targets. `bound` records each target's URL at save time so a
// later URL edit forces a re-save instead of silently re-pointing the token.
export type SavedTokenLogin = { credentialId: string; bound: Array<{ id: string; value: string }> };

type TestResult = { state: string; reason: string };

// tokenLoginBindings returns one access binding per bound service, each with
// that service's protected path (when given) as its verification URL.
export function tokenLoginBindings(saved: SavedTokenLogin | null, targets: ServiceURLTarget[]) {
  if (!saved) return [];
  return saved.bound.flatMap(({ id }) => {
    const target = targets.find((t) => t.id === id);
    if (!target) return [];
    return [{ target_ids: [id], kind: "TOKEN_LOGIN", credential_id: saved.credentialId, verify_url: protectedPathURL(target) }];
  });
}

export function tokenLoginStale(saved: SavedTokenLogin | null, targets: ServiceURLTarget[]): boolean {
  return !!saved && saved.bound.some(({ id, value }) => targets.find((t) => t.id === id)?.value !== value);
}

export function TokenLoginSetup({ targets, loginTargets, value, onChange }: {
  targets: ServiceURLTarget[];
  loginTargets: string[];
  value: SavedTokenLogin | null;
  onChange: (value: SavedTokenLogin | null) => void;
}) {
  const [loginURL, setLoginURL] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [usernameField, setUsernameField] = useState("username");
  const [passwordField, setPasswordField] = useState("password");
  const [bodyFormat, setBodyFormat] = useState<"json" | "form">("json");
  const [extraFields, setExtraFields] = useState("");
  const [tokenPath, setTokenPath] = useState("");
  const [headerName, setHeaderName] = useState("Authorization");
  const [headerPrefix, setHeaderPrefix] = useState("Bearer ");
  const [selected, setSelected] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tests, setTests] = useState<Record<string, TestResult | undefined>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const chosen = selected ?? targets.map((t) => t.id);
  if (!targets.length) return null;

  async function save() {
    setError(null);
    if (!loginURL.trim() || !username || !password) { setError("Enter the login API URL, username and password."); return; }
    if (!chosen.length) { setError("Tick at least one service to receive the token."); return; }
    if (extraFields.trim()) {
      try {
        const parsed = JSON.parse(extraFields);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.values(parsed).some((v) => typeof v !== "string")) throw new Error();
      } catch { setError("Extra fields must be a JSON object of strings, for example {\"client_id\":\"web\"}."); return; }
    }
    setSaving(true);
    try {
      const values: Record<string, string> = { login_url: loginURL.trim(), username, password, username_field: usernameField.trim() || "username", password_field: passwordField.trim() || "password", body_format: bodyFormat, header_name: headerName.trim() || "Authorization", header_prefix: headerPrefix };
      if (extraFields.trim()) values.extra_fields = extraFields.trim();
      if (tokenPath.trim()) values.token_path = tokenPath.trim();
      const meta = await api.createCredential({ name: "Shared service login", kind: "TOKEN_LOGIN", target_ids: chosen, values });
      setPassword("");
      setTests({});
      onChange({ credentialId: meta.id, bound: targets.filter((t) => chosen.includes(t.id)).map((t) => ({ id: t.id, value: t.value })) });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the login credential");
    } finally {
      setSaving(false);
    }
  }

  async function test(target: ServiceURLTarget) {
    if (!value) return;
    setTesting(target.id);
    try {
      const result = await api.testCredential(value.credentialId, { target_id: target.id, target_url: target.value, verify_url: protectedPathURL(target), login_targets: loginTargets });
      setTests((current) => ({ ...current, [target.id]: { state: result.state, reason: result.reason } }));
    } catch (err) {
      setTests((current) => ({ ...current, [target.id]: { state: "failed", reason: err instanceof Error ? err.message : "test failed" } }));
    } finally {
      setTesting(null);
    }
  }

  return <Card>
    <CardHeader>
      <CardTitle>Shared login for services</CardTitle>
      <p className="text-sm text-muted-foreground">Log in once with your login API (for example the auth service) and send the returned token to every service you tick, so ZAP and the other web scanners test all of them authenticated. The password goes only to the login URL, which must be one of this assessment's URLs. The token is kept in memory, renewed before it expires, and never sent to services you did not tick.</p>
    </CardHeader>
    <CardContent className="space-y-4">
      {value ? <div className="space-y-3 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm text-emerald-300">Shared login saved (encrypted) for {value.bound.length} service URL{value.bound.length === 1 ? "" : "s"}.</p><Button type="button" size="sm" variant="outline" onClick={() => { onChange(null); setTests({}); }}>Remove</Button></div>
        <p className="break-all font-mono text-xs text-muted-foreground">Credential reference: {value.credentialId}</p>
        <ul className="space-y-2">{value.bound.map(({ id }) => {
          const target = targets.find((t) => t.id === id);
          if (!target) return null;
          const result = tests[id];
          return <li key={id} className="flex flex-wrap items-center justify-between gap-2 rounded border p-2 text-xs">
            <div><p className="font-medium">{target.service}</p><p className="font-mono text-muted-foreground">{target.value}{target.protectedPath ? ` · verify ${target.protectedPath}` : " · no protected path"}</p>{result && <p role="status" className={result.state === "verified" ? "text-emerald-300" : "text-amber-200"}>{result.state}: {result.reason}</p>}</div>
            <Button type="button" size="sm" variant="outline" disabled={testing === id} onClick={() => void test(target)}>{testing === id ? "Testing…" : "Test"}</Button>
          </li>;
        })}</ul>
        <p className="text-xs text-muted-foreground">Services without a protected path are scanned with the token but reported as "token applied, not verified". Add a protected path in the Services table to prove access.</p>
      </div> : <>
        <div className="space-y-2"><Label htmlFor="token-login-url">Login API URL</Label><Input id="token-login-url" value={loginURL} onChange={(e) => setLoginURL(e.target.value)} placeholder="http://10.0.0.5:30862/api/auth/login" /></div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-2"><Label htmlFor="token-username">Username</Label><Input id="token-username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" /></div>
          <div className="space-y-2"><Label htmlFor="token-password">Password</Label><Input id="token-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
        </div>
        <details className="rounded border p-3"><summary className="cursor-pointer text-sm">Request and token format</summary>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <div className="space-y-2"><Label htmlFor="token-username-field">Username field</Label><Input id="token-username-field" value={usernameField} onChange={(e) => setUsernameField(e.target.value)} placeholder="username or email" /></div>
            <div className="space-y-2"><Label htmlFor="token-password-field">Password field</Label><Input id="token-password-field" value={passwordField} onChange={(e) => setPasswordField(e.target.value)} /></div>
            <div className="space-y-2"><Label htmlFor="token-format">Body format</Label><select id="token-format" className="w-full rounded border bg-background p-2 text-sm" value={bodyFormat} onChange={(e) => setBodyFormat(e.target.value as "json" | "form")}><option value="json">JSON</option><option value="form">Form (x-www-form-urlencoded, e.g. Keycloak)</option></select></div>
            <div className="space-y-2"><Label htmlFor="token-extra">Extra fields (optional JSON)</Label><Input id="token-extra" value={extraFields} onChange={(e) => setExtraFields(e.target.value)} placeholder='{"grant_type":"password","client_id":"web"}' /></div>
            <div className="space-y-2"><Label htmlFor="token-path">Token path (optional)</Label><Input id="token-path" value={tokenPath} onChange={(e) => setTokenPath(e.target.value)} placeholder="auto: access_token, token, data.token…" /></div>
            <div className="grid grid-cols-2 gap-2"><div className="space-y-2"><Label htmlFor="token-header">Header</Label><Input id="token-header" value={headerName} onChange={(e) => setHeaderName(e.target.value)} /></div><div className="space-y-2"><Label htmlFor="token-prefix">Prefix</Label><Input id="token-prefix" value={headerPrefix} onChange={(e) => setHeaderPrefix(e.target.value)} /></div></div>
          </div>
        </details>
        <fieldset className="space-y-2"><legend className="text-sm font-medium">Send the token to</legend>
          <div className="flex gap-3 text-xs"><button type="button" className="underline" onClick={() => setSelected(targets.map((t) => t.id))}>All</button><button type="button" className="underline" onClick={() => setSelected([])}>None</button></div>
          {targets.map((target) => <label key={target.id} className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={chosen.includes(target.id)} onChange={(e) => setSelected(e.target.checked ? [...chosen, target.id] : chosen.filter((id) => id !== target.id))} /><span>{target.service} <span className="font-mono text-xs text-muted-foreground">{target.value}</span></span></label>)}
        </fieldset>
        <Button type="button" variant="outline" onClick={() => void save()} disabled={saving}>{saving ? "Encrypting…" : "Save shared login"}</Button>
      </>}
      {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    </CardContent>
  </Card>;
}
