import { useState } from "react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { protectedPathURL, type ServiceURLTarget } from "@/components/services-setup";

// A saved shared credential bound to the ticked URL targets.
// - TOKEN_LOGIN: Xalgorix logs in with a username/password and renews the token.
// - APPLICATION_HEADERS: a token or cookie the operator pasted (for logins that
//   cannot be automated, such as NDI wallet sign-in); it cannot be renewed.
// `bound` records each target's URL at save time so a later URL edit forces a
// re-save instead of silently re-pointing the credential.
export type SavedTokenLogin = {
  credentialId: string;
  kind: "TOKEN_LOGIN" | "APPLICATION_HEADERS";
  bound: Array<{ id: string; value: string; verifyPath?: string }>;
  marker?: string;
  expiresAt?: number; // epoch ms from the pasted JWT, when known
};

type TestResult = { state: string; reason: string };

function verifyURLFor(target: ServiceURLTarget, verifyPath?: string): string | undefined {
  return protectedPathURL({ ...target, protectedPath: verifyPath ?? target.protectedPath });
}

// tokenLoginBindings returns one access binding per bound target, each with its
// own verification path (when given) as the verification URL.
export function tokenLoginBindings(saved: SavedTokenLogin | null, targets: ServiceURLTarget[]) {
  if (!saved) return [];
  return saved.bound.flatMap(({ id, verifyPath }) => {
    const target = targets.find((t) => t.id === id);
    if (!target) return [];
    const verifyURL = verifyURLFor(target, verifyPath);
    // The marker belongs to the verification path; a target without one is
    // applied unverified rather than checked for the marker at its root.
    return [{ target_ids: [id], kind: saved.kind, credential_id: saved.credentialId, verify_url: verifyURL, verify_marker: verifyURL && saved.marker ? saved.marker : undefined }];
  });
}

export function tokenLoginStale(saved: SavedTokenLogin | null, targets: ServiceURLTarget[]): boolean {
  return !!saved && saved.bound.some(({ id, value }) => targets.find((t) => t.id === id)?.value !== value);
}

// jwtExpiry reads the exp claim of a pasted bearer token locally (nothing is
// sent anywhere); the signature is not checked.
export function jwtExpiry(header: string): number | undefined {
  const token = header.trim().replace(/^bearer\s+/i, "");
  const parts = token.split(".");
  if (parts.length !== 3) return undefined;
  try {
    const json = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(parts[1].length / 4) * 4, "="));
    const exp = Number(JSON.parse(json).exp);
    return Number.isFinite(exp) && exp > 0 ? exp * 1000 : undefined;
  } catch {
    return undefined;
  }
}

function expiryText(expiresAt: number | undefined): { text: string; expired: boolean } | null {
  if (!expiresAt) return null;
  const minutes = Math.round((expiresAt - Date.now()) / 60000);
  const when = new Date(expiresAt).toLocaleString();
  if (minutes <= 0) return { text: `expired at ${when}`, expired: true };
  const h = Math.floor(minutes / 60), m = minutes % 60;
  return { text: `expires at ${when} (in ${h ? `${h} h ` : ""}${m} min)`, expired: false };
}

export function TokenLoginSetup({ targets, loginTargets, value, onChange }: {
  targets: ServiceURLTarget[];
  loginTargets: string[];
  value: SavedTokenLogin | null;
  onChange: (value: SavedTokenLogin | null) => void;
}) {
  const [mode, setMode] = useState<"login" | "paste">("login");
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
  const [pastedAuthorization, setPastedAuthorization] = useState("");
  const [pastedCookie, setPastedCookie] = useState("");
  const [marker, setMarker] = useState("");
  const [verifyPaths, setVerifyPaths] = useState<Record<string, string>>({});
  const [selected, setSelected] = useState<string[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tests, setTests] = useState<Record<string, TestResult | undefined>>({});
  const [testing, setTesting] = useState<string | null>(null);
  const chosen = selected ?? targets.map((t) => t.id);
  if (!targets.length) return null;
  const pastedExpiry = expiryText(jwtExpiry(pastedAuthorization));
  const savedExpiry = expiryText(value?.expiresAt);
  const label = (target: ServiceURLTarget) => target.service || target.value;

  function boundTargets() {
    return targets.filter((t) => chosen.includes(t.id)).map((t) => ({ id: t.id, value: t.value, verifyPath: mode === "paste" ? (verifyPaths[t.id] ?? t.protectedPath).trim() : undefined }));
  }

  async function saveLogin() {
    if (!loginURL.trim() || !username || !password) { setError("Enter the login API URL, username and password."); return; }
    if (extraFields.trim()) {
      try {
        const parsed = JSON.parse(extraFields);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.values(parsed).some((v) => typeof v !== "string")) throw new Error();
      } catch { setError("Extra fields must be a JSON object of strings, for example {\"client_id\":\"web\"}."); return; }
    }
    const values: Record<string, string> = { login_url: loginURL.trim(), username, password, username_field: usernameField.trim() || "username", password_field: passwordField.trim() || "password", body_format: bodyFormat, header_name: headerName.trim() || "Authorization", header_prefix: headerPrefix };
    if (extraFields.trim()) values.extra_fields = extraFields.trim();
    if (tokenPath.trim()) values.token_path = tokenPath.trim();
    const meta = await api.createCredential({ name: "Shared service login", kind: "TOKEN_LOGIN", target_ids: chosen, values });
    setPassword("");
    onChange({ credentialId: meta.id, kind: "TOKEN_LOGIN", bound: boundTargets() });
  }

  async function savePasted() {
    const authorization = pastedAuthorization.trim();
    const cookie = pastedCookie.trim().replace(/^cookie:\s*/i, "");
    if (!authorization && !cookie) { setError("Paste the Authorization value, the session cookie, or both."); return; }
    if (/[\r\n]/.test(authorization + cookie)) { setError("Paste each value on a single line."); return; }
    if (pastedExpiry?.expired) { setError("This token has already expired. Copy a fresh one from the browser right before starting the scan."); return; }
    const values: Record<string, string> = {};
    if (authorization) values.Authorization = /^bearer\s/i.test(authorization) || authorization.includes(" ") ? authorization : `Bearer ${authorization}`;
    if (cookie) values.Cookie = cookie;
    const meta = await api.createCredential({ name: "Pasted session token", kind: "APPLICATION_HEADERS", target_ids: chosen, values });
    setPastedAuthorization("");
    setPastedCookie("");
    onChange({ credentialId: meta.id, kind: "APPLICATION_HEADERS", bound: boundTargets(), marker: marker.trim() || undefined, expiresAt: jwtExpiry(values.Authorization ?? "") });
  }

  async function save() {
    setError(null);
    if (!chosen.length) { setError("Tick at least one target to receive the credential."); return; }
    setSaving(true);
    try {
      if (mode === "login") await saveLogin(); else await savePasted();
      setTests({});
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the credential");
    } finally {
      setSaving(false);
    }
  }

  async function test(target: ServiceURLTarget, verifyPath?: string) {
    if (!value) return;
    setTesting(target.id);
    try {
      const verifyURL = verifyURLFor(target, verifyPath);
      const result = await api.testCredential(value.credentialId, { target_id: target.id, target_url: target.value, verify_url: verifyURL, verify_marker: verifyURL ? value.marker : undefined, login_targets: loginTargets });
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
      <p className="text-sm text-muted-foreground">Use one login for every service and portal you tick, so ZAP and the other web scanners test all of them authenticated. The credential is stored encrypted and is never sent to targets you did not tick.</p>
    </CardHeader>
    <CardContent className="space-y-4">
      {value ? <div className="space-y-3 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-sm text-emerald-300">{value.kind === "TOKEN_LOGIN" ? "Shared login" : "Pasted token"} saved (encrypted) for {value.bound.length} target{value.bound.length === 1 ? "" : "s"}.</p>
          <Button type="button" size="sm" variant="outline" onClick={() => { onChange(null); setTests({}); }}>Remove</Button>
        </div>
        {savedExpiry && <p role="status" className={`text-xs ${savedExpiry.expired ? "text-destructive" : "text-amber-200"}`}>Token {savedExpiry.text}. It cannot be renewed automatically; when it expires, authenticated testing stops and is reported as expired. Start the scan soon after pasting.</p>}
        <p className="break-all font-mono text-xs text-muted-foreground">Credential reference: {value.credentialId}</p>
        <ul className="space-y-2">{value.bound.map(({ id, verifyPath }) => {
          const target = targets.find((t) => t.id === id);
          if (!target) return null;
          const path = verifyPath ?? target.protectedPath;
          const result = tests[id];
          return <li key={id} className="flex flex-wrap items-center justify-between gap-2 rounded border p-2 text-xs">
            <div><p className="font-medium">{label(target)}</p><p className="font-mono text-muted-foreground">{target.value}{path ? ` · verify ${path}` : " · no verification path"}</p>{result && <p role="status" className={result.state === "verified" ? "text-emerald-300" : "text-amber-200"}>{result.state}: {result.reason}</p>}</div>
            <Button type="button" size="sm" variant="outline" disabled={testing === id} onClick={() => void test(target, verifyPath)}>{testing === id ? "Testing…" : "Test"}</Button>
          </li>;
        })}</ul>
        <p className="text-xs text-muted-foreground">Targets without a verification path are scanned with the credential but reported as "not verified". A verification path is a URL that only works when logged in.</p>
      </div> : <>
        <fieldset className="grid gap-2 sm:grid-cols-2">
          <legend className="sr-only">How do you sign in?</legend>
          <label className={`flex cursor-pointer items-start gap-2 rounded-lg border p-3 text-sm ${mode === "login" ? "border-primary bg-primary/5" : ""}`}><input type="radio" name="shared-login-mode" className="mt-1" checked={mode === "login"} onChange={() => setMode("login")} /><span><span className="font-medium">Log in with a username and password</span><span className="block text-xs text-muted-foreground">Xalgorix calls your login API and renews the token itself.</span></span></label>
          <label className={`flex cursor-pointer items-start gap-2 rounded-lg border p-3 text-sm ${mode === "paste" ? "border-primary bg-primary/5" : ""}`}><input type="radio" name="shared-login-mode" className="mt-1" checked={mode === "paste"} onChange={() => setMode("paste")} /><span><span className="font-medium">Paste a token I already have</span><span className="block text-xs text-muted-foreground">For logins Xalgorix cannot perform, such as NDI or a mobile app QR scan.</span></span></label>
        </fieldset>
        {mode === "login" ? <>
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
        </> : <>
          <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-100">Sign in to the app normally (for example with NDI), open the browser's DevTools → Network, click any request to the API or portal and copy the <span className="font-mono">authorization</span> header and/or the session cookie. Paste them here only — never in chat or tickets. A pasted token cannot be renewed: copy it right before starting the scan.</p>
          <div className="space-y-2"><Label htmlFor="paste-authorization">Authorization header value (for the APIs)</Label><Input id="paste-authorization" type="password" autoComplete="off" value={pastedAuthorization} onChange={(e) => setPastedAuthorization(e.target.value)} placeholder="Bearer eyJhbGciOi…" />
            {pastedExpiry && <p className={`text-xs ${pastedExpiry.expired ? "text-destructive" : "text-muted-foreground"}`}>This token {pastedExpiry.text}.</p>}</div>
          <div className="space-y-2"><Label htmlFor="paste-cookie">Session cookie (for a Next.js / NextAuth portal, optional)</Label><Input id="paste-cookie" type="password" autoComplete="off" value={pastedCookie} onChange={(e) => setPastedCookie(e.target.value)} placeholder="__Secure-next-auth.session-token=… (only the session cookie is needed)" /></div>
          <div className="space-y-2"><Label htmlFor="paste-marker">Text visible only when logged in (optional)</Label><Input id="paste-marker" value={marker} onChange={(e) => setMarker(e.target.value)} placeholder='For NextAuth portals use path /api/auth/session and the text "expires"' /></div>
        </>}
        <fieldset className="space-y-2"><legend className="text-sm font-medium">Send it to</legend>
          <div className="flex gap-3 text-xs"><button type="button" className="underline" onClick={() => setSelected(targets.map((t) => t.id))}>All</button><button type="button" className="underline" onClick={() => setSelected([])}>None</button></div>
          {targets.map((target) => <div key={target.id} className="flex flex-wrap items-center gap-2 text-sm">
            <label className="flex min-w-0 flex-1 items-start gap-2"><input type="checkbox" className="mt-1" checked={chosen.includes(target.id)} onChange={(e) => setSelected(e.target.checked ? [...chosen, target.id] : chosen.filter((id) => id !== target.id))} /><span className="min-w-0">{target.service || "Target"} <span className="break-all font-mono text-xs text-muted-foreground">{target.value}</span></span></label>
            {mode === "paste" && chosen.includes(target.id) && <Input aria-label={`Verification path for ${label(target)}`} className="h-8 w-56 text-xs" value={verifyPaths[target.id] ?? target.protectedPath} onChange={(e) => setVerifyPaths((current) => ({ ...current, [target.id]: e.target.value }))} placeholder="verification path, e.g. /api/auth/session" />}
          </div>)}
        </fieldset>
        <Button type="button" variant="outline" onClick={() => void save()} disabled={saving}>{saving ? "Encrypting…" : mode === "login" ? "Save shared login" : "Save pasted token"}</Button>
      </>}
      {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    </CardContent>
  </Card>;
}
