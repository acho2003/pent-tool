import { useEffect, useState } from "react";
import { Sparkles, Terminal } from "lucide-react";
import { api } from "@/api/client";
import type { AIConnectionStatus } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

// Connect Claude for AI-written reports using your Claude subscription (Claude
// Code), not a metered Anthropic API key. Run `claude setup-token` in a terminal,
// log in with your plan, paste the token it prints. The secret is stored
// encrypted on the server and never returned; only connection status is shown
// here. A plain Anthropic API key also works as a fallback.
export function AIConnectionSetup() {
  const [status, setStatus] = useState<AIConnectionStatus | null>(null);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.aiConnection().then(setStatus).catch(() => setStatus({ configured: false }));
  }, []);

  async function connect() {
    const v = value.trim();
    if (!v) { setError("Paste the token from `claude setup-token` (or an API key)."); return; }
    // sk-ant-api… is a metered API key; anything else (the sk-ant-oat…
    // subscription token from `claude setup-token`) uses the OAuth path, which
    // the server sends with the oauth beta header.
    const kind = v.startsWith("sk-ant-api") ? "api_key" : "auth_token";
    setBusy(true); setError(null);
    try {
      setStatus(await api.setAIConnection(kind, v));
      setValue("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not connect Claude");
    } finally { setBusy(false); }
  }

  async function disconnect() {
    setBusy(true); setError(null);
    try { setStatus(await api.clearAIConnection()); }
    catch (err) { setError(err instanceof Error ? err.message : "Could not disconnect"); }
    finally { setBusy(false); }
  }

  const envManaged = status?.source === "environment";
  const kindLabel = status?.kind === "auth_token" ? "subscription" : status?.kind === "api_key" ? "API key" : "";

  return <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2"><Sparkles className="h-4 w-4" /> Connect Claude</CardTitle>
      <CardDescription>
        Turn on full AI-written reports using your Claude subscription. Your token is stored encrypted and used only to compose the report from the already-sanitized findings.
      </CardDescription>
    </CardHeader>
    <CardContent className="space-y-4">
      <div>
        {status?.configured
          ? <Badge className="bg-emerald-500/15 text-emerald-500">Connected{kindLabel ? ` · ${kindLabel}` : ""}{status.source === "environment" ? " · env" : ""}</Badge>
          : <Badge variant="outline">Not connected</Badge>}
      </div>

      {envManaged ? (
        <p className="text-sm text-muted-foreground">A credential is set from the environment (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN). Unset it to manage the connection here.</p>
      ) : status?.configured ? (
        <Button type="button" variant="outline" size="sm" onClick={() => void disconnect()} disabled={busy}>Disconnect</Button>
      ) : (
        <div className="space-y-3">
          <div className="space-y-2 rounded-md border bg-muted/40 p-3 text-sm">
            <div className="flex items-center gap-2 font-medium"><Terminal className="h-4 w-4" /> Use your Claude subscription</div>
            <p className="text-muted-foreground">In a terminal signed in to Claude Code, run this, log in, then copy the token it prints:</p>
            <code className="block rounded bg-background px-2 py-1 font-mono text-xs">claude setup-token</code>
          </div>
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-0 flex-1 space-y-1">
              <Input type="password" autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Paste the token (sk-ant-oat… — or an API key)" onKeyDown={(e) => { if (e.key === "Enter") void connect(); }} />
            </div>
            <Button type="button" size="sm" onClick={() => void connect()} disabled={busy || !value.trim()}>{busy ? "Connecting…" : "Connect"}</Button>
          </div>
          <p className="text-xs text-muted-foreground">The subscription token uses your Claude plan (no per-use billing). The app can't refresh it, so rerun <code>claude setup-token</code> if reports ever start failing with an auth error. An Anthropic API key (sk-ant-api…) also works and is billed per-use.</p>
        </div>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}
    </CardContent>
  </Card>;
}
