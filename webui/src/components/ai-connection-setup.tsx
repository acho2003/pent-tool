import { useEffect, useState } from "react";
import { Sparkles } from "lucide-react";
import { api } from "@/api/client";
import type { AIConnectionStatus } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

// Connect Claude for AI-written reports. The credential is stored encrypted on
// the server and never returned; only connection status is shown here.
export function AIConnectionSetup() {
  const [status, setStatus] = useState<AIConnectionStatus | null>(null);
  const [kind, setKind] = useState<"api_key" | "auth_token">("api_key");
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.aiConnection().then(setStatus).catch(() => setStatus({ configured: false }));
  }, []);

  async function connect() {
    if (!value.trim()) { setError("Enter your Claude API key or token."); return; }
    setBusy(true); setError(null);
    try {
      setStatus(await api.setAIConnection(kind, value.trim()));
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

  return <Card>
    <CardHeader>
      <CardTitle className="flex items-center gap-2"><Sparkles className="h-4 w-4" /> Connect Claude (AI reports)</CardTitle>
      <CardDescription>
        Enable full AI-written reports. Your key is stored encrypted and sent only to Anthropic to compose the report from the already-sanitized findings; nothing leaves the server until you connect.
      </CardDescription>
    </CardHeader>
    <CardContent className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {status?.configured
          ? <Badge className="bg-emerald-500/15 text-emerald-500">Connected · {status.kind === "auth_token" ? "OAuth token" : "API key"}{status.source === "environment" ? " (environment)" : ""}</Badge>
          : <Badge variant="outline">Not connected</Badge>}
      </div>

      {envManaged ? (
        <p className="text-sm text-muted-foreground">A credential is set from the environment (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN). Unset it to manage the connection here.</p>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-[180px_1fr]">
            <div className="space-y-1">
              <Label htmlFor="ai-kind">Credential type</Label>
              <select id="ai-kind" className="w-full rounded-md border bg-background p-2 text-sm" value={kind} onChange={(e) => setKind(e.target.value as "api_key" | "auth_token")}>
                <option value="api_key">API key (console.anthropic.com)</option>
                <option value="auth_token">Claude Code OAuth token</option>
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="ai-value">{kind === "api_key" ? "API key" : "OAuth token"}</Label>
              <Input id="ai-value" type="password" autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} placeholder={kind === "api_key" ? "sk-ant-…" : "paste `ant auth print-credentials --access-token`"} />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" onClick={() => void connect()} disabled={busy || !value.trim()}>{busy ? "Connecting…" : status?.configured ? "Replace credential" : "Connect"}</Button>
            {status?.configured && <Button type="button" variant="outline" size="sm" onClick={() => void disconnect()} disabled={busy}>Disconnect</Button>}
          </div>
          <p className="text-xs text-muted-foreground">Reports download at <span className="font-mono">/api/report/&lt;scan&gt;?format=ai</span>. An API key bills to that key; an OAuth token uses your Claude subscription but is short-lived.</p>
        </>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}
    </CardContent>
  </Card>;
}
