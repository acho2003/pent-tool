import { useEffect, useState } from "react";
import { ExternalLink, Sparkles } from "lucide-react";
import { api } from "@/api/client";
import type { AIConnectionStatus } from "@/types/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

const KEYS_URL = "https://console.anthropic.com/settings/keys";

// Connect Claude for AI-written reports. One step: log in to Anthropic to get a
// key, paste it, connected. The key is stored encrypted on the server and never
// returned; only connection status is shown here.
export function AIConnectionSetup() {
  const [status, setStatus] = useState<AIConnectionStatus | null>(null);
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.aiConnection().then(setStatus).catch(() => setStatus({ configured: false }));
  }, []);

  async function connect() {
    if (!value.trim()) { setError("Paste your Claude API key."); return; }
    setBusy(true); setError(null);
    try {
      setStatus(await api.setAIConnection("api_key", value.trim()));
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
      <CardTitle className="flex items-center gap-2"><Sparkles className="h-4 w-4" /> Connect Claude</CardTitle>
      <CardDescription>
        Turn on full AI-written reports. Your key is stored encrypted and used only to compose the report from the already-sanitized findings.
      </CardDescription>
    </CardHeader>
    <CardContent className="space-y-4">
      <div>
        {status?.configured
          ? <Badge className="bg-emerald-500/15 text-emerald-500">Connected{status.source === "environment" ? " (environment)" : ""}</Badge>
          : <Badge variant="outline">Not connected</Badge>}
      </div>

      {envManaged ? (
        <p className="text-sm text-muted-foreground">A credential is set from the environment (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN). Unset it to manage the connection here.</p>
      ) : status?.configured ? (
        <Button type="button" variant="outline" size="sm" onClick={() => void disconnect()} disabled={busy}>Disconnect</Button>
      ) : (
        <div className="space-y-3">
          <Button type="button" variant="outline" size="sm" onClick={() => window.open(KEYS_URL, "_blank", "noopener")}>
            <ExternalLink className="h-4 w-4" /> Log in to Anthropic &amp; create a key
          </Button>
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-0 flex-1 space-y-1">
              <Input type="password" autoComplete="new-password" value={value} onChange={(e) => setValue(e.target.value)} placeholder="Paste your key (sk-ant-…)" onKeyDown={(e) => { if (e.key === "Enter") void connect(); }} />
            </div>
            <Button type="button" size="sm" onClick={() => void connect()} disabled={busy || !value.trim()}>{busy ? "Connecting…" : "Connect"}</Button>
          </div>
          <p className="text-xs text-muted-foreground">Billed to that key. (An advanced ANTHROPIC_AUTH_TOKEN env var also works for a Claude subscription, but is short-lived.)</p>
        </div>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}
    </CardContent>
  </Card>;
}
