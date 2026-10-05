import { useCallback, useEffect, useState } from "react";
import { api, HttpError } from "@/api/client";
import { Button } from "@/components/ui/button";

const PAGE_BYTES = 65536;

// Scanner output is untrusted terminal text. React escapes HTML; strip ANSI
// control sequences so scanners cannot move the cursor or create OSC links.
function displayText(raw: string): string {
  return raw
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "")
    .replace(/\r/g, "\n");
}

type Stream = "combined" | "stdout" | "stderr";

function TerminalStream({ scanId, scanner, scope, attemptId, stream, running, onMissing }: {
  scanId: string; scanner: string; scope?: string; attemptId?: string; stream: Stream; running: boolean; onMissing?: () => void;
}) {
  const [page, setPage] = useState({ text: "", start: 0, next: 0, total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [following, setFollowing] = useState(true);

  useEffect(() => {
    let active = true;
    setPage({ text: "", start: 0, next: 0, total: 0 });
    setLoading(true);
    setError("");
    setFollowing(true);
    void (async () => {
      try {
        const probe = await api.scannerOutputChunk(scanId, scanner, stream, scope, 0, 1, attemptId);
        const start = Math.max(0, probe.total - PAGE_BYTES);
        const chunk = await api.scannerOutputChunk(scanId, scanner, stream, scope, start, PAGE_BYTES, attemptId);
        if (active) setPage(chunk);
      } catch (e) {
        if (!active) return;
        if (e instanceof HttpError && e.status === 404 && onMissing) onMissing();
        else setError(e instanceof Error ? e.message : "Output unavailable");
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, [scanId, scanner, scope, attemptId, stream, onMissing]);

  useEffect(() => {
    if (!running || !following || loading || error) return;
    let active = true;
    const timer = window.setInterval(() => {
      void api.scannerOutputChunk(scanId, scanner, stream, scope, page.next, PAGE_BYTES, attemptId)
        .then((chunk) => {
          if (!active || chunk.next === page.next) return;
          setPage((prev) => {
            const text = prev.text + chunk.text;
            const trimmed = text.length > PAGE_BYTES * 2 ? text.slice(-PAGE_BYTES * 2) : text;
            return { text: trimmed, start: chunk.next - trimmed.length, next: chunk.next, total: chunk.total };
          });
        })
        .catch((e) => { if (active) setError(e instanceof Error ? e.message : "Output unavailable"); });
    }, 1000);
    return () => { active = false; window.clearInterval(timer); };
  }, [scanId, scanner, scope, attemptId, stream, running, following, loading, error, page.next]);

  async function show(offset: number, follow: boolean) {
    setLoading(true);
    setError("");
    try {
      const chunk = await api.scannerOutputChunk(scanId, scanner, stream, scope, offset, PAGE_BYTES, attemptId);
      setPage(chunk);
      setFollowing(follow);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Output unavailable");
    } finally {
      setLoading(false);
    }
  }

  return <div className="space-y-2">
    {stream !== "combined" && <p className="text-xs font-medium text-muted-foreground">{stream}</p>}
    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
      <span>{page.total ? `${page.start + 1}–${page.next} of ${page.total} recorded bytes` : "No output recorded"}</span>
      {page.start > 0 && <Button size="sm" variant="outline" onClick={() => void show(Math.max(0, page.start - PAGE_BYTES), false)}>Older output</Button>}
      {page.next < page.total && <Button size="sm" variant="outline" onClick={() => void show(page.next, false)}>Newer output</Button>}
      {!following && <Button size="sm" variant="outline" onClick={() => void show(Math.max(0, page.total - PAGE_BYTES), true)}>Follow latest</Button>}
    </div>
    {error && <p className="text-xs text-destructive">{error}</p>}
    <pre className="max-h-[32rem] min-h-48 overflow-auto whitespace-pre-wrap break-words rounded-md bg-background p-4 font-mono text-xs text-foreground">{loading ? "Loading…" : displayText(page.text) || "No output recorded."}</pre>
  </div>;
}

export function ScannerTerminal({ scanId, scanner, scope, attemptId, status, reason, truncated }: {
  scanId: string; scanner: string; scope?: string; attemptId?: string; status: string; reason?: string; truncated?: boolean;
}) {
  const [legacy, setLegacy] = useState(false);
  useEffect(() => setLegacy(false), [scanId, scanner, scope, attemptId]);
  const missing = useCallback(() => setLegacy(true), []);
  return <div className="space-y-3">
    <p className="text-xs text-muted-foreground">Status: <span className="text-foreground">{status.replaceAll("_", " ")}</span>{reason ? ` — ${reason}` : ""}</p>
    {truncated && <p className="text-xs text-amber-400">Output reached the configured size limit; this transcript is incomplete.</p>}
    {legacy ? <>
      <p className="text-xs text-muted-foreground">Older scan: stdout and stderr were saved separately, so their original order is unavailable.</p>
      <TerminalStream scanId={scanId} scanner={scanner} scope={scope} attemptId={attemptId} stream="stdout" running={status === "running"} />
      <TerminalStream scanId={scanId} scanner={scanner} scope={scope} attemptId={attemptId} stream="stderr" running={status === "running"} />
    </> : <TerminalStream scanId={scanId} scanner={scanner} scope={scope} attemptId={attemptId} stream="combined" running={status === "running"} onMissing={missing} />}
  </div>;
}
