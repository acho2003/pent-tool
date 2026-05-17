import { Link } from "react-router-dom";
import { Loader2, Menu, Plus, Search, StopCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ConnectionStatus } from "@/components/connection-status";
import { useStatus, useInstances, useStopAll } from "@/api/queries";
import { useCommandPalette } from "@/components/command-palette";

export function Topbar({ onMenuToggle }: { onMenuToggle?: () => void }) {
  const { data: status } = useStatus();
  const { data: instances } = useInstances();
  const stopAll = useStopAll();
  const palette = useCommandPalette();

  const running =
    status?.running_instances ?? (status?.running ? 1 : 0);
  const activeInst = instances?.instances?.find(
    (i) => i.id === status?.instance_id,
  );

  return (
    <header className="flex h-14 items-center gap-2 border-b border-border bg-background/80 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <button
        type="button"
        onClick={onMenuToggle}
        className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground hover:text-foreground md:hidden"
        aria-label="Toggle menu"
      >
        <Menu className="h-5 w-5" />
      </button>
      <button
        type="button"
        onClick={() => palette.setOpen(true)}
        className="group inline-flex h-8 flex-1 items-center gap-2 rounded-md border border-border bg-card px-2.5 text-xs text-muted-foreground hover:text-foreground transition-colors md:flex-none md:min-w-72"
        aria-label="Open command palette"
      >
        <Search className="h-3.5 w-3.5 shrink-0" />
        <span className="hidden sm:inline truncate">Search scans, findings, actions…</span>
        <span className="sm:hidden truncate">Search…</span>
        <kbd className="ml-auto hidden sm:inline rounded-sm border border-border bg-muted px-1 py-0.5 text-[10px] mono">
          Ctrl K
        </kbd>
      </button>

      {activeInst ? (
        <Link
          to={`/scans/${activeInst.id}`}
          className="hidden md:flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/5 px-2.5 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10 transition-colors"
        >
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 pulse-dot" />
          <span className="mono truncate max-w-64">
            Scanning {activeInst.name || activeInst.targets.split(",")[0]}
          </span>
        </Link>
      ) : (
        running > 0 && (
          <span className="hidden md:inline-flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-2.5 py-1 text-xs text-amber-300">
            <Loader2 className="h-3 w-3 animate-spin" /> {running} active scan
            {running > 1 ? "s" : ""}
          </span>
        )
      )}

      <div className="ml-auto flex items-center gap-2">
        <ConnectionStatus />
        {running > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => stopAll.mutate()}
            disabled={stopAll.isPending}
            className="hidden sm:inline-flex text-red-400 hover:text-red-300"
          >
            <StopCircle className="h-3.5 w-3.5" />
            Stop all
          </Button>
        )}
        <Button asChild size="sm">
          <Link to="/scans/new">
            <Plus className="h-3.5 w-3.5" /> <span className="hidden sm:inline">New Scan</span>
          </Link>
        </Button>
      </div>
    </header>
  );
}
