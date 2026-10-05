import { WorkflowProof, EndpointTraceDialog } from "@/components/workflow-proof";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { SeverityBadge } from "@/components/severity-badge";
import { Markdown } from "@/components/markdown";
import { VerificationBadge } from "@/components/verification-badge";
import { PhaseProgress, PHASES } from "@/components/phase-progress";
import { CopyButton } from "@/components/copy-button";
import { ErrorState, EmptyState } from "@/components/states";
import {
  useScan,
  useStopInstance,
  useStartSavedInstance,
  useDeleteScan,
  useDeleteVuln,
} from "@/api/queries";
import { api } from "@/api/client";
import {
  filterEventsForInstance,
  mergeFeedEvents,
  toFeedEvent,
  useWSStore,
  type FeedEvent,
} from "@/store/ws";
import {
  timeAgo,
  formatTime,
  formatDuration,
  severityRank,
  normalizeSeverity,
  cn,
  menuContentClass,
  menuItemClass,
} from "@/lib/utils";
import {
  ChevronLeft,
  ChevronDown,
  ChevronRight,
  Download,
  ExternalLink,
  MoreHorizontal,
  X,
  Play,
  Trash2,
  ShieldAlert,
  Terminal,
  ListChecks,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import { LiveFeed, type FeedFilter } from "@/components/live-feed";
import { ScannerTerminal } from "@/components/scanner-terminal";
import { Pagination, DEFAULT_PAGE_SIZE } from "@/components/Pagination";
import type { AttackSurfaceEndpoint, ScanRecord, ReportScope, ScopeRun, SubScanSummary, VulnSummary } from "@/types/api";

export default function ScanDetailPage() {
  const navigate = useNavigate();
  const { scanId } = useParams<{ scanId: string }>();
  const id = scanId ?? "";
  const { data: scan, isLoading, isFetching, error, refetch } = useScan(id);
  const stop = useStopInstance();
  const start = useStartSavedInstance();
  const del = useDeleteScan();
  const subscribe = useWSStore((s) => s.subscribe);
  const unsubscribe = useWSStore((s) => s.unsubscribe);
  const liveEvents = useWSStore((s) => s.events);
  const subscriptionId = scan?.instance_id || scan?.id || id;

  useEffect(() => {
    if (!subscriptionId) return;
    subscribe(subscriptionId);
    return () => unsubscribe();
  }, [subscriptionId, subscribe, unsubscribe]);

  if (error)
    return (
      <ErrorState
        title="Could not load scan"
        description={error instanceof Error ? error.message : "Unknown error"}
        action={
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            Retry
          </Button>
        }
      />
    );
  if (isLoading) return <ScanDetailSkeleton />;
  if (!scan)
    return (
      <ErrorState
        title="Scan details are starting"
        description={
          isFetching
            ? "Waiting for the running scan record to become available."
            : "The scan route is open, but the backend has not returned the scan record yet."
        }
        action={
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            Retry
          </Button>
        }
      />
    );
	if ((scan.schema_version ?? 0) >= 2) {
		return <DeterministicScanDetail key={scan.id} scan={scan} />;
	}

  const status = (scan.status || "").toLowerCase();
  const canStop = status === "running" || status === "paused";
  const canStart =
    status === "saved" ||
    status === "stopped" ||
    status === "failed" ||
    status === "finished";

  // Combine persisted events from the scan record with the live websocket
  // feed for this instance, deduped by content.
  const eventInstanceId = scan.instance_id || scan.id || id;
  const wsForScan = filterEventsForInstance(liveEvents, eventInstanceId);
  const persistedAsFeed: FeedEvent[] = (scan.events ?? []).map((e, i) =>
    toFeedEvent(e, `scan:${eventInstanceId}`, i),
  );
  const mergedEvents = mergeFeedEvents(persistedAsFeed, wsForScan);

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/scans"
          className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground"
        >
          <ChevronLeft className="mr-1 h-3 w-3" />
          All scans
        </Link>
      </div>

      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2 min-w-0 flex-1">
          <div className="flex items-center gap-3 min-w-0">
            <h1 className="font-mono text-xl sm:text-2xl font-semibold tracking-tight text-foreground truncate min-w-0">
              {scan.target}
            </h1>
            <CopyButton value={scan.target} />
          </div>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
            <span className="mono truncate max-w-full">{scan.id}</span>
            <span className="hidden sm:inline">·</span>
            <span>Started {timeAgo(scan.started_at)}</span>
            <span className="hidden sm:inline">·</span>
            <span>
              Duration {formatDuration(scan.started_at, scan.finished_at)}
            </span>
            {scan.scan_mode && (
              <>
                <span className="hidden sm:inline">·</span>
                <Badge variant="outline" className="font-normal capitalize">
                  {scan.scan_mode}
                </Badge>
              </>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <ScanStatusPill status={scan.status} />
          <Button variant="outline" size="sm" asChild>
            <a href={api.reportUrl(scan.id)} target="_blank" rel="noreferrer">
              <Download className="mr-1 h-4 w-4" /> Report
            </a>
          </Button>
          {canStart && (
            <Button
              variant="outline"
              size="sm"
              onClick={() =>
                // Instance-action endpoints key off the instance id, which for
                // wildcard scans differs from the scan record id (scan.id).
                start.mutate(scan.instance_id || scan.id, {
                  onSuccess: (res) => {
                    if (res.instance_id) {
                      navigate(`/scans/${res.instance_id}`);
                    } else {
                      void refetch();
                    }
                  },
                })
              }
              disabled={start.isPending}
            >
              <Play className="mr-1 h-4 w-4" /> Start
            </Button>
          )}
          {canStop && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => stop.mutate(scan.instance_id || scan.id)}
              disabled={stop.isPending}
            >
              <X className="mr-1 h-4 w-4" /> Stop
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              if (
                window.confirm(
                  "Permanently delete this scan and all its events?",
                )
              ) {
                del.mutate(scan.id, {
                  onSuccess: () => {
                    navigate("/scans", { replace: true });
                  },
                });
              }
            }}
            disabled={del.isPending}
          >
            <Trash2 className="mr-1 h-4 w-4" /> Delete
          </Button>
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm">Phase progress</CardTitle>
            <CardDescription>
			  Legacy scan methodology ({PHASES.length} phases).
              Currently:{" "}
              <span className="text-foreground">
                {currentPhaseLabel(scan.current_phase)}
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <PhaseProgress
              current={scan.current_phase}
              selected={scan.phases}
              status={scan.status}
            />
            {/* Responsive phase-tile grid. Cells use a min-width
                template so 22 short tiles flow into rows that fit the
                viewport instead of cramming 5 wide cells into 800 px
                of card space. */}
            <div className="grid grid-cols-[repeat(auto-fill,minmax(140px,1fr))] gap-2">
              {PHASES.map((p) => (
                <div
                  key={p.id}
                  className={cn(
                    "flex items-baseline gap-1.5 rounded-md border border-border bg-muted/20 px-2 py-1.5 text-[11px]",
                    scan.current_phase === p.id &&
                      "border-amber-400/50 text-amber-300",
                  )}
                >
                  <span className="mono shrink-0 text-muted-foreground">
                    {p.id}
                  </span>
                  <span className="truncate" title={p.name}>
                    {p.name}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Risk overview</CardTitle>
            <CardDescription>
              {(scan.vulns ?? []).length} findings
            </CardDescription>
          </CardHeader>
          <CardContent>
            <RiskBreakdown vulns={scan.vulns ?? []} />
          </CardContent>
        </Card>

        {!!scan.sub_scan_total && (
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-sm">Wildcard coverage</CardTitle>
              <CardDescription>
                {scan.sub_scan_completed ?? 0} scanned ·{" "}
                {scan.sub_scan_running ?? 0} running ·{" "}
                {scan.sub_scan_remaining ?? 0} remaining
              </CardDescription>
            </CardHeader>
            <CardContent>
              <SubdomainProgress
                completed={scan.sub_scan_completed ?? 0}
                running={scan.sub_scan_running ?? 0}
                remaining={scan.sub_scan_remaining ?? 0}
                total={scan.sub_scan_total ?? 0}
              />
            </CardContent>
          </Card>
        )}
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            Findings
          </TabsTrigger>
          <TabsTrigger value="events">
            <Terminal className="mr-1.5 h-3.5 w-3.5" />
            Activity & logs
          </TabsTrigger>
          {!!scan.sub_scan_total && (
            <TabsTrigger value="subdomains">
              <ListChecks className="mr-1.5 h-3.5 w-3.5" />
              Subdomains
            </TabsTrigger>
          )}
          <TabsTrigger value="config">
            <ListChecks className="mr-1.5 h-3.5 w-3.5" />
            Configuration
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-2">
          <FindingsTab vulns={scan.vulns ?? []} scanId={scan.id} />
        </TabsContent>
        <TabsContent value="events">
		  <EventsTab
			events={mergedEvents}
			scanId={scan.id}
			target={scan.target}
          />
        </TabsContent>
        {!!scan.sub_scan_total && (
          <TabsContent value="subdomains">
            <SubdomainsTab subScans={scan.sub_scans ?? []} />
          </TabsContent>
        )}
        <TabsContent value="config">
          <ConfigTab scan={scan} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

type RunKey = { scanner: string; scope: string; attemptId?: string };
const sameKey = (a: RunKey | null, b: RunKey) => !!a && a.scanner === b.scanner && a.scope === b.scope && a.attemptId === b.attemptId;
const keyOf = (r: ScopeRun, fallbackScope: string): RunKey => ({ scanner: r.scanner, scope: r.scope || fallbackScope, attemptId: r.attempt_id });
const ATTENTION = new Set(["failed", "running", "cancelled"]);
const TERMINAL_RUN = new Set(["completed", "failed", "cancelled", "not_applicable", "skipped"]);

type ScanProgress = { percent: number; done: number; running: number; total: number };

// Overall completion: finished jobs plus each running job's own reported
// progress, over the planned (selected/conditional) jobs. Running jobs with no
// native progress signal count only once they finish, so this never overstates.
function computeScanProgress(scan: ScanRecord): ScanProgress | null {
	const runs = scan.scanner_runs ?? [];
	const jobs = (scan.assessment_plan?.jobs ?? []).filter((job) => job.state === "selected" || job.state === "conditional");
	const units = jobs.length
		? jobs.map((job) => runs.find((run) => run.scanner === job.scanner && (run.target === job.target || run.scope === job.target) && (!run.variant || !job.variant || run.variant === job.variant)))
		: runs;
	if (!units.length) return null;
	let done = 0, running = 0, partial = 0;
	for (const run of units) {
		if (run && TERMINAL_RUN.has(run.status)) done++;
		else if (run?.status === "running") {
			running++;
			partial += Math.min(Math.max(run.progress ?? 0, 0), 99) / 100;
		}
	}
	const finished = scan.status === "completed" || scan.status === "finished";
	const percent = finished ? 100 : Math.min(99, Math.floor(((done + partial) / units.length) * 100));
	return { percent, done, running, total: units.length };
}

function liveRunProgress(run?: { status?: string; progress?: number; progress_stage?: string }): { percent: number; stage: string } | null {
	if (!run || run.status !== "running" || run.progress == null) return null;
	return { percent: Math.min(Math.max(run.progress, 0), 100), stage: run.progress_stage || "progress" };
}

function ScanProgressBar({ progress }: { progress: ScanProgress }) {
	return <div className="space-y-2 rounded-lg border p-4" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress.percent}>
		<div className="flex flex-wrap items-baseline justify-between gap-2"><p className="text-sm font-medium">Progress <span className="font-mono">{progress.percent}%</span></p><p className="text-xs text-muted-foreground">{progress.done} of {progress.total} scanner job{progress.total === 1 ? "" : "s"} done{progress.running ? ` · ${progress.running} running` : ""}</p></div>
		<div className="h-2 overflow-hidden rounded-sm bg-muted"><div className="h-full bg-success transition-[width] duration-500" style={{ width: `${progress.percent}%` }} /></div>
	</div>;
}

function RunProgress({ live }: { live: { percent: number; stage: string } }) {
	return <div className="mt-2 space-y-1"><p className="text-[11px] text-muted-foreground">{live.stage} <span className="font-mono text-foreground">{live.percent}%</span></p><div className="h-1 overflow-hidden rounded-sm bg-muted"><div className="h-full bg-warning transition-[width] duration-500" style={{ width: `${live.percent}%` }} /></div></div>;
}

function scopeHeading(sc: ReportScope): string {
	if (sc.kind === "source") return `SOURCE CODE  ${sc.origin || sc.target || "none provided"}`;
	return `HOST  ${sc.target || sc.id.replace(/^host:/, "")}`;
}

// Scanner-group display order + labels (mirrors the backend registry Group).
const RUN_GROUP_ORDER = ["web_api", "network_servers", "cloud", "kubernetes", "code"];
const RUN_GROUP_LABELS: Record<string, string> = {
	web_api: "Web & API",
	network_servers: "Network & servers",
	cloud: "Cloud",
	kubernetes: "Kubernetes",
	code: "Source, dependencies & containers",
};
const runGroupLabel = (g: string) => RUN_GROUP_LABELS[g] ?? (g || "Other");

function DeterministicScanDetail({ scan }: { scan: ScanRecord }) {
	const [picked, setPicked] = useState<RunKey | null>(null);
	const [openState, setOpenState] = useState<Record<string, boolean>>({});
	const [inactiveRun, setInactiveRun] = useState<{ scanner: string; scope: string; attemptId?: string; lastActivity: number } | null>(null);
	const stopScan = useStopInstance();
	const runsRef = useRef(scan.scanner_runs ?? []);
	const activityRef = useRef(new Map<string, { at: number; signature: string; bytes?: number }>());
	const promptedRef = useRef(new Set<string>());
	runsRef.current = scan.scanner_runs ?? [];
	useEffect(() => {
		const now = Date.now();
		const running = new Set<string>();
		for (const run of scan.scanner_runs ?? []) {
			if (run.status !== "running") continue;
			const key = `${run.scanner}|${run.attempt_id ?? run.scope ?? run.target}`;
			running.add(key);
			const signature = `${run.progress ?? ""}|${run.progress_stage ?? ""}|${run.last_activity_at ?? ""}`;
			const current = activityRef.current.get(key);
			if (!current || current.signature !== signature) activityRef.current.set(key, { at: run.last_activity_at ? Date.parse(run.last_activity_at) : now, signature, bytes: current?.bytes });
		}
		for (const key of activityRef.current.keys()) if (!running.has(key)) {
			activityRef.current.delete(key);
			promptedRef.current.delete(key);
		}
	}, [scan.scanner_runs]);
	useEffect(() => {
		let active = true;
		const check = async () => {
			for (const run of runsRef.current) {
				if (!active || run.status !== "running") continue;
				const key = `${run.scanner}|${run.attempt_id ?? run.scope ?? run.target}`;
				let activity = activityRef.current.get(key);
				if (!activity) {
					activity = { at: run.last_activity_at ? Date.parse(run.last_activity_at) : Date.now(), signature: `${run.progress ?? ""}|${run.progress_stage ?? ""}` };
					activityRef.current.set(key, activity);
				}
				try {
					const output = await api.scannerOutputChunk(scan.id, run.scanner, "combined", run.scope || undefined, 0, 1, run.attempt_id);
					if (!active) return;
					if (activity.bytes === undefined) activity.bytes = output.total;
					else if (activity.bytes !== output.total) {
						activity.bytes = output.total;
						activity.at = Date.now();
						promptedRef.current.delete(key);
					}
				} catch { /* Old scans may not retain a combined transcript. */ }
				if (Date.now() - activity.at >= 10 * 60 * 1000 && !promptedRef.current.has(key)) {
					promptedRef.current.add(key);
					setInactiveRun({ scanner: run.scanner, scope: run.scope ?? run.target, attemptId: run.attempt_id, lastActivity: activity.at });
					return;
				}
			}
		};
		const timer = window.setInterval(() => void check(), 60_000);
		return () => { active = false; window.clearInterval(timer); };
	}, [scan.id]);
	// Refetch the grouping whenever any run is added or changes status.
	const runsSignature = useMemo(() => (scan.scanner_runs ?? []).map((r) => `${r.scope ?? ""}|${r.scanner}|${r.status}`).join(","), [scan.scanner_runs]);
	const scopesQuery = useQuery({ queryKey: ["scan-scopes", scan.id, runsSignature], queryFn: () => api.scanScopes(scan.id), placeholderData: (prev) => prev });
	const coverageQuery = useQuery({ queryKey: ["assessment-coverage", scan.id, runsSignature], queryFn: () => api.assessmentCoverage(scan.id), enabled: !!scan.id, placeholderData: (prev) => prev });
	const registryQuery = useQuery({ queryKey: ["scanner-registry-groups"], queryFn: api.scannerRegistry, staleTime: 60000 });
	const groupOf = useMemo(() => {
		const m: Record<string, string> = {};
		for (const d of registryQuery.data?.scanners ?? []) m[d.id] = d.group;
		return (id: string) => m[id] ?? "";
	}, [registryQuery.data]);
	const recon = scopesQuery.data?.recon ?? [];
	const scopes = scopesQuery.data?.scopes ?? [];
	const hostCount = scopes.filter((s) => s.kind !== "source").length;
	const firstKey = useMemo<RunKey | null>(() => {
		if (recon[0]) return keyOf(recon[0], "");
		const sc = scopes.find((s) => s.runs.length);
		return sc ? keyOf(sc.runs[0], sc.id) : null;
	}, [recon, scopes]);
	const pickedPresent = useMemo(() => {
		if (!picked) return false;
		if (recon.some((x) => sameKey(picked, keyOf(x, "")))) return true;
		return scopes.some((sc) => sc.runs.some((x) => sameKey(picked, keyOf(x, sc.id))));
	}, [picked, recon, scopes]);
	const selected = picked && pickedPresent ? picked : firstKey;
	const located = useMemo(() => {
		if (!selected) return null;
		const r = recon.find((x) => sameKey(selected, keyOf(x, "")));
		if (r) return { run: r, label: "recon" };
		for (const sc of scopes) {
			const hit = sc.runs.find((x) => sameKey(selected, keyOf(x, sc.id)));
			if (hit) return { run: hit, label: scopeHeading(sc).replace(/\s+/g, " ").toLowerCase() };
		}
		return null;
	}, [selected, recon, scopes]);
	// The default-open decision (few hosts, or a scope needing attention) is only
	// meaningful the first time a scope is seen — otherwise an untoggled section
	// would open and close on its own as runs change status underneath it. Snapshot
	// it into openState once per scope id; isOpen only falls back to recomputing it
	// for the render(s) before this effect has run.
	const defaultOpen = (sc: ReportScope) => sc.kind === "source" || hostCount <= 3 || sc.runs.some((r) => ATTENTION.has(r.status));
	useEffect(() => {
		setOpenState((prev) => {
			let changed = false;
			const next = { ...prev };
			for (const sc of scopes) {
				if (!(sc.id in prev)) {
					next[sc.id] = defaultOpen(sc);
					changed = true;
				}
			}
			return changed ? next : prev;
		});
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [scopes, hostCount]);
	const isOpen = (sc: ReportScope) => openState[sc.id] ?? defaultOpen(sc);
	const scanProgress = useMemo(() => computeScanProgress(scan), [scan]);
	// Re-parse the scan's sealed scanner output into findings (e.g. after a
	// parser fix). Artifacts are only read, never rewritten.
	const queryClient = useQueryClient();
	const stopScanner = useMutation({
		mutationFn: (attemptId: string) => api.stopScannerRun(scan.id, attemptId),
		onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ["scan", scan.id] }); },
	});
	const reimport = useMutation({
		mutationFn: () => api.rebuildScanFindings(scan.id),
		onSuccess: () => { void queryClient.invalidateQueries(); },
	});
	const scanFinished = ["completed", "finished", "failed", "cancelled", "stopped"].includes(scan.status);
	// Scope runs refetch only on status changes; live progress comes from the
	// scan record, which polls every few seconds while running.
	const liveRun = (scanner: string, scope: string) => (scan.scanner_runs ?? []).find((run) => run.scanner === scanner && (run.scope ?? "") === scope);
	const cards = (runs: ScopeRun[], fallbackScope: string) => <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">{runs.map((r) => {
		const k = keyOf(r, fallbackScope);
		return <ScannerStatusCard key={`${k.scope}|${k.scanner}|${k.attemptId ?? ""}`} name={r.scanner} run={r} live={liveRunProgress(liveRun(k.scanner, k.scope))} active={sameKey(selected, k)} onClick={() => setPicked(k)} onStop={(attemptId) => stopScanner.mutate(attemptId)} stopping={stopScanner.isPending ? stopScanner.variables : undefined} />;
	})}</div>;
	// Render a scope's runs grouped by scanner group (web/network/cloud/k8s/code),
	// each under a small subheader. A single group falls back to a flat grid.
	const grid = (runs: ScopeRun[], fallbackScope: string) => {
		const present = [...RUN_GROUP_ORDER, ...[...new Set(runs.map((r) => groupOf(r.scanner)))].filter((g) => !RUN_GROUP_ORDER.includes(g))].filter((g) => runs.some((r) => groupOf(r.scanner) === g));
		if (present.length <= 1) return cards(runs, fallbackScope);
		return <div className="space-y-3">{present.map((g) => <div key={g} className="space-y-2"><p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{runGroupLabel(g)}</p>{cards(runs.filter((r) => groupOf(r.scanner) === g), fallbackScope)}</div>)}</div>;
	};
	return <div className="space-y-6">
		{stopScanner.isError && <p role="alert" className="text-sm text-destructive">Could not stop scanner: {stopScanner.error.message}</p>}
		<Dialog open={!!inactiveRun} onOpenChange={(open) => { if (!open && inactiveRun) activityRef.current.set(`${inactiveRun.scanner}|${inactiveRun.attemptId ?? inactiveRun.scope}`, { at: Date.now(), signature: "" }); setInactiveRun(open ? inactiveRun : null); }}>
			<DialogContent>
				<DialogHeader><DialogTitle>Scanner has shown no progress</DialogTitle><DialogDescription>{inactiveRun?.scanner} at {inactiveRun?.scope} has produced no new output or progress updates for 10 minutes. Last activity: {inactiveRun ? formatTime(new Date(inactiveRun.lastActivity).toISOString()) : "unknown"}. Stop this scanner, or keep it running?</DialogDescription></DialogHeader>
				<DialogFooter><Button variant="outline" onClick={() => { if (inactiveRun) activityRef.current.set(`${inactiveRun.scanner}|${inactiveRun.attemptId ?? inactiveRun.scope}`, { at: Date.now(), signature: "" }); setInactiveRun(null); }}>Keep running</Button>{inactiveRun?.attemptId && <Button variant="destructive" disabled={stopScanner.isPending} onClick={() => { stopScanner.mutate(inactiveRun.attemptId!); setInactiveRun(null); }}>Stop this scanner</Button>}<Button variant="destructive" disabled={stopScan.isPending} onClick={() => { stopScan.mutate(scan.instance_id || scan.id); setInactiveRun(null); }}>{stopScan.isPending ? "Stopping…" : "Stop assessment"}</Button></DialogFooter>
			</DialogContent>
		</Dialog>
		<Link to="/scans" className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground"><ChevronLeft className="mr-1 h-3 w-3" /> All scans</Link>
		<header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div><h1 className="font-mono text-2xl font-semibold">{scan.target}</h1><div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground"><span>{scan.id}</span><span>·</span><span>{formatDuration(scan.started_at, scan.finished_at)}</span><Badge variant="outline">schema v{scan.schema_version ?? 2}</Badge>{scan.assessment && <><Badge variant="outline">{scan.assessment.assessment_mode.replaceAll("_", " ")}</Badge><Badge variant="outline">{scan.profile || scan.assessment.profile || "web-gentle"}</Badge></>}</div></div><div className="flex flex-wrap items-center gap-2"><ScanStatusPill status={scan.status} />{scanFinished && <Button variant="outline" size="sm" disabled={reimport.isPending} onClick={() => reimport.mutate()} title="Re-read this scan's saved scanner output into findings"><RefreshCw className={cn("mr-1 h-4 w-4", reimport.isPending && "animate-spin")} /> {reimport.isPending ? "Re-importing…" : "Re-import findings"}</Button>}<Button variant="outline" size="sm" asChild><a href={api.reportUrl(scan.id)} target="_blank" rel="noreferrer"><Download className="mr-1 h-4 w-4" /> Report</a></Button></div></header>
		{reimport.isSuccess && <p className="text-xs text-emerald-300">Findings re-imported from the saved scanner output.</p>}
		{reimport.isError && <p role="alert" className="text-xs text-destructive">Could not re-import findings: {reimport.error instanceof Error ? reimport.error.message : "unknown error"}</p>}
		{scanProgress && !["completed", "finished", "failed", "cancelled", "stopped"].includes(scan.status) && <ScanProgressBar progress={scanProgress} />}
		{scan.assessment && coverageQuery.data && <Card><CardHeader><CardTitle className="text-sm">Assessment coverage · {coverageQuery.data.state}</CardTitle><CardDescription>Requested types, scanner job outcomes, and remaining coverage gaps.</CardDescription></CardHeader><CardContent className="space-y-4">
			{coverageQuery.data.reason && <p className="text-xs text-muted-foreground">{coverageQuery.data.reason}</p>}
			<div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{(coverageQuery.data.type_coverage ?? []).map((item) => <div key={item.type} className="rounded-md border p-3"><p className="text-xs font-medium">{item.type.replaceAll("_", " ")} · {item.state}</p><p className="mt-1 text-xs text-muted-foreground">{item.reason}</p></div>)}</div>
			{(coverageQuery.data.capabilities ?? []).length > 0 && <div><p className="mb-2 text-xs font-medium">Access and capabilities</p><div className="space-y-1">{coverageQuery.data.capabilities?.map((item, index) => <p key={`${item.target_id}-${item.capability}-${index}`} className="text-xs text-muted-foreground"><span className="font-mono text-foreground">{item.target_id || "assessment"} · {item.capability} · {item.state}</span> — {item.reason}</p>)}</div></div>}
			{(coverageQuery.data.gaps ?? []).length > 0 && <div><p className="mb-2 text-xs font-medium">Coverage gaps</p><div className="space-y-2">{coverageQuery.data.gaps?.map((gap, index) => <div key={`${gap.scanner}-${gap.target_id}-${index}`} className="border-l-2 pl-3"><p className="text-xs font-medium">{gap.scanner} · {gap.state} · {gap.reason_code}</p><p className="text-xs text-muted-foreground">{gap.reason}</p></div>)}</div></div>}
			{coverageQuery.data.api_operation_counts && <p className="text-xs text-muted-foreground">API operations: {coverageQuery.data.api_operation_counts.discovered} discovered · {coverageQuery.data.api_operation_counts.eligible} eligible · {coverageQuery.data.api_operation_counts.attempted} attempted · {coverageQuery.data.api_operation_counts.completed} completed · {coverageQuery.data.api_operation_counts.batch_completed} batch completed · {coverageQuery.data.api_operation_counts.failed} failed · {coverageQuery.data.api_operation_counts.skipped} skipped · {coverageQuery.data.api_operation_counts.not_attempted} not attempted</p>}{(coverageQuery.data.api_operations ?? []).length > 0 && <div><p className="mb-2 text-xs font-medium">API operations</p><div className="space-y-1">{coverageQuery.data.api_operations?.map((op, index) => <p key={`${op.target_id}-${op.method}-${op.path}-${index}`} className="text-xs"><span className="font-mono">{op.method} {op.path}</span> · {op.status}{!op.eligible && <span className="text-muted-foreground"> — {op.reason}</span>}</p>)}</div></div>}
		</CardContent></Card>}
		{scan.assessment_plan && <AssessmentWorkflowCard scan={scan} coverage={coverageQuery.data} onOpen={(scanner, scope, attemptId) => setPicked({ scanner, scope, attemptId })} onStop={(attemptId) => stopScanner.mutate(attemptId)} stopping={stopScanner.isPending ? stopScanner.variables : undefined} />}
		<WorkflowProof scanId={scan.id} running={scan.status === "running"} proof={coverageQuery.data?.proof} />
		<AttackSurfaceCard scanId={scan.id} runsSignature={runsSignature} />
		{scopesQuery.isError && <Card><CardContent className="flex items-center justify-between gap-3 p-4 text-sm"><span className="text-destructive">Could not load scanner runs.</span><Button size="sm" variant="outline" onClick={() => void scopesQuery.refetch()}>Retry</Button></CardContent></Card>}
		{scopesQuery.isSuccess && !recon.length && !scopes.length && <p className="text-sm text-muted-foreground">No scanner runs yet.</p>}
		{recon.length > 0 && <section className="space-y-2"><h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Recon</h2>{grid(recon, "")}</section>}
		{scopes.map((sc) => {
			const open = isOpen(sc);
			return <section key={sc.id} className="space-y-2">
				<button type="button" onClick={() => setOpenState((prev) => ({ ...prev, [sc.id]: !open }))} className="flex w-full flex-wrap items-center gap-2 text-left">
					{open ? <ChevronDown className="h-3 w-3 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
					<span className="font-mono text-xs font-medium uppercase tracking-wider">{scopeHeading(sc)}</span>
					{(sc.tracks ?? []).map((t) => <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>)}
					{sc.kind !== "source" && <span className="text-[11px] text-muted-foreground">{(sc.open_ports ?? []).length} open port{(sc.open_ports ?? []).length === 1 ? "" : "s"}</span>}
				</button>
				{open && grid(sc.runs, sc.id)}
			</section>;
		})}
		{selected && <Card><CardHeader><div className="flex flex-wrap items-center justify-between gap-3"><div><CardTitle><span className="capitalize">{selected.scanner}</span>{located && <span className="font-normal text-muted-foreground"> @ {located.label}</span>}</CardTitle><CardDescription>Saved scanner evidence: combined terminal output and native artifact when available.</CardDescription></div><div className="flex gap-2">{located?.run.status === "running" && located.run.attempt_id && <Button size="sm" variant="destructive" disabled={stopScanner.isPending && stopScanner.variables === located.run.attempt_id} onClick={() => stopScanner.mutate(located.run.attempt_id!)}>{stopScanner.isPending && stopScanner.variables === located.run.attempt_id ? "Stopping…" : "Stop scanner"}</Button>}{located?.run.has_artifact && <Button size="sm" variant="outline" asChild><a href={api.scannerArtifactUrl(scan.id, selected.scanner, selected.scope || undefined, located.run.attempt_id)}><Download className="mr-1 h-4 w-4" /> Artifact</a></Button>}</div></div></CardHeader><CardContent><ScannerTerminal key={`${selected.scope}|${selected.scanner}|${located?.run.attempt_id ?? ""}`} scanId={scan.id} scanner={selected.scanner} scope={selected.scope || undefined} attemptId={located?.run.attempt_id} status={located?.run.status || "pending"} reason={located?.run.reason} truncated={located?.run.truncated} /></CardContent></Card>}
	</div>;
}

function AssessmentWorkflowCard({ scan, coverage, onOpen, onStop, stopping }: { scan: ScanRecord; coverage?: ScanRecord extends never ? never : import("@/types/api").AssessmentCoverage; onOpen: (scanner: string, scope: string, attemptId?: string) => void; onStop: (attemptId: string) => void; stopping?: string }) {
	const plan = scan.assessment_plan;
	if (!plan) return null;
	const jobs = plan.jobs ?? [];
	const runs = scan.scanner_runs ?? [];
	const authRequested = (scan.assessment?.access?.length ?? 0) > 0 || !!scan.vuls_ssh_host;
	const authEvidence = (coverage?.capabilities ?? []).filter((item) => item.capability === "authenticated_web" || item.capability === "ssh");
	const prepJobs = jobs.filter((job) => ["subfinder", "httpx", "nmap"].includes(job.scanner));
	const testJobs = jobs.filter((job) => !["subfinder", "httpx", "nmap"].includes(job.scanner));
	const renderJob = (job: typeof jobs[number]) => {
		const planned = coverage?.jobs?.find((item) => item.id === job.id);
		const run = runs.filter((item) => item.scanner === job.scanner && (!item.variant || item.variant === job.variant) && (item.scope === `app:${job.target_id}` || item.scope === `host:${job.target_id}` || item.target === job.target)).sort((a,b) => Date.parse(b.started_at || "0") - Date.parse(a.started_at || "0"))[0];
		const status = run?.outcome || planned?.status || run?.status || job.state;
		const definition = job.scanner;
		const live = liveRunProgress(run);
		return <div key={job.id} className="flex flex-col gap-2 rounded-md border bg-background/40 p-3 sm:flex-row sm:items-start"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-medium">{definition}</span><Badge variant="outline" className="text-[10px]">{status.replaceAll("_", " ")}</Badge><Badge variant="outline" className="text-[10px]">{job.target}</Badge>{run?.completeness && <Badge variant="outline" className="text-[10px]">evidence · {run.completeness}</Badge>}{live && <Badge variant="outline" className="text-[10px] text-amber-300">{live.stage} {live.percent}%</Badge>}</div><p className="mt-1 text-xs text-muted-foreground">{(job.assessment_types ?? [job.assessment_type]).map((type) => type.replaceAll("_", " ")).join(", ")}{run?.started_at ? ` · started ${formatTime(run.started_at)}` : ""}{run?.finished_at ? ` · finished ${formatTime(run.finished_at)}` : ""}</p>{(planned?.reason || run?.reason || job.reason) && <p className="mt-1 text-xs text-muted-foreground">{planned?.reason || run?.reason || job.reason}</p>}</div>{run && <div className="flex gap-2"><Button size="sm" variant="outline" onClick={() => onOpen(run.scanner, run.scope || job.target, run.attempt_id)}><Terminal className="mr-1 h-3.5 w-3.5" />Evidence</Button>{run.status === "running" && run.attempt_id && <Button size="sm" variant="destructive" disabled={stopping === run.attempt_id} onClick={() => onStop(run.attempt_id!)}>{stopping === run.attempt_id ? "Stopping…" : "Stop"}</Button>}</div>}</div>;
	};
	return <Card><CardHeader><CardTitle className="text-sm">Assessment workflow</CardTitle><CardDescription>Planned tools and their current execution state. Scanner jobs can run concurrently.</CardDescription></CardHeader><CardContent className="space-y-4">
		{authRequested && <div className="rounded-lg border p-3"><p className="text-xs font-medium">Access verification</p><div className="mt-2 flex flex-wrap gap-2">{authEvidence.length ? authEvidence.map((item, index) => { const state = item.state === "verified" ? "verified" : item.state === "available" || item.state === "declared" ? "configured" : "failed"; return <Badge key={`${item.capability}-${item.target_id}-${index}`} variant="outline" className={state === "verified" ? "text-emerald-300" : state === "failed" ? "text-red-300" : "text-amber-300"}>{item.target_id || "target"} · {state}</Badge>; }) : <Badge variant="outline" className="text-amber-300">configured · verification pending</Badge>}</div>{authEvidence.some((item) => item.state === "unavailable" || item.state === "failed") && <p className="mt-2 text-xs text-red-300">{authEvidence.find((item) => item.state === "unavailable" || item.state === "failed")?.reason}</p>}</div>}
		<div className="space-y-2"><h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Discovery and preparation</h3>{prepJobs.length ? prepJobs.map(renderJob) : <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">No separate network discovery job is in this plan.</p>}{(plan.config.assessment_types ?? []).some((type) => type === "WEB_APPLICATION" || type === "API") && <div className="rounded-md border border-dashed p-3"><p className="text-sm font-medium">Web discovery</p><p className="mt-1 text-xs text-muted-foreground">HTTP reachability and Katana URL discovery feed in scope web and API routes to later checks. These preparation tasks are managed by the pipeline and are not separate assessment jobs.</p></div>}</div>
		<div className="space-y-2"><h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Security testing</h3>{testJobs.length ? testJobs.map(renderJob) : <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">No scanner jobs were accepted for this assessment.</p>}</div>
		<div className="rounded-md border bg-muted/10 p-3"><p className="text-sm font-medium">Results and report</p><p className="mt-1 text-xs text-muted-foreground">Scanner observations are collected and the assessment report is prepared when the run finishes.</p></div>
		{(coverage?.gaps ?? []).length > 0 && <details className="rounded-md border border-amber-500/30 p-3"><summary className="cursor-pointer text-sm font-medium">Coverage gaps ({coverage!.gaps!.length})</summary><div className="mt-3 space-y-2">{coverage!.gaps!.map((gap, index) => <div key={`${gap.scanner}-${gap.target_id}-${index}`} className="border-l-2 border-amber-500/40 pl-3 text-xs"><p className="font-medium">{gap.scanner} · {gap.state}</p><p className="mt-1 text-muted-foreground">{gap.reason}</p></div>)}</div></details>}
	</CardContent></Card>;
}

function AttackSurfaceCard({ scanId, runsSignature }: { scanId: string; runsSignature: string }) {
 const [tracedEndpoint,setTracedEndpoint] = useState<string|null>(null);
	const [page, setPage] = useState(1);
	const [kind, setKind] = useState("all");
	const [scanner, setScanner] = useState("");
	const [status, setStatus] = useState("");
	const [query, setQuery] = useState("");
	const size = 25;
	const result = useQuery({
		queryKey: ["attack-surface", scanId, runsSignature, page, kind, scanner, status, query],
		queryFn: () => api.attackSurface(scanId, { page, size, kind: kind === "all" ? "" : kind, scanner, status, q: query }),
		placeholderData: (previous) => previous,
	});
	const data = result.data;
	const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / size));
	const reset = (change: () => void) => { change(); setPage(1); };
	const parameterLabel = (endpoint: AttackSurfaceEndpoint) => (endpoint.parameters ?? []).map((p) => `${p.location}:${p.name}`).join(", ");
	return <Card>
		<CardHeader><CardTitle className="text-sm">Attack Surface · {data?.state ?? "loading"}</CardTitle><CardDescription>Discovered resources are inventory, not vulnerabilities. Coverage states show scanner dispatch and execution.</CardDescription></CardHeader>
		<CardContent className="space-y-4">
			{result.isError && <div className="flex items-center justify-between text-sm text-destructive"><span>Could not load the attack surface.</span><Button size="sm" variant="outline" onClick={() => void result.refetch()}>Retry</Button></div>}
			{data?.reason && <p className="text-xs text-muted-foreground">{data.reason}</p>}
			{data && data.summary.unique > 0 && <>
				<div className="grid gap-2 sm:grid-cols-4 lg:grid-cols-8">{([
					["Raw", data.summary.raw], ["Unique", data.summary.unique], ["Web", data.summary.web], ["API", data.summary.api],
					["Static", data.summary.static], ["Sensitive", data.summary.sensitive], ["Parameters", data.summary.parameterized], ["Forms", data.summary.forms],
				] as Array<[string, number]>).map(([label, value]) => <div key={label} className="rounded-md border p-2"><p className="text-[10px] uppercase text-muted-foreground">{label}</p><p className="font-mono text-lg">{value}</p></div>)}</div>
				<div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
					<input aria-label="Search endpoints" value={query} onChange={(event) => reset(() => setQuery(event.target.value))} placeholder="Search path or URL" className="h-9 rounded-md border bg-background px-3 text-xs lg:col-span-2" />
					<select aria-label="Endpoint kind" value={kind} onChange={(event) => reset(() => setKind(event.target.value))} className="h-9 rounded-md border bg-background px-3 text-xs"><option value="all">All kinds</option><option value="web">Web</option><option value="api">API</option><option value="static">Static</option></select>
					<input aria-label="Scanner filter" value={scanner} onChange={(event) => reset(() => setScanner(event.target.value))} placeholder="Scanner" className="h-9 rounded-md border bg-background px-3 text-xs" />
					<select aria-label="Coverage status" value={status} onChange={(event) => reset(() => setStatus(event.target.value))} className="h-9 rounded-md border bg-background px-3 text-xs"><option value="">All coverage</option><option value="dispatched">Dispatched</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="skipped">Skipped</option></select>
				</div>
				<div className="overflow-x-auto rounded-md border"><table className="w-full text-left text-xs"><thead className="border-b bg-muted/30 text-muted-foreground"><tr><th className="px-3 py-2">Method</th><th className="px-3 py-2">Canonical endpoint</th><th className="px-3 py-2">Classification</th><th className="px-3 py-2">Parameters</th><th className="px-3 py-2">Coverage</th></tr></thead><tbody>{data.items.map((endpoint) => <tr key={endpoint.id} className="border-b last:border-0 align-top"><td className="px-3 py-3 font-mono">{endpoint.method}<Button size="sm" variant="ghost" onClick={()=>setTracedEndpoint(endpoint.id)}>Trace</Button></td><td className="max-w-md px-3 py-3"><p className="break-all font-mono">{endpoint.canonical_url}</p>{(endpoint.spa_routes ?? []).length > 0 && <p className="mt-1 text-muted-foreground">SPA {(endpoint.spa_routes ?? []).map((route) => `#${route}`).join(", ")}</p>}<p className="mt-1 text-[10px] text-muted-foreground">{(endpoint.sources ?? []).join(", ")}</p></td><td className="px-3 py-3"><div className="flex flex-wrap gap-1"><Badge variant="outline">{endpoint.kind}</Badge>{endpoint.sensitive && <Badge variant="outline">sensitive</Badge>}{endpoint.has_form && <Badge variant="outline">form</Badge>}</div></td><td className="max-w-xs break-words px-3 py-3 text-muted-foreground">{parameterLabel(endpoint) || "—"}</td><td className="px-3 py-3"><div className="space-y-1">{(endpoint.scanner_coverage ?? []).map((coverage) => <p key={coverage.scanner} title={coverage.reason} className="whitespace-nowrap"><span className="font-mono">{coverage.scanner}</span> · {coverage.status}</p>)}</div></td></tr>)}</tbody></table></div>
				<div className="flex items-center justify-between text-xs text-muted-foreground"><span>Page {Math.min(page, totalPages)} of {totalPages} · {data.total} endpoint{data.total === 1 ? "" : "s"}</span><div className="flex gap-2"><Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>Previous</Button><Button size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((value) => Math.min(totalPages, value + 1))}>Next</Button></div></div>
			</>}
		<EndpointTraceDialog scanId={scanId} endpointId={tracedEndpoint} onClose={()=>setTracedEndpoint(null)} />
		<EndpointTraceDialog scanId={scanId} endpointId={tracedEndpoint} onClose={()=>setTracedEndpoint(null)} />
		</CardContent>
	</Card>;
}

function ScannerStatusCard({ name, run, live, active, onClick, onStop, stopping }: { name: string; run?: { status: string; reason?: string; truncated?: boolean; authenticated?: boolean; attempt_id?: string }; live?: { percent: number; stage: string } | null; active: boolean; onClick: () => void; onStop: (attemptId: string) => void; stopping?: string }) {
	const status = run?.status ?? "pending";
	return <div className={cn("rounded-lg border p-3 transition-colors hover:bg-muted/30", active && "border-primary bg-muted/30")}><button type="button" onClick={onClick} className="w-full text-left"><p className="font-medium capitalize">{name}</p><p className={cn("mt-2 text-xs capitalize", status === "completed" && "text-emerald-400", status === "failed" && "text-red-400", status === "not_applicable" && "text-muted-foreground", status === "skipped" && "text-muted-foreground", status === "cancelled" && "text-amber-400")}>{status.replaceAll("_", " ")}</p>{live && <RunProgress live={live} />}{run?.authenticated && <Badge variant="outline" className="mt-2">Authenticated session</Badge>}{run?.reason && <p className="mt-2 line-clamp-2 text-[11px] text-muted-foreground" title={run.reason}>{run.reason}</p>}{run?.truncated && <Badge variant="outline" className="mt-2">truncated</Badge>}</button>{status === "running" && run?.attempt_id && <Button className="mt-3" size="sm" variant="destructive" disabled={stopping === run.attempt_id} onClick={() => onStop(run.attempt_id!)}>{stopping === run?.attempt_id ? "Stopping…" : "Stop scanner"}</Button>}</div>;
}

function currentPhaseLabel(p?: number): string {
  if (!p) return "—";
  const found = PHASES.find((x) => x.id === p);
  return found ? `${p}. ${found.name}` : `Phase ${p}`;
}

function SubdomainProgress({
  completed,
  running,
  remaining,
  total,
}: {
  completed: number;
  running: number;
  remaining: number;
  total: number;
}) {
  const denominator = Math.max(total, 1);
  const completedPct = (completed / denominator) * 100;
  const runningPct = (running / denominator) * 100;
  const remainingPct = Math.max(0, 100 - completedPct - runningPct);
  return (
    <div className="space-y-3">
      <div className="flex h-2 overflow-hidden rounded-sm bg-muted">
        <div className="bg-success" style={{ width: `${completedPct}%` }} />
        <div className="bg-warning" style={{ width: `${runningPct}%` }} />
        <div
          className="bg-muted-foreground/25"
          style={{ width: `${remainingPct}%` }}
        />
      </div>
      <div className="grid gap-2 text-xs sm:grid-cols-4">
        <ProgressStat label="Total" value={total} />
        <ProgressStat label="Scanned" value={completed} />
        <ProgressStat label="Running" value={running} />
        <ProgressStat label="Remaining" value={remaining} />
      </div>
    </div>
  );
}

function ProgressStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mono mt-1 text-lg text-foreground">{value}</div>
    </div>
  );
}

function RiskBreakdown({ vulns }: { vulns: VulnSummary[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const v of vulns) {
      c[normalizeSeverity(v.severity)] += 1;
    }
    return c;
  }, [vulns]);
  const total = vulns.length || 1;
  const order: Array<keyof typeof counts> = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ];
  return (
    <div className="space-y-3">
      <div className="flex h-12 items-end gap-1">
        {order.map((sev) => {
          const n = counts[sev as string];
          if (!n) return null;
          const pct = Math.max(4, Math.round((n / total) * 100));
          return (
            <div
              key={sev}
              className={cn(
                "h-full rounded-sm",
                sev === "critical" && "bg-red-500/70",
                sev === "high" && "bg-orange-500/70",
                sev === "medium" && "bg-amber-400/70",
                sev === "low" && "bg-blue-400/70",
                sev === "info" && "bg-neutral-500/60",
              )}
              style={{ width: `${pct}%` }}
              title={`${sev}: ${n}`}
            />
          );
        })}
        {vulns.length === 0 && (
          <div className="h-full w-full rounded-sm border border-dashed border-border" />
        )}
      </div>
      {/* Severity legend. Horizontal-scroll on very narrow widths so the
          five labels never overlap; wide enough to read at all sizes. */}
      <div className="-mx-1 flex gap-1.5 overflow-x-auto px-1 pb-1 text-[11px]">
        {order.map((sev) => (
          <div
            key={sev}
            className="flex min-w-[60px] flex-1 flex-col rounded-md border border-border bg-muted/20 px-2 py-1.5"
          >
            <span className="truncate uppercase tracking-wide text-muted-foreground">
              {sev}
            </span>
            <span className="mono text-base leading-tight text-foreground">
              {counts[sev as string]}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SubdomainsTab({ subScans }: { subScans: SubScanSummary[] }) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<number>(DEFAULT_PAGE_SIZE);

  const total = subScans.length;
  // Clamp the current page when the list shrinks/grows (it grows live during a
  // wildcard scan) so we never strand the user on an empty page.
  const totalPages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
  const safePage = Math.min(Math.max(1, page), totalPages);
  useEffect(() => {
    if (safePage !== page) setPage(safePage);
  }, [safePage, page]);

  const paged = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return subScans.slice(start, start + pageSize);
  }, [subScans, safePage, pageSize]);

  if (subScans.length === 0) {
    return (
      <EmptyState
        title="No subdomains recorded yet"
        description="Discovered subdomains will appear here as the wildcard scan progresses."
      />
    );
  }

  return (
    <Card>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <Th>Subdomain</Th>
                <Th>Status</Th>
                <Th>Findings</Th>
                <Th>Started</Th>
              </tr>
            </thead>
            <tbody>
              {paged.map((sub) => (
                <tr
                  key={sub.id || sub.target}
                  className="border-b border-border/60 last:border-0"
                >
                  <Td>
                    <div className="mono text-sm text-foreground">
                      {sub.target}
                    </div>
                    <div className="mono text-xs text-muted-foreground">
                      {sub.id}
                    </div>
                  </Td>
                  <Td>
                    <ScanStatusPill status={sub.status} />
                  </Td>
                  <Td className="mono text-xs">{sub.vuln_count ?? 0}</Td>
                  <Td className="text-muted-foreground">
                    {sub.started_at ? timeAgo(sub.started_at) : "—"}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pagination
          totalItems={total}
          page={safePage}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
        />
      </CardContent>
    </Card>
  );
}

function Th({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <th className={cn("px-4 py-3 text-left font-medium", className)}>
      {children}
    </th>
  );
}

function Td({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <td className={cn("px-4 py-3 align-middle", className)}>{children}</td>
  );
}

function FindingsTab({
  vulns,
  scanId,
}: {
  vulns: VulnSummary[];
  scanId: string;
}) {
  const del = useDeleteVuln();
  const [selected, setSelected] = useState<VulnSummary | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const sorted = useMemo(
    () =>
      [...vulns].sort(
        (a, b) => severityRank(b.severity) - severityRank(a.severity),
      ),
    [vulns],
  );

  const allSelected = sorted.length > 0 && selectedIds.size === sorted.length;

  useEffect(() => {
    const allIds = new Set(sorted.map((v) => v.id));
    setSelectedIds((current) => {
      const next = new Set([...current].filter((id) => allIds.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [sorted]);

  function toggleSelect(id: string, checked: boolean) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (checked) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  function selectAll() {
    setSelectedIds(new Set(sorted.map((v) => v.id)));
  }
  function clearSelection() {
    setSelectedIds(new Set());
  }

  async function deleteVulns(ids: string[]) {
    const unique = [...new Set(ids)].filter(Boolean);
    if (!unique.length) return;
    const label =
      unique.length === 1
        ? "Permanently delete this finding?"
        : `Permanently delete ${unique.length} selected findings?`;
    if (!window.confirm(label)) return;
    for (const vulnId of unique) {
      await del.mutateAsync({ scanId, vulnId });
    }
    setSelectedIds((current) => {
      const next = new Set(current);
      for (const id of unique) next.delete(id);
      return next;
    });
  }

  if (sorted.length === 0)
    return (
      <EmptyState
        title="No findings yet"
        description="Vulnerabilities will appear here as the engagement progresses."
      />
    );

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={allSelected ? clearSelection : selectAll}
        >
          {allSelected ? "Clear selection" : "Select all"}
        </Button>
        <span className="text-xs text-muted-foreground">
          {selectedIds.size} selected
        </span>
        <BulkActionMenu
          disabled={selectedIds.size === 0 || del.isPending}
          selectedCount={selectedIds.size}
          onDelete={() => void deleteVulns([...selectedIds])}
        />
      </div>
      <div className="space-y-2">
        {sorted.map((f) => (
          <Card
            key={f.id}
            id={`finding-${f.id}`}
            className={cn(
              "overflow-hidden",
              selectedIds.has(f.id) && "ring-1 ring-primary/30",
            )}
          >
            <div className="flex items-start gap-2 p-2 pl-4">
              <input
                type="checkbox"
                checked={selectedIds.has(f.id)}
                aria-label={`Select ${f.title}`}
                onChange={(e) => toggleSelect(f.id, e.currentTarget.checked)}
                className="mt-3 h-4 w-4 shrink-0 rounded border-border bg-input accent-primary"
              />
              <button
                type="button"
                className="group block w-full flex-1 text-left transition-colors hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring rounded"
                onClick={() => setSelected(f)}
                aria-label={`Open finding details for ${f.title}`}
              >
                <CardContent className="flex flex-col gap-3 p-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0 space-y-1 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={f.severity} />
                      <h3 className="font-medium text-foreground">{f.title}</h3>
                      {f.cve && (
                        <Badge variant="outline" className="mono">
                          {f.cve}
                        </Badge>
                      )}
                      {f.cwe_id && (
                        <Badge
                          variant="outline"
                          className="mono text-emerald-400 border-emerald-400/30"
                        >
                          {f.cwe_id}
                        </Badge>
                      )}
                      {f.owasp && (
                        <Badge
                          variant="outline"
                          className="mono text-amber-400 border-amber-400/30"
                        >
                          {f.owasp}
                        </Badge>
                      )}
                      <VerificationBadge verified={f.verified} tags={f.tags} />
                    </div>
                    {f.description && (
                      <p className="text-sm leading-relaxed text-muted-foreground line-clamp-3">
                        {f.description}
                      </p>
                    )}
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      {f.target && <span className="mono">{f.target}</span>}
                      {f.endpoint && <span className="mono">{f.endpoint}</span>}
                      {f.method && <span className="mono">{f.method}</span>}
                      {f.parameter && <span className="mono">Parameter: {f.parameter}</span>}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {f.cvss != null && f.cvss > 0 && (
                      <Badge variant="outline" className="mono">
                        CVSS {f.cvss.toFixed(1)}
                      </Badge>
                    )}
                    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground group-hover:text-foreground">
                      Details <ArrowRight className="h-3.5 w-3.5" />
                    </span>
                  </div>
                </CardContent>
              </button>
              <FindingRowMenu
                finding={f}
                scanId={scanId}
                deleting={del.isPending}
                onDelete={() => void deleteVulns([f.id])}
              />
            </div>
          </Card>
        ))}
      </div>
      <FindingDetailsDialog
        scanId={scanId}
        finding={selected}
        onOpenChange={(open) => !open && setSelected(null)}
      />
    </>
  );
}

function BulkActionMenu({
  disabled,
  selectedCount,
  onDelete,
}: {
  disabled: boolean;
  selectedCount: number;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button size="sm" variant="secondary" disabled={disabled}>
          Actions
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="start" className={menuContentClass}>
          <DropdownMenu.Label className="px-2 py-1.5 text-xs text-muted-foreground">
            {selectedCount} selected
          </DropdownMenu.Label>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            className={cn(menuItemClass, "text-red-400 focus:text-red-300")}
            onSelect={(event) => {
              event.preventDefault();
              onDelete();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete selected
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function FindingRowMenu({
  finding,
  scanId,
  deleting,
  onDelete,
}: {
  finding: VulnSummary;
  scanId: string;
  deleting: boolean;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <Button
          size="icon"
          variant="ghost"
          aria-label={`Actions for ${finding.title}`}
          className="mt-1 shrink-0"
        >
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" className={menuContentClass}>
          <DropdownMenu.Item asChild className={menuItemClass}>
            <Link to={`/scans/${scanId}`}>
              <ExternalLink className="h-3.5 w-3.5" />
              Open scan
            </Link>
          </DropdownMenu.Item>
          <DropdownMenu.Separator className="-mx-1 my-1 h-px bg-border" />
          <DropdownMenu.Item
            disabled={deleting}
            className={cn(
              menuItemClass,
              "text-red-400 focus:text-red-300 data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
            )}
            onSelect={(event) => {
              event.preventDefault();
              onDelete();
            }}
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete finding
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function FindingDetailsDialog({
  scanId,
  finding,
  onOpenChange,
}: {
  scanId: string;
  finding: VulnSummary | null;
  onOpenChange: (open: boolean) => void;
}) {
  const observationsQuery = useQuery({
    queryKey: ["finding-observations", scanId, finding?.id],
    queryFn: () => api.allFindingObservations(scanId, finding!.id),
    enabled: !!finding,
  });
  const observations = observationsQuery.data ?? [];
  return (
    <Dialog open={!!finding} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] max-w-3xl overflow-y-auto">
        {finding && (
          <>
            <DialogHeader>
              <div className="flex flex-wrap items-center gap-2 pr-8">
                <SeverityBadge severity={finding.severity} />
                {finding.cve && (
                  <Badge variant="outline" className="mono">
                    {finding.cve}
                  </Badge>
                )}
                {finding.cvss != null && finding.cvss > 0 && (
                  <Badge variant="outline" className="mono">
                    CVSS {finding.cvss.toFixed(1)}
                  </Badge>
                )}
                {finding.cwe_id && (
                  <Badge
                    variant="outline"
                    className="mono text-emerald-400 border-emerald-400/30"
                  >
                    {finding.cwe_id}
                  </Badge>
                )}
                {finding.owasp && (
                  <Badge
                    variant="outline"
                    className="mono text-amber-400 border-amber-400/30"
                  >
                    {finding.owasp}
                  </Badge>
                )}
                <VerificationBadge verified={finding.verified} tags={finding.tags} />
              </div>
              <DialogTitle className="pr-8 text-lg">
                {finding.title}
              </DialogTitle>
              <DialogDescription>
                Detailed vulnerability record from this scan.
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-3 rounded-md border border-border bg-muted/20 p-3 text-sm sm:grid-cols-2">
              <DetailRow label="Target" value={finding.target} mono />
              <DetailRow label="Endpoint" value={finding.endpoint} mono />
              <DetailRow label="Method" value={finding.method} mono />
              <DetailRow label="Parameter" value={finding.parameter} mono />
              <DetailRow label="Confidence" value={finding.confidence} />
              <DetailRow label="Scanner confidence" value={finding.native_confidence} />
              <DetailRow label="Evidence quality" value={finding.evidence_completeness} />
              <DetailRow label="Fingerprint" value={finding.fingerprint} mono />
              <DetailRow label="CVSS vector" value={finding.cvss_vector} mono />
              <DetailRow label="CWE" value={finding.cwe_id} mono />
              <DetailRow label="OWASP" value={finding.owasp} mono />
              <DetailRow label="Finding ID" value={finding.id} mono />
              <DetailRow
                label="Verification"
                value={finding.verification_method}
              />
            </div>

            <Separator />

            <section className="space-y-3" aria-label="Affected locations and scanner evidence">
              <div><h3 className="text-sm font-semibold">Affected locations and scanner evidence</h3><p className="text-xs text-muted-foreground">Evidence is taken from saved scanner output. Sensitive values are redacted and excerpts are limited.</p></div>
              {observationsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading scanner observations…</p>}
              {observationsQuery.isError && <p role="alert" className="text-sm text-destructive">Could not load scanner observations.</p>}
              {!observationsQuery.isLoading && !observationsQuery.isError && observations.length === 0 && <p className="rounded border p-3 text-sm text-muted-foreground">Evidence: Not provided by scanner.</p>}
              {observations.map((observation) => {
                const locations = [
                  observation.endpoint && `URL/endpoint: ${observation.endpoint}`,
                  observation.method && `Method: ${observation.method}`,
                  observation.parameter && `${observation.parameter_location || ""} parameter: ${observation.parameter}`,
                  observation.source_location && `Source: ${observation.source_location}`,
                  observation.package && `Package: ${observation.package}${observation.package_version ? `@${observation.package_version}` : ""}`,
                  (observation.protocol || observation.port) && `Service: ${[observation.protocol, observation.port].filter(Boolean).join("/")}`,
                  observation.target && `Target: ${observation.target}`,
                  observation.container && `Container: ${observation.container}`,
                  observation.resource && `Resource: ${observation.resource}`,
                ].filter(Boolean) as string[];
                return <article key={observation.id} className="space-y-2 rounded-md border p-3">
                  <div className="flex flex-wrap items-center gap-2 text-xs"><Badge variant="outline">{observation.scanner}</Badge><Badge variant="outline">{observation.evidence_completeness === "request_response" ? "Request/response recorded" : observation.evidence ? "Scanner output excerpt" : observation.evidence_reference ? "Scanner reference only" : "Evidence not provided"}{observation.evidence_completeness === "partial" ? " · partial" : ""}</Badge>{observation.source_id && <span className="break-all font-mono text-muted-foreground">{observation.source_id}</span>}</div>
                  <p className="text-sm font-medium">{observation.title}</p>
                  <div className="space-y-1 text-xs">{locations.length ? locations.map((location) => <p key={location} className="break-all font-mono">{location}</p>) : <p className="text-muted-foreground">Location: Not provided by scanner.</p>}</div>
                  {observation.description && <p className="text-sm text-muted-foreground">{observation.description}</p>}
                  <div className="rounded bg-muted/30 p-2"><p className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">Evidence excerpt</p><pre className="whitespace-pre-wrap break-words font-mono text-xs">{observation.evidence || "Not provided by scanner."}</pre></div>
                  {observation.evidence_reference && <p className="break-all text-[11px] text-muted-foreground">Evidence reference: <span className="font-mono">{observation.evidence_reference}</span></p>}
                </article>;
              })}
            </section>

            <div className="space-y-4">
              <DetailSection title="Description" value={finding.description} />
              <DetailSection title="Impact" value={finding.impact} />
              <DetailSection
                title="Technical analysis"
                value={finding.technical_analysis}
              />
              <DetailSection
                title="Proof of concept"
                value={finding.poc_description}
              />
              {finding.poc_script && (
                <DetailSection
                  title="PoC script"
                  value={finding.poc_script}
                  code
                />
              )}
              {finding.exploitation_proof && (
                <DetailSection
                  title="Exploitation proof"
                  value={finding.exploitation_proof}
                  code
                />
              )}
              <DetailSection title="Remediation" value={finding.remediation} />
              {finding.fix && (
                <DetailSection title="Suggested fix" value={finding.fix} code />
              )}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value?: string;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div
        className={cn(
          "mt-1 break-words text-foreground",
          mono && "mono text-xs",
        )}
      >
        {value || "—"}
      </div>
    </div>
  );
}

function DetailSection({
  title,
  value,
  code,
}: {
  title: string;
  value?: string;
  code?: boolean;
}) {
  if (!value) return null;
  return (
    <section className="space-y-2">
      <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
        {title}
      </h4>
      {code ? (
        <pre className="max-h-64 overflow-auto rounded-md border border-border bg-black/40 p-3 text-xs leading-relaxed text-foreground whitespace-pre-wrap break-words">
          <code>{value}</code>
        </pre>
      ) : (
        <Markdown source={value} />
      )}
    </section>
  );
}

function EventsTab({
  events,
  scanId,
  target,
}: {
  events: FeedEvent[];
  scanId: string;
  target: string;
}) {
  const [filter, setFilter] = useState<FeedFilter>("all");
  return (
    <div className="space-y-3">
      <LiveFeed
        events={events}
        filter={filter}
        onFilterChange={setFilter}
        exportFilePrefix={`xalgorix-${target || scanId}-events`}
        exportScope={scanId}
        emptyTitle="No events yet"
        emptyDescription="Once the scan starts producing output it will stream here."
      />
	</div>
  );
}

function ConfigTab({
  scan,
}: {
  scan: NonNullable<ReturnType<typeof useScan>["data"]>;
}) {
  const items: Array<{ k: string; v: ReactNode }> = [
    { k: "Scan mode", v: scan.scan_mode || "—" },
    {
      k: "Severity filter",
      v: (scan.severity_filter ?? []).join(", ") || "all",
    },
    { k: "Phases", v: (scan.phases ?? []).join(", ") || "all" },
    { k: "Stop reason", v: scan.stop_reason || "—" },
    { k: "Started", v: formatTime(scan.started_at) },
    { k: "Finished", v: scan.finished_at ? formatTime(scan.finished_at) : "—" },
    {
      k: "Discord webhook",
      v:
        scan.discord_webhook_configured || scan.discord_webhook
          ? "configured"
          : "none",
    },
  ];
  return (
    <Card>
      <CardContent className="p-0">
        <dl className="divide-y divide-border/60">
          {items.map((it) => (
            <div
              key={it.k}
              className="grid grid-cols-3 gap-2 px-4 py-3 text-sm"
            >
              <dt className="text-muted-foreground">{it.k}</dt>
              <dd className="col-span-2 text-foreground">{it.v}</dd>
            </div>
          ))}
        </dl>
      </CardContent>
    </Card>
  );
}

function ScanDetailSkeleton() {
  return (
    <>
      <Skeleton className="h-4 w-24" />
      <Skeleton className="h-10 w-2/3" />
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-40 lg:col-span-2" />
        <Skeleton className="h-40" />
      </div>
      <Skeleton className="h-10 w-72" />
      <Skeleton className="h-96 w-full" />
    </>
  );
}
