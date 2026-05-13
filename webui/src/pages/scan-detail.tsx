import { useEffect, useMemo, useState, type ReactNode } from "react"
import { Link, useNavigate, useParams } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { ScanStatusPill } from "@/components/scan-status-pill"
import { SeverityBadge } from "@/components/severity-badge"
import { PhaseProgress, PHASES } from "@/components/phase-progress"
import { CopyButton } from "@/components/copy-button"
import { ErrorState, EmptyState } from "@/components/states"
import { useScan, useStopInstance, useStartSavedInstance, useDeleteScan } from "@/api/queries"
import { api } from "@/api/client"
import { useWSStore, filterEventsForInstance, type FeedEvent } from "@/store/ws"
import { timeAgo, formatTime, formatDuration, severityRank, normalizeSeverity, cn } from "@/lib/utils"
import {
  ChevronLeft,
  Download,
  X,
  Play,
  Trash2,
  ShieldAlert,
  Terminal,
  Sparkles,
  ListChecks,
} from "lucide-react"
import { LiveFeed, type FeedFilter } from "@/components/live-feed"
import type { VulnSummary } from "@/types/api"

export default function ScanDetailPage() {
  const navigate = useNavigate()
  const { scanId } = useParams<{ scanId: string }>()
  const id = scanId ?? ""
  const { data: scan, isLoading, error, refetch } = useScan(id)
  const stop = useStopInstance()
  const start = useStartSavedInstance()
  const del = useDeleteScan()
  const subscribe = useWSStore((s) => s.subscribe)
  const unsubscribe = useWSStore((s) => s.unsubscribe)
  const liveEvents = useWSStore((s) => s.events)

  useEffect(() => {
    if (!id) return
    subscribe(id)
    return () => unsubscribe()
  }, [id, subscribe, unsubscribe])

  if (error)
    return (
      <ErrorState
        title="Could not load scan"
        description={error instanceof Error ? error.message : "Unknown error"}
        action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
      />
    )
  if (isLoading || !scan) return <ScanDetailSkeleton />

  const status = (scan.status || "").toLowerCase()
  const canStop = status === "running" || status === "paused"
  const canStart = status === "saved" || status === "stopped" || status === "failed" || status === "finished"

  // Combine persisted events from the scan record with the live websocket
  // feed for this instance, deduped by content.
  const wsForScan = filterEventsForInstance(liveEvents, id)
  const persistedAsFeed: FeedEvent[] = (scan.events ?? []).map((e, i) => ({
    ...e,
    _key: `persisted:${i}`,
    _receivedAt: e.timestamp ? new Date(e.timestamp).getTime() : Date.now(),
  }))
  const mergedEvents = mergeEventStreams(persistedAsFeed, wsForScan)

  return (
    <>
      <div>
        <Link to="/scans" className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground">
          <ChevronLeft className="mr-1 h-3 w-3" />
          All scans
        </Link>
      </div>

      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2 min-w-0">
          <div className="flex items-center gap-3 min-w-0">
            <h1 className="font-mono text-2xl font-semibold tracking-tight text-foreground truncate">
              {scan.target}
            </h1>
            <CopyButton value={scan.target} />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span className="mono">{scan.id}</span>
            <span>·</span>
            <span>Started {timeAgo(scan.started_at)}</span>
            <span>·</span>
            <span>Duration {formatDuration(scan.started_at, scan.finished_at)}</span>
            {scan.scan_mode && (
              <>
                <span>·</span>
                <Badge variant="outline" className="font-normal capitalize">{scan.scan_mode}</Badge>
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
              onClick={() => start.mutate(scan.id)}
              disabled={start.isPending}
            >
              <Play className="mr-1 h-4 w-4" /> Start
            </Button>
          )}
          {canStop && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => stop.mutate(scan.id)}
              disabled={stop.isPending}
            >
              <X className="mr-1 h-4 w-4" /> Stop
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              if (window.confirm("Permanently delete this scan and all its events?")) {
                del.mutate(scan.id, {
                  onSuccess: () => {
                    navigate("/scans", { replace: true })
                  },
                })
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
              Xalgorix runs a 10-phase autonomous methodology. Currently:{" "}
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
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
              {PHASES.map((p) => (
                <div
                  key={p.id}
                  className={cn(
                    "rounded-md border border-border bg-muted/20 px-2 py-1.5 text-[11px]",
                    scan.current_phase === p.id && "border-amber-400/50 text-amber-300",
                  )}
                >
                  <span className="text-muted-foreground mono mr-1.5">{p.id}</span>
                  {p.name}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Risk overview</CardTitle>
            <CardDescription>{(scan.vulns ?? []).length} findings</CardDescription>
          </CardHeader>
          <CardContent>
            <RiskBreakdown vulns={scan.vulns ?? []} />
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            Findings
          </TabsTrigger>
          <TabsTrigger value="events">
            <Terminal className="mr-1.5 h-3.5 w-3.5" />
            Events
          </TabsTrigger>
          <TabsTrigger value="config">
            <ListChecks className="mr-1.5 h-3.5 w-3.5" />
            Config
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-2">
          <FindingsTab vulns={scan.vulns ?? []} />
        </TabsContent>
        <TabsContent value="events">
          <EventsTab events={mergedEvents} />
        </TabsContent>
        <TabsContent value="config">
          <ConfigTab scan={scan} />
        </TabsContent>
      </Tabs>
    </>
  )
}

function currentPhaseLabel(p?: number): string {
  if (!p) return "—"
  const found = PHASES.find((x) => x.id === p)
  return found ? `${p}. ${found.name}` : `Phase ${p}`
}

function mergeEventStreams(persisted: FeedEvent[], live: FeedEvent[]): FeedEvent[] {
  const seen = new Set<string>()
  const out: FeedEvent[] = []
  for (const e of persisted) {
    const k = `${e.type}|${e.timestamp || ""}|${(e.content || e.output || "").slice(0, 80)}`
    if (seen.has(k)) continue
    seen.add(k)
    out.push(e)
  }
  for (const e of live) {
    const k = `${e.type}|${e.timestamp || ""}|${(e.content || e.output || "").slice(0, 80)}`
    if (seen.has(k)) continue
    seen.add(k)
    out.push(e)
  }
  return out
}

function RiskBreakdown({ vulns }: { vulns: VulnSummary[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const v of vulns) {
      c[normalizeSeverity(v.severity)] += 1
    }
    return c
  }, [vulns])
  const total = vulns.length || 1
  const order: Array<keyof typeof counts> = ["critical", "high", "medium", "low", "info"]
  return (
    <div className="space-y-3">
      <div className="flex items-end gap-1">
        {order.map((sev) => {
          const n = counts[sev as string]
          if (!n) return null
          const pct = Math.max(4, Math.round((n / total) * 100))
          return (
            <div
              key={sev}
              className={cn(
                "h-12 rounded-sm",
                sev === "critical" && "bg-red-500/70",
                sev === "high" && "bg-orange-500/70",
                sev === "medium" && "bg-amber-400/70",
                sev === "low" && "bg-blue-400/70",
                sev === "info" && "bg-neutral-500/60",
              )}
              style={{ width: `${pct}%` }}
              title={`${sev}: ${n}`}
            />
          )
        })}
        {vulns.length === 0 && (
          <div className="h-12 w-full rounded-sm border border-dashed border-border" />
        )}
      </div>
      <div className="grid grid-cols-5 gap-1.5 text-[11px]">
        {order.map((sev) => (
          <div key={sev} className="rounded-md border border-border bg-muted/20 px-2 py-1.5">
            <div className="text-muted-foreground uppercase tracking-wide">{sev}</div>
            <div className="mono text-base text-foreground">{counts[sev as string]}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function FindingsTab({ vulns }: { vulns: VulnSummary[] }) {
  const sorted = useMemo(
    () => [...vulns].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    [vulns],
  )
  if (sorted.length === 0)
    return (
      <EmptyState
        title="No findings yet"
        description="Vulnerabilities will appear here as the engagement progresses."
      />
    )

  return (
    <div className="space-y-2">
      {sorted.map((f) => (
        <Card key={f.id}>
          <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0 space-y-1 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <h3 className="font-medium text-foreground">{f.title}</h3>
                {f.cve && (
                  <Badge variant="outline" className="mono">{f.cve}</Badge>
                )}
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
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {f.cvss != null && f.cvss > 0 && (
                <Badge variant="outline" className="mono">CVSS {f.cvss.toFixed(1)}</Badge>
              )}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function EventsTab({ events }: { events: FeedEvent[] }) {
  const [filter, setFilter] = useState<FeedFilter>("all")
  return (
    <LiveFeed
      events={events}
      filter={filter}
      onFilterChange={setFilter}
      emptyTitle="No events yet"
      emptyDescription="Once the scan starts producing output it will stream here."
    />
  )
}

function ConfigTab({ scan }: { scan: NonNullable<ReturnType<typeof useScan>["data"]> }) {
  const items: Array<{ k: string; v: ReactNode }> = [
    { k: "Scan mode", v: scan.scan_mode || "—" },
    { k: "Severity filter", v: (scan.severity_filter ?? []).join(", ") || "all" },
    { k: "Phases", v: (scan.phases ?? []).join(", ") || "all" },
    { k: "Iterations", v: <span className="mono">{scan.iterations}</span> },
    { k: "Tool calls", v: <span className="mono">{scan.tool_calls}</span> },
    { k: "Tokens", v: <span className="mono">{scan.total_tokens?.toLocaleString() ?? 0}</span> },
    { k: "Stop reason", v: scan.stop_reason || "—" },
    { k: "Started", v: formatTime(scan.started_at) },
    { k: "Finished", v: scan.finished_at ? formatTime(scan.finished_at) : "—" },
    { k: "Discord webhook", v: scan.discord_webhook ? "configured" : "none" },
  ]
  return (
    <Card>
      <CardContent className="p-0">
        <dl className="divide-y divide-border/60">
          {items.map((it) => (
            <div key={it.k} className="grid grid-cols-3 gap-2 px-4 py-3 text-sm">
              <dt className="text-muted-foreground">{it.k}</dt>
              <dd className="col-span-2 text-foreground">{it.v}</dd>
            </div>
          ))}
          {scan.instruction && (
            <div className="grid grid-cols-3 gap-2 px-4 py-3 text-sm">
              <dt className="text-muted-foreground flex items-center gap-1">
                <Sparkles className="h-3 w-3" /> Instruction
              </dt>
              <dd className="col-span-2 whitespace-pre-wrap text-foreground/90">
                {scan.instruction}
              </dd>
            </div>
          )}
        </dl>
      </CardContent>
    </Card>
  )
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
  )
}
