import { useMemo } from "react"
import { Link, useParams, useNavigate } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { ScanStatusPill, ScanPhaseBadge } from "@/components/scan-status-pill"
import { SeverityBadge } from "@/components/severity-badge"
import { PhaseProgress, RiskScoreRing } from "@/components/phase-progress"
import { CopyButton } from "@/components/copy-button"
import { ErrorState, EmptyState } from "@/components/states"
import {
  useScan,
  useScanFindings,
  useScanEvents,
  useCancelScan,
  useExportScan,
} from "@/api/queries"
import { useWS } from "@/store/ws"
import { formatRelative } from "@/lib/utils"
import {
  ChevronLeft,
  Download,
  X,
  ExternalLink,
  ShieldAlert,
  Terminal,
  Network,
  Sparkles,
} from "lucide-react"
import { LiveFeed } from "@/components/live-feed"

export default function ScanDetailPage() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const id = scanId ?? ""
  const { data: scan, isLoading, error, refetch } = useScan(id)
  const cancel = useCancelScan()
  const exporter = useExportScan()

  // Subscribe to the WS room for this scan so live findings/events flow in.
  useWS((s) => s.subscribe)
  // simple side-effect: call subscribe once
  // (handled below in useMemo to avoid re-subscribing)

  useMemo(() => {
    const sub = useWS.getState().subscribe
    const unsub = useWS.getState().unsubscribe
    if (id) sub(`scan:${id}`)
    return () => unsub(`scan:${id}`)
  }, [id])

  if (error) return <ErrorState message={String(error)} onRetry={() => refetch()} />
  if (isLoading || !scan) return <ScanDetailSkeleton />

  const canCancel = scan.status === "running" || scan.status === "queued"

  return (
    <>
      <div>
        <Link to="/scans" className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground">
          <ChevronLeft className="mr-1 h-3 w-3" />
          All scans
        </Link>
      </div>

      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <h1 className="font-mono text-2xl font-semibold tracking-tight text-foreground">{scan.target}</h1>
            <CopyButton value={scan.target} />
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span className="font-mono">{scan.id}</span>
            <span>·</span>
            <span>Started {scan.started_at ? formatRelative(scan.started_at) : "—"}</span>
            {scan.tags?.length ? (
              <>
                <span>·</span>
                <div className="flex items-center gap-1">
                  {scan.tags.map((t) => (
                    <Badge key={t} variant="outline" className="font-normal">
                      {t}
                    </Badge>
                  ))}
                </div>
              </>
            ) : null}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <ScanStatusPill status={scan.status} />
          {scan.phase && <ScanPhaseBadge phase={scan.phase} />}
          <Button
            variant="outline"
            size="sm"
            onClick={() => exporter.mutate({ scanId: id, format: "json" })}
            disabled={exporter.isPending}
          >
            <Download className="mr-1 h-4 w-4" />
            Export
          </Button>
          {canCancel && (
            <Button
              variant="destructive"
              size="sm"
              onClick={() => {
                if (confirm("Cancel this scan? In-flight operations will be stopped.")) {
                  cancel.mutate(id, {
                    onSuccess: () => navigate(0),
                  })
                }
              }}
              disabled={cancel.isPending}
            >
              <X className="mr-1 h-4 w-4" />
              Cancel
            </Button>
          )}
        </div>
      </header>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Phase progress</CardTitle>
            <CardDescription>Real-time view of the autonomous engagement.</CardDescription>
          </CardHeader>
          <CardContent>
            <PhaseProgress
              phase={scan.phase ?? null}
              status={scan.status}
              progress={scan.progress}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Risk score</CardTitle>
            <CardDescription>AI-derived composite risk</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-center py-2">
            <RiskScoreRing score={scan.risk_score ?? 0} />
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">
            <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            Findings
          </TabsTrigger>
          <TabsTrigger value="recon">
            <Network className="mr-1.5 h-3.5 w-3.5" />
            Recon
          </TabsTrigger>
          <TabsTrigger value="events">
            <Terminal className="mr-1.5 h-3.5 w-3.5" />
            Events
          </TabsTrigger>
          <TabsTrigger value="ai">
            <Sparkles className="mr-1.5 h-3.5 w-3.5" />
            AI analysis
          </TabsTrigger>
        </TabsList>

        <TabsContent value="findings">
          <FindingsTab scanId={id} />
        </TabsContent>
        <TabsContent value="recon">
          <ReconTab scan={scan} />
        </TabsContent>
        <TabsContent value="events">
          <EventsTab scanId={id} />
        </TabsContent>
        <TabsContent value="ai">
          <AITab scan={scan} />
        </TabsContent>
      </Tabs>
    </>
  )
}

function FindingsTab({ scanId }: { scanId: string }) {
  const { data, isLoading, error, refetch } = useScanFindings(scanId)
  if (error) return <ErrorState message={String(error)} onRetry={() => refetch()} />
  if (isLoading) return <Skeleton className="h-64 w-full" />
  if (!data || data.length === 0)
    return (
      <EmptyState
        title="No findings yet"
        description="Findings will appear here as the engagement progresses."
      />
    )

  return (
    <div className="space-y-2">
      {data.map((f) => (
        <Card key={f.id}>
          <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-start sm:justify-between">
            <div className="min-w-0 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <h3 className="truncate font-medium text-foreground">{f.title}</h3>
                {f.cve && (
                  <Badge variant="outline" className="font-mono">
                    {f.cve}
                  </Badge>
                )}
              </div>
              {f.description && (
                <p className="text-sm leading-relaxed text-muted-foreground">{f.description}</p>
              )}
              <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                {f.host && <span className="font-mono">{f.host}</span>}
                {f.port != null && <span className="font-mono">:{f.port}</span>}
                {f.path && <span className="font-mono">{f.path}</span>}
                <span>· {formatRelative(f.detected_at)}</span>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {f.cvss != null && (
                <Badge variant="outline" className="font-mono">
                  CVSS {f.cvss.toFixed(1)}
                </Badge>
              )}
              <Button variant="ghost" size="icon" aria-label="Open finding">
                <ExternalLink className="h-4 w-4" />
              </Button>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

function EventsTab({ scanId }: { scanId: string }) {
  const { data, isLoading, error, refetch } = useScanEvents(scanId)
  return (
    <LiveFeed
      title="Engagement events"
      events={data ?? []}
      isLoading={isLoading}
      error={error ? String(error) : null}
      onRetry={() => refetch()}
      filterKey={`scan:${scanId}`}
    />
  )
}

function ReconTab({ scan }: { scan: NonNullable<ReturnType<typeof useScan>["data"]> }) {
  const recon = scan.recon ?? null
  if (!recon)
    return (
      <EmptyState
        title="No recon data"
        description="Reconnaissance data will appear once the recon phase begins."
      />
    )
  return (
    <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
      <ReconCard title="Subdomains" items={recon.subdomains ?? []} />
      <ReconCard title="Open ports" items={(recon.open_ports ?? []).map((p) => `${p.host}:${p.port}`)} />
      <ReconCard title="Technologies" items={recon.technologies ?? []} />
      <ReconCard title="Endpoints" items={recon.endpoints ?? []} />
      <ReconCard title="Certificates" items={recon.certificates ?? []} />
      <ReconCard title="DNS records" items={recon.dns_records ?? []} />
    </div>
  )
}

function ReconCard({ title, items }: { title: string; items: string[] }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center justify-between text-sm">
          <span>{title}</span>
          <Badge variant="outline" className="font-mono">
            {items.length}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="max-h-64 overflow-y-auto p-0">
        {items.length === 0 ? (
          <div className="px-4 pb-4 text-xs text-muted-foreground">No data</div>
        ) : (
          <ul className="divide-y divide-border/60">
            {items.map((it, i) => (
              <li key={i} className="px-4 py-2 font-mono text-xs text-foreground/90">
                {it}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function AITab({ scan }: { scan: NonNullable<ReturnType<typeof useScan>["data"]> }) {
  const summary = scan.ai_summary
  if (!summary)
    return (
      <EmptyState
        title="No AI analysis yet"
        description="Once enough signal is collected, the model will produce an exploit chain and remediation guidance."
      />
    )
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Summary</CardTitle>
        </CardHeader>
        <CardContent className="prose prose-sm prose-invert max-w-none whitespace-pre-wrap text-sm leading-relaxed text-foreground/90">
          {summary.summary}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Exploit chain</CardTitle>
          <CardDescription>Ordered steps proposed by the model</CardDescription>
        </CardHeader>
        <CardContent>
          {summary.exploit_chain?.length ? (
            <ol className="space-y-3 text-sm">
              {summary.exploit_chain.map((step, i) => (
                <li key={i} className="flex gap-3">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border bg-muted font-mono text-xs">
                    {i + 1}
                  </span>
                  <div className="space-y-1">
                    <div className="font-medium text-foreground">{step.title}</div>
                    {step.detail && <div className="text-muted-foreground">{step.detail}</div>}
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-sm text-muted-foreground">No chain produced.</p>
          )}
        </CardContent>
      </Card>
      {summary.remediation?.length ? (
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Remediation</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm">
              {summary.remediation.map((r, i) => (
                <li key={i} className="flex gap-2">
                  <span className="text-muted-foreground">—</span>
                  <span className="text-foreground/90">{r}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ) : null}
    </div>
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
