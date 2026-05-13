import { useMemo, useState } from "react"
import { Link } from "react-router-dom"
import { Card, CardContent } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ScanStatusPill, ScanPhaseBadge } from "@/components/scan-status-pill"
import { EmptyState, ErrorState } from "@/components/states"
import { Skeleton } from "@/components/ui/skeleton"
import { useScans } from "@/api/queries"
import { formatRelative } from "@/lib/utils"
import type { Scan } from "@/types/api"
import { Search, Plus, ArrowUpDown, AlertOctagon, AlertTriangle, Activity, Zap } from "lucide-react"
import NewScanDialog from "@/components/new-scan-dialog"

export default function ScansPage() {
  const { data, isLoading, error, refetch } = useScans()
  const [q, setQ] = useState("")
  const [status, setStatus] = useState<string>("all")
  const [newOpen, setNewOpen] = useState(false)

  const scans = useMemo(() => {
    let list = data ?? []
    if (status !== "all") list = list.filter((s) => s.status === status)
    if (q.trim()) {
      const needle = q.toLowerCase()
      list = list.filter(
        (s) =>
          s.target.toLowerCase().includes(needle) ||
          s.id.toLowerCase().includes(needle) ||
          (s.tags ?? []).some((t) => t.toLowerCase().includes(needle)),
      )
    }
    return list
  }, [data, q, status])

  return (
    <>
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-sans text-2xl font-semibold tracking-tight">Scans</h1>
          <p className="text-sm text-muted-foreground">Manage continuous offensive engagements.</p>
        </div>
        <Button onClick={() => setNewOpen(true)} className="self-start sm:self-auto">
          <Plus className="mr-1 h-4 w-4" />
          New scan
        </Button>
      </header>

      <Card>
        <CardContent className="p-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search target, scan id, or tag…"
                className="pl-9"
              />
            </div>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger className="w-full sm:w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="queued">Queued</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="cancelled">Cancelled</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {error ? (
        <ErrorState message={String(error)} onRetry={() => refetch()} />
      ) : isLoading ? (
        <ScanListSkeleton />
      ) : scans.length === 0 ? (
        <EmptyState
          title="No scans match"
          description="Adjust filters or kick off a new engagement."
          action={
            <Button onClick={() => setNewOpen(true)}>
              <Plus className="mr-1 h-4 w-4" />
              New scan
            </Button>
          }
        />
      ) : (
        <ScanTable scans={scans} />
      )}

      <NewScanDialog open={newOpen} onOpenChange={setNewOpen} />
    </>
  )
}

function ScanTable({ scans }: { scans: Scan[] }) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-muted/30 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <Th className="pl-4">
                  Target <ArrowUpDown className="ml-1 inline h-3 w-3 opacity-60" />
                </Th>
                <Th>Status</Th>
                <Th>Phase</Th>
                <Th>Findings</Th>
                <Th>Started</Th>
                <Th className="pr-4 text-right">Duration</Th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr
                  key={s.id}
                  className="group border-b border-border/60 last:border-0 transition-colors hover:bg-muted/30"
                >
                  <Td className="pl-4">
                    <Link to={`/scans/${s.id}`} className="block">
                      <div className="font-mono text-sm font-medium text-foreground group-hover:text-primary">
                        {s.target}
                      </div>
                      <div className="text-xs text-muted-foreground">{s.id.slice(0, 12)}</div>
                    </Link>
                  </Td>
                  <Td>
                    <ScanStatusPill status={s.status} />
                  </Td>
                  <Td>
                    {s.phase ? (
                      <ScanPhaseBadge phase={s.phase} />
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </Td>
                  <Td>
                    <FindingsInline scan={s} />
                  </Td>
                  <Td>
                    <span className="text-muted-foreground">
                      {s.started_at ? formatRelative(s.started_at) : "—"}
                    </span>
                  </Td>
                  <Td className="pr-4 text-right font-mono text-xs text-muted-foreground">
                    {durationOf(s)}
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  )
}

function FindingsInline({ scan }: { scan: Scan }) {
  const c = scan.findings_counts ?? {}
  const items: { icon: React.ReactNode; n: number; tone: string }[] = []
  if (c.critical) items.push({ icon: <AlertOctagon className="h-3 w-3" />, n: c.critical, tone: "text-severity-critical" })
  if (c.high) items.push({ icon: <AlertTriangle className="h-3 w-3" />, n: c.high, tone: "text-severity-high" })
  if (c.medium) items.push({ icon: <Activity className="h-3 w-3" />, n: c.medium, tone: "text-severity-medium" })
  if (c.low) items.push({ icon: <Zap className="h-3 w-3" />, n: c.low, tone: "text-severity-low" })
  if (items.length === 0) return <span className="text-muted-foreground">—</span>
  return (
    <div className="flex items-center gap-2">
      {items.map((it, i) => (
        <span key={i} className={`inline-flex items-center gap-1 font-mono text-xs ${it.tone}`}>
          {it.icon}
          {it.n}
        </span>
      ))}
    </div>
  )
}

function durationOf(s: Scan) {
  if (!s.started_at) return "—"
  const start = new Date(s.started_at).getTime()
  const end = s.completed_at ? new Date(s.completed_at).getTime() : Date.now()
  const sec = Math.max(0, Math.floor((end - start) / 1000))
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const ss = sec % 60
  if (h) return `${h}h ${m}m`
  if (m) return `${m}m ${ss}s`
  return `${ss}s`
}

function Th({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <th className={`px-3 py-2 text-left font-medium ${className}`}>{children}</th>
}
function Td({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <td className={`px-3 py-3 align-middle ${className}`}>{children}</td>
}

function ScanListSkeleton() {
  return (
    <Card>
      <CardContent className="space-y-2 p-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </CardContent>
    </Card>
  )
}
