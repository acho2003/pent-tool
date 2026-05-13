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
import { ScanStatusPill } from "@/components/scan-status-pill"
import { EmptyState, ErrorState } from "@/components/states"
import { Skeleton } from "@/components/ui/skeleton"
import { useScansList } from "@/api/queries"
import { timeAgo, shortId } from "@/lib/utils"
import type { ScanListItem } from "@/types/api"
import { Search, Plus, ArrowUpDown, ShieldAlert } from "lucide-react"
import NewScanDialog from "@/components/new-scan-dialog"

export default function ScansPage() {
  const { data, isLoading, error, refetch } = useScansList()
  const [q, setQ] = useState("")
  const [status, setStatus] = useState<string>("all")
  const [newOpen, setNewOpen] = useState(false)

  const scans = useMemo<ScanListItem[]>(() => {
    let list: ScanListItem[] = data ?? []
    if (status !== "all") list = list.filter((s) => s.status === status)
    if (q.trim()) {
      const needle = q.toLowerCase()
      list = list.filter(
        (s) =>
          s.target.toLowerCase().includes(needle) ||
          s.id.toLowerCase().includes(needle),
      )
    }
    // newest first
    return [...list].sort(
      (a, b) =>
        new Date(b.started_at).getTime() - new Date(a.started_at).getTime(),
    )
  }, [data, q, status])

  return (
    <>
      <header className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="font-sans text-2xl font-semibold tracking-tight">Scans</h1>
          <p className="text-sm text-muted-foreground">All historical and in-flight scans.</p>
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
                placeholder="Search target or scan id…"
                className="pl-9"
              />
            </div>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger className="w-full sm:w-44">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="running">Running</SelectItem>
                <SelectItem value="paused">Paused</SelectItem>
                <SelectItem value="saved">Saved</SelectItem>
                <SelectItem value="finished">Finished</SelectItem>
                <SelectItem value="stopped">Stopped</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {error ? (
        <ErrorState
          title="Could not load scans"
          description={String(error)}
          action={<Button size="sm" variant="outline" onClick={() => refetch()}>Retry</Button>}
        />
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

function ScanTable({ scans }: { scans: ScanListItem[] }) {
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
                <Th>Findings</Th>
                <Th>Tokens</Th>
                <Th className="pr-4">Started</Th>
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
                      <div className="mono text-sm font-medium text-foreground group-hover:text-primary">
                        {s.target}
                      </div>
                      <div className="text-xs text-muted-foreground mono">{shortId(s.id, 12)}</div>
                    </Link>
                  </Td>
                  <Td>
                    <ScanStatusPill status={s.status} />
                  </Td>
                  <Td>
                    <div className="inline-flex items-center gap-1 mono text-xs">
                      <ShieldAlert
                        className={
                          s.vuln_count > 0
                            ? "h-3 w-3 text-amber-400"
                            : "h-3 w-3 text-muted-foreground"
                        }
                      />
                      {s.vuln_count ?? 0}
                    </div>
                  </Td>
                  <Td className="mono text-xs text-muted-foreground">
                    {s.total_tokens ? s.total_tokens.toLocaleString() : "—"}
                  </Td>
                  <Td className="pr-4">
                    <span className="text-muted-foreground">{timeAgo(s.started_at)}</span>
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
