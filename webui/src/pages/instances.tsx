import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { EmptyState, ErrorState } from "@/components/states"
import { useInstances, useInstanceAction } from "@/api/queries"
import { formatRelative, cn } from "@/lib/utils"
import type { Instance } from "@/types/api"
import { Cpu, MemoryStick, Activity, Pause, Play, RotateCw } from "lucide-react"

export default function InstancesPage() {
  const { data, isLoading, error, refetch } = useInstances()

  return (
    <>
      <header className="flex flex-col gap-1">
        <h1 className="font-sans text-2xl font-semibold tracking-tight">Instances</h1>
        <p className="text-sm text-muted-foreground">Worker agents executing offensive operations.</p>
      </header>

      {error ? (
        <ErrorState message={String(error)} onRetry={() => refetch()} />
      ) : isLoading ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-44" />
          ))}
        </div>
      ) : !data || data.length === 0 ? (
        <EmptyState title="No instances registered" description="Start a worker agent to see it here." />
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {data.map((inst) => (
            <InstanceCard key={inst.id} instance={inst} />
          ))}
        </div>
      )}
    </>
  )
}

function InstanceCard({ instance }: { instance: Instance }) {
  const action = useInstanceAction()
  const stateColor =
    instance.state === "online"
      ? "bg-success"
      : instance.state === "busy"
        ? "bg-warning"
        : instance.state === "offline"
          ? "bg-muted-foreground"
          : "bg-destructive"

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <CardTitle className="truncate font-mono text-sm">{instance.name ?? instance.id}</CardTitle>
            <CardDescription className="truncate text-xs">{instance.region ?? "—"}</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <span className={cn("h-2 w-2 rounded-full", stateColor)} />
            <Badge variant="outline" className="capitalize">
              {instance.state}
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-3 gap-2 text-xs">
          <Stat icon={<Cpu className="h-3 w-3" />} label="CPU" value={pct(instance.cpu_pct)} />
          <Stat icon={<MemoryStick className="h-3 w-3" />} label="MEM" value={pct(instance.mem_pct)} />
          <Stat icon={<Activity className="h-3 w-3" />} label="JOBS" value={String(instance.active_jobs ?? 0)} />
        </div>
        <div className="border-t border-border pt-3 text-xs text-muted-foreground">
          <div>Last seen {formatRelative(instance.last_seen)}</div>
          {instance.version && <div className="font-mono">v{instance.version}</div>}
        </div>
        <div className="flex flex-wrap gap-2 pt-1">
          <Button
            size="sm"
            variant="outline"
            disabled={action.isPending || instance.state === "offline"}
            onClick={() => action.mutate({ id: instance.id, action: "pause" })}
          >
            <Pause className="mr-1 h-3.5 w-3.5" /> Pause
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={action.isPending}
            onClick={() => action.mutate({ id: instance.id, action: "resume" })}
          >
            <Play className="mr-1 h-3.5 w-3.5" /> Resume
          </Button>
          <Button
            size="sm"
            variant="ghost"
            disabled={action.isPending}
            onClick={() => action.mutate({ id: instance.id, action: "restart" })}
          >
            <RotateCw className="mr-1 h-3.5 w-3.5" /> Restart
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="font-mono text-base text-foreground">{value}</div>
    </div>
  )
}

function pct(n: number | null | undefined) {
  if (n == null) return "—"
  return `${Math.round(n)}%`
}
