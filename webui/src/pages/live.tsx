import { useGlobalEvents } from "@/api/queries"
import { LiveFeed } from "@/components/live-feed"

export default function LivePage() {
  const { data, isLoading, error, refetch } = useGlobalEvents()
  return (
    <>
      <header>
        <h1 className="font-sans text-2xl font-semibold tracking-tight">Live operations</h1>
        <p className="text-sm text-muted-foreground">Real-time stream of every offensive action across the fleet.</p>
      </header>
      <LiveFeed
        title="Global event stream"
        events={data ?? []}
        isLoading={isLoading}
        error={error ? String(error) : null}
        onRetry={() => refetch()}
        filterKey="global"
        showFilters
      />
    </>
  )
}
