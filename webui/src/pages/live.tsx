import { useState } from "react"
import { useWSStore } from "@/store/ws"
import { LiveFeed, type FeedFilter } from "@/components/live-feed"
import { ConnectionStatus } from "@/components/connection-status"

export default function LivePage() {
  const events = useWSStore((s) => s.events)
  const [filter, setFilter] = useState<FeedFilter>("all")

  return (
    <>
      <header className="flex items-center justify-between gap-3">
        <div>
          <h1 className="font-sans text-2xl font-semibold tracking-tight">Live feed</h1>
          <p className="text-sm text-muted-foreground">
            Streaming events from every active scan and worker.
          </p>
        </div>
        <ConnectionStatus />
      </header>
      <LiveFeed
        events={events}
        filter={filter}
        onFilterChange={setFilter}
        emptyTitle="Quiet on the wire"
        emptyDescription="Events from any running instance will appear here in real time."
      />
    </>
  )
}
