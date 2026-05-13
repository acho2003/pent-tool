import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { EmptyState, ErrorState } from "@/components/states"
import { SeverityBadge } from "@/components/severity-badge"
import { useEmails, useEmailVerdict } from "@/api/queries"
import { formatRelative, cn } from "@/lib/utils"
import type { EmailItem } from "@/types/api"
import { Mail, ShieldCheck, ShieldAlert, Skull } from "lucide-react"

export default function EmailTriagePage() {
  const { data, isLoading, error, refetch } = useEmails()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const verdict = useEmailVerdict()

  const selected = data?.find((e) => e.id === selectedId) ?? data?.[0]

  return (
    <>
      <header>
        <h1 className="font-sans text-2xl font-semibold tracking-tight">Email triage</h1>
        <p className="text-sm text-muted-foreground">AgentMail inbox with AI verdicts and one-click response.</p>
      </header>

      {error ? (
        <ErrorState message={String(error)} onRetry={() => refetch()} />
      ) : isLoading ? (
        <div className="grid gap-4 lg:grid-cols-[360px_1fr]">
          <Skeleton className="h-[600px]" />
          <Skeleton className="h-[600px]" />
        </div>
      ) : !data || data.length === 0 ? (
        <EmptyState
          title="Inbox is empty"
          description="Connect AgentMail to start receiving and triaging emails."
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[360px_1fr]">
          <Card className="overflow-hidden">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Inbox</CardTitle>
              <CardDescription>{data.length} messages</CardDescription>
            </CardHeader>
            <CardContent className="max-h-[640px] overflow-y-auto p-0">
              <ul className="divide-y divide-border/60">
                {data.map((e) => {
                  const active = (selected?.id ?? null) === e.id
                  return (
                    <li key={e.id}>
                      <button
                        type="button"
                        onClick={() => setSelectedId(e.id)}
                        className={cn(
                          "w-full px-4 py-3 text-left transition-colors hover:bg-muted/40",
                          active && "bg-muted/50",
                        )}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-mono text-xs text-muted-foreground">{e.from}</span>
                          <VerdictDot verdict={e.verdict} />
                        </div>
                        <div className="mt-1 truncate text-sm font-medium text-foreground">{e.subject}</div>
                        <div className="mt-1 truncate text-xs text-muted-foreground">{e.snippet}</div>
                        <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
                          <span>{formatRelative(e.received_at)}</span>
                          {e.severity && (
                            <>
                              <span>·</span>
                              <SeverityBadge severity={e.severity} />
                            </>
                          )}
                        </div>
                      </button>
                    </li>
                  )
                })}
              </ul>
            </CardContent>
          </Card>

          {selected ? (
            <Card className="flex flex-col">
              <CardHeader className="border-b border-border pb-4">
                <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <CardTitle className="text-base">{selected.subject}</CardTitle>
                    <CardDescription className="font-mono text-xs">
                      {selected.from} · {formatRelative(selected.received_at)}
                    </CardDescription>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <VerdictBadge verdict={selected.verdict} />
                    {selected.severity && <SeverityBadge severity={selected.severity} />}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="flex-1 overflow-y-auto">
                <Tabs defaultValue="body">
                  <TabsList>
                    <TabsTrigger value="body">Message</TabsTrigger>
                    <TabsTrigger value="analysis">AI analysis</TabsTrigger>
                    <TabsTrigger value="headers">Headers</TabsTrigger>
                  </TabsList>
                  <TabsContent value="body">
                    <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-foreground/90">
                      {selected.body ?? selected.snippet}
                    </pre>
                  </TabsContent>
                  <TabsContent value="analysis">
                    <div className="space-y-3 text-sm">
                      {selected.analysis ? (
                        <>
                          <p className="leading-relaxed text-foreground/90">{selected.analysis.summary}</p>
                          {selected.analysis.indicators?.length ? (
                            <div>
                              <div className="mb-1 text-xs uppercase tracking-wider text-muted-foreground">
                                Indicators
                              </div>
                              <div className="flex flex-wrap gap-1.5">
                                {selected.analysis.indicators.map((ind, i) => (
                                  <Badge key={i} variant="outline" className="font-mono">
                                    {ind}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          ) : null}
                        </>
                      ) : (
                        <p className="text-muted-foreground">No analysis available.</p>
                      )}
                    </div>
                  </TabsContent>
                  <TabsContent value="headers">
                    <pre className="overflow-x-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-xs text-foreground/80">
                      {JSON.stringify(selected.headers ?? {}, null, 2)}
                    </pre>
                  </TabsContent>
                </Tabs>
              </CardContent>
              <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-6 py-3">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => verdict.mutate({ id: selected.id, verdict: "benign" })}
                  disabled={verdict.isPending}
                >
                  <ShieldCheck className="mr-1 h-4 w-4" /> Mark benign
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => verdict.mutate({ id: selected.id, verdict: "suspicious" })}
                  disabled={verdict.isPending}
                >
                  <ShieldAlert className="mr-1 h-4 w-4" /> Suspicious
                </Button>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => verdict.mutate({ id: selected.id, verdict: "malicious" })}
                  disabled={verdict.isPending}
                >
                  <Skull className="mr-1 h-4 w-4" /> Malicious
                </Button>
              </div>
            </Card>
          ) : (
            <Card className="flex items-center justify-center p-12">
              <div className="text-center text-muted-foreground">
                <Mail className="mx-auto mb-2 h-8 w-8 opacity-50" />
                <p className="text-sm">Select a message</p>
              </div>
            </Card>
          )}
        </div>
      )}
    </>
  )
}

function VerdictDot({ verdict }: { verdict?: EmailItem["verdict"] }) {
  const color =
    verdict === "malicious"
      ? "bg-severity-critical"
      : verdict === "suspicious"
        ? "bg-severity-high"
        : verdict === "benign"
          ? "bg-success"
          : "bg-muted-foreground"
  return <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", color)} />
}

function VerdictBadge({ verdict }: { verdict?: EmailItem["verdict"] }) {
  if (!verdict) return <Badge variant="outline">Unscored</Badge>
  const map = {
    malicious: "border-severity-critical/40 bg-severity-critical/10 text-severity-critical",
    suspicious: "border-severity-high/40 bg-severity-high/10 text-severity-high",
    benign: "border-success/40 bg-success/10 text-success",
  } as const
  return (
    <Badge variant="outline" className={cn("capitalize", map[verdict])}>
      {verdict}
    </Badge>
  )
}
