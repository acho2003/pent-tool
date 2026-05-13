import { useMemo } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Inbox, Mail, Radio, ShieldAlert } from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/states";
import { useAgentMail } from "@/api/queries";
import { useWSStore, type FeedEvent } from "@/store/ws";
import { timeAgo } from "@/lib/utils";

const EMAIL_PATTERN = /(email|inbox|mail|agentmail|smtp|imap|phish|spoof)/i;

export default function EmailTriagePage() {
  const { data: mail } = useAgentMail();
  const events = useWSStore((s) => s.events);

  const emailEvents = useMemo<FeedEvent[]>(
    () =>
      events.filter((e: FeedEvent) => {
        const text =
          (e.content || "") + " " + (e.output || "") + " " + (e.tool_name || "");
        return (
          (typeof e.type === "string" && EMAIL_PATTERN.test(e.type)) ||
          EMAIL_PATTERN.test(text)
        );
      }),
    [events],
  );

  const configured = !!mail?.pod && !!mail?.hasApiKey;

  return (
    <>
      <header className="space-y-1">
        <h1 className="font-sans text-2xl font-semibold tracking-tight">
          Email triage
        </h1>
        <p className="text-sm text-muted-foreground">
          Live AgentMail events and ingestion status.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Inbox className="h-4 w-4" /> AgentMail pod
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="font-mono text-sm text-foreground">
              {mail?.pod || (
                <span className="text-muted-foreground">not configured</span>
              )}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <ShieldAlert className="h-4 w-4" /> API key
            </CardTitle>
          </CardHeader>
          <CardContent>
            {mail?.hasApiKey ? (
              <Badge variant="success">
                <CheckCircle2 className="mr-1 h-3 w-3" /> set
              </Badge>
            ) : (
              <Badge variant="muted">missing</Badge>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Radio className="h-4 w-4" /> Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            {configured ? (
              <Badge variant="success">listening</Badge>
            ) : (
              <Badge variant="warning">setup required</Badge>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Mail className="h-4 w-4" /> Live events
            </CardTitle>
            <CardDescription>
              Filtered from the global agent stream. Triage decisions appear
              here as they happen.
            </CardDescription>
          </div>
          <Button asChild size="sm" variant="outline">
            <Link to="/settings">Configure</Link>
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          {emailEvents.length === 0 ? (
            <div className="p-6">
              <EmptyState
                title="No email events yet"
                description={
                  configured
                    ? "Inbound messages routed through AgentMail will appear here."
                    : "Add a pod and API key in Settings to begin ingestion."
                }
                icon={<Mail className="h-6 w-6" />}
                action={
                  !configured ? (
                    <Button asChild size="sm">
                      <Link to="/settings">Set up AgentMail</Link>
                    </Button>
                  ) : undefined
                }
              />
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {emailEvents.slice(0, 60).map((evt: FeedEvent) => {
                const text = evt.content || evt.output || evt.tool_name || "";
                return (
                  <li
                    key={evt._key}
                    className="flex items-start gap-3 px-4 py-3 text-sm hover:bg-muted/30"
                  >
                    <span className="mt-1 inline-flex h-2 w-2 shrink-0 rounded-full bg-success" />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {evt.type || "event"}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {timeAgo(evt.timestamp)}
                        </span>
                      </div>
                      {text && (
                        <p className="mt-1 truncate font-mono text-xs text-foreground/90">
                          {text}
                        </p>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    </>
  );
}
