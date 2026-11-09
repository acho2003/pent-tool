import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { IntegrationInfo } from "@/types/api";

const groups: { id: string; title: string; description: string }[] = [
  { id: "web_api", title: "Web & API", description: "Discovery, crawling, web and API vulnerability testing" },
  { id: "network_servers", title: "Network & servers", description: "Service discovery, network vulnerability tests and host audits" },
  { id: "code", title: "Code, dependencies & containers", description: "Static analysis, secrets and dependency checks" },
  { id: "cloud", title: "Cloud", description: "Read-only cloud posture audits" },
  { id: "kubernetes", title: "Kubernetes", description: "Cluster benchmark checks" },
];

const integrationLabel: Record<string, string> = {
  bundled: "Bundled tool",
  service: "Service",
  "built-in": "Built-in check",
  "operator-supplied": "Operator-supplied",
};

const selectionLabel: Record<string, string> = {
  automatic: "Runs automatically",
  conditional: "Runs when its input exists",
  optional: "Optional",
  explicit_opt_in: "Explicit opt-in",
};

function ToolCard({ tool }: { tool: IntegrationInfo }) {
  return (
    <Card>
      <CardHeader className="space-y-2 pb-2">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-base">{tool.name}</CardTitle>
          <Badge variant={tool.available ? "success" : tool.integration === "operator-supplied" ? "warning" : "destructive"}>{tool.available ? "Available" : tool.integration === "operator-supplied" ? "Not configured" : "Unavailable"}</Badge>
        </div>
        <div className="flex flex-wrap gap-1">
          <Badge variant="outline">{integrationLabel[tool.integration] ?? tool.integration}</Badge>
          {tool.default_selection && <Badge variant="muted">{selectionLabel[tool.default_selection] ?? tool.default_selection}</Badge>}
          {tool.risk && <Badge variant="muted">{tool.risk} risk</Badge>}
        </div>
      </CardHeader>
      <CardContent className="space-y-1 text-xs text-muted-foreground">
        <p>{tool.summary}</p>
        {tool.version && <p className="break-all">Version: {tool.version}</p>}
        {tool.path && <p className="break-all font-mono">{tool.path}</p>}
        {!tool.available && tool.availability_reason && <p className="text-amber-300">{tool.availability_reason}</p>}
      </CardContent>
    </Card>
  );
}

export default function IntegrationsPage() {
  const query = useQuery({ queryKey: ["integrations"], queryFn: api.integrations, refetchInterval: 30000 });
  const tools = query.data?.integrations ?? [];
  const available = tools.filter((tool) => tool.available).length;
  const known = new Set(groups.map((group) => group.id));
  const sections = [...groups, ...(tools.some((tool) => !known.has(tool.group)) ? [{ id: "__other", title: "Other", description: "" }] : [])];
  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-2xl font-semibold">Scanner integrations</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {query.isLoading ? "Loading tools…" : `${tools.length} tools · ${available} available here. Execution integrations are fixed; operator-supplied tools need deployment configuration.`}
        </p>
        {query.isError && <p className="mt-2 text-sm text-red-400">Tool status could not be loaded.</p>}
      </header>
      {sections.map((section) => {
        const members = tools.filter((tool) => (section.id === "__other" ? !known.has(tool.group) : tool.group === section.id));
        if (!members.length) return null;
        return (
          <section key={section.id} className="space-y-3">
            <div>
              <h2 className="text-lg font-semibold">{section.title} <span className="text-sm font-normal text-muted-foreground">({members.filter((tool) => tool.available).length}/{members.length} available)</span></h2>
              {section.description && <p className="text-xs text-muted-foreground">{section.description}</p>}
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{members.map((tool) => <ToolCard key={tool.id} tool={tool} />)}</div>
          </section>
        );
      })}
    </div>
  );
}
