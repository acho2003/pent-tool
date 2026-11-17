import type { AssessmentTarget } from "@/types/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";

export function NextjsSourceSetup({ targets, links, onChange }: {
  targets: AssessmentTarget[];
  links: Record<string, string>;
  onChange: (links: Record<string, string>) => void;
}) {
  const sources = targets.filter(target => target.type === "REPOSITORY" || target.type === "LOCAL_SOURCE_PATH");
  const sites = targets.filter(target => target.type === "URL");
  if (!sources.length || !sites.length) return null;
  return <Card><CardHeader><CardTitle>Link source code to each site</CardTitle><p className="text-xs text-muted-foreground">Choose which source target belongs to each site. Routes declared in that code (NestJS controllers, Next.js pages and route handlers) are added to the site's scan so endpoints the crawler cannot find are still tested, and recorded Next.js versions are compared with the version observed at runtime. Service rows with a repository are linked automatically.</p></CardHeader><CardContent className="space-y-3">
    {sites.map(target => <div key={target.id} className="space-y-2"><Label htmlFor={`nextjs-source-${target.id}`}>{target.value}</Label><select id={`nextjs-source-${target.id}`} className="w-full rounded border bg-background p-2" value={sources.some(source => source.value === links[target.value]) ? links[target.value] : ""} onChange={event => onChange({ ...links, [target.value]: event.target.value })}><option value="">{target.related_to ? "Linked by its service row" : "No linked source"}</option>{sources.map(source => <option key={source.id} value={source.value}>{source.value}</option>)}</select></div>)}
  </CardContent></Card>;
}
