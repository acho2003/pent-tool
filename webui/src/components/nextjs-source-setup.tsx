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
  return <Card><CardHeader><CardTitle>Related source and runtime versions</CardTitle><p className="text-xs text-muted-foreground">Choose which source target belongs to each site. The results compare recorded lockfile versions with an observed runtime version when both are available. Choose source/dependency coverage and Next.js asset discovery in the workflow. Missing evidence stays unknown.</p></CardHeader><CardContent className="space-y-3">
    {sites.map(target => <div key={target.id} className="space-y-2"><Label htmlFor={`nextjs-source-${target.id}`}>{target.value}</Label><select id={`nextjs-source-${target.id}`} className="w-full rounded border bg-background p-2" value={sources.some(source => source.value === links[target.value]) ? links[target.value] : ""} onChange={event => onChange({ ...links, [target.value]: event.target.value })}><option value="">No declared source relationship</option>{sources.map(source => <option key={source.id} value={source.value}>{source.value}</option>)}</select></div>)}
  </CardContent></Card>;
}
