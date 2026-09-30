import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, ExternalLink, FolderOpen, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { api, HttpError } from "@/api/client";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SeverityBadge } from "@/components/severity-badge";
import { ScanStatusPill } from "@/components/scan-status-pill";
import { EmptyState } from "@/components/states";
import { Skeleton } from "@/components/ui/skeleton";
import { DEFAULT_PAGE_SIZE, PAGE_SIZE_OPTIONS, Pagination } from "@/components/Pagination";
import type { FindingsProject, FindingsProjectScan, ScanFinding } from "@/types/api";
import { timeAgo } from "@/lib/utils";

const activeStatuses = new Set(["POTENTIAL", "CONFIRMED", "ACCEPTED_RISK"]);
const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

function SeverityTotals({ totals }: { totals: Record<string, number> }) {
  return <div className="flex flex-wrap gap-1.5" aria-label="Active findings by severity">{severityOrder.map((severity) => <span key={severity} className="rounded-md border bg-muted/10 px-2 py-1 text-[11px] text-muted-foreground"><span className="font-semibold text-foreground">{totals[severity] ?? 0}</span> {severity}</span>)}</div>;
}

function useFindingProjects() {
  return useQuery({ queryKey: ["findings", "projects"], queryFn: api.listFindingProjects, refetchInterval: 15_000 });
}

export default function FindingsPage() {
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const projectID = params.get("project") ?? "";
  const scanID = params.get("scan") ?? "";
  const projectsQuery = useFindingProjects();
  const projects = projectsQuery.data?.projects ?? [];
  const project = projects.find((item) => item.id === projectID);
  const scan = project?.scans.find((item) => item.id === scanID);
  const [projectSearch, setProjectSearch] = useState("");
  const [scanSearch, setScanSearch] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [scanner, setScanner] = useState("");
  const [page, setPage] = useState(() => Math.max(1, Number(params.get("page")) || 1));
  const [pageSize, setPageSize] = useState(() => {
    const size = Number(params.get("size"));
    return (PAGE_SIZE_OPTIONS as readonly number[]).includes(size) ? size : DEFAULT_PAGE_SIZE;
  });
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [actionError, setActionError] = useState("");

  const findingsQuery = useQuery({
    queryKey: ["findings", "scan", scan?.id, page, pageSize, query, severity, status, scanner],
    queryFn: () => api.listScanFindings(scan!.id, { page, size: pageSize, q: query, severity, status, scanner }),
    enabled: !!scan,
    refetchInterval: scan?.status === "running" ? 10_000 : false,
  });
  const findings = findingsQuery.data?.items ?? [];
  const total = findingsQuery.data?.total ?? 0;

  useEffect(() => { setSelected(new Set()); setActionError(""); }, [scanID]);
  useEffect(() => {
    if (findingsQuery.data) setPage((current) => Math.min(current, Math.max(1, Math.ceil(total / pageSize))));
  }, [findingsQuery.data, total, pageSize]);

  function choose(nextProject?: FindingsProject, nextScan?: FindingsProjectScan) {
    const next = new URLSearchParams(params);
    if (nextProject) next.set("project", nextProject.id); else next.delete("project");
    if (nextScan) next.set("scan", nextScan.id); else next.delete("scan");
    next.delete("page");
    setPage(1);
    setSelected(new Set());
    setActionError("");
    setParams(next);
  }

  async function deleteSelected() {
    if (!scan || selected.size === 0 || !window.confirm(`Permanently delete ${selected.size} selected finding${selected.size === 1 ? "" : "s"}?`)) return;
    setActionError("");
    try {
      for (const id of selected) await api.deleteVuln(scan.id, id);
      setSelected(new Set());
      await Promise.all([qc.invalidateQueries({ queryKey: ["findings", "scan", scan.id] }), qc.invalidateQueries({ queryKey: ["findings", "projects"] })]);
    } catch (error) {
      setActionError(error instanceof HttpError && error.status === 409 ? "Scanner-backed findings cannot be deleted. Change their analyst status in Scan Detail." : error instanceof Error ? error.message : "Could not delete finding.");
    }
  }

  const filteredProjects = useMemo(() => projects.filter((item) => !projectSearch || [item.label, ...item.scans.map((scan) => scan.name || scan.target)].some((value) => value.toLowerCase().includes(projectSearch.toLowerCase()))), [projects, projectSearch]);
  const filteredScans = useMemo(() => (project?.scans ?? []).filter((item) => !scanSearch || [item.name, item.target, item.id].some((value) => (value ?? "").toLowerCase().includes(scanSearch.toLowerCase()))), [project, scanSearch]);

  return <div className="space-y-5">
    <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {(projectID || scanID) && <div className="mb-2 flex flex-wrap items-center gap-1 text-xs text-muted-foreground"><button type="button" onClick={() => choose()} className="hover:text-primary">Projects</button>{projectID && <><ChevronRight className="h-3 w-3" /><button type="button" onClick={() => choose(project)} className="max-w-[24ch] truncate hover:text-primary">{project?.label ?? projectID}</button></>}{scanID && <><ChevronRight className="h-3 w-3" /><span className="font-medium text-foreground">{scan?.name || scan?.target || scanID}</span></>}</div>}
        <h1 className="text-2xl font-semibold tracking-tight">{scan ? scan.name || scan.target : project ? project.label : "Findings"}</h1>
        <p className="mt-1 text-sm text-muted-foreground">{scan ? `Findings from this scan · ${timeAgo(scan.started_at)}` : project ? `${project.scan_count} scan${project.scan_count === 1 ? "" : "s"} for this target` : "Select a project, then a scan, to review its findings."}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {scan && <Button variant="outline" size="sm" asChild><Link to={`/scans/${scan.id}`}><ExternalLink className="h-3.5 w-3.5" /> Open scan</Link></Button>}
        <Button variant="outline" size="sm" onClick={() => { void qc.invalidateQueries({ queryKey: ["findings", "projects"] }); if (scan) void qc.invalidateQueries({ queryKey: ["findings", "scan", scan.id] }); }} disabled={projectsQuery.isFetching || findingsQuery.isFetching}><RefreshCw className={`h-3.5 w-3.5 ${(projectsQuery.isFetching || findingsQuery.isFetching) ? "animate-spin" : ""}`} /> Refresh</Button>
      </div>
    </header>

    {(scan || project) && <div className="flex flex-col gap-2 rounded-lg border bg-card p-3 sm:flex-row sm:items-center sm:justify-between"><div className="text-sm"><span className="font-semibold">{scan ? scan.active_count : project?.active_count} active</span><span className="ml-2 text-muted-foreground">· {scan ? scan.finding_count : project?.finding_count} unique in {scan ? "this scan" : "these scans"} · {scan ? scan.observation_count : project?.observation_count} observations</span></div><SeverityTotals totals={(scan ?? project)!.severity} /></div>}

    {projectsQuery.isLoading && <Card><CardContent className="space-y-2 p-4">{Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-16 w-full" />)}</CardContent></Card>}
    {projectsQuery.isError && <Card><CardContent className="p-5 text-sm text-destructive">Could not load finding projects. <button type="button" onClick={() => void projectsQuery.refetch()} className="underline">Retry</button></CardContent></Card>}
    {!projectsQuery.isLoading && !projectsQuery.isError && !projectID && <>
      <div className="relative"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input aria-label="Search projects" placeholder="Search projects by target or scan name…" value={projectSearch} onChange={(event) => setProjectSearch(event.target.value)} className="pl-9" /></div>
      {filteredProjects.length ? <div className="grid gap-3 sm:grid-cols-2">{filteredProjects.map((item) => <button key={item.id} type="button" onClick={() => choose(item)} className="rounded-lg border bg-card p-4 text-left transition-colors hover:border-primary/50 hover:bg-primary/5 focus-visible:ring-2 focus-visible:ring-ring"><div className="flex items-start justify-between gap-2"><div className="flex min-w-0 items-center gap-2"><FolderOpen className="h-4 w-4 shrink-0 text-primary" /><span className="truncate font-semibold">{item.label}</span></div><ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" /></div><p className="mt-2 text-xs text-muted-foreground">{item.scan_count} scan{item.scan_count === 1 ? "" : "s"} · {item.active_count} active findings · {item.observation_count} observations</p><div className="mt-3"><SeverityTotals totals={item.severity} /></div><p className="mt-3 text-[11px] text-muted-foreground">Latest scan {timeAgo(item.latest_at)}</p></button>)}</div> : <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title={projects.length ? "No matching projects" : "No scan projects yet"} description={projects.length ? "Try a different project search." : "Run an assessment to create a project history."} />}
    </>}

    {!projectsQuery.isLoading && projectID && !project && <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title="Project not found" description="This project may have been removed or its target changed." />}
    {project && !scanID && <>
      <div className="relative"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input aria-label="Search scans" placeholder="Search scans in this project…" value={scanSearch} onChange={(event) => setScanSearch(event.target.value)} className="pl-9" /></div>
      {filteredScans.length ? <Card><ul className="divide-y">{filteredScans.map((item) => <li key={item.id}><button type="button" onClick={() => choose(project, item)} className="flex w-full flex-col gap-2 p-4 text-left hover:bg-muted/20 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className="font-medium">{item.name || item.target}</span><ScanStatusPill status={item.status} /></div><p className="mt-1 break-all text-xs text-muted-foreground">{item.target} · {item.id} · {timeAgo(item.started_at)}{item.parent_target && item.parent_target !== item.target ? ` · child of ${item.parent_target}` : ""}</p></div><div className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground"><span>{item.active_count} active · {item.finding_count} findings · {item.observation_count} observations</span><ChevronRight className="h-4 w-4" /></div></button></li>)}</ul></Card> : <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title="No matching scans" description="Try a different scan search." />}
    </>}

    {project && scanID && !scan && <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title="Scan not found in this project" description="Choose a scan from this project's history." />}
    {scan && <>
      <Card><CardContent className="grid gap-3 p-3 sm:grid-cols-2 lg:grid-cols-4"><div className="relative sm:col-span-2"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input aria-label="Search findings" placeholder="Search title, endpoint, CVE, or parameter…" value={query} onChange={(event) => { setQuery(event.target.value); setPage(1); setSelected(new Set()); }} className="pl-9" /></div><Select value={severity} onValueChange={(value) => { setSeverity(value); setPage(1); setSelected(new Set()); }}><SelectTrigger aria-label="Filter by severity"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All severities</SelectItem>{severityOrder.map((value) => <SelectItem key={value} value={value}>{value}</SelectItem>)}</SelectContent></Select><Select value={status} onValueChange={(value) => { setStatus(value); setPage(1); setSelected(new Set()); }}><SelectTrigger aria-label="Filter by status"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All statuses</SelectItem>{["POTENTIAL", "CONFIRMED", "ACCEPTED_RISK", "OBSERVATION", "LIKELY_FALSE_POSITIVE", "FALSE_POSITIVE", "REMEDIATED"].map((value) => <SelectItem key={value} value={value}>{value.replaceAll("_", " ")}</SelectItem>)}</SelectContent></Select><Input aria-label="Filter by scanner" placeholder="Scanner name…" value={scanner} onChange={(event) => { setScanner(event.target.value); setPage(1); setSelected(new Set()); }} className="sm:col-span-2 lg:col-span-4" /></CardContent>{findings.length > 0 && <div className="flex items-center gap-2 border-t px-3 py-2"><Button size="sm" variant="outline" onClick={() => setSelected((current) => { const next = new Set(current); const allVisible = findings.every((item) => next.has(item.id)); for (const item of findings) { if (allVisible) next.delete(item.id); else next.add(item.id); } return next; })}>{findings.every((item) => selected.has(item.id)) ? "Clear page" : "Select page"}</Button><span className="text-xs text-muted-foreground">{selected.size} selected in this scan</span><Button size="sm" variant="outline" disabled={selected.size === 0} onClick={() => void deleteSelected()}>Delete selected</Button></div>}</Card>
      {actionError && <p role="alert" className="text-sm text-destructive">{actionError}</p>}
      <Card>{findingsQuery.isLoading ? <CardContent className="space-y-2 p-4">{Array.from({ length: 5 }, (_, index) => <Skeleton key={index} className="h-16 w-full" />)}</CardContent> : findingsQuery.isError ? <CardContent className="p-5 text-sm text-destructive">Could not load this scan's findings. <button type="button" onClick={() => void findingsQuery.refetch()} className="underline">Retry</button></CardContent> : findings.length ? <><ul className="divide-y">{findings.map((finding) => <FindingRow key={finding.id} scanID={scan.id} finding={finding} selected={selected.has(finding.id)} onSelect={(checked) => setSelected((current) => { const next = new Set(current); if (checked) next.add(finding.id); else next.delete(finding.id); return next; })} />)}</ul><Pagination totalItems={total} page={page} pageSize={pageSize} onPageChange={setPage} onPageSizeChange={setPageSize} /></> : <EmptyState icon={<ShieldAlert className="h-6 w-6" />} title="No matching findings in this scan" description="Try widening the filters, or review another scan." />}</Card>
    </>}
  </div>;
}

function FindingRow({ scanID, finding, selected, onSelect }: { scanID: string; finding: ScanFinding; selected: boolean; onSelect: (checked: boolean) => void }) {
  const [open, setOpen] = useState(false);
  const observations = useQuery({ queryKey: ["findings", "observations", scanID, finding.id], queryFn: () => api.findingObservations(scanID, finding.id, { page: 1, size: 10 }), enabled: open });
  const endpoint = finding.endpoints?.[0]?.endpoint || finding.target || "No endpoint recorded";
  return <li className="p-4"><div className="flex items-start gap-3"><input type="checkbox" checked={selected} onChange={(event) => onSelect(event.target.checked)} aria-label={`Select finding ${finding.title}`} className="mt-1 h-4 w-4 shrink-0 accent-primary" /><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={finding.severity} /><span className="font-medium">{finding.title}</span><span className={`rounded border px-2 py-0.5 text-[10px] ${activeStatuses.has(finding.status) ? "text-primary" : "text-muted-foreground"}`}>{finding.status.replaceAll("_", " ")}</span></div><p className="mt-1 truncate text-xs text-muted-foreground" title={endpoint}>{endpoint}</p><p className="mt-1 text-[11px] text-muted-foreground">{finding.affected_endpoint_count} affected endpoints · {finding.affected_instance_count} instances · {finding.observation_count} observations · {(finding.scanners ?? []).join(", ") || "Unknown scanner"}</p></div><Link to={`/scans/${scanID}`} aria-label={`Open scan for ${finding.title}`} className="rounded-md p-1 text-muted-foreground hover:text-primary"><ExternalLink className="h-4 w-4" /></Link></div><button type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open} className="mt-3 flex items-center gap-1 text-xs text-primary hover:underline">{open ? "Hide evidence" : "View endpoints and evidence"}<ChevronRight className={`h-3.5 w-3.5 transition-transform ${open ? "rotate-90" : ""}`} /></button>{open && <div className="mt-3 space-y-3 rounded-md border bg-muted/10 p-3 text-xs"><div><p className="font-medium">Affected endpoints</p>{finding.endpoints?.length ? finding.endpoints.slice(0, 5).map((item, index) => <p key={`${item.canonical_endpoint || item.endpoint}-${index}`} className="mt-1 break-all font-mono text-muted-foreground">{item.method || "GET"} {item.endpoint || item.canonical_endpoint}{item.parameter ? ` · ${item.parameter_location || "parameter"}: ${item.parameter}` : ""}</p>) : <p className="mt-1 text-muted-foreground">No endpoint details recorded.</p>}{finding.affected_endpoint_count > 5 && <p className="mt-1 text-muted-foreground">Showing 5 of {finding.affected_endpoint_count} endpoints.</p>}</div><div><p className="font-medium">Scanner observations</p>{observations.isLoading && <p className="mt-1 text-muted-foreground">Loading evidence…</p>}{observations.isError && <p className="mt-1 text-destructive">Could not load observations.</p>}{observations.data?.items.map((item) => <div key={item.id} className="mt-2 border-l-2 border-primary/30 pl-2"><p>{item.scanner} · {item.title}</p>{item.evidence_reference && <p className="break-all text-muted-foreground">Artifact: {item.evidence_reference}</p>}{item.evidence && <p className="mt-1 line-clamp-3 whitespace-pre-wrap break-words font-mono text-muted-foreground">{item.evidence}</p>}</div>)}{observations.data && observations.data.total > observations.data.items.length && <p className="mt-2 text-muted-foreground">Showing {observations.data.items.length} of {observations.data.total} observations. Open the scan for the full record.</p>}</div></div>}</li>;
}
