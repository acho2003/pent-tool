import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { CoverageProof, DiscoveryRevision } from "@/types/api";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

export function WorkflowProof({ scanId, running, proof }: {scanId: string; running: boolean; proof?: CoverageProof}) {
 const [selected, setSelected] = useState<string[]>([]);
 const [revision, setRevision] = useState<DiscoveryRevision>();
 const [started, setStarted] = useState("");
 const discovery = useQuery({queryKey:["discovery-preview",scanId,running],queryFn:()=>api.discoveryPreview(scanId),enabled:!!proof?.expanded_enabled,retry:false});
 const approval = useMutation({mutationFn:()=>api.approveDiscovery(scanId,discovery.data!.fingerprint,selected),onSuccess:setRevision});
 const start = useMutation({mutationFn:()=>api.startScan({assessment:revision!.plan.config,plan_fingerprint:revision!.plan.fingerprint,targets:revision!.plan.config.assessment_targets.map(t=>t.value)}),onSuccess:r=>setStarted(r.instance_id)});
 if (!proof) return null;
 return <Card><CardHeader><CardTitle className="text-sm">Recorded coverage</CardTitle><CardDescription>Counts refer to saved inventory and scanner evidence. Submission and batch completion do not prove every check ran.</CardDescription></CardHeader><CardContent className="space-y-4">
 <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">{Object.entries({"Inventory requests":proof.discovered,"Supplied seeds":proof.seeds,"Observed hosts":proof.hosts,"Services":proof.services,"TLS services":proof.tls_services,"Forms":proof.forms,"Parameterized requests":proof.parameterized,"Observed with auth":proof.observed_with_auth}).map(([label,count])=><div className="rounded border p-2" key={label}><p className="text-muted-foreground">{label}</p><p className="font-medium">{count}</p></div>)}</div>
 <div className="overflow-auto"><table className="w-full text-left text-xs"><thead><tr>{["Scanner","Selected","Submitted","Acknowledged","Observed active endpoints","Batch completed","Failed","Skipped","Unknown"].map(label=><th className="whitespace-nowrap p-2" key={label}>{label}</th>)}</tr></thead><tbody>{proof.scanners.map(row=><tr className="border-t" key={row.scanner}>{[row.scanner,row.selected,row.submitted,row.acknowledged,row.exercised??"NOT TRACKED",row.batch_completed,row.failed,row.skipped,row.unknown].map((value,i)=><td className="whitespace-nowrap p-2" key={i}>{value}</td>)}</tr>)}</tbody></table></div>
 <p className="text-xs text-muted-foreground">{proof.not_tracked.map(metric=>`${metric.replaceAll("_"," ")}: NOT TRACKED`).join(" · ")}</p>
 {proof.definitions.map(definition=><p className="text-xs" key={definition.id}>{definition.kind} · {definition.state} · {definition.url} {definition.reason}</p>)}
 {proof.discovery_gaps.map((gap,i)=><p className="text-xs text-muted-foreground" key={i}>Discovery gap: {gap}</p>)}
 {discovery.data && discovery.data.candidates.length>0 && <div className="space-y-2 border-t pt-3"><p className="text-sm font-medium">Review discovered destinations</p><p className="text-xs text-muted-foreground">These candidates are outside the accepted plan. Credentials are not copied to new targets.</p>{discovery.data.candidates.map(candidate=><label className="flex items-center gap-2 text-xs" key={candidate.id}><input type="checkbox" checked={selected.includes(candidate.id)} onChange={e=>setSelected(values=>e.target.checked?[...values,candidate.id]:values.filter(id=>id!==candidate.id))}/><span>{candidate.value} · {candidate.kind} · {candidate.source}</span></label>)}<Button size="sm" disabled={running||selected.length===0||approval.isPending} onClick={()=>approval.mutate()}>Approve and preview revised plan</Button>{running&&<p className="text-xs text-muted-foreground">Accepted jobs can finish before a revised plan starts.</p>}</div>}
 {revision&&<div className="space-y-2 border-t pt-3"><p className="text-sm font-medium">Approved revision</p><p className="break-all text-xs text-muted-foreground">{revision.plan.fingerprint}</p>{revision.plan.jobs?.map(job=><p className="text-xs" key={job.id}>{job.scanner} · {job.target} · {job.state} · {job.reason}</p>)}<Button size="sm" disabled={start.isPending||!!started} onClick={()=>start.mutate()}>Start approved revision</Button></div>}
 {(approval.error||start.error)&&<p role="alert" className="text-xs text-destructive">{(approval.error||start.error)?.message}</p>}{started&&<p className="text-xs">Approved revision queued: {started}</p>}
 </CardContent></Card>;
}

export function EndpointTraceDialog({scanId,endpointId,onClose}:{scanId:string;endpointId:string|null;onClose:()=>void}) {
 const [page,setPage]=useState(1);
 const result=useQuery({queryKey:["endpoint-trace",scanId,endpointId,page],queryFn:()=>api.endpointTrace(scanId,endpointId!,page),enabled:!!endpointId});
 return <Dialog open={!!endpointId} onOpenChange={open=>{if(!open){setPage(1);onClose()}}}><DialogContent className="max-h-[85vh] overflow-auto"><DialogHeader><DialogTitle>Endpoint evidence trace</DialogTitle></DialogHeader>
 {result.error&&<p role="alert">{result.error.message}</p>}{result.data&&<div className="space-y-3 text-xs"><p className="break-all font-mono">{result.data.endpoint.method} {result.data.endpoint.url}</p><p>Evidence: {result.data.state}</p>{result.data.endpoint.coverage_history?.map((entry,i)=><p key={i}>{entry.scanner} · {entry.status} · attempt {entry.attempt_id??"NOT TRACKED"} · {entry.reason}</p>)}{result.data.items.map((event,i)=><div className="rounded border p-2" key={i}><p>{event.scanner} · {event.phase} · {event.kind} · {event.response_code??""}</p><p>{event.at} · attempt {event.attempt_id}</p><p>{event.reason}</p></div>)}<div className="flex gap-2"><Button size="sm" variant="outline" disabled={page===1} onClick={()=>setPage(page-1)}>Previous</Button><Button size="sm" variant="outline" disabled={page*25>=result.data.total} onClick={()=>setPage(page+1)}>Next</Button></div></div>}
 </DialogContent></Dialog>;
}
