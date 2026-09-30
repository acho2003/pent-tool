import { useMemo, useState, type ReactNode } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link, useSearchParams } from "react-router-dom"
import { Activity, AlertTriangle, ArrowLeft, ExternalLink, Plus, Search, Server } from "lucide-react"
import { api } from "@/api/client"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { EmptyState, ErrorState } from "@/components/states"
import type { MonitoringConnectionInput } from "@/types/api"

type Section = "overview" | "agents" | "alerts" | "vulnerabilities" | "responses" | "connection"
const docs = {
  Linux: "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html",
  Windows: "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html",
  macOS: "https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-macos.html",
}

function useMonitoringData() {
  const connection = useQuery({queryKey:["monitoring","connection"], queryFn:api.monitoringConnection})
  const configured = Boolean(connection.data?.manager_url)
  const health = useQuery({queryKey:["monitoring","health"], queryFn:api.monitoringHealth, enabled:configured, refetchInterval:30000, retry:false})
  return {connection, health, configured}
}

export default function MonitoringPage() {
  const [params, setParams] = useSearchParams()
  const section = (params.get("view") || "overview") as Section
  const agentId = params.get("agent") || ""
  const {connection, health, configured} = useMonitoringData()
  const setSection = (next:string) => { const p = new URLSearchParams(params); p.set("view",next); p.delete("agent"); setParams(p) }
  const selectAgent = (id:string) => { const p = new URLSearchParams(params); p.set("view","agents"); p.set("agent",id); setParams(p) }
  return <div className="space-y-6">
    <header className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
      <div><h1 className="text-2xl font-semibold tracking-tight">Continuous Monitoring</h1><p className="mt-1 text-sm text-muted-foreground">Wazuh agent health and security activity. Separate from one-time assessments.</p></div>
      {configured && <Button onClick={() => setSection("agents")}><Plus className="mr-2 h-4 w-4"/>Add server</Button>}
    </header>
    {connection.isLoading ? <p className="text-sm text-muted-foreground">Loading monitoring connection…</p> : connection.error ? <ErrorState title="Could not load monitoring configuration" description={String(connection.error)} /> : <>
      {!configured && section !== "connection" ? <EmptyState title="Connect Wazuh to start monitoring" description="Deploy the optional Wazuh stack on a Linux server, then add its API endpoints here." action={<Button onClick={() => setSection("connection")}>Configure Wazuh</Button>} /> : <>
        {configured && <div className="flex flex-wrap gap-2"><Badge variant={health.data?.manager ? "success" : "muted"}>Manager {health.data?.manager ? "connected" : "unavailable"}</Badge><Badge variant={health.data?.indexer ? "success" : "muted"}>Indexer {health.data?.indexer ? "connected" : "unavailable"}</Badge>{health.error && <span className="text-sm text-destructive">Connection check failed. Review configuration and certificates.</span>}</div>}
        <Tabs value={section} onValueChange={setSection}><TabsList className="flex h-auto flex-wrap justify-start"><TabsTrigger value="overview">Overview</TabsTrigger><TabsTrigger value="agents">Servers</TabsTrigger><TabsTrigger value="alerts">Alerts &amp; FIM</TabsTrigger><TabsTrigger value="vulnerabilities">CVE &amp; SCA</TabsTrigger><TabsTrigger value="responses">Responses</TabsTrigger><TabsTrigger value="connection">Connection</TabsTrigger></TabsList>
          <TabsContent value="overview"><Overview onAgent={selectAgent}/></TabsContent>
          <TabsContent value="agents">{agentId ? <AgentDetail id={agentId} onBack={() => selectAgent("")} commands={connection.data?.allowed_commands ?? []}/> : <Agents onAgent={selectAgent} host={connection.data?.agent_host || ""}/>}</TabsContent>
          <TabsContent value="alerts"><SearchResults kind="alerts"/></TabsContent>
          <TabsContent value="vulnerabilities"><div className="space-y-5"><SearchResults kind="vulnerabilities"/><p className="text-sm text-muted-foreground">Security configuration assessment policies are available on each server’s detail page.</p></div></TabsContent>
          <TabsContent value="responses"><Responses/></TabsContent>
          <TabsContent value="connection"><ConnectionForm connection={connection.data}/></TabsContent>
        </Tabs>
      </>}
    </>}
  </div>
}

function Overview({onAgent}:{onAgent:(id:string)=>void}) {
  const agents = useQuery({queryKey:["monitoring","agents",1],queryFn:()=>api.monitoringAgents(1,25),refetchInterval:30000,retry:false})
  const alerts = useQuery({queryKey:["monitoring","alerts",1,""],queryFn:()=>api.monitoringSearch("alerts",1,5),refetchInterval:30000,retry:false})
  const items = agents.data?.data?.affected_items ?? []
  return <div className="space-y-4"><div className="grid gap-3 sm:grid-cols-3"><Stat icon={<Server className="h-4 w-4"/>} label="Enrolled servers" value={agents.data?.data?.total_affected_items ?? "—"}/><Stat icon={<Activity className="h-4 w-4"/>} label="Active agents" value={items.filter(a=>a.status === "active").length}/><Stat icon={<AlertTriangle className="h-4 w-4"/>} label="Alerts in index" value={alerts.data?.hits?.total?.value ?? "—"}/></div>
    {(agents.error || alerts.error) && <ErrorState title="Some Wazuh data is unavailable" description="Check the manager and indexer connection. Other Xalgorix assessments are unaffected."/>}
    <Card><CardHeader><CardTitle>Servers needing attention</CardTitle></CardHeader><CardContent className="space-y-2">{items.filter(a=>a.status !== "active").length ? items.filter(a=>a.status !== "active").map(a=><button key={a.id} onClick={()=>onAgent(a.id)} className="block w-full rounded border border-border p-3 text-left hover:bg-accent"><span className="font-medium">{a.name}</span><span className="ml-2 text-sm text-muted-foreground">{a.status || "unknown"}</span></button>) : <p className="text-sm text-muted-foreground">No disconnected agents on this page.</p>}</CardContent></Card>
  </div>
}
function Stat({icon,label,value}:{icon:ReactNode;label:string;value:number|string}) { return <Card><CardContent className="flex items-center gap-3 p-4"><span className="text-primary">{icon}</span><div><p className="text-xs text-muted-foreground">{label}</p><p className="text-xl font-semibold">{value}</p></div></CardContent></Card> }

function Agents({onAgent,host}:{onAgent:(id:string)=>void;host:string}) {
  const [page,setPage] = useState(1)
  const [filter,setFilter] = useState("")
  const [search,setSearch] = useState("")
  const [showEnroll,setShowEnroll] = useState(false)
  const query = useQuery({queryKey:["monitoring","agents",page,search],queryFn:()=>api.monitoringAgents(page,25,search),refetchInterval:30000,retry:false})
  const agents = query.data?.data?.affected_items ?? []
  return <div className="space-y-4"><div className="flex flex-wrap gap-2"><form className="flex min-w-0 flex-1 gap-2" onSubmit={e=>{e.preventDefault();setPage(1);setSearch(filter)}}><div className="relative flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground"/><Input aria-label="Search servers" value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Search all servers" className="pl-9"/></div><Button type="submit" variant="outline">Search</Button></form><Button variant="outline" onClick={()=>setShowEnroll(v=>!v)}>{showEnroll ? "Hide guide" : "Add server guide"}</Button></div>
    {showEnroll && <Enrollment host={host}/>} {query.error ? <ErrorState title="Could not load agents" description={String(query.error)} action={<Button variant="outline" onClick={()=>query.refetch()}>Retry</Button>}/> : <Card><CardContent className="divide-y divide-border p-0">{agents.map(a=><button key={a.id} onClick={()=>onAgent(a.id)} className="flex w-full flex-wrap items-center justify-between gap-2 p-4 text-left hover:bg-accent"><span className="min-w-0"><strong>{a.name}</strong><span className="ml-2 text-xs text-muted-foreground">#{a.id} · {a.ip || "IP unknown"}</span></span><Badge variant={a.status === "active" ? "success" : "muted"}>{a.status || "unknown"}</Badge></button>)}{!agents.length && <p className="p-4 text-sm text-muted-foreground">No matching servers.</p>}</CardContent></Card>}
    <div className="flex items-center gap-3"><Button variant="outline" disabled={page===1} onClick={()=>setPage(page-1)}>Previous</Button><span className="text-sm">Page {page}</span><Button variant="outline" disabled={agents.length<25} onClick={()=>setPage(page+1)}>Next</Button></div>
  </div>
}

function Enrollment({host}:{host:string}) {
  const [os,setOS] = useState<keyof typeof docs>("Linux")
  const [expected,setExpected] = useState("")
  const qc = useQueryClient()
  const saved = useQuery({queryKey:["monitoring","enrollments"],queryFn:api.monitoringEnrollments})
  const allAgents = useQuery({queryKey:["monitoring","agents","enrollment-check"],queryFn:()=>api.monitoringAgents(1,100),refetchInterval:30000,retry:false})
  const add = useMutation({mutationFn:()=>api.addMonitoringEnrollment(expected.trim(),os),onSuccess:()=>{setExpected("");qc.invalidateQueries({queryKey:["monitoring","enrollments"]})}})
  return <Card><CardHeader><CardTitle>Guided agent enrollment</CardTitle></CardHeader><CardContent className="space-y-3 text-sm"><p>Install the official Wazuh agent on the server and point it at <code className="break-all text-primary">{host || "the configured manager host"}</code>. Xalgorix does not access your server over SSH.</p><div className="flex flex-wrap gap-2">{(Object.keys(docs) as Array<keyof typeof docs>).map(name=><Button key={name} size="sm" variant={os===name?"default":"outline"} onClick={()=>setOS(name)}>{name}</Button>)}</div><Link className="inline-flex items-center gap-1 text-primary underline" to={docs[os]} target="_blank" rel="noreferrer">Open official {os} installation steps <ExternalLink className="h-3 w-3"/></Link><p>During setup, use the manager address above. Allow agent traffic to the Wazuh manager’s configured enrollment and communication ports.</p><Label htmlFor="expected-agent">Expected agent name</Label><div className="flex gap-2"><Input id="expected-agent" value={expected} onChange={e=>setExpected(e.target.value)} placeholder="server-01"/><Button disabled={!expected.trim()||add.isPending} onClick={()=>add.mutate()}>Add</Button></div>{add.error && <p className="text-destructive">{String(add.error)}</p>}<div className="space-y-2">{saved.data?.map(item=>{const matched=allAgents.data?.data?.affected_items?.find(a=>a.name.toLowerCase()===item.name.toLowerCase());return <div key={item.name} className="flex items-center justify-between rounded border border-border p-2"><span>{item.name} · {item.os}</span><Badge variant={matched?.status==="active"?"success":"muted"}>{allAgents.error ? "Unable to verify" : matched?.status==="active"?"Verified online":matched?matched.status||"Enrolled":"Pending"}</Badge></div>})}{saved.error && <p className="text-destructive">Could not load enrollment requests.</p>}</div></CardContent></Card>
}

function AgentDetail({id,onBack,commands}:{id:string;onBack:()=>void;commands:string[]}) {
  const agent = useQuery({queryKey:["monitoring","agent",id],queryFn:()=>api.monitoringAgent(id),refetchInterval:30000,retry:false})
  const fim = useQuery({queryKey:["monitoring","fim",id],queryFn:()=>api.monitoringFIM(id),retry:false})
  const sca = useQuery({queryKey:["monitoring","sca",id],queryFn:()=>api.monitoringSCA(id),retry:false})
  const item = agent.data?.data?.affected_items?.[0]
  return <div className="space-y-4"><Button variant="ghost" onClick={onBack}><ArrowLeft className="mr-2 h-4 w-4"/>Servers</Button>{agent.error ? <ErrorState title="Could not load server" description={String(agent.error)}/> : <Card><CardHeader><CardTitle>{item?.name || `Agent ${id}`}</CardTitle></CardHeader><CardContent className="grid gap-2 text-sm sm:grid-cols-2"><p>Status: {item?.status || "Loading…"}</p><p>IP: {item?.ip || "—"}</p><p>OS: {item?.os?.name || "—"} {item?.os?.version || ""}</p><p>Last seen: {item?.lastKeepAlive || "—"}</p></CardContent></Card>}
    <div className="grid gap-4 lg:grid-cols-2"><DataCard title="File integrity" items={fim.data?.data?.affected_items} error={fim.error}/><DataCard title="Security configuration assessments" items={sca.data?.data?.affected_items} error={sca.error}/></div>
    <SearchResults kind="alerts" agentId={id}/><SearchResults kind="vulnerabilities" agentId={id}/><ResponseControls id={id} commands={commands}/>
  </div>
}
function DataCard({title,items,error}:{title:string;items?:Record<string,unknown>[];error:unknown}) {
  return <Card><CardHeader><CardTitle>{title}</CardTitle></CardHeader><CardContent>{error ? <p className="text-sm text-destructive">Unavailable: {String(error)}</p> : !items?.length ? <p className="text-sm text-muted-foreground">No data returned by Wazuh.</p> : <div className="max-h-64 space-y-2 overflow-y-auto">{items.slice(0,25).map((item,i)=><details key={i} className="rounded border border-border p-3"><summary className="cursor-pointer break-all text-sm font-medium">{String(item.name || item.file || item.path || item.id || `Record ${i+1}`)}<span className="ml-2 text-xs font-normal text-muted-foreground">{String(item.status || item.type || "")}</span></summary>{Boolean(item.description) && <p className="mt-2 text-xs text-muted-foreground">{String(item.description)}</p>}<pre className="mt-2 overflow-auto text-xs">{JSON.stringify(item,null,2)}</pre></details>)}</div>}</CardContent></Card>
}

function SearchResults({kind,agentId=""}:{kind:"alerts"|"vulnerabilities";agentId?:string}) {
  const [page,setPage] = useState(1)
  const [q,setQ] = useState("")
  const [search,setSearch] = useState("")
  const result = useQuery({queryKey:["monitoring",kind,agentId,page,search],queryFn:()=>api.monitoringSearch(kind,page,25,search,agentId),refetchInterval:30000,retry:false})
  const hits = result.data?.hits?.hits ?? []
  return <Card><CardHeader><CardTitle>{kind==="alerts"?"Security alerts and FIM events":"Detected vulnerabilities"}</CardTitle></CardHeader><CardContent className="space-y-3"><form onSubmit={e=>{e.preventDefault();setPage(1);setSearch(q)}} className="flex gap-2"><Input aria-label={`Search ${kind}`} value={q} onChange={e=>setQ(e.target.value)} placeholder={`Search ${kind}`}/><Button type="submit">Search</Button></form>{result.error ? <p className="text-sm text-destructive">Wazuh data unavailable: {String(result.error)}</p> : !hits.length ? <p className="text-sm text-muted-foreground">No results.</p> : <div className="divide-y divide-border">{hits.map(hit=><EventRow key={hit._id} source={hit._source} kind={kind}/>)}</div>}<div className="flex items-center gap-3"><Button variant="outline" disabled={page===1} onClick={()=>setPage(page-1)}>Previous</Button><span className="text-sm">Page {page}</span><Button variant="outline" disabled={hits.length<25} onClick={()=>setPage(page+1)}>Next</Button></div></CardContent></Card>
}
function EventRow({source,kind}:{source:Record<string,unknown>;kind:string}) {
  const rule = source.rule as Record<string,unknown>|undefined
  const vulnerability = source.vulnerability as Record<string,unknown>|undefined
  const agent = source.agent as Record<string,unknown>|undefined
  const title = kind==="alerts" ? String(rule?.description || "Wazuh alert") : String(vulnerability?.id || vulnerability?.title || "Vulnerability")
  return <details className="py-3"><summary className="cursor-pointer break-words text-sm font-medium">{title}<span className="ml-2 text-xs text-muted-foreground">{String(agent?.name || "")} · {String(source["@timestamp"] || "")}</span></summary><pre className="mt-2 max-h-72 overflow-auto rounded bg-background p-3 text-xs">{JSON.stringify(source,null,2)}</pre></details>
}

function ResponseControls({id,commands}:{id:string;commands:string[]}) {
  const [command,setCommand] = useState("")
  const [confirm,setConfirm] = useState("")
  const qc = useQueryClient()
  const run = useMutation({mutationFn:()=>api.monitoringResponse(id,command),onSuccess:()=>{qc.invalidateQueries({queryKey:["monitoring","audit"]});setConfirm("")}})
  return <Card><CardHeader><CardTitle>Manual active response</CardTitle></CardHeader><CardContent className="space-y-3 text-sm"><p className="text-muted-foreground">A response may interrupt traffic or service on this server. Only configured Wazuh commands are available.</p>{!commands.length ? <p>No commands are allowlisted. Configure them in Connection before using active response.</p> : <><Label htmlFor="response-command">Approved command</Label><select id="response-command" value={command} onChange={e=>setCommand(e.target.value)} className="w-full rounded border border-border bg-background p-2"><option value="">Choose command</option>{commands.map(c=><option key={c} value={c}>{c}</option>)}</select><Label htmlFor="confirm-agent">Type agent ID {id} to confirm</Label><Input id="confirm-agent" value={confirm} onChange={e=>setConfirm(e.target.value)}/><Button variant="destructive" disabled={!command || confirm!==id || run.isPending} onClick={()=>run.mutate()}>Run response on agent {id}</Button>{run.error && <p className="text-destructive">{String(run.error)}</p>}{run.isSuccess && <p>Submitted to Wazuh. Check response history and agent logs for execution.</p>}</>}</CardContent></Card>
}
function Responses() { const result = useQuery({queryKey:["monitoring","audit"],queryFn:api.monitoringAudit}); return <Card><CardHeader><CardTitle>Manual response history</CardTitle></CardHeader><CardContent className="space-y-2">{result.error ? <p className="text-destructive">{String(result.error)}</p> : !result.data?.length ? <p className="text-sm text-muted-foreground">No manual responses submitted from Xalgorix.</p> : result.data.map((a,i)=><div key={i} className="rounded border border-border p-3 text-sm"><strong>{a.command}</strong> on agent {a.agent_id} · {a.status}<p className="text-xs text-muted-foreground">{a.time} · {a.actor}</p>{a.result && <p className="mt-1 break-all text-xs">{a.result}</p>}</div>)}</CardContent></Card> }

function ConnectionForm({connection}:{connection?:import("@/types/api").MonitoringConnection}) {
  const qc = useQueryClient()
  const initial = useMemo<MonitoringConnectionInput>(()=>({manager_url:connection?.manager_url||"",indexer_url:connection?.indexer_url||"",manager_user:connection?.manager_user||"",manager_password:"",indexer_user:connection?.indexer_user||"",indexer_password:"",ca_pem:"",agent_host:connection?.agent_host||"",allowed_commands:connection?.allowed_commands||[]}),[connection])
  const [values,setValues] = useState<MonitoringConnectionInput>(initial)
  const [commands,setCommands] = useState(initial.allowed_commands.join("\n"))
  const save = useMutation({mutationFn:()=>api.saveMonitoringConnection({...values,allowed_commands:commands.split(/\r?\n/).map(x=>x.trim()).filter(Boolean)}),onSuccess:()=>qc.invalidateQueries({queryKey:["monitoring"]})})
  const field = (name:keyof MonitoringConnectionInput,label:string,type="text") => <div className="space-y-1"><Label htmlFor={name}>{label}</Label><Input id={name} type={type} value={String(values[name])} onChange={e=>setValues({...values,[name]:e.target.value})}/></div>
  return <Card><CardHeader><CardTitle>Wazuh connection</CardTitle></CardHeader><CardContent className="space-y-4"><p className="text-sm text-muted-foreground">Use HTTPS endpoints reachable from the Xalgorix server. Passwords and the CA certificate stay on the server and are never returned to the browser.</p><div className="grid gap-4 md:grid-cols-2">{field("manager_url","Manager API URL")}{field("indexer_url","Indexer API URL")}{field("manager_user","Manager API user")}{field("indexer_user","Indexer API user")}{field("manager_password",connection?.has_manager_password?"Manager password (leave blank to keep)":"Manager password","password")}{field("indexer_password",connection?.has_indexer_password?"Indexer password (leave blank to keep)":"Indexer password","password")}{field("agent_host","Public manager hostname/IP for agents")}</div><div className="space-y-1"><Label htmlFor="ca-pem">Trusted CA certificate PEM {connection?.has_ca && "(leave blank to keep)"}</Label><Textarea id="ca-pem" value={values.ca_pem} onChange={e=>setValues({...values,ca_pem:e.target.value})} rows={4}/></div><div className="space-y-1"><Label htmlFor="commands">Approved active-response command names, one per line</Label><Textarea id="commands" value={commands} onChange={e=>setCommands(e.target.value)} rows={3}/><p className="text-xs text-muted-foreground">Empty by default. Commands must already be configured in Wazuh; this list only permits them in Xalgorix.</p></div><Button onClick={()=>save.mutate()} disabled={save.isPending}>Save connection</Button>{save.error && <p className="text-sm text-destructive">{String(save.error)}</p>}{save.isSuccess && <p className="text-sm text-primary">Saved. Use the status badges above to verify connectivity.</p>}</CardContent></Card>
}
