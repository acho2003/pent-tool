import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useStartScan } from "@/api/queries";

export default function NewScanDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
	const navigate = useNavigate();
	const mutation = useStartScan();
	const [targets, setTargets] = useState("");
	const [mode, setMode] = useState("single");
	const [name, setName] = useState("");
	const [error, setError] = useState<string | null>(null);
	async function submit(e: FormEvent) {
		e.preventDefault(); setError(null);
		const list = targets.split(/[\n,]/).map((v) => v.trim()).filter(Boolean);
		if (!list.length) { setError("Provide at least one target."); return; }
		try {
			const res = await mutation.mutateAsync({ targets: list, scan_mode: mode, name: name.trim() || undefined });
			onOpenChange(false); setTargets(""); setName("");
			navigate(res.instance_id ? `/scans/${res.instance_id}` : "/scans");
		} catch (e) { setError(e instanceof Error ? e.message : "Failed to start scan"); }
	}
	return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent><DialogHeader><DialogTitle>New deterministic scan</DialogTitle><DialogDescription>Runs Nuclei, ZAP, OpenVAS, Trivy, and Vuls in fixed order.</DialogDescription></DialogHeader><form onSubmit={submit} className="space-y-4"><div className="space-y-2"><Label htmlFor="quick-name">Name</Label><Input id="quick-name" value={name} onChange={(e) => setName(e.target.value)} /></div><div className="space-y-2"><Label htmlFor="quick-targets">Targets</Label><textarea id="quick-targets" value={targets} onChange={(e) => setTargets(e.target.value)} rows={4} className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono" placeholder="https://example.com" /></div><div className="space-y-2"><Label>Mode</Label><Select value={mode} onValueChange={setMode}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="single">Single</SelectItem><SelectItem value="wildcard">Wildcard</SelectItem></SelectContent></Select></div>{error && <p className="text-sm text-destructive">{error}</p>}<DialogFooter><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button><Button type="submit" disabled={mutation.isPending}>{mutation.isPending ? "Starting…" : "Start scan"}</Button></DialogFooter></form></DialogContent></Dialog>;
}
