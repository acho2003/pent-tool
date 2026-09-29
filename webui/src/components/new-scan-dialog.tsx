import { useNavigate } from "react-router-dom";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

export default function NewScanDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
	const navigate = useNavigate();
	function openPlanner() {
		onOpenChange(false);
		navigate("/scans/new");
	}
	return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent><DialogHeader><DialogTitle>Start a new assessment</DialogTitle><DialogDescription>Review the assessment mode, target scope, scanner plan, and coverage gaps before starting. The planner checks the configuration without contacting the targets.</DialogDescription></DialogHeader><DialogFooter><Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button><Button type="button" onClick={openPlanner}>Open assessment planner</Button></DialogFooter></DialogContent></Dialog>;
}
