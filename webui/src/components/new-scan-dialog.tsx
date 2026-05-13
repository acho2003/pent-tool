import { useState, type FormEvent } from "react"
import { useNavigate } from "react-router-dom"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useCreateScan } from "@/api/queries"

export default function NewScanDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (v: boolean) => void
}) {
  const navigate = useNavigate()
  const [target, setTarget] = useState("")
  const [profile, setProfile] = useState("balanced")
  const [tags, setTags] = useState("")
  const [error, setError] = useState<string | null>(null)
  const mutation = useCreateScan()

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      const res = await mutation.mutateAsync({
        target: target.trim(),
        profile,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      })
      onOpenChange(false)
      setTarget("")
      setTags("")
      if (res?.id) navigate(`/scans/${res.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create scan")
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New scan</DialogTitle>
          <DialogDescription>
            Provide an authorized target and select an engagement profile.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target">Target</Label>
            <Input
              id="target"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com or 10.0.0.0/24"
              required
              autoFocus
            />
            <p className="text-xs text-muted-foreground">
              Only run engagements against assets you are explicitly authorized to test.
            </p>
          </div>
          <div className="space-y-2">
            <Label>Profile</Label>
            <Select value={profile} onValueChange={setProfile}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="passive">Passive recon</SelectItem>
                <SelectItem value="balanced">Balanced</SelectItem>
                <SelectItem value="aggressive">Aggressive</SelectItem>
                <SelectItem value="exploit">Full exploitation</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="tags">Tags</Label>
            <Input
              id="tags"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="prod, public-bounty"
            />
          </div>
          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending || !target.trim()}>
              {mutation.isPending ? "Creating…" : "Start scan"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
