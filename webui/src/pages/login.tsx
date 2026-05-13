import { useState, type FormEvent } from "react"
import { useNavigate, useLocation } from "react-router-dom"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { useAuth } from "@/store/auth"
import { AlertCircle } from "lucide-react"

export default function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const login = useAuth((s) => s.login)
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const from = (location.state as { from?: string } | null)?.from ?? "/"

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid min-h-screen w-full bg-background lg:grid-cols-2">
      <div className="hidden flex-col justify-between border-r border-border bg-muted/30 p-12 lg:flex">
        <div className="flex items-center gap-3">
          <img src="/logo.png" alt="Xalgorix" className="h-8 w-8 rounded-md" />
          <span className="font-mono text-sm font-semibold tracking-tight">XALGORIX</span>
        </div>
        <div className="space-y-6">
          <div className="space-y-2">
            <h1 className="font-sans text-4xl font-semibold tracking-tight text-foreground text-balance">
              The autonomous offensive AI platform.
            </h1>
            <p className="max-w-md text-sm leading-relaxed text-muted-foreground">
              Continuous reconnaissance, multi-phase exploitation, and AI-driven triage — orchestrated from a single
              console.
            </p>
          </div>
          <dl className="grid grid-cols-2 gap-6 border-t border-border pt-6">
            <Stat label="Active scans" value="12" />
            <Stat label="Findings (7d)" value="2,431" />
            <Stat label="Mean time to detect" value="42s" />
            <Stat label="Coverage" value="98.4%" />
          </dl>
        </div>
        <p className="text-xs text-muted-foreground">© Xalgorix · Internal use only</p>
      </div>

      <div className="flex items-center justify-center p-6 sm:p-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <img src="/logo.png" alt="Xalgorix" className="h-8 w-8 rounded-md" />
            <span className="font-mono text-sm font-semibold tracking-tight">XALGORIX</span>
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Sign in</CardTitle>
              <CardDescription>Operator console access</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={onSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    autoComplete="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                    autoFocus
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>
                {error && (
                  <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                    <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{error}</span>
                  </div>
                )}
                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? "Signing in…" : "Sign in"}
                </Button>
              </form>
            </CardContent>
          </Card>
          <p className="mt-6 text-center text-xs text-muted-foreground">
            Protected by CSRF · Session cookies are HTTP-only
          </p>
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className="mt-1 font-mono text-2xl font-semibold tracking-tight">{value}</dd>
    </div>
  )
}
