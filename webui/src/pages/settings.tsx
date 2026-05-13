import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"
import { Skeleton } from "@/components/ui/skeleton"
import { ErrorState } from "@/components/states"
import { useSettings, useUpdateSettings } from "@/api/queries"
import { useAuth } from "@/store/auth"
import { useNavigate } from "react-router-dom"

export default function SettingsPage() {
  const { data, isLoading, error, refetch } = useSettings()
  const update = useUpdateSettings()
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const [form, setForm] = useState({
    concurrency: 4,
    rate_limit_rps: 10,
    notify_email: "",
    auto_triage: true,
    aggressive_mode: false,
    retain_days: 30,
  })

  useEffect(() => {
    if (data) setForm({ ...form, ...data })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data])

  if (error) return <ErrorState message={String(error)} onRetry={() => refetch()} />

  return (
    <>
      <header>
        <h1 className="font-sans text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">Engagement defaults, notifications, and account.</p>
      </header>

      <Tabs defaultValue="engagement">
        <TabsList>
          <TabsTrigger value="engagement">Engagement</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
        </TabsList>

        <TabsContent value="engagement">
          {isLoading ? (
            <Skeleton className="h-80" />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Defaults</CardTitle>
                <CardDescription>Applied to new scans unless overridden.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-2 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="concurrency">Worker concurrency</Label>
                    <Input
                      id="concurrency"
                      type="number"
                      min={1}
                      max={64}
                      value={form.concurrency}
                      onChange={(e) => setForm({ ...form, concurrency: Number(e.target.value) })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="rate">Rate limit (req/s)</Label>
                    <Input
                      id="rate"
                      type="number"
                      min={1}
                      max={1000}
                      value={form.rate_limit_rps}
                      onChange={(e) => setForm({ ...form, rate_limit_rps: Number(e.target.value) })}
                    />
                  </div>
                </div>
                <Separator />
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <Label htmlFor="agg" className="text-sm">
                      Aggressive mode
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      Allow exploit modules that may cause service disruption.
                    </p>
                  </div>
                  <Switch
                    id="agg"
                    checked={form.aggressive_mode}
                    onChange={(e) => setForm({ ...form, aggressive_mode: e.target.checked })}
                  />
                </div>
                <Separator />
                <div className="space-y-2">
                  <Label htmlFor="retain">Retention (days)</Label>
                  <Input
                    id="retain"
                    type="number"
                    min={1}
                    max={365}
                    value={form.retain_days}
                    onChange={(e) => setForm({ ...form, retain_days: Number(e.target.value) })}
                  />
                </div>
                <div className="flex justify-end">
                  <Button onClick={() => update.mutate(form)} disabled={update.isPending}>
                    {update.isPending ? "Saving…" : "Save changes"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="notifications">
          <Card>
            <CardHeader>
              <CardTitle>Notifications</CardTitle>
              <CardDescription>Alerts for new critical findings and email triage.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <div className="space-y-2">
                <Label htmlFor="email">Notify email</Label>
                <Input
                  id="email"
                  type="email"
                  value={form.notify_email}
                  onChange={(e) => setForm({ ...form, notify_email: e.target.value })}
                  placeholder="ops@xalgorix.local"
                />
              </div>
              <Separator />
              <div className="flex items-start justify-between gap-4">
                <div>
                  <Label htmlFor="autotri" className="text-sm">
                    Auto-triage incoming email
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Run AI verdict on every AgentMail message as it arrives.
                  </p>
                </div>
                <Switch
                  id="autotri"
                  checked={form.auto_triage}
                  onChange={(e) => setForm({ ...form, auto_triage: e.target.checked })}
                />
              </div>
              <div className="flex justify-end">
                <Button onClick={() => update.mutate(form)} disabled={update.isPending}>
                  Save
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="account">
          <Card>
            <CardHeader>
              <CardTitle>Account</CardTitle>
              <CardDescription>Session and access.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2 text-sm sm:grid-cols-2">
                <Field label="Username" value={user?.username ?? "—"} />
                <Field label="Role" value={user?.role ?? "operator"} />
              </div>
              <Separator />
              <div className="flex justify-end">
                <Button
                  variant="destructive"
                  onClick={async () => {
                    await logout()
                    navigate("/login", { replace: true })
                  }}
                >
                  Sign out
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-3">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-1 font-mono text-sm text-foreground">{value}</div>
    </div>
  )
}
