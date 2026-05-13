import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/states";
import {
  useAgentMail,
  useRateLimit,
  useUpdateAgentMail,
  useUpdateRateLimit,
  useAuthStatus,
} from "@/api/queries";
import { useAuth } from "@/store/auth";

export default function SettingsPage() {
  const rate = useRateLimit();
  const updateRate = useUpdateRateLimit();
  const mail = useAgentMail();
  const updateMail = useUpdateAgentMail();
  const auth = useAuthStatus();
  const logout = useAuth((s) => s.logout);
  const navigate = useNavigate();

  const [rateForm, setRateForm] = useState({ requests: 10, window: 1 });
  const [mailForm, setMailForm] = useState({ pod: "", apiKey: "" });
  const [savedRate, setSavedRate] = useState(false);
  const [savedMail, setSavedMail] = useState(false);

  useEffect(() => {
    if (rate.data) {
      setRateForm({
        requests: rate.data.requests ?? 10,
        window: rate.data.window ?? 1,
      });
    }
  }, [rate.data]);

  useEffect(() => {
    if (mail.data) {
      setMailForm({
        pod: mail.data.pod ?? "",
        apiKey: mail.data.apiKey ?? "",
      });
    }
  }, [mail.data]);

  return (
    <>
      <header className="space-y-1">
        <h1 className="font-sans text-2xl font-semibold tracking-tight">
          Settings
        </h1>
        <p className="text-sm text-muted-foreground">
          Engagement defaults, AgentMail credentials, and account.
        </p>
      </header>

      <Tabs defaultValue="engagement">
        <TabsList>
          <TabsTrigger value="engagement">Engagement</TabsTrigger>
          <TabsTrigger value="email">AgentMail</TabsTrigger>
          <TabsTrigger value="account">Account</TabsTrigger>
        </TabsList>

        <TabsContent value="engagement">
          {rate.isLoading ? (
            <Skeleton className="h-72" />
          ) : rate.error ? (
            <ErrorState
              title="Failed to load rate limits"
              description={rate.error instanceof Error ? rate.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => rate.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Rate limits</CardTitle>
                <CardDescription>
                  Applied to outbound requests issued by the agent.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label htmlFor="requests">Requests per window</Label>
                    <Input
                      id="requests"
                      type="number"
                      min={1}
                      max={1000}
                      value={rateForm.requests}
                      onChange={(e) =>
                        setRateForm({
                          ...rateForm,
                          requests: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="window">Window (seconds)</Label>
                    <Input
                      id="window"
                      type="number"
                      min={1}
                      max={600}
                      value={rateForm.window}
                      onChange={(e) =>
                        setRateForm({
                          ...rateForm,
                          window: Number(e.target.value),
                        })
                      }
                    />
                  </div>
                </div>
                <div className="flex items-center justify-end gap-3">
                  {savedRate && (
                    <span className="text-xs text-success">Saved</span>
                  )}
                  <Button
                    onClick={async () => {
                      setSavedRate(false);
                      await updateRate.mutateAsync(rateForm);
                      setSavedRate(true);
                      setTimeout(() => setSavedRate(false), 2500);
                    }}
                    disabled={updateRate.isPending}
                  >
                    {updateRate.isPending ? "Saving…" : "Save"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="email">
          {mail.isLoading ? (
            <Skeleton className="h-72" />
          ) : mail.error ? (
            <ErrorState
              title="Failed to load AgentMail settings"
              description={mail.error instanceof Error ? mail.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => mail.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>AgentMail</CardTitle>
                <CardDescription>
                  Inbound triage requires a configured pod and API key.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="space-y-2">
                  <Label htmlFor="pod">Pod</Label>
                  <Input
                    id="pod"
                    value={mailForm.pod}
                    onChange={(e) =>
                      setMailForm({ ...mailForm, pod: e.target.value })
                    }
                    placeholder="xalgorix-prod"
                    className="font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="apikey">API key</Label>
                  <Input
                    id="apikey"
                    value={mailForm.apiKey}
                    onChange={(e) =>
                      setMailForm({ ...mailForm, apiKey: e.target.value })
                    }
                    placeholder={mail.data?.hasApiKey ? "•••• (saved)" : "ak_…"}
                    className="font-mono"
                  />
                  <p className="text-xs text-muted-foreground">
                    Leave masked value untouched to keep the existing key.
                  </p>
                </div>
                <Separator />
                <div className="flex items-center justify-end gap-3">
                  {savedMail && (
                    <span className="text-xs text-success">Saved</span>
                  )}
                  <Button
                    onClick={async () => {
                      setSavedMail(false);
                      await updateMail.mutateAsync(mailForm);
                      setSavedMail(true);
                      setTimeout(() => setSavedMail(false), 2500);
                    }}
                    disabled={updateMail.isPending}
                  >
                    {updateMail.isPending ? "Saving…" : "Save"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="account">
          <Card>
            <CardHeader>
              <CardTitle>Account</CardTitle>
              <CardDescription>Session and access.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2 text-sm sm:grid-cols-2">
                <Field
                  label="Auth"
                  value={
                    auth.data?.auth_enabled
                      ? auth.data.authenticated
                        ? "Authenticated"
                        : "Logged out"
                      : "Disabled"
                  }
                />
                <Field
                  label="Session"
                  value={auth.data?.authenticated ? "Active" : "None"}
                />
              </div>
              {auth.data?.auth_enabled && (
                <>
                  <Separator />
                  <div className="flex justify-end">
                    <Button
                      variant="destructive"
                      onClick={async () => {
                        await logout();
                        navigate("/login", { replace: true });
                      }}
                    >
                      Sign out
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-3">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 font-mono text-sm text-foreground">{value}</div>
    </div>
  );
}
