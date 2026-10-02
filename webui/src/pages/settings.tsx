import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Search } from "lucide-react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { ErrorState } from "@/components/states";
import {
  useEnvironmentSettings,
  useRateLimit,
  useUpdateEnvironmentSettings,
  useUpdateRateLimit,
  useAuthStatus,
} from "@/api/queries";
import { useAuth } from "@/store/auth";
import type {
  EnvironmentSettings,
  EnvironmentVariableSetting,
} from "@/types/api";

const settingsTabs = [
  "engagement",
  "notifications",
  "environment",
  "account",
] as const;

type SettingsTab = (typeof settingsTabs)[number];

export default function SettingsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requestedTab = searchParams.get("tab") as SettingsTab | null;
  const activeTab = settingsTabs.includes(requestedTab as SettingsTab)
    ? (requestedTab as SettingsTab)
    : "engagement";

  const rate = useRateLimit();
  const updateRate = useUpdateRateLimit();
  const environment = useEnvironmentSettings();
  const updateEnvironment = useUpdateEnvironmentSettings();
  const auth = useAuthStatus();
  const logout = useAuth((s) => s.logout);
  const navigate = useNavigate();

  const [rateForm, setRateForm] = useState({ requests: 10, window: 1 });
  const [notificationForm, setNotificationForm] = useState({
    webhook: "",
    minSeverity: "",
    telegramBotToken: "",
    telegramChatId: "",
    telegramMinSeverity: "",
  });
  const [envValues, setEnvValues] = useState<Record<string, string>>({});
  const [envChanges, setEnvChanges] = useState<Record<string, string>>({});
  const [envFilter, setEnvFilter] = useState("");
  const [envRestartRequired, setEnvRestartRequired] = useState(false);
  const [savedRate, setSavedRate] = useState(false);
  const [savedNotifications, setSavedNotifications] = useState(false);
  const [savedEnvironment, setSavedEnvironment] = useState(false);

  useEffect(() => {
    if (rate.data) {
      setRateForm({
        requests: rate.data.requests ?? 10,
        window: rate.data.window ?? 1,
      });
    }
  }, [rate.data]);

  useEffect(() => {
    const webhook = envValue(environment.data, "XALGORIX_DISCORD_WEBHOOK");
    const minSeverity = envValue(environment.data, "XALGORIX_DISCORD_MIN_SEVERITY");
    const telegramBotToken = envValue(environment.data, "XALGORIX_TELEGRAM_BOT_TOKEN");
    const telegramChatId = envValue(environment.data, "XALGORIX_TELEGRAM_CHAT_ID");
    const telegramMinSeverity = envValue(environment.data, "XALGORIX_TELEGRAM_MIN_SEVERITY");
    setNotificationForm({ webhook, minSeverity, telegramBotToken, telegramChatId, telegramMinSeverity });
  }, [environment.data]);

  useEffect(() => {
    if (!environment.data) return;
    setEnvValues(
      Object.fromEntries(
        environment.data.variables.map((variable) => [
          variable.key,
          variable.value ?? "",
        ]),
      ),
    );
    setEnvChanges({});
  }, [environment.data]);

  function changeTab(value: string) {
    const next = new URLSearchParams(searchParams);
    next.set("tab", value);
    setSearchParams(next, { replace: true });
  }

  function updateEnvValue(variable: EnvironmentVariableSetting, value: string) {
    setEnvValues((current) => ({ ...current, [variable.key]: value }));
    setEnvChanges((current) => {
      const next = { ...current };
      if (value === (variable.value ?? "")) {
        delete next[variable.key];
      } else {
        next[variable.key] = value;
      }
      return next;
    });
  }

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-sans text-2xl font-semibold tracking-tight">
          Settings
        </h1>
        <p className="text-sm text-muted-foreground">
		  Engagement limits, notifications, environment variables, and account access.
        </p>
      </header>

      <Tabs value={activeTab} onValueChange={changeTab}>
        <TabsList className="flex h-auto flex-wrap">
          <TabsTrigger value="engagement">Engagement</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="environment">Environment</TabsTrigger>
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
                  Applied to outbound scanner requests and persisted to the env file.
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
                    {updateRate.isPending ? "Saving..." : "Save"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="notifications">
          {environment.isLoading ? (
            <Skeleton className="h-72" />
          ) : environment.error ? (
            <ErrorState
              title="Failed to load notification settings"
              description={environment.error instanceof Error ? environment.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => environment.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <>
            <Card>
              <CardHeader>
                <CardTitle>Discord notifications</CardTitle>
                <CardDescription>
                  Global defaults used unless a scan provides its own webhook.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-3 lg:grid-cols-[1fr_220px]">
                  <div className="space-y-2">
                    <Label htmlFor="discord-webhook">Discord webhook</Label>
                    <Input
                      id="discord-webhook"
                      value={notificationForm.webhook}
                      onChange={(e) =>
                        setNotificationForm({
                          ...notificationForm,
                          webhook: e.target.value,
                        })
                      }
                      placeholder="https://discord.com/api/webhooks/..."
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground">
                      Keep the masked value to preserve the saved webhook.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label>Minimum severity</Label>
                    <Select
                      value={notificationForm.minSeverity || "__unset__"}
                      onValueChange={(value) =>
                        setNotificationForm({
                          ...notificationForm,
                          minSeverity: value === "__unset__" ? "" : value,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__unset__">Default</SelectItem>
                        {["info", "low", "medium", "high", "critical"].map((value) => (
                          <SelectItem key={value} value={value}>
                            {value}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <Separator />
                <div className="flex items-center justify-end gap-3">
                  {savedNotifications && (
                    <span className="text-xs text-success">Saved</span>
                  )}
                  <Button
                    onClick={async () => {
                      setSavedNotifications(false);
                      await updateEnvironment.mutateAsync({
                        XALGORIX_DISCORD_WEBHOOK: notificationForm.webhook,
                        XALGORIX_DISCORD_MIN_SEVERITY: notificationForm.minSeverity,
                        XALGORIX_TELEGRAM_BOT_TOKEN: notificationForm.telegramBotToken,
                        XALGORIX_TELEGRAM_CHAT_ID: notificationForm.telegramChatId,
                        XALGORIX_TELEGRAM_MIN_SEVERITY: notificationForm.telegramMinSeverity,
                      });
                      setSavedNotifications(true);
                      setTimeout(() => setSavedNotifications(false), 2500);
                    }}
                    disabled={updateEnvironment.isPending}
                  >
                    {updateEnvironment.isPending ? "Saving..." : "Save notifications"}
                  </Button>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Telegram notifications</CardTitle>
                <CardDescription>
                  Send scan events and findings to a Telegram chat or channel.
                  Configure a bot via @BotFather and add it to the target chat as an admin.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-3 lg:grid-cols-[1fr_1fr_220px]">
                  <div className="space-y-2">
                    <Label htmlFor="telegram-bot-token">Bot token</Label>
                    <Input
                      id="telegram-bot-token"
                      value={notificationForm.telegramBotToken}
                      onChange={(e) =>
                        setNotificationForm({
                          ...notificationForm,
                          telegramBotToken: e.target.value,
                        })
                      }
                      placeholder="123456789:ABC-DEF..."
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground">
                      Keep the masked value to preserve the saved token.
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="telegram-chat-id">Chat ID</Label>
                    <Input
                      id="telegram-chat-id"
                      value={notificationForm.telegramChatId}
                      onChange={(e) =>
                        setNotificationForm({
                          ...notificationForm,
                          telegramChatId: e.target.value,
                        })
                      }
                      placeholder="-1001234567890 or @channelusername"
                      className="font-mono"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Minimum severity</Label>
                    <Select
                      value={notificationForm.telegramMinSeverity || "__unset__"}
                      onValueChange={(value) =>
                        setNotificationForm({
                          ...notificationForm,
                          telegramMinSeverity: value === "__unset__" ? "" : value,
                        })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__unset__">Default</SelectItem>
                        {["info", "low", "medium", "high", "critical"].map((value) => (
                          <SelectItem key={value} value={value}>
                            {value}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">
                  Telegram is independent of Discord — configure one or both.
                  The bot token is treated as a secret and never returned in API responses.
                </p>
              </CardContent>
            </Card>
            </>
          )}
        </TabsContent>

        <TabsContent value="environment">
          {environment.isLoading ? (
            <Skeleton className="h-96" />
          ) : environment.error ? (
            <ErrorState
              title="Failed to load environment settings"
              description={environment.error instanceof Error ? environment.error.message : "Unknown error"}
              action={
                <Button size="sm" variant="outline" onClick={() => environment.refetch()}>
                  Retry
                </Button>
              }
            />
          ) : (
            <div className="space-y-4">
              <Card>
                <CardContent className="space-y-4 p-4">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                    <div>
                      <p className="text-sm font-medium">Environment variables</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Editing {environment.data?.envFile || "~/.xalgorix.env"}. Masked secrets are preserved unless you replace or clear them.
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      {envRestartRequired && (
                        <Badge variant="warning">Restart required for some changes</Badge>
                      )}
                      {Object.keys(envChanges).length > 0 && (
                        <Badge variant="outline">
                          {Object.keys(envChanges).length} unsaved
                        </Badge>
                      )}
                      {savedEnvironment && (
                        <span className="text-xs text-success">Saved</span>
                      )}
                      <Button
                        onClick={async () => {
                          setSavedEnvironment(false);
                          const response = await updateEnvironment.mutateAsync(envChanges);
                          setEnvRestartRequired(Boolean(response.restartRequired));
                          setEnvChanges({});
                          setSavedEnvironment(true);
                          setTimeout(() => setSavedEnvironment(false), 2500);
                        }}
                        disabled={
                          updateEnvironment.isPending ||
                          Object.keys(envChanges).length === 0
                        }
                      >
                        {updateEnvironment.isPending ? "Saving..." : "Save changes"}
                      </Button>
                    </div>
                  </div>
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      value={envFilter}
                      onChange={(e) => setEnvFilter(e.target.value)}
                      placeholder="Search variables..."
                      className="pl-8"
                    />
                  </div>
                </CardContent>
              </Card>

              {Object.entries(filterEnvironment(environment.data, envFilter)).map(
                ([category, variables]) => (
                  <Card key={category} className="overflow-hidden">
                    <CardHeader className="pb-3">
                      <CardTitle className="text-base">{category}</CardTitle>
                    </CardHeader>
                    <CardContent className="p-0">
                      <div className="divide-y divide-border">
                        {variables.map((variable) => (
                          <EnvironmentRow
                            key={variable.key}
                            variable={variable}
                            value={envValues[variable.key] ?? variable.value ?? ""}
                            changed={Object.prototype.hasOwnProperty.call(
                              envChanges,
                              variable.key,
                            )}
                            onChange={(value) => updateEnvValue(variable, value)}
                          />
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ),
              )}
            </div>
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
    </div>
  );
}

function EnvironmentRow({
  variable,
  value,
  changed,
  onChange,
}: {
  variable: EnvironmentVariableSetting;
  value: string;
  changed: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-3 px-4 py-3 lg:grid-cols-[minmax(240px,360px)_1fr] lg:items-center">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="font-mono text-xs text-foreground">{variable.key}</p>
          {changed && <Badge variant="outline">edited</Badge>}
          {variable.requiresRestart && <Badge variant="warning">restart</Badge>}
          {!variable.hasValue && variable.defaultValue && (
            <Badge variant="muted">default {variable.defaultValue}</Badge>
          )}
        </div>
        <p className="text-sm font-medium">{variable.label}</p>
        <p className="text-xs text-muted-foreground">{variable.description}</p>
      </div>
      <EnvironmentControl variable={variable} value={value} onChange={onChange} />
    </div>
  );
}

function EnvironmentControl({
  variable,
  value,
  onChange,
}: {
  variable: EnvironmentVariableSetting;
  value: string;
  onChange: (value: string) => void;
}) {
  if (variable.inputType === "boolean") {
    return (
      <Select
        value={value === "" ? "__unset__" : value}
        onValueChange={(next) => onChange(next === "__unset__" ? "" : next)}
      >
        <SelectTrigger className="font-mono">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__unset__">Default / unset</SelectItem>
          <SelectItem value="true">true</SelectItem>
          <SelectItem value="false">false</SelectItem>
        </SelectContent>
      </Select>
    );
  }

  if (variable.inputType === "select") {
    return (
      <Select
        value={value === "" ? "__unset__" : value}
        onValueChange={(next) => onChange(next === "__unset__" ? "" : next)}
      >
        <SelectTrigger className="font-mono">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__unset__">Default / unset</SelectItem>
          {(variable.options ?? [])
            .filter((option) => option !== "")
            .map((option) => (
              <SelectItem key={option} value={option}>
                {option}
              </SelectItem>
            ))}
        </SelectContent>
      </Select>
    );
  }

  return (
    <Input
      type={variable.inputType === "number" ? "number" : "text"}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={variable.placeholder || variable.defaultValue || ""}
      className="font-mono"
    />
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

function envValue(data: EnvironmentSettings | undefined, key: string) {
  return data?.variables.find((variable) => variable.key === key)?.value ?? "";
}

function filterEnvironment(
  data: EnvironmentSettings | undefined,
  filter: string,
) {
  const needle = filter.trim().toLowerCase();
  const variables = data?.variables ?? [];
  const filtered = needle
    ? variables.filter((variable) =>
        [
          variable.key,
          variable.label,
          variable.category,
          variable.description,
        ]
          .join(" ")
          .toLowerCase()
          .includes(needle),
      )
    : variables;
  return groupBy(filtered, (variable) => variable.category);
}

function groupBy<T, K extends string>(items: T[], getKey: (item: T) => K) {
  return items.reduce<Record<string, T[]>>((acc, item) => {
    const key = getKey(item);
    (acc[key] ||= []).push(item);
    return acc;
  }, {});
}
