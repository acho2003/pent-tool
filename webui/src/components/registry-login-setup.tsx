import { useState } from "react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { ServiceImageTarget } from "@/components/services-setup";

export type SavedRegistryLogin = { credentialId: string; registry: string; bound: Array<{ id: string; value: string }> };

// imageRegistryHost mirrors the backend rule: the first path component is a
// registry when it contains "." or ":" or is "localhost"; otherwise Docker Hub.
export function imageRegistryHost(ref: string): string {
  const slash = ref.indexOf("/");
  if (slash > 0) {
    const first = ref.slice(0, slash);
    if (first.includes(".") || first.includes(":") || first === "localhost") return first.toLowerCase();
  }
  return "docker.io";
}

function normalizeRegistry(host: string): string {
  const h = host.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  return ["index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"].includes(h) ? "docker.io" : h;
}

export function registryLoginBindings(saved: SavedRegistryLogin | null, images: ServiceImageTarget[]) {
  if (!saved) return [];
  const ids = saved.bound.map((b) => b.id).filter((id) => images.some((image) => image.id === id));
  return ids.length ? [{ target_ids: ids, kind: "REGISTRY_CREDENTIALS", credential_id: saved.credentialId }] : [];
}

export function registryLoginStale(saved: SavedRegistryLogin | null, images: ServiceImageTarget[]): boolean {
  return !!saved && saved.bound.some(({ id, value }) => images.find((image) => image.id === id)?.value !== value);
}

export function RegistryLoginSetup({ images, value, onChange }: { images: ServiceImageTarget[]; value: SavedRegistryLogin | null; onChange: (value: SavedRegistryLogin | null) => void }) {
  const [registry, setRegistry] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (!images.length) return null;
  const host = normalizeRegistry(registry || imageRegistryHost(images[0].value));
  const matching = images.filter((image) => imageRegistryHost(image.value) === host);

  async function save() {
    setError(null);
    if (!username || !password) { setError("Enter the registry username and password or token."); return; }
    if (!matching.length) { setError(`No service image is hosted on ${host}.`); return; }
    setSaving(true);
    try {
      const meta = await api.createCredential({ name: `Registry ${host}`, kind: "REGISTRY_CREDENTIALS", target_ids: matching.map((image) => image.id), values: { registry: host, username, password } });
      setPassword("");
      onChange({ credentialId: meta.id, registry: host, bound: matching.map((image) => ({ id: image.id, value: image.value })) });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the registry credential");
    } finally {
      setSaving(false);
    }
  }

  return <Card>
    <CardHeader>
      <CardTitle>Container registry login</CardTitle>
      <p className="text-sm text-muted-foreground">For private images, save a read-only registry login. Trivy receives it only through its environment, and only for images hosted on that registry. Images referenced by a tag are allowed; the report records the exact digest that was scanned.</p>
    </CardHeader>
    <CardContent className="space-y-3">
      {value ? <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3"><p className="text-sm text-emerald-300">Registry login for {value.registry} saved (encrypted) for {value.bound.length} image{value.bound.length === 1 ? "" : "s"}.</p><Button type="button" size="sm" variant="outline" onClick={() => onChange(null)}>Remove</Button></div> : <>
        <div className="space-y-2"><Label htmlFor="registry-host">Registry</Label><Input id="registry-host" value={registry} onChange={(e) => setRegistry(e.target.value)} placeholder={imageRegistryHost(images[0].value)} /></div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-2"><Label htmlFor="registry-user">Username</Label><Input id="registry-user" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" /></div>
          <div className="space-y-2"><Label htmlFor="registry-password">Password or token</Label><Input id="registry-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} /></div>
        </div>
        <p className="text-xs text-muted-foreground">Applies to {matching.length} of {images.length} image{images.length === 1 ? "" : "s"} on {host}.</p>
        <Button type="button" variant="outline" onClick={() => void save()} disabled={saving}>{saving ? "Encrypting…" : "Save registry login"}</Button>
      </>}
      {error && <p role="alert" className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{error}</p>}
    </CardContent>
  </Card>;
}
