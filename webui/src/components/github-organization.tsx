import { useEffect, useRef, useState } from "react";
import { api, type GitHubRepository } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function GitHubOrganization({ onChange, note }: { onChange: (repos: GitHubRepository[], credentialId: string) => void; note?: string }) {
  const [organization, setOrganization] = useState("");
  const [token, setToken] = useState("");
  const [credentialId, setCredentialId] = useState("");
  const [repos, setRepos] = useState<GitHubRepository[]>([]);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [search, setSearch] = useState("");
  const [visibility, setVisibility] = useState("all");
  const [archived, setArchived] = useState(true);
  const [forks, setForks] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  useEffect(() => () => { generation.current++; }, []);
  const included = (repo: GitHubRepository, v = visibility, a = archived, f = forks) =>
    (v === "all" || (v === "private") === repo.private) && (a || !repo.archived) && (f || !repo.fork);
  const filtered = repos.filter(repo => included(repo));
  const visible = filtered.filter(repo => repo.full_name.toLowerCase().includes(search.toLowerCase()));
  function publish(ids: Set<number>, v = visibility, a = archived, f = forks) {
    setSelected(ids);
    onChange(repos.filter(repo => ids.has(repo.id) && included(repo, v, a, f)), credentialId);
  }
  function reset() {
    generation.current++; setRepos([]); setSelected(new Set()); setError(""); onChange([], "");
  }
  async function discover() {
    const current = ++generation.current;
    setBusy(true); setError(""); setRepos([]); onChange([], "");
    try {
      let id = credentialId;
      const org = organization.trim().replace(/^https:\/\/github\.com\//, "").replace(/\/$/, "").toLowerCase();
      if (!/^[a-z0-9][a-z0-9-]{0,38}$/.test(org)) throw new Error("Enter a GitHub.com organization name or HTTPS organization URL.");
      if (token.trim()) {
        const credential = await api.createCredential({ name: `GitHub organization ${org}`, kind: "REPOSITORY_CREDENTIALS", target_ids: [`github-org:${org}`], values: { token: token.trim() } });
        id = credential.id;
        if (current !== generation.current) return;
        setCredentialId(id); setToken("");
      }
      const result = await api.discoverGitHubOrganization(organization, id || undefined);
      if (current !== generation.current) return;
      setRepos(result.repositories);
      const ids = new Set(result.repositories.map(repo => repo.id));
      setSelected(ids);
      onChange(result.repositories.filter(repo => included(repo)), id);
      if (!result.repositories.length) setError("No repositories are accessible with these credentials.");
    } catch (err) {
      if (current === generation.current) setError(err instanceof Error ? err.message : "Discovery failed. Retry discovery.");
    } finally { setBusy(false); }
  }
  return <div className="space-y-3 sm:col-span-2">
    <Label htmlFor="github-org">GitHub organization</Label>
    <Input id="github-org" value={organization} placeholder="organization or https://github.com/organization" onChange={event => { setOrganization(event.target.value); setCredentialId(""); reset(); }} disabled={busy} />
    <Label htmlFor="github-org-token">Repository access token (optional)</Label>
    <Input id="github-org-token" type="password" autoComplete="off" value={token} placeholder={credentialId ? "Encrypted token saved; enter a replacement if needed" : "Token for private repository access"} onChange={event => { setToken(event.target.value); reset(); }} disabled={busy} />
    <Button type="button" onClick={() => void discover()} disabled={busy || !organization.trim()}>{busy ? "Discovering…" : "Discover repositories"}</Button>
    <p className="text-xs text-muted-foreground">{note ?? "Results reflect this credential’s access. Tokens are encrypted on the server. Selected repositories are scanned on their default branches under this assessment."}</p>
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {repos.length > 0 && <>
      <div className="flex flex-wrap items-center gap-3">
        <label>Visibility <select aria-label="Repository visibility" value={visibility} onChange={event => { setVisibility(event.target.value); publish(selected, event.target.value); }}><option value="all">All</option><option value="public">Public</option><option value="private">Private</option></select></label>
        <label><input type="checkbox" checked={archived} onChange={event => { setArchived(event.target.checked); publish(selected, visibility, event.target.checked); }} /> Include archived</label>
        <label><input type="checkbox" checked={forks} onChange={event => { setForks(event.target.checked); publish(selected, visibility, archived, event.target.checked); }} /> Include forks</label>
      </div>
      <Input aria-label="Search repositories" placeholder="Search repositories" value={search} onChange={event => setSearch(event.target.value)} />
      <div className="flex gap-2"><Button type="button" variant="outline" onClick={() => publish(new Set(filtered.map(repo => repo.id)))}>Select all</Button><Button type="button" variant="outline" onClick={() => publish(new Set())}>Clear selection</Button></div>
      <p className="text-sm">{filtered.filter(repo => selected.has(repo.id)).length} selected / {repos.length} accessible repositories</p>
      <div className="max-h-72 space-y-2 overflow-auto rounded border p-3">{visible.map(repo => <label key={repo.id} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={selected.has(repo.id)} onChange={event => { const next = new Set(selected); if (event.target.checked) next.add(repo.id); else next.delete(repo.id); publish(next); }} /><span>{repo.full_name} · {repo.private ? "private" : "public"}{repo.archived ? " · archived" : ""}{repo.fork ? " · fork" : ""} · {repo.default_branch || "empty repository"}</span></label>)}</div>
    </>}
  </div>;
}
