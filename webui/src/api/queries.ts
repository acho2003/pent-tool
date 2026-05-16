import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import type { ScanRequest } from "@/types/api";

export const qk = {
  authStatus: ["auth", "status"] as const,
  status: ["status"] as const,
  version: ["version"] as const,
  scans: ["scans"] as const,
  scan: (id: string) => ["scan", id] as const,
  instances: ["instances"] as const,
  instance: (id: string) => ["instance", id] as const,
  instanceEvents: (id: string) => ["instance", id, "events"] as const,
  queue: ["queue"] as const,
  rateLimit: ["settings", "rate-limit"] as const,
  agentMail: ["settings", "agentmail"] as const,
  llmSettings: ["settings", "llm"] as const,
  environmentSettings: ["settings", "environment"] as const,
};

export function useAuthStatus() {
  return useQuery({
    queryKey: qk.authStatus,
    queryFn: api.authStatus,
    staleTime: 60_000,
  });
}

export function useStatus() {
  return useQuery({
    queryKey: qk.status,
    queryFn: api.status,
    refetchInterval: 5000,
  });
}

export function useVersion() {
  return useQuery({
    queryKey: qk.version,
    queryFn: api.version,
    staleTime: Infinity,
  });
}

export function useScansList() {
  return useQuery({
    queryKey: qk.scans,
    queryFn: api.listScans,
    refetchInterval: 15000,
  });
}

export function useScan(id?: string) {
  return useQuery({
    queryKey: id ? qk.scan(id) : ["scan", "none"],
    queryFn: () => api.getScan(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const scan = query.state.data;
      if (!scan) return 2000;
      const status = (scan.status || "").toLowerCase();
      return status === "running" || status === "pending" || status === "paused"
        ? 2000
        : false;
    },
  });
}

export function useInstances() {
  return useQuery({
    queryKey: qk.instances,
    queryFn: api.instances,
    refetchInterval: 8000,
  });
}

export function useInstanceEvents(id?: string) {
  return useQuery({
    queryKey: id ? qk.instanceEvents(id) : ["instance", "none", "events"],
    queryFn: () => api.instanceEvents(id!),
    enabled: !!id,
    staleTime: 1000,
    refetchInterval: 5000,
  });
}

export function useQueueStatus() {
  return useQuery({
    queryKey: qk.queue,
    queryFn: api.queueStatus,
    refetchInterval: 10000,
  });
}

export function useRateLimit() {
  return useQuery({
    queryKey: qk.rateLimit,
    queryFn: api.rateLimit,
  });
}

export function useAgentMail() {
  return useQuery({
    queryKey: qk.agentMail,
    queryFn: api.agentMail,
  });
}

export function useLLMSettings() {
  return useQuery({
    queryKey: qk.llmSettings,
    queryFn: api.llmSettings,
  });
}

export function useEnvironmentSettings() {
  return useQuery({
    queryKey: qk.environmentSettings,
    queryFn: api.environmentSettings,
  });
}

export function useStartScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: ScanRequest) => api.startScan(req),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: qk.status });
    },
  });
}

export function useStopAll() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.stopAll(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.status });
    },
  });
}

export function useStopInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.stopInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function useRestartInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.restartInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function useStartSavedInstance() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.startSavedInstance(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.instances }),
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.deleteScan(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.instances });
      qc.invalidateQueries({ queryKey: qk.scans });
    },
  });
}

export function useDeleteVuln() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ scanId, vulnId }: { scanId: string; vulnId: string }) =>
      api.deleteVuln(scanId, vulnId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.scans });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
    onError: (err) => {
      console.error("Failed to delete vulnerability:", err);
    },
  });
}

export function useUpdateRateLimit() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateRateLimit,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.rateLimit });
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
    },
  });
}

export function useUpdateAgentMail() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateAgentMail,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.agentMail });
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
    },
  });
}

export function useUpdateLLMSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateLLMSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.llmSettings });
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
      qc.invalidateQueries({ queryKey: qk.version });
    },
  });
}

export function useUpdateEnvironmentSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.updateEnvironmentSettings,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.environmentSettings });
      qc.invalidateQueries({ queryKey: qk.llmSettings });
      qc.invalidateQueries({ queryKey: qk.agentMail });
      qc.invalidateQueries({ queryKey: qk.rateLimit });
      qc.invalidateQueries({ queryKey: qk.version });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
  });
}

export function useQueueResume() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.queueResume,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.queue });
      qc.invalidateQueries({ queryKey: qk.instances });
    },
  });
}

export function useQueueClear() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: api.queueClear,
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.queue }),
  });
}
