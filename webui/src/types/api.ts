// Types mirror Go structs in internal/web/server.go.
// These are inferred from the actual backend, not invented.

export interface VulnSummary {
  id: string;
  title: string;
  severity: string;
  target?: string;
  endpoint: string;
  cvss: number;
  cvss_vector?: string;
  description?: string;
  impact?: string;
  method?: string;
  cve?: string;
  cwe_id?: string;
  owasp?: string;
  technical_analysis?: string;
  poc_description?: string;
  poc_script?: string;
  remediation?: string;
  exploitation_proof?: string;
  verification_method?: string;
}

export interface WSEvent {
  type: string;
  content?: string;
  tool_name?: string;
  tool_args?: Record<string, string>;
  output?: string;
  error?: string;
  agent_id?: string;
  instance_id?: string;
  timestamp?: string;
  vulns?: VulnSummary[];
  target_index?: number;
  total_targets?: number;
  target?: string;
  total_tokens?: number;
  sub_target_index?: number;
  sub_target_total?: number;
  parent_target?: string;
  current_phase?: number;
}

export interface ScanInstance {
  id: string;
  name?: string;
  targets: string;
  parent_target?: string;
  status: string;
  started_at: string;
  finished_at?: string;
  stop_reason?: string;
  iterations: number;
  tool_calls: number;
  vuln_count: number;
  total_tokens: number;
  scan_mode: string;
  instruction?: string;
  severity_filter?: string[];
  phases?: number[];
  company_name?: string;
  logo_path?: string;
  vulns?: VulnSummary[];
  current_phase?: number;
}

export interface SubScanSummary {
  id: string;
  target: string;
  started_at?: string;
  finished_at?: string;
  status: string;
  vuln_count: number;
  total_tokens: number;
}

export interface ScanRecord {
  id: string;
  instance_id?: string;
  name?: string;
  target: string;
  parent_target?: string;
  started_at: string;
  finished_at?: string;
  status: string;
  stop_reason?: string;
  scan_mode?: string;
  instruction?: string;
  severity_filter?: string[];
  discord_webhook?: string;
  discord_webhook_configured?: boolean;
  events: WSEvent[];
  vulns: VulnSummary[];
  total_tokens: number;
  iterations: number;
  tool_calls: number;
  company_name?: string;
  logo_path?: string;
  phases?: number[];
  current_phase?: number;
  sub_scans?: SubScanSummary[];
  sub_scan_total?: number;
  sub_scan_completed?: number;
  sub_scan_running?: number;
  sub_scan_remaining?: number;
}

export interface ScanListItem {
  id: string;
  target: string;
  started_at: string;
  status: string;
  scan_mode?: string;
  vuln_count: number;
  total_tokens: number;
  sub_scan_total?: number;
  sub_scan_completed?: number;
  sub_scan_running?: number;
  sub_scan_remaining?: number;
}

export interface InstancesResponse {
  instances: ScanInstance[];
  resources: {
    cpu_cores: number;
    cpu_load_1m: number;
    ram_total_mb: number;
    ram_available_mb: number;
    disk_free_mb: number;
    level: string;
    reason: string;
    max_instances: number;
    manual_max_instances: number;
    effective_max_instances: number;
  };
}

export interface StatusResponse {
  running: boolean;
  scan_id: string;
  instance_id: string;
  current_phase: number;
  vulns: number;
  running_instances: number;
}

export interface VersionInfo {
  version: string;
  ai?: {
    configured: boolean;
    provider: string;
    model?: string;
    gateway?: string;
  };
}

export interface AuthStatus {
  auth_enabled: boolean;
  authenticated: boolean;
}

export interface ScanRequest {
  targets: string[];
  instruction?: string;
  scan_mode?: string;
  model?: string;
  api_key?: string;
  api_base?: string;
  discord_webhook?: string;
  severity_filter?: string[];
  name?: string;
  save_only?: boolean;
  phases?: number[];
  company_name?: string;
  logo_path?: string;
}

export interface QueueStatus {
  available: boolean;
  targets?: string[];
  current_idx?: number;
  remaining?: number;
  instruction?: string;
  scan_mode?: string;
  started_at?: string;
}

export interface RateLimitSettings {
  requests: number;
  window: number;
}

export interface AgentMailSettings {
  pod: string;
  apiKey: string;
  hasApiKey: boolean;
}

export interface LLMSettings {
  model: string;
  apiBase: string;
  apiKey: string;
  hasApiKey: boolean;
  reasoningEffort: string;
  llmMaxRetries: number;
  memoryCompressorTimeout: number;
  maxIterations: number;
  geminiApiKey: string;
  hasGeminiApiKey: boolean;
  envFile: string;
}

export interface EnvironmentVariableSetting {
  key: string;
  label: string;
  category: string;
  description: string;
  defaultValue?: string;
  placeholder?: string;
  inputType: "text" | "url" | "path" | "secret" | "number" | "boolean" | "select";
  options?: string[];
  sensitive: boolean;
  requiresRestart: boolean;
  value: string;
  hasValue: boolean;
}

export interface EnvironmentSettings {
  envFile: string;
  variables: EnvironmentVariableSetting[];
  restartRequired?: boolean;
}

export interface ScanSchedule {
  id: string;
  name: string;
  interval: string;
  next_run: string;
  last_run?: string;
  enabled: boolean;
  targets: string[];
  instruction?: string;
  scan_mode: string;
  severity_filter?: string[];
  phases?: number[];
  company_name?: string;
  logo_path?: string;
  discord_webhook?: string;
  model?: string;
}
