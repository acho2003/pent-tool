// Types mirror Go structs in internal/web/server.go.
// These are inferred from the actual backend, not invented.

export interface VulnSummary {
  id: string;
  fingerprint?: string;
  title: string;
  severity: string;
  target?: string;
  endpoint: string;
  cvss: number;
  cvss_vector?: string;
  description?: string;
  impact?: string;
  method?: string;
  parameter?: string;
  cve?: string;
  cwe_id?: string;
  confidence?: string;
  native_confidence?: string;
  evidence_completeness?: string;
  owasp?: string;
  technical_analysis?: string;
  poc_description?: string;
  poc_script?: string;
  remediation?: string;
  fix?: string;
  exploitation_proof?: string;
  verification_method?: string;
  verified?: boolean;
  // Machine-readable labels. Always carries a verification tag:
  // "verified" (independently reproduced) or "needs-manual-verification"
  // (preserved but not confirmed — a human must review it).
  tags?: string[];
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
  scanner?: string;
  stream?: "stdout" | "stderr" | string;
  sequence?: number;
}

export interface ScannerArtifact { kind: "filesystem" | "repository" | "image" | "sbom" | string; ref: string; }
export interface ScannerRun {
  scanner: string;
  scope?: string;
  target: string;
  status: "completed" | "failed" | "cancelled" | "not_applicable" | "skipped" | "running";
  started_at?: string; finished_at?: string; exit_code?: number; reason?: string;
  stdout_path?: string; stderr_path?: string; artifact_path?: string; checksum?: string; truncated?: boolean;
}

// One pipeline tool, from GET /api/scanners/status (backend scanner.Catalog).
export interface ToolInfo {
  name: string;
  phase: "recon" | "web" | "server" | "sast" | string;
  selectable: boolean;
  summary: string;
  available: boolean;
  path?: string;
  endpoint_configured?: boolean;
}

export type AssessmentMode = "BLACK_BOX" | "GRAY_BOX" | "WHITE_BOX";
export type AssessmentType = "NETWORK" | "WEB_APPLICATION" | "API" | "SOURCE_CODE" | "DEPENDENCIES" | "CONTAINER" | "HOST" | "CLOUD" | "KUBERNETES" | "INFRASTRUCTURE_AS_CODE" | "COMPLIANCE";
export interface AssessmentTarget { id: string; type: string; value: string; }
export interface AssessmentConfig {
  assessment_mode: AssessmentMode;
  assessment_types: AssessmentType[];
  assessment_targets: AssessmentTarget[];
  profile?: string;
  subdomain_discovery?: boolean;
  api_definitions?: Array<{ target_id: string; definition_id: string }>;
  access?: Array<{ target_ids: string[]; kind: string; credential_id: string; verify_url?: string; verify_marker?: string }>;
  scanner_selection?: { mode?: "auto" | "custom"; variants?: string[] };
}
export interface CredentialMetadata { id: string; name: string; kind: string; target_ids: string[]; created_at: string; }
export interface AssessmentPlan {
  config: AssessmentConfig;
  capabilities: Array<{ capability: string; target_id: string; reference_id?: string; access_kind?: string; state: string; provenance: string; reason: string }>;
  decisions: Array<{ scanner: string; target_id?: string; assessment_types?: AssessmentType[]; state: string; reason_code: string; reason: string; execution_mode?: string }>;
  jobs: Array<{ id: string; state: string; scanner: string; target_id: string; target: string; assessment_type: AssessmentType; assessment_types?: AssessmentType[]; variant: string; execution_mode?: string; reason?: string }>;
  coverage: Array<{ type: AssessmentType; state: string; reason: string }>;
  api_endpoints?: Array<{ method: string; path: string; origin?: string; target_id?: string; source: string; resolved: boolean; eligible: boolean; reason?: string }>;
  warnings?: Array<{ code: string; message: string; blocking: boolean }>;
  errors?: Array<{ code: string; message: string; blocking: boolean }>;
  fingerprint: string;
  registry_version: string;
}

// One run within a scope, from GET /api/scans/{id}/scopes.
export interface ScopeRun {
  scanner: string;
  status: string;
  reason?: string;
  scope?: string;
  truncated?: boolean;
  has_artifact?: boolean;
}

export interface ReportScope {
  id: string;
  kind: "host" | "source" | string;
  target?: string;
  origin?: string;
  tracks?: string[];
  open_ports?: string[];
  services?: string[];
  live_urls?: string[];
  runs: ScopeRun[];
}

export interface ScanScopes {
  recon: ScopeRun[];
  scopes: ReportScope[];
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
  vuln_count: number;
  scan_mode: string;
  severity_filter?: string[];
  scanners?: string[];
  phases?: number[];
  company_name?: string;
  logo_path?: string;
  vulns?: VulnSummary[];
  current_phase?: number;
  scanner_runs?: ScannerRun[];
  artifact?: ScannerArtifact;
  vuls_ssh_host?: string;
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
  schema_version?: number;
  assessment?: AssessmentConfig;
  assessment_plan?: AssessmentPlan;
  plan_fingerprint?: string;
  profile?: string;
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
  severity_filter?: string[];
  scanners?: string[];
  discord_webhook?: string;
  discord_webhook_configured?: boolean;
  telegram_configured?: boolean;
  events: WSEvent[];
  vulns: VulnSummary[];
  company_name?: string;
  logo_path?: string;
  phases?: number[];
  current_phase?: number;
  sub_scans?: SubScanSummary[];
  sub_scan_total?: number;
  sub_scan_completed?: number;
  sub_scan_running?: number;
  sub_scan_remaining?: number;
  scanner_runs?: ScannerRun[];
  artifact?: ScannerArtifact;
  vuls_ssh_host?: string;
}

export interface AssessmentCoverage {
  scan_id: string;
  state: string;
  profile?: string;
  plan_fingerprint?: string;
  assessment_mode?: AssessmentMode;
  assessment_types?: AssessmentType[];
  type_coverage?: Array<{ type: AssessmentType; state: string; reason: string }>;
  jobs?: Array<{ id: string; scanner: string; variant: string; target_id: string; target: string; assessment_types?: AssessmentType[]; planned_state: string; status: string; reason?: string; has_artifact: boolean; artifact_state: string }>;
  capabilities?: Array<{ capability: string; target_id?: string; state: string; reason: string }>;
  api_operations?: Array<{ target_id: string; method: string; path: string; origin?: string; status: string; reason: string; eligible: boolean }>;
  gaps?: Array<{ scanner: string; target_id?: string; assessment_types?: AssessmentType[]; state: string; reason_code: string; reason: string }>;
  counts: Record<string, number>;
  reason?: string;
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

/** Generic server-side pagination envelope: { items, total, page, size }. */
export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

/** Query params accepted by the paginated list endpoints. */
export interface ListParams {
  page: number;
  size: number;
  q?: string;
  status?: string;
  mode?: string;
}

export interface InstancesResponse {
  instances: ScanInstance[];
  // Present when the request used server-side pagination/filtering.
  total?: number;
  page?: number;
  size?: number;
  /** Distinct scan modes across all instances, for the filter dropdown. */
  modes?: string[];
  resources: {
    cpu_cores: number;
    cpu_load_1m: number;
    ram_total_mb: number;
    ram_available_mb: number;
    disk_free_mb: number;
    process_rss_mb?: number;
    go_heap_alloc_mb?: number;
    go_heap_sys_mb?: number;
    goroutines?: number;
    level: string;
    reason: string;
    max_instances: number;
    manual_max_instances: number;
    effective_max_instances: number;
    active_tool_leases?: number;
    active_heavy_tool_leases?: number;
    heavy_tool_slots?: number;
    light_tool_slots?: number;
    tool_mem_limit_mb?: number;
    scan_memory_budget_mb?: number;
    heavy_tool_cpu_load?: number;
    go_memory_limit_mb?: number;
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
}

export interface AuthStatus {
  auth_enabled: boolean;
  authenticated: boolean;
}

export interface ScanRequest {
  assessment?: AssessmentConfig;
  plan_fingerprint?: string;
  profile?: string;
  targets: string[];
  scan_mode?: string;
  name?: string;
  save_only?: boolean;
  company_name?: string;
  logo_path?: string;
  target_auth?: string;
  artifact?: ScannerArtifact;
  vuls_ssh_host?: string;
  // Restrict the post-scan report to findings at or above the selected
  // severities. Empty/omitted = all severities. Accepted by the backend
  // ScanRequest (`severity_filter`).
  severity_filter?: string[];
  // Restrict the run to these scanners (the selectable tools from /api/scanners/status). Omitted or
  // empty runs the whole pipeline; deselected scanners are recorded as
  // "skipped" rather than omitted from the scan record.
  scanners?: string[];
}

export interface QueueStatus {
  available: boolean;
  queue_count?: number;
  total_remaining?: number;
  instance_id?: string;
  targets?: string[];
  current_idx?: number;
  remaining?: number;
  scan_mode?: string;
  paused?: boolean;
  active_target?: string;
  active_scan_id?: string;
  wildcard_active_target?: string;
  wildcard_active_scan_id?: string;
  wildcard_sub_index?: number;
  wildcard_subdomains_total?: number;
  started_at?: string;
}

export interface RateLimitSettings {
  requests: number;
  window: number;
}

export interface EnvironmentVariableSetting {
  key: string;
  label: string;
  category: string;
  description: string;
  defaultValue?: string;
  placeholder?: string;
  inputType:
    | "text"
    | "url"
    | "path"
    | "secret"
    | "number"
    | "boolean"
    | "select";
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
  assessment?: AssessmentConfig;
  profile?: string;
  plan_fingerprint?: string;
  id: string;
  name: string;
  interval: string;
  // Wall-clock time of day the schedule fires, "HH:MM" in 24h form and
  // interpreted in `timezone`. Empty/absent keeps the legacy behavior of
  // running one interval after creation or the last run. For the "hourly"
  // interval only the minutes apply.
  run_at?: string;
  // Day within the interval: weekday for "weekly" (0=Sunday … 6=Saturday) and
  // day of month for "monthly" (1-31, clamped to the last day of shorter
  // months). Ignored for "hourly" and "daily".
  run_day?: number;
  // IANA timezone name `run_at`/`run_day` are read in, e.g.
  // "America/Argentina/Buenos_Aires". Empty means the server's local time.
  timezone?: string;
  next_run: string;
  last_run?: string;
  enabled: boolean;
  targets: string[];
  scan_mode: string;
  company_name?: string;
  logo_path?: string;
  artifact?: ScannerArtifact;
  vuls_ssh_host?: string;
}

// Response shape of GET /api/findings/summary. Polled every 10s by the
// Findings and Overview pages; counts are deduplicated server-side by
// (target, endpoint, title, severity) so the totals strip and the
// row list always agree. The same query key (qk.findingsSummary) is
// used on both pages so the React Query cache is shared.
export interface FindingsSummaryResponse {
  totals: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  as_of: string;
  etag: string;
}
