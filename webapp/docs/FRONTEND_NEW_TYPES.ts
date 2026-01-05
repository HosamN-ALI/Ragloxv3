/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * RAGLOX v3.0 - New TypeScript Types for Frontend
 * هذا الملف يحتوي على جميع الـ Types الجديدة المطلوبة للواجهة
 * يجب إضافة هذه الـ Types إلى client/src/types/index.ts
 * ═══════════════════════════════════════════════════════════════════════════════
 */

// ═══════════════════════════════════════════════════════════════
// EXPLOITATION MODULE TYPES
// ═══════════════════════════════════════════════════════════════

/**
 * C2 Session - جلسة الأوامر والتحكم
 */
export interface C2Session {
  session_id: string;
  target_ip: string;
  target_hostname?: string;
  session_type: C2SessionType;
  username: string;
  privilege: PrivilegeLevel;
  status: C2SessionStatus;
  platform: string;
  arch: "x64" | "x86" | "arm64" | "arm";
  established_at: string;
  last_seen: string;
  pid?: number;
  process_name?: string;
  tunnel_info?: TunnelInfo;
}

export type C2SessionType = "meterpreter" | "shell" | "beacon" | "ssh" | "winrm";

export type C2SessionStatus = "active" | "dead" | "stale" | "sleeping";

export interface TunnelInfo {
  type: "reverse" | "bind";
  local_port: number;
  remote_port: number;
  encrypted: boolean;
}

/**
 * Exploit Definition
 */
export interface Exploit {
  exploit_id: string;
  name: string;
  full_name: string;
  description: string;
  cve_ids: string[];
  platforms: string[];
  rank: ExploitRank;
  disclosure_date: string;
  author: string;
  references: string[];
  options: ExploitOption[];
  targets: ExploitTarget[];
  payload_types: string[];
}

export type ExploitRank = "excellent" | "great" | "good" | "normal" | "low" | "manual";

export interface ExploitOption {
  name: string;
  display_name: string;
  description: string;
  required: boolean;
  default_value?: string;
  type: "string" | "integer" | "boolean" | "address" | "port";
}

export interface ExploitTarget {
  id: number;
  name: string;
  info: string;
}

/**
 * Payload Configuration
 */
export interface Payload {
  name: string;
  description: string;
  platform: string;
  arch: string;
  type: PayloadType;
  connection_type: "reverse" | "bind";
  encoder?: string;
  iterations?: number;
}

export type PayloadType = "staged" | "stageless" | "inline";

export interface PayloadConfig {
  payload_type: string;
  platform: string;
  arch: string;
  format: PayloadFormat;
  lhost: string;
  lport: number;
  encoder?: string;
  iterations?: number;
  options?: Record<string, unknown>;
}

export type PayloadFormat =
  | "raw"
  | "exe"
  | "dll"
  | "elf"
  | "msi"
  | "powershell"
  | "python"
  | "bash"
  | "base64";

export interface PayloadResult {
  success: boolean;
  payload_data?: string;
  file_path?: string;
  size_bytes: number;
  handler_info: {
    lhost: string;
    lport: number;
    payload: string;
  };
}

/**
 * Post-Exploitation
 */
export interface HarvestConfig {
  session_id: string;
  harvest_types: HarvestType[];
  stealth_mode: boolean;
}

export type HarvestType =
  | "credentials"
  | "hashes"
  | "tokens"
  | "cookies"
  | "browser_data"
  | "wifi_passwords"
  | "ssh_keys"
  | "certificates";

export interface HarvestResult {
  session_id: string;
  credentials: HarvestedCredential[];
  hashes: HarvestedHash[];
  tokens: HarvestedToken[];
  other_data: Record<string, unknown>;
  harvest_time: string;
}

export interface HarvestedCredential {
  username: string;
  password: string;
  domain?: string;
  source: string;
  type: string;
}

export interface HarvestedHash {
  username: string;
  hash: string;
  hash_type: "ntlm" | "lm" | "sha256" | "md5" | "kerberos";
  domain?: string;
}

export interface HarvestedToken {
  token_type: string;
  token_value: string;
  user: string;
  privileges: string[];
}

/**
 * Pivoting / Network Routes
 */
export interface PortForwardConfig {
  session_id: string;
  local_port: number;
  remote_host: string;
  remote_port: number;
  direction: "local" | "remote";
}

export interface Route {
  id: string;
  subnet: string;
  netmask: string;
  gateway: string;
  session_id: string;
  status: "active" | "down";
}

export interface ProxyConfig {
  session_id: string;
  proxy_type: "socks4" | "socks5";
  local_port: number;
}

export interface ProxyResult {
  proxy_host: string;
  proxy_port: number;
  proxy_type: string;
  status: "running" | "stopped";
}

/**
 * Command Execution Results
 */
export interface CommandResult {
  success: boolean;
  output: string;
  error?: string;
  execution_time_ms: number;
}

/**
 * Exploitation Statistics
 */
export interface ExploitStats {
  total_exploits: number;
  by_platform: Record<string, number>;
  by_rank: Record<ExploitRank, number>;
  recent_cves: string[];
}

export interface ExploitationHealth {
  metasploit_connected: boolean;
  metasploit_version?: string;
  active_sessions: number;
  active_handlers: number;
  database_connected: boolean;
}

// ═══════════════════════════════════════════════════════════════
// INFRASTRUCTURE MODULE TYPES
// ═══════════════════════════════════════════════════════════════

/**
 * Environment - بيئة التنفيذ SSH/WinRM
 */
export interface Environment {
  id: string;
  name: string;
  type: EnvironmentType;
  host: string;
  port: number;
  username: string;
  status: EnvironmentStatus;
  created_at: string;
  last_connected: string;
  user_id: string;
  system_info?: SystemInfo;
  metadata?: Record<string, unknown>;
}

export type EnvironmentType = "ssh" | "winrm" | "local";

export type EnvironmentStatus = "connected" | "disconnected" | "connecting" | "error";

export interface CreateEnvironmentRequest {
  name: string;
  type: EnvironmentType;
  host: string;
  port: number;
  username: string;
  password?: string;
  private_key?: string;
  passphrase?: string;
}

/**
 * System Information
 */
export interface SystemInfo {
  hostname: string;
  os: string;
  os_version: string;
  kernel: string;
  arch: string;
  uptime: string;
  uptime_seconds: number;
  memory: MemoryInfo;
  disk: DiskInfo[];
  network: NetworkInterface[];
  users: SystemUser[];
}

export interface MemoryInfo {
  total_mb: number;
  used_mb: number;
  free_mb: number;
  percentage: number;
}

export interface DiskInfo {
  device: string;
  mount_point: string;
  filesystem: string;
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percentage: number;
}

export interface NetworkInterface {
  name: string;
  ip_address: string;
  mac_address: string;
  netmask: string;
  is_up: boolean;
}

export interface SystemUser {
  username: string;
  uid: number;
  gid: number;
  home: string;
  shell: string;
}

/**
 * Execution Results
 */
export interface ExecutionResult {
  success: boolean;
  output: string;
  error?: string;
  exit_code: number;
  execution_time_ms: number;
  environment_id: string;
}

/**
 * Health Status
 */
export interface HealthStatus {
  status: "healthy" | "unhealthy" | "degraded";
  connected: boolean;
  last_check: string;
  latency_ms?: number;
  errors?: string[];
}

export interface HealthStatistics {
  uptime_percentage: number;
  total_commands_executed: number;
  average_latency_ms: number;
  errors_last_24h: number;
}

/**
 * Infrastructure Statistics
 */
export interface InfrastructureStats {
  total_environments: number;
  connected: number;
  disconnected: number;
  by_type: Record<EnvironmentType, number>;
  total_commands_executed: number;
}

// ═══════════════════════════════════════════════════════════════
// WORKFLOW MODULE TYPES
// ═══════════════════════════════════════════════════════════════

/**
 * Workflow Phases - المراحل التسع
 */
export type WorkflowPhase =
  | "init"
  | "planning"
  | "reconnaissance"
  | "initial_access"
  | "post_exploitation"
  | "lateral_movement"
  | "goal_execution"
  | "reporting"
  | "cleanup";

export const WORKFLOW_PHASES: WorkflowPhase[] = [
  "init",
  "planning",
  "reconnaissance",
  "initial_access",
  "post_exploitation",
  "lateral_movement",
  "goal_execution",
  "reporting",
  "cleanup",
];

export const PHASE_LABELS: Record<WorkflowPhase, string> = {
  init: "Initialization",
  planning: "Planning",
  reconnaissance: "Reconnaissance",
  initial_access: "Initial Access",
  post_exploitation: "Post-Exploitation",
  lateral_movement: "Lateral Movement",
  goal_execution: "Goal Execution",
  reporting: "Reporting",
  cleanup: "Cleanup",
};

export const PHASE_DESCRIPTIONS: Record<WorkflowPhase, string> = {
  init: "Initialize mission context and validate configuration",
  planning: "AI-driven campaign planning and strategy",
  reconnaissance: "Network discovery and information gathering",
  initial_access: "Exploitation and foothold establishment",
  post_exploitation: "Privilege escalation and persistence",
  lateral_movement: "Network pivoting and expansion",
  goal_execution: "Execute specific mission goals",
  reporting: "Generate findings and evidence report",
  cleanup: "Remove artifacts and restore state",
};

/**
 * Workflow Status
 */
export interface WorkflowStatus {
  mission_id: string;
  current_phase: WorkflowPhase;
  phases_completed: WorkflowPhase[];
  phases_remaining: WorkflowPhase[];
  phases_skipped: WorkflowPhase[];
  progress_percentage: number;
  status: "running" | "paused" | "completed" | "failed" | "waiting_approval";
  started_at: string;
  estimated_completion?: string;
  current_action?: string;
  last_error?: string;
}

/**
 * Phase Result
 */
export interface PhaseResult {
  phase: WorkflowPhase;
  status: PhaseStatus;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  findings: PhaseFinding[];
  actions_taken: number;
  errors: string[];
  metrics: PhaseMetrics;
}

export type PhaseStatus = "pending" | "running" | "completed" | "failed" | "skipped";

export interface PhaseFinding {
  id: string;
  type: FindingType;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence?: string;
  target?: string;
  timestamp: string;
}

export type FindingType =
  | "target_discovered"
  | "port_open"
  | "service_detected"
  | "vulnerability_found"
  | "credential_harvested"
  | "session_established"
  | "privilege_escalated"
  | "data_exfiltrated"
  | "goal_achieved";

export interface PhaseMetrics {
  targets_discovered?: number;
  ports_scanned?: number;
  vulnerabilities_found?: number;
  exploits_attempted?: number;
  exploits_succeeded?: number;
  credentials_harvested?: number;
  sessions_established?: number;
}

/**
 * Tools Management
 */
export interface Tool {
  name: string;
  display_name: string;
  category: ToolCategory;
  description: string;
  installed: boolean;
  version?: string;
  platforms: string[];
  dependencies: string[];
  install_command?: string;
  check_command?: string;
}

export type ToolCategory =
  | "recon"
  | "scanner"
  | "exploit"
  | "post_exploit"
  | "credential"
  | "lateral"
  | "utility";

export const TOOL_CATEGORY_LABELS: Record<ToolCategory, string> = {
  recon: "Reconnaissance",
  scanner: "Scanners",
  exploit: "Exploitation",
  post_exploit: "Post-Exploitation",
  credential: "Credential Attacks",
  lateral: "Lateral Movement",
  utility: "Utilities",
};

export interface InstallResult {
  tool_name: string;
  success: boolean;
  version?: string;
  message: string;
  install_time_seconds: number;
}

export interface WorkflowHealth {
  orchestrator_active: boolean;
  active_workflows: number;
  tools_available: number;
  tools_missing: string[];
}

// ═══════════════════════════════════════════════════════════════
// SECURITY MODULE TYPES
// ═══════════════════════════════════════════════════════════════

/**
 * Validation Types
 */
export interface ValidationResult {
  valid: boolean;
  value: string;
  errors?: string[];
  normalized?: string;
}

export interface ValidationItem {
  type: ValidationType;
  value: string;
}

export type ValidationType =
  | "ip"
  | "cidr"
  | "uuid"
  | "hostname"
  | "port"
  | "cve"
  | "safe_string"
  | "scope";

export interface BatchValidationResult {
  results: Array<{
    type: ValidationType;
    value: string;
    valid: boolean;
    error?: string;
  }>;
  all_valid: boolean;
  invalid_count: number;
}

/**
 * Rate Limiting
 */
export interface RateLimitInfo {
  endpoint: string;
  limit: number;
  window_seconds: number;
  remaining: number;
  reset_at: string;
}

export interface RateLimitStatus {
  enabled: boolean;
  current_requests: number;
  limit: number;
  window_seconds: number;
  remaining: number;
  reset_in_seconds: number;
  blocked_until?: string;
}

/**
 * Security Health & Stats
 */
export interface SecurityHealth {
  validation_enabled: boolean;
  rate_limiting_enabled: boolean;
  xss_protection: boolean;
  sql_injection_protection: boolean;
  command_injection_protection: boolean;
  path_traversal_protection: boolean;
  recent_blocks: number;
  status: "healthy" | "degraded" | "unhealthy";
}

export interface SecurityStats {
  total_requests: number;
  blocked_requests: number;
  validation_failures: number;
  rate_limit_hits: number;
  by_endpoint: Record<string, EndpointStats>;
  by_ip: Record<string, number>;
  last_24h: {
    total: number;
    blocked: number;
    rate_limited: number;
  };
}

export interface EndpointStats {
  requests: number;
  blocked: number;
  avg_response_time_ms: number;
}

// ═══════════════════════════════════════════════════════════════
// REPORT MODULE TYPES
// ═══════════════════════════════════════════════════════════════

export interface Report {
  id: string;
  mission_id: string;
  title: string;
  type: ReportType;
  format: ReportFormat;
  status: "generating" | "ready" | "failed";
  created_at: string;
  file_path?: string;
  file_size_bytes?: number;
}

export type ReportType = "executive" | "technical" | "compliance" | "full";

export type ReportFormat = "pdf" | "html" | "json" | "markdown";

export interface ReportConfig {
  mission_id: string;
  type: ReportType;
  format: ReportFormat;
  include_sections: ReportSection[];
  include_evidence: boolean;
  include_recommendations: boolean;
  executive_summary: boolean;
}

export type ReportSection =
  | "summary"
  | "scope"
  | "methodology"
  | "timeline"
  | "findings"
  | "vulnerabilities"
  | "credentials"
  | "sessions"
  | "recommendations"
  | "appendix";

// ═══════════════════════════════════════════════════════════════
// API RESPONSE WRAPPER TYPES
// ═══════════════════════════════════════════════════════════════

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  timestamp: string;
}

export interface PaginatedApiResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

// ═══════════════════════════════════════════════════════════════
// WEBSOCKET EVENT TYPES (Extended)
// ═══════════════════════════════════════════════════════════════

export type ExtendedWebSocketEventType =
  // Existing
  | "connected"
  | "pong"
  | "subscribed"
  | "new_target"
  | "target_update"
  | "new_vuln"
  | "vuln_update"
  | "new_cred"
  | "new_session"
  | "session_closed"
  | "approval_request"
  | "approval_response"
  | "approval_resolved"
  | "mission_status"
  | "status_change"
  | "statistics"
  | "goal_achieved"
  | "chat_message"
  | "ai_plan"
  | "mission_update"
  | "error"
  // New - Workflow
  | "workflow_started"
  | "phase_started"
  | "phase_completed"
  | "phase_failed"
  | "workflow_completed"
  // New - Exploitation
  | "session_opened"
  | "session_upgraded"
  | "exploit_started"
  | "exploit_succeeded"
  | "exploit_failed"
  | "payload_delivered"
  // New - Infrastructure
  | "environment_connected"
  | "environment_disconnected"
  | "command_output"
  // New - Security
  | "security_alert"
  | "rate_limit_warning";

export interface ExtendedWebSocketMessage {
  type: ExtendedWebSocketEventType;
  data: unknown;
  timestamp: string;
  mission_id?: string;
  session_id?: string;
  environment_id?: string;
}
