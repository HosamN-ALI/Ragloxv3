// RAGLOX v3.0 - Type Definitions
// Based on Backend-Frontend Integration Guide

// ============================================
// Enums
// ============================================

export enum MissionStatus {
  CREATED = "created",
  STARTING = "starting",
  RUNNING = "running",
  PAUSED = "paused",
  WAITING_FOR_APPROVAL = "waiting_for_approval",
  COMPLETING = "completing",
  COMPLETED = "completed",
  FAILED = "failed",
  CANCELLED = "cancelled",
  ARCHIVED = "archived"
}

export enum TargetStatus {
  DISCOVERED = "discovered",
  SCANNING = "scanning",
  SCANNED = "scanned",
  EXPLOITING = "exploiting",
  EXPLOITED = "exploited",
  OWNED = "owned",
  FAILED = "failed"
}

export enum Priority {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low"
}

export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info"
}

export enum CredentialType {
  PASSWORD = "password",
  HASH = "hash",
  KEY = "key",
  TOKEN = "token",
  CERTIFICATE = "certificate"
}

export enum PrivilegeLevel {
  USER = "user",
  ADMIN = "admin",
  SYSTEM = "system",
  ROOT = "root",
  DOMAIN_ADMIN = "domain_admin",
  UNKNOWN = "unknown"
}

export enum SessionType {
  SHELL = "shell",
  METERPRETER = "meterpreter",
  SSH = "ssh",
  RDP = "rdp",
  WMI = "wmi",
  WINRM = "winrm",
  SMB = "smb"
}

export type TaskStatus = "pending" | "running" | "completed" | "failed";

// ============================================
// Data Models
// ============================================

export interface Mission {
  mission_id: string;
  name: string;
  description?: string;
  status: MissionStatus;
  scope: string[];
  goals: Record<string, string>;
  constraints?: Record<string, unknown>;
  statistics: MissionStatistics;
  target_count: number;
  vuln_count: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface MissionStatistics {
  targets_discovered: number;
  vulns_found: number;
  creds_harvested: number;
  sessions_established: number;
  goals_achieved: number;
  goals_total?: number;
  completion_percentage?: number;
}

export interface Target {
  target_id: string;
  ip: string;
  hostname?: string;
  os?: string;
  status: TargetStatus;
  priority: Priority;
  risk_score: number;
  ports: Record<string, string>;
}

export interface Vulnerability {
  vuln_id: string;
  target_id: string;
  type: string;
  name: string;
  severity: Severity;
  cvss: number;
  status: string;
  exploit_available: boolean;
}

export interface Credential {
  cred_id: string;
  target_id: string;
  type: CredentialType;
  username: string;
  password?: string;
  domain?: string;
  privilege_level: PrivilegeLevel;
  source: string;
  verified: boolean;
  created_at: string;
}

export interface Session {
  session_id: string;
  target_id: string;
  type: SessionType;
  user: string;
  privilege: string;
  status: string;
  established_at: string;
  last_activity: string;
}

export interface ApprovalRequest {
  action_id: string;
  action_type: string;
  action_description: string;
  target_ip: string;
  risk_level: string;
  risk_reasons: string[];
  potential_impact: string;
  command_preview: string;
  requested_at: string;
  expires_at: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "system" | "assistant";
  content: string;
  timestamp: string;
  related_task_id?: string;
  related_action_id?: string;
  // Command execution context (for terminal integration)
  command?: string;
  output?: string[];
}

// ============================================
// WebSocket Event Types
// ============================================

export type WebSocketEventType =
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
  | "error";

export interface WebSocketMessage {
  type: WebSocketEventType | string;
  data: unknown;
  timestamp: string;
  mission_id?: string;
}

// ============================================
// UI Component Types
// ============================================

export interface PlanTask {
  id: string;
  title: string;
  description?: string;
  status: TaskStatus;
  type?: string;
  target?: string;
  command?: string;
  output?: string;
  timestamp?: string;
  knowledge?: KnowledgeItem[];
  order?: number;
}

export interface KnowledgeItem {
  id: string;
  title: string;
  type: string;
  content?: string;
}

export interface EventCard {
  id: string;
  type?: WebSocketEventType | "approval" | "artifact";
  title: string;
  description?: string;
  timestamp: string;
  data?: unknown;
  expanded?: boolean;
  command?: string;
  output?: string;
  knowledge?: KnowledgeItem[];
  status?: TaskStatus;
  terminalPreview?: string[];
  // HITL Approval fields
  approval?: ApprovalRequest;
  // AI-PLAN fields
  aiPlan?: AIPlanData;
  // Artifact fields (for discovered data)
  artifact?: ArtifactData;
}

export interface ArtifactData {
  type: "credential" | "session" | "vulnerability" | "target";
  credential?: {
    id: string;
    username: string;
    password?: string;
    credential_type: string;
    service?: string;
    host?: string;
  };
  session?: {
    id: string;
    session_type: string;
    username: string;
    target_ip: string;
    port: number;
    status: string;
  };
  vulnerability?: {
    id: string;
    name: string;
    severity: string;
    cve_id?: string;
    target_ip: string;
    port: number;
  };
  target?: {
    id: string;
    ip: string;
    hostname?: string;
    os?: string;
    status: string;
    risk_score: number;
    open_ports: number[];
  };
}

export interface AIPlanData {
  subtype: string;
  port?: number;
  templates_count?: number;
  message: string;
  templates?: string[];
  reasoning?: string;
}

// ============================================
// API Response Types
// ============================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
}

export interface MissionCreateResponse {
  mission_id: string;
  name: string;
  status: MissionStatus;
  message: string;
}

export interface MissionControlResponse {
  mission_id: string;
  name: string;
  status: MissionStatus;
  message: string;
}

export interface ApprovalResponse {
  success: boolean;
  message: string;
  action_id: string;
  mission_status: MissionStatus;
}

// ============================================
// Knowledge Base Types
// ============================================

export interface Technique {
  id: string;
  name: string;
  description: string;
  platforms: string[];
  test_count: number;
}

export interface RXModule {
  rx_module_id: string;
  index: number;
  technique_id: string;
  technique_name: string;
  description: string;
  execution: {
    platforms: string[];
    executor_type: string;
    command: string;
    elevation_required: boolean;
    cleanup_command?: string;
  };
  variables: Array<{
    name: string;
    description: string;
    type: string;
    default_value?: string;
  }>;
  prerequisites: Array<{
    description: string;
    check_command?: string;
    install_command?: string;
  }>;
}

export interface Tactic {
  id: string;
  name: string;
  technique_count: number;
}

export interface NucleiTemplate {
  template_id: string;
  name: string;
  severity: string;
  protocol: string[];
  cve_id: string | string[];
  cwe_id: string | string[];
  cvss_score?: number;
  cvss_metrics?: string;
  tags: string[];
  description?: string;
  author?: string;
  reference: string[];
  file_path?: string;
}

export interface KnowledgeStats {
  total_techniques: number;
  total_tactics: number;
  total_rx_modules: number;
  platforms: string[];
  modules_per_platform: Record<string, number>;
  modules_per_executor: Record<string, number>;
  memory_size_mb: number;
  loaded: boolean;
  total_nuclei_templates: number;
  nuclei_by_severity: Record<string, number>;
  nuclei_by_protocol: Record<string, number>;
}

// ============================================
// Paginated Response Types
// ============================================

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

// ============================================
// Authentication Types
// ============================================

// User roles from backend
export type UserRole = "admin" | "operator" | "analyst" | "viewer";

// User account status
export type UserStatus = "pending" | "provisioning" | "active" | "suspended" | "deleted";

// VM provisioning status
export type VMProvisionStatus = "pending" | "creating" | "configuring" | "ready" | "failed";

export interface User {
  id: string;
  email: string;
  full_name: string;
  organization?: string;
  role: UserRole;
  status: UserStatus;
  vm_status?: VMProvisionStatus;
  vm_ip?: string;
  created_at: string;
  last_login?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  remember_me?: boolean;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface VMConfiguration {
  plan: string;
  location: string;
  os: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name: string;
  organization?: string;
  vm_config?: VMConfiguration;
}

export interface RegisterResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

// ============================================
// API Configuration Types
// ============================================

export interface ApiConfig {
  baseUrl: string;
  wsUrl: string;
  timeout: number;
  retryAttempts: number;
}

// ============================================
// Connection Status Types
// ============================================

export type ConnectionStatus =
  | "connecting"
  | "connected"
  | "disconnected"
  | "error"
  | "disabled"
  | "polling";
