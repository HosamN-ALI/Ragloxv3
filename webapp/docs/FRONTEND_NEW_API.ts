/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * RAGLOX v3.0 - New API Functions for Frontend
 * هذا الملف يحتوي على جميع الـ API Functions الجديدة المطلوبة
 * يجب إضافة هذه الـ Functions إلى client/src/lib/api.ts
 * ═══════════════════════════════════════════════════════════════════════════════
 */

import type {
  // Exploitation Types
  C2Session,
  Exploit,
  PayloadConfig,
  PayloadResult,
  HarvestConfig,
  HarvestResult,
  PortForwardConfig,
  Route,
  ProxyConfig,
  ProxyResult,
  CommandResult,
  ExploitStats,
  ExploitationHealth,
  // Infrastructure Types
  Environment,
  CreateEnvironmentRequest,
  SystemInfo,
  ExecutionResult,
  HealthStatus,
  HealthStatistics,
  InfrastructureStats,
  // Workflow Types
  WorkflowStatus,
  PhaseResult,
  Tool,
  InstallResult,
  WorkflowHealth,
  // Security Types
  ValidationResult,
  ValidationItem,
  BatchValidationResult,
  RateLimitInfo,
  RateLimitStatus,
  SecurityHealth,
  SecurityStats,
  // Report Types
  Report,
  ReportConfig,
} from "@/types";

// ═══════════════════════════════════════════════════════════════
// EXPLOITATION API
// ═══════════════════════════════════════════════════════════════

export const exploitationApi = {
  // ============================================
  // C2 Sessions
  // ============================================
  sessions: {
    /**
     * Get all active C2 sessions
     */
    list: async (): Promise<C2Session[]> => {
      return fetchApi<C2Session[]>("/api/v1/exploitation/c2/sessions");
    },

    /**
     * Get specific session details
     */
    get: async (sessionId: string): Promise<C2Session> => {
      return fetchApi<C2Session>(`/api/v1/exploitation/c2/sessions/${sessionId}`);
    },

    /**
     * Execute command on session
     */
    execute: async (sessionId: string, command: string): Promise<CommandResult> => {
      return fetchApi<CommandResult>(
        `/api/v1/exploitation/c2/sessions/${sessionId}/execute`,
        {
          method: "POST",
          body: JSON.stringify({ command }),
        }
      );
    },

    /**
     * Close/terminate a session
     */
    close: async (sessionId: string): Promise<void> => {
      return fetchApi<void>(`/api/v1/exploitation/c2/sessions/${sessionId}`, {
        method: "DELETE",
      });
    },

    /**
     * Setup SOCKS proxy through session
     */
    proxy: async (sessionId: string, config: ProxyConfig): Promise<ProxyResult> => {
      return fetchApi<ProxyResult>(
        `/api/v1/exploitation/c2/sessions/${sessionId}/proxy`,
        {
          method: "POST",
          body: JSON.stringify(config),
        }
      );
    },
  },

  // ============================================
  // Exploits
  // ============================================
  exploits: {
    /**
     * List all available exploits
     */
    list: async (): Promise<Exploit[]> => {
      return fetchApi<Exploit[]>("/api/v1/exploitation/exploits");
    },

    /**
     * Get exploit details
     */
    get: async (exploitId: string): Promise<Exploit> => {
      return fetchApi<Exploit>(`/api/v1/exploitation/exploits/${exploitId}`);
    },

    /**
     * Search exploits by CVE
     */
    searchByCve: async (cveId: string): Promise<Exploit[]> => {
      return fetchApi<Exploit[]>(`/api/v1/exploitation/exploits/cve/${cveId}`);
    },

    /**
     * Get exploit statistics
     */
    stats: async (): Promise<ExploitStats> => {
      return fetchApi<ExploitStats>("/api/v1/exploitation/exploits/stats");
    },

    /**
     * Execute EternalBlue exploit
     */
    executeEternalBlue: async (
      targetIp: string,
      options?: Record<string, unknown>
    ): Promise<CommandResult> => {
      return fetchApi<CommandResult>("/api/v1/exploitation/exploits/eternalblue/execute", {
        method: "POST",
        body: JSON.stringify({ target_ip: targetIp, ...options }),
      });
    },

    /**
     * Check if target is vulnerable to EternalBlue
     */
    checkEternalBlue: async (targetIp: string): Promise<{ vulnerable: boolean }> => {
      return fetchApi<{ vulnerable: boolean }>(
        "/api/v1/exploitation/exploits/eternalblue/check",
        {
          method: "POST",
          body: JSON.stringify({ target_ip: targetIp }),
        }
      );
    },

    /**
     * Execute Log4Shell exploit
     */
    executeLog4Shell: async (
      targetUrl: string,
      options?: Record<string, unknown>
    ): Promise<CommandResult> => {
      return fetchApi<CommandResult>("/api/v1/exploitation/exploits/log4shell/execute", {
        method: "POST",
        body: JSON.stringify({ target_url: targetUrl, ...options }),
      });
    },

    /**
     * Scan for Log4Shell vulnerability
     */
    scanLog4Shell: async (targetUrl: string): Promise<{ vulnerable: boolean }> => {
      return fetchApi<{ vulnerable: boolean }>(
        "/api/v1/exploitation/exploits/log4shell/scan",
        {
          method: "POST",
          body: JSON.stringify({ target_url: targetUrl }),
        }
      );
    },
  },

  // ============================================
  // Payloads
  // ============================================
  payloads: {
    /**
     * Generate a payload
     */
    generate: async (config: PayloadConfig): Promise<PayloadResult> => {
      return fetchApi<PayloadResult>("/api/v1/exploitation/payloads/generate", {
        method: "POST",
        body: JSON.stringify(config),
      });
    },

    /**
     * Get available payload types
     */
    types: async (): Promise<string[]> => {
      return fetchApi<string[]>("/api/v1/exploitation/payloads/types");
    },
  },

  // ============================================
  // Post-Exploitation
  // ============================================
  postExploit: {
    /**
     * Harvest credentials/data from session
     */
    harvest: async (config: HarvestConfig): Promise<HarvestResult> => {
      return fetchApi<HarvestResult>("/api/v1/exploitation/post-exploitation/harvest", {
        method: "POST",
        body: JSON.stringify(config),
      });
    },
  },

  // ============================================
  // Pivoting
  // ============================================
  pivoting: {
    /**
     * Setup port forwarding
     */
    portForward: async (config: PortForwardConfig): Promise<void> => {
      return fetchApi<void>("/api/v1/exploitation/pivoting/port-forward", {
        method: "POST",
        body: JSON.stringify(config),
      });
    },

    /**
     * Get active routes
     */
    routes: async (): Promise<Route[]> => {
      return fetchApi<Route[]>("/api/v1/exploitation/pivoting/routes");
    },
  },

  // ============================================
  // Metasploit Integration
  // ============================================
  metasploit: {
    /**
     * Get available Metasploit modules
     */
    modules: async (): Promise<string[]> => {
      return fetchApi<string[]>("/api/v1/exploitation/metasploit/modules");
    },

    /**
     * Execute a Metasploit module
     */
    execute: async (
      moduleName: string,
      options: Record<string, unknown>
    ): Promise<CommandResult> => {
      return fetchApi<CommandResult>("/api/v1/exploitation/metasploit/execute", {
        method: "POST",
        body: JSON.stringify({ module: moduleName, options }),
      });
    },

    /**
     * Get Metasploit status
     */
    status: async (): Promise<{ connected: boolean; version?: string }> => {
      return fetchApi<{ connected: boolean; version?: string }>(
        "/api/v1/exploitation/status/metasploit"
      );
    },
  },

  // ============================================
  // Health & Status
  // ============================================
  health: async (): Promise<ExploitationHealth> => {
    return fetchApi<ExploitationHealth>("/api/v1/exploitation/health");
  },

  status: async (): Promise<{ status: string; components: Record<string, string> }> => {
    return fetchApi<{ status: string; components: Record<string, string> }>(
      "/api/v1/exploitation/status/exploitation"
    );
  },

  /**
   * Clear exploitation cache
   */
  clearCache: async (): Promise<void> => {
    return fetchApi<void>("/api/v1/exploitation/cache/clear", {
      method: "DELETE",
    });
  },
};

// ═══════════════════════════════════════════════════════════════
// INFRASTRUCTURE API
// ═══════════════════════════════════════════════════════════════

export const infrastructureApi = {
  // ============================================
  // Environments
  // ============================================
  environments: {
    /**
     * Create a new environment
     */
    create: async (data: CreateEnvironmentRequest): Promise<Environment> => {
      return fetchApi<Environment>("/api/v1/infrastructure/environments", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },

    /**
     * Get environment by ID
     */
    get: async (environmentId: string): Promise<Environment> => {
      return fetchApi<Environment>(
        `/api/v1/infrastructure/environments/${environmentId}`
      );
    },

    /**
     * List environments for a user
     */
    listByUser: async (userId: string): Promise<Environment[]> => {
      return fetchApi<Environment[]>(
        `/api/v1/infrastructure/users/${userId}/environments`
      );
    },

    /**
     * Delete an environment
     */
    delete: async (environmentId: string): Promise<void> => {
      return fetchApi<void>(
        `/api/v1/infrastructure/environments/${environmentId}`,
        { method: "DELETE" }
      );
    },

    /**
     * Reconnect to an environment
     */
    reconnect: async (environmentId: string): Promise<void> => {
      return fetchApi<void>(
        `/api/v1/infrastructure/environments/${environmentId}/reconnect`,
        { method: "POST" }
      );
    },

    /**
     * Execute a command on the environment
     */
    executeCommand: async (
      environmentId: string,
      command: string,
      timeout?: number
    ): Promise<ExecutionResult> => {
      return fetchApi<ExecutionResult>(
        `/api/v1/infrastructure/environments/${environmentId}/execute/command`,
        {
          method: "POST",
          body: JSON.stringify({ command, timeout }),
          timeout: (timeout || 30) * 1000 + 5000, // Add 5s buffer
        }
      );
    },

    /**
     * Execute a script on the environment
     */
    executeScript: async (
      environmentId: string,
      script: string,
      interpreter?: string,
      timeout?: number
    ): Promise<ExecutionResult> => {
      return fetchApi<ExecutionResult>(
        `/api/v1/infrastructure/environments/${environmentId}/execute/script`,
        {
          method: "POST",
          body: JSON.stringify({ script, interpreter, timeout }),
          timeout: (timeout || 60) * 1000 + 5000,
        }
      );
    },

    /**
     * Get system information
     */
    getSystemInfo: async (environmentId: string): Promise<SystemInfo> => {
      const result = await fetchApi<ExecutionResult>(
        `/api/v1/infrastructure/environments/${environmentId}/system-info`
      );
      return JSON.parse(result.output) as SystemInfo;
    },

    /**
     * Get environment health
     */
    getHealth: async (environmentId: string): Promise<HealthStatus> => {
      return fetchApi<HealthStatus>(
        `/api/v1/infrastructure/environments/${environmentId}/health`
      );
    },

    /**
     * Get environment health statistics
     */
    getHealthStats: async (environmentId: string): Promise<HealthStatistics> => {
      return fetchApi<HealthStatistics>(
        `/api/v1/infrastructure/environments/${environmentId}/health/statistics`
      );
    },
  },

  /**
   * Get overall infrastructure statistics
   */
  stats: async (): Promise<InfrastructureStats> => {
    return fetchApi<InfrastructureStats>("/api/v1/infrastructure/statistics");
  },
};

// ═══════════════════════════════════════════════════════════════
// WORKFLOW API
// ═══════════════════════════════════════════════════════════════

export const workflowApi = {
  /**
   * Start a new workflow for a mission
   */
  start: async (missionId: string): Promise<WorkflowStatus> => {
    return fetchApi<WorkflowStatus>("/api/v1/workflow/start", {
      method: "POST",
      body: JSON.stringify({ mission_id: missionId }),
    });
  },

  /**
   * Get workflow status
   */
  status: async (missionId: string): Promise<WorkflowStatus> => {
    return fetchApi<WorkflowStatus>(`/api/v1/workflow/${missionId}/status`);
  },

  /**
   * Get all phase results
   */
  phases: async (missionId: string): Promise<PhaseResult[]> => {
    return fetchApi<PhaseResult[]>(`/api/v1/workflow/${missionId}/phases`);
  },

  /**
   * Pause workflow
   */
  pause: async (missionId: string): Promise<void> => {
    return fetchApi<void>(`/api/v1/workflow/${missionId}/pause`, {
      method: "POST",
    });
  },

  /**
   * Resume workflow
   */
  resume: async (missionId: string): Promise<void> => {
    return fetchApi<void>(`/api/v1/workflow/${missionId}/resume`, {
      method: "POST",
    });
  },

  /**
   * Stop workflow
   */
  stop: async (missionId: string): Promise<void> => {
    return fetchApi<void>(`/api/v1/workflow/${missionId}/stop`, {
      method: "POST",
    });
  },

  // ============================================
  // Tools
  // ============================================
  tools: {
    /**
     * List all available tools
     */
    list: async (): Promise<Tool[]> => {
      return fetchApi<Tool[]>("/api/v1/workflow/tools");
    },

    /**
     * Get tools recommended for a goal
     */
    forGoal: async (goal: string): Promise<Tool[]> => {
      return fetchApi<Tool[]>(`/api/v1/workflow/tools/for-goal/${goal}`);
    },

    /**
     * Get tool details
     */
    get: async (toolName: string): Promise<Tool> => {
      return fetchApi<Tool>(`/api/v1/workflow/tools/${toolName}`);
    },

    /**
     * Install a tool
     */
    install: async (toolName: string): Promise<InstallResult> => {
      return fetchApi<InstallResult>("/api/v1/workflow/tools/install", {
        method: "POST",
        body: JSON.stringify({ tool_name: toolName }),
        timeout: 300000, // 5 minutes for installation
      });
    },
  },

  /**
   * Get workflow health
   */
  health: async (): Promise<WorkflowHealth> => {
    return fetchApi<WorkflowHealth>("/api/v1/workflow/health");
  },
};

// ═══════════════════════════════════════════════════════════════
// SECURITY API
// ═══════════════════════════════════════════════════════════════

export const securityApi = {
  // ============================================
  // Validation (SEC-03)
  // ============================================
  validate: {
    ip: async (ip: string): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/ip", {
        method: "POST",
        body: JSON.stringify({ value: ip }),
      });
    },

    cidr: async (cidr: string): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/cidr", {
        method: "POST",
        body: JSON.stringify({ value: cidr }),
      });
    },

    uuid: async (uuid: string): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/uuid", {
        method: "POST",
        body: JSON.stringify({ value: uuid }),
      });
    },

    hostname: async (hostname: string): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/hostname", {
        method: "POST",
        body: JSON.stringify({ value: hostname }),
      });
    },

    port: async (port: number): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/port", {
        method: "POST",
        body: JSON.stringify({ value: port }),
      });
    },

    cve: async (cve: string): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/cve", {
        method: "POST",
        body: JSON.stringify({ value: cve }),
      });
    },

    safeString: async (text: string): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/safe-string", {
        method: "POST",
        body: JSON.stringify({ value: text }),
      });
    },

    scope: async (scope: string[]): Promise<ValidationResult> => {
      return fetchApi<ValidationResult>("/api/v1/security/validate/scope", {
        method: "POST",
        body: JSON.stringify({ scope }),
      });
    },

    batch: async (items: ValidationItem[]): Promise<BatchValidationResult> => {
      return fetchApi<BatchValidationResult>("/api/v1/security/validate/batch", {
        method: "POST",
        body: JSON.stringify({ items }),
      });
    },
  },

  // ============================================
  // Rate Limiting (SEC-04)
  // ============================================
  rateLimit: {
    info: async (): Promise<RateLimitInfo> => {
      return fetchApi<RateLimitInfo>("/api/v1/security/rate-limit/info");
    },

    status: async (): Promise<RateLimitStatus> => {
      return fetchApi<RateLimitStatus>("/api/v1/security/rate-limit/status");
    },

    reset: async (): Promise<void> => {
      return fetchApi<void>("/api/v1/security/rate-limit/reset", {
        method: "POST",
      });
    },
  },

  /**
   * Get security health status
   */
  health: async (): Promise<SecurityHealth> => {
    return fetchApi<SecurityHealth>("/api/v1/security/health");
  },

  /**
   * Get security statistics
   */
  stats: async (): Promise<SecurityStats> => {
    return fetchApi<SecurityStats>("/api/v1/security/stats");
  },

  /**
   * Add IP to whitelist
   */
  whitelist: async (ip: string): Promise<void> => {
    return fetchApi<void>("/api/v1/security/whitelist", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  },
};

// ═══════════════════════════════════════════════════════════════
// STATS API (Extended)
// ═══════════════════════════════════════════════════════════════

export const statsApi = {
  /**
   * Get system statistics
   */
  system: async (): Promise<Record<string, unknown>> => {
    return fetchApi<Record<string, unknown>>("/api/v1/stats/system");
  },

  /**
   * Get retry policy statistics
   */
  retryPolicies: async (): Promise<Record<string, unknown>> => {
    return fetchApi<Record<string, unknown>>("/api/v1/stats/retry-policies");
  },

  /**
   * Get session statistics
   */
  sessions: async (): Promise<Record<string, unknown>> => {
    return fetchApi<Record<string, unknown>>("/api/v1/stats/sessions");
  },

  /**
   * Get circuit breaker status
   */
  circuitBreakers: async (): Promise<Record<string, unknown>> => {
    return fetchApi<Record<string, unknown>>("/api/v1/stats/circuit-breakers");
  },
};

// ═══════════════════════════════════════════════════════════════
// REPORT API (Future Implementation)
// ═══════════════════════════════════════════════════════════════

export const reportApi = {
  /**
   * Generate a new report
   */
  generate: async (config: ReportConfig): Promise<Report> => {
    return fetchApi<Report>("/api/v1/reports/generate", {
      method: "POST",
      body: JSON.stringify(config),
      timeout: 120000, // 2 minutes for report generation
    });
  },

  /**
   * Get report status
   */
  get: async (reportId: string): Promise<Report> => {
    return fetchApi<Report>(`/api/v1/reports/${reportId}`);
  },

  /**
   * List reports for a mission
   */
  list: async (missionId: string): Promise<Report[]> => {
    return fetchApi<Report[]>(`/api/v1/reports?mission_id=${missionId}`);
  },

  /**
   * Download report
   */
  download: async (reportId: string): Promise<Blob> => {
    const response = await fetch(
      `${API_BASE_URL}/api/v1/reports/${reportId}/download`,
      {
        headers: getAuthHeaders(),
      }
    );
    return response.blob();
  },

  /**
   * Delete report
   */
  delete: async (reportId: string): Promise<void> => {
    return fetchApi<void>(`/api/v1/reports/${reportId}`, {
      method: "DELETE",
    });
  },
};
