// RAGLOX v3.0 - API Service
// Handles all communication with the backend
// Updated for real API integration with authentication support

import type {
  Mission,
  Target,
  Vulnerability,
  Credential,
  Session,
  ApprovalRequest,
  ChatMessage,
  MissionCreateResponse,
  MissionControlResponse,
  ApprovalResponse,
  MissionStatistics,
  KnowledgeStats,
  Technique,
  RXModule,
  Tactic,
  NucleiTemplate,
  PaginatedResponse,
  LoginRequest,
  LoginResponse,
  User,
} from "@/types";

import {
  API_BASE_URL,
  API_URL,
  API_TIMEOUT,
  API_RETRY_ATTEMPTS,
  API_RETRY_DELAY,
  AUTH_TOKEN_KEY,
  getWsUrl,
  shouldEnableWebSocket,
} from "./config";

// ============================================
// Authentication Token Management
// ============================================

let authToken: string | null = null;

/**
 * Set the authentication token
 */
export function setAuthToken(token: string | null): void {
  authToken = token;
  if (token) {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
  } else {
    localStorage.removeItem(AUTH_TOKEN_KEY);
  }
}

/**
 * Get the current authentication token
 */
export function getAuthToken(): string | null {
  if (authToken) return authToken;

  // Try to load from localStorage
  const storedToken = localStorage.getItem(AUTH_TOKEN_KEY);
  if (storedToken) {
    authToken = storedToken;
  }
  return authToken;
}

/**
 * Get authentication headers
 */
export function getAuthHeaders(): Record<string, string> {
  const token = getAuthToken();
  if (token) {
    return { Authorization: `Bearer ${token}` };
  }
  return {};
}

/**
 * Clear authentication
 */
export function clearAuth(): void {
  authToken = null;
  localStorage.removeItem(AUTH_TOKEN_KEY);
}

// ============================================
// API Error Class
// ============================================

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public endpoint: string,
    public details?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function logApiError(
  endpoint: string,
  error: unknown,
  metadata: Record<string, unknown> = {}
): void {
  console.error("[API Error]", {
    endpoint,
    timestamp: new Date().toISOString(),
    message: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
    ...metadata,
  });
}

// ============================================
// Helper Functions
// ============================================

async function fetchApi<T>(
  endpoint: string,
  options: (RequestInit & { timeout?: number }) = {}
): Promise<T> {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;

  const { timeout, headers, ...restOptions } = options as RequestInit & {
    timeout?: number;
    headers?: HeadersInit;
  };
  const requestTimeout = timeout ?? API_TIMEOUT;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), requestTimeout);

  try {
    const mergedHeaders = new Headers({
      "Content-Type": "application/json",
      ...getAuthHeaders(),
    });

    if (headers) {
      if (headers instanceof Headers) {
        headers.forEach((value, key) => mergedHeaders.set(key, value));
      } else if (Array.isArray(headers)) {
        headers.forEach(([key, value]) => mergedHeaders.set(key, value));
      } else {
        Object.entries(headers).forEach(([key, value]) => mergedHeaders.set(key, value as string));
      }
    }

    const response = await fetch(url, {
      ...restOptions,
      signal: controller.signal,
      headers: mergedHeaders,
    });

    // Handle non-JSON responses
    const contentType = response.headers.get("content-type");

    if (!response.ok) {
      let errorMessage = `HTTP ${response.status}`;
      let errorDetails: unknown = null;

      // Handle 401 Unauthorized - clear auth and redirect
      if (response.status === 401) {
        clearAuth();
        // Optionally trigger a redirect to login
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('auth:unauthorized'));
        }
      }

      if (contentType?.includes("application/json")) {
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.detail || errorMessage;
          errorDetails = errorData;
        } catch {
          // Ignore JSON parse errors
        }
      }

      logApiError(endpoint, errorMessage, {
        status: response.status,
        details: errorDetails,
        context: "response",
      });

      throw new ApiError(errorMessage, response.status, endpoint, errorDetails);
    }

    // Handle empty responses
    if (response.status === 204 || !contentType?.includes("application/json")) {
      return {} as T;
    }

    return response.json();
  } catch (error) {
    if (!(error instanceof ApiError)) {
      logApiError(endpoint, error, {
        context: "request",
        timeout: requestTimeout,
      });
    }

    if (error instanceof ApiError) {
      throw error;
    }

    // Handle abort (timeout)
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError(
        "Request timeout - server took too long to respond",
        408,
        endpoint,
        { originalError: 'AbortError' }
      );
    }

    // Network errors
    if (error instanceof TypeError && error.message.includes("fetch")) {
      throw new ApiError(
        "Network error - Unable to connect to server",
        0,
        endpoint,
        { originalError: error.message }
      );
    }

    throw new ApiError(
      error instanceof Error ? error.message : "Unknown error",
      0,
      endpoint
    );
  } finally {
    clearTimeout(timeoutId);
  }
}

// Retry wrapper for transient failures
async function fetchWithRetry<T>(
  endpoint: string,
  options: (RequestInit & { timeout?: number }) = {},
  maxRetries = API_RETRY_ATTEMPTS,
  retryDelay = API_RETRY_DELAY
): Promise<T> {
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fetchApi<T>(endpoint, options);
    } catch (error) {
      lastError = error as Error;

      // Don't retry on client errors (4xx) except 408 (timeout) and 429 (rate limit)
      if (error instanceof ApiError) {
        if (error.status >= 400 && error.status < 500 && error.status !== 408 && error.status !== 429) {
          throw error;
        }
      }

      // Wait before retrying with exponential backoff
      if (attempt < maxRetries) {
        const delay = retryDelay * Math.pow(2, attempt - 1);
        await new Promise((resolve) => setTimeout(resolve, delay));
        console.log(`[API] Retry attempt ${attempt}/${maxRetries} for ${endpoint}`);
      }
    }
  }

  throw lastError;
}

// ============================================
// Authentication API
// ============================================

// Registration request type
export interface RegisterRequest {
  email: string;
  password: string;
  full_name: string;
  organization?: string;
  vm_config?: {
    plan_id: string;
    location_id: string;
    os_id: string;
  };
}

export const authApi = {
  // Login
  login: async (credentials: { email: string; password: string }): Promise<LoginResponse> => {
    const response = await fetchApi<LoginResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });

    // Store the token
    if (response.access_token) {
      setAuthToken(response.access_token);
    }

    return response;
  },

  // Register new user with VM provisioning
  register: async (data: RegisterRequest): Promise<LoginResponse> => {
    const response = await fetchApi<LoginResponse>("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(data),
    });

    // Store the token
    if (response.access_token) {
      setAuthToken(response.access_token);
    }

    return response;
  },

  // Logout
  logout: async (): Promise<void> => {
    try {
      await fetchApi<void>("/api/v1/auth/logout", {
        method: "POST",
      });
    } finally {
      clearAuth();
    }
  },

  // Refresh token
  refresh: async (): Promise<{ access_token: string }> => {
    const response = await fetchApi<{ access_token: string }>("/api/v1/auth/refresh", {
      method: "POST",
    });

    if (response.access_token) {
      setAuthToken(response.access_token);
    }

    return response;
  },

  // Get current user
  me: async (): Promise<User> => {
    return fetchApi<User>("/api/v1/auth/me");
  },

  // Check if authenticated
  check: async (): Promise<boolean> => {
    try {
      await fetchApi<User>("/api/v1/auth/me");
      return true;
    } catch {
      return false;
    }
  },

  // Get VM status
  vmStatus: async (): Promise<{ vm_status: string; vm_ip: string | null; message: string }> => {
    return fetchApi<{ vm_status: string; vm_ip: string | null; message: string }>("/api/v1/auth/vm/status");
  },

  // Reprovision VM
  vmReprovision: async (config?: { location_id?: string; os_id?: string }): Promise<{ status: string; message: string }> => {
    return fetchApi<{ status: string; message: string }>("/api/v1/auth/vm/reprovision", {
      method: "POST",
      body: JSON.stringify(config || {}),
    });
  },

  // Change password
  changePassword: async (currentPassword: string, newPassword: string): Promise<{ message: string }> => {
    return fetchApi<{ message: string }>("/api/v1/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  },

  // Update profile
  updateProfile: async (data: { full_name?: string; organization?: string }): Promise<User> => {
    return fetchApi<User>("/api/v1/auth/me", {
      method: "PUT",
      body: JSON.stringify(data),
    });
  },
};

// ============================================
// Mission API
// ============================================

export const missionApi = {
  // Get all missions
  list: async (): Promise<string[]> => {
    return fetchApi<string[]>("/api/v1/missions");
  },

  // Get mission details
  get: async (missionId: string): Promise<Mission> => {
    try {
      return await fetchApi<Mission>(`/api/v1/missions/${missionId}`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Create new mission
  create: async (data: {
    name: string;
    description?: string;
    scope: string[];
    goals: string[];
    constraints?: Record<string, unknown>;
  }): Promise<MissionCreateResponse> => {
    return fetchApi<MissionCreateResponse>("/api/v1/missions", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  // Start mission
  start: async (missionId: string): Promise<MissionControlResponse> => {
    try {
      return await fetchApi<MissionControlResponse>(`/api/v1/missions/${missionId}/start`, {
        method: "POST",
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Pause mission
  pause: async (missionId: string): Promise<MissionControlResponse> => {
    try {
      return await fetchApi<MissionControlResponse>(`/api/v1/missions/${missionId}/pause`, {
        method: "POST",
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Resume mission
  resume: async (missionId: string): Promise<MissionControlResponse> => {
    try {
      return await fetchApi<MissionControlResponse>(`/api/v1/missions/${missionId}/resume`, {
        method: "POST",
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Stop mission
  stop: async (missionId: string): Promise<MissionControlResponse> => {
    try {
      return await fetchApi<MissionControlResponse>(`/api/v1/missions/${missionId}/stop`, {
        method: "POST",
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Get mission statistics
  stats: async (missionId: string): Promise<MissionStatistics> => {
    try {
      return await fetchApi<MissionStatistics>(`/api/v1/missions/${missionId}/stats`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },
};

// ============================================
// Target API
// ============================================

export const targetApi = {
  // Get all targets for a mission
  list: async (missionId: string): Promise<Target[]> => {
    try {
      return await fetchApi<Target[]>(`/api/v1/missions/${missionId}/targets`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Get specific target
  get: async (missionId: string, targetId: string): Promise<Target> => {
    try {
      return await fetchApi<Target>(`/api/v1/missions/${missionId}/targets/${targetId}`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Target or Mission not found");
      }
      throw error;
    }
  },
};

// ============================================
// Vulnerability API
// ============================================

export const vulnApi = {
  // Get all vulnerabilities for a mission
  list: async (missionId: string): Promise<Vulnerability[]> => {
    try {
      return await fetchApi<Vulnerability[]>(`/api/v1/missions/${missionId}/vulnerabilities`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },
};

// ============================================
// Credential API
// ============================================

export const credApi = {
  // Get all credentials for a mission
  list: async (missionId: string): Promise<Credential[]> => {
    try {
      return await fetchApi<Credential[]>(`/api/v1/missions/${missionId}/credentials`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },
};

// ============================================
// Session API
// ============================================

export const sessionApi = {
  // Get all sessions for a mission
  list: async (missionId: string): Promise<Session[]> => {
    try {
      return await fetchApi<Session[]>(`/api/v1/missions/${missionId}/sessions`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },
};

// ============================================
// HITL (Human-in-the-Loop) API
// ============================================

export const hitlApi = {
  // Get pending approvals
  list: async (missionId: string): Promise<ApprovalRequest[]> => {
    try {
      return await fetchApi<ApprovalRequest[]>(`/api/v1/missions/${missionId}/approvals`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Approve action
  approve: async (
    missionId: string,
    actionId: string,
    comment?: string
  ): Promise<ApprovalResponse> => {
    try {
      return await fetchApi<ApprovalResponse>(
        `/api/v1/missions/${missionId}/approve/${actionId}`,
        {
          method: "POST",
          body: JSON.stringify({ user_comment: comment }),
        }
      );
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Action or Mission not found");
      }
      throw error;
    }
  },

  // Reject action
  reject: async (
    missionId: string,
    actionId: string,
    reason: string,
    comment?: string
  ): Promise<ApprovalResponse> => {
    try {
      return await fetchApi<ApprovalResponse>(
        `/api/v1/missions/${missionId}/reject/${actionId}`,
        {
          method: "POST",
          body: JSON.stringify({
            rejection_reason: reason,
            user_comment: comment,
          }),
        }
      );
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Action or Mission not found");
      }
      throw error;
    }
  },
};

// ============================================
// Chat API
// ============================================

export const chatApi = {
  // Get chat history
  list: async (missionId: string, limit = 50): Promise<ChatMessage[]> => {
    try {
      return await fetchApi<ChatMessage[]>(
        `/api/v1/missions/${missionId}/chat?limit=${limit}`
      );
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format or limit");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },

  // Send message
  send: async (
    missionId: string,
    content: string,
    relatedTaskId?: string,
    relatedActionId?: string
  ): Promise<ChatMessage> => {
    try {
      return await fetchApi<ChatMessage>(`/api/v1/missions/${missionId}/chat`, {
        method: "POST",
        timeout: 120000,
        body: JSON.stringify({
          content,
          related_task_id: relatedTaskId,
          related_action_id: relatedActionId,
        }),
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 422) {
        throw new Error("Invalid mission ID format");
      }
      if (error instanceof ApiError && error.status === 404) {
        throw new Error("Mission not found");
      }
      throw error;
    }
  },
};

// ============================================
// WebSocket Connection
// ============================================

export class MissionWebSocket {
  private ws: WebSocket | null = null;
  private missionId: string;
  private onMessage: (message: unknown) => void;
  private onError: (error: Event) => void;
  private onClose: () => void;
  private onOpen: () => void;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private isManualClose = false;

  constructor(
    missionId: string,
    onMessage: (message: unknown) => void,
    onError: (error: Event) => void = () => { },
    onClose: () => void = () => { },
    onOpen: () => void = () => { }
  ) {
    this.missionId = missionId;
    this.onMessage = onMessage;
    this.onError = onError;
    this.onClose = onClose;
    this.onOpen = onOpen;
  }

  connect(): void {
    // Check if WebSocket should be enabled
    if (!shouldEnableWebSocket()) {
      console.log('[WebSocket] WebSocket disabled - using polling mode');
      return;
    }

    const url = getWsUrl(this.missionId);
    console.log('[WebSocket] Connecting to:', url);

    try {
      this.ws = new WebSocket(url);
      this.isManualClose = false;

      this.ws.onopen = () => {
        console.log(`[WebSocket] Connected to mission ${this.missionId}`);
        this.reconnectAttempts = 0;
        this.onOpen();
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.onMessage(message);
        } catch (e) {
          console.error("[WebSocket] Failed to parse message:", e);
        }
      };

      this.ws.onerror = (error) => {
        console.error("[WebSocket] Error:", error);
        this.onError(error);
      };

      this.ws.onclose = (event) => {
        console.log("[WebSocket] Connection closed", event.code, event.reason);
        this.onClose();

        // Only attempt reconnect if not manually closed
        if (!this.isManualClose) {
          this.attemptReconnect();
        }
      };
    } catch (error) {
      console.error("[WebSocket] Failed to connect:", error);
      this.attemptReconnect();
    }
  }

  private attemptReconnect(): void {
    if (!shouldEnableWebSocket()) return;

    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
      console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      setTimeout(() => this.connect(), delay);
    } else {
      console.log('[WebSocket] Max reconnect attempts reached');
    }
  }

  disconnect(): void {
    this.isManualClose = true;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  send(data: unknown): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  get isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  get readyState(): number {
    return this.ws?.readyState ?? WebSocket.CLOSED;
  }
}

// ============================================
// Health Check
// ============================================

export const healthApi = {
  check: async (): Promise<{ status: string; components: Record<string, string> }> => {
    return fetchApi<{ status: string; components: Record<string, string> }>("/health");
  },

  // Quick connectivity check
  ping: async (): Promise<boolean> => {
    try {
      await fetch(`${API_BASE_URL}/health`, { method: 'HEAD' });
      return true;
    } catch {
      return false;
    }
  },
};

// ============================================
// Terminal Output API (for real-time output)
// ============================================

export interface CommandExecutionResult {
  id: string;
  command: string;
  output: string[];
  exit_code: number;
  status: string;
  duration_ms: number;
  timestamp: string;
}

// Suggestion types for terminal/chat
export interface SuggestedActionData {
  id: string;
  type: 'scan' | 'exploit' | 'credential' | 'lateral' | 'recon' | 'report' | 'custom';
  title: string;
  description?: string;
  command?: string;
  priority: 'high' | 'medium' | 'low';
  reason?: string;
  target_info?: Record<string, unknown>;
}

export interface SuggestionsResponse {
  mission_id: string;
  suggestions: SuggestedActionData[];
  generated_at: string;
}

export const terminalApi = {
  // Get terminal output history for a mission
  getOutput: async (missionId: string, limit = 100): Promise<string[]> => {
    try {
      const results = await fetchApi<{ output: string[] }>(
        `/api/v1/missions/${missionId}/terminal/output?limit=${limit}`
      );
      return results.output || [];
    } catch {
      // Terminal endpoint might not exist - return empty
      return [];
    }
  },

  // Execute a command on the mission's environment
  execute: async (missionId: string, command: string, timeout = 30): Promise<CommandExecutionResult> => {
    return fetchApi<CommandExecutionResult>(
      `/api/v1/missions/${missionId}/execute`,
      {
        method: "POST",
        timeout: timeout * 1000 + 5000, // Add 5s buffer
        body: JSON.stringify({ command, timeout }),
      }
    );
  },

  // Get command history
  getHistory: async (missionId: string, page = 1, pageSize = 50): Promise<{
    commands: CommandExecutionResult[];
    total: number;
    page: number;
    page_size: number;
  }> => {
    try {
      return await fetchApi(`/api/v1/missions/${missionId}/commands?page=${page}&page_size=${pageSize}`);
    } catch {
      return { commands: [], total: 0, page: 1, page_size: pageSize };
    }
  },

  // Get AI-generated suggestions for next actions
  getSuggestions: async (missionId: string, limit = 5): Promise<SuggestionsResponse> => {
    try {
      return await fetchApi<SuggestionsResponse>(
        `/api/v1/missions/${missionId}/suggestions?limit=${limit}`
      );
    } catch {
      return {
        mission_id: missionId,
        suggestions: [],
        generated_at: new Date().toISOString(),
      };
    }
  },
};

// ============================================
// Knowledge API - Complete Integration
// ============================================

// Helper to build query string
const buildQueryString = (params: Record<string, string | number | boolean | undefined>): string => {
  const filtered = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`);
  return filtered.length > 0 ? `?${filtered.join('&')}` : '';
};

export const knowledgeApi = {
  // ============================================
  // Statistics
  // ============================================
  stats: async (): Promise<KnowledgeStats> => {
    return fetchApi<KnowledgeStats>("/api/v1/knowledge/stats");
  },

  // ============================================
  // Techniques
  // ============================================
  techniques: {
    list: async (params?: {
      platform?: string;
      limit?: number;
      offset?: number;
    }): Promise<PaginatedResponse<Technique>> => {
      const query = buildQueryString(params || {});
      return fetchApi<PaginatedResponse<Technique>>(`/api/v1/knowledge/techniques${query}`);
    },

    get: async (techniqueId: string): Promise<Technique> => {
      return fetchApi<Technique>(`/api/v1/knowledge/techniques/${techniqueId}`);
    },

    getModules: async (techniqueId: string, platform?: string): Promise<RXModule[]> => {
      const query = platform ? `?platform=${encodeURIComponent(platform)}` : '';
      return fetchApi<RXModule[]>(`/api/v1/knowledge/techniques/${techniqueId}/modules${query}`);
    },
  },

  // ============================================
  // Modules (RX Modules)
  // ============================================
  modules: {
    list: async (params?: {
      technique_id?: string;
      platform?: string;
      executor_type?: string;
      limit?: number;
      offset?: number;
    }): Promise<PaginatedResponse<RXModule>> => {
      const query = buildQueryString(params || {});
      return fetchApi<PaginatedResponse<RXModule>>(`/api/v1/knowledge/modules${query}`);
    },

    get: async (moduleId: string): Promise<RXModule> => {
      return fetchApi<RXModule>(`/api/v1/knowledge/modules/${moduleId}`);
    },

    search: async (q: string, params?: {
      platform?: string;
      tactic?: string;
      limit?: number;
    }): Promise<RXModule[]> => {
      const query = buildQueryString({ q, ...params });
      return fetchApi<RXModule[]>(`/api/v1/knowledge/search${query}`);
    },
  },

  // ============================================
  // Tactics
  // ============================================
  tactics: {
    list: async (): Promise<Tactic[]> => {
      return fetchApi<Tactic[]>("/api/v1/knowledge/tactics");
    },

    getTechniques: async (tacticId: string): Promise<Technique[]> => {
      return fetchApi<Technique[]>(`/api/v1/knowledge/tactics/${tacticId}/techniques`);
    },
  },

  // ============================================
  // Platforms
  // ============================================
  platforms: {
    list: async (): Promise<string[]> => {
      return fetchApi<string[]>("/api/v1/knowledge/platforms");
    },

    getModules: async (platform: string, limit?: number): Promise<RXModule[]> => {
      const query = limit ? `?limit=${limit}` : '';
      return fetchApi<RXModule[]>(`/api/v1/knowledge/platforms/${encodeURIComponent(platform)}/modules${query}`);
    },
  },

  // ============================================
  // Specialized Queries (for Specialists)
  // ============================================
  specialized: {
    bestModule: async (params: {
      tactic?: string;
      technique?: string;
      platform?: string;
      executor_type?: string;
      require_elevation?: boolean;
    }): Promise<RXModule | null> => {
      return fetchApi<RXModule | null>("/api/v1/knowledge/best-module", {
        method: "POST",
        body: JSON.stringify(params),
      });
    },

    exploitModules: async (vuln_type?: string, platform?: string, limit?: number): Promise<RXModule[]> => {
      const query = buildQueryString({ vuln_type, platform, limit });
      return fetchApi<RXModule[]>(`/api/v1/knowledge/exploit-modules${query}`);
    },

    reconModules: async (platform?: string, limit?: number): Promise<RXModule[]> => {
      const query = buildQueryString({ platform, limit });
      return fetchApi<RXModule[]>(`/api/v1/knowledge/recon-modules${query}`);
    },

    credentialModules: async (platform?: string, limit?: number): Promise<RXModule[]> => {
      const query = buildQueryString({ platform, limit });
      return fetchApi<RXModule[]>(`/api/v1/knowledge/credential-modules${query}`);
    },

    privescModules: async (platform?: string, limit?: number): Promise<RXModule[]> => {
      const query = buildQueryString({ platform, limit });
      return fetchApi<RXModule[]>(`/api/v1/knowledge/privesc-modules${query}`);
    },
  },

  // ============================================
  // Nuclei Templates
  // ============================================
  nuclei: {
    list: async (params?: {
      severity?: string;
      protocol?: string;
      tag?: string;
      limit?: number;
      offset?: number;
    }): Promise<PaginatedResponse<NucleiTemplate>> => {
      const query = buildQueryString(params || {});
      return fetchApi<PaginatedResponse<NucleiTemplate>>(`/api/v1/knowledge/nuclei/templates${query}`);
    },

    get: async (templateId: string): Promise<NucleiTemplate> => {
      return fetchApi<NucleiTemplate>(`/api/v1/knowledge/nuclei/templates/${encodeURIComponent(templateId)}`);
    },

    search: async (q: string, params?: {
      severity?: string;
      protocol?: string;
      limit?: number;
    }): Promise<NucleiTemplate[]> => {
      const query = buildQueryString({ q, ...params });
      return fetchApi<NucleiTemplate[]>(`/api/v1/knowledge/nuclei/search${query}`);
    },

    getByCve: async (cveId: string): Promise<NucleiTemplate> => {
      return fetchApi<NucleiTemplate>(`/api/v1/knowledge/nuclei/cve/${encodeURIComponent(cveId)}`);
    },

    getBySeverity: async (severity: string, limit?: number): Promise<NucleiTemplate[]> => {
      const query = limit ? `?limit=${limit}` : '';
      return fetchApi<NucleiTemplate[]>(`/api/v1/knowledge/nuclei/severity/${severity}${query}`);
    },

    critical: async (limit?: number): Promise<NucleiTemplate[]> => {
      const query = limit ? `?limit=${limit}` : '';
      return fetchApi<NucleiTemplate[]>(`/api/v1/knowledge/nuclei/critical${query}`);
    },

    rce: async (limit?: number): Promise<NucleiTemplate[]> => {
      const query = limit ? `?limit=${limit}` : '';
      return fetchApi<NucleiTemplate[]>(`/api/v1/knowledge/nuclei/rce${query}`);
    },

    sqli: async (limit?: number): Promise<NucleiTemplate[]> => {
      const query = limit ? `?limit=${limit}` : '';
      return fetchApi<NucleiTemplate[]>(`/api/v1/knowledge/nuclei/sqli${query}`);
    },

    xss: async (limit?: number): Promise<NucleiTemplate[]> => {
      const query = limit ? `?limit=${limit}` : '';
      return fetchApi<NucleiTemplate[]>(`/api/v1/knowledge/nuclei/xss${query}`);
    },
  },

  // ============================================
  // Legacy Search (backwards compatibility)
  // ============================================
  searchModules: async (query: string): Promise<RXModule[]> => {
    return fetchApi<RXModule[]>(`/api/v1/knowledge/search?q=${encodeURIComponent(query)}`);
  },
};

// Export base URLs for reference
export { API_BASE_URL, API_URL, fetchWithRetry };
