// RAGLOX v3.0 - Centralized Configuration
// All environment variables and configuration settings
// NO DEMO MODE - Production-ready configuration

// ============================================
// Environment Detection
// ============================================

export const isDevelopment = import.meta.env.DEV || import.meta.env.MODE === 'development';
export const isProduction = import.meta.env.PROD || import.meta.env.MODE === 'production';

// Check if running in sandbox/development environment
export const isSandbox = typeof window !== 'undefined' && (
  window.location.hostname === 'localhost' ||
  window.location.hostname.includes('genspark') ||
  window.location.hostname.includes('sandbox') ||
  window.location.hostname.includes('e2b.dev')
);

// ============================================
// API Configuration
// ============================================

// Backend server IP - configurable via environment variable
const BACKEND_HOST = import.meta.env.VITE_BACKEND_HOST || '172.245.232.188';
const BACKEND_PORT = import.meta.env.VITE_BACKEND_PORT || '8000';

// API Base URL
export const API_BASE_URL = import.meta.env.VITE_API_URL || `http://${BACKEND_HOST}:${BACKEND_PORT}`;

// WebSocket Base URL
export const WS_BASE_URL = import.meta.env.VITE_WS_URL || `ws://${BACKEND_HOST}:${BACKEND_PORT}`;

// API Prefix
export const API_PREFIX = '/api/v1';

// Full API URL
export const API_URL = `${API_BASE_URL}${API_PREFIX}`;

// ============================================
// API Timeouts and Retry Configuration
// ============================================

export const API_TIMEOUT = 30000; // 30 seconds
export const API_RETRY_ATTEMPTS = 3;
export const API_RETRY_DELAY = 1000; // 1 second base delay

// ============================================
// WebSocket Configuration
// ============================================

export const WS_RECONNECT_ATTEMPTS = 5;
export const WS_RECONNECT_DELAY = 2000; // 2 seconds base delay
export const WS_PING_INTERVAL = 30000; // 30 seconds

// ============================================
// Authentication Configuration
// ============================================

export const AUTH_TOKEN_KEY = 'raglox_auth_token';
export const AUTH_USER_KEY = 'raglox_auth_user';
export const AUTH_TOKEN_EXPIRY_KEY = 'raglox_token_expiry';

// Token refresh threshold (refresh when less than this time remaining)
export const TOKEN_REFRESH_THRESHOLD = 5 * 60 * 1000; // 5 minutes

// ============================================
// Feature Flags - NO DEMO MODE
// ============================================

// Enable/disable WebSocket (for testing without backend)
export const WS_ENABLED = import.meta.env.VITE_WS_ENABLED !== 'false';

// ============================================
// Polling Configuration (fallback when WebSocket unavailable)
// ============================================

export const POLLING_INTERVAL = 5000; // 5 seconds
export const POLLING_ENABLED = true;

// ============================================
// UI Configuration
// ============================================

export const MAX_EVENTS_DISPLAY = 100;
export const MAX_CHAT_MESSAGES = 200;
export const MAX_TERMINAL_LINES = 500;

// ============================================
// Helper Functions
// ============================================

/**
 * Get the full API endpoint URL
 */
export function getApiUrl(endpoint: string): string {
  // Remove leading slash if present
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
  return `${API_URL}/${cleanEndpoint}`;
}

/**
 * Get the WebSocket URL for a specific mission
 */
export function getWsUrl(missionId: string): string {
  return `${WS_BASE_URL}/ws/missions/${missionId}`;
}

/**
 * Get the global WebSocket URL
 */
export function getGlobalWsUrl(): string {
  return `${WS_BASE_URL}/ws`;
}

/**
 * Check if WebSocket should be enabled based on protocol
 * Returns false if page is HTTPS but backend doesn't support WSS
 */
export function shouldEnableWebSocket(): boolean {
  if (!WS_ENABLED) return false;

  // In development/sandbox, always try WebSocket
  if (isDevelopment || isSandbox) return true;

  // In production with HTTPS, we need WSS
  if (typeof window !== 'undefined' && window.location.protocol === 'https:') {
    // Check if WS_BASE_URL uses wss://
    return WS_BASE_URL.startsWith('wss://');
  }

  return true;
}

/**
 * Get configuration object for API client
 */
export function getApiConfig() {
  return {
    baseUrl: API_BASE_URL,
    apiUrl: API_URL,
    wsUrl: WS_BASE_URL,
    timeout: API_TIMEOUT,
    retryAttempts: API_RETRY_ATTEMPTS,
    retryDelay: API_RETRY_DELAY,
  };
}

/**
 * Log configuration (for debugging)
 */
export function logConfig(): void {
  console.log('[Config] RAGLOX v3.0 Configuration:');
  console.log(`  - API Base URL: ${API_BASE_URL}`);
  console.log(`  - WebSocket URL: ${WS_BASE_URL}`);
  console.log(`  - Environment: ${isDevelopment ? 'development' : 'production'}`);
  console.log(`  - WebSocket Enabled: ${shouldEnableWebSocket()}`);
}

// Log config in development
if (isDevelopment) {
  logConfig();
}

export default {
  API_BASE_URL,
  WS_BASE_URL,
  API_URL,
  API_TIMEOUT,
  WS_ENABLED,
  getApiUrl,
  getWsUrl,
  shouldEnableWebSocket,
};
