# Implementation Plan - RAGLOX v3.0 Frontend-Backend Integration

## Overview
Complete integration of the RAGLOX v3.0 React/TypeScript frontend with the FastAPI backend, enabling real-time WebSocket communication, removing mock data fallbacks, and implementing authentication.

This implementation connects the existing beautiful Manus-style UI to the production-ready backend API. The frontend currently has well-structured components but uses hardcoded data and disabled WebSocket connections. The backend provides 40+ REST endpoints and 15+ WebSocket event types that need to be properly consumed by the frontend.

### Current State Analysis
- **Backend**: Production-ready with complete REST API (`/api/v1/*`) and WebSocket (`/ws/missions/{mission_id}`)
- **Frontend**: Beautiful UI with Zustand state management, but WebSocket disabled and some mock fallbacks
- **Gap**: Need to enable WebSocket, add authentication, and ensure all API calls work end-to-end

### Server Configuration
- **API Base URL**: `http://172.245.232.188:8000`
- **WebSocket URL**: `ws://172.245.232.188:8000`
- **API Prefix**: `/api/v1`
- **WebSocket Endpoint**: `/ws/missions/{mission_id}`

---

## [Types]
Add authentication types and enhance existing types for better type safety.

### New Types to Add (`types/index.ts`)

```typescript
// Authentication Types
export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  created_at: string;
  last_login?: string;
}

export enum UserRole {
  ADMIN = "admin",
  OPERATOR = "operator",
  VIEWER = "viewer"
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
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

// API Configuration Types
export interface ApiConfig {
  baseUrl: string;
  wsUrl: string;
  timeout: number;
  retryAttempts: number;
}
```

---

## [Files]
Detailed breakdown of all file modifications.

### New Files to Create

1. **`webapp/frontend/client/src/lib/config.ts`**
   - Centralized configuration for API URLs and environment variables
   - Export `API_BASE_URL`, `WS_BASE_URL`, `API_TIMEOUT`

2. **`webapp/frontend/client/src/stores/authStore.ts`**
   - Zustand store for authentication state
   - Login, logout, token refresh functionality

3. **`webapp/frontend/client/src/pages/Login.tsx`**
   - Login page component with form validation
   - Redirect to Operations after successful login

4. **`webapp/frontend/client/src/components/ProtectedRoute.tsx`**
   - HOC for protecting routes that require authentication

5. **`webapp/frontend/client/src/lib/websocket.ts`**
   - Dedicated WebSocket client class with reconnection logic
   - Event type handling and message parsing

### Existing Files to Modify

1. **`webapp/frontend/client/src/lib/api.ts`**
   - Add authentication headers to all requests
   - Remove hardcoded IP, use config
   - Add token refresh interceptor
   - Improve error handling

2. **`webapp/frontend/client/src/hooks/useWebSocket.ts`**
   - Enable WebSocket by default (remove disabled logic)
   - Use centralized config for URLs
   - Add authentication token to WebSocket connection

3. **`webapp/frontend/client/src/stores/missionStore.ts`**
   - Add mission control actions (start, pause, resume, stop)
   - Improve WebSocket event handling
   - Add statistics state

4. **`webapp/frontend/client/src/pages/Home.tsx`**
   - Connect "New Mission" button to create mission API
   - Add mission creation dialog

5. **`webapp/frontend/client/src/pages/Operations.tsx`**
   - Add mission control buttons (start/stop/pause/resume)
   - Connect to real mission data
   - Show real statistics

6. **`webapp/frontend/client/src/components/manus/AIChatPanel.tsx`**
   - Remove demo data fallback
   - Ensure events come from WebSocket only

7. **`webapp/frontend/client/src/components/manus/ApprovalCard.tsx`**
   - Ensure approve/reject calls work with real API

8. **`webapp/frontend/client/src/App.tsx`**
   - Add Login route
   - Wrap routes with ProtectedRoute
   - Add AuthProvider

9. **`webapp/frontend/client/src/types/index.ts`**
   - Add authentication types
   - Add API config types

---

## [Functions]
Detailed breakdown of function modifications.

### New Functions

#### `webapp/frontend/client/src/lib/config.ts`
```typescript
export function getApiConfig(): ApiConfig
export function getWsUrl(missionId: string): string
export function isProduction(): boolean
```

#### `webapp/frontend/client/src/stores/authStore.ts`
```typescript
interface AuthStore {
  // State
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  login: (credentials: LoginRequest) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<void>;
  checkAuth: () => Promise<boolean>;
  clearError: () => void;
}
```

#### `webapp/frontend/client/src/lib/api.ts`
```typescript
// New functions
export function setAuthToken(token: string | null): void
export function getAuthHeaders(): Record<string, string>
export async function refreshAuthToken(): Promise<string>

// Auth API
export const authApi = {
  login: (credentials: LoginRequest) => Promise<LoginResponse>,
  logout: () => Promise<void>,
  refresh: () => Promise<{ access_token: string }>,
  me: () => Promise<User>,
}
```

#### `webapp/frontend/client/src/lib/websocket.ts`
```typescript
export class WebSocketClient {
  constructor(missionId: string, options: WebSocketOptions)
  connect(): void
  disconnect(): void
  send(data: unknown): void
  onMessage(handler: (message: WebSocketMessage) => void): void
  onConnect(handler: () => void): void
  onDisconnect(handler: () => void): void
  onError(handler: (error: Event) => void): void
  get isConnected(): boolean
  get status(): ConnectionStatus
}
```

### Modified Functions

#### `webapp/frontend/client/src/lib/api.ts`
- `fetchApi<T>()` - Add auth headers, use config URL
- `MissionWebSocket` class - Use config URL, add auth token

#### `webapp/frontend/client/src/stores/missionStore.ts`
- `connectWebSocket()` - Use new WebSocketClient class
- `handleWebSocketMessage()` - Add more event type handlers
- Add new actions: `startMission()`, `pauseMission()`, `resumeMission()`, `stopMission()`

#### `webapp/frontend/client/src/hooks/useWebSocket.ts`
- `getWsBaseUrl()` - Use config instead of hardcoded URL
- `connect()` - Remove disabled check, always try to connect
- `handleMessage()` - Improve event type handling

---

## [Classes]
Class modifications and new classes.

### New Classes

#### `WebSocketClient` (`lib/websocket.ts`)
```typescript
export class WebSocketClient {
  private ws: WebSocket | null = null;
  private missionId: string;
  private options: WebSocketOptions;
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectDelay: number = 1000;
  private messageHandlers: Set<(message: WebSocketMessage) => void>;
  private connectHandlers: Set<() => void>;
  private disconnectHandlers: Set<() => void>;
  private errorHandlers: Set<(error: Event) => void>;
  
  constructor(missionId: string, options?: Partial<WebSocketOptions>);
  connect(): void;
  disconnect(): void;
  send(data: unknown): void;
  onMessage(handler: (message: WebSocketMessage) => void): () => void;
  onConnect(handler: () => void): () => void;
  onDisconnect(handler: () => void): () => void;
  onError(handler: (error: Event) => void): () => void;
  private attemptReconnect(): void;
  private handleOpen(): void;
  private handleClose(): void;
  private handleError(error: Event): void;
  private handleMessage(event: MessageEvent): void;
  get isConnected(): boolean;
  get status(): ConnectionStatus;
}
```

### Modified Classes

#### `MissionWebSocket` (`lib/api.ts`)
- Add authentication token to connection URL
- Use centralized config for base URL
- Improve reconnection logic with exponential backoff

---

## [Dependencies]
No new dependencies required. The existing dependencies are sufficient:
- `zustand` - State management (already installed)
- `axios` - HTTP client (already installed, but using fetch)
- `sonner` - Toast notifications (already installed)

---

## [Testing]
Testing approach for the integration.

### Manual Testing Steps

1. **Authentication Flow**
   - Login with valid credentials
   - Verify token is stored
   - Verify protected routes redirect to login
   - Verify logout clears token

2. **Mission Creation**
   - Create new mission from Home page
   - Verify mission appears in list
   - Verify redirect to Operations page

3. **Mission Controls**
   - Start a mission
   - Pause a running mission
   - Resume a paused mission
   - Stop a mission

4. **WebSocket Connection**
   - Verify connection status indicator
   - Verify real-time events appear
   - Verify reconnection after disconnect

5. **HITL Approval**
   - Trigger an approval request
   - Approve an action
   - Reject an action
   - Verify mission continues after approval

6. **Chat Interface**
   - Send a message
   - Verify response appears
   - Verify messages persist

### Test Commands
```bash
# Start backend
cd /root/RAGLOX_V3/webapp && python -m src.api.main

# Start frontend
cd /root/RAGLOX_V3/webapp/frontend && pnpm dev

# Test API connectivity
curl http://172.245.232.188:8000/health
curl http://172.245.232.188:8000/api/v1/missions
```

---

## [Implementation Order]
Numbered steps showing the logical order of changes.

### Phase 1: Core Infrastructure (Day 1-2)

1. **Create `lib/config.ts`** - Centralized configuration
2. **Update `lib/api.ts`** - Use config, add auth headers
3. **Create `lib/websocket.ts`** - New WebSocket client class
4. **Update `hooks/useWebSocket.ts`** - Use new WebSocket client

### Phase 2: Authentication (Day 3)

5. **Update `types/index.ts`** - Add auth types
6. **Create `stores/authStore.ts`** - Auth state management
7. **Create `pages/Login.tsx`** - Login page
8. **Create `components/ProtectedRoute.tsx`** - Route protection
9. **Update `App.tsx`** - Add auth routes and protection

### Phase 3: Mission Integration (Day 4-5)

10. **Update `stores/missionStore.ts`** - Add mission control actions
11. **Update `pages/Home.tsx`** - Mission creation dialog
12. **Update `pages/Operations.tsx`** - Mission controls UI
13. **Update `components/manus/AIChatPanel.tsx`** - Remove demo data

### Phase 4: Polish & Testing (Day 6-7)

14. **Update `components/manus/ApprovalCard.tsx`** - Verify HITL flow
15. **Test all flows end-to-end**
16. **Fix any issues found during testing**
17. **Update documentation**

---

## Task Progress Items

- [ ] Step 1: Create `lib/config.ts` with centralized configuration
- [ ] Step 2: Update `lib/api.ts` to use config and add auth support
- [ ] Step 3: Create `lib/websocket.ts` with WebSocket client class
- [ ] Step 4: Update `hooks/useWebSocket.ts` to use new WebSocket client
- [ ] Step 5: Update `types/index.ts` with authentication types
- [ ] Step 6: Create `stores/authStore.ts` for auth state management
- [ ] Step 7: Create `pages/Login.tsx` login page
- [ ] Step 8: Create `components/ProtectedRoute.tsx` for route protection
- [ ] Step 9: Update `App.tsx` with auth routes and protection
- [ ] Step 10: Update `stores/missionStore.ts` with mission control actions
- [ ] Step 11: Update `pages/Home.tsx` with mission creation dialog
- [ ] Step 12: Update `pages/Operations.tsx` with mission controls
- [ ] Step 13: Update `components/manus/AIChatPanel.tsx` to remove demo data
- [ ] Step 14: Verify `components/manus/ApprovalCard.tsx` HITL flow
- [ ] Step 15: End-to-end testing
- [ ] Step 16: Fix issues and polish
- [ ] Step 17: Update documentation
