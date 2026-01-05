# RAGLOX v3.0 - Complete Backend-Frontend Integration Map

> **Date**: 2026-01-03
> **Status**: COMPREHENSIVE INTEGRATION ANALYSIS

---

## 1. Backend API Endpoints - Complete Inventory

### 1.1 Mission Management (`/api/v1/missions`)

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/missions` | POST | **Implemented** | Create new mission |
| `/missions` | GET | **Implemented** | List active mission IDs |
| `/missions/{mission_id}` | GET | **Implemented** | Get mission details |
| `/missions/{mission_id}/start` | POST | **Implemented** | Start mission |
| `/missions/{mission_id}/pause` | POST | **Implemented** | Pause mission |
| `/missions/{mission_id}/resume` | POST | **Implemented** | Resume mission |
| `/missions/{mission_id}/stop` | POST | **Implemented** | Stop mission |
| `/missions/{mission_id}/stats` | GET | **Implemented** | Get mission statistics |

### 1.2 Target Management (`/api/v1/missions/{mission_id}/targets`)

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/targets` | GET | **Implemented** | List targets |
| `/targets/{target_id}` | GET | **Implemented** | Get target details |

### 1.3 Vulnerability Management

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/vulnerabilities` | GET | **Implemented** | List vulnerabilities |

### 1.4 Credential Management

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/credentials` | GET | **Implemented** | List credentials |

### 1.5 Session Management

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/sessions` | GET | **Implemented** | List sessions |

### 1.6 HITL (Human-in-the-Loop)

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/approvals` | GET | **Implemented** | List pending approvals |
| `/approve/{action_id}` | POST | **Implemented** | Approve action |
| `/reject/{action_id}` | POST | **Implemented** | Reject action |

### 1.7 Chat

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/chat` | GET | **Implemented** | Get chat history |
| `/chat` | POST | **Implemented** | Send message |

### 1.8 Knowledge Base (`/api/v1/knowledge`)

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/stats` | GET | **Partial** | Get KB statistics |
| `/techniques` | GET | **Missing** | List techniques (paginated) |
| `/techniques/{technique_id}` | GET | **Missing** | Get technique details |
| `/techniques/{technique_id}/modules` | GET | **Missing** | Get modules for technique |
| `/modules` | GET | **Missing** | List modules (paginated) |
| `/modules/{module_id}` | GET | **Missing** | Get module details |
| `/tactics` | GET | **Missing** | List tactics |
| `/tactics/{tactic_id}/techniques` | GET | **Missing** | Get tactic techniques |
| `/platforms` | GET | **Missing** | List platforms |
| `/platforms/{platform}/modules` | GET | **Missing** | Get platform modules |
| `/search` | GET | **Partial** | Search modules |
| `/search` | POST | **Missing** | Search modules (POST) |
| `/best-module` | POST | **Missing** | Get best module for task |
| `/exploit-modules` | GET | **Missing** | Get exploit modules |
| `/recon-modules` | GET | **Missing** | Get recon modules |
| `/credential-modules` | GET | **Missing** | Get credential modules |
| `/privesc-modules` | GET | **Missing** | Get privesc modules |

### 1.9 Nuclei Templates (`/api/v1/knowledge/nuclei`)

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/templates` | GET | **Missing** | List templates (paginated) |
| `/templates/{template_id}` | GET | **Missing** | Get template details |
| `/search` | GET | **Missing** | Search templates |
| `/cve/{cve_id}` | GET | **Missing** | Get template by CVE |
| `/severity/{severity}` | GET | **Missing** | Get by severity |
| `/critical` | GET | **Missing** | Get critical templates |
| `/rce` | GET | **Missing** | Get RCE templates |
| `/sqli` | GET | **Missing** | Get SQLi templates |
| `/xss` | GET | **Missing** | Get XSS templates |

### 1.10 Health Check

| Endpoint | Method | Frontend Status | Function |
|----------|--------|-----------------|----------|
| `/health` | GET | **Implemented** | Health check |
| `/` | GET | **Not used** | API info |

---

## 2. WebSocket Events - Complete Inventory

### 2.1 Connection Events

| Event | Direction | Frontend Status | Description |
|-------|-----------|-----------------|-------------|
| `connected` | Server->Client | **Implemented** | Connection established |
| `pong` | Server->Client | **Implemented** | Ping response |
| `subscribed` | Server->Client | **Implemented** | Event subscription confirmed |
| `error` | Server->Client | **Implemented** | Error message |

### 2.2 Mission Events

| Event | Direction | Frontend Status | Description |
|-------|-----------|-----------------|-------------|
| `new_target` | Server->Client | **Implemented** | New target discovered |
| `target_update` | Server->Client | **Implemented** | Target status updated |
| `new_vuln` | Server->Client | **Implemented** | New vulnerability found |
| `new_cred` | Server->Client | **Implemented** | New credential harvested |
| `new_session` | Server->Client | **Implemented** | New session established |
| `goal_achieved` | Server->Client | **Implemented** | Goal completed |
| `status_change` | Server->Client | **Implemented** | Mission status changed |
| `statistics` | Server->Client | **Implemented** | Stats update |
| `mission_status` | Server->Client | **Implemented** | Mission status update |

### 2.3 HITL Events

| Event | Direction | Frontend Status | Description |
|-------|-----------|-----------------|-------------|
| `approval_request` | Server->Client | **Implemented** | Approval needed |
| `approval_response` | Server->Client | **Implemented** | Approval decision made |
| `approval_resolved` | Server->Client | **Implemented** | Approval resolved |

### 2.4 Chat Events

| Event | Direction | Frontend Status | Description |
|-------|-----------|-----------------|-------------|
| `chat_message` | Server->Client | **Implemented** | New chat message |

### 2.5 AI Plan Events

| Event | Direction | Frontend Status | Description |
|-------|-----------|-----------------|-------------|
| `ai_plan` | Server->Client | **Implemented** | AI execution plan |

### 2.6 Client Commands

| Command | Direction | Backend Status | Description |
|---------|-----------|----------------|-------------|
| `ping` | Client->Server | **Implemented** | Keep-alive |
| `subscribe` | Client->Server | **Implemented** | Subscribe to events |

---

## 3. Frontend Integration Gaps

### 3.1 Critical Gaps (Priority: HIGH)

1. **Knowledge Base API** - Most endpoints not integrated
   - Missing: techniques, modules, tactics, platforms listing
   - Missing: Nuclei templates API
   - Missing: Search functionality with filters

2. **Missions List Page** - No page to list/manage all missions
   - Missing: `/missions` route
   - Missing: Mission cards with status indicators
   - Missing: Mission creation modal

### 3.2 Medium Priority Gaps

3. **Knowledge Page** - No dedicated knowledge browser
   - Missing: `/knowledge` route
   - Missing: Technique/Module/Tactic explorer
   - Missing: Nuclei template browser

4. **Terminal Output** - Limited real-time output
   - Backend: No `/terminal` endpoint exists
   - Terminal output only via WebSocket events

### 3.3 Low Priority Gaps

5. **Mission Details Enhancement**
   - Better target/vuln/cred/session cards
   - Timeline view of events
   - Mission progress visualization

---

## 4. Implementation Plan

### Phase 1: Knowledge API Integration (PRIORITY)

**File: `/client/src/lib/api.ts`**

Add complete Knowledge API:

```typescript
export const knowledgeApi = {
  // Statistics
  stats: async () => fetchApi('/api/v1/knowledge/stats'),
  
  // Techniques
  techniques: {
    list: async (params?: { platform?: string; limit?: number; offset?: number }) =>
      fetchApi(`/api/v1/knowledge/techniques?${new URLSearchParams(params as Record<string, string>)}`),
    get: async (techniqueId: string) =>
      fetchApi(`/api/v1/knowledge/techniques/${techniqueId}`),
    getModules: async (techniqueId: string, platform?: string) =>
      fetchApi(`/api/v1/knowledge/techniques/${techniqueId}/modules${platform ? `?platform=${platform}` : ''}`),
  },
  
  // Modules
  modules: {
    list: async (params?: { technique_id?: string; platform?: string; executor_type?: string; limit?: number; offset?: number }) =>
      fetchApi(`/api/v1/knowledge/modules?${new URLSearchParams(params as Record<string, string>)}`),
    get: async (moduleId: string) =>
      fetchApi(`/api/v1/knowledge/modules/${moduleId}`),
  },
  
  // Tactics
  tactics: {
    list: async () => fetchApi('/api/v1/knowledge/tactics'),
    getTechniques: async (tacticId: string) =>
      fetchApi(`/api/v1/knowledge/tactics/${tacticId}/techniques`),
  },
  
  // Platforms
  platforms: {
    list: async () => fetchApi('/api/v1/knowledge/platforms'),
    getModules: async (platform: string, limit?: number) =>
      fetchApi(`/api/v1/knowledge/platforms/${platform}/modules${limit ? `?limit=${limit}` : ''}`),
  },
  
  // Search
  search: async (q: string, params?: { platform?: string; tactic?: string; limit?: number }) =>
    fetchApi(`/api/v1/knowledge/search?q=${encodeURIComponent(q)}&${new URLSearchParams(params as Record<string, string>)}`),
  
  // Specialized Queries
  specialized: {
    bestModule: async (params: { tactic?: string; technique?: string; platform?: string; executor_type?: string; require_elevation?: boolean }) =>
      fetchApi('/api/v1/knowledge/best-module', { method: 'POST', body: JSON.stringify(params) }),
    exploitModules: async (vuln_type?: string, platform?: string) =>
      fetchApi(`/api/v1/knowledge/exploit-modules?${new URLSearchParams({ vuln_type, platform } as Record<string, string>)}`),
    reconModules: async (platform?: string) =>
      fetchApi(`/api/v1/knowledge/recon-modules?${platform ? `platform=${platform}` : ''}`),
    credentialModules: async (platform?: string) =>
      fetchApi(`/api/v1/knowledge/credential-modules?${platform ? `platform=${platform}` : ''}`),
    privescModules: async (platform?: string) =>
      fetchApi(`/api/v1/knowledge/privesc-modules?${platform ? `platform=${platform}` : ''}`),
  },
  
  // Nuclei Templates
  nuclei: {
    list: async (params?: { severity?: string; protocol?: string; tag?: string; limit?: number; offset?: number }) =>
      fetchApi(`/api/v1/knowledge/nuclei/templates?${new URLSearchParams(params as Record<string, string>)}`),
    get: async (templateId: string) =>
      fetchApi(`/api/v1/knowledge/nuclei/templates/${templateId}`),
    search: async (q: string, params?: { severity?: string; protocol?: string; limit?: number }) =>
      fetchApi(`/api/v1/knowledge/nuclei/search?q=${encodeURIComponent(q)}&${new URLSearchParams(params as Record<string, string>)}`),
    getByCve: async (cveId: string) =>
      fetchApi(`/api/v1/knowledge/nuclei/cve/${cveId}`),
    getBySeverity: async (severity: string, limit?: number) =>
      fetchApi(`/api/v1/knowledge/nuclei/severity/${severity}${limit ? `?limit=${limit}` : ''}`),
    critical: async (limit?: number) =>
      fetchApi(`/api/v1/knowledge/nuclei/critical${limit ? `?limit=${limit}` : ''}`),
    rce: async (limit?: number) =>
      fetchApi(`/api/v1/knowledge/nuclei/rce${limit ? `?limit=${limit}` : ''}`),
    sqli: async (limit?: number) =>
      fetchApi(`/api/v1/knowledge/nuclei/sqli${limit ? `?limit=${limit}` : ''}`),
    xss: async (limit?: number) =>
      fetchApi(`/api/v1/knowledge/nuclei/xss${limit ? `?limit=${limit}` : ''}`),
  },
};
```

### Phase 2: Type Definitions

**File: `/client/src/types/index.ts`**

Add Knowledge types:

```typescript
// Knowledge Base Types
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

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}
```

### Phase 3: New Pages (Optional)

1. **Missions List Page** (`/client/src/pages/Missions.tsx`)
2. **Knowledge Browser Page** (`/client/src/pages/Knowledge.tsx`)

---

## 5. Current Implementation Summary

### What's Working:
- Mission CRUD operations
- Target/Vulnerability/Credential/Session listing
- HITL Approvals (approve/reject)
- Chat (send/receive messages)
- WebSocket real-time updates
- Health check

### What Needs Work:
- **Knowledge API** - Only basic stats endpoint
- **Missions list** - No dedicated page
- **Knowledge browser** - No dedicated page
- **Nuclei templates** - Not integrated

---

## 6. Design Consistency Notes

When implementing new features, maintain:

1. **Colors** - Use CSS variables from `index.css`
2. **Typography** - Inter + JetBrains Mono
3. **Spacing** - padding: 16px, gap: 24px
4. **Border Radius** - 12px
5. **Shadows** - var(--shadow-card)
6. **Transitions** - 200ms

---

> **Report Generated**: 2026-01-03
> **Author**: RAGLOX Integration Team
