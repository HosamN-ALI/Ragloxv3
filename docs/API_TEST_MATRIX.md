# API Test Matrix

This document outlines the test matrix for the RAGLOX API based on the OpenAPI specification. It details every endpoint, its requirements, and specific test scenarios to ensure robust functionality.

## 1. Endpoint Reference

### 1.1 General Endpoints

| Method | Path | Operation ID | Purpose | Inputs | Constraints | Expected Responses | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | `root__get` | Root endpoint | None | None | 200 (OK) | None |
| `GET` | `/health` | `health_check_health_get` | Health check | None | None | 200 (OK) | None |

### 1.2 Mission Management

| Method | Path | Operation ID | Purpose | Inputs | Constraints | Expected Responses | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/missions` | `list_missions_api_v1_missions_get` | List all active mission IDs | None | None | 200 (List[str]) | None |
| `POST` | `/api/v1/missions` | `create_mission_api_v1_missions_post` | Create a new mission | Body: `MissionCreate` <br> - `name` (str) <br> - `scope` (List[str]) <br> - `goals` (List[str]) <br> - `description` (opt) <br> - `constraints` (opt) | `name`: min 1, max 255 <br> `scope`: minItems 1 <br> `goals`: minItems 1 | 201 (MissionResponse) <br> 422 (Validation Error) | None |
| `GET` | `/api/v1/missions/{mission_id}` | `get_mission_api_v1_missions__mission_id__get` | Get mission status and details | Path: `mission_id` | `mission_id`: required | 200 (MissionStatusResponse) <br> 422 (Validation Error) | Mission must exist |
| `POST` | `/api/v1/missions/{mission_id}/start` | `start_mission_api_v1_missions__mission_id__start_post` | Start a mission | Path: `mission_id` | `mission_id`: required | 200 (MissionResponse) <br> 422 (Validation Error) | Mission created |
| `POST` | `/api/v1/missions/{mission_id}/pause` | `pause_mission_api_v1_missions__mission_id__pause_post` | Pause a running mission | Path: `mission_id` | `mission_id`: required | 200 (MissionResponse) <br> 422 (Validation Error) | Mission running |
| `POST` | `/api/v1/missions/{mission_id}/resume` | `resume_mission_api_v1_missions__mission_id__resume_post` | Resume a paused mission | Path: `mission_id` | `mission_id`: required | 200 (MissionResponse) <br> 422 (Validation Error) | Mission paused |
| `POST` | `/api/v1/missions/{mission_id}/stop` | `stop_mission_api_v1_missions__mission_id__stop_post` | Stop a mission | Path: `mission_id` | `mission_id`: required | 200 (MissionResponse) <br> 422 (Validation Error) | Mission active |

### 1.3 Mission Data & Stats

| Method | Path | Operation ID | Purpose | Inputs | Constraints | Expected Responses | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/missions/{mission_id}/targets` | `list_targets_api_v1_missions__mission_id__targets_get` | List all targets for a mission | Path: `mission_id` | `mission_id`: required | 200 (List[TargetResponse]) <br> 422 | Mission exists |
| `GET` | `/api/v1/missions/{mission_id}/targets/{target_id}` | `get_target_api_v1_missions__mission_id__targets__target_id__get` | Get a specific target | Path: `mission_id`, `target_id` | Both required | 200 (TargetResponse) <br> 422 | Mission & Target exist |
| `GET` | `/api/v1/missions/{mission_id}/vulnerabilities` | `list_vulnerabilities_api_v1_missions__mission_id__vulnerabilities_get` | List all vulnerabilities | Path: `mission_id` | `mission_id`: required | 200 (List[VulnerabilityResponse]) <br> 422 | Mission exists |
| `GET` | `/api/v1/missions/{mission_id}/credentials` | `list_credentials_api_v1_missions__mission_id__credentials_get` | List all credentials | Path: `mission_id` | `mission_id`: required | 200 (List[CredentialResponse]) <br> 422 | Mission exists |
| `GET` | `/api/v1/missions/{mission_id}/sessions` | `list_sessions_api_v1_missions__mission_id__sessions_get` | List all active sessions | Path: `mission_id` | `mission_id`: required | 200 (List[SessionResponse]) <br> 422 | Mission exists |
| `GET` | `/api/v1/missions/{mission_id}/stats` | `get_mission_stats_api_v1_missions__mission_id__stats_get` | Get mission statistics | Path: `mission_id` | `mission_id`: required | 200 (Object) <br> 422 | Mission exists |

### 1.4 Mission Interaction (Approvals & Chat)

| Method | Path | Operation ID | Purpose | Inputs | Constraints | Expected Responses | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/missions/{mission_id}/approvals` | `list_pending_approvals_api_v1_missions__mission_id__approvals_get` | List pending approval requests | Path: `mission_id` | `mission_id`: required | 200 (List[PendingApprovalResponse]) <br> 422 | Mission exists |
| `POST` | `/api/v1/missions/{mission_id}/approve/{action_id}` | `approve_action_api_v1_missions__mission_id__approve__action_id__post` | Approve a pending action | Path: `mission_id`, `action_id` <br> Body: `ApprovalRequest` | `user_comment` (opt) | 200 (ApprovalResponse) <br> 422 | Pending action exists |
| `POST` | `/api/v1/missions/{mission_id}/reject/{action_id}` | `reject_action_api_v1_missions__mission_id__reject__action_id__post` | Reject a pending action | Path: `mission_id`, `action_id` <br> Body: `RejectionRequest` | `rejection_reason` (opt) <br> `user_comment` (opt) | 200 (ApprovalResponse) <br> 422 | Pending action exists |
| `POST` | `/api/v1/missions/{mission_id}/chat` | `send_chat_message_api_v1_missions__mission_id__chat_post` | Send chat message to mission | Path: `mission_id` <br> Body: `ChatRequest` | `content`: required, max 4096 <br> `related_task_id` (opt) <br> `related_action_id` (opt) | 200 (ChatMessageResponse) <br> 422 | Mission exists |
| `GET` | `/api/v1/missions/{mission_id}/chat` | `get_chat_history_api_v1_missions__mission_id__chat_get` | Get chat history | Path: `mission_id` <br> Query: `limit` | `limit`: default 50 | 200 (List[ChatMessageResponse]) <br> 422 | Mission exists |

### 1.5 Knowledge Base (General & RX Modules)

| Method | Path | Operation ID | Purpose | Inputs | Constraints | Expected Responses | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/knowledge/stats` | `get_knowledge_stats_api_v1_knowledge_stats_get` | Get KB stats | None | None | 200 (KnowledgeStatsResponse) | None |
| `GET` | `/api/v1/knowledge/techniques` | `list_techniques_api_v1_knowledge_techniques_get` | List techniques | Query: `platform`, `limit`, `offset` | `limit`: max 500 | 200 (PaginatedResponse) <br> 422 | None |
| `GET` | `/api/v1/knowledge/techniques/{technique_id}` | `get_technique_api_v1_knowledge_techniques__technique_id__get` | Get specific technique | Path: `technique_id` | Required | 200 (TechniqueResponse) <br> 422 | None |
| `GET` | `/api/v1/knowledge/techniques/{technique_id}/modules` | `get_technique_modules_api_v1_knowledge_techniques__technique_id__modules_get` | Get modules for technique | Path: `technique_id` <br> Query: `platform` | Required | 200 (List[ModuleResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/modules` | `list_modules_api_v1_knowledge_modules_get` | List RX modules | Query: `technique_id`, `platform`, `executor_type`, `limit`, `offset` | `limit`: max 500 | 200 (PaginatedResponse) <br> 422 | None |
| `GET` | `/api/v1/knowledge/modules/{module_id}` | `get_module_api_v1_knowledge_modules__module_id__get` | Get specific module | Path: `module_id` | Required | 200 (ModuleResponse) <br> 422 | None |
| `GET` | `/api/v1/knowledge/tactics` | `list_tactics_api_v1_knowledge_tactics_get` | List tactics | None | None | 200 (List[TacticResponse]) | None |
| `GET` | `/api/v1/knowledge/tactics/{tactic_id}/techniques` | `get_tactic_techniques_api_v1_knowledge_tactics__tactic_id__techniques_get` | Get techniques for tactic | Path: `tactic_id` | Required | 200 (List[TechniqueResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/platforms` | `list_platforms_api_v1_knowledge_platforms_get` | List platforms | None | None | 200 (List[str]) | None |
| `GET` | `/api/v1/knowledge/platforms/{platform}/modules` | `get_platform_modules_api_v1_knowledge_platforms__platform__modules_get` | Get modules for platform | Path: `platform` <br> Query: `limit` | `limit`: max 200 | 200 (List[ModuleResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/search` | `search_modules_api_v1_knowledge_search_get` | Search modules (GET) | Query: `q` (req), `platform`, `tactic`, `limit` | `q`: min 1, max 200 | 200 (List[ModuleResponse]) <br> 422 | None |
| `POST` | `/api/v1/knowledge/search` | `search_modules_post_api_v1_knowledge_search_post` | Search modules (POST) | Body: `SearchRequest` | `query`: req | 200 (List[ModuleResponse]) <br> 422 | None |
| `POST` | `/api/v1/knowledge/best-module` | `get_best_module_for_task_api_v1_knowledge_best_module_post` | Get best module for task | Body: `TaskModuleRequest` | None | 200 (ModuleResponse or null) <br> 422 | None |

### 1.6 Knowledge Base (Specialized Modules)

| Method | Path | Operation ID | Purpose | Inputs | Constraints | Expected Responses | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/knowledge/exploit-modules` | `get_exploit_modules_api_v1_knowledge_exploit_modules_get` | Get exploit modules | Query: `vuln_type`, `platform`, `limit` | None | 200 (List[ModuleResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/recon-modules` | `get_recon_modules_api_v1_knowledge_recon_modules_get` | Get recon modules | Query: `platform`, `limit` | None | 200 (List[ModuleResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/credential-modules` | `get_credential_modules_api_v1_knowledge_credential_modules_get` | Get credential modules | Query: `platform`, `limit` | None | 200 (List[ModuleResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/privesc-modules` | `get_privesc_modules_api_v1_knowledge_privesc_modules_get` | Get privesc modules | Query: `platform`, `limit` | None | 200 (List[ModuleResponse]) <br> 422 | None |

### 1.7 Knowledge Base (Nuclei)

| Method | Path | Operation ID | Purpose | Inputs | Constraints | Expected Responses | Dependencies |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/knowledge/nuclei/templates` | `list_nuclei_templates_api_v1_knowledge_nuclei_templates_get` | List Nuclei templates | Query: `severity`, `protocol`, `tag`, `limit`, `offset` | `limit`: max 500 | 200 (PaginatedResponse) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/templates/{template_id}` | `get_nuclei_template_api_v1_knowledge_nuclei_templates__template_id__get` | Get Nuclei template | Path: `template_id` | Required | 200 (NucleiTemplateResponse) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/search` | `search_nuclei_templates_api_v1_knowledge_nuclei_search_get` | Search Nuclei templates | Query: `q` (req), `severity`, `protocol`, `limit` | `q`: min 1, max 200 | 200 (List[NucleiTemplateResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/cve/{cve_id}` | `get_nuclei_template_by_cve_api_v1_knowledge_nuclei_cve__cve_id__get` | Get template by CVE | Path: `cve_id` | Required | 200 (NucleiTemplateResponse) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/severity/{severity}` | `get_nuclei_templates_by_severity_api_v1_knowledge_nuclei_severity__severity__get` | Get templates by severity | Path: `severity` <br> Query: `limit` | Required | 200 (List[NucleiTemplateResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/critical` | `get_critical_nuclei_templates_api_v1_knowledge_nuclei_critical_get` | Get critical templates | Query: `limit` | None | 200 (List[NucleiTemplateResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/rce` | `get_rce_nuclei_templates_api_v1_knowledge_nuclei_rce_get` | Get RCE templates | Query: `limit` | None | 200 (List[NucleiTemplateResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/sqli` | `get_sqli_nuclei_templates_api_v1_knowledge_nuclei_sqli_get` | Get SQLi templates | Query: `limit` | None | 200 (List[NucleiTemplateResponse]) <br> 422 | None |
| `GET` | `/api/v1/knowledge/nuclei/xss` | `get_xss_nuclei_templates_api_v1_knowledge_nuclei_xss_get` | Get XSS templates | Query: `limit` | None | 200 (List[NucleiTemplateResponse]) <br> 422 | None |

---

## 2. Test Scenarios

### 2.1 Happy Path Scenarios
*These tests verify that the API functions correctly under normal conditions with valid inputs.*

1.  **Create Mission**: POST `/api/v1/missions` with valid `name`, `scope` (e.g., `["192.168.1.0/24"]`), and `goals`. Verify 201 Created and response contains `mission_id`.
2.  **Get Mission Details**: GET `/api/v1/missions/{mission_id}` using ID from step 1. Verify 200 OK and status matches.
3.  **Start Mission**: POST `/api/v1/missions/{mission_id}/start`. Verify 200 OK and status changes to "running".
4.  **List Knowledge Stats**: GET `/api/v1/knowledge/stats`. Verify 200 OK and non-zero counts for techniques/modules.
5.  **Search Modules**: GET `/api/v1/knowledge/search?q=scan`. Verify 200 OK and results list.
6.  **Get Nuclei Templates**: GET `/api/v1/knowledge/nuclei/templates?limit=5`. Verify 200 OK and list of 5 templates.

### 2.2 Validation Scenarios
*These tests verify that the API correctly rejects invalid inputs.*

1.  **Create Mission - Missing Fields**: POST `/api/v1/missions` with empty body or missing `scope`. Verify 422 Validation Error.
2.  **Create Mission - Invalid Scope**: POST `/api/v1/missions` with empty list for `scope`. Verify 422 Validation Error (`minItems` constraint).
3.  **Get Mission - Invalid ID Format**: GET `/api/v1/missions/invalid-uuid-format`. Verify 422 or 404 (depending on implementation).
4.  **Search Modules - Empty Query**: GET `/api/v1/knowledge/search?q=`. Verify 422 Validation Error (`minLength` constraint).
5.  **Pagination - Negative Limit**: GET `/api/v1/knowledge/modules?limit=-1`. Verify 422 Validation Error.

### 2.3 Edge Case Scenarios
*These tests cover boundary conditions and state transitions.*

1.  **State Transition - Pause Stopped**: Attempt to POST `/api/v1/missions/{mission_id}/pause` on a mission that is already "stopped" or "created" (not running). Verify appropriate error or no-op (400/422).
2.  **State Transition - Resume Running**: Attempt to POST `/api/v1/missions/{mission_id}/resume` on a mission that is already "running".
3.  **Non-Existent Resources**:
    *   GET `/api/v1/missions/non-existent-id` -> 404 Not Found.
    *   GET `/api/v1/missions/{valid_id}/targets/non-existent-target` -> 404 Not Found.
4.  **Large Payloads**: Create mission with maximum allowed name length (255 chars). Verify success.
5.  **Empty Lists**: Request lists (targets, vulns) for a new mission. Verify 200 OK with empty array `[]`.

### 2.4 Workflow Scenarios
*End-to-end flows simulating real user behavior.*

#### Workflow A: Mission Lifecycle
1.  **Create**: `POST /api/v1/missions` -> Store `mission_id`.
2.  **Verify Created**: `GET /api/v1/missions/{mission_id}` -> Status should be "created".
3.  **Start**: `POST /api/v1/missions/{mission_id}/start`.
4.  **Verify Running**: `GET /api/v1/missions/{mission_id}` -> Status should be "running".
5.  **Pause**: `POST /api/v1/missions/{mission_id}/pause`.
6.  **Verify Paused**: `GET /api/v1/missions/{mission_id}` -> Status should be "paused".
7.  **Resume**: `POST /api/v1/missions/{mission_id}/resume`.
8.  **Stop**: `POST /api/v1/missions/{mission_id}/stop`.
9.  **Verify Stopped**: `GET /api/v1/missions/{mission_id}` -> Status should be "stopped".

#### Workflow B: Data Retrieval (Polling)
*Simulate frontend polling for updates.*
1.  **Start Mission**.
2.  **Loop (e.g., 3 times)**:
    *   `GET /api/v1/missions/{mission_id}/stats`
    *   `GET /api/v1/missions/{mission_id}/targets`
    *   `GET /api/v1/missions/{mission_id}/vulnerabilities`
    *   `GET /api/v1/missions/{mission_id}/approvals`
3.  **Verify**: Responses are 200 OK and structures match schemas.

#### Workflow C: Approval Process
1.  **Pre-condition**: Mission is running and generates a pending approval (mocked or real).
2.  **List Approvals**: `GET /api/v1/missions/{mission_id}/approvals`. Find `action_id`.
3.  **Approve**: `POST /api/v1/missions/{mission_id}/approve/{action_id}` with `{"user_comment": "Proceed"}`.
4.  **Verify**: `GET /api/v1/missions/{mission_id}/approvals` should no longer list that `action_id`.

#### Workflow D: Chat Interaction
1.  **Send Message**: `POST /api/v1/missions/{mission_id}/chat` with `{"content": "Status report"}`.
2.  **Verify Response**: Check 200 OK and response content.
3.  **Get History**: `GET /api/v1/missions/{mission_id}/chat`. Verify the sent message appears in history.