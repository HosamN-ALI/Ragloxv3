# RAGLOX v3.0 API Documentation

**Base URL:** `http://172.245.232.188:8000`
**API Version:** 3.0.0
**OpenAPI Spec:** `/openapi.json`

## Missions API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/missions` | List all missions |
| POST | `/api/v1/missions` | Create new mission |
| GET | `/api/v1/missions/{mission_id}` | Get mission details |
| POST | `/api/v1/missions/{mission_id}/start` | Start mission |
| POST | `/api/v1/missions/{mission_id}/pause` | Pause mission |
| POST | `/api/v1/missions/{mission_id}/resume` | Resume mission |
| POST | `/api/v1/missions/{mission_id}/stop` | Stop mission |
| GET | `/api/v1/missions/{mission_id}/targets` | List targets |
| GET | `/api/v1/missions/{mission_id}/targets/{target_id}` | Get target details |
| GET | `/api/v1/missions/{mission_id}/vulnerabilities` | List vulnerabilities |
| GET | `/api/v1/missions/{mission_id}/credentials` | List credentials |
| GET | `/api/v1/missions/{mission_id}/sessions` | List sessions |
| GET | `/api/v1/missions/{mission_id}/stats` | Get mission stats |
| GET | `/api/v1/missions/{mission_id}/approvals` | List pending approvals |
| POST | `/api/v1/missions/{mission_id}/approve/{action_id}` | Approve action |
| POST | `/api/v1/missions/{mission_id}/reject/{action_id}` | Reject action |
| POST | `/api/v1/missions/{mission_id}/chat` | Send chat message |
| GET | `/api/v1/missions/{mission_id}/chat` | Get chat history |

## Knowledge API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/knowledge/stats` | Get knowledge stats |
| GET | `/api/v1/knowledge/techniques` | List techniques |
| GET | `/api/v1/knowledge/techniques/{technique_id}` | Get technique |
| GET | `/api/v1/knowledge/techniques/{technique_id}/modules` | Get technique modules |
| GET | `/api/v1/knowledge/modules` | List modules |
| GET | `/api/v1/knowledge/modules/{module_id}` | Get module |
| GET | `/api/v1/knowledge/tactics` | List tactics |
| GET | `/api/v1/knowledge/tactics/{tactic_id}/techniques` | Get tactic techniques |
| GET | `/api/v1/knowledge/platforms` | List platforms |
| GET | `/api/v1/knowledge/platforms/{platform}/modules` | Get platform modules |
| GET | `/api/v1/knowledge/search` | Search modules (GET) |
| POST | `/api/v1/knowledge/search` | Search modules (POST) |
| POST | `/api/v1/knowledge/best-module` | Get best module for task |
| GET | `/api/v1/knowledge/exploit-modules` | Get exploit modules |
| GET | `/api/v1/knowledge/recon-modules` | Get recon modules |
| GET | `/api/v1/knowledge/credential-modules` | Get credential modules |
| GET | `/api/v1/knowledge/privesc-modules` | Get privesc modules |

## Health & Root

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |

## WebSocket

| Endpoint | Description |
|----------|-------------|
| `ws://172.245.232.188:8000/ws/{mission_id}` | Real-time updates for mission |

## Test Data

- **Mission ID:** `6b14028c-7f30-4ce6-aad2-20f17eee39d0`
- **Target IP:** 172.28.0.100 (Linux Ubuntu 22.04)
- **Risk Score:** 85.0 (High)
- **Open Ports:** SSH (22), HTTP (80), PostgreSQL (5432)
- **Vulnerabilities:** 2 (SSH Weak Password - High, DB Credentials in File - Critical)
- **Credentials:** 2 (postgres/database, admin/SSH)
- **Active Sessions:** 1 (SSH as root)

## Data Models (Schemas)

- ApprovalRequest
- ApprovalResponse
- ChatMessageResponse
- ChatRequest
- CredentialResponse
- HTTPValidationError
- KnowledgeStatsResponse
- MissionCreate
- MissionResponse
- MissionStatusResponse
- ModuleResponse
- PaginatedResponse
- PendingApprovalResponse
- RejectionRequest
- SearchRequest
- SessionResponse
- TacticResponse
- TargetResponse
- TaskModuleRequest
- TechniqueResponse
- ValidationError
- VulnerabilityResponse
