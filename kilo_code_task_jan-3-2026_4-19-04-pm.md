**User:**

<task>
We have 16 remaining test failures that need to be fixed. Based on the test results, here are the issues:

## Remaining Failures to Fix

### 1. Mission Stop (3 tests) - Still returns 500 error
The stop_mission endpoint still has issues. Look at `src/api/routes.py` and ensure the stop logic properly handles all cases without throwing exceptions.

### 2. Reject Action (4 tests) - Returns 400 instead of 404
The `reject_action` endpoint needs the same fix as `approve_action`. Ensure it returns 404 when the action doesn't exist.

### 3. Chat Endpoints (3 tests) - Missing 404 for non-existent missions
- `send_chat_message` and `get_chat_history` need to check if mission exists and return 404 if not.

### 4. Mission Data Endpoints (5 tests) - Missing 404 for non-existent missions
- `list_targets`, `list_vulnerabilities`, `list_credentials`, `list_sessions`, `get_mission_stats` need mission existence checks.

### 5. Mission Invalid ID (1 test) - Returns 404 instead of 422
- When an invalid mission_id format is provided, it should return 422 (validation error) not 404.

## Instructions

1. Read `src/api/routes.py` to understand the current implementation
2. Fix each of the above issues
3. Ensure consistent error handling:
   - Invalid format/type → 422
   - Resource not found → 404
   - Server error → 500 (should be avoided)
4. Use `attempt_completion` when done to summarize the changes made
</task>
<environment_details>
# VSCode Visible Files
docs/COMPREHENSIVE_TEST_REPORT.md

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:02:57.447Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.00

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>


# Current Workspace Directory (/root/RAGLOX_V3/webapp) Files
.blackboxrules
.env.example
.gitignore
apiendpoints.md
AUDIT_SUMMARY_AR.md
BACKEND_ANALYSIS_REPORT.md
BACKEND_FRONTEND_INTEGRATION_COMPLETE_MAP_AR.md
BACKEND_INTEGRATION_ANALYSIS_REPORT.md
blackbox_mcp_settings.json
BROWSER_AGENT_TEST_INSTRUCTIONS.md
DEEP_ANALYSIS_REPORT.md
DESERIALIZATION_FIX.md
FINAL_AUDIT_REPORT.md
HYBRID_INTELLIGENCE_IMPLEMENTATION_REPORT.md
INTEGRATION_SUMMARY_EN.md
INTELLIGENCE_REASONING_AUDIT.md
INTELLIGENCE_TREATMENT_PLAN.md
ITERM_MCP_DEMONSTRATION.md
ITERM_MCP_SETUP.md
MCP_SERVER_SUMMARY.md
MCP_SERVER_TEST_REPORT.md
pyproject.toml
pytest.ini
README.md
run_demo.py
run_real_ai_demo.py
run.py
test_iterm_mcp.js
test_mcp_server.js
.github/
data/
docs/
docs/API_TEST_MATRIX.md
docs/BACKEND_FRONTEND_INTEGRATION_GUIDE.md
docs/COMPREHENSIVE_TEST_REPORT.md
docs/E2E_DEMO.md
docs/ENTERPRISE_UI_IMPROVEMENT_PLAN.md
docs/FRONTEND_INTEGRATION_NOTES.md
docs/INTELLIGENCE_TREATMENT_PLAN.md
docs/openapi.json
docs/test_results_v2.xml
docs/test_results.xml
infrastructure/
infrastructure/.env.example
infrastructure/docker-compose.yml
infrastructure/postgres/init.sql
infrastructure/postgres/seed.sql
infrastructure/redis/key-schema.md
infrastructure/redis/redis.conf
infrastructure/vulnerable-target/admin.html
infrastructure/vulnerable-target/Dockerfile
infrastructure/vulnerable-target/entrypoint.sh
infrastructure/vulnerable-target/index.html
infrastructure/vulnerable-target/nginx-default.conf
src/
src/utils/__init__.py
tests/
tests/__init__.py
tests/conftest.py
tests/test_analysis_reflexion.py
tests/test_api.py
tests/test_blackboard.py
tests/test_config.py
tests/test_controller.py
tests/test_core_models.py
tests/test_deserialization_fix.py
tests/test_deserialization_simple.py
tests/test_distributed_claiming.py
tests/test_exceptions.py
tests/test_executors.py
tests/test_hitl.py
tests/test_integration.py
tests/test_intel_elastic.py
tests/test_intel.py
tests/test_knowledge_api.py
tests/test_knowledge.py
tests/test_llm_integration.py
tests/test_logging.py
tests/test_logic_trigger_chain.py
tests/test_nuclei_ai_wiring.py
tests/test_nuclei_integration.py
tests/test_nuclei_knowledge.py
tests/test_performance.py
tests/test_specialists.py
tests/test_validators.py
tests/test_zombie_task_recovery.py
tests/api_suite/__init__.py
tests/api_suite/conftest.py
tests/api_suite/test_approvals.py
tests/api_suite/test_chat.py
tests/api_suite/test_general.py
tests/api_suite/test_knowledge.py
tests/api_suite/test_mission_data.py
tests/api_suite/test_missions_lifecycle.py
tests/api_suite/test_nuclei.py
webapp/
webapp/frontend/client/index.html
webapp/frontend/client/public/.gitkeep
webapp/frontend/client/src/components/ErrorBoundary.tsx
webapp/frontend/client/src/components/Map.tsx
webapp/frontend/client/src/components/ProtectedRoute.tsx
webapp/frontend/client/src/components/ui/accordion.tsx
webapp/frontend/client/src/components/ui/alert-dialog.tsx
webapp/frontend/client/src/components/ui/alert.tsx
webapp/frontend/client/src/components/ui/aspect-ratio.tsx
webapp/frontend/client/src/components/ui/avatar.tsx
webapp/frontend/client/src/components/ui/badge.tsx
webapp/frontend/client/src/components/ui/breadcrumb.tsx
webapp/frontend/client/src/components/ui/button.tsx
webapp/frontend/client/src/components/ui/carousel.tsx
webapp/frontend/client/src/components/ui/collapsible.tsx
webapp/frontend/client/src/components/ui/context-menu.tsx
webapp/frontend/client/src/components/ui/dialog.tsx
webapp/frontend/client/src/components/ui/drawer.tsx
webapp/frontend/client/src/components/ui/dropdown-menu.tsx
webapp/frontend/client/src/components/ui/empty.tsx
webapp/frontend/client/src/components/ui/field.tsx
webapp/frontend/client/src/components/ui/form.tsx
webapp/frontend/client/src/components/ui/hover-card.tsx
webapp/frontend/client/src/components/ui/input-group.tsx
webapp/frontend/client/src/components/ui/item.tsx
webapp/frontend/client/src/components/ui/label.tsx
webapp/frontend/client/src/components/ui/menubar.tsx
webapp/frontend/client/src/components/ui/pagination.tsx
webapp/frontend/client/src/components/ui/popover.tsx
webapp/frontend/client/src/components/ui/progress.tsx
webapp/frontend/client/src/components/ui/radio-group.tsx
webapp/frontend/client/src/components/ui/select.tsx
webapp/frontend/client/src/components/ui/separator.tsx
webapp/frontend/client/src/components/ui/skeleton.tsx
webapp/frontend/client/src/components/ui/slider.tsx
webapp/frontend/client/src/components/ui/spinner.tsx
webapp/frontend/client/src/components/ui/table.tsx
webapp/frontend_backup_20260102_180738/.gitignore
webapp/frontend_backup_20260102_180738/eslint.config.js
webapp/frontend_backup_20260102_180738/index.html
webapp/frontend_backup_20260102_180738/package-lock.json
webapp/frontend_backup_20260102_180738/package.json
webapp/frontend_backup_20260102_180738/README.md
webapp/frontend_backup_20260102_180738/SERVICE_TO_UI_MAPPING_PLAN.md
webapp/frontend_backup_20260102_180738/tsconfig.app.json
webapp/frontend_backup_20260102_180738/tsconfig.json
webapp/frontend_backup_20260102_180738/tsconfig.node.json
webapp/frontend_backup_20260102_180738/vite.config.ts
webapp/frontend_backup_20260102_180738/public/vite.svg
webapp/frontend_backup_20260102_180738/src/App.css
webapp/frontend_backup_20260102_180738/src/App.tsx
webapp/frontend_backup_20260102_180738/src/index.css
webapp/frontend_backup_20260102_180738/src/main.tsx
webapp/frontend_backup_20260102_180738/src/assets/react.svg
webapp/frontend_backup_20260102_180738/src/components/ai/AIAssistantSidebar.tsx
webapp/frontend_backup_20260102_180738/src/components/assets/AssetCard.tsx
webapp/frontend_backup_20260102_180738/src/components/assets/index.ts
webapp/frontend_backup_20260102_180738/src/components/control/EmergencyStop.tsx
webapp/frontend_backup_20260102_180738/src/components/control/index.ts
webapp/frontend_backup_20260102_180738/src/components/dashboard/ActivityFeed.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/HITLApprovalModal.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/NetworkGraph.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/StatsGrid.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/TargetDetailsDrawer.tsx
webapp/frontend_backup_20260102_180738/src/components/intelligence/index.ts
webapp/frontend_backup_20260102_180738/src/components/intelligence/IntelligenceSidebar.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/GlobalConsole.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/Header.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/Layout.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/Sidebar.tsx
webapp/frontend_backup_20260102_180738/src/components/loot/CredentialVault.tsx
webapp/frontend_backup_20260102_180738/src/components/loot/index.ts
webapp/frontend_backup_20260102_180738/src/components/loot/SessionTerminal.tsx
webapp/frontend_backup_20260102_180738/src/components/manus/AIChatPanel.tsx
webapp/frontend_backup_20260102_180738/src/components/manus/DualPanelLayout.tsx
webapp/frontend_backup_20260102_180738/src/components/manus/EventCard.tsx
webapp/frontend_backup_20260102_180738/src/components/manus/index.ts
webapp/frontend_backup_20260102_180738/src/components/manus/PlanView.tsx
webapp/frontend_backup_20260102_180738/src/components/manus/TerminalPanel.tsx
webapp/frontend_backup_20260102_180738/src/components/mission/MissionSelector.tsx
webapp/frontend_backup_20260102_180738/src/components/operations/index.ts
webapp/frontend_backup_20260102_180738/src/components/operations/MissionTimeline.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Badge.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Button.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Card.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Drawer.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Input.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Modal.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Toast.tsx
webapp/frontend_backup_20260102_180738/src/components/wizard/index.ts
webapp/frontend_backup_20260102_180738/src/components/wizard/MissionSetupWizard.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/index.ts
webapp/frontend_backup_20260102_180738/src/components/workspaces/LootView.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/OperationsView.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/OperationsViewManus.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/ReconView.tsx
webapp/frontend_backup_20260102_180738/src/hooks/index.ts
webapp/frontend_backup_20260102_180738/src/hooks/useMissionData.ts
webapp/frontend_backup_20260102_180738/src/hooks/useWebSocket.ts
webapp/frontend_backup_20260102_180738/src/pages/Dashboard.tsx
webapp/frontend_backup_20260102_180738/src/services/api.ts
webapp/frontend_backup_20260102_180738/src/stores/eventStore.ts
webapp/frontend_backup_20260102_180738/src/stores/missionStore.ts
webapp/frontend_backup_20260102_180738/src/types/index.ts

(File list truncated. Use list_files on specific subdirectories if you need to explore further.)
You have not created a todo list yet. Create one with `update_todo_list` if your task is complicated or involves multiple steps.
</environment_details>

---

**Assistant:**


I'll help you fix the remaining 16 test failures. Let me start by reading the routes.py file to understand the current implementation and then fix each issue systematically.

[Tool Use: read_file]
Files: [
  {
    "path": "src/api/routes.py"
  }
]

---

**User:**

[Tool]
File: src/api/routes.py
Lines 1-711:
  1 | # ═══════════════════════════════════════════════════════════════
  2 | # RAGLOX v3.0 - API Routes
  3 | # REST API endpoints for mission management
  4 | # ═══════════════════════════════════════════════════════════════
  5 | 
  6 | from typing import Any, Dict, List, Optional
  7 | from uuid import UUID
  8 | 
  9 | from fastapi import APIRouter, Depends, HTTPException, Request, status
 10 | from pydantic import BaseModel, Field
 11 | 
 12 | from ..core.models import (
 13 |     MissionCreate, MissionStatus, MissionStats,
 14 |     Target, TargetStatus, Priority,
 15 |     Vulnerability, Severity,
 16 |     Credential, CredentialType,
 17 |     Session, SessionStatus,
 18 |     # HITL Models
 19 |     ApprovalAction, ApprovalStatus, RiskLevel, ActionType
 20 | )
 21 | from ..controller.mission import MissionController
 22 | 
 23 | 
 24 | router = APIRouter(tags=["Missions"])
 25 | 
 26 | 
 27 | # ═══════════════════════════════════════════════════════════════
 28 | # Dependencies
 29 | # ═══════════════════════════════════════════════════════════════
 30 | 
 31 | async def get_controller(request: Request) -> MissionController:
 32 |     """Get the mission controller from app state."""
 33 |     if not hasattr(request.app.state, 'controller') or not request.app.state.controller:
 34 |         raise HTTPException(
 35 |             status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
 36 |             detail="Controller not initialized"
 37 |         )
 38 |     return request.app.state.controller
 39 | 
 40 | 
 41 | # ═══════════════════════════════════════════════════════════════
 42 | # Response Models
 43 | # ═══════════════════════════════════════════════════════════════
 44 | 
 45 | class MissionResponse(BaseModel):
 46 |     """Mission response model."""
 47 |     mission_id: str
 48 |     name: str
 49 |     status: str
 50 |     message: str
 51 | 
 52 | 
 53 | class MissionStatusResponse(BaseModel):
 54 |     """Comprehensive mission status response."""
 55 |     mission_id: str
 56 |     name: Optional[str] = None
 57 |     status: Optional[str] = None
 58 |     scope: Optional[List[str]] = None
 59 |     goals: Optional[Dict[str, str]] = None
 60 |     statistics: Optional[Dict[str, int]] = None
 61 |     target_count: int = 0
 62 |     vuln_count: int = 0
 63 |     created_at: Optional[str] = None
 64 |     started_at: Optional[str] = None
 65 |     completed_at: Optional[str] = None
 66 | 
 67 | 
 68 | class TargetResponse(BaseModel):
 69 |     """Target response model."""
 70 |     target_id: str
 71 |     ip: str
 72 |     hostname: Optional[str] = None
 73 |     os: Optional[str] = None
 74 |     status: str
 75 |     priority: str
 76 |     risk_score: Optional[float] = None
 77 |     ports: Dict[str, str] = {}
 78 | 
 79 | 
 80 | class VulnerabilityResponse(BaseModel):
 81 |     """Vulnerability response model."""
 82 |     vuln_id: str
 83 |     target_id: str
 84 |     type: str
 85 |     name: Optional[str] = None
 86 |     severity: str
 87 |     cvss: Optional[float] = None
 88 |     status: str
 89 |     exploit_available: bool = False
 90 | 
 91 | 
 92 | class CredentialResponse(BaseModel):
 93 |     """Credential response model."""
 94 |     cred_id: str
 95 |     target_id: str
 96 |     type: str
 97 |     username: str
 98 |     domain: Optional[str] = None
 99 |     privilege_level: str
100 |     source: Optional[str] = None
101 |     verified: bool = False
102 |     created_at: Optional[str] = None
103 | 
104 | 
105 | class SessionResponse(BaseModel):
106 |     """Session response model."""
107 |     session_id: str
108 |     target_id: str
109 |     type: str
110 |     user: str
111 |     privilege: str
112 |     status: str
113 |     established_at: Optional[str] = None
114 |     last_activity: Optional[str] = None
115 | 
116 | 
117 | # ═══════════════════════════════════════════════════════════════
118 | # HITL Request/Response Models
119 | # ═══════════════════════════════════════════════════════════════
120 | 
121 | class ApprovalRequest(BaseModel):
122 |     """Request model for approving/rejecting actions."""
123 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
124 | 
125 | 
126 | class RejectionRequest(BaseModel):
127 |     """Request model for rejecting actions."""
128 |     rejection_reason: Optional[str] = Field(None, description="Reason for rejection")
129 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
130 | 
131 | 
132 | class ChatRequest(BaseModel):
133 |     """Request model for chat messages."""
134 |     content: str = Field(..., min_length=1, max_length=4096, description="Message content")
135 |     related_task_id: Optional[str] = Field(None, description="Related task ID")
136 |     related_action_id: Optional[str] = Field(None, description="Related approval action ID")
137 | 
138 | 
139 | class ApprovalResponse(BaseModel):
140 |     """Response model for approval operations."""
141 |     success: bool
142 |     message: str
143 |     action_id: str
144 |     mission_status: str
145 | 
146 | 
147 | class PendingApprovalResponse(BaseModel):
148 |     """Response model for pending approvals."""
149 |     action_id: str
150 |     action_type: str
151 |     action_description: str
152 |     target_ip: Optional[str] = None
153 |     risk_level: str
154 |     risk_reasons: List[str] = []
155 |     potential_impact: Optional[str] = None
156 |     command_preview: Optional[str] = None
157 |     requested_at: str
158 |     expires_at: Optional[str] = None
159 | 
160 | 
161 | class ChatMessageResponse(BaseModel):
162 |     """Response model for chat messages."""
163 |     id: str
164 |     role: str
165 |     content: str
166 |     timestamp: str
167 |     related_task_id: Optional[str] = None
168 |     related_action_id: Optional[str] = None
169 | 
170 | 
171 | # ═══════════════════════════════════════════════════════════════
172 | # Mission Endpoints
173 | # ═══════════════════════════════════════════════════════════════
174 | 
175 | @router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
176 | async def create_mission(
177 |     mission_data: MissionCreate,
178 |     controller: MissionController = Depends(get_controller)
179 | ) -> MissionResponse:
180 |     """
181 |     Create a new mission.
182 |     
183 |     - **name**: Mission name
184 |     - **description**: Optional description
185 |     - **scope**: List of target ranges (CIDRs, IPs, domains)
186 |     - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
187 |     - **constraints**: Optional constraints (e.g., {"stealth": true})
188 |     """
189 |     try:
190 |         mission_id = await controller.create_mission(mission_data)
191 |         
192 |         return MissionResponse(
193 |             mission_id=mission_id,
194 |             name=mission_data.name,
195 |             status="created",
196 |             message="Mission created successfully"
197 |         )
198 |     except Exception as e:
199 |         raise HTTPException(
200 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
201 |             detail=f"Failed to create mission: {str(e)}"
202 |         )
203 | 
204 | 
205 | @router.get("/missions", response_model=List[str])
206 | async def list_missions(
207 |     controller: MissionController = Depends(get_controller)
208 | ) -> List[str]:
209 |     """List all active mission IDs."""
210 |     return await controller.get_active_missions()
211 | 
212 | 
213 | @router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
214 | async def get_mission(
215 |     mission_id: str,
216 |     controller: MissionController = Depends(get_controller)
217 | ) -> MissionStatusResponse:
218 |     """Get mission status and details."""
219 |     status_data = await controller.get_mission_status(mission_id)
220 |     
221 |     if not status_data:
222 |         raise HTTPException(
223 |             status_code=status.HTTP_404_NOT_FOUND,
224 |             detail=f"Mission {mission_id} not found"
225 |         )
226 |     
227 |     return MissionStatusResponse(**status_data)
228 | 
229 | 
230 | @router.post("/missions/{mission_id}/start", response_model=MissionResponse)
231 | async def start_mission(
232 |     mission_id: str,
233 |     controller: MissionController = Depends(get_controller)
234 | ) -> MissionResponse:
235 |     """Start a mission."""
236 |     # Check if mission exists first
237 |     mission_data = await controller.get_mission_status(mission_id)
238 |     if not mission_data:
239 |         raise HTTPException(
240 |             status_code=status.HTTP_404_NOT_FOUND,
241 |             detail=f"Mission {mission_id} not found"
242 |         )
243 |     
244 |     result = await controller.start_mission(mission_id)
245 |     
246 |     if not result:
247 |         raise HTTPException(
248 |             status_code=status.HTTP_400_BAD_REQUEST,
249 |             detail=f"Failed to start mission {mission_id}"
250 |         )
251 |     
252 |     return MissionResponse(
253 |         mission_id=mission_id,
254 |         name="",
255 |         status="running",
256 |         message="Mission started successfully"
257 |     )
258 | 
259 | 
260 | @router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
261 | async def pause_mission(
262 |     mission_id: str,
263 |     controller: MissionController = Depends(get_controller)
264 | ) -> MissionResponse:
265 |     """Pause a running mission."""
266 |     result = await controller.pause_mission(mission_id)
267 |     
268 |     if not result:
269 |         raise HTTPException(
270 |             status_code=status.HTTP_400_BAD_REQUEST,
271 |             detail=f"Failed to pause mission {mission_id}"
272 |         )
273 |     
274 |     return MissionResponse(
275 |         mission_id=mission_id,
276 |         name="",
277 |         status="paused",
278 |         message="Mission paused successfully"
279 |     )
280 | 
281 | 
282 | @router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
283 | async def resume_mission(
284 |     mission_id: str,
285 |     controller: MissionController = Depends(get_controller)
286 | ) -> MissionResponse:
287 |     """Resume a paused mission."""
288 |     result = await controller.resume_mission(mission_id)
289 |     
290 |     if not result:
291 |         raise HTTPException(
292 |             status_code=status.HTTP_400_BAD_REQUEST,
293 |             detail=f"Failed to resume mission {mission_id}"
294 |         )
295 |     
296 |     return MissionResponse(
297 |         mission_id=mission_id,
298 |         name="",
299 |         status="running",
300 |         message="Mission resumed successfully"
301 |     )
302 | 
303 | 
304 | @router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
305 | async def stop_mission(
306 |     mission_id: str,
307 |     controller: MissionController = Depends(get_controller)
308 | ) -> MissionResponse:
309 |     """Stop a mission."""
310 |     # Check if mission exists first
311 |     mission_data = await controller.get_mission_status(mission_id)
312 |     if not mission_data:
313 |         raise HTTPException(
314 |             status_code=status.HTTP_404_NOT_FOUND,
315 |             detail=f"Mission {mission_id} not found"
316 |         )
317 |     
318 |     result = await controller.stop_mission(mission_id)
319 |     
320 |     if not result:
321 |         raise HTTPException(
322 |             status_code=status.HTTP_400_BAD_REQUEST,
323 |             detail=f"Failed to stop mission {mission_id}"
324 |         )
325 |     
326 |     return MissionResponse(
327 |         mission_id=mission_id,
328 |         name="",
329 |         status="completed",
330 |         message="Mission stopped successfully"
331 |     )
332 | 
333 | 
334 | # ═══════════════════════════════════════════════════════════════
335 | # Target Endpoints
336 | # ═══════════════════════════════════════════════════════════════
337 | 
338 | @router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
339 | async def list_targets(
340 |     mission_id: str,
341 |     controller: MissionController = Depends(get_controller)
342 | ) -> List[TargetResponse]:
343 |     """List all targets for a mission."""
344 |     blackboard = controller.blackboard
345 |     
346 |     target_keys = await blackboard.get_mission_targets(mission_id)
347 |     targets = []
348 |     
349 |     for target_key in target_keys:
350 |         target_id = target_key.replace("target:", "")
351 |         target_data = await blackboard.get_target(target_id)
352 |         
353 |         if target_data:
354 |             ports = await blackboard.get_target_ports(target_id)
355 |             targets.append(TargetResponse(
356 |                 target_id=target_id,
357 |                 ip=target_data.get("ip", ""),
358 |                 hostname=target_data.get("hostname"),
359 |                 os=target_data.get("os"),
360 |                 status=target_data.get("status", "unknown"),
361 |                 priority=target_data.get("priority", "medium"),
362 |                 risk_score=target_data.get("risk_score"),
363 |                 ports=ports
364 |             ))
365 |     
366 |     return targets
367 | 
368 | 
369 | @router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
370 | async def get_target(
371 |     mission_id: str,
372 |     target_id: str,
373 |     controller: MissionController = Depends(get_controller)
374 | ) -> TargetResponse:
375 |     """Get a specific target."""
376 |     blackboard = controller.blackboard
377 |     
378 |     target_data = await blackboard.get_target(target_id)
379 |     
380 |     if not target_data:
381 |         raise HTTPException(
382 |             status_code=status.HTTP_404_NOT_FOUND,
383 |             detail=f"Target {target_id} not found"
384 |         )
385 |     
386 |     ports = await blackboard.get_target_ports(target_id)
387 |     
388 |     return TargetResponse(
389 |         target_id=target_id,
390 |         ip=target_data.get("ip", ""),
391 |         hostname=target_data.get("hostname"),
392 |         os=target_data.get("os"),
393 |         status=target_data.get("status", "unknown"),
394 |         priority=target_data.get("priority", "medium"),
395 |         risk_score=target_data.get("risk_score"),
396 |         ports=ports
397 |     )
398 | 
399 | 
400 | # ═══════════════════════════════════════════════════════════════
401 | # Vulnerability Endpoints
402 | # ═══════════════════════════════════════════════════════════════
403 | 
404 | @router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
405 | async def list_vulnerabilities(
406 |     mission_id: str,
407 |     controller: MissionController = Depends(get_controller)
408 | ) -> List[VulnerabilityResponse]:
409 |     """List all vulnerabilities for a mission."""
410 |     blackboard = controller.blackboard
411 |     
412 |     vuln_keys = await blackboard.get_mission_vulns(mission_id)
413 |     vulns = []
414 |     
415 |     for vuln_key in vuln_keys:
416 |         vuln_id = vuln_key.replace("vuln:", "")
417 |         vuln_data = await blackboard.get_vulnerability(vuln_id)
418 |         
419 |         if vuln_data:
420 |             vulns.append(VulnerabilityResponse(
421 |                 vuln_id=vuln_id,
422 |                 target_id=str(vuln_data.get("target_id", "")),
423 |                 type=vuln_data.get("type", ""),
424 |                 name=vuln_data.get("name"),
425 |                 severity=vuln_data.get("severity", "medium"),
426 |                 cvss=vuln_data.get("cvss"),
427 |                 status=vuln_data.get("status", "discovered"),
428 |                 exploit_available=vuln_data.get("exploit_available", False)
429 |             ))
430 |     
431 |     return vulns
432 | 
433 | 
434 | # ═══════════════════════════════════════════════════════════════
435 | # Statistics Endpoint
436 | # ═══════════════════════════════════════════════════════════════
437 | 
438 | # ═══════════════════════════════════════════════════════════════
439 | # Credential Endpoints
440 | # ═══════════════════════════════════════════════════════════════
441 | 
442 | @router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
443 | async def list_credentials(
444 |     mission_id: str,
445 |     controller: MissionController = Depends(get_controller)
446 | ) -> List[CredentialResponse]:
447 |     """List all credentials for a mission."""
448 |     blackboard = controller.blackboard
449 |     
450 |     cred_keys = await blackboard.get_mission_creds(mission_id)
451 |     creds = []
452 |     
453 |     for cred_key in cred_keys:
454 |         cred_id = cred_key.replace("cred:", "")
455 |         cred_data = await blackboard.get_credential(cred_id)
456 |         
457 |         if cred_data:
458 |             creds.append(CredentialResponse(
459 |                 cred_id=cred_id,
460 |                 target_id=str(cred_data.get("target_id", "")),
461 |                 type=cred_data.get("type", ""),
462 |                 username=cred_data.get("username", ""),
463 |                 domain=cred_data.get("domain"),
464 |                 privilege_level=cred_data.get("privilege_level", "user"),
465 |                 source=cred_data.get("source"),
466 |                 verified=cred_data.get("verified", "false").lower() == "true",
467 |                 created_at=cred_data.get("created_at")
468 |             ))
469 |     
470 |     return creds
471 | 
472 | 
473 | # ═══════════════════════════════════════════════════════════════
474 | # Session Endpoints
475 | # ═══════════════════════════════════════════════════════════════
476 | 
477 | @router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
478 | async def list_sessions(
479 |     mission_id: str,
480 |     controller: MissionController = Depends(get_controller)
481 | ) -> List[SessionResponse]:
482 |     """List all active sessions for a mission."""
483 |     blackboard = controller.blackboard
484 |     
485 |     session_keys = await blackboard.get_mission_sessions(mission_id)
486 |     sessions = []
487 |     
488 |     for session_key in session_keys:
489 |         session_id = session_key.replace("session:", "")
490 |         session_data = await blackboard.get_session(session_id)
491 |         
492 |         if session_data:
493 |             sessions.append(SessionResponse(
494 |                 session_id=session_id,
495 |                 target_id=str(session_data.get("target_id", "")),
496 |                 type=session_data.get("type", "shell"),
497 |                 user=session_data.get("user", "unknown"),
498 |                 privilege=session_data.get("privilege", "user"),
499 |                 status=session_data.get("status", "unknown"),
500 |                 established_at=session_data.get("established_at"),
501 |                 last_activity=session_data.get("last_activity")
502 |             ))
503 |     
504 |     return sessions
505 | 
506 | 
507 | # ═══════════════════════════════════════════════════════════════
508 | # Statistics Endpoint
509 | # ═══════════════════════════════════════════════════════════════
510 | 
511 | @router.get("/missions/{mission_id}/stats")
512 | async def get_mission_stats(
513 |     mission_id: str,
514 |     controller: MissionController = Depends(get_controller)
515 | ) -> Dict[str, Any]:
516 |     """Get mission statistics."""
517 |     blackboard = controller.blackboard
518 |     
519 |     stats = await blackboard.get_mission_stats(mission_id)
520 |     goals = await blackboard.get_mission_goals(mission_id)
521 |     
522 |     # Count achieved goals
523 |     achieved = sum(1 for g in goals.values() if g == "achieved")
524 |     total = len(goals)
525 |     
526 |     return {
527 |         "targets_discovered": stats.targets_discovered,
528 |         "vulns_found": stats.vulns_found,
529 |         "creds_harvested": stats.creds_harvested,
530 |         "sessions_established": stats.sessions_established,
531 |         "goals_achieved": achieved,
532 |         "goals_total": total,
533 |         "completion_percentage": (achieved / total * 100) if total > 0 else 0
534 |     }
535 | 
536 | 
537 | # ═══════════════════════════════════════════════════════════════
538 | # HITL (Human-in-the-Loop) Endpoints
539 | # ═══════════════════════════════════════════════════════════════
540 | 
541 | @router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
542 | async def list_pending_approvals(
543 |     mission_id: str,
544 |     controller: MissionController = Depends(get_controller)
545 | ) -> List[PendingApprovalResponse]:
546 |     """
547 |     List all pending approval requests for a mission.
548 |     
549 |     These are high-risk actions waiting for user consent.
550 |     """
551 |     # Check if mission exists first
552 |     mission_data = await controller.get_mission_status(mission_id)
553 |     if not mission_data:
554 |         raise HTTPException(
555 |             status_code=status.HTTP_404_NOT_FOUND,
556 |             detail=f"Mission {mission_id} not found"
557 |         )
558 |     
559 |     pending = await controller.get_pending_approvals(mission_id)
560 |     return [PendingApprovalResponse(**p) for p in pending]
561 | 
562 | 
563 | @router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
564 | async def approve_action(
565 |     mission_id: str,
566 |     action_id: str,
567 |     request_data: ApprovalRequest = None,
568 |     controller: MissionController = Depends(get_controller)
569 | ) -> ApprovalResponse:
570 |     """
571 |     Approve a pending action.
572 |     
573 |     This allows the action to proceed and resumes mission execution.
574 |     
575 |     - **action_id**: ID of the action to approve
576 |     - **user_comment**: Optional comment explaining the approval
577 |     """
578 |     # Check if mission exists first
579 |     mission_data = await controller.get_mission_status(mission_id)
580 |     if not mission_data:
581 |         raise HTTPException(
582 |             status_code=status.HTTP_404_NOT_FOUND,
583 |             detail=f"Mission {mission_id} not found"
584 |         )
585 |     
586 |     user_comment = request_data.user_comment if request_data else None
587 |     
588 |     result = await controller.approve_action(
589 |         mission_id=mission_id,
590 |         action_id=action_id,
591 |         user_comment=user_comment
592 |     )
593 |     
594 |     if not result:
595 |         raise HTTPException(
596 |             status_code=status.HTTP_404_NOT_FOUND,
597 |             detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
598 |         )
599 |     
600 |     # Get current mission status
601 |     current_status = mission_data.get("status", "unknown")
602 |     
603 |     return ApprovalResponse(
604 |         success=True,
605 |         message="Action approved successfully. Mission execution resumed.",
606 |         action_id=action_id,
607 |         mission_status=current_status
608 |     )
609 | 
610 | 
611 | @router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
612 | async def reject_action(
613 |     mission_id: str,
614 |     action_id: str,
615 |     request_data: RejectionRequest = None,
616 |     controller: MissionController = Depends(get_controller)
617 | ) -> ApprovalResponse:
618 |     """
619 |     Reject a pending action.
620 |     
621 |     The system will attempt to find an alternative approach.
622 |     
623 |     - **action_id**: ID of the action to reject
624 |     - **rejection_reason**: Reason for rejection
625 |     - **user_comment**: Optional additional comment
626 |     """
627 |     rejection_reason = request_data.rejection_reason if request_data else None
628 |     user_comment = request_data.user_comment if request_data else None
629 |     
630 |     result = await controller.reject_action(
631 |         mission_id=mission_id,
632 |         action_id=action_id,
633 |         rejection_reason=rejection_reason,
634 |         user_comment=user_comment
635 |     )
636 |     
637 |     if not result:
638 |         raise HTTPException(
639 |             status_code=status.HTTP_400_BAD_REQUEST,
640 |             detail=f"Failed to reject action {action_id}. It may not exist or belong to this mission."
641 |         )
642 |     
643 |     # Get current mission status
644 |     mission_data = await controller.get_mission_status(mission_id)
645 |     current_status = mission_data.get("status", "unknown") if mission_data else "unknown"
646 |     
647 |     return ApprovalResponse(
648 |         success=True,
649 |         message="Action rejected. System will seek alternatives.",
650 |         action_id=action_id,
651 |         mission_status=current_status
652 |     )
653 | 
654 | 
655 | @router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
656 | async def send_chat_message(
657 |     mission_id: str,
658 |     request_data: ChatRequest,
659 |     controller: MissionController = Depends(get_controller)
660 | ) -> ChatMessageResponse:
661 |     """
662 |     Send a chat message to interact with the mission.
663 |     
664 |     This allows users to:
665 |     - Ask about mission status
666 |     - Give instructions (pause, resume)
667 |     - Query pending approvals
668 |     
669 |     - **content**: Message content
670 |     - **related_task_id**: Optional related task
671 |     - **related_action_id**: Optional related approval action
672 |     """
673 |     try:
674 |         message = await controller.send_chat_message(
675 |             mission_id=mission_id,
676 |             content=request_data.content,
677 |             related_task_id=request_data.related_task_id,
678 |             related_action_id=request_data.related_action_id
679 |         )
680 |         
681 |         return ChatMessageResponse(
682 |             id=str(message.id),
683 |             role=message.role,
684 |             content=message.content,
685 |             timestamp=message.timestamp.isoformat(),
686 |             related_task_id=str(message.related_task_id) if message.related_task_id else None,
687 |             related_action_id=str(message.related_action_id) if message.related_action_id else None
688 |         )
689 |     except Exception as e:
690 |         # Log the error for debugging
691 |         import logging
692 |         logging.error(f"Chat message error for mission {mission_id}: {e}")
693 |         raise HTTPException(
694 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
695 |             detail=f"Failed to process chat message: {str(e)}"
696 |         )
697 | 
698 | 
699 | @router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
700 | async def get_chat_history(
701 |     mission_id: str,
702 |     limit: int = 50,
703 |     controller: MissionController = Depends(get_controller)
704 | ) -> List[ChatMessageResponse]:
705 |     """
706 |     Get chat history for a mission.
707 |     
708 |     - **limit**: Maximum number of messages to return (default 50)
709 |     """
710 |     history = await controller.get_chat_history(mission_id, limit)
711 |     return [ChatMessageResponse(**msg) for msg in history]

<environment_details>
# VSCode Visible Files
docs/COMPREHENSIVE_TEST_REPORT.md

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:03:13.592Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.01

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
You have not created a todo list yet. Create one with `update_todo_list` if your task is complicated or involves multiple steps.
</environment_details>

---

**Assistant:**


Now I'll create a todo list to track the fixes needed for the 16 test failures:

[Tool Use: update_todo_list]
Todos: [ ] Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors
[ ] Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist
[ ] Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history
[ ] Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats
[ ] Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format

---

**User:**

[Tool]
Todo list updated successfully.
<environment_details>
# VSCode Visible Files
docs/COMPREHENSIVE_TEST_REPORT.md

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:03:43.310Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.02

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Let me start by examining the controller to understand how it handles mission validation:

[Tool Use: read_file]
Files: [
  {
    "path": "src/controller/mission.py"
  }
]

---

**User:**

[Tool]
File: src/controller/mission.py
Lines 1-1183:
   1 | # ═══════════════════════════════════════════════════════════════
   2 | # RAGLOX v3.0 - Mission Controller
   3 | # Central orchestration for missions
   4 | # ═══════════════════════════════════════════════════════════════
   5 | 
   6 | import asyncio
   7 | from datetime import datetime, timedelta
   8 | from typing import Any, Dict, List, Optional, Set
   9 | from uuid import UUID, uuid4
  10 | 
  11 | # Note: uuid4 is used for generating new UUIDs in HITL functionality
  12 | import logging
  13 | 
  14 | from ..core.blackboard import Blackboard
  15 | from ..core.models import (
  16 |     Mission, MissionCreate, MissionStatus, MissionStats,
  17 |     Target, TargetStatus,
  18 |     Vulnerability, Severity,
  19 |     Task, TaskType, TaskStatus, SpecialistType,
  20 |     GoalStatus, GoalAchievedEvent,
  21 |     # HITL Models
  22 |     ApprovalAction, ApprovalStatus, ApprovalRequestEvent, ApprovalResponseEvent,
  23 |     ActionType, RiskLevel, ChatMessage, ChatEvent
  24 | )
  25 | from ..core.config import Settings, get_settings
  26 | from ..specialists.recon import ReconSpecialist
  27 | from ..specialists.attack import AttackSpecialist
  28 | 
  29 | 
  30 | class MissionController:
  31 |     """
  32 |     Mission Controller - Central orchestration for RAGLOX missions.
  33 |     
  34 |     Responsibilities:
  35 |     - Mission lifecycle management (create, start, pause, resume, stop)
  36 |     - Specialist coordination
  37 |     - Goal tracking
  38 |     - Statistics monitoring
  39 |     - Task prioritization
  40 |     
  41 |     Design Principles:
  42 |     - Single point of control for missions
  43 |     - Reads from and writes to Blackboard
  44 |     - Does not directly communicate with specialists
  45 |     - Uses Pub/Sub for control commands
  46 |     """
  47 |     
  48 |     def __init__(
  49 |         self,
  50 |         blackboard: Optional[Blackboard] = None,
  51 |         settings: Optional[Settings] = None
  52 |     ):
  53 |         """
  54 |         Initialize the Mission Controller.
  55 |         
  56 |         Args:
  57 |             blackboard: Blackboard instance
  58 |             settings: Application settings
  59 |         """
  60 |         self.settings = settings or get_settings()
  61 |         self.blackboard = blackboard or Blackboard(settings=self.settings)
  62 |         
  63 |         # Logging
  64 |         self.logger = logging.getLogger("raglox.controller.mission")
  65 |         
  66 |         # State
  67 |         self._active_missions: Dict[str, Dict[str, Any]] = {}
  68 |         self._running = False
  69 |         
  70 |         # Specialist instances
  71 |         self._specialists: Dict[str, List[Any]] = {
  72 |             "recon": [],
  73 |             "attack": [],
  74 |         }
  75 |         
  76 |         # Monitor interval (seconds)
  77 |         self._monitor_interval = 5
  78 |         
  79 |         # Task Watchdog settings
  80 |         self._watchdog_interval = 30  # Check every 30 seconds
  81 |         self._task_timeout = timedelta(minutes=5)  # Tasks stale after 5 minutes
  82 |         self._max_task_retries = 3  # Max retries before marking FAILED
  83 |         
  84 |         # HITL: Pending approval actions
  85 |         self._pending_approvals: Dict[str, ApprovalAction] = {}
  86 |         
  87 |         # HITL: Chat history per mission
  88 |         self._chat_history: Dict[str, List[ChatMessage]] = {}
  89 |     
  90 |     # ═══════════════════════════════════════════════════════════
  91 |     # Mission Lifecycle
  92 |     # ═══════════════════════════════════════════════════════════
  93 |     
  94 |     async def create_mission(self, mission_data: MissionCreate) -> str:
  95 |         """
  96 |         Create a new mission.
  97 |         
  98 |         Args:
  99 |             mission_data: Mission creation data
 100 |             
 101 |         Returns:
 102 |             Mission ID
 103 |         """
 104 |         self.logger.info(f"Creating mission: {mission_data.name}")
 105 |         
 106 |         # Connect to Blackboard if needed
 107 |         if not await self.blackboard.health_check():
 108 |             await self.blackboard.connect()
 109 |         
 110 |         # Convert goals list to dict with status
 111 |         goals_dict = {
 112 |             goal: GoalStatus.PENDING for goal in mission_data.goals
 113 |         }
 114 |         
 115 |         # Create Mission object
 116 |         mission = Mission(
 117 |             name=mission_data.name,
 118 |             description=mission_data.description,
 119 |             scope=mission_data.scope,
 120 |             goals=goals_dict,
 121 |             constraints=mission_data.constraints,
 122 |             status=MissionStatus.CREATED
 123 |         )
 124 |         
 125 |         # Store in Blackboard
 126 |         mission_id = await self.blackboard.create_mission(mission)
 127 |         
 128 |         # Track locally
 129 |         self._active_missions[mission_id] = {
 130 |             "mission": mission,
 131 |             "status": MissionStatus.CREATED,
 132 |             "specialists": [],
 133 |             "created_at": datetime.utcnow()
 134 |         }
 135 |         
 136 |         self.logger.info(f"Mission created: {mission_id}")
 137 |         return mission_id
 138 |     
 139 |     async def start_mission(self, mission_id: str) -> bool:
 140 |         """
 141 |         Start a mission.
 142 |         
 143 |         Args:
 144 |             mission_id: Mission to start
 145 |             
 146 |         Returns:
 147 |             True if started successfully
 148 |         """
 149 |         self.logger.info(f"Starting mission: {mission_id}")
 150 |         
 151 |         # Verify mission exists
 152 |         mission_data = await self.blackboard.get_mission(mission_id)
 153 |         if not mission_data:
 154 |             self.logger.error(f"Mission {mission_id} not found")
 155 |             return False
 156 |         
 157 |         # Check current status
 158 |         current_status = mission_data.get("status")
 159 |         if current_status not in ("created", "paused"):
 160 |             self.logger.error(f"Cannot start mission in status: {current_status}")
 161 |             return False
 162 |         
 163 |         # Update status to starting
 164 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.STARTING)
 165 |         
 166 |         # Create initial network scan task based on scope
 167 |         mission_scope = mission_data.get("scope", [])
 168 |         if isinstance(mission_scope, str):
 169 |             import json
 170 |             mission_scope = json.loads(mission_scope)
 171 |         
 172 |         if mission_scope:
 173 |             await self._create_initial_scan_task(mission_id)
 174 |         
 175 |         # Start specialists
 176 |         await self._start_specialists(mission_id)
 177 |         
 178 |         # Update status to running
 179 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
 180 |         
 181 |         # Update local tracking
 182 |         if mission_id in self._active_missions:
 183 |             self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
 184 |         
 185 |         # Start monitor loop
 186 |         if not self._running:
 187 |             self._running = True
 188 |             asyncio.create_task(self._monitor_loop())
 189 |             asyncio.create_task(self._watchdog_loop())  # Start Task Watchdog
 190 |         
 191 |         self.logger.info(f"Mission {mission_id} started successfully")
 192 |         return True
 193 |     
 194 |     async def pause_mission(self, mission_id: str) -> bool:
 195 |         """
 196 |         Pause a running mission.
 197 |         
 198 |         Args:
 199 |             mission_id: Mission to pause
 200 |             
 201 |         Returns:
 202 |             True if paused successfully
 203 |         """
 204 |         self.logger.info(f"Pausing mission: {mission_id}")
 205 |         
 206 |         mission_data = await self.blackboard.get_mission(mission_id)
 207 |         if not mission_data:
 208 |             return False
 209 |         
 210 |         if mission_data.get("status") != "running":
 211 |             self.logger.error("Can only pause running missions")
 212 |             return False
 213 |         
 214 |         # Send pause command to specialists
 215 |         await self._send_control_command(mission_id, "pause")
 216 |         
 217 |         # Update status
 218 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.PAUSED)
 219 |         
 220 |         if mission_id in self._active_missions:
 221 |             self._active_missions[mission_id]["status"] = MissionStatus.PAUSED
 222 |         
 223 |         self.logger.info(f"Mission {mission_id} paused")
 224 |         return True
 225 |     
 226 |     async def resume_mission(self, mission_id: str) -> bool:
 227 |         """
 228 |         Resume a paused mission.
 229 |         
 230 |         Args:
 231 |             mission_id: Mission to resume
 232 |             
 233 |         Returns:
 234 |             True if resumed successfully
 235 |         """
 236 |         self.logger.info(f"Resuming mission: {mission_id}")
 237 |         
 238 |         mission_data = await self.blackboard.get_mission(mission_id)
 239 |         if not mission_data:
 240 |             return False
 241 |         
 242 |         if mission_data.get("status") != "paused":
 243 |             self.logger.error("Can only resume paused missions")
 244 |             return False
 245 |         
 246 |         # Send resume command to specialists
 247 |         await self._send_control_command(mission_id, "resume")
 248 |         
 249 |         # Update status
 250 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
 251 |         
 252 |         if mission_id in self._active_missions:
 253 |             self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
 254 |         
 255 |         self.logger.info(f"Mission {mission_id} resumed")
 256 |         return True
 257 |     
 258 |     async def stop_mission(self, mission_id: str) -> bool:
 259 |         """
 260 |         Stop a mission.
 261 |         
 262 |         Args:
 263 |             mission_id: Mission to stop
 264 |             
 265 |         Returns:
 266 |             True if stopped successfully
 267 |         """
 268 |         self.logger.info(f"Stopping mission: {mission_id}")
 269 |         
 270 |         mission_data = await self.blackboard.get_mission(mission_id)
 271 |         if not mission_data:
 272 |             return False
 273 |         
 274 |         # Update status to completing
 275 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.COMPLETING)
 276 |         
 277 |         # Send stop command to specialists
 278 |         await self._send_control_command(mission_id, "stop")
 279 |         
 280 |         # Stop specialists
 281 |         await self._stop_specialists(mission_id)
 282 |         
 283 |         # Update status to completed
 284 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.COMPLETED)
 285 |         
 286 |         # Clean up local tracking
 287 |         if mission_id in self._active_missions:
 288 |             del self._active_missions[mission_id]
 289 |         
 290 |         self.logger.info(f"Mission {mission_id} stopped")
 291 |         return True
 292 |     
 293 |     async def get_mission_status(self, mission_id: str) -> Optional[Dict[str, Any]]:
 294 |         """
 295 |         Get comprehensive mission status.
 296 |         
 297 |         First tries to get mission from Redis, then falls back to local cache.
 298 |         
 299 |         Args:
 300 |             mission_id: Mission ID
 301 |             
 302 |         Returns:
 303 |             Status dictionary
 304 |         """
 305 |         mission_data = await self.blackboard.get_mission(mission_id)
 306 |         
 307 |         # If not in Redis, check local cache (for in-memory missions)
 308 |         if not mission_data:
 309 |             if mission_id in self._active_missions:
 310 |                 local_mission = self._active_missions[mission_id]
 311 |                 mission = local_mission.get("mission")
 312 |                 if mission:
 313 |                     # Reconstruct from local cache
 314 |                     goals_dict = {}
 315 |                     if hasattr(mission, 'goals'):
 316 |                         goals_dict = {
 317 |                             k: v.value if hasattr(v, 'value') else str(v) 
 318 |                             for k, v in mission.goals.items()
 319 |                         }
 320 |                     
 321 |                     return {
 322 |                         "mission_id": mission_id,
 323 |                         "name": getattr(mission, 'name', 'Unknown'),
 324 |                         "status": local_mission.get("status", MissionStatus.CREATED).value if hasattr(local_mission.get("status"), 'value') else str(local_mission.get("status", "unknown")),
 325 |                         "scope": getattr(mission, 'scope', []),
 326 |                         "goals": goals_dict,
 327 |                         "statistics": {
 328 |                             "targets_discovered": 0,
 329 |                             "vulns_found": 0,
 330 |                             "creds_harvested": 0,
 331 |                             "sessions_established": 0,
 332 |                             "goals_achieved": 0
 333 |                         },
 334 |                         "target_count": 0,
 335 |                         "vuln_count": 0,
 336 |                         "created_at": local_mission.get("created_at", datetime.utcnow()).isoformat() if hasattr(local_mission.get("created_at"), 'isoformat') else str(local_mission.get("created_at")),
 337 |                         "started_at": None,
 338 |                         "completed_at": None
 339 |                     }
 340 |             return None
 341 |         
 342 |         # Get statistics
 343 |         stats = await self.blackboard.get_mission_stats(mission_id)
 344 |         
 345 |         # Get goals
 346 |         goals = await self.blackboard.get_mission_goals(mission_id)
 347 |         
 348 |         # Get targets
 349 |         targets = await self.blackboard.get_mission_targets(mission_id)
 350 |         
 351 |         # Get vulnerabilities
 352 |         vulns = await self.blackboard.get_mission_vulns(mission_id)
 353 |         
 354 |         return {
 355 |             "mission_id": mission_id,
 356 |             "name": mission_data.get("name"),
 357 |             "status": mission_data.get("status"),
 358 |             "scope": mission_data.get("scope"),
 359 |             "goals": goals,
 360 |             "statistics": {
 361 |                 "targets_discovered": stats.targets_discovered,
 362 |                 "vulns_found": stats.vulns_found,
 363 |                 "creds_harvested": stats.creds_harvested,
 364 |                 "sessions_established": stats.sessions_established,
 365 |                 "goals_achieved": stats.goals_achieved
 366 |             },
 367 |             "target_count": len(targets),
 368 |             "vuln_count": len(vulns),
 369 |             "created_at": mission_data.get("created_at"),
 370 |             "started_at": mission_data.get("started_at"),
 371 |             "completed_at": mission_data.get("completed_at")
 372 |         }
 373 |     
 374 |     # ═══════════════════════════════════════════════════════════
 375 |     # Specialist Management
 376 |     # ═══════════════════════════════════════════════════════════
 377 |     
 378 |     async def _start_specialists(self, mission_id: str) -> None:
 379 |         """Start specialist workers for a mission."""
 380 |         self.logger.info(f"Starting specialists for mission {mission_id}")
 381 |         
 382 |         # Create and start Recon specialist
 383 |         recon = ReconSpecialist(
 384 |             blackboard=self.blackboard,
 385 |             settings=self.settings
 386 |         )
 387 |         await recon.start(mission_id)
 388 |         self._specialists["recon"].append(recon)
 389 |         
 390 |         # Create and start Attack specialist
 391 |         attack = AttackSpecialist(
 392 |             blackboard=self.blackboard,
 393 |             settings=self.settings
 394 |         )
 395 |         await attack.start(mission_id)
 396 |         self._specialists["attack"].append(attack)
 397 |         
 398 |         self.logger.info(f"Specialists started for mission {mission_id}")
 399 |     
 400 |     async def _stop_specialists(self, mission_id: str) -> None:
 401 |         """Stop specialist workers for a mission."""
 402 |         self.logger.info(f"Stopping specialists for mission {mission_id}")
 403 |         
 404 |         # Stop all specialists
 405 |         for specialist_type, specialists in self._specialists.items():
 406 |             for specialist in specialists:
 407 |                 if specialist.current_mission == mission_id:
 408 |                     await specialist.stop()
 409 |         
 410 |         self.logger.info(f"Specialists stopped for mission {mission_id}")
 411 |     
 412 |     # ═══════════════════════════════════════════════════════════
 413 |     # Task Management
 414 |     # ═══════════════════════════════════════════════════════════
 415 |     
 416 |     async def _create_initial_scan_task(self, mission_id: str) -> str:
 417 |         """Create the initial network scan task."""
 418 |         task = Task(
 419 |             mission_id=UUID(mission_id),
 420 |             type=TaskType.NETWORK_SCAN,
 421 |             specialist=SpecialistType.RECON,
 422 |             priority=10  # Highest priority
 423 |         )
 424 |         
 425 |         task_id = await self.blackboard.add_task(task)
 426 |         self.logger.info(f"Created initial scan task: {task_id}")
 427 |         return task_id
 428 |     
 429 |     async def create_exploit_tasks_for_critical_vulns(self, mission_id: str) -> int:
 430 |         """
 431 |         Create exploit tasks for critical vulnerabilities.
 432 |         
 433 |         Called by monitor to ensure high-value vulns get attacked.
 434 |         """
 435 |         vulns = await self.blackboard.get_mission_vulns(mission_id)
 436 |         tasks_created = 0
 437 |         
 438 |         for vuln_key in vulns:
 439 |             vuln_id = vuln_key.replace("vuln:", "")
 440 |             vuln = await self.blackboard.get_vulnerability(vuln_id)
 441 |             
 442 |             if not vuln:
 443 |                 continue
 444 |             
 445 |             # Check if vuln is critical/high and exploitable
 446 |             severity = vuln.get("severity")
 447 |             exploit_available = vuln.get("exploit_available")
 448 |             status = vuln.get("status", "discovered")
 449 |             
 450 |             if severity in ("critical", "high") and exploit_available and status == "discovered":
 451 |                 # Create exploit task
 452 |                 task = Task(
 453 |                     mission_id=UUID(mission_id),
 454 |                     type=TaskType.EXPLOIT,
 455 |                     specialist=SpecialistType.ATTACK,
 456 |                     priority=9 if severity == "critical" else 8,
 457 |                     vuln_id=UUID(vuln_id),
 458 |                     target_id=UUID(vuln.get("target_id")) if vuln.get("target_id") else None
 459 |                 )
 460 |                 
 461 |                 await self.blackboard.add_task(task)
 462 |                 await self.blackboard.update_vuln_status(vuln_id, "pending_exploit")
 463 |                 tasks_created += 1
 464 |         
 465 |         return tasks_created
 466 |     
 467 |     # ═══════════════════════════════════════════════════════════
 468 |     # Control Commands
 469 |     # ═══════════════════════════════════════════════════════════
 470 |     
 471 |     async def _send_control_command(self, mission_id: str, command: str) -> None:
 472 |         """Send a control command to all specialists via Pub/Sub."""
 473 |         channel = self.blackboard.get_channel(mission_id, "control")
 474 |         
 475 |         event = {
 476 |             "event": "control",
 477 |             "command": command,
 478 |             "mission_id": mission_id,
 479 |             "timestamp": datetime.utcnow().isoformat()
 480 |         }
 481 |         
 482 |         await self.blackboard.publish_dict(channel, event)
 483 |         self.logger.info(f"Sent {command} command for mission {mission_id}")
 484 |     
 485 |     # ═══════════════════════════════════════════════════════════
 486 |     # Monitoring
 487 |     # ═══════════════════════════════════════════════════════════
 488 |     
 489 |     async def _monitor_loop(self) -> None:
 490 |         """Main monitoring loop for active missions."""
 491 |         while self._running and self._active_missions:
 492 |             try:
 493 |                 for mission_id in list(self._active_missions.keys()):
 494 |                     await self._monitor_mission(mission_id)
 495 |                 
 496 |                 await asyncio.sleep(self._monitor_interval)
 497 |                 
 498 |             except Exception as e:
 499 |                 self.logger.error(f"Error in monitor loop: {e}")
 500 |                 await asyncio.sleep(1)
 501 |     
 502 |     async def _monitor_mission(self, mission_id: str) -> None:
 503 |         """Monitor a single mission."""
 504 |         mission_data = await self.blackboard.get_mission(mission_id)
 505 |         if not mission_data:
 506 |             return
 507 |         
 508 |         status = mission_data.get("status")
 509 |         
 510 |         if status != "running":
 511 |             return
 512 |         
 513 |         # Check goals
 514 |         goals = await self.blackboard.get_mission_goals(mission_id)
 515 |         all_achieved = all(g == "achieved" for g in goals.values()) if goals else False
 516 |         
 517 |         if all_achieved and goals:
 518 |             self.logger.info(f"🎯 All goals achieved for mission {mission_id}")
 519 |             await self.stop_mission(mission_id)
 520 |             return
 521 |         
 522 |         # Create exploit tasks for new critical vulns
 523 |         await self.create_exploit_tasks_for_critical_vulns(mission_id)
 524 |         
 525 |         # Check heartbeats (detect dead specialists)
 526 |         heartbeats = await self.blackboard.get_heartbeats(mission_id)
 527 |         if not heartbeats:
 528 |             self.logger.warning(f"No heartbeats for mission {mission_id}")
 529 |     
 530 |     # ═══════════════════════════════════════════════════════════
 531 |     # Task Watchdog (Zombie Task Hunter)
 532 |     # ═══════════════════════════════════════════════════════════
 533 |     
 534 |     async def _watchdog_loop(self) -> None:
 535 |         """
 536 |         Background task that monitors for zombie/stale tasks.
 537 |         
 538 |         Runs periodically to detect tasks that are:
 539 |         - Status: RUNNING but haven't been updated for too long
 540 |         - Likely abandoned by a crashed specialist
 541 |         
 542 |         Actions:
 543 |         - Re-queue task if retry count < max_retries
 544 |         - Mark as FAILED if retry count >= max_retries
 545 |         """
 546 |         self.logger.info("🐕 Task Watchdog started")
 547 |         
 548 |         while self._running and self._active_missions:
 549 |             try:
 550 |                 for mission_id in list(self._active_missions.keys()):
 551 |                     await self._check_zombie_tasks(mission_id)
 552 |                 
 553 |                 await asyncio.sleep(self._watchdog_interval)
 554 |                 
 555 |             except Exception as e:
 556 |                 self.logger.error(f"Error in watchdog loop: {e}")
 557 |                 await asyncio.sleep(5)
 558 |         
 559 |         self.logger.info("🐕 Task Watchdog stopped")
 560 |     
 561 |     async def _check_zombie_tasks(self, mission_id: str) -> None:
 562 |         """
 563 |         Check for and recover zombie tasks in a mission.
 564 |         
 565 |         A zombie task is one that:
 566 |         - Has status RUNNING
 567 |         - Has not been updated within the timeout period
 568 |         
 569 |         Args:
 570 |             mission_id: Mission ID to check
 571 |         """
 572 |         try:
 573 |             # Get all running tasks
 574 |             running_tasks = await self.blackboard.get_running_tasks(mission_id)
 575 |             
 576 |             if not running_tasks:
 577 |                 return
 578 |             
 579 |             now = datetime.utcnow()
 580 |             zombies_found = 0
 581 |             
 582 |             for task_key in running_tasks:
 583 |                 task_id = task_key.replace("task:", "")
 584 |                 task = await self.blackboard.get_task(task_id)
 585 |                 
 586 |                 if not task:
 587 |                     continue
 588 |                 
 589 |                 # Check last update time
 590 |                 updated_at_str = task.get("updated_at") or task.get("started_at")
 591 |                 if not updated_at_str:
 592 |                     continue
 593 |                 
 594 |                 try:
 595 |                     updated_at = datetime.fromisoformat(updated_at_str)
 596 |                 except ValueError:
 597 |                     self.logger.warning(f"Invalid timestamp for task {task_id}: {updated_at_str}")
 598 |                     continue
 599 |                 
 600 |                 # Check if task is stale
 601 |                 if now - updated_at > self._task_timeout:
 602 |                     zombies_found += 1
 603 |                     retry_count = int(task.get("retry_count", 0))
 604 |                     
 605 |                     if retry_count < self._max_task_retries:
 606 |                         # Re-queue the task
 607 |                         self.logger.warning(
 608 |                             f"🧟 Zombie task detected: {task_id} "
 609 |                             f"(stale for {now - updated_at}). Re-queuing (attempt {retry_count + 1}/{self._max_task_retries})"
 610 |                         )
 611 |                         await self.blackboard.requeue_task(
 612 |                             mission_id=mission_id,
 613 |                             task_id=task_id,
 614 |                             reason=f"watchdog_timeout_after_{(now - updated_at).total_seconds():.0f}s"
 615 |                         )
 616 |                     else:
 617 |                         # Mark as permanently failed
 618 |                         self.logger.error(
 619 |                             f"💀 Task {task_id} exceeded max retries ({self._max_task_retries}). "
 620 |                             f"Marking as FAILED."
 621 |                         )
 622 |                         await self.blackboard.mark_task_failed_permanently(
 623 |                             mission_id=mission_id,
 624 |                             task_id=task_id,
 625 |                             reason=f"max_retries_exceeded_after_{retry_count}_attempts"
 626 |                         )
 627 |             
 628 |             if zombies_found > 0:
 629 |                 self.logger.info(f"🐕 Watchdog processed {zombies_found} zombie task(s) for mission {mission_id}")
 630 |                 
 631 |         except Exception as e:
 632 |             self.logger.error(f"Error checking zombie tasks: {e}")
 633 |     
 634 |     # ═══════════════════════════════════════════════════════════
 635 |     # Utility Methods
 636 |     # ═══════════════════════════════════════════════════════════
 637 |     
 638 |     async def get_active_missions(self) -> List[str]:
 639 |         """Get list of active mission IDs."""
 640 |         return list(self._active_missions.keys())
 641 |     
 642 |     # ═══════════════════════════════════════════════════════════
 643 |     # HITL (Human-in-the-Loop) Methods
 644 |     # ═══════════════════════════════════════════════════════════
 645 |     
 646 |     async def request_approval(
 647 |         self,
 648 |         mission_id: str,
 649 |         action: ApprovalAction
 650 |     ) -> str:
 651 |         """
 652 |         Request user approval for a high-risk action.
 653 |         
 654 |         This pauses the mission (sets status to WAITING_FOR_APPROVAL)
 655 |         and broadcasts an ApprovalRequestEvent via WebSocket.
 656 |         
 657 |         Args:
 658 |             mission_id: Mission ID
 659 |             action: ApprovalAction with details of what needs approval
 660 |             
 661 |         Returns:
 662 |             Action ID
 663 |         """
 664 |         action_type_str = action.action_type.value if hasattr(action.action_type, 'value') else str(action.action_type)
 665 |         self.logger.info(f"🔐 Requesting approval for action: {action_type_str}")
 666 |         
 667 |         action_id = str(action.id)
 668 |         
 669 |         # Store pending approval
 670 |         self._pending_approvals[action_id] = action
 671 |         
 672 |         # Update mission status to waiting
 673 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.WAITING_FOR_APPROVAL)
 674 |         
 675 |         if mission_id in self._active_missions:
 676 |             self._active_missions[mission_id]["status"] = MissionStatus.WAITING_FOR_APPROVAL
 677 |         
 678 |         # Publish approval request event
 679 |         event = ApprovalRequestEvent(
 680 |             mission_id=UUID(mission_id),
 681 |             action_id=action.id,
 682 |             action_type=action.action_type,
 683 |             action_description=action.action_description,
 684 |             target_ip=action.target_ip,
 685 |             target_hostname=action.target_hostname,
 686 |             risk_level=action.risk_level,
 687 |             risk_reasons=action.risk_reasons,
 688 |             potential_impact=action.potential_impact,
 689 |             command_preview=action.command_preview,
 690 |             expires_at=action.expires_at
 691 |         )
 692 |         
 693 |         # Publish to blackboard for WebSocket broadcast
 694 |         channel = self.blackboard.get_channel(mission_id, "approvals")
 695 |         await self.blackboard.publish(channel, event)
 696 |         
 697 |         self.logger.info(f"⏳ Mission {mission_id} waiting for approval: {action_id}")
 698 |         
 699 |         return action_id
 700 |     
 701 |     async def approve_action(
 702 |         self,
 703 |         mission_id: str,
 704 |         action_id: str,
 705 |         user_comment: Optional[str] = None
 706 |     ) -> bool:
 707 |         """
 708 |         Approve a pending action and resume mission execution.
 709 |         
 710 |         Args:
 711 |             mission_id: Mission ID
 712 |             action_id: Action ID to approve
 713 |             user_comment: Optional comment from user
 714 |             
 715 |         Returns:
 716 |             True if approved successfully
 717 |         """
 718 |         self.logger.info(f"✅ Approving action: {action_id}")
 719 |         
 720 |         # Verify action exists
 721 |         if action_id not in self._pending_approvals:
 722 |             self.logger.error(f"Action {action_id} not found in pending approvals")
 723 |             return False
 724 |         
 725 |         action = self._pending_approvals[action_id]
 726 |         
 727 |         # Verify mission matches
 728 |         if str(action.mission_id) != mission_id:
 729 |             self.logger.error(f"Action {action_id} does not belong to mission {mission_id}")
 730 |             return False
 731 |         
 732 |         # Update action status
 733 |         action.status = ApprovalStatus.APPROVED
 734 |         action.responded_at = datetime.utcnow()
 735 |         action.user_comment = user_comment
 736 |         
 737 |         # Remove from pending
 738 |         del self._pending_approvals[action_id]
 739 |         
 740 |         # Resume mission
 741 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
 742 |         
 743 |         if mission_id in self._active_missions:
 744 |             self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
 745 |         
 746 |         # Publish approval response
 747 |         response_event = ApprovalResponseEvent(
 748 |             mission_id=UUID(mission_id),
 749 |             action_id=UUID(action_id),
 750 |             approved=True,
 751 |             user_comment=user_comment
 752 |         )
 753 |         
 754 |         channel = self.blackboard.get_channel(mission_id, "approvals")
 755 |         await self.blackboard.publish(channel, response_event)
 756 |         
 757 |         # Resume specialists
 758 |         await self._send_control_command(mission_id, "resume")
 759 |         
 760 |         # If there was a task waiting, re-queue it
 761 |         if action.task_id:
 762 |             await self._resume_approved_task(mission_id, action)
 763 |         
 764 |         self.logger.info(f"▶️ Mission {mission_id} resumed after approval")
 765 |         
 766 |         return True
 767 |     
 768 |     async def reject_action(
 769 |         self,
 770 |         mission_id: str,
 771 |         action_id: str,
 772 |         rejection_reason: Optional[str] = None,
 773 |         user_comment: Optional[str] = None
 774 |     ) -> bool:
 775 |         """
 776 |         Reject a pending action and prompt AnalysisSpecialist for alternative.
 777 |         
 778 |         Args:
 779 |             mission_id: Mission ID
 780 |             action_id: Action ID to reject
 781 |             rejection_reason: Reason for rejection
 782 |             user_comment: Optional comment from user
 783 |             
 784 |         Returns:
 785 |             True if rejected successfully
 786 |         """
 787 |         self.logger.info(f"❌ Rejecting action: {action_id}")
 788 |         
 789 |         # Verify action exists
 790 |         if action_id not in self._pending_approvals:
 791 |             self.logger.error(f"Action {action_id} not found in pending approvals")
 792 |             return False
 793 |         
 794 |         action = self._pending_approvals[action_id]
 795 |         
 796 |         # Verify mission matches
 797 |         if str(action.mission_id) != mission_id:
 798 |             self.logger.error(f"Action {action_id} does not belong to mission {mission_id}")
 799 |             return False
 800 |         
 801 |         # Update action status
 802 |         action.status = ApprovalStatus.REJECTED
 803 |         action.responded_at = datetime.utcnow()
 804 |         action.rejection_reason = rejection_reason
 805 |         action.user_comment = user_comment
 806 |         
 807 |         # Remove from pending
 808 |         del self._pending_approvals[action_id]
 809 |         
 810 |         # Publish rejection response
 811 |         response_event = ApprovalResponseEvent(
 812 |             mission_id=UUID(mission_id),
 813 |             action_id=UUID(action_id),
 814 |             approved=False,
 815 |             rejection_reason=rejection_reason,
 816 |             user_comment=user_comment
 817 |         )
 818 |         
 819 |         channel = self.blackboard.get_channel(mission_id, "approvals")
 820 |         await self.blackboard.publish(channel, response_event)
 821 |         
 822 |         # Request AnalysisSpecialist to find alternative
 823 |         if action.task_id:
 824 |             await self._request_alternative_analysis(mission_id, action, rejection_reason)
 825 |         
 826 |         # Resume mission (to allow alternative actions)
 827 |         await self.blackboard.update_mission_status(mission_id, MissionStatus.RUNNING)
 828 |         
 829 |         if mission_id in self._active_missions:
 830 |             self._active_missions[mission_id]["status"] = MissionStatus.RUNNING
 831 |         
 832 |         await self._send_control_command(mission_id, "resume")
 833 |         
 834 |         self.logger.info(f"▶️ Mission {mission_id} resumed, seeking alternatives")
 835 |         
 836 |         return True
 837 |     
 838 |     async def get_pending_approvals(self, mission_id: str) -> List[Dict[str, Any]]:
 839 |         """
 840 |         Get all pending approval requests for a mission.
 841 |         
 842 |         Args:
 843 |             mission_id: Mission ID
 844 |             
 845 |         Returns:
 846 |             List of pending approval actions
 847 |         """
 848 |         pending = []
 849 |         for action_id, action in self._pending_approvals.items():
 850 |             if str(action.mission_id) == mission_id:
 851 |                 # Handle both enum and string values for action_type and risk_level
 852 |                 action_type = action.action_type.value if hasattr(action.action_type, 'value') else str(action.action_type)
 853 |                 risk_level = action.risk_level.value if hasattr(action.risk_level, 'value') else str(action.risk_level)
 854 |                 
 855 |                 pending.append({
 856 |                     "action_id": action_id,
 857 |                     "action_type": action_type,
 858 |                     "action_description": action.action_description,
 859 |                     "target_ip": action.target_ip,
 860 |                     "risk_level": risk_level,
 861 |                     "risk_reasons": action.risk_reasons,
 862 |                     "potential_impact": action.potential_impact,
 863 |                     "command_preview": action.command_preview,
 864 |                     "requested_at": action.requested_at.isoformat(),
 865 |                     "expires_at": action.expires_at.isoformat() if action.expires_at else None
 866 |                 })
 867 |         return pending
 868 |     
 869 |     async def _resume_approved_task(self, mission_id: str, action: ApprovalAction) -> None:
 870 |         """
 871 |         Resume a task that was waiting for approval.
 872 |         """
 873 |         task_id = str(action.task_id)
 874 |         
 875 |         # Create a new task with the approved action
 876 |         task = Task(
 877 |             mission_id=UUID(mission_id),
 878 |             type=TaskType.EXPLOIT if action.action_type == ActionType.EXPLOIT else TaskType.LATERAL,
 879 |             specialist=SpecialistType.ATTACK,
 880 |             priority=9,  # High priority for approved actions
 881 |             rx_module=action.module_to_execute,
 882 |         )
 883 |         
 884 |         # Add approval metadata
 885 |         task.metadata["approved_action_id"] = str(action.id)
 886 |         task.metadata["user_approved"] = True
 887 |         task.metadata["parameters"] = action.parameters
 888 |         
 889 |         await self.blackboard.add_task(task)
 890 |         self.logger.info(f"Re-queued approved task: {task.id}")
 891 |     
 892 |     async def _request_alternative_analysis(
 893 |         self,
 894 |         mission_id: str,
 895 |         rejected_action: ApprovalAction,
 896 |         rejection_reason: Optional[str]
 897 |     ) -> None:
 898 |         """
 899 |         Request AnalysisSpecialist to find an alternative approach.
 900 |         """
 901 |         # Publish analysis request event
 902 |         from ..core.models import TaskAnalysisRequestEvent
 903 |         
 904 |         event = TaskAnalysisRequestEvent(
 905 |             mission_id=UUID(mission_id),
 906 |             task_id=rejected_action.task_id or uuid4(),
 907 |             task_type=TaskType.EXPLOIT,
 908 |             error_context={
 909 |                 "error_type": "user_rejected",
 910 |                 "error_message": rejection_reason or "User rejected the proposed action",
 911 |                 "rejected_module": rejected_action.module_to_execute,
 912 |                 "rejection_reason": rejection_reason,
 913 |                 "original_action_type": rejected_action.action_type.value if hasattr(rejected_action.action_type, 'value') else str(rejected_action.action_type),
 914 |                 "target_ip": rejected_action.target_ip,
 915 |             },
 916 |             execution_logs=[],
 917 |             priority=9
 918 |         )
 919 |         
 920 |         channel = self.blackboard.get_channel(mission_id, "analysis")
 921 |         await self.blackboard.publish(channel, event)
 922 |         
 923 |         self.logger.info(f"Requested alternative analysis after rejection")
 924 |     
 925 |     # ═══════════════════════════════════════════════════════════
 926 |     # Chat / Interactive Methods
 927 |     # ═══════════════════════════════════════════════════════════
 928 |     
 929 |     async def send_chat_message(
 930 |         self,
 931 |         mission_id: str,
 932 |         content: str,
 933 |         related_task_id: Optional[str] = None,
 934 |         related_action_id: Optional[str] = None
 935 |     ) -> ChatMessage:
 936 |         """
 937 |         Send a chat message from user to the system.
 938 |         
 939 |         This allows users to provide instructions or ask questions
 940 |         during mission execution.
 941 |         
 942 |         Args:
 943 |             mission_id: Mission ID
 944 |             content: Message content
 945 |             related_task_id: Optional related task
 946 |             related_action_id: Optional related approval action
 947 |             
 948 |         Returns:
 949 |             ChatMessage object
 950 |         """
 951 |         self.logger.info(f"💬 Chat message received for mission {mission_id}")
 952 |         
 953 |         # Create message - handle both UUID strings and regular strings
 954 |         try:
 955 |             mission_uuid = UUID(mission_id) if isinstance(mission_id, str) and len(mission_id) == 36 else uuid4()
 956 |         except ValueError:
 957 |             mission_uuid = uuid4()
 958 |         
 959 |         message = ChatMessage(
 960 |             mission_id=mission_uuid,
 961 |             role="user",
 962 |             content=content,
 963 |             related_task_id=UUID(related_task_id) if related_task_id and len(related_task_id) == 36 else None,
 964 |             related_action_id=UUID(related_action_id) if related_action_id and len(related_action_id) == 36 else None
 965 |         )
 966 |         
 967 |         # Store in history
 968 |         if mission_id not in self._chat_history:
 969 |             self._chat_history[mission_id] = []
 970 |         self._chat_history[mission_id].append(message)
 971 |         
 972 |         # Publish chat event
 973 |         event = ChatEvent(
 974 |             mission_id=UUID(mission_id),
 975 |             message_id=message.id,
 976 |             role=message.role,
 977 |             content=message.content,
 978 |             related_task_id=message.related_task_id,
 979 |             related_action_id=message.related_action_id
 980 |         )
 981 |         
 982 |         channel = self.blackboard.get_channel(mission_id, "chat")
 983 |         # Use publish_dict instead of publish for Pydantic models if publish is not available
 984 |         if hasattr(self.blackboard, 'publish'):
 985 |             await self.blackboard.publish(channel, event)
 986 |         else:
 987 |             await self.blackboard.publish_dict(channel, event.model_dump())
 988 |         
 989 |         # Process the message and generate response
 990 |         response = await self._process_chat_message(mission_id, message)
 991 |         
 992 |         if response:
 993 |             self._chat_history[mission_id].append(response)
 994 |             
 995 |             # Publish response event
 996 |             response_event = ChatEvent(
 997 |                 mission_id=UUID(mission_id),
 998 |                 message_id=response.id,
 999 |                 role=response.role,
1000 |                 content=response.content,
1001 |                 related_task_id=response.related_task_id,
1002 |                 related_action_id=response.related_action_id
1003 |             )
1004 |             if hasattr(self.blackboard, 'publish'):
1005 |                 await self.blackboard.publish(channel, response_event)
1006 |             else:
1007 |                 await self.blackboard.publish_dict(channel, response_event.model_dump())
1008 |         
1009 |         return message
1010 |     
1011 |     async def get_chat_history(self, mission_id: str, limit: int = 50) -> List[Dict[str, Any]]:
1012 |         """
1013 |         Get chat history for a mission.
1014 |         
1015 |         Args:
1016 |             mission_id: Mission ID
1017 |             limit: Max messages to return
1018 |             
1019 |         Returns:
1020 |             List of chat messages
1021 |         """
1022 |         history = self._chat_history.get(mission_id, [])
1023 |         return [
1024 |             {
1025 |                 "id": str(msg.id),
1026 |                 "role": msg.role,
1027 |                 "content": msg.content,
1028 |                 "timestamp": msg.timestamp.isoformat(),
1029 |                 "related_task_id": str(msg.related_task_id) if msg.related_task_id else None,
1030 |                 "related_action_id": str(msg.related_action_id) if msg.related_action_id else None
1031 |             }
1032 |             for msg in history[-limit:]
1033 |         ]
1034 |     
1035 |     async def _process_chat_message(
1036 |         self,
1037 |         mission_id: str,
1038 |         message: ChatMessage
1039 |     ) -> Optional[ChatMessage]:
1040 |         """
1041 |         Process a chat message and generate a system response.
1042 |         
1043 |         Uses LLM for intelligent responses with fallback to simple commands.
1044 |         """
1045 |         content = message.content.lower()
1046 |         response_content = None
1047 |         
1048 |         # Check for simple commands first (fast path)
1049 |         if "status" in content:
1050 |             status = await self.get_mission_status(mission_id)
1051 |             if status:
1052 |                 response_content = (
1053 |                     f"📊 Mission Status: {status.get('status', 'unknown')}\n"
1054 |                     f"Targets: {status.get('target_count', 0)}\n"
1055 |                     f"Vulnerabilities: {status.get('vuln_count', 0)}\n"
1056 |                     f"Goals: {status.get('statistics', {}).get('goals_achieved', 0)}/"
1057 |                     f"{len(status.get('goals', {}))}"
1058 |                 )
1059 |         
1060 |         elif "pause" in content or "ايقاف" in content:
1061 |             await self.pause_mission(mission_id)
1062 |             response_content = "⏸️ Mission paused as requested."
1063 |         
1064 |         elif "resume" in content or "استئناف" in content:
1065 |             await self.resume_mission(mission_id)
1066 |             response_content = "▶️ Mission resumed."
1067 |         
1068 |         elif "pending" in content or "approvals" in content or "موافق" in content:
1069 |             pending = await self.get_pending_approvals(mission_id)
1070 |             if pending:
1071 |                 response_content = f"🔐 Pending approvals: {len(pending)}\n"
1072 |                 for p in pending:
1073 |                     response_content += f"  - {p['action_type']}: {p['action_description'][:50]}...\n"
1074 |             else:
1075 |                 response_content = "✅ No pending approvals."
1076 |         
1077 |         elif "help" in content or "مساعدة" in content:
1078 |             response_content = (
1079 |                 "📖 Available commands:\n"
1080 |                 "  - 'status': Get mission status\n"
1081 |                 "  - 'pause': Pause the mission\n"
1082 |                 "  - 'resume': Resume the mission\n"
1083 |                 "  - 'pending': List pending approvals\n"
1084 |                 "  - 'help': Show this help message\n"
1085 |                 "\nYou can also ask me anything about the mission!"
1086 |             )
1087 |         
1088 |         else:
1089 |             # Use LLM for general questions
1090 |             response_content = await self._get_llm_response(mission_id, message.content)
1091 |         
1092 |         if response_content:
1093 |             return ChatMessage(
1094 |                 mission_id=UUID(mission_id),
1095 |                 role="system",
1096 |                 content=response_content,
1097 |                 related_task_id=message.related_task_id,
1098 |                 related_action_id=message.related_action_id
1099 |             )
1100 |         
1101 |         return None
1102 |     
1103 |     async def _get_llm_response(self, mission_id: str, user_message: str) -> str:
1104 |         """
1105 |         Get LLM response for a chat message.
1106 |         
1107 |         Args:
1108 |             mission_id: Mission ID
1109 |             user_message: User's message
1110 |             
1111 |         Returns:
1112 |             LLM response or fallback message
1113 |         """
1114 |         try:
1115 |             from ..core.llm.service import get_llm_service
1116 |             from ..core.llm.base import LLMMessage, MessageRole
1117 |             
1118 |             llm_service = get_llm_service()
1119 |             
1120 |             if not llm_service or not llm_service.providers:
1121 |                 self.logger.warning("LLM service not available, using fallback")
1122 |                 return f"🤖 Received your message: '{user_message}'. Use 'help' to see available commands."
1123 |             
1124 |             # Get mission context
1125 |             status = await self.get_mission_status(mission_id)
1126 |             mission_context = ""
1127 |             if status:
1128 |                 mission_context = f"""
1129 | Current Mission Status:
1130 | - Name: {status.get('name', 'Unknown')}
1131 | - Status: {status.get('status', 'unknown')}
1132 | - Targets: {status.get('target_count', 0)}
1133 | - Vulnerabilities: {status.get('vuln_count', 0)}
1134 | - Goals: {status.get('statistics', {}).get('goals_achieved', 0)}/{len(status.get('goals', {}))}
1135 | """
1136 |             
1137 |             # Build messages
1138 |             system_prompt = f"""You are RAGLOX, an AI-powered Red Team Automation assistant.
1139 | You help operators manage and monitor penetration testing missions.
1140 | 
1141 | {mission_context}
1142 | 
1143 | Be concise, professional, and helpful. If asked about something outside your scope,
1144 | politely redirect the user to relevant commands.
1145 | 
1146 | Available commands the user can use:
1147 | - 'status': Get mission status
1148 | - 'pause': Pause the mission
1149 | - 'resume': Resume the mission
1150 | - 'pending': List pending approvals
1151 | - 'help': Show help message"""
1152 | 
1153 |             messages = [
1154 |                 LLMMessage(role=MessageRole.SYSTEM, content=system_prompt),
1155 |                 LLMMessage(role=MessageRole.USER, content=user_message)
1156 |             ]
1157 |             
1158 |             # Get response from LLM
1159 |             response = await llm_service.generate(messages)
1160 |             
1161 |             if response and response.content:
1162 |                 return f"🤖 {response.content}"
1163 |             else:
1164 |                 return f"🤖 Received your message. Use 'help' to see available commands."
1165 |                 
1166 |         except Exception as e:
1167 |             self.logger.error(f"LLM error: {e}")
1168 |             return f"🤖 Received your message: '{user_message}'. Use 'help' to see available commands."
1169 |     
1170 |     async def shutdown(self) -> None:
1171 |         """Shutdown the controller gracefully."""
1172 |         self.logger.info("Shutting down Mission Controller")
1173 |         
1174 |         self._running = False
1175 |         
1176 |         # Stop all active missions
1177 |         for mission_id in list(self._active_missions.keys()):
1178 |             await self.stop_mission(mission_id)
1179 |         
1180 |         # Disconnect from Blackboard
1181 |         await self.blackboard.disconnect()
1182 |         
1183 |         self.logger.info("Mission Controller shutdown complete")

<environment_details>
# VSCode Visible Files
docs/COMPREHENSIVE_TEST_REPORT.md

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:04:00.614Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.02

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Now I'll start fixing the issues one by one. Let me first check how UUID validation is handled in the codebase:

[Tool Use: search_files]
Path: src
Regex: UUID|uuid
File_pattern: *.py

---

**User:**

[Tool]
Found 129 results.

# src/api/routes.py
  6 | from typing import Any, Dict, List, Optional
  7 | from uuid import UUID
  8 | 
----

# src/executors/factory.py
  9 | from typing import Any, Dict, List, Optional, Type, TypeVar
 10 | from uuid import UUID, uuid4
 11 | from weakref import WeakValueDictionary
----
102 |         # Connection info tracking
103 |         self._connections: Dict[UUID, ConnectionInfo] = {}
104 | 
----
251 |         # Track connection
252 |         conn_id = uuid4()
253 |         self._connections[conn_id] = ConnectionInfo(
----

# src/executors/runner.py
 10 | from typing import Any, Dict, List, Optional, Set, Tuple
 11 | from uuid import UUID, uuid4
 12 | 
----

# src/executors/models.py
  8 | from typing import Any, Dict, List, Optional, Union
  9 | from uuid import UUID, uuid4
 10 | 
----
151 | 
152 |     id: UUID = Field(default_factory=uuid4, description="Unique request ID")
153 | 
----
168 |     # Context (for logging and tracking)
169 |     task_id: Optional[UUID] = Field(default=None, description="Associated task ID")
170 |     mission_id: Optional[UUID] = Field(default=None, description="Associated mission ID")
171 |     rx_module_id: Optional[str] = Field(default=None, description="RX Module being executed")
----
184 |     # Request tracking
185 |     request_id: UUID = Field(..., description="Original request ID")
186 | 
----
252 | 
253 |     id: UUID = Field(default_factory=uuid4, description="Unique request ID")
254 | 
----
274 |     # Context
275 |     task_id: Optional[UUID] = Field(default=None, description="Associated task ID")
276 |     mission_id: Optional[UUID] = Field(default=None, description="Associated mission ID")
277 |     session_id: Optional[UUID] = Field(default=None, description="Session to use (if available)")
278 | 
----
287 |     # Request tracking
288 |     request_id: UUID = Field(..., description="Original request ID")
289 |     rx_module_id: str = Field(..., description="RX Module ID")
----
352 |     """Information about an active connection."""
353 |     id: UUID = Field(default_factory=uuid4)
354 |     executor_type: ExecutorType
----

# src/executors/base.py
 11 | from typing import Any, Dict, List, Optional, Type, TypeVar
 12 | from uuid import UUID
 13 | 
----

# src/controller/mission.py
  8 | from typing import Any, Dict, List, Optional, Set
  9 | from uuid import UUID, uuid4
 10 | 
 11 | # Note: uuid4 is used for generating new UUIDs in HITL functionality
 12 | import logging
----
418 |         task = Task(
419 |             mission_id=UUID(mission_id),
420 |             type=TaskType.NETWORK_SCAN,
----
452 |                 task = Task(
453 |                     mission_id=UUID(mission_id),
454 |                     type=TaskType.EXPLOIT,
----
456 |                     priority=9 if severity == "critical" else 8,
457 |                     vuln_id=UUID(vuln_id),
458 |                     target_id=UUID(vuln.get("target_id")) if vuln.get("target_id") else None
459 |                 )
----
679 |         event = ApprovalRequestEvent(
680 |             mission_id=UUID(mission_id),
681 |             action_id=action.id,
----
747 |         response_event = ApprovalResponseEvent(
748 |             mission_id=UUID(mission_id),
749 |             action_id=UUID(action_id),
750 |             approved=True,
----
811 |         response_event = ApprovalResponseEvent(
812 |             mission_id=UUID(mission_id),
813 |             action_id=UUID(action_id),
814 |             approved=False,
----
876 |         task = Task(
877 |             mission_id=UUID(mission_id),
878 |             type=TaskType.EXPLOIT if action.action_type == ActionType.EXPLOIT else TaskType.LATERAL,
----
904 |         event = TaskAnalysisRequestEvent(
905 |             mission_id=UUID(mission_id),
906 |             task_id=rejected_action.task_id or uuid4(),
907 |             task_type=TaskType.EXPLOIT,
----
952 | 
953 |         # Create message - handle both UUID strings and regular strings
954 |         try:
955 |             mission_uuid = UUID(mission_id) if isinstance(mission_id, str) and len(mission_id) == 36 else uuid4()
956 |         except ValueError:
957 |             mission_uuid = uuid4()
958 | 
959 |         message = ChatMessage(
960 |             mission_id=mission_uuid,
961 |             role="user",
962 |             content=content,
963 |             related_task_id=UUID(related_task_id) if related_task_id and len(related_task_id) == 36 else None,
964 |             related_action_id=UUID(related_action_id) if related_action_id and len(related_action_id) == 36 else None
965 |         )
----
973 |         event = ChatEvent(
974 |             mission_id=UUID(mission_id),
975 |             message_id=message.id,
----
996 |             response_event = ChatEvent(
997 |                 mission_id=UUID(mission_id),
998 |                 message_id=response.id,
----
1093 |             return ChatMessage(
1094 |                 mission_id=UUID(mission_id),
1095 |                 role="system",
----

# src/core/operational_memory.py
 15 | from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
 16 | from uuid import UUID, uuid4
 17 | 
----
 43 |     """سجل قرار واحد"""
 44 |     id: UUID = field(default_factory=uuid4)
 45 |     mission_id: Optional[UUID] = None
 46 |     timestamp: datetime = field(default_factory=datetime.utcnow)
----
 95 |         return cls(
 96 |             id=UUID(data["id"]) if data.get("id") else uuid4(),
 97 |             mission_id=UUID(data["mission_id"]) if data.get("mission_id") else None,
 98 |             timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.utcnow(),
----
200 |         self,
201 |         mission_id: Optional[UUID],
202 |         context: OperationalContext,
----
207 |         vuln_info: Optional[Dict] = None
208 |     ) -> UUID:
209 |         """
----
221 |         Returns:
222 |             UUID للقرار للتحديث لاحقاً
223 |         """
----
273 |         self,
274 |         decision_id: UUID,
275 |         outcome: DecisionOutcome,
----
801 | 
802 |     async def _fetch_record(self, record_id: UUID) -> Optional[DecisionRecord]:
803 |         """استرجاع سجل من Redis."""
----
839 |                     rid = rid.decode()
840 |                 record = await self._fetch_record(UUID(rid))
841 |                 if record:
----

# src/specialists/analysis.py
 11 | from typing import Any, Dict, List, Optional, TYPE_CHECKING
 12 | from uuid import UUID, uuid4
 13 | 
----
291 | 
292 |     def _safe_uuid(self, value: str) -> UUID:
293 |         """Safely convert a string to UUID, generating new one if invalid."""
294 |         try:
295 |             return UUID(value) if value and len(value) == 36 else uuid4()
296 |         except (ValueError, TypeError):
297 |             return uuid4()
298 | 
----
696 |                 try:
697 |                     mission_id = UUID(self._current_mission_id)
698 |                 except (ValueError, TypeError):
----
733 |         self,
734 |         decision_id: UUID,
735 |         success: bool,
----
1504 |         approval_action = ApprovalAction(
1505 |             mission_id=self._safe_uuid(self._current_mission_id) if self._current_mission_id else uuid4(),
1506 |             task_id=self._safe_uuid(original_task["id"].replace("task:", "")) if original_task.get("id") else None,
1507 |             action_type=action_type,
----
1521 |             event = ApprovalRequestEvent(
1522 |                 mission_id=self._safe_uuid(self._current_mission_id),
1523 |                 action_id=approval_action.id,
----
1805 |         event = TaskAnalysisResultEvent(
1806 |             mission_id=UUID(self._current_mission_id),
1807 |             original_task_id=UUID(original_task_id.replace("task:", "")),
1808 |             decision=decision["decision"],
----

# src/specialists/recon.py
 11 | from typing import Any, Dict, List, Optional, TYPE_CHECKING
 12 | from uuid import UUID
 13 | 
----
1027 |                         raglox_vuln = nuclei_vuln.to_vulnerability(
1028 |                             mission_id=UUID(self._current_mission_id),
1029 |                             target_id=UUID(target_id)
1030 |                         )
----

# src/specialists/base.py
  8 | from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
  9 | from uuid import uuid4
 10 | import asyncio
----
 74 |         self.blackboard = blackboard or Blackboard(settings=self.settings)
 75 |         self.worker_id = worker_id or f"{specialist_type.value}-{uuid4().hex[:8]}"
 76 | 
----
376 |         """
377 |         from uuid import UUID
378 | 
379 |         task = Task(
380 |             mission_id=UUID(self._current_mission_id),
381 |             type=task_type,
----
383 |             priority=priority,
384 |             target_id=UUID(target_id) if target_id else None,
385 |             vuln_id=UUID(vuln_id) if vuln_id else None,
386 |             cred_id=UUID(cred_id) if cred_id else None,
387 |             rx_module=rx_module,
----
394 |         event = NewTaskEvent(
395 |             mission_id=UUID(self._current_mission_id),
396 |             task_id=task.id,
----
425 |         """
426 |         from uuid import UUID
427 |         from ..core.models import Priority
----
429 |         target = Target(
430 |             mission_id=UUID(self._current_mission_id),
431 |             ip=ip,
----
441 |         event = NewTargetEvent(
442 |             mission_id=UUID(self._current_mission_id),
443 |             target_id=target.id,
----
479 |         """
480 |         from uuid import UUID
481 | 
482 |         vuln = Vulnerability(
483 |             mission_id=UUID(self._current_mission_id),
484 |             target_id=UUID(target_id),
485 |             type=vuln_type,
----
498 |         event = NewVulnEvent(
499 |             mission_id=UUID(self._current_mission_id),
500 |             vuln_id=vuln.id,
501 |             target_id=UUID(target_id),
502 |             severity=severity,
----
536 |         """
537 |         from uuid import UUID
538 | 
539 |         cred = Credential(
540 |             mission_id=UUID(self._current_mission_id),
541 |             target_id=UUID(target_id),
542 |             type=cred_type,
----
555 |         event = NewCredEvent(
556 |             mission_id=UUID(self._current_mission_id),
557 |             cred_id=cred.id,
558 |             target_id=UUID(target_id),
559 |             type=cred_type,
----
589 |         """
590 |         from uuid import UUID
591 |         from ..core.models import SessionType
----
593 |         session = Session(
594 |             mission_id=UUID(self._current_mission_id),
595 |             target_id=UUID(target_id),
596 |             type=SessionType(session_type),
----
598 |             privilege=privilege,
599 |             via_vuln_id=UUID(via_vuln_id) if via_vuln_id else None,
600 |             via_cred_id=UUID(via_cred_id) if via_cred_id else None
601 |         )
----
607 |         event = NewSessionEvent(
608 |             mission_id=UUID(self._current_mission_id),
609 |             session_id=session.id,
610 |             target_id=UUID(target_id),
611 |             privilege=privilege,
----
856 |         from ..executors import RXModuleRequest, Platform
857 |         from uuid import UUID
858 | 
----
905 |                 timeout=timeout,
906 |                 task_id=UUID(task_id) if task_id else None,
907 |                 mission_id=UUID(self._current_mission_id) if self._current_mission_id else None
908 |             )
----

# src/core/exceptions.py
543 | 
544 | class InvalidUUIDError(ValidationException):
545 |     """Invalid UUID format."""
546 | 
----
548 |         self,
549 |         uuid_str: str,
550 |         field: str = "id",
----
553 |         super().__init__(
554 |             message=f"Invalid UUID: {uuid_str}",
555 |             field=field,
556 |             value=uuid_str,
557 |             details=details
558 |         )
559 |         self.error_code = "INVALID_UUID"
560 | 
----

# src/core/stealth_profiles.py
 14 | from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
 15 | from uuid import UUID, uuid4
 16 | 
----
145 |     """بصمة عملية"""
146 |     operation_id: UUID = field(default_factory=uuid4)
147 |     operation_type: str = ""
----

# src/core/strategic_scorer.py
 13 | from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
 14 | from uuid import UUID, uuid4
 15 | 
----

# src/specialists/intel.py
 27 | from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
 28 | from uuid import UUID
 29 | 
----
301 | 
302 |             # Get the cred_id and ensure it's a valid UUID string
303 |             cred_id = high_reliability_creds[0]["cred_id"]
----
341 |         """
342 |         from uuid import UUID
343 |         from ..core.models import Credential
----
382 |         cred = Credential(
383 |             mission_id=UUID(self._current_mission_id),
384 |             target_id=UUID(target_id),
385 |             type=cred_type,
----
400 |         event = NewCredEvent(
401 |             mission_id=UUID(self._current_mission_id),
402 |             cred_id=cred.id,
403 |             target_id=UUID(target_id),
404 |             type=cred_type,
----

# src/core/logging.py
 14 | from typing import Any, Callable, Dict, Optional, TypeVar, Union
 15 | from uuid import uuid4
 16 | 
----

# src/core/__init__.py
 42 |     validate_ip_address,
 43 |     validate_uuid,
 44 |     validate_scope,
----
135 |     "validate_ip_address",
136 |     "validate_uuid",
137 |     "validate_scope",
----

# src/core/blackboard.py
  7 | from typing import Any, Dict, List, Optional, Set, Type, TypeVar
  8 | from uuid import UUID
  9 | import json
----
118 |                 serialized[k] = v.isoformat()
119 |             elif isinstance(v, UUID):
120 |                 serialized[k] = str(v)
----
484 | 
485 |             -- Return task key (e.g., "task:uuid")
486 |             return task_key
----
536 |         if result:
537 |             # Result is the task key (e.g., "task:uuid")
538 |             task_id = self._extract_task_id(result)
----

# src/core/validators.py
  8 | from typing import Any, Dict, List, Optional, Set, Tuple, Union
  9 | from uuid import UUID
 10 | from functools import wraps
----
 16 |     InvalidCIDRError,
 17 |     InvalidUUIDError,
 18 |     MissingRequiredFieldError,
----
160 | # ═══════════════════════════════════════════════════════════════
161 | # UUID Validation
162 | # ═══════════════════════════════════════════════════════════════
163 | 
164 | def validate_uuid(
165 |     uuid_str: str,
166 |     field_name: str = "id"
167 | ) -> UUID:
168 |     """
169 |     Validate and parse a UUID string.
170 | 
171 |     Args:
172 |         uuid_str: UUID string
173 |         field_name: Field name for error messages
----
175 |     Returns:
176 |         UUID object
177 | 
178 |     Raises:
179 |         InvalidUUIDError: If UUID is invalid
180 |     """
181 |     try:
182 |         return UUID(uuid_str.strip())
183 |     except (ValueError, AttributeError) as e:
184 |         raise InvalidUUIDError(uuid_str, field_name, details={"reason": str(e)})
185 | 
186 | 
187 | def is_valid_uuid(uuid_str: str) -> bool:
188 |     """Check if a string is a valid UUID."""
189 |     try:
190 |         UUID(uuid_str)
191 |         return True
----

# src/specialists/attack.py
  9 | from typing import Any, Dict, List, Optional, TYPE_CHECKING
 10 | from uuid import UUID
 11 | 
----
1214 |             clean_cred_id = cred_id
1215 |             if isinstance(cred_id, str) and not self._is_valid_uuid(cred_id):
1216 |                 clean_cred_id = None  # Invalid UUID, don't pass it
1217 | 
----
1423 | 
1424 |     def _is_valid_uuid(self, uuid_str: str) -> bool:
1425 |         """Check if string is a valid UUID."""
1426 |         try:
1427 |             UUID(uuid_str)
1428 |             return True
----
1654 |                 event = GoalAchievedEvent(
1655 |                     mission_id=UUID(self._current_mission_id),
1656 |                     goal=goal_name
----

# src/core/models.py
  8 | from typing import Any, Dict, List, Optional
  9 | from uuid import UUID, uuid4
 10 | 
----
162 | 
163 |     id: UUID = Field(default_factory=uuid4, description="Unique identifier")
164 |     created_at: datetime = Field(default_factory=datetime.utcnow)
----
210 |     # Ownership
211 |     created_by: Optional[UUID] = None
212 | 
----
254 |     """Target entity - a discovered host."""
255 |     mission_id: UUID
256 |     ip: str
----
278 |     """Vulnerability entity."""
279 |     mission_id: UUID
280 |     target_id: UUID
281 | 
----
314 |     """
315 |     mission_id: UUID
316 |     target_id: UUID
317 | 
----
353 |     """Session entity - an active connection to a target."""
354 |     mission_id: UUID
355 |     target_id: UUID
356 | 
----
368 |     # How it was obtained
369 |     via_vuln_id: Optional[UUID] = None
370 |     via_cred_id: Optional[UUID] = None
371 | 
----
422 |     """Task entity - a unit of work for specialists."""
423 |     mission_id: UUID
424 | 
----
430 |     # References
431 |     target_id: Optional[UUID] = None
432 |     vuln_id: Optional[UUID] = None
433 |     cred_id: Optional[UUID] = None
434 |     session_id: Optional[UUID] = None
435 |     rx_module: Optional[str] = None
----
460 |     max_retries: int = 3
461 |     parent_task_id: Optional[UUID] = None  # If this is a retry of another task
462 | 
----
473 |     """Attack path entity - a discovered lateral movement path."""
474 |     mission_id: UUID
475 |     from_target_id: UUID
476 |     to_target_id: UUID
477 | 
----
479 |     method: str  # pass_the_hash, rdp, ssh, smb, wmi, etc.
480 |     requires_cred_id: Optional[UUID] = None
481 | 
----
494 |     event: str
495 |     mission_id: UUID
496 |     timestamp: datetime = Field(default_factory=datetime.utcnow)
----
502 |     event: str = "new_target"
503 |     target_id: UUID
504 |     ip: str
----
511 |     event: str = "new_vuln"
512 |     vuln_id: UUID
513 |     target_id: UUID
514 |     severity: Severity
----
520 |     event: str = "new_cred"
521 |     cred_id: UUID
522 |     target_id: UUID
523 |     type: CredentialType
----
529 |     event: str = "new_session"
530 |     session_id: UUID
531 |     target_id: UUID
532 |     privilege: PrivilegeLevel
----
538 |     event: str = "new_task"
539 |     task_id: UUID
540 |     type: TaskType
----
548 |     goal: str
549 |     via_cred_id: Optional[UUID] = None
550 |     via_session_id: Optional[UUID] = None
551 | 
----
562 |     event: str = "task_failed"
563 |     task_id: UUID
564 |     task_type: TaskType
565 |     target_id: Optional[UUID] = None
566 | 
----
588 |     event: str = "analysis_request"
589 |     task_id: UUID
590 |     task_type: TaskType
----
598 |     event: str = "analysis_result"
599 |     original_task_id: UUID
600 | 
----
605 |     # If retry
606 |     new_task_id: Optional[UUID] = None
607 |     modified_parameters: Dict[str, Any] = Field(default_factory=dict)
----
615 |     command: str  # pause, resume, stop
616 |     mission_id: Optional[UUID] = None
617 |     timestamp: datetime = Field(default_factory=datetime.utcnow)
----
658 |     """
659 |     mission_id: UUID
660 |     task_id: Optional[UUID] = None
661 | 
----
697 |     event: str = "approval_request"
698 |     action_id: UUID
699 |     action_type: ActionType
----
722 |     event: str = "approval_response"
723 |     action_id: UUID
724 |     approved: bool
----
734 |     """
735 |     id: UUID = Field(default_factory=uuid4)
736 |     mission_id: UUID
737 | 
----
742 |     # Context
743 |     related_task_id: Optional[UUID] = None
744 |     related_action_id: Optional[UUID] = None
745 | 
----
755 |     event: str = "chat_message"
756 |     message_id: UUID
757 |     role: str
758 |     content: str
759 |     related_task_id: Optional[UUID] = None
760 |     related_action_id: Optional[UUID] = None
----

# src/core/intel/elasticsearch_provider.py
 37 | from typing import Any, Dict, List, Optional, Tuple
 38 | from uuid import uuid4
 39 | 
----

# src/core/intel/base.py
 10 | from pydantic import BaseModel, Field
 11 | from uuid import UUID, uuid4
 12 | import hashlib
----
 38 | 
 39 |     id: UUID = Field(default_factory=uuid4)
 40 | 
----
100 | 
101 |     def to_credential_dict(self, mission_id: UUID, target_id: UUID) -> Dict[str, Any]:
102 |         """
----

# src/core/intelligence_coordinator.py
 14 | from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
 15 | from uuid import UUID, uuid4
 16 | 
----
 35 |     """مسار هجوم مقترح"""
 36 |     id: UUID = field(default_factory=uuid4)
 37 |     path_type: AttackPathType = AttackPathType.DIRECT_EXPLOIT
----
 58 |     reasoning: str = ""
 59 |     alternative_paths: List[UUID] = field(default_factory=list)
 60 | 
----

# src/core/scanners/nuclei.py
 13 | from typing import Any, Dict, List, Optional, Union
 14 | from uuid import UUID, uuid4
 15 | 
----
 73 |         self,
 74 |         mission_id: UUID,
 75 |         target_id: UUID
 76 |     ) -> Vulnerability:
----
<environment_details>
# VSCode Visible Files
docs/COMPREHENSIVE_TEST_REPORT.md

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:04:26.762Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.04

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Now I'll start fixing the issues in routes.py. Let me first check the validators module to understand how UUID validation is implemented:

[Tool Use: read_file]
Files: [
  {
    "path": "src/core/validators.py"
  }
]

---

**User:**

[Tool]
File: src/core/validators.py
Lines 1-800:
  1 | # ═══════════════════════════════════════════════════════════════
  2 | # RAGLOX v3.0 - Input Validators
  3 | # Comprehensive validation utilities for all inputs
  4 | # ═══════════════════════════════════════════════════════════════
  5 | 
  6 | import ipaddress
  7 | import re
  8 | from typing import Any, Dict, List, Optional, Set, Tuple, Union
  9 | from uuid import UUID
 10 | from functools import wraps
 11 | 
 12 | from pydantic import BaseModel, ValidationError
 13 | 
 14 | from .exceptions import (
 15 |     InvalidIPAddressError,
 16 |     InvalidCIDRError,
 17 |     InvalidUUIDError,
 18 |     MissingRequiredFieldError,
 19 |     ValidationException,
 20 |     TargetOutOfScopeError,
 21 | )
 22 | 
 23 | 
 24 | # ═══════════════════════════════════════════════════════════════
 25 | # IP Address Validation
 26 | # ═══════════════════════════════════════════════════════════════
 27 | 
 28 | def validate_ip_address(ip: str) -> str:
 29 |     """
 30 |     Validate an IP address (IPv4 or IPv6).
 31 |     
 32 |     Args:
 33 |         ip: IP address string
 34 |         
 35 |     Returns:
 36 |         Normalized IP address string
 37 |         
 38 |     Raises:
 39 |         InvalidIPAddressError: If IP is invalid
 40 |     """
 41 |     try:
 42 |         # This normalizes the IP address
 43 |         return str(ipaddress.ip_address(ip.strip()))
 44 |     except ValueError as e:
 45 |         raise InvalidIPAddressError(ip, details={"reason": str(e)})
 46 | 
 47 | 
 48 | def validate_ip_network(cidr: str, strict: bool = False) -> ipaddress.IPv4Network:
 49 |     """
 50 |     Validate a CIDR network notation.
 51 |     
 52 |     Args:
 53 |         cidr: CIDR notation string (e.g., "192.168.1.0/24")
 54 |         strict: If True, host bits must be zero
 55 |         
 56 |     Returns:
 57 |         ipaddress.IPv4Network object
 58 |         
 59 |     Raises:
 60 |         InvalidCIDRError: If CIDR is invalid
 61 |     """
 62 |     try:
 63 |         return ipaddress.ip_network(cidr.strip(), strict=strict)
 64 |     except ValueError as e:
 65 |         raise InvalidCIDRError(cidr, details={"reason": str(e)})
 66 | 
 67 | 
 68 | def is_ip_in_networks(
 69 |     ip: str,
 70 |     networks: List[str]
 71 | ) -> bool:
 72 |     """
 73 |     Check if an IP address is within any of the given networks.
 74 |     
 75 |     Args:
 76 |         ip: IP address to check
 77 |         networks: List of CIDR notations
 78 |         
 79 |     Returns:
 80 |         True if IP is in any network
 81 |     """
 82 |     try:
 83 |         ip_obj = ipaddress.ip_address(ip.strip())
 84 |         
 85 |         for network in networks:
 86 |             try:
 87 |                 net = ipaddress.ip_network(network.strip(), strict=False)
 88 |                 if ip_obj in net:
 89 |                     return True
 90 |             except ValueError:
 91 |                 # Also check if network is a single IP
 92 |                 try:
 93 |                     if ip_obj == ipaddress.ip_address(network.strip()):
 94 |                         return True
 95 |                 except ValueError:
 96 |                     continue
 97 |         
 98 |         return False
 99 |     except ValueError:
100 |         return False
101 | 
102 | 
103 | def validate_target_in_scope(
104 |     target_ip: str,
105 |     mission_scope: List[str]
106 | ) -> None:
107 |     """
108 |     Validate that a target IP is within mission scope.
109 |     
110 |     Args:
111 |         target_ip: Target IP address
112 |         mission_scope: List of in-scope CIDRs/IPs
113 |         
114 |     Raises:
115 |         TargetOutOfScopeError: If target is out of scope
116 |     """
117 |     if not is_ip_in_networks(target_ip, mission_scope):
118 |         raise TargetOutOfScopeError(target_ip, mission_scope)
119 | 
120 | 
121 | def parse_scope(scope_list: List[str]) -> Tuple[List[str], List[str]]:
122 |     """
123 |     Parse and validate a scope list.
124 |     
125 |     Args:
126 |         scope_list: List of IPs, CIDRs, or hostnames
127 |         
128 |     Returns:
129 |         Tuple of (valid_networks, hostnames)
130 |     """
131 |     networks = []
132 |     hostnames = []
133 |     
134 |     for item in scope_list:
135 |         item = item.strip()
136 |         
137 |         # Try as network/CIDR
138 |         try:
139 |             ipaddress.ip_network(item, strict=False)
140 |             networks.append(item)
141 |             continue
142 |         except ValueError:
143 |             pass
144 |         
145 |         # Try as IP address
146 |         try:
147 |             ipaddress.ip_address(item)
148 |             networks.append(item)
149 |             continue
150 |         except ValueError:
151 |             pass
152 |         
153 |         # Treat as hostname
154 |         if validate_hostname(item):
155 |             hostnames.append(item)
156 |     
157 |     return networks, hostnames
158 | 
159 | 
160 | # ═══════════════════════════════════════════════════════════════
161 | # UUID Validation
162 | # ═══════════════════════════════════════════════════════════════
163 | 
164 | def validate_uuid(
165 |     uuid_str: str,
166 |     field_name: str = "id"
167 | ) -> UUID:
168 |     """
169 |     Validate and parse a UUID string.
170 |     
171 |     Args:
172 |         uuid_str: UUID string
173 |         field_name: Field name for error messages
174 |         
175 |     Returns:
176 |         UUID object
177 |         
178 |     Raises:
179 |         InvalidUUIDError: If UUID is invalid
180 |     """
181 |     try:
182 |         return UUID(uuid_str.strip())
183 |     except (ValueError, AttributeError) as e:
184 |         raise InvalidUUIDError(uuid_str, field_name, details={"reason": str(e)})
185 | 
186 | 
187 | def is_valid_uuid(uuid_str: str) -> bool:
188 |     """Check if a string is a valid UUID."""
189 |     try:
190 |         UUID(uuid_str)
191 |         return True
192 |     except (ValueError, AttributeError):
193 |         return False
194 | 
195 | 
196 | # ═══════════════════════════════════════════════════════════════
197 | # Hostname Validation
198 | # ═══════════════════════════════════════════════════════════════
199 | 
200 | # RFC 1123 hostname pattern
201 | HOSTNAME_PATTERN = re.compile(
202 |     r'^(?=.{1,253}$)'  # Total length
203 |     r'(?!-)[A-Za-z0-9-]{1,63}(?<!-)'  # Labels
204 |     r'(\.[A-Za-z0-9-]{1,63})*$'  # Additional labels
205 | )
206 | 
207 | # Domain name pattern
208 | DOMAIN_PATTERN = re.compile(
209 |     r'^(?=.{1,253}$)'
210 |     r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*'
211 |     r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
212 | )
213 | 
214 | 
215 | def validate_hostname(hostname: str) -> bool:
216 |     """
217 |     Validate a hostname.
218 |     
219 |     Args:
220 |         hostname: Hostname string
221 |         
222 |     Returns:
223 |         True if valid, False otherwise
224 |     """
225 |     if not hostname or len(hostname) > 253:
226 |         return False
227 |     
228 |     # Remove trailing dot for validation
229 |     if hostname.endswith('.'):
230 |         hostname = hostname[:-1]
231 |     
232 |     return bool(HOSTNAME_PATTERN.match(hostname))
233 | 
234 | 
235 | def validate_domain(domain: str) -> bool:
236 |     """
237 |     Validate a domain name.
238 |     
239 |     Args:
240 |         domain: Domain name string
241 |         
242 |     Returns:
243 |         True if valid, False otherwise
244 |     """
245 |     if not domain or len(domain) > 253:
246 |         return False
247 |     
248 |     # Remove trailing dot for validation
249 |     if domain.endswith('.'):
250 |         domain = domain[:-1]
251 |     
252 |     return bool(DOMAIN_PATTERN.match(domain))
253 | 
254 | 
255 | # ═══════════════════════════════════════════════════════════════
256 | # Port Validation
257 | # ═══════════════════════════════════════════════════════════════
258 | 
259 | def validate_port(port: int) -> int:
260 |     """
261 |     Validate a port number.
262 |     
263 |     Args:
264 |         port: Port number
265 |         
266 |     Returns:
267 |         Validated port number
268 |         
269 |     Raises:
270 |         ValidationException: If port is invalid
271 |     """
272 |     if not isinstance(port, int):
273 |         try:
274 |             port = int(port)
275 |         except (ValueError, TypeError):
276 |             raise ValidationException(
277 |                 f"Invalid port: {port}",
278 |                 field="port",
279 |                 value=port
280 |             )
281 |     
282 |     if port < 1 or port > 65535:
283 |         raise ValidationException(
284 |             f"Port must be between 1 and 65535: {port}",
285 |             field="port",
286 |             value=port
287 |         )
288 |     
289 |     return port
290 | 
291 | 
292 | def validate_port_range(port_range: str) -> Tuple[int, int]:
293 |     """
294 |     Validate a port range string (e.g., "80-443").
295 |     
296 |     Args:
297 |         port_range: Port range string
298 |         
299 |     Returns:
300 |         Tuple of (start_port, end_port)
301 |         
302 |     Raises:
303 |         ValidationException: If range is invalid
304 |     """
305 |     if '-' not in port_range:
306 |         port = validate_port(int(port_range))
307 |         return (port, port)
308 |     
309 |     try:
310 |         parts = port_range.split('-')
311 |         if len(parts) != 2:
312 |             raise ValueError("Invalid format")
313 |         
314 |         start = validate_port(int(parts[0].strip()))
315 |         end = validate_port(int(parts[1].strip()))
316 |         
317 |         if start > end:
318 |             raise ValidationException(
319 |                 f"Start port must be <= end port: {port_range}",
320 |                 field="port_range",
321 |                 value=port_range
322 |             )
323 |         
324 |         return (start, end)
325 |         
326 |     except ValueError as e:
327 |         raise ValidationException(
328 |             f"Invalid port range: {port_range}",
329 |             field="port_range",
330 |             value=port_range,
331 |             details={"reason": str(e)}
332 |         )
333 | 
334 | 
335 | # ═══════════════════════════════════════════════════════════════
336 | # String Validation & Sanitization
337 | # ═══════════════════════════════════════════════════════════════
338 | 
339 | # Characters that might be dangerous in various contexts
340 | DANGEROUS_CHARS = re.compile(r'[<>&\'"\x00-\x1f\x7f-\x9f]')
341 | 
342 | # Pattern for command injection
343 | CMD_INJECTION_PATTERN = re.compile(r'[;|&`$(){}[\]\\]')
344 | 
345 | # Path traversal pattern
346 | PATH_TRAVERSAL_PATTERN = re.compile(r'\.\.[/\\]')
347 | 
348 | 
349 | def sanitize_string(
350 |     value: str,
351 |     max_length: int = 1000,
352 |     allow_newlines: bool = False,
353 |     strip: bool = True
354 | ) -> str:
355 |     """
356 |     Sanitize a string input.
357 |     
358 |     Args:
359 |         value: Input string
360 |         max_length: Maximum allowed length
361 |         allow_newlines: Whether to allow newline characters
362 |         strip: Whether to strip whitespace
363 |         
364 |     Returns:
365 |         Sanitized string
366 |     """
367 |     if not isinstance(value, str):
368 |         value = str(value)
369 |     
370 |     if strip:
371 |         value = value.strip()
372 |     
373 |     # Remove null bytes
374 |     value = value.replace('\x00', '')
375 |     
376 |     # Remove newlines if not allowed
377 |     if not allow_newlines:
378 |         value = value.replace('\n', ' ').replace('\r', ' ')
379 |     
380 |     # Truncate to max length
381 |     if len(value) > max_length:
382 |         value = value[:max_length]
383 |     
384 |     return value
385 | 
386 | 
387 | def escape_html(value: str) -> str:
388 |     """
389 |     Escape HTML special characters.
390 |     
391 |     Args:
392 |         value: Input string
393 |         
394 |     Returns:
395 |         HTML-escaped string
396 |     """
397 |     html_escape_table = {
398 |         "&": "&amp;",
399 |         '"': "&quot;",
400 |         "'": "&#x27;",
401 |         ">": "&gt;",
402 |         "<": "&lt;",
403 |     }
404 |     return "".join(html_escape_table.get(c, c) for c in value)
405 | 
406 | 
407 | def check_command_injection(value: str) -> bool:
408 |     """
409 |     Check if a string contains potential command injection characters.
410 |     
411 |     Args:
412 |         value: Input string
413 |         
414 |     Returns:
415 |         True if potential injection detected
416 |     """
417 |     return bool(CMD_INJECTION_PATTERN.search(value))
418 | 
419 | 
420 | def check_path_traversal(value: str) -> bool:
421 |     """
422 |     Check if a string contains path traversal patterns.
423 |     
424 |     Args:
425 |         value: Input string
426 |         
427 |     Returns:
428 |         True if path traversal detected
429 |     """
430 |     return bool(PATH_TRAVERSAL_PATTERN.search(value))
431 | 
432 | 
433 | def validate_safe_string(
434 |     value: str,
435 |     field_name: str = "input",
436 |     max_length: int = 1000
437 | ) -> str:
438 |     """
439 |     Validate and sanitize a string, checking for injection patterns.
440 |     
441 |     Args:
442 |         value: Input string
443 |         field_name: Field name for error messages
444 |         max_length: Maximum allowed length
445 |         
446 |     Returns:
447 |         Sanitized string
448 |         
449 |     Raises:
450 |         ValidationException: If dangerous patterns detected
451 |     """
452 |     value = sanitize_string(value, max_length=max_length)
453 |     
454 |     if check_command_injection(value):
455 |         raise ValidationException(
456 |             f"Invalid characters in {field_name}",
457 |             field=field_name,
458 |             value=value[:50] + "..." if len(value) > 50 else value,
459 |             details={"reason": "potential_command_injection"}
460 |         )
461 |     
462 |     if check_path_traversal(value):
463 |         raise ValidationException(
464 |             f"Invalid path pattern in {field_name}",
465 |             field=field_name,
466 |             value=value[:50] + "..." if len(value) > 50 else value,
467 |             details={"reason": "potential_path_traversal"}
468 |         )
469 |     
470 |     return value
471 | 
472 | 
473 | # ═══════════════════════════════════════════════════════════════
474 | # Name Validation
475 | # ═══════════════════════════════════════════════════════════════
476 | 
477 | # Pattern for safe names (alphanumeric, underscores, hyphens, spaces)
478 | SAFE_NAME_PATTERN = re.compile(r'^[A-Za-z0-9_\- ]+$')
479 | 
480 | 
481 | def validate_name(
482 |     name: str,
483 |     field_name: str = "name",
484 |     min_length: int = 1,
485 |     max_length: int = 255
486 | ) -> str:
487 |     """
488 |     Validate a name field.
489 |     
490 |     Args:
491 |         name: Name string
492 |         field_name: Field name for error messages
493 |         min_length: Minimum length
494 |         max_length: Maximum length
495 |         
496 |     Returns:
497 |         Validated name
498 |         
499 |     Raises:
500 |         ValidationException: If name is invalid
501 |     """
502 |     name = sanitize_string(name, max_length=max_length)
503 |     
504 |     if len(name) < min_length:
505 |         raise MissingRequiredFieldError(field_name, "name")
506 |     
507 |     if not SAFE_NAME_PATTERN.match(name):
508 |         raise ValidationException(
509 |             f"Invalid {field_name}: only alphanumeric, underscores, hyphens, and spaces allowed",
510 |             field=field_name,
511 |             value=name
512 |         )
513 |     
514 |     return name
515 | 
516 | 
517 | # ═══════════════════════════════════════════════════════════════
518 | # CVE Validation
519 | # ═══════════════════════════════════════════════════════════════
520 | 
521 | CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
522 | 
523 | 
524 | def validate_cve(cve: str) -> str:
525 |     """
526 |     Validate a CVE identifier.
527 |     
528 |     Args:
529 |         cve: CVE string (e.g., "CVE-2021-44228")
530 |         
531 |     Returns:
532 |         Normalized CVE string
533 |         
534 |     Raises:
535 |         ValidationException: If CVE is invalid
536 |     """
537 |     cve = cve.strip().upper()
538 |     
539 |     if not CVE_PATTERN.match(cve):
540 |         raise ValidationException(
541 |             f"Invalid CVE format: {cve}",
542 |             field="cve",
543 |             value=cve,
544 |             details={"expected_format": "CVE-YYYY-NNNNN"}
545 |         )
546 |     
547 |     return cve
548 | 
549 | 
550 | def is_valid_cve(cve: str) -> bool:
551 |     """Check if a string is a valid CVE identifier."""
552 |     return bool(CVE_PATTERN.match(cve.strip().upper()))
553 | 
554 | 
555 | # ═══════════════════════════════════════════════════════════════
556 | # CVSS Validation
557 | # ═══════════════════════════════════════════════════════════════
558 | 
559 | def validate_cvss(score: float) -> float:
560 |     """
561 |     Validate a CVSS score.
562 |     
563 |     Args:
564 |         score: CVSS score (0.0 to 10.0)
565 |         
566 |     Returns:
567 |         Validated score
568 |         
569 |     Raises:
570 |         ValidationException: If score is invalid
571 |     """
572 |     try:
573 |         score = float(score)
574 |     except (ValueError, TypeError):
575 |         raise ValidationException(
576 |             f"Invalid CVSS score: {score}",
577 |             field="cvss",
578 |             value=score
579 |         )
580 |     
581 |     if score < 0.0 or score > 10.0:
582 |         raise ValidationException(
583 |             f"CVSS score must be between 0.0 and 10.0: {score}",
584 |             field="cvss",
585 |             value=score
586 |         )
587 |     
588 |     return round(score, 1)
589 | 
590 | 
591 | # ═══════════════════════════════════════════════════════════════
592 | # Mission Scope Validation
593 | # ═══════════════════════════════════════════════════════════════
594 | 
595 | def validate_scope(scope: List[str]) -> List[str]:
596 |     """
597 |     Validate a mission scope list.
598 |     
599 |     Args:
600 |         scope: List of scope entries (IPs, CIDRs, hostnames)
601 |         
602 |     Returns:
603 |         Validated scope list
604 |         
605 |     Raises:
606 |         ValidationException: If scope is invalid
607 |     """
608 |     if not scope:
609 |         raise MissingRequiredFieldError("scope", "mission")
610 |     
611 |     validated = []
612 |     errors = []
613 |     
614 |     for i, entry in enumerate(scope):
615 |         entry = entry.strip()
616 |         
617 |         if not entry:
618 |             continue
619 |         
620 |         # Try as IP
621 |         try:
622 |             ipaddress.ip_address(entry)
623 |             validated.append(entry)
624 |             continue
625 |         except ValueError:
626 |             pass
627 |         
628 |         # Try as CIDR
629 |         try:
630 |             ipaddress.ip_network(entry, strict=False)
631 |             validated.append(entry)
632 |             continue
633 |         except ValueError:
634 |             pass
635 |         
636 |         # Try as hostname/domain
637 |         if validate_hostname(entry) or validate_domain(entry):
638 |             validated.append(entry)
639 |             continue
640 |         
641 |         errors.append(f"Invalid scope entry at index {i}: {entry}")
642 |     
643 |     if errors:
644 |         raise ValidationException(
645 |             f"Invalid scope entries: {len(errors)} errors",
646 |             field="scope",
647 |             details={"errors": errors}
648 |         )
649 |     
650 |     if not validated:
651 |         raise ValidationException(
652 |             "Scope must contain at least one valid entry",
653 |             field="scope"
654 |         )
655 |     
656 |     return validated
657 | 
658 | 
659 | # ═══════════════════════════════════════════════════════════════
660 | # Enum Validation
661 | # ═══════════════════════════════════════════════════════════════
662 | 
663 | def validate_enum(
664 |     value: str,
665 |     enum_class,
666 |     field_name: str = "value"
667 | ) -> Any:
668 |     """
669 |     Validate an enum value.
670 |     
671 |     Args:
672 |         value: Value to validate
673 |         enum_class: Enum class to validate against
674 |         field_name: Field name for error messages
675 |         
676 |     Returns:
677 |         Enum member
678 |         
679 |     Raises:
680 |         ValidationException: If value is not a valid enum member
681 |     """
682 |     try:
683 |         return enum_class(value)
684 |     except ValueError:
685 |         valid_values = [e.value for e in enum_class]
686 |         raise ValidationException(
687 |             f"Invalid {field_name}: {value}",
688 |             field=field_name,
689 |             value=value,
690 |             details={"valid_values": valid_values}
691 |         )
692 | 
693 | 
694 | # ═══════════════════════════════════════════════════════════════
695 | # Pydantic Model Validation
696 | # ═══════════════════════════════════════════════════════════════
697 | 
698 | def validate_model(
699 |     data: Dict[str, Any],
700 |     model_class: type,
701 |     partial: bool = False
702 | ) -> BaseModel:
703 |     """
704 |     Validate data against a Pydantic model.
705 |     
706 |     Args:
707 |         data: Data to validate
708 |         model_class: Pydantic model class
709 |         partial: If True, allow missing required fields
710 |         
711 |     Returns:
712 |         Validated model instance
713 |         
714 |     Raises:
715 |         ValidationException: If validation fails
716 |     """
717 |     try:
718 |         if partial:
719 |             # Create with defaults for missing fields
720 |             return model_class.model_construct(**data)
721 |         return model_class(**data)
722 |     except ValidationError as e:
723 |         errors = []
724 |         for error in e.errors():
725 |             field = '.'.join(str(loc) for loc in error['loc'])
726 |             errors.append({
727 |                 'field': field,
728 |                 'message': error['msg'],
729 |                 'type': error['type']
730 |             })
731 |         
732 |         raise ValidationException(
733 |             f"Validation failed for {model_class.__name__}",
734 |             details={"validation_errors": errors}
735 |         )
736 | 
737 | 
738 | # ═══════════════════════════════════════════════════════════════
739 | # Decorator for Input Validation
740 | # ═══════════════════════════════════════════════════════════════
741 | 
742 | def validate_inputs(**validators):
743 |     """
744 |     Decorator to validate function inputs.
745 |     
746 |     Args:
747 |         **validators: Mapping of parameter names to validator functions
748 |         
749 |     Usage:
750 |         @validate_inputs(
751 |             ip=validate_ip_address,
752 |             port=validate_port
753 |         )
754 |         def process_target(ip: str, port: int):
755 |             ...
756 |     """
757 |     def decorator(func):
758 |         @wraps(func)
759 |         def wrapper(*args, **kwargs):
760 |             # Get function signature
761 |             import inspect
762 |             sig = inspect.signature(func)
763 |             bound = sig.bind(*args, **kwargs)
764 |             bound.apply_defaults()
765 |             
766 |             # Validate each parameter
767 |             for param_name, validator in validators.items():
768 |                 if param_name in bound.arguments:
769 |                     value = bound.arguments[param_name]
770 |                     if value is not None:
771 |                         bound.arguments[param_name] = validator(value)
772 |             
773 |             return func(*bound.args, **bound.kwargs)
774 |         
775 |         return wrapper
776 |     
777 |     return decorator
778 | 
779 | 
780 | def validate_inputs_async(**validators):
781 |     """Async version of validate_inputs decorator."""
782 |     def decorator(func):
783 |         @wraps(func)
784 |         async def wrapper(*args, **kwargs):
785 |             import inspect
786 |             sig = inspect.signature(func)
787 |             bound = sig.bind(*args, **kwargs)
788 |             bound.apply_defaults()
789 |             
790 |             for param_name, validator in validators.items():
791 |                 if param_name in bound.arguments:
792 |                     value = bound.arguments[param_name]
793 |                     if value is not None:
794 |                         bound.arguments[param_name] = validator(value)
795 |             
796 |             return await func(*bound.args, **bound.kwargs)
797 |         
798 |         return wrapper
799 |     
800 |     return decorator

<environment_details>
# VSCode Visible Files
docs/COMPREHENSIVE_TEST_REPORT.md

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:04:59.190Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.05

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Now I'll start fixing the issues in routes.py. Let me implement all the fixes at once:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:6
-------
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..core.models import (
    MissionCreate, MissionStatus, MissionStats,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType,
    Session, SessionStatus,
    # HITL Models
    ApprovalAction, ApprovalStatus, RiskLevel, ActionType
)
from ..controller.mission import MissionController
=======
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..core.models import (
    MissionCreate, MissionStatus, MissionStats,
    Target, TargetStatus, Priority,
    Vulnerability, Severity,
    Credential, CredentialType,
    Session, SessionStatus,
    # HITL Models
    ApprovalAction, ApprovalStatus, RiskLevel, ActionType
)
from ..core.validators import validate_uuid
from ..core.exceptions import InvalidUUIDError
from ..controller.mission import MissionController
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:213
-------
@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)
=======
@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:230
-------
@router.post("/missions/{mission_id}/start", response_model=MissionResponse)
async def start_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Start a mission."""
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.start_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to start mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission started successfully"
    )
=======
@router.post("/missions/{mission_id}/start", response_model=MissionResponse)
async def start_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Start a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.start_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to start mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission started successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:260
-------
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
=======
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:282
-------
@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Resume a paused mission."""
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )
=======
@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Resume a paused mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:304
-------
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.stop_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to stop mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="completed",
        message="Mission stopped successfully"
    )
=======
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    try:
        result = await controller.stop_mission(mission_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to stop mission {mission_id}"
            )
        
        return MissionResponse(
            mission_id=mission_id,
            name="",
            status="completed",
            message="Mission stopped successfully"
        )
    except Exception as e:
        # Log the error for debugging
        import logging
        logging.error(f"Error stopping mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop mission: {str(e)}"
        )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:338
-------
@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[TargetResponse]:
    """List all targets for a mission."""
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets
=======
@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[TargetResponse]:
    """List all targets for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:369
-------
@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller)
) -> TargetResponse:
    """Get a specific target."""
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )
=======
@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller)
) -> TargetResponse:
    """Get a specific target."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(target_id, "target_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:404
-------
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
=======
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:442
-------
@router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
async def list_credentials(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[CredentialResponse]:
    """List all credentials for a mission."""
    blackboard = controller.blackboard
    
    cred_keys = await blackboard.get_mission_creds(mission_id)
    creds = []
    
    for cred_key in cred_keys:
        cred_id = cred_key.replace("cred:", "")
        cred_data = await blackboard.get_credential(cred_id)
        
        if cred_data:
            creds.append(CredentialResponse(
                cred_id=cred_id,
                target_id=str(cred_data.get("target_id", "")),
                type=cred_data.get("type", ""),
                username=cred_data.get("username", ""),
                domain=cred_data.get("domain"),
                privilege_level=cred_data.get("privilege_level", "user"),
                source=cred_data.get("source"),
                verified=cred_data.get("verified", "false").lower() == "true",
                created_at=cred_data.get("created_at")
            ))
    
    return creds
=======
@router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
async def list_credentials(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[CredentialResponse]:
    """List all credentials for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    cred_keys = await blackboard.get_mission_creds(mission_id)
    creds = []
    
    for cred_key in cred_keys:
        cred_id = cred_key.replace("cred:", "")
        cred_data = await blackboard.get_credential(cred_id)
        
        if cred_data:
            creds.append(CredentialResponse(
                cred_id=cred_id,
                target_id=str(cred_data.get("target_id", "")),
                type=cred_data.get("type", ""),
                username=cred_data.get("username", ""),
                domain=cred_data.get("domain"),
                privilege_level=cred_data.get("privilege_level", "user"),
                source=cred_data.get("source"),
                verified=cred_data.get("verified", "false").lower() == "true",
                created_at=cred_data.get("created_at")
            ))
    
    return creds
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:477
-------
@router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
async def list_sessions(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[SessionResponse]:
    """List all active sessions for a mission."""
    blackboard = controller.blackboard
    
    session_keys = await blackboard.get_mission_sessions(mission_id)
    sessions = []
    
    for session_key in session_keys:
        session_id = session_key.replace("session:", "")
        session_data = await blackboard.get_session(session_id)
        
        if session_data:
            sessions.append(SessionResponse(
                session_id=session_id,
                target_id=str(session_data.get("target_id", "")),
                type=session_data.get("type", "shell"),
                user=session_data.get("user", "unknown"),
                privilege=session_data.get("privilege", "user"),
                status=session_data.get("status", "unknown"),
                established_at=session_data.get("established_at"),
                last_activity=session_data.get("last_activity")
            ))
    
    return sessions
=======
@router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
async def list_sessions(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[SessionResponse]:
    """List all active sessions for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    session_keys = await blackboard.get_mission_sessions(mission_id)
    sessions = []
    
    for session_key in session_keys:
        session_id = session_key.replace("session:", "")
        session_data = await blackboard.get_session(session_id)
        
        if session_data:
            sessions.append(SessionResponse(
                session_id=session_id,
                target_id=str(session_data.get("target_id", "")),
                type=session_data.get("type", "shell"),
                user=session_data.get("user", "unknown"),
                privilege=session_data.get("privilege", "user"),
                status=session_data.get("status", "unknown"),
                established_at=session_data.get("established_at"),
                last_activity=session_data.get("last_activity")
            ))
    
    return sessions
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:511
-------
@router.get("/missions/{mission_id}/stats")
async def get_mission_stats(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> Dict[str, Any]:
    """Get mission statistics."""
    blackboard = controller.blackboard
    
    stats = await blackboard.get_mission_stats(mission_id)
    goals = await blackboard.get_mission_goals(mission_id)
    
    # Count achieved goals
    achieved = sum(1 for g in goals.values() if g == "achieved")
    total = len(goals)
    
    return {
        "targets_discovered": stats.targets_discovered,
        "vulns_found": stats.vulns_found,
        "creds_harvested": stats.creds_harvested,
        "sessions_established": stats.sessions_established,
        "goals_achieved": achieved,
        "goals_total": total,
        "completion_percentage": (achieved / total * 100) if total > 0 else 0
    }
=======
@router.get("/missions/{mission_id}/stats")
async def get_mission_stats(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> Dict[str, Any]:
    """Get mission statistics."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    stats = await blackboard.get_mission_stats(mission_id)
    goals = await blackboard.get_mission_goals(mission_id)
    
    # Count achieved goals
    achieved = sum(1 for g in goals.values() if g == "achieved")
    total = len(goals)
    
    return {
        "targets_discovered": stats.targets_discovered,
        "vulns_found": stats.vulns_found,
        "creds_harvested": stats.creds_harvested,
        "sessions_established": stats.sessions_established,
        "goals_achieved": achieved,
        "goals_total": total,
        "completion_percentage": (achieved / total * 100) if total > 0 else 0
    }
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:541
-------
@router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
async def list_pending_approvals(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[PendingApprovalResponse]:
    """
    List all pending approval requests for a mission.
    
    These are high-risk actions waiting for user consent.
    """
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    pending = await controller.get_pending_approvals(mission_id)
    return [PendingApprovalResponse(**p) for p in pending]
=======
@router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
async def list_pending_approvals(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[PendingApprovalResponse]:
    """
    List all pending approval requests for a mission.
    
    These are high-risk actions waiting for user consent.
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    pending = await controller.get_pending_approvals(mission_id)
    return [PendingApprovalResponse(**p) for p in pending]
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:563
-------
@router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
async def approve_action(
    mission_id: str,
    action_id: str,
    request_data: ApprovalRequest = None,
    controller: MissionController = Depends(get_controller)
) -> ApprovalResponse:
    """
    Approve a pending action.
    
    This allows the action to proceed and resumes mission execution.
    
    - **action_id**: ID of the action to approve
    - **user_comment**: Optional comment explaining the approval
    """
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.approve_action(
        mission_id=mission_id,
        action_id=action_id,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    # Get current mission status
    current_status = mission_data.get("status", "unknown")
    
    return ApprovalResponse(
        success=True,
        message="Action approved successfully. Mission execution resumed.",
        action_id=action_id,
        mission_status=current_status
    )
=======
@router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
async def approve_action(
    mission_id: str,
    action_id: str,
    request_data: ApprovalRequest = None,
    controller: MissionController = Depends(get_controller)
) -> ApprovalResponse:
    """
    Approve a pending action.
    
    This allows the action to proceed and resumes mission execution.
    
    - **action_id**: ID of the action to approve
    - **user_comment**: Optional comment explaining the approval
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.approve_action(
        mission_id=mission_id,
        action_id=action_id,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    # Get current mission status
    current_status = mission_data.get("status", "unknown")
    
    return ApprovalResponse(
        success=True,
        message="Action approved successfully. Mission execution resumed.",
        action_id=action_id,
        mission_status=current_status
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:611
-------
@router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
async def reject_action(
    mission_id: str,
    action_id: str,
    request_data: RejectionRequest = None,
    controller: MissionController = Depends(get_controller)
) -> ApprovalResponse:
    """
    Reject a pending action.
    
    The system will attempt to find an alternative approach.
    
    - **action_id**: ID of the action to reject
    - **rejection_reason**: Reason for rejection
    - **user_comment**: Optional additional comment
    """
    rejection_reason = request_data.rejection_reason if request_data else None
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.reject_action(
        mission_id=mission_id,
        action_id=action_id,
        rejection_reason=rejection_reason,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to reject action {action_id}. It may not exist or belong to this mission."
        )
    
    # Get current mission status
    mission_data = await controller.get_mission_status(mission_id)
    current_status = mission_data.get("status", "unknown") if mission_data else "unknown"
    
    return ApprovalResponse(
        success=True,
        message="Action rejected. System will seek alternatives.",
        action_id=action_id,
        mission_status=current_status
    )
=======
@router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
async def reject_action(
    mission_id: str,
    action_id: str,
    request_data: RejectionRequest = None,
    controller: MissionController = Depends(get_controller)
) -> ApprovalResponse:
    """
    Reject a pending action.
    
    The system will attempt to find an alternative approach.
    
    - **action_id**: ID of the action to reject
    - **rejection_reason**: Reason for rejection
    - **user_comment**: Optional additional comment
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(action_id, "action_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    rejection_reason = request_data.rejection_reason if request_data else None
    user_comment = request_data.user_comment if request_data else None
    
    result = await controller.reject_action(
        mission_id=mission_id,
        action_id=action_id,
        rejection_reason=rejection_reason,
        user_comment=user_comment
    )
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
        )
    
    # Get current mission status
    current_status = mission_data.get("status", "unknown")
    
    return ApprovalResponse(
        success=True,
        message="Action rejected. System will seek alternatives.",
        action_id=action_id,
        mission_status=current_status
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:655
-------
@router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
async def send_chat_message(
    mission_id: str,
    request_data: ChatRequest,
    controller: MissionController = Depends(get_controller)
) -> ChatMessageResponse:
    """
    Send a chat message to interact with the mission.
    
    This allows users to:
    - Ask about mission status
    - Give instructions (pause, resume)
    - Query pending approvals
    
    - **content**: Message content
    - **related_task_id**: Optional related task
    - **related_action_id**: Optional related approval action
    """
    try:
        message = await controller.send_chat_message(
            mission_id=mission_id,
            content=request_data.content,
            related_task_id=request_data.related_task_id,
            related_action_id=request_data.related_action_id
        )
        
        return ChatMessageResponse(
            id=str(message.id),
            role=message.role,
            content=message.content,
            timestamp=message.timestamp.isoformat(),
            related_task_id=str(message.related_task_id) if message.related_task_id else None,
            related_action_id=str(message.related_action_id) if message.related_action_id else None
        )
    except Exception as e:
        # Log the error for debugging
        import logging
        logging.error(f"Chat message error for mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process chat message: {str(e)}"
        )
=======
@router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
async def send_chat_message(
    mission_id: str,
    request_data: ChatRequest,
    controller: MissionController = Depends(get_controller)
) -> ChatMessageResponse:
    """
    Send a chat message to interact with the mission.
    
    This allows users to:
    - Ask about mission status
    - Give instructions (pause, resume)
    - Query pending approvals
    
    - **content**: Message content
    - **related_task_id**: Optional related task
    - **related_action_id**: Optional related approval action
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    try:
        message = await controller.send_chat_message(
            mission_id=mission_id,
            content=request_data.content,
            related_task_id=request_data.related_task_id,
            related_action_id=request_data.related_action_id
        )
        
        return ChatMessageResponse(
            id=str(message.id),
            role=message.role,
            content=message.content,
            timestamp=message.timestamp.isoformat(),
            related_task_id=str(message.related_task_id) if message.related_task_id else None,
            related_action_id=str(message.related_action_id) if message.related_action_id else None
        )
    except Exception as e:
        # Log the error for debugging
        import logging
        logging.error(f"Chat message error for mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process chat message: {str(e)}"
        )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:699
-------
@router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
async def get_chat_history(
    mission_id: str,
    limit: int = 50,
    controller: MissionController = Depends(get_controller)
) -> List[ChatMessageResponse]:
    """
    Get chat history for a mission.
    
    - **limit**: Maximum number of messages to return (default 50)
    """
    history = await controller.get_chat_history(mission_id, limit)
    return [ChatMessageResponse(**msg) for msg in history]
=======
@router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
async def get_chat_history(
    mission_id: str,
    limit: int = 50,
    controller: MissionController = Depends(get_controller)
) -> List[ChatMessageResponse]:
    """
    Get chat history for a mission.
    
    - **limit**: Maximum number of messages to return (default 50)
    """
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    history = await controller.get_chat_history(mission_id, limit)
    return [ChatMessageResponse(**msg) for msg in history]
>>>>>>> REPLACE


---

**User:**

[Tool]
But unable to apply all diff parts to file: /root/RAGLOX_V3/webapp/src/api/routes.py, silently use <read_file> tool to check newest file version and re-apply diffs
{"path":"src/api/routes.py","operation":"modified","notice":"You do not need to re-read the file, as you have seen all changes Proceed with the task using these changes as the new baseline."}
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Recently Modified Files
These files have been modified since you last accessed them (file was just edited so you may need to re-read it before editing):
src/api/routes.py

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:07:11.232Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.09

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Let me read the file again to see the current state:

[Tool Use: read_file]
Files: [
  {
    "path": "src/api/routes.py"
  }
]

---

**User:**

[Tool]
File: src/api/routes.py
Lines 1-713:
  1 | # ═══════════════════════════════════════════════════════════════
  2 | # RAGLOX v3.0 - API Routes
  3 | # REST API endpoints for mission management
  4 | # ═══════════════════════════════════════════════════════════════
  5 | 
  6 | from typing import Any, Dict, List, Optional
  7 | from uuid import UUID
  8 | 
  9 | from fastapi import APIRouter, Depends, HTTPException, Request, status
 10 | from pydantic import BaseModel, Field
 11 | 
 12 | from ..core.models import (
 13 |     MissionCreate, MissionStatus, MissionStats,
 14 |     Target, TargetStatus, Priority,
 15 |     Vulnerability, Severity,
 16 |     Credential, CredentialType,
 17 |     Session, SessionStatus,
 18 |     # HITL Models
 19 |     ApprovalAction, ApprovalStatus, RiskLevel, ActionType
 20 | )
 21 | from ..core.validators import validate_uuid
 22 | from ..core.exceptions import InvalidUUIDError
 23 | from ..controller.mission import MissionController
 24 | 
 25 | 
 26 | router = APIRouter(tags=["Missions"])
 27 | 
 28 | 
 29 | # ═══════════════════════════════════════════════════════════════
 30 | # Dependencies
 31 | # ═══════════════════════════════════════════════════════════════
 32 | 
 33 | async def get_controller(request: Request) -> MissionController:
 34 |     """Get the mission controller from app state."""
 35 |     if not hasattr(request.app.state, 'controller') or not request.app.state.controller:
 36 |         raise HTTPException(
 37 |             status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
 38 |             detail="Controller not initialized"
 39 |         )
 40 |     return request.app.state.controller
 41 | 
 42 | 
 43 | # ═══════════════════════════════════════════════════════════════
 44 | # Response Models
 45 | # ═══════════════════════════════════════════════════════════════
 46 | 
 47 | class MissionResponse(BaseModel):
 48 |     """Mission response model."""
 49 |     mission_id: str
 50 |     name: str
 51 |     status: str
 52 |     message: str
 53 | 
 54 | 
 55 | class MissionStatusResponse(BaseModel):
 56 |     """Comprehensive mission status response."""
 57 |     mission_id: str
 58 |     name: Optional[str] = None
 59 |     status: Optional[str] = None
 60 |     scope: Optional[List[str]] = None
 61 |     goals: Optional[Dict[str, str]] = None
 62 |     statistics: Optional[Dict[str, int]] = None
 63 |     target_count: int = 0
 64 |     vuln_count: int = 0
 65 |     created_at: Optional[str] = None
 66 |     started_at: Optional[str] = None
 67 |     completed_at: Optional[str] = None
 68 | 
 69 | 
 70 | class TargetResponse(BaseModel):
 71 |     """Target response model."""
 72 |     target_id: str
 73 |     ip: str
 74 |     hostname: Optional[str] = None
 75 |     os: Optional[str] = None
 76 |     status: str
 77 |     priority: str
 78 |     risk_score: Optional[float] = None
 79 |     ports: Dict[str, str] = {}
 80 | 
 81 | 
 82 | class VulnerabilityResponse(BaseModel):
 83 |     """Vulnerability response model."""
 84 |     vuln_id: str
 85 |     target_id: str
 86 |     type: str
 87 |     name: Optional[str] = None
 88 |     severity: str
 89 |     cvss: Optional[float] = None
 90 |     status: str
 91 |     exploit_available: bool = False
 92 | 
 93 | 
 94 | class CredentialResponse(BaseModel):
 95 |     """Credential response model."""
 96 |     cred_id: str
 97 |     target_id: str
 98 |     type: str
 99 |     username: str
100 |     domain: Optional[str] = None
101 |     privilege_level: str
102 |     source: Optional[str] = None
103 |     verified: bool = False
104 |     created_at: Optional[str] = None
105 | 
106 | 
107 | class SessionResponse(BaseModel):
108 |     """Session response model."""
109 |     session_id: str
110 |     target_id: str
111 |     type: str
112 |     user: str
113 |     privilege: str
114 |     status: str
115 |     established_at: Optional[str] = None
116 |     last_activity: Optional[str] = None
117 | 
118 | 
119 | # ═══════════════════════════════════════════════════════════════
120 | # HITL Request/Response Models
121 | # ═══════════════════════════════════════════════════════════════
122 | 
123 | class ApprovalRequest(BaseModel):
124 |     """Request model for approving/rejecting actions."""
125 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
126 | 
127 | 
128 | class RejectionRequest(BaseModel):
129 |     """Request model for rejecting actions."""
130 |     rejection_reason: Optional[str] = Field(None, description="Reason for rejection")
131 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
132 | 
133 | 
134 | class ChatRequest(BaseModel):
135 |     """Request model for chat messages."""
136 |     content: str = Field(..., min_length=1, max_length=4096, description="Message content")
137 |     related_task_id: Optional[str] = Field(None, description="Related task ID")
138 |     related_action_id: Optional[str] = Field(None, description="Related approval action ID")
139 | 
140 | 
141 | class ApprovalResponse(BaseModel):
142 |     """Response model for approval operations."""
143 |     success: bool
144 |     message: str
145 |     action_id: str
146 |     mission_status: str
147 | 
148 | 
149 | class PendingApprovalResponse(BaseModel):
150 |     """Response model for pending approvals."""
151 |     action_id: str
152 |     action_type: str
153 |     action_description: str
154 |     target_ip: Optional[str] = None
155 |     risk_level: str
156 |     risk_reasons: List[str] = []
157 |     potential_impact: Optional[str] = None
158 |     command_preview: Optional[str] = None
159 |     requested_at: str
160 |     expires_at: Optional[str] = None
161 | 
162 | 
163 | class ChatMessageResponse(BaseModel):
164 |     """Response model for chat messages."""
165 |     id: str
166 |     role: str
167 |     content: str
168 |     timestamp: str
169 |     related_task_id: Optional[str] = None
170 |     related_action_id: Optional[str] = None
171 | 
172 | 
173 | # ═══════════════════════════════════════════════════════════════
174 | # Mission Endpoints
175 | # ═══════════════════════════════════════════════════════════════
176 | 
177 | @router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
178 | async def create_mission(
179 |     mission_data: MissionCreate,
180 |     controller: MissionController = Depends(get_controller)
181 | ) -> MissionResponse:
182 |     """
183 |     Create a new mission.
184 |     
185 |     - **name**: Mission name
186 |     - **description**: Optional description
187 |     - **scope**: List of target ranges (CIDRs, IPs, domains)
188 |     - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
189 |     - **constraints**: Optional constraints (e.g., {"stealth": true})
190 |     """
191 |     try:
192 |         mission_id = await controller.create_mission(mission_data)
193 |         
194 |         return MissionResponse(
195 |             mission_id=mission_id,
196 |             name=mission_data.name,
197 |             status="created",
198 |             message="Mission created successfully"
199 |         )
200 |     except Exception as e:
201 |         raise HTTPException(
202 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
203 |             detail=f"Failed to create mission: {str(e)}"
204 |         )
205 | 
206 | 
207 | @router.get("/missions", response_model=List[str])
208 | async def list_missions(
209 |     controller: MissionController = Depends(get_controller)
210 | ) -> List[str]:
211 |     """List all active mission IDs."""
212 |     return await controller.get_active_missions()
213 | 
214 | 
215 | @router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
216 | async def get_mission(
217 |     mission_id: str,
218 |     controller: MissionController = Depends(get_controller)
219 | ) -> MissionStatusResponse:
220 |     """Get mission status and details."""
221 |     status_data = await controller.get_mission_status(mission_id)
222 |     
223 |     if not status_data:
224 |         raise HTTPException(
225 |             status_code=status.HTTP_404_NOT_FOUND,
226 |             detail=f"Mission {mission_id} not found"
227 |         )
228 |     
229 |     return MissionStatusResponse(**status_data)
230 | 
231 | 
232 | @router.post("/missions/{mission_id}/start", response_model=MissionResponse)
233 | async def start_mission(
234 |     mission_id: str,
235 |     controller: MissionController = Depends(get_controller)
236 | ) -> MissionResponse:
237 |     """Start a mission."""
238 |     # Check if mission exists first
239 |     mission_data = await controller.get_mission_status(mission_id)
240 |     if not mission_data:
241 |         raise HTTPException(
242 |             status_code=status.HTTP_404_NOT_FOUND,
243 |             detail=f"Mission {mission_id} not found"
244 |         )
245 |     
246 |     result = await controller.start_mission(mission_id)
247 |     
248 |     if not result:
249 |         raise HTTPException(
250 |             status_code=status.HTTP_400_BAD_REQUEST,
251 |             detail=f"Failed to start mission {mission_id}"
252 |         )
253 |     
254 |     return MissionResponse(
255 |         mission_id=mission_id,
256 |         name="",
257 |         status="running",
258 |         message="Mission started successfully"
259 |     )
260 | 
261 | 
262 | @router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
263 | async def pause_mission(
264 |     mission_id: str,
265 |     controller: MissionController = Depends(get_controller)
266 | ) -> MissionResponse:
267 |     """Pause a running mission."""
268 |     result = await controller.pause_mission(mission_id)
269 |     
270 |     if not result:
271 |         raise HTTPException(
272 |             status_code=status.HTTP_400_BAD_REQUEST,
273 |             detail=f"Failed to pause mission {mission_id}"
274 |         )
275 |     
276 |     return MissionResponse(
277 |         mission_id=mission_id,
278 |         name="",
279 |         status="paused",
280 |         message="Mission paused successfully"
281 |     )
282 | 
283 | 
284 | @router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
285 | async def resume_mission(
286 |     mission_id: str,
287 |     controller: MissionController = Depends(get_controller)
288 | ) -> MissionResponse:
289 |     """Resume a paused mission."""
290 |     result = await controller.resume_mission(mission_id)
291 |     
292 |     if not result:
293 |         raise HTTPException(
294 |             status_code=status.HTTP_400_BAD_REQUEST,
295 |             detail=f"Failed to resume mission {mission_id}"
296 |         )
297 |     
298 |     return MissionResponse(
299 |         mission_id=mission_id,
300 |         name="",
301 |         status="running",
302 |         message="Mission resumed successfully"
303 |     )
304 | 
305 | 
306 | @router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
307 | async def stop_mission(
308 |     mission_id: str,
309 |     controller: MissionController = Depends(get_controller)
310 | ) -> MissionResponse:
311 |     """Stop a mission."""
312 |     # Check if mission exists first
313 |     mission_data = await controller.get_mission_status(mission_id)
314 |     if not mission_data:
315 |         raise HTTPException(
316 |             status_code=status.HTTP_404_NOT_FOUND,
317 |             detail=f"Mission {mission_id} not found"
318 |         )
319 |     
320 |     result = await controller.stop_mission(mission_id)
321 |     
322 |     if not result:
323 |         raise HTTPException(
324 |             status_code=status.HTTP_400_BAD_REQUEST,
325 |             detail=f"Failed to stop mission {mission_id}"
326 |         )
327 |     
328 |     return MissionResponse(
329 |         mission_id=mission_id,
330 |         name="",
331 |         status="completed",
332 |         message="Mission stopped successfully"
333 |     )
334 | 
335 | 
336 | # ═══════════════════════════════════════════════════════════════
337 | # Target Endpoints
338 | # ═══════════════════════════════════════════════════════════════
339 | 
340 | @router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
341 | async def list_targets(
342 |     mission_id: str,
343 |     controller: MissionController = Depends(get_controller)
344 | ) -> List[TargetResponse]:
345 |     """List all targets for a mission."""
346 |     blackboard = controller.blackboard
347 |     
348 |     target_keys = await blackboard.get_mission_targets(mission_id)
349 |     targets = []
350 |     
351 |     for target_key in target_keys:
352 |         target_id = target_key.replace("target:", "")
353 |         target_data = await blackboard.get_target(target_id)
354 |         
355 |         if target_data:
356 |             ports = await blackboard.get_target_ports(target_id)
357 |             targets.append(TargetResponse(
358 |                 target_id=target_id,
359 |                 ip=target_data.get("ip", ""),
360 |                 hostname=target_data.get("hostname"),
361 |                 os=target_data.get("os"),
362 |                 status=target_data.get("status", "unknown"),
363 |                 priority=target_data.get("priority", "medium"),
364 |                 risk_score=target_data.get("risk_score"),
365 |                 ports=ports
366 |             ))
367 |     
368 |     return targets
369 | 
370 | 
371 | @router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
372 | async def get_target(
373 |     mission_id: str,
374 |     target_id: str,
375 |     controller: MissionController = Depends(get_controller)
376 | ) -> TargetResponse:
377 |     """Get a specific target."""
378 |     blackboard = controller.blackboard
379 |     
380 |     target_data = await blackboard.get_target(target_id)
381 |     
382 |     if not target_data:
383 |         raise HTTPException(
384 |             status_code=status.HTTP_404_NOT_FOUND,
385 |             detail=f"Target {target_id} not found"
386 |         )
387 |     
388 |     ports = await blackboard.get_target_ports(target_id)
389 |     
390 |     return TargetResponse(
391 |         target_id=target_id,
392 |         ip=target_data.get("ip", ""),
393 |         hostname=target_data.get("hostname"),
394 |         os=target_data.get("os"),
395 |         status=target_data.get("status", "unknown"),
396 |         priority=target_data.get("priority", "medium"),
397 |         risk_score=target_data.get("risk_score"),
398 |         ports=ports
399 |     )
400 | 
401 | 
402 | # ═══════════════════════════════════════════════════════════════
403 | # Vulnerability Endpoints
404 | # ═══════════════════════════════════════════════════════════════
405 | 
406 | @router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
407 | async def list_vulnerabilities(
408 |     mission_id: str,
409 |     controller: MissionController = Depends(get_controller)
410 | ) -> List[VulnerabilityResponse]:
411 |     """List all vulnerabilities for a mission."""
412 |     blackboard = controller.blackboard
413 |     
414 |     vuln_keys = await blackboard.get_mission_vulns(mission_id)
415 |     vulns = []
416 |     
417 |     for vuln_key in vuln_keys:
418 |         vuln_id = vuln_key.replace("vuln:", "")
419 |         vuln_data = await blackboard.get_vulnerability(vuln_id)
420 |         
421 |         if vuln_data:
422 |             vulns.append(VulnerabilityResponse(
423 |                 vuln_id=vuln_id,
424 |                 target_id=str(vuln_data.get("target_id", "")),
425 |                 type=vuln_data.get("type", ""),
426 |                 name=vuln_data.get("name"),
427 |                 severity=vuln_data.get("severity", "medium"),
428 |                 cvss=vuln_data.get("cvss"),
429 |                 status=vuln_data.get("status", "discovered"),
430 |                 exploit_available=vuln_data.get("exploit_available", False)
431 |             ))
432 |     
433 |     return vulns
434 | 
435 | 
436 | # ═══════════════════════════════════════════════════════════════
437 | # Statistics Endpoint
438 | # ═══════════════════════════════════════════════════════════════
439 | 
440 | # ═══════════════════════════════════════════════════════════════
441 | # Credential Endpoints
442 | # ═══════════════════════════════════════════════════════════════
443 | 
444 | @router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
445 | async def list_credentials(
446 |     mission_id: str,
447 |     controller: MissionController = Depends(get_controller)
448 | ) -> List[CredentialResponse]:
449 |     """List all credentials for a mission."""
450 |     blackboard = controller.blackboard
451 |     
452 |     cred_keys = await blackboard.get_mission_creds(mission_id)
453 |     creds = []
454 |     
455 |     for cred_key in cred_keys:
456 |         cred_id = cred_key.replace("cred:", "")
457 |         cred_data = await blackboard.get_credential(cred_id)
458 |         
459 |         if cred_data:
460 |             creds.append(CredentialResponse(
461 |                 cred_id=cred_id,
462 |                 target_id=str(cred_data.get("target_id", "")),
463 |                 type=cred_data.get("type", ""),
464 |                 username=cred_data.get("username", ""),
465 |                 domain=cred_data.get("domain"),
466 |                 privilege_level=cred_data.get("privilege_level", "user"),
467 |                 source=cred_data.get("source"),
468 |                 verified=cred_data.get("verified", "false").lower() == "true",
469 |                 created_at=cred_data.get("created_at")
470 |             ))
471 |     
472 |     return creds
473 | 
474 | 
475 | # ═══════════════════════════════════════════════════════════════
476 | # Session Endpoints
477 | # ═══════════════════════════════════════════════════════════════
478 | 
479 | @router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
480 | async def list_sessions(
481 |     mission_id: str,
482 |     controller: MissionController = Depends(get_controller)
483 | ) -> List[SessionResponse]:
484 |     """List all active sessions for a mission."""
485 |     blackboard = controller.blackboard
486 |     
487 |     session_keys = await blackboard.get_mission_sessions(mission_id)
488 |     sessions = []
489 |     
490 |     for session_key in session_keys:
491 |         session_id = session_key.replace("session:", "")
492 |         session_data = await blackboard.get_session(session_id)
493 |         
494 |         if session_data:
495 |             sessions.append(SessionResponse(
496 |                 session_id=session_id,
497 |                 target_id=str(session_data.get("target_id", "")),
498 |                 type=session_data.get("type", "shell"),
499 |                 user=session_data.get("user", "unknown"),
500 |                 privilege=session_data.get("privilege", "user"),
501 |                 status=session_data.get("status", "unknown"),
502 |                 established_at=session_data.get("established_at"),
503 |                 last_activity=session_data.get("last_activity")
504 |             ))
505 |     
506 |     return sessions
507 | 
508 | 
509 | # ═══════════════════════════════════════════════════════════════
510 | # Statistics Endpoint
511 | # ═══════════════════════════════════════════════════════════════
512 | 
513 | @router.get("/missions/{mission_id}/stats")
514 | async def get_mission_stats(
515 |     mission_id: str,
516 |     controller: MissionController = Depends(get_controller)
517 | ) -> Dict[str, Any]:
518 |     """Get mission statistics."""
519 |     blackboard = controller.blackboard
520 |     
521 |     stats = await blackboard.get_mission_stats(mission_id)
522 |     goals = await blackboard.get_mission_goals(mission_id)
523 |     
524 |     # Count achieved goals
525 |     achieved = sum(1 for g in goals.values() if g == "achieved")
526 |     total = len(goals)
527 |     
528 |     return {
529 |         "targets_discovered": stats.targets_discovered,
530 |         "vulns_found": stats.vulns_found,
531 |         "creds_harvested": stats.creds_harvested,
532 |         "sessions_established": stats.sessions_established,
533 |         "goals_achieved": achieved,
534 |         "goals_total": total,
535 |         "completion_percentage": (achieved / total * 100) if total > 0 else 0
536 |     }
537 | 
538 | 
539 | # ═══════════════════════════════════════════════════════════════
540 | # HITL (Human-in-the-Loop) Endpoints
541 | # ═══════════════════════════════════════════════════════════════
542 | 
543 | @router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
544 | async def list_pending_approvals(
545 |     mission_id: str,
546 |     controller: MissionController = Depends(get_controller)
547 | ) -> List[PendingApprovalResponse]:
548 |     """
549 |     List all pending approval requests for a mission.
550 |     
551 |     These are high-risk actions waiting for user consent.
552 |     """
553 |     # Check if mission exists first
554 |     mission_data = await controller.get_mission_status(mission_id)
555 |     if not mission_data:
556 |         raise HTTPException(
557 |             status_code=status.HTTP_404_NOT_FOUND,
558 |             detail=f"Mission {mission_id} not found"
559 |         )
560 |     
561 |     pending = await controller.get_pending_approvals(mission_id)
562 |     return [PendingApprovalResponse(**p) for p in pending]
563 | 
564 | 
565 | @router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
566 | async def approve_action(
567 |     mission_id: str,
568 |     action_id: str,
569 |     request_data: ApprovalRequest = None,
570 |     controller: MissionController = Depends(get_controller)
571 | ) -> ApprovalResponse:
572 |     """
573 |     Approve a pending action.
574 |     
575 |     This allows the action to proceed and resumes mission execution.
576 |     
577 |     - **action_id**: ID of the action to approve
578 |     - **user_comment**: Optional comment explaining the approval
579 |     """
580 |     # Check if mission exists first
581 |     mission_data = await controller.get_mission_status(mission_id)
582 |     if not mission_data:
583 |         raise HTTPException(
584 |             status_code=status.HTTP_404_NOT_FOUND,
585 |             detail=f"Mission {mission_id} not found"
586 |         )
587 |     
588 |     user_comment = request_data.user_comment if request_data else None
589 |     
590 |     result = await controller.approve_action(
591 |         mission_id=mission_id,
592 |         action_id=action_id,
593 |         user_comment=user_comment
594 |     )
595 |     
596 |     if not result:
597 |         raise HTTPException(
598 |             status_code=status.HTTP_404_NOT_FOUND,
599 |             detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
600 |         )
601 |     
602 |     # Get current mission status
603 |     current_status = mission_data.get("status", "unknown")
604 |     
605 |     return ApprovalResponse(
606 |         success=True,
607 |         message="Action approved successfully. Mission execution resumed.",
608 |         action_id=action_id,
609 |         mission_status=current_status
610 |     )
611 | 
612 | 
613 | @router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
614 | async def reject_action(
615 |     mission_id: str,
616 |     action_id: str,
617 |     request_data: RejectionRequest = None,
618 |     controller: MissionController = Depends(get_controller)
619 | ) -> ApprovalResponse:
620 |     """
621 |     Reject a pending action.
622 |     
623 |     The system will attempt to find an alternative approach.
624 |     
625 |     - **action_id**: ID of the action to reject
626 |     - **rejection_reason**: Reason for rejection
627 |     - **user_comment**: Optional additional comment
628 |     """
629 |     rejection_reason = request_data.rejection_reason if request_data else None
630 |     user_comment = request_data.user_comment if request_data else None
631 |     
632 |     result = await controller.reject_action(
633 |         mission_id=mission_id,
634 |         action_id=action_id,
635 |         rejection_reason=rejection_reason,
636 |         user_comment=user_comment
637 |     )
638 |     
639 |     if not result:
640 |         raise HTTPException(
641 |             status_code=status.HTTP_400_BAD_REQUEST,
642 |             detail=f"Failed to reject action {action_id}. It may not exist or belong to this mission."
643 |         )
644 |     
645 |     # Get current mission status
646 |     mission_data = await controller.get_mission_status(mission_id)
647 |     current_status = mission_data.get("status", "unknown") if mission_data else "unknown"
648 |     
649 |     return ApprovalResponse(
650 |         success=True,
651 |         message="Action rejected. System will seek alternatives.",
652 |         action_id=action_id,
653 |         mission_status=current_status
654 |     )
655 | 
656 | 
657 | @router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
658 | async def send_chat_message(
659 |     mission_id: str,
660 |     request_data: ChatRequest,
661 |     controller: MissionController = Depends(get_controller)
662 | ) -> ChatMessageResponse:
663 |     """
664 |     Send a chat message to interact with the mission.
665 |     
666 |     This allows users to:
667 |     - Ask about mission status
668 |     - Give instructions (pause, resume)
669 |     - Query pending approvals
670 |     
671 |     - **content**: Message content
672 |     - **related_task_id**: Optional related task
673 |     - **related_action_id**: Optional related approval action
674 |     """
675 |     try:
676 |         message = await controller.send_chat_message(
677 |             mission_id=mission_id,
678 |             content=request_data.content,
679 |             related_task_id=request_data.related_task_id,
680 |             related_action_id=request_data.related_action_id
681 |         )
682 |         
683 |         return ChatMessageResponse(
684 |             id=str(message.id),
685 |             role=message.role,
686 |             content=message.content,
687 |             timestamp=message.timestamp.isoformat(),
688 |             related_task_id=str(message.related_task_id) if message.related_task_id else None,
689 |             related_action_id=str(message.related_action_id) if message.related_action_id else None
690 |         )
691 |     except Exception as e:
692 |         # Log the error for debugging
693 |         import logging
694 |         logging.error(f"Chat message error for mission {mission_id}: {e}")
695 |         raise HTTPException(
696 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
697 |             detail=f"Failed to process chat message: {str(e)}"
698 |         )
699 | 
700 | 
701 | @router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
702 | async def get_chat_history(
703 |     mission_id: str,
704 |     limit: int = 50,
705 |     controller: MissionController = Depends(get_controller)
706 | ) -> List[ChatMessageResponse]:
707 |     """
708 |     Get chat history for a mission.
709 |     
710 |     - **limit**: Maximum number of messages to return (default 50)
711 |     """
712 |     history = await controller.get_chat_history(mission_id, limit)
713 |     return [ChatMessageResponse(**msg) for msg in history]

<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:07:30.145Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.10

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


I see that the imports were added but the rest of the changes weren't applied. Let me apply the remaining fixes in smaller chunks:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:215
-------
@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)
=======
@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:232
-------
@router.post("/missions/{mission_id}/start", response_model=MissionResponse)
async def start_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Start a mission."""
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.start_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to start mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission started successfully"
    )
=======
@router.post("/missions/{mission_id}/start", response_model=MissionResponse)
async def start_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Start a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.start_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to start mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission started successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:262
-------
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
=======
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:284
-------
@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Resume a paused mission."""
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )
=======
@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Resume a paused mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:306
-------
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.stop_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to stop mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="completed",
        message="Mission stopped successfully"
    )
=======
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    try:
        result = await controller.stop_mission(mission_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to stop mission {mission_id}"
            )
        
        return MissionResponse(
            mission_id=mission_id,
            name="",
            status="completed",
            message="Mission stopped successfully"
        )
    except Exception as e:
        # Log error for debugging
        import logging
        logging.error(f"Error stopping mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop mission: {str(e)}"
        )
>>>>>>> REPLACE


---

**User:**

[Tool]
But unable to apply all diff parts to file: /root/RAGLOX_V3/webapp/src/api/routes.py, silently use <read_file> tool to check newest file version and re-apply diffs
{"path":"src/api/routes.py","operation":"modified","notice":"You do not need to re-read the file, as you have seen all changes Proceed with the task using these changes as the new baseline."}
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:08:27.256Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.12

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Let me try applying the changes in smaller chunks:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:215
-------
@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)
=======
@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)
>>>>>>> REPLACE
</tool_call>

---

**User:**

[Tool]
<error_details>
No sufficiently similar match found at line: 215 (66% similar, needs 100%)

Debug Info:
- Similarity Score: 66%
- Required Threshold: 100%
- Search Range: starting at line 215
- Tried both standard and aggressive line number stripping
- Tip: Use the read_file tool to get the latest content of the file before attempting to use the apply_diff tool again, as the file content may have changed

Search Content:
@router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
async def get_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionStatusResponse:
    """Get mission status and details."""
    status_data = await controller.get_mission_status(mission_id)
    
    if not status_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    return MissionStatusResponse(**status_data)

Best Match Found:
215 | @router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
216 | async def get_mission(
217 |     mission_id: str,
218 |     controller: MissionController = Depends(get_controller)
219 | ) -> MissionStatusResponse:
220 |     """Get mission status and details."""
221 |     # Validate UUID format first
222 |     try:
223 |         validate_uuid(mission_id, "mission_id")
224 |     except InvalidUUIDError as e:
225 |         raise HTTPException(
226 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
227 |             detail=str(e)
228 |         )
229 |     


Original Content:
175 | # ═══════════════════════════════════════════════════════════════
176 | 
177 | @router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
178 | async def create_mission(
179 |     mission_data: MissionCreate,
180 |     controller: MissionController = Depends(get_controller)
181 | ) -> MissionResponse:
182 |     """
183 |     Create a new mission.
184 |     
185 |     - **name**: Mission name
186 |     - **description**: Optional description
187 |     - **scope**: List of target ranges (CIDRs, IPs, domains)
188 |     - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
189 |     - **constraints**: Optional constraints (e.g., {"stealth": true})
190 |     """
191 |     try:
192 |         mission_id = await controller.create_mission(mission_data)
193 |         
194 |         return MissionResponse(
195 |             mission_id=mission_id,
196 |             name=mission_data.name,
197 |             status="created",
198 |             message="Mission created successfully"
199 |         )
200 |     except Exception as e:
201 |         raise HTTPException(
202 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
203 |             detail=f"Failed to create mission: {str(e)}"
204 |         )
205 | 
206 | 
207 | @router.get("/missions", response_model=List[str])
208 | async def list_missions(
209 |     controller: MissionController = Depends(get_controller)
210 | ) -> List[str]:
211 |     """List all active mission IDs."""
212 |     return await controller.get_active_missions()
213 | 
214 | 
215 | @router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
216 | async def get_mission(
217 |     mission_id: str,
218 |     controller: MissionController = Depends(get_controller)
219 | ) -> MissionStatusResponse:
220 |     """Get mission status and details."""
221 |     # Validate UUID format first
222 |     try:
223 |         validate_uuid(mission_id, "mission_id")
224 |     except InvalidUUIDError as e:
225 |         raise HTTPException(
226 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
227 |             detail=str(e)
228 |         )
229 |     
230 |     status_data = await controller.get_mission_status(mission_id)
231 |     
232 |     if not status_data:
233 |         raise HTTPException(
234 |             status_code=status.HTTP_404_NOT_FOUND,
235 |             detail=f"Mission {mission_id} not found"
236 |         )
237 |     
238 |     return MissionStatusResponse(**status_data)
239 | 
240 | 
241 | @router.post("/missions/{mission_id}/start", response_model=MissionResponse)
242 | async def start_mission(
243 |     mission_id: str,
244 |     controller: MissionController = Depends(get_controller)
245 | ) -> MissionResponse:
246 |     """Start a mission."""
247 |     # Validate UUID format first
248 |     try:
249 |         validate_uuid(mission_id, "mission_id")
250 |     except InvalidUUIDError as e:
251 |         raise HTTPException(
252 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
253 |             detail=str(e)
254 |         )
255 |     
256 |     # Check if mission exists first
257 |     mission_data = await controller.get_mission_status(mission_id)
258 |     if not mission_data:
259 |         raise HTTPException(
260 |             status_code=status.HTTP_404_NOT_FOUND,
261 |             detail=f"Mission {mission_id} not found"
262 |         )
263 |     
264 |     result = await controller.start_mission(mission_id)
265 |     
266 |     if not result:
267 |         raise HTTPException(
268 |             status_code=status.HTTP_400_BAD_REQUEST,
269 |             detail=f"Failed to start mission {mission_id}"

</error_details>
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:08:44.496Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.13

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


I see that some changes have already been applied. Let me check the current state of the file and continue with the remaining fixes:

[Tool Use: read_file]
Files: [
  {
    "path": "src/api/routes.py"
  }
]

---

**User:**

[Tool]
File: src/api/routes.py
Lines 1-731:
  1 | # ═══════════════════════════════════════════════════════════════
  2 | # RAGLOX v3.0 - API Routes
  3 | # REST API endpoints for mission management
  4 | # ═══════════════════════════════════════════════════════════════
  5 | 
  6 | from typing import Any, Dict, List, Optional
  7 | from uuid import UUID
  8 | 
  9 | from fastapi import APIRouter, Depends, HTTPException, Request, status
 10 | from pydantic import BaseModel, Field
 11 | 
 12 | from ..core.models import (
 13 |     MissionCreate, MissionStatus, MissionStats,
 14 |     Target, TargetStatus, Priority,
 15 |     Vulnerability, Severity,
 16 |     Credential, CredentialType,
 17 |     Session, SessionStatus,
 18 |     # HITL Models
 19 |     ApprovalAction, ApprovalStatus, RiskLevel, ActionType
 20 | )
 21 | from ..core.validators import validate_uuid
 22 | from ..core.exceptions import InvalidUUIDError
 23 | from ..controller.mission import MissionController
 24 | 
 25 | 
 26 | router = APIRouter(tags=["Missions"])
 27 | 
 28 | 
 29 | # ═══════════════════════════════════════════════════════════════
 30 | # Dependencies
 31 | # ═══════════════════════════════════════════════════════════════
 32 | 
 33 | async def get_controller(request: Request) -> MissionController:
 34 |     """Get the mission controller from app state."""
 35 |     if not hasattr(request.app.state, 'controller') or not request.app.state.controller:
 36 |         raise HTTPException(
 37 |             status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
 38 |             detail="Controller not initialized"
 39 |         )
 40 |     return request.app.state.controller
 41 | 
 42 | 
 43 | # ═══════════════════════════════════════════════════════════════
 44 | # Response Models
 45 | # ═══════════════════════════════════════════════════════════════
 46 | 
 47 | class MissionResponse(BaseModel):
 48 |     """Mission response model."""
 49 |     mission_id: str
 50 |     name: str
 51 |     status: str
 52 |     message: str
 53 | 
 54 | 
 55 | class MissionStatusResponse(BaseModel):
 56 |     """Comprehensive mission status response."""
 57 |     mission_id: str
 58 |     name: Optional[str] = None
 59 |     status: Optional[str] = None
 60 |     scope: Optional[List[str]] = None
 61 |     goals: Optional[Dict[str, str]] = None
 62 |     statistics: Optional[Dict[str, int]] = None
 63 |     target_count: int = 0
 64 |     vuln_count: int = 0
 65 |     created_at: Optional[str] = None
 66 |     started_at: Optional[str] = None
 67 |     completed_at: Optional[str] = None
 68 | 
 69 | 
 70 | class TargetResponse(BaseModel):
 71 |     """Target response model."""
 72 |     target_id: str
 73 |     ip: str
 74 |     hostname: Optional[str] = None
 75 |     os: Optional[str] = None
 76 |     status: str
 77 |     priority: str
 78 |     risk_score: Optional[float] = None
 79 |     ports: Dict[str, str] = {}
 80 | 
 81 | 
 82 | class VulnerabilityResponse(BaseModel):
 83 |     """Vulnerability response model."""
 84 |     vuln_id: str
 85 |     target_id: str
 86 |     type: str
 87 |     name: Optional[str] = None
 88 |     severity: str
 89 |     cvss: Optional[float] = None
 90 |     status: str
 91 |     exploit_available: bool = False
 92 | 
 93 | 
 94 | class CredentialResponse(BaseModel):
 95 |     """Credential response model."""
 96 |     cred_id: str
 97 |     target_id: str
 98 |     type: str
 99 |     username: str
100 |     domain: Optional[str] = None
101 |     privilege_level: str
102 |     source: Optional[str] = None
103 |     verified: bool = False
104 |     created_at: Optional[str] = None
105 | 
106 | 
107 | class SessionResponse(BaseModel):
108 |     """Session response model."""
109 |     session_id: str
110 |     target_id: str
111 |     type: str
112 |     user: str
113 |     privilege: str
114 |     status: str
115 |     established_at: Optional[str] = None
116 |     last_activity: Optional[str] = None
117 | 
118 | 
119 | # ═══════════════════════════════════════════════════════════════
120 | # HITL Request/Response Models
121 | # ═══════════════════════════════════════════════════════════════
122 | 
123 | class ApprovalRequest(BaseModel):
124 |     """Request model for approving/rejecting actions."""
125 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
126 | 
127 | 
128 | class RejectionRequest(BaseModel):
129 |     """Request model for rejecting actions."""
130 |     rejection_reason: Optional[str] = Field(None, description="Reason for rejection")
131 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
132 | 
133 | 
134 | class ChatRequest(BaseModel):
135 |     """Request model for chat messages."""
136 |     content: str = Field(..., min_length=1, max_length=4096, description="Message content")
137 |     related_task_id: Optional[str] = Field(None, description="Related task ID")
138 |     related_action_id: Optional[str] = Field(None, description="Related approval action ID")
139 | 
140 | 
141 | class ApprovalResponse(BaseModel):
142 |     """Response model for approval operations."""
143 |     success: bool
144 |     message: str
145 |     action_id: str
146 |     mission_status: str
147 | 
148 | 
149 | class PendingApprovalResponse(BaseModel):
150 |     """Response model for pending approvals."""
151 |     action_id: str
152 |     action_type: str
153 |     action_description: str
154 |     target_ip: Optional[str] = None
155 |     risk_level: str
156 |     risk_reasons: List[str] = []
157 |     potential_impact: Optional[str] = None
158 |     command_preview: Optional[str] = None
159 |     requested_at: str
160 |     expires_at: Optional[str] = None
161 | 
162 | 
163 | class ChatMessageResponse(BaseModel):
164 |     """Response model for chat messages."""
165 |     id: str
166 |     role: str
167 |     content: str
168 |     timestamp: str
169 |     related_task_id: Optional[str] = None
170 |     related_action_id: Optional[str] = None
171 | 
172 | 
173 | # ═══════════════════════════════════════════════════════════════
174 | # Mission Endpoints
175 | # ═══════════════════════════════════════════════════════════════
176 | 
177 | @router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
178 | async def create_mission(
179 |     mission_data: MissionCreate,
180 |     controller: MissionController = Depends(get_controller)
181 | ) -> MissionResponse:
182 |     """
183 |     Create a new mission.
184 |     
185 |     - **name**: Mission name
186 |     - **description**: Optional description
187 |     - **scope**: List of target ranges (CIDRs, IPs, domains)
188 |     - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
189 |     - **constraints**: Optional constraints (e.g., {"stealth": true})
190 |     """
191 |     try:
192 |         mission_id = await controller.create_mission(mission_data)
193 |         
194 |         return MissionResponse(
195 |             mission_id=mission_id,
196 |             name=mission_data.name,
197 |             status="created",
198 |             message="Mission created successfully"
199 |         )
200 |     except Exception as e:
201 |         raise HTTPException(
202 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
203 |             detail=f"Failed to create mission: {str(e)}"
204 |         )
205 | 
206 | 
207 | @router.get("/missions", response_model=List[str])
208 | async def list_missions(
209 |     controller: MissionController = Depends(get_controller)
210 | ) -> List[str]:
211 |     """List all active mission IDs."""
212 |     return await controller.get_active_missions()
213 | 
214 | 
215 | @router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
216 | async def get_mission(
217 |     mission_id: str,
218 |     controller: MissionController = Depends(get_controller)
219 | ) -> MissionStatusResponse:
220 |     """Get mission status and details."""
221 |     # Validate UUID format first
222 |     try:
223 |         validate_uuid(mission_id, "mission_id")
224 |     except InvalidUUIDError as e:
225 |         raise HTTPException(
226 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
227 |             detail=str(e)
228 |         )
229 |     
230 |     status_data = await controller.get_mission_status(mission_id)
231 |     
232 |     if not status_data:
233 |         raise HTTPException(
234 |             status_code=status.HTTP_404_NOT_FOUND,
235 |             detail=f"Mission {mission_id} not found"
236 |         )
237 |     
238 |     return MissionStatusResponse(**status_data)
239 | 
240 | 
241 | @router.post("/missions/{mission_id}/start", response_model=MissionResponse)
242 | async def start_mission(
243 |     mission_id: str,
244 |     controller: MissionController = Depends(get_controller)
245 | ) -> MissionResponse:
246 |     """Start a mission."""
247 |     # Validate UUID format first
248 |     try:
249 |         validate_uuid(mission_id, "mission_id")
250 |     except InvalidUUIDError as e:
251 |         raise HTTPException(
252 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
253 |             detail=str(e)
254 |         )
255 |     
256 |     # Check if mission exists first
257 |     mission_data = await controller.get_mission_status(mission_id)
258 |     if not mission_data:
259 |         raise HTTPException(
260 |             status_code=status.HTTP_404_NOT_FOUND,
261 |             detail=f"Mission {mission_id} not found"
262 |         )
263 |     
264 |     result = await controller.start_mission(mission_id)
265 |     
266 |     if not result:
267 |         raise HTTPException(
268 |             status_code=status.HTTP_400_BAD_REQUEST,
269 |             detail=f"Failed to start mission {mission_id}"
270 |         )
271 |     
272 |     return MissionResponse(
273 |         mission_id=mission_id,
274 |         name="",
275 |         status="running",
276 |         message="Mission started successfully"
277 |     )
278 | 
279 | 
280 | @router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
281 | async def pause_mission(
282 |     mission_id: str,
283 |     controller: MissionController = Depends(get_controller)
284 | ) -> MissionResponse:
285 |     """Pause a running mission."""
286 |     result = await controller.pause_mission(mission_id)
287 |     
288 |     if not result:
289 |         raise HTTPException(
290 |             status_code=status.HTTP_400_BAD_REQUEST,
291 |             detail=f"Failed to pause mission {mission_id}"
292 |         )
293 |     
294 |     return MissionResponse(
295 |         mission_id=mission_id,
296 |         name="",
297 |         status="paused",
298 |         message="Mission paused successfully"
299 |     )
300 | 
301 | 
302 | @router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
303 | async def resume_mission(
304 |     mission_id: str,
305 |     controller: MissionController = Depends(get_controller)
306 | ) -> MissionResponse:
307 |     """Resume a paused mission."""
308 |     result = await controller.resume_mission(mission_id)
309 |     
310 |     if not result:
311 |         raise HTTPException(
312 |             status_code=status.HTTP_400_BAD_REQUEST,
313 |             detail=f"Failed to resume mission {mission_id}"
314 |         )
315 |     
316 |     return MissionResponse(
317 |         mission_id=mission_id,
318 |         name="",
319 |         status="running",
320 |         message="Mission resumed successfully"
321 |     )
322 | 
323 | 
324 | @router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
325 | async def stop_mission(
326 |     mission_id: str,
327 |     controller: MissionController = Depends(get_controller)
328 | ) -> MissionResponse:
329 |     """Stop a mission."""
330 |     # Check if mission exists first
331 |     mission_data = await controller.get_mission_status(mission_id)
332 |     if not mission_data:
333 |         raise HTTPException(
334 |             status_code=status.HTTP_404_NOT_FOUND,
335 |             detail=f"Mission {mission_id} not found"
336 |         )
337 |     
338 |     result = await controller.stop_mission(mission_id)
339 |     
340 |     if not result:
341 |         raise HTTPException(
342 |             status_code=status.HTTP_400_BAD_REQUEST,
343 |             detail=f"Failed to stop mission {mission_id}"
344 |         )
345 |     
346 |     return MissionResponse(
347 |         mission_id=mission_id,
348 |         name="",
349 |         status="completed",
350 |         message="Mission stopped successfully"
351 |     )
352 | 
353 | 
354 | # ═══════════════════════════════════════════════════════════════
355 | # Target Endpoints
356 | # ═══════════════════════════════════════════════════════════════
357 | 
358 | @router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
359 | async def list_targets(
360 |     mission_id: str,
361 |     controller: MissionController = Depends(get_controller)
362 | ) -> List[TargetResponse]:
363 |     """List all targets for a mission."""
364 |     blackboard = controller.blackboard
365 |     
366 |     target_keys = await blackboard.get_mission_targets(mission_id)
367 |     targets = []
368 |     
369 |     for target_key in target_keys:
370 |         target_id = target_key.replace("target:", "")
371 |         target_data = await blackboard.get_target(target_id)
372 |         
373 |         if target_data:
374 |             ports = await blackboard.get_target_ports(target_id)
375 |             targets.append(TargetResponse(
376 |                 target_id=target_id,
377 |                 ip=target_data.get("ip", ""),
378 |                 hostname=target_data.get("hostname"),
379 |                 os=target_data.get("os"),
380 |                 status=target_data.get("status", "unknown"),
381 |                 priority=target_data.get("priority", "medium"),
382 |                 risk_score=target_data.get("risk_score"),
383 |                 ports=ports
384 |             ))
385 |     
386 |     return targets
387 | 
388 | 
389 | @router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
390 | async def get_target(
391 |     mission_id: str,
392 |     target_id: str,
393 |     controller: MissionController = Depends(get_controller)
394 | ) -> TargetResponse:
395 |     """Get a specific target."""
396 |     blackboard = controller.blackboard
397 |     
398 |     target_data = await blackboard.get_target(target_id)
399 |     
400 |     if not target_data:
401 |         raise HTTPException(
402 |             status_code=status.HTTP_404_NOT_FOUND,
403 |             detail=f"Target {target_id} not found"
404 |         )
405 |     
406 |     ports = await blackboard.get_target_ports(target_id)
407 |     
408 |     return TargetResponse(
409 |         target_id=target_id,
410 |         ip=target_data.get("ip", ""),
411 |         hostname=target_data.get("hostname"),
412 |         os=target_data.get("os"),
413 |         status=target_data.get("status", "unknown"),
414 |         priority=target_data.get("priority", "medium"),
415 |         risk_score=target_data.get("risk_score"),
416 |         ports=ports
417 |     )
418 | 
419 | 
420 | # ═══════════════════════════════════════════════════════════════
421 | # Vulnerability Endpoints
422 | # ═══════════════════════════════════════════════════════════════
423 | 
424 | @router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
425 | async def list_vulnerabilities(
426 |     mission_id: str,
427 |     controller: MissionController = Depends(get_controller)
428 | ) -> List[VulnerabilityResponse]:
429 |     """List all vulnerabilities for a mission."""
430 |     blackboard = controller.blackboard
431 |     
432 |     vuln_keys = await blackboard.get_mission_vulns(mission_id)
433 |     vulns = []
434 |     
435 |     for vuln_key in vuln_keys:
436 |         vuln_id = vuln_key.replace("vuln:", "")
437 |         vuln_data = await blackboard.get_vulnerability(vuln_id)
438 |         
439 |         if vuln_data:
440 |             vulns.append(VulnerabilityResponse(
441 |                 vuln_id=vuln_id,
442 |                 target_id=str(vuln_data.get("target_id", "")),
443 |                 type=vuln_data.get("type", ""),
444 |                 name=vuln_data.get("name"),
445 |                 severity=vuln_data.get("severity", "medium"),
446 |                 cvss=vuln_data.get("cvss"),
447 |                 status=vuln_data.get("status", "discovered"),
448 |                 exploit_available=vuln_data.get("exploit_available", False)
449 |             ))
450 |     
451 |     return vulns
452 | 
453 | 
454 | # ═══════════════════════════════════════════════════════════════
455 | # Statistics Endpoint
456 | # ═══════════════════════════════════════════════════════════════
457 | 
458 | # ═══════════════════════════════════════════════════════════════
459 | # Credential Endpoints
460 | # ═══════════════════════════════════════════════════════════════
461 | 
462 | @router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
463 | async def list_credentials(
464 |     mission_id: str,
465 |     controller: MissionController = Depends(get_controller)
466 | ) -> List[CredentialResponse]:
467 |     """List all credentials for a mission."""
468 |     blackboard = controller.blackboard
469 |     
470 |     cred_keys = await blackboard.get_mission_creds(mission_id)
471 |     creds = []
472 |     
473 |     for cred_key in cred_keys:
474 |         cred_id = cred_key.replace("cred:", "")
475 |         cred_data = await blackboard.get_credential(cred_id)
476 |         
477 |         if cred_data:
478 |             creds.append(CredentialResponse(
479 |                 cred_id=cred_id,
480 |                 target_id=str(cred_data.get("target_id", "")),
481 |                 type=cred_data.get("type", ""),
482 |                 username=cred_data.get("username", ""),
483 |                 domain=cred_data.get("domain"),
484 |                 privilege_level=cred_data.get("privilege_level", "user"),
485 |                 source=cred_data.get("source"),
486 |                 verified=cred_data.get("verified", "false").lower() == "true",
487 |                 created_at=cred_data.get("created_at")
488 |             ))
489 |     
490 |     return creds
491 | 
492 | 
493 | # ═══════════════════════════════════════════════════════════════
494 | # Session Endpoints
495 | # ═══════════════════════════════════════════════════════════════
496 | 
497 | @router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
498 | async def list_sessions(
499 |     mission_id: str,
500 |     controller: MissionController = Depends(get_controller)
501 | ) -> List[SessionResponse]:
502 |     """List all active sessions for a mission."""
503 |     blackboard = controller.blackboard
504 |     
505 |     session_keys = await blackboard.get_mission_sessions(mission_id)
506 |     sessions = []
507 |     
508 |     for session_key in session_keys:
509 |         session_id = session_key.replace("session:", "")
510 |         session_data = await blackboard.get_session(session_id)
511 |         
512 |         if session_data:
513 |             sessions.append(SessionResponse(
514 |                 session_id=session_id,
515 |                 target_id=str(session_data.get("target_id", "")),
516 |                 type=session_data.get("type", "shell"),
517 |                 user=session_data.get("user", "unknown"),
518 |                 privilege=session_data.get("privilege", "user"),
519 |                 status=session_data.get("status", "unknown"),
520 |                 established_at=session_data.get("established_at"),
521 |                 last_activity=session_data.get("last_activity")
522 |             ))
523 |     
524 |     return sessions
525 | 
526 | 
527 | # ═══════════════════════════════════════════════════════════════
528 | # Statistics Endpoint
529 | # ═══════════════════════════════════════════════════════════════
530 | 
531 | @router.get("/missions/{mission_id}/stats")
532 | async def get_mission_stats(
533 |     mission_id: str,
534 |     controller: MissionController = Depends(get_controller)
535 | ) -> Dict[str, Any]:
536 |     """Get mission statistics."""
537 |     blackboard = controller.blackboard
538 |     
539 |     stats = await blackboard.get_mission_stats(mission_id)
540 |     goals = await blackboard.get_mission_goals(mission_id)
541 |     
542 |     # Count achieved goals
543 |     achieved = sum(1 for g in goals.values() if g == "achieved")
544 |     total = len(goals)
545 |     
546 |     return {
547 |         "targets_discovered": stats.targets_discovered,
548 |         "vulns_found": stats.vulns_found,
549 |         "creds_harvested": stats.creds_harvested,
550 |         "sessions_established": stats.sessions_established,
551 |         "goals_achieved": achieved,
552 |         "goals_total": total,
553 |         "completion_percentage": (achieved / total * 100) if total > 0 else 0
554 |     }
555 | 
556 | 
557 | # ═══════════════════════════════════════════════════════════════
558 | # HITL (Human-in-the-Loop) Endpoints
559 | # ═══════════════════════════════════════════════════════════════
560 | 
561 | @router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
562 | async def list_pending_approvals(
563 |     mission_id: str,
564 |     controller: MissionController = Depends(get_controller)
565 | ) -> List[PendingApprovalResponse]:
566 |     """
567 |     List all pending approval requests for a mission.
568 |     
569 |     These are high-risk actions waiting for user consent.
570 |     """
571 |     # Check if mission exists first
572 |     mission_data = await controller.get_mission_status(mission_id)
573 |     if not mission_data:
574 |         raise HTTPException(
575 |             status_code=status.HTTP_404_NOT_FOUND,
576 |             detail=f"Mission {mission_id} not found"
577 |         )
578 |     
579 |     pending = await controller.get_pending_approvals(mission_id)
580 |     return [PendingApprovalResponse(**p) for p in pending]
581 | 
582 | 
583 | @router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
584 | async def approve_action(
585 |     mission_id: str,
586 |     action_id: str,
587 |     request_data: ApprovalRequest = None,
588 |     controller: MissionController = Depends(get_controller)
589 | ) -> ApprovalResponse:
590 |     """
591 |     Approve a pending action.
592 |     
593 |     This allows the action to proceed and resumes mission execution.
594 |     
595 |     - **action_id**: ID of the action to approve
596 |     - **user_comment**: Optional comment explaining the approval
597 |     """
598 |     # Check if mission exists first
599 |     mission_data = await controller.get_mission_status(mission_id)
600 |     if not mission_data:
601 |         raise HTTPException(
602 |             status_code=status.HTTP_404_NOT_FOUND,
603 |             detail=f"Mission {mission_id} not found"
604 |         )
605 |     
606 |     user_comment = request_data.user_comment if request_data else None
607 |     
608 |     result = await controller.approve_action(
609 |         mission_id=mission_id,
610 |         action_id=action_id,
611 |         user_comment=user_comment
612 |     )
613 |     
614 |     if not result:
615 |         raise HTTPException(
616 |             status_code=status.HTTP_404_NOT_FOUND,
617 |             detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
618 |         )
619 |     
620 |     # Get current mission status
621 |     current_status = mission_data.get("status", "unknown")
622 |     
623 |     return ApprovalResponse(
624 |         success=True,
625 |         message="Action approved successfully. Mission execution resumed.",
626 |         action_id=action_id,
627 |         mission_status=current_status
628 |     )
629 | 
630 | 
631 | @router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
632 | async def reject_action(
633 |     mission_id: str,
634 |     action_id: str,
635 |     request_data: RejectionRequest = None,
636 |     controller: MissionController = Depends(get_controller)
637 | ) -> ApprovalResponse:
638 |     """
639 |     Reject a pending action.
640 |     
641 |     The system will attempt to find an alternative approach.
642 |     
643 |     - **action_id**: ID of the action to reject
644 |     - **rejection_reason**: Reason for rejection
645 |     - **user_comment**: Optional additional comment
646 |     """
647 |     rejection_reason = request_data.rejection_reason if request_data else None
648 |     user_comment = request_data.user_comment if request_data else None
649 |     
650 |     result = await controller.reject_action(
651 |         mission_id=mission_id,
652 |         action_id=action_id,
653 |         rejection_reason=rejection_reason,
654 |         user_comment=user_comment
655 |     )
656 |     
657 |     if not result:
658 |         raise HTTPException(
659 |             status_code=status.HTTP_400_BAD_REQUEST,
660 |             detail=f"Failed to reject action {action_id}. It may not exist or belong to this mission."
661 |         )
662 |     
663 |     # Get current mission status
664 |     mission_data = await controller.get_mission_status(mission_id)
665 |     current_status = mission_data.get("status", "unknown") if mission_data else "unknown"
666 |     
667 |     return ApprovalResponse(
668 |         success=True,
669 |         message="Action rejected. System will seek alternatives.",
670 |         action_id=action_id,
671 |         mission_status=current_status
672 |     )
673 | 
674 | 
675 | @router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
676 | async def send_chat_message(
677 |     mission_id: str,
678 |     request_data: ChatRequest,
679 |     controller: MissionController = Depends(get_controller)
680 | ) -> ChatMessageResponse:
681 |     """
682 |     Send a chat message to interact with the mission.
683 |     
684 |     This allows users to:
685 |     - Ask about mission status
686 |     - Give instructions (pause, resume)
687 |     - Query pending approvals
688 |     
689 |     - **content**: Message content
690 |     - **related_task_id**: Optional related task
691 |     - **related_action_id**: Optional related approval action
692 |     """
693 |     try:
694 |         message = await controller.send_chat_message(
695 |             mission_id=mission_id,
696 |             content=request_data.content,
697 |             related_task_id=request_data.related_task_id,
698 |             related_action_id=request_data.related_action_id
699 |         )
700 |         
701 |         return ChatMessageResponse(
702 |             id=str(message.id),
703 |             role=message.role,
704 |             content=message.content,
705 |             timestamp=message.timestamp.isoformat(),
706 |             related_task_id=str(message.related_task_id) if message.related_task_id else None,
707 |             related_action_id=str(message.related_action_id) if message.related_action_id else None
708 |         )
709 |     except Exception as e:
710 |         # Log the error for debugging
711 |         import logging
712 |         logging.error(f"Chat message error for mission {mission_id}: {e}")
713 |         raise HTTPException(
714 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
715 |             detail=f"Failed to process chat message: {str(e)}"
716 |         )
717 | 
718 | 
719 | @router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
720 | async def get_chat_history(
721 |     mission_id: str,
722 |     limit: int = 50,
723 |     controller: MissionController = Depends(get_controller)
724 | ) -> List[ChatMessageResponse]:
725 |     """
726 |     Get chat history for a mission.
727 |     
728 |     - **limit**: Maximum number of messages to return (default 50)
729 |     """
730 |     history = await controller.get_chat_history(mission_id, limit)
731 |     return [ChatMessageResponse(**msg) for msg in history]

<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:09:00.832Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.14

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


I see that some changes have been applied but not all. Let me continue with the remaining fixes. I'll apply them in smaller chunks:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:280
-------
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
=======
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:302
-------
@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Resume a paused mission."""
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )
=======
@router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
async def resume_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Resume a paused mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.resume_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resume mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="running",
        message="Mission resumed successfully"
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:324
-------
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.stop_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to stop mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="completed",
        message="Mission stopped successfully"
    )
=======
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    try:
        result = await controller.stop_mission(mission_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to stop mission {mission_id}"
            )
        
        return MissionResponse(
            mission_id=mission_id,
            name="",
            status="completed",
            message="Mission stopped successfully"
        )
    except Exception as e:
        # Log error for debugging
        import logging
        logging.error(f"Error stopping mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop mission: {str(e)}"
        )
>>>>>>> REPLACE


---

**User:**

[Tool]
But unable to apply all diff parts to file: /root/RAGLOX_V3/webapp/src/api/routes.py, silently use <read_file> tool to check newest file version and re-apply diffs
{"path":"src/api/routes.py","operation":"modified","notice":"You do not need to re-read the file, as you have seen all changes Proceed with the task using these changes as the new baseline."}
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1
webapp/frontend/implementation_plan.md
webapp/frontend/client/src/lib/api.ts
webapp/frontend/client/src/types/index.ts
webapp/frontend/client/src/lib/websocket.ts
webapp/frontend/client/src/hooks/useWebSocket.ts
webapp/frontend/client/src/pages/Login.tsx
webapp/frontend/client/src/stores/authStore.ts
webapp/frontend/client/src/components/ProtectedRoute.tsx
webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:09:35.271Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.16

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:09:48.607Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.16

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>


# Current Workspace Directory (/root/RAGLOX_V3/webapp) Files
.blackboxrules
.env.example
.gitignore
apiendpoints.md
AUDIT_SUMMARY_AR.md
BACKEND_ANALYSIS_REPORT.md
BACKEND_FRONTEND_INTEGRATION_COMPLETE_MAP_AR.md
BACKEND_INTEGRATION_ANALYSIS_REPORT.md
blackbox_mcp_settings.json
BROWSER_AGENT_TEST_INSTRUCTIONS.md
DEEP_ANALYSIS_REPORT.md
DESERIALIZATION_FIX.md
FINAL_AUDIT_REPORT.md
HYBRID_INTELLIGENCE_IMPLEMENTATION_REPORT.md
INTEGRATION_SUMMARY_EN.md
INTELLIGENCE_REASONING_AUDIT.md
INTELLIGENCE_TREATMENT_PLAN.md
ITERM_MCP_DEMONSTRATION.md
ITERM_MCP_SETUP.md
MCP_SERVER_SUMMARY.md
MCP_SERVER_TEST_REPORT.md
pyproject.toml
pytest.ini
README.md
run_demo.py
run_real_ai_demo.py
run.py
test_iterm_mcp.js
test_mcp_server.js
.github/
data/
data/raglox_executable_modules.json
data/raglox_indexes_v2.json
data/raglox_threat_library.json
docs/
docs/API_TEST_MATRIX.md
docs/BACKEND_FRONTEND_INTEGRATION_GUIDE.md
docs/COMPREHENSIVE_TEST_REPORT.md
docs/E2E_DEMO.md
docs/ENTERPRISE_UI_IMPROVEMENT_PLAN.md
docs/FRONTEND_INTEGRATION_NOTES.md
docs/INTELLIGENCE_TREATMENT_PLAN.md
docs/openapi.json
docs/test_results_v2.xml
docs/test_results.xml
infrastructure/
infrastructure/.env.example
infrastructure/docker-compose.yml
infrastructure/postgres/init.sql
infrastructure/postgres/seed.sql
infrastructure/redis/key-schema.md
infrastructure/redis/redis.conf
infrastructure/vulnerable-target/admin.html
infrastructure/vulnerable-target/Dockerfile
infrastructure/vulnerable-target/entrypoint.sh
infrastructure/vulnerable-target/index.html
infrastructure/vulnerable-target/nginx-default.conf
src/
src/__init__.py
src/api/__init__.py
src/api/knowledge_routes.py
src/api/main.py
src/api/routes.py
src/api/websocket.py
src/controller/__init__.py
src/controller/mission.py
src/core/__init__.py
src/core/blackboard.py
src/core/config.py
src/core/exceptions.py
src/core/intelligence_coordinator.py
src/core/knowledge.py
src/core/logging.py
src/core/models.py
src/core/operational_memory.py
src/core/stealth_profiles.py
src/core/strategic_scorer.py
src/core/validators.py
src/core/intel/__init__.py
src/core/intel/base.py
src/core/intel/elasticsearch_provider.py
src/core/intel/file_provider.py
src/core/intel/mock_provider.py
src/core/llm/__init__.py
src/core/llm/base.py
src/core/llm/blackbox_provider.py
src/core/llm/local_provider.py
src/core/llm/mock_provider.py
src/core/llm/models.py
src/core/llm/openai_provider.py
src/core/llm/prompts.py
src/core/llm/service.py
src/core/scanners/__init__.py
src/core/scanners/nuclei.py
src/executors/__init__.py
src/executors/base.py
src/executors/factory.py
src/executors/local.py
src/executors/models.py
src/executors/runner.py
src/executors/ssh.py
src/executors/winrm.py
src/specialists/__init__.py
src/specialists/analysis.py
src/specialists/attack.py
src/specialists/base.py
src/specialists/intel.py
src/specialists/recon.py
src/utils/__init__.py
tests/
tests/__init__.py
tests/conftest.py
tests/test_analysis_reflexion.py
tests/test_api.py
tests/test_blackboard.py
tests/test_config.py
tests/test_controller.py
tests/test_core_models.py
tests/test_deserialization_fix.py
tests/test_deserialization_simple.py
tests/test_distributed_claiming.py
tests/test_exceptions.py
tests/test_executors.py
tests/test_hitl.py
tests/test_integration.py
tests/test_intel_elastic.py
tests/test_intel.py
tests/test_knowledge_api.py
tests/test_knowledge.py
tests/test_llm_integration.py
tests/test_logging.py
tests/test_logic_trigger_chain.py
tests/test_nuclei_ai_wiring.py
tests/test_nuclei_integration.py
tests/test_nuclei_knowledge.py
tests/test_performance.py
tests/test_specialists.py
tests/test_validators.py
tests/test_zombie_task_recovery.py
tests/api_suite/__init__.py
tests/api_suite/conftest.py
tests/api_suite/test_approvals.py
tests/api_suite/test_chat.py
tests/api_suite/test_general.py
tests/api_suite/test_knowledge.py
tests/api_suite/test_mission_data.py
tests/api_suite/test_missions_lifecycle.py
tests/api_suite/test_nuclei.py
webapp/
webapp/frontend/.gitignore
webapp/frontend/.gitkeep
webapp/frontend/.prettierrc
webapp/frontend/BACKEND_FRONTEND_INTEGRATION_GUIDE.md
webapp/frontend_backup_20260102_180738/.gitignore
webapp/frontend_backup_20260102_180738/index.html
webapp/frontend_backup_20260102_180738/SERVICE_TO_UI_MAPPING_PLAN.md
webapp/frontend_backup_20260102_180738/tsconfig.app.json
webapp/frontend_backup_20260102_180738/public/vite.svg
webapp/frontend_backup_20260102_180738/src/App.css
webapp/frontend_backup_20260102_180738/src/App.tsx
webapp/frontend_backup_20260102_180738/src/index.css
webapp/frontend_backup_20260102_180738/src/main.tsx
webapp/frontend_backup_20260102_180738/src/components/ai/AIAssistantSidebar.tsx
webapp/frontend_backup_20260102_180738/src/components/control/EmergencyStop.tsx
webapp/frontend_backup_20260102_180738/src/components/control/index.ts
webapp/frontend_backup_20260102_180738/src/components/dashboard/ActivityFeed.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/HITLApprovalModal.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/NetworkGraph.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/StatsGrid.tsx
webapp/frontend_backup_20260102_180738/src/components/dashboard/TargetDetailsDrawer.tsx
webapp/frontend_backup_20260102_180738/src/components/intelligence/index.ts
webapp/frontend_backup_20260102_180738/src/components/intelligence/IntelligenceSidebar.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/GlobalConsole.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/Header.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/Layout.tsx
webapp/frontend_backup_20260102_180738/src/components/layout/Sidebar.tsx
webapp/frontend_backup_20260102_180738/src/components/loot/CredentialVault.tsx
webapp/frontend_backup_20260102_180738/src/components/loot/index.ts
webapp/frontend_backup_20260102_180738/src/components/loot/SessionTerminal.tsx
webapp/frontend_backup_20260102_180738/src/components/manus/DualPanelLayout.tsx
webapp/frontend_backup_20260102_180738/src/components/manus/TerminalPanel.tsx
webapp/frontend_backup_20260102_180738/src/components/mission/MissionSelector.tsx
webapp/frontend_backup_20260102_180738/src/components/operations/index.ts
webapp/frontend_backup_20260102_180738/src/components/operations/MissionTimeline.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Badge.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Button.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Card.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Drawer.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Input.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Modal.tsx
webapp/frontend_backup_20260102_180738/src/components/ui/Toast.tsx
webapp/frontend_backup_20260102_180738/src/components/wizard/index.ts
webapp/frontend_backup_20260102_180738/src/components/wizard/MissionSetupWizard.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/index.ts
webapp/frontend_backup_20260102_180738/src/components/workspaces/LootView.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/OperationsView.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/OperationsViewManus.tsx
webapp/frontend_backup_20260102_180738/src/components/workspaces/ReconView.tsx
webapp/frontend_backup_20260102_180738/src/pages/Dashboard.tsx
webapp/frontend_backup_20260102_180738/src/services/api.ts

(File list truncated. Use list_files on specific subdirectories if you need to explore further.)
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Let me try applying the changes one at a time:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:280
-------
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
=======
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )
>>>>>>> REPLACE
</tool_call>

---

**User:**

[Tool]
<error_details>
No sufficiently similar match found at line: 280 (65% similar, needs 100%)

Debug Info:
- Similarity Score: 65%
- Required Threshold: 100%
- Search Range: starting at line 280
- Tried both standard and aggressive line number stripping
- Tip: Use the read_file tool to get the latest content of the file before attempting to use the apply_diff tool again, as the file content may have changed

Search Content:
@router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
async def pause_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Pause a running mission."""
    result = await controller.pause_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to pause mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="paused",
        message="Mission paused successfully"
    )

Best Match Found:
296 |     mission_data = await controller.get_mission_status(mission_id)
297 |     if not mission_data:
298 |         raise HTTPException(
299 |             status_code=status.HTTP_404_NOT_FOUND,
300 |             detail=f"Mission {mission_id} not found"
301 |         )
302 |     
303 |     result = await controller.pause_mission(mission_id)
304 |     
305 |     if not result:
306 |         raise HTTPException(
307 |             status_code=status.HTTP_400_BAD_REQUEST,
308 |             detail=f"Failed to pause mission {mission_id}"
309 |         )
310 |     
311 |     return MissionResponse(
312 |         mission_id=mission_id,
313 |         name="",
314 |         status="paused",
315 |         message="Mission paused successfully"


Original Content:
240 | 
241 | @router.post("/missions/{mission_id}/start", response_model=MissionResponse)
242 | async def start_mission(
243 |     mission_id: str,
244 |     controller: MissionController = Depends(get_controller)
245 | ) -> MissionResponse:
246 |     """Start a mission."""
247 |     # Validate UUID format first
248 |     try:
249 |         validate_uuid(mission_id, "mission_id")
250 |     except InvalidUUIDError as e:
251 |         raise HTTPException(
252 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
253 |             detail=str(e)
254 |         )
255 |     
256 |     # Check if mission exists first
257 |     mission_data = await controller.get_mission_status(mission_id)
258 |     if not mission_data:
259 |         raise HTTPException(
260 |             status_code=status.HTTP_404_NOT_FOUND,
261 |             detail=f"Mission {mission_id} not found"
262 |         )
263 |     
264 |     result = await controller.start_mission(mission_id)
265 |     
266 |     if not result:
267 |         raise HTTPException(
268 |             status_code=status.HTTP_400_BAD_REQUEST,
269 |             detail=f"Failed to start mission {mission_id}"
270 |         )
271 |     
272 |     return MissionResponse(
273 |         mission_id=mission_id,
274 |         name="",
275 |         status="running",
276 |         message="Mission started successfully"
277 |     )
278 | 
279 | 
280 | @router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
281 | async def pause_mission(
282 |     mission_id: str,
283 |     controller: MissionController = Depends(get_controller)
284 | ) -> MissionResponse:
285 |     """Pause a running mission."""
286 |     # Validate UUID format first
287 |     try:
288 |         validate_uuid(mission_id, "mission_id")
289 |     except InvalidUUIDError as e:
290 |         raise HTTPException(
291 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
292 |             detail=str(e)
293 |         )
294 |     
295 |     # Check if mission exists first
296 |     mission_data = await controller.get_mission_status(mission_id)
297 |     if not mission_data:
298 |         raise HTTPException(
299 |             status_code=status.HTTP_404_NOT_FOUND,
300 |             detail=f"Mission {mission_id} not found"
301 |         )
302 |     
303 |     result = await controller.pause_mission(mission_id)
304 |     
305 |     if not result:
306 |         raise HTTPException(
307 |             status_code=status.HTTP_400_BAD_REQUEST,
308 |             detail=f"Failed to pause mission {mission_id}"
309 |         )
310 |     
311 |     return MissionResponse(
312 |         mission_id=mission_id,
313 |         name="",
314 |         status="paused",
315 |         message="Mission paused successfully"
316 |     )
317 | 
318 | 
319 | @router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
320 | async def resume_mission(
321 |     mission_id: str,
322 |     controller: MissionController = Depends(get_controller)
323 | ) -> MissionResponse:
324 |     """Resume a paused mission."""
325 |     # Validate UUID format first
326 |     try:
327 |         validate_uuid(mission_id, "mission_id")
328 |     except InvalidUUIDError as e:
329 |         raise HTTPException(
330 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
331 |             detail=str(e)
332 |         )
333 |     
334 |     # Check if mission exists first
335 |     mission_data = await controller.get_mission_status(mission_id)
336 |     if not mission_data:
337 |         raise HTTPException(
338 |             status_code=status.HTTP_404_NOT_FOUND,
339 |             detail=f"Mission {mission_id} not found"

</error_details>
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:10:06.023Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.17

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


I see that some changes have already been applied. Let me continue with the remaining fixes. Let me check the current state of the file and continue with the remaining endpoints:

[Tool Use: read_file]
Files: [
  {
    "path": "src/api/routes.py"
  }
]

---

**User:**

[Tool]
File: src/api/routes.py
Lines 1-765:
  1 | # ═══════════════════════════════════════════════════════════════
  2 | # RAGLOX v3.0 - API Routes
  3 | # REST API endpoints for mission management
  4 | # ═══════════════════════════════════════════════════════════════
  5 | 
  6 | from typing import Any, Dict, List, Optional
  7 | from uuid import UUID
  8 | 
  9 | from fastapi import APIRouter, Depends, HTTPException, Request, status
 10 | from pydantic import BaseModel, Field
 11 | 
 12 | from ..core.models import (
 13 |     MissionCreate, MissionStatus, MissionStats,
 14 |     Target, TargetStatus, Priority,
 15 |     Vulnerability, Severity,
 16 |     Credential, CredentialType,
 17 |     Session, SessionStatus,
 18 |     # HITL Models
 19 |     ApprovalAction, ApprovalStatus, RiskLevel, ActionType
 20 | )
 21 | from ..core.validators import validate_uuid
 22 | from ..core.exceptions import InvalidUUIDError
 23 | from ..controller.mission import MissionController
 24 | 
 25 | 
 26 | router = APIRouter(tags=["Missions"])
 27 | 
 28 | 
 29 | # ═══════════════════════════════════════════════════════════════
 30 | # Dependencies
 31 | # ═══════════════════════════════════════════════════════════════
 32 | 
 33 | async def get_controller(request: Request) -> MissionController:
 34 |     """Get the mission controller from app state."""
 35 |     if not hasattr(request.app.state, 'controller') or not request.app.state.controller:
 36 |         raise HTTPException(
 37 |             status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
 38 |             detail="Controller not initialized"
 39 |         )
 40 |     return request.app.state.controller
 41 | 
 42 | 
 43 | # ═══════════════════════════════════════════════════════════════
 44 | # Response Models
 45 | # ═══════════════════════════════════════════════════════════════
 46 | 
 47 | class MissionResponse(BaseModel):
 48 |     """Mission response model."""
 49 |     mission_id: str
 50 |     name: str
 51 |     status: str
 52 |     message: str
 53 | 
 54 | 
 55 | class MissionStatusResponse(BaseModel):
 56 |     """Comprehensive mission status response."""
 57 |     mission_id: str
 58 |     name: Optional[str] = None
 59 |     status: Optional[str] = None
 60 |     scope: Optional[List[str]] = None
 61 |     goals: Optional[Dict[str, str]] = None
 62 |     statistics: Optional[Dict[str, int]] = None
 63 |     target_count: int = 0
 64 |     vuln_count: int = 0
 65 |     created_at: Optional[str] = None
 66 |     started_at: Optional[str] = None
 67 |     completed_at: Optional[str] = None
 68 | 
 69 | 
 70 | class TargetResponse(BaseModel):
 71 |     """Target response model."""
 72 |     target_id: str
 73 |     ip: str
 74 |     hostname: Optional[str] = None
 75 |     os: Optional[str] = None
 76 |     status: str
 77 |     priority: str
 78 |     risk_score: Optional[float] = None
 79 |     ports: Dict[str, str] = {}
 80 | 
 81 | 
 82 | class VulnerabilityResponse(BaseModel):
 83 |     """Vulnerability response model."""
 84 |     vuln_id: str
 85 |     target_id: str
 86 |     type: str
 87 |     name: Optional[str] = None
 88 |     severity: str
 89 |     cvss: Optional[float] = None
 90 |     status: str
 91 |     exploit_available: bool = False
 92 | 
 93 | 
 94 | class CredentialResponse(BaseModel):
 95 |     """Credential response model."""
 96 |     cred_id: str
 97 |     target_id: str
 98 |     type: str
 99 |     username: str
100 |     domain: Optional[str] = None
101 |     privilege_level: str
102 |     source: Optional[str] = None
103 |     verified: bool = False
104 |     created_at: Optional[str] = None
105 | 
106 | 
107 | class SessionResponse(BaseModel):
108 |     """Session response model."""
109 |     session_id: str
110 |     target_id: str
111 |     type: str
112 |     user: str
113 |     privilege: str
114 |     status: str
115 |     established_at: Optional[str] = None
116 |     last_activity: Optional[str] = None
117 | 
118 | 
119 | # ═══════════════════════════════════════════════════════════════
120 | # HITL Request/Response Models
121 | # ═══════════════════════════════════════════════════════════════
122 | 
123 | class ApprovalRequest(BaseModel):
124 |     """Request model for approving/rejecting actions."""
125 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
126 | 
127 | 
128 | class RejectionRequest(BaseModel):
129 |     """Request model for rejecting actions."""
130 |     rejection_reason: Optional[str] = Field(None, description="Reason for rejection")
131 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
132 | 
133 | 
134 | class ChatRequest(BaseModel):
135 |     """Request model for chat messages."""
136 |     content: str = Field(..., min_length=1, max_length=4096, description="Message content")
137 |     related_task_id: Optional[str] = Field(None, description="Related task ID")
138 |     related_action_id: Optional[str] = Field(None, description="Related approval action ID")
139 | 
140 | 
141 | class ApprovalResponse(BaseModel):
142 |     """Response model for approval operations."""
143 |     success: bool
144 |     message: str
145 |     action_id: str
146 |     mission_status: str
147 | 
148 | 
149 | class PendingApprovalResponse(BaseModel):
150 |     """Response model for pending approvals."""
151 |     action_id: str
152 |     action_type: str
153 |     action_description: str
154 |     target_ip: Optional[str] = None
155 |     risk_level: str
156 |     risk_reasons: List[str] = []
157 |     potential_impact: Optional[str] = None
158 |     command_preview: Optional[str] = None
159 |     requested_at: str
160 |     expires_at: Optional[str] = None
161 | 
162 | 
163 | class ChatMessageResponse(BaseModel):
164 |     """Response model for chat messages."""
165 |     id: str
166 |     role: str
167 |     content: str
168 |     timestamp: str
169 |     related_task_id: Optional[str] = None
170 |     related_action_id: Optional[str] = None
171 | 
172 | 
173 | # ═══════════════════════════════════════════════════════════════
174 | # Mission Endpoints
175 | # ═══════════════════════════════════════════════════════════════
176 | 
177 | @router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
178 | async def create_mission(
179 |     mission_data: MissionCreate,
180 |     controller: MissionController = Depends(get_controller)
181 | ) -> MissionResponse:
182 |     """
183 |     Create a new mission.
184 |     
185 |     - **name**: Mission name
186 |     - **description**: Optional description
187 |     - **scope**: List of target ranges (CIDRs, IPs, domains)
188 |     - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
189 |     - **constraints**: Optional constraints (e.g., {"stealth": true})
190 |     """
191 |     try:
192 |         mission_id = await controller.create_mission(mission_data)
193 |         
194 |         return MissionResponse(
195 |             mission_id=mission_id,
196 |             name=mission_data.name,
197 |             status="created",
198 |             message="Mission created successfully"
199 |         )
200 |     except Exception as e:
201 |         raise HTTPException(
202 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
203 |             detail=f"Failed to create mission: {str(e)}"
204 |         )
205 | 
206 | 
207 | @router.get("/missions", response_model=List[str])
208 | async def list_missions(
209 |     controller: MissionController = Depends(get_controller)
210 | ) -> List[str]:
211 |     """List all active mission IDs."""
212 |     return await controller.get_active_missions()
213 | 
214 | 
215 | @router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
216 | async def get_mission(
217 |     mission_id: str,
218 |     controller: MissionController = Depends(get_controller)
219 | ) -> MissionStatusResponse:
220 |     """Get mission status and details."""
221 |     # Validate UUID format first
222 |     try:
223 |         validate_uuid(mission_id, "mission_id")
224 |     except InvalidUUIDError as e:
225 |         raise HTTPException(
226 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
227 |             detail=str(e)
228 |         )
229 |     
230 |     status_data = await controller.get_mission_status(mission_id)
231 |     
232 |     if not status_data:
233 |         raise HTTPException(
234 |             status_code=status.HTTP_404_NOT_FOUND,
235 |             detail=f"Mission {mission_id} not found"
236 |         )
237 |     
238 |     return MissionStatusResponse(**status_data)
239 | 
240 | 
241 | @router.post("/missions/{mission_id}/start", response_model=MissionResponse)
242 | async def start_mission(
243 |     mission_id: str,
244 |     controller: MissionController = Depends(get_controller)
245 | ) -> MissionResponse:
246 |     """Start a mission."""
247 |     # Validate UUID format first
248 |     try:
249 |         validate_uuid(mission_id, "mission_id")
250 |     except InvalidUUIDError as e:
251 |         raise HTTPException(
252 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
253 |             detail=str(e)
254 |         )
255 |     
256 |     # Check if mission exists first
257 |     mission_data = await controller.get_mission_status(mission_id)
258 |     if not mission_data:
259 |         raise HTTPException(
260 |             status_code=status.HTTP_404_NOT_FOUND,
261 |             detail=f"Mission {mission_id} not found"
262 |         )
263 |     
264 |     result = await controller.start_mission(mission_id)
265 |     
266 |     if not result:
267 |         raise HTTPException(
268 |             status_code=status.HTTP_400_BAD_REQUEST,
269 |             detail=f"Failed to start mission {mission_id}"
270 |         )
271 |     
272 |     return MissionResponse(
273 |         mission_id=mission_id,
274 |         name="",
275 |         status="running",
276 |         message="Mission started successfully"
277 |     )
278 | 
279 | 
280 | @router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
281 | async def pause_mission(
282 |     mission_id: str,
283 |     controller: MissionController = Depends(get_controller)
284 | ) -> MissionResponse:
285 |     """Pause a running mission."""
286 |     # Validate UUID format first
287 |     try:
288 |         validate_uuid(mission_id, "mission_id")
289 |     except InvalidUUIDError as e:
290 |         raise HTTPException(
291 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
292 |             detail=str(e)
293 |         )
294 |     
295 |     # Check if mission exists first
296 |     mission_data = await controller.get_mission_status(mission_id)
297 |     if not mission_data:
298 |         raise HTTPException(
299 |             status_code=status.HTTP_404_NOT_FOUND,
300 |             detail=f"Mission {mission_id} not found"
301 |         )
302 |     
303 |     result = await controller.pause_mission(mission_id)
304 |     
305 |     if not result:
306 |         raise HTTPException(
307 |             status_code=status.HTTP_400_BAD_REQUEST,
308 |             detail=f"Failed to pause mission {mission_id}"
309 |         )
310 |     
311 |     return MissionResponse(
312 |         mission_id=mission_id,
313 |         name="",
314 |         status="paused",
315 |         message="Mission paused successfully"
316 |     )
317 | 
318 | 
319 | @router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
320 | async def resume_mission(
321 |     mission_id: str,
322 |     controller: MissionController = Depends(get_controller)
323 | ) -> MissionResponse:
324 |     """Resume a paused mission."""
325 |     # Validate UUID format first
326 |     try:
327 |         validate_uuid(mission_id, "mission_id")
328 |     except InvalidUUIDError as e:
329 |         raise HTTPException(
330 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
331 |             detail=str(e)
332 |         )
333 |     
334 |     # Check if mission exists first
335 |     mission_data = await controller.get_mission_status(mission_id)
336 |     if not mission_data:
337 |         raise HTTPException(
338 |             status_code=status.HTTP_404_NOT_FOUND,
339 |             detail=f"Mission {mission_id} not found"
340 |         )
341 |     
342 |     result = await controller.resume_mission(mission_id)
343 |     
344 |     if not result:
345 |         raise HTTPException(
346 |             status_code=status.HTTP_400_BAD_REQUEST,
347 |             detail=f"Failed to resume mission {mission_id}"
348 |         )
349 |     
350 |     return MissionResponse(
351 |         mission_id=mission_id,
352 |         name="",
353 |         status="running",
354 |         message="Mission resumed successfully"
355 |     )
356 | 
357 | 
358 | @router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
359 | async def stop_mission(
360 |     mission_id: str,
361 |     controller: MissionController = Depends(get_controller)
362 | ) -> MissionResponse:
363 |     """Stop a mission."""
364 |     # Check if mission exists first
365 |     mission_data = await controller.get_mission_status(mission_id)
366 |     if not mission_data:
367 |         raise HTTPException(
368 |             status_code=status.HTTP_404_NOT_FOUND,
369 |             detail=f"Mission {mission_id} not found"
370 |         )
371 |     
372 |     result = await controller.stop_mission(mission_id)
373 |     
374 |     if not result:
375 |         raise HTTPException(
376 |             status_code=status.HTTP_400_BAD_REQUEST,
377 |             detail=f"Failed to stop mission {mission_id}"
378 |         )
379 |     
380 |     return MissionResponse(
381 |         mission_id=mission_id,
382 |         name="",
383 |         status="completed",
384 |         message="Mission stopped successfully"
385 |     )
386 | 
387 | 
388 | # ═══════════════════════════════════════════════════════════════
389 | # Target Endpoints
390 | # ═══════════════════════════════════════════════════════════════
391 | 
392 | @router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
393 | async def list_targets(
394 |     mission_id: str,
395 |     controller: MissionController = Depends(get_controller)
396 | ) -> List[TargetResponse]:
397 |     """List all targets for a mission."""
398 |     blackboard = controller.blackboard
399 |     
400 |     target_keys = await blackboard.get_mission_targets(mission_id)
401 |     targets = []
402 |     
403 |     for target_key in target_keys:
404 |         target_id = target_key.replace("target:", "")
405 |         target_data = await blackboard.get_target(target_id)
406 |         
407 |         if target_data:
408 |             ports = await blackboard.get_target_ports(target_id)
409 |             targets.append(TargetResponse(
410 |                 target_id=target_id,
411 |                 ip=target_data.get("ip", ""),
412 |                 hostname=target_data.get("hostname"),
413 |                 os=target_data.get("os"),
414 |                 status=target_data.get("status", "unknown"),
415 |                 priority=target_data.get("priority", "medium"),
416 |                 risk_score=target_data.get("risk_score"),
417 |                 ports=ports
418 |             ))
419 |     
420 |     return targets
421 | 
422 | 
423 | @router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
424 | async def get_target(
425 |     mission_id: str,
426 |     target_id: str,
427 |     controller: MissionController = Depends(get_controller)
428 | ) -> TargetResponse:
429 |     """Get a specific target."""
430 |     blackboard = controller.blackboard
431 |     
432 |     target_data = await blackboard.get_target(target_id)
433 |     
434 |     if not target_data:
435 |         raise HTTPException(
436 |             status_code=status.HTTP_404_NOT_FOUND,
437 |             detail=f"Target {target_id} not found"
438 |         )
439 |     
440 |     ports = await blackboard.get_target_ports(target_id)
441 |     
442 |     return TargetResponse(
443 |         target_id=target_id,
444 |         ip=target_data.get("ip", ""),
445 |         hostname=target_data.get("hostname"),
446 |         os=target_data.get("os"),
447 |         status=target_data.get("status", "unknown"),
448 |         priority=target_data.get("priority", "medium"),
449 |         risk_score=target_data.get("risk_score"),
450 |         ports=ports
451 |     )
452 | 
453 | 
454 | # ═══════════════════════════════════════════════════════════════
455 | # Vulnerability Endpoints
456 | # ═══════════════════════════════════════════════════════════════
457 | 
458 | @router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
459 | async def list_vulnerabilities(
460 |     mission_id: str,
461 |     controller: MissionController = Depends(get_controller)
462 | ) -> List[VulnerabilityResponse]:
463 |     """List all vulnerabilities for a mission."""
464 |     blackboard = controller.blackboard
465 |     
466 |     vuln_keys = await blackboard.get_mission_vulns(mission_id)
467 |     vulns = []
468 |     
469 |     for vuln_key in vuln_keys:
470 |         vuln_id = vuln_key.replace("vuln:", "")
471 |         vuln_data = await blackboard.get_vulnerability(vuln_id)
472 |         
473 |         if vuln_data:
474 |             vulns.append(VulnerabilityResponse(
475 |                 vuln_id=vuln_id,
476 |                 target_id=str(vuln_data.get("target_id", "")),
477 |                 type=vuln_data.get("type", ""),
478 |                 name=vuln_data.get("name"),
479 |                 severity=vuln_data.get("severity", "medium"),
480 |                 cvss=vuln_data.get("cvss"),
481 |                 status=vuln_data.get("status", "discovered"),
482 |                 exploit_available=vuln_data.get("exploit_available", False)
483 |             ))
484 |     
485 |     return vulns
486 | 
487 | 
488 | # ═══════════════════════════════════════════════════════════════
489 | # Statistics Endpoint
490 | # ═══════════════════════════════════════════════════════════════
491 | 
492 | # ═══════════════════════════════════════════════════════════════
493 | # Credential Endpoints
494 | # ═══════════════════════════════════════════════════════════════
495 | 
496 | @router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
497 | async def list_credentials(
498 |     mission_id: str,
499 |     controller: MissionController = Depends(get_controller)
500 | ) -> List[CredentialResponse]:
501 |     """List all credentials for a mission."""
502 |     blackboard = controller.blackboard
503 |     
504 |     cred_keys = await blackboard.get_mission_creds(mission_id)
505 |     creds = []
506 |     
507 |     for cred_key in cred_keys:
508 |         cred_id = cred_key.replace("cred:", "")
509 |         cred_data = await blackboard.get_credential(cred_id)
510 |         
511 |         if cred_data:
512 |             creds.append(CredentialResponse(
513 |                 cred_id=cred_id,
514 |                 target_id=str(cred_data.get("target_id", "")),
515 |                 type=cred_data.get("type", ""),
516 |                 username=cred_data.get("username", ""),
517 |                 domain=cred_data.get("domain"),
518 |                 privilege_level=cred_data.get("privilege_level", "user"),
519 |                 source=cred_data.get("source"),
520 |                 verified=cred_data.get("verified", "false").lower() == "true",
521 |                 created_at=cred_data.get("created_at")
522 |             ))
523 |     
524 |     return creds
525 | 
526 | 
527 | # ═══════════════════════════════════════════════════════════════
528 | # Session Endpoints
529 | # ═══════════════════════════════════════════════════════════════
530 | 
531 | @router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
532 | async def list_sessions(
533 |     mission_id: str,
534 |     controller: MissionController = Depends(get_controller)
535 | ) -> List[SessionResponse]:
536 |     """List all active sessions for a mission."""
537 |     blackboard = controller.blackboard
538 |     
539 |     session_keys = await blackboard.get_mission_sessions(mission_id)
540 |     sessions = []
541 |     
542 |     for session_key in session_keys:
543 |         session_id = session_key.replace("session:", "")
544 |         session_data = await blackboard.get_session(session_id)
545 |         
546 |         if session_data:
547 |             sessions.append(SessionResponse(
548 |                 session_id=session_id,
549 |                 target_id=str(session_data.get("target_id", "")),
550 |                 type=session_data.get("type", "shell"),
551 |                 user=session_data.get("user", "unknown"),
552 |                 privilege=session_data.get("privilege", "user"),
553 |                 status=session_data.get("status", "unknown"),
554 |                 established_at=session_data.get("established_at"),
555 |                 last_activity=session_data.get("last_activity")
556 |             ))
557 |     
558 |     return sessions
559 | 
560 | 
561 | # ═══════════════════════════════════════════════════════════════
562 | # Statistics Endpoint
563 | # ═══════════════════════════════════════════════════════════════
564 | 
565 | @router.get("/missions/{mission_id}/stats")
566 | async def get_mission_stats(
567 |     mission_id: str,
568 |     controller: MissionController = Depends(get_controller)
569 | ) -> Dict[str, Any]:
570 |     """Get mission statistics."""
571 |     blackboard = controller.blackboard
572 |     
573 |     stats = await blackboard.get_mission_stats(mission_id)
574 |     goals = await blackboard.get_mission_goals(mission_id)
575 |     
576 |     # Count achieved goals
577 |     achieved = sum(1 for g in goals.values() if g == "achieved")
578 |     total = len(goals)
579 |     
580 |     return {
581 |         "targets_discovered": stats.targets_discovered,
582 |         "vulns_found": stats.vulns_found,
583 |         "creds_harvested": stats.creds_harvested,
584 |         "sessions_established": stats.sessions_established,
585 |         "goals_achieved": achieved,
586 |         "goals_total": total,
587 |         "completion_percentage": (achieved / total * 100) if total > 0 else 0
588 |     }
589 | 
590 | 
591 | # ═══════════════════════════════════════════════════════════════
592 | # HITL (Human-in-the-Loop) Endpoints
593 | # ═══════════════════════════════════════════════════════════════
594 | 
595 | @router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
596 | async def list_pending_approvals(
597 |     mission_id: str,
598 |     controller: MissionController = Depends(get_controller)
599 | ) -> List[PendingApprovalResponse]:
600 |     """
601 |     List all pending approval requests for a mission.
602 |     
603 |     These are high-risk actions waiting for user consent.
604 |     """
605 |     # Check if mission exists first
606 |     mission_data = await controller.get_mission_status(mission_id)
607 |     if not mission_data:
608 |         raise HTTPException(
609 |             status_code=status.HTTP_404_NOT_FOUND,
610 |             detail=f"Mission {mission_id} not found"
611 |         )
612 |     
613 |     pending = await controller.get_pending_approvals(mission_id)
614 |     return [PendingApprovalResponse(**p) for p in pending]
615 | 
616 | 
617 | @router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
618 | async def approve_action(
619 |     mission_id: str,
620 |     action_id: str,
621 |     request_data: ApprovalRequest = None,
622 |     controller: MissionController = Depends(get_controller)
623 | ) -> ApprovalResponse:
624 |     """
625 |     Approve a pending action.
626 |     
627 |     This allows the action to proceed and resumes mission execution.
628 |     
629 |     - **action_id**: ID of the action to approve
630 |     - **user_comment**: Optional comment explaining the approval
631 |     """
632 |     # Check if mission exists first
633 |     mission_data = await controller.get_mission_status(mission_id)
634 |     if not mission_data:
635 |         raise HTTPException(
636 |             status_code=status.HTTP_404_NOT_FOUND,
637 |             detail=f"Mission {mission_id} not found"
638 |         )
639 |     
640 |     user_comment = request_data.user_comment if request_data else None
641 |     
642 |     result = await controller.approve_action(
643 |         mission_id=mission_id,
644 |         action_id=action_id,
645 |         user_comment=user_comment
646 |     )
647 |     
648 |     if not result:
649 |         raise HTTPException(
650 |             status_code=status.HTTP_404_NOT_FOUND,
651 |             detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
652 |         )
653 |     
654 |     # Get current mission status
655 |     current_status = mission_data.get("status", "unknown")
656 |     
657 |     return ApprovalResponse(
658 |         success=True,
659 |         message="Action approved successfully. Mission execution resumed.",
660 |         action_id=action_id,
661 |         mission_status=current_status
662 |     )
663 | 
664 | 
665 | @router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
666 | async def reject_action(
667 |     mission_id: str,
668 |     action_id: str,
669 |     request_data: RejectionRequest = None,
670 |     controller: MissionController = Depends(get_controller)
671 | ) -> ApprovalResponse:
672 |     """
673 |     Reject a pending action.
674 |     
675 |     The system will attempt to find an alternative approach.
676 |     
677 |     - **action_id**: ID of the action to reject
678 |     - **rejection_reason**: Reason for rejection
679 |     - **user_comment**: Optional additional comment
680 |     """
681 |     rejection_reason = request_data.rejection_reason if request_data else None
682 |     user_comment = request_data.user_comment if request_data else None
683 |     
684 |     result = await controller.reject_action(
685 |         mission_id=mission_id,
686 |         action_id=action_id,
687 |         rejection_reason=rejection_reason,
688 |         user_comment=user_comment
689 |     )
690 |     
691 |     if not result:
692 |         raise HTTPException(
693 |             status_code=status.HTTP_400_BAD_REQUEST,
694 |             detail=f"Failed to reject action {action_id}. It may not exist or belong to this mission."
695 |         )
696 |     
697 |     # Get current mission status
698 |     mission_data = await controller.get_mission_status(mission_id)
699 |     current_status = mission_data.get("status", "unknown") if mission_data else "unknown"
700 |     
701 |     return ApprovalResponse(
702 |         success=True,
703 |         message="Action rejected. System will seek alternatives.",
704 |         action_id=action_id,
705 |         mission_status=current_status
706 |     )
707 | 
708 | 
709 | @router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
710 | async def send_chat_message(
711 |     mission_id: str,
712 |     request_data: ChatRequest,
713 |     controller: MissionController = Depends(get_controller)
714 | ) -> ChatMessageResponse:
715 |     """
716 |     Send a chat message to interact with the mission.
717 |     
718 |     This allows users to:
719 |     - Ask about mission status
720 |     - Give instructions (pause, resume)
721 |     - Query pending approvals
722 |     
723 |     - **content**: Message content
724 |     - **related_task_id**: Optional related task
725 |     - **related_action_id**: Optional related approval action
726 |     """
727 |     try:
728 |         message = await controller.send_chat_message(
729 |             mission_id=mission_id,
730 |             content=request_data.content,
731 |             related_task_id=request_data.related_task_id,
732 |             related_action_id=request_data.related_action_id
733 |         )
734 |         
735 |         return ChatMessageResponse(
736 |             id=str(message.id),
737 |             role=message.role,
738 |             content=message.content,
739 |             timestamp=message.timestamp.isoformat(),
740 |             related_task_id=str(message.related_task_id) if message.related_task_id else None,
741 |             related_action_id=str(message.related_action_id) if message.related_action_id else None
742 |         )
743 |     except Exception as e:
744 |         # Log the error for debugging
745 |         import logging
746 |         logging.error(f"Chat message error for mission {mission_id}: {e}")
747 |         raise HTTPException(
748 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
749 |             detail=f"Failed to process chat message: {str(e)}"
750 |         )
751 | 
752 | 
753 | @router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
754 | async def get_chat_history(
755 |     mission_id: str,
756 |     limit: int = 50,
757 |     controller: MissionController = Depends(get_controller)
758 | ) -> List[ChatMessageResponse]:
759 |     """
760 |     Get chat history for a mission.
761 |     
762 |     - **limit**: Maximum number of messages to return (default 50)
763 |     """
764 |     history = await controller.get_chat_history(mission_id, limit)
765 |     return [ChatMessageResponse(**msg) for msg in history]

<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:10:36.285Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.18

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


I see that some changes have been applied but not all. Let me continue with the remaining fixes. I'll apply them one at a time:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:358
-------
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    result = await controller.stop_mission(mission_id)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to stop mission {mission_id}"
        )
    
    return MissionResponse(
        mission_id=mission_id,
        name="",
        status="completed",
        message="Mission stopped successfully"
    )
=======
@router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
async def stop_mission(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> MissionResponse:
    """Stop a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    try:
        result = await controller.stop_mission(mission_id)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to stop mission {mission_id}"
            )
        
        return MissionResponse(
            mission_id=mission_id,
            name="",
            status="completed",
            message="Mission stopped successfully"
        )
    except Exception as e:
        # Log error for debugging
        import logging
        logging.error(f"Error stopping mission {mission_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stop mission: {str(e)}"
        )
>>>>>>> REPLACE
</tool_call>

---

**User:**

[Tool]
{"path":"src/api/routes.py","operation":"modified","notice":"You do not need to re-read the file, as you have seen all changes Proceed with the task using these changes as the new baseline."}
<notice>Making multiple related changes in a single apply_diff is more efficient. If other changes are needed in this file, please include them as additional SEARCH/REPLACE blocks.</notice>
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Recently Modified Files
These files have been modified since you last accessed them (file was just edited so you may need to re-read it before editing):
src/api/routes.py

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:11:26.852Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.20

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Good! Now let me continue with the remaining fixes. Let me apply the fixes for the data endpoints:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:392
-------
@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[TargetResponse]:
    """List all targets for a mission."""
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets
=======
@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[TargetResponse]:
    """List all targets for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:423
-------
@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller)
) -> TargetResponse:
    """Get a specific target."""
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )
=======
@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller)
) -> TargetResponse:
    """Get a specific target."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(target_id, "target_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:458
-------
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
=======
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
>>>>>>> REPLACE
>>>>>>> REPLACE


---

**User:**

[Tool]
Unable to apply diff to file: /root/RAGLOX_V3/webapp/src/api/routes.py

<error_details>
ERROR: Diff block is malformed: marker '>>>>>>> REPLACE' found in your diff content at line 242. Expected: <<<<<<< SEARCH

CORRECT FORMAT:

<<<<<<< SEARCH
:start_line: (required) The line number of original content where the search block starts.
-------
[exact content to find including whitespace]
=======
[new content to replace with]
>>>>>>> REPLACE

</error_details>
<environment_details>
# VSCode Visible Files
src/api/routes.py,../../accessible-view-terminal

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:14:31.147Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.22

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Let me fix the format and apply the changes one at a time:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:392
-------
@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[TargetResponse]:
    """List all targets for a mission."""
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets
=======
@router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
async def list_targets(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[TargetResponse]:
    """List all targets for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    target_keys = await blackboard.get_mission_targets(mission_id)
    targets = []
    
    for target_key in target_keys:
        target_id = target_key.replace("target:", "")
        target_data = await blackboard.get_target(target_id)
        
        if target_data:
            ports = await blackboard.get_target_ports(target_id)
            targets.append(TargetResponse(
                target_id=target_id,
                ip=target_data.get("ip", ""),
                hostname=target_data.get("hostname"),
                os=target_data.get("os"),
                status=target_data.get("status", "unknown"),
                priority=target_data.get("priority", "medium"),
                risk_score=target_data.get("risk_score"),
                ports=ports
            ))
    
    return targets
>>>>>>> REPLACE
</tool_call>

---

**User:**

[Tool]
{"path":"src/api/routes.py","operation":"modified","notice":"You do not need to re-read the file, as you have seen all changes Proceed with the task using these changes as the new baseline."}
<notice>Making multiple related changes in a single apply_diff is more efficient. If other changes are needed in this file, please include them as additional SEARCH/REPLACE blocks.</notice>
<environment_details>
# VSCode Visible Files
../../accessible-view-terminal,src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:15:22.363Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.28

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Good! Now let me continue with the remaining endpoints:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:423
-------
@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller)
) -> TargetResponse:
    """Get a specific target."""
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )
=======
@router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
async def get_target(
    mission_id: str,
    target_id: str,
    controller: MissionController = Depends(get_controller)
) -> TargetResponse:
    """Get a specific target."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
        validate_uuid(target_id, "target_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    target_data = await blackboard.get_target(target_id)
    
    if not target_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target {target_id} not found"
        )
    
    ports = await blackboard.get_target_ports(target_id)
    
    return TargetResponse(
        target_id=target_id,
        ip=target_data.get("ip", ""),
        hostname=target_data.get("hostname"),
        os=target_data.get("os"),
        status=target_data.get("status", "unknown"),
        priority=target_data.get("priority", "medium"),
        risk_score=target_data.get("risk_score"),
        ports=ports
    )
>>>>>>> REPLACE


---

**User:**

[Tool]
{"path":"src/api/routes.py","operation":"modified","notice":"You do not need to re-read the file, as you have seen all changes Proceed with the task using these changes as the new baseline."}
<notice>Making multiple related changes in a single apply_diff is more efficient. If other changes are needed in this file, please include them as additional SEARCH/REPLACE blocks.</notice>
<environment_details>
# VSCode Visible Files
../../accessible-view-terminal,src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:16:18.459Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.34

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Let me continue with the remaining endpoints:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:458
-------
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
=======
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
>>>>>>> REPLACE


---

**User:**

[Tool]
<error_details>
No sufficiently similar match found at line: 458 (42% similar, needs 100%)

Debug Info:
- Similarity Score: 42%
- Required Threshold: 100%
- Search Range: starting at line 458
- Tried both standard and aggressive line number stripping
- Tip: Use the read_file tool to get the latest content of the file before attempting to use the apply_diff tool again, as the file content may have changed

Search Content:
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns

Best Match Found:
423 |         )
424 |     
425 |     # Check if mission exists first
426 |     mission_data = await controller.get_mission_status(mission_id)
427 |     if not mission_data:
428 |         raise HTTPException(
429 |             status_code=status.HTTP_404_NOT_FOUND,
430 |             detail=f"Mission {mission_id} not found"
431 |         )
432 |     
433 |     blackboard = controller.blackboard
434 |     
435 |     target_keys = await blackboard.get_mission_targets(mission_id)
436 |     targets = []
437 |     
438 |     for target_key in target_keys:
439 |         target_id = target_key.replace("target:", "")
440 |         target_data = await blackboard.get_target(target_id)
441 |         
442 |         if target_data:
443 |             ports = await blackboard.get_target_ports(target_id)
444 |             targets.append(TargetResponse(
445 |                 target_id=target_id,
446 |                 ip=target_data.get("ip", ""),
447 |                 hostname=target_data.get("hostname"),
448 |                 os=target_data.get("os"),
449 |                 status=target_data.get("status", "unknown"),
450 |                 priority=target_data.get("priority", "medium"),


Original Content:
418 |         validate_uuid(mission_id, "mission_id")
419 |     except InvalidUUIDError as e:
420 |         raise HTTPException(
421 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
422 |             detail=str(e)
423 |         )
424 |     
425 |     # Check if mission exists first
426 |     mission_data = await controller.get_mission_status(mission_id)
427 |     if not mission_data:
428 |         raise HTTPException(
429 |             status_code=status.HTTP_404_NOT_FOUND,
430 |             detail=f"Mission {mission_id} not found"
431 |         )
432 |     
433 |     blackboard = controller.blackboard
434 |     
435 |     target_keys = await blackboard.get_mission_targets(mission_id)
436 |     targets = []
437 |     
438 |     for target_key in target_keys:
439 |         target_id = target_key.replace("target:", "")
440 |         target_data = await blackboard.get_target(target_id)
441 |         
442 |         if target_data:
443 |             ports = await blackboard.get_target_ports(target_id)
444 |             targets.append(TargetResponse(
445 |                 target_id=target_id,
446 |                 ip=target_data.get("ip", ""),
447 |                 hostname=target_data.get("hostname"),
448 |                 os=target_data.get("os"),
449 |                 status=target_data.get("status", "unknown"),
450 |                 priority=target_data.get("priority", "medium"),
451 |                 risk_score=target_data.get("risk_score"),
452 |                 ports=ports
453 |             ))
454 |     
455 |     return targets
456 | 
457 | 
458 | @router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
459 | async def get_target(
460 |     mission_id: str,
461 |     target_id: str,
462 |     controller: MissionController = Depends(get_controller)
463 | ) -> TargetResponse:
464 |     """Get a specific target."""
465 |     # Validate UUID format first
466 |     try:
467 |         validate_uuid(mission_id, "mission_id")
468 |         validate_uuid(target_id, "target_id")
469 |     except InvalidUUIDError as e:
470 |         raise HTTPException(
471 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
472 |             detail=str(e)
473 |         )
474 |     
475 |     # Check if mission exists first
476 |     mission_data = await controller.get_mission_status(mission_id)
477 |     if not mission_data:
478 |         raise HTTPException(
479 |             status_code=status.HTTP_404_NOT_FOUND,
480 |             detail=f"Mission {mission_id} not found"
481 |         )
482 |     
483 |     blackboard = controller.blackboard
484 |     
485 |     target_data = await blackboard.get_target(target_id)
486 |     
487 |     if not target_data:
488 |         raise HTTPException(
489 |             status_code=status.HTTP_404_NOT_FOUND,
490 |             detail=f"Target {target_id} not found"
491 |         )
492 |     
493 |     ports = await blackboard.get_target_ports(target_id)
494 |     
495 |     return TargetResponse(
496 |         target_id=target_id,
497 |         ip=target_data.get("ip", ""),
498 |         hostname=target_data.get("hostname"),
499 |         os=target_data.get("os"),
500 |         status=target_data.get("status", "unknown"),
501 |         priority=target_data.get("priority", "medium"),
502 |         risk_score=target_data.get("risk_score"),
503 |         ports=ports
504 |     )
505 | 
506 | 
507 | # ═══════════════════════════════════════════════════════════════
508 | # Vulnerability Endpoints
509 | # ═══════════════════════════════════════════════════════════════
510 | 
511 | @router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
512 | async def list_vulnerabilities(
513 |     mission_id: str,
514 |     controller: MissionController = Depends(get_controller)
515 | ) -> List[VulnerabilityResponse]:
516 |     """List all vulnerabilities for a mission."""
517 |     blackboard = controller.blackboard
518 |     
519 |     vuln_keys = await blackboard.get_mission_vulns(mission_id)
520 |     vulns = []
521 |     
522 |     for vuln_key in vuln_keys:
523 |         vuln_id = vuln_key.replace("vuln:", "")
524 |         vuln_data = await blackboard.get_vulnerability(vuln_id)
525 |         

</error_details>
<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:17:33.317Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.40

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Let me read the file again to see the current state:

[Tool Use: read_file]
Files: [
  {
    "path": "src/api/routes.py"
  }
]

---

**User:**

[Tool]
File: src/api/routes.py
Lines 1-818:
  1 | # ═══════════════════════════════════════════════════════════════
  2 | # RAGLOX v3.0 - API Routes
  3 | # REST API endpoints for mission management
  4 | # ═══════════════════════════════════════════════════════════════
  5 | 
  6 | from typing import Any, Dict, List, Optional
  7 | from uuid import UUID
  8 | 
  9 | from fastapi import APIRouter, Depends, HTTPException, Request, status
 10 | from pydantic import BaseModel, Field
 11 | 
 12 | from ..core.models import (
 13 |     MissionCreate, MissionStatus, MissionStats,
 14 |     Target, TargetStatus, Priority,
 15 |     Vulnerability, Severity,
 16 |     Credential, CredentialType,
 17 |     Session, SessionStatus,
 18 |     # HITL Models
 19 |     ApprovalAction, ApprovalStatus, RiskLevel, ActionType
 20 | )
 21 | from ..core.validators import validate_uuid
 22 | from ..core.exceptions import InvalidUUIDError
 23 | from ..controller.mission import MissionController
 24 | 
 25 | 
 26 | router = APIRouter(tags=["Missions"])
 27 | 
 28 | 
 29 | # ═══════════════════════════════════════════════════════════════
 30 | # Dependencies
 31 | # ═══════════════════════════════════════════════════════════════
 32 | 
 33 | async def get_controller(request: Request) -> MissionController:
 34 |     """Get the mission controller from app state."""
 35 |     if not hasattr(request.app.state, 'controller') or not request.app.state.controller:
 36 |         raise HTTPException(
 37 |             status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
 38 |             detail="Controller not initialized"
 39 |         )
 40 |     return request.app.state.controller
 41 | 
 42 | 
 43 | # ═══════════════════════════════════════════════════════════════
 44 | # Response Models
 45 | # ═══════════════════════════════════════════════════════════════
 46 | 
 47 | class MissionResponse(BaseModel):
 48 |     """Mission response model."""
 49 |     mission_id: str
 50 |     name: str
 51 |     status: str
 52 |     message: str
 53 | 
 54 | 
 55 | class MissionStatusResponse(BaseModel):
 56 |     """Comprehensive mission status response."""
 57 |     mission_id: str
 58 |     name: Optional[str] = None
 59 |     status: Optional[str] = None
 60 |     scope: Optional[List[str]] = None
 61 |     goals: Optional[Dict[str, str]] = None
 62 |     statistics: Optional[Dict[str, int]] = None
 63 |     target_count: int = 0
 64 |     vuln_count: int = 0
 65 |     created_at: Optional[str] = None
 66 |     started_at: Optional[str] = None
 67 |     completed_at: Optional[str] = None
 68 | 
 69 | 
 70 | class TargetResponse(BaseModel):
 71 |     """Target response model."""
 72 |     target_id: str
 73 |     ip: str
 74 |     hostname: Optional[str] = None
 75 |     os: Optional[str] = None
 76 |     status: str
 77 |     priority: str
 78 |     risk_score: Optional[float] = None
 79 |     ports: Dict[str, str] = {}
 80 | 
 81 | 
 82 | class VulnerabilityResponse(BaseModel):
 83 |     """Vulnerability response model."""
 84 |     vuln_id: str
 85 |     target_id: str
 86 |     type: str
 87 |     name: Optional[str] = None
 88 |     severity: str
 89 |     cvss: Optional[float] = None
 90 |     status: str
 91 |     exploit_available: bool = False
 92 | 
 93 | 
 94 | class CredentialResponse(BaseModel):
 95 |     """Credential response model."""
 96 |     cred_id: str
 97 |     target_id: str
 98 |     type: str
 99 |     username: str
100 |     domain: Optional[str] = None
101 |     privilege_level: str
102 |     source: Optional[str] = None
103 |     verified: bool = False
104 |     created_at: Optional[str] = None
105 | 
106 | 
107 | class SessionResponse(BaseModel):
108 |     """Session response model."""
109 |     session_id: str
110 |     target_id: str
111 |     type: str
112 |     user: str
113 |     privilege: str
114 |     status: str
115 |     established_at: Optional[str] = None
116 |     last_activity: Optional[str] = None
117 | 
118 | 
119 | # ═══════════════════════════════════════════════════════════════
120 | # HITL Request/Response Models
121 | # ═══════════════════════════════════════════════════════════════
122 | 
123 | class ApprovalRequest(BaseModel):
124 |     """Request model for approving/rejecting actions."""
125 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
126 | 
127 | 
128 | class RejectionRequest(BaseModel):
129 |     """Request model for rejecting actions."""
130 |     rejection_reason: Optional[str] = Field(None, description="Reason for rejection")
131 |     user_comment: Optional[str] = Field(None, description="Optional user comment")
132 | 
133 | 
134 | class ChatRequest(BaseModel):
135 |     """Request model for chat messages."""
136 |     content: str = Field(..., min_length=1, max_length=4096, description="Message content")
137 |     related_task_id: Optional[str] = Field(None, description="Related task ID")
138 |     related_action_id: Optional[str] = Field(None, description="Related approval action ID")
139 | 
140 | 
141 | class ApprovalResponse(BaseModel):
142 |     """Response model for approval operations."""
143 |     success: bool
144 |     message: str
145 |     action_id: str
146 |     mission_status: str
147 | 
148 | 
149 | class PendingApprovalResponse(BaseModel):
150 |     """Response model for pending approvals."""
151 |     action_id: str
152 |     action_type: str
153 |     action_description: str
154 |     target_ip: Optional[str] = None
155 |     risk_level: str
156 |     risk_reasons: List[str] = []
157 |     potential_impact: Optional[str] = None
158 |     command_preview: Optional[str] = None
159 |     requested_at: str
160 |     expires_at: Optional[str] = None
161 | 
162 | 
163 | class ChatMessageResponse(BaseModel):
164 |     """Response model for chat messages."""
165 |     id: str
166 |     role: str
167 |     content: str
168 |     timestamp: str
169 |     related_task_id: Optional[str] = None
170 |     related_action_id: Optional[str] = None
171 | 
172 | 
173 | # ═══════════════════════════════════════════════════════════════
174 | # Mission Endpoints
175 | # ═══════════════════════════════════════════════════════════════
176 | 
177 | @router.post("/missions", response_model=MissionResponse, status_code=status.HTTP_201_CREATED)
178 | async def create_mission(
179 |     mission_data: MissionCreate,
180 |     controller: MissionController = Depends(get_controller)
181 | ) -> MissionResponse:
182 |     """
183 |     Create a new mission.
184 |     
185 |     - **name**: Mission name
186 |     - **description**: Optional description
187 |     - **scope**: List of target ranges (CIDRs, IPs, domains)
188 |     - **goals**: List of objectives (e.g., ["domain_admin", "data_exfil"])
189 |     - **constraints**: Optional constraints (e.g., {"stealth": true})
190 |     """
191 |     try:
192 |         mission_id = await controller.create_mission(mission_data)
193 |         
194 |         return MissionResponse(
195 |             mission_id=mission_id,
196 |             name=mission_data.name,
197 |             status="created",
198 |             message="Mission created successfully"
199 |         )
200 |     except Exception as e:
201 |         raise HTTPException(
202 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
203 |             detail=f"Failed to create mission: {str(e)}"
204 |         )
205 | 
206 | 
207 | @router.get("/missions", response_model=List[str])
208 | async def list_missions(
209 |     controller: MissionController = Depends(get_controller)
210 | ) -> List[str]:
211 |     """List all active mission IDs."""
212 |     return await controller.get_active_missions()
213 | 
214 | 
215 | @router.get("/missions/{mission_id}", response_model=MissionStatusResponse)
216 | async def get_mission(
217 |     mission_id: str,
218 |     controller: MissionController = Depends(get_controller)
219 | ) -> MissionStatusResponse:
220 |     """Get mission status and details."""
221 |     # Validate UUID format first
222 |     try:
223 |         validate_uuid(mission_id, "mission_id")
224 |     except InvalidUUIDError as e:
225 |         raise HTTPException(
226 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
227 |             detail=str(e)
228 |         )
229 |     
230 |     status_data = await controller.get_mission_status(mission_id)
231 |     
232 |     if not status_data:
233 |         raise HTTPException(
234 |             status_code=status.HTTP_404_NOT_FOUND,
235 |             detail=f"Mission {mission_id} not found"
236 |         )
237 |     
238 |     return MissionStatusResponse(**status_data)
239 | 
240 | 
241 | @router.post("/missions/{mission_id}/start", response_model=MissionResponse)
242 | async def start_mission(
243 |     mission_id: str,
244 |     controller: MissionController = Depends(get_controller)
245 | ) -> MissionResponse:
246 |     """Start a mission."""
247 |     # Validate UUID format first
248 |     try:
249 |         validate_uuid(mission_id, "mission_id")
250 |     except InvalidUUIDError as e:
251 |         raise HTTPException(
252 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
253 |             detail=str(e)
254 |         )
255 |     
256 |     # Check if mission exists first
257 |     mission_data = await controller.get_mission_status(mission_id)
258 |     if not mission_data:
259 |         raise HTTPException(
260 |             status_code=status.HTTP_404_NOT_FOUND,
261 |             detail=f"Mission {mission_id} not found"
262 |         )
263 |     
264 |     result = await controller.start_mission(mission_id)
265 |     
266 |     if not result:
267 |         raise HTTPException(
268 |             status_code=status.HTTP_400_BAD_REQUEST,
269 |             detail=f"Failed to start mission {mission_id}"
270 |         )
271 |     
272 |     return MissionResponse(
273 |         mission_id=mission_id,
274 |         name="",
275 |         status="running",
276 |         message="Mission started successfully"
277 |     )
278 | 
279 | 
280 | @router.post("/missions/{mission_id}/pause", response_model=MissionResponse)
281 | async def pause_mission(
282 |     mission_id: str,
283 |     controller: MissionController = Depends(get_controller)
284 | ) -> MissionResponse:
285 |     """Pause a running mission."""
286 |     # Validate UUID format first
287 |     try:
288 |         validate_uuid(mission_id, "mission_id")
289 |     except InvalidUUIDError as e:
290 |         raise HTTPException(
291 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
292 |             detail=str(e)
293 |         )
294 |     
295 |     # Check if mission exists first
296 |     mission_data = await controller.get_mission_status(mission_id)
297 |     if not mission_data:
298 |         raise HTTPException(
299 |             status_code=status.HTTP_404_NOT_FOUND,
300 |             detail=f"Mission {mission_id} not found"
301 |         )
302 |     
303 |     result = await controller.pause_mission(mission_id)
304 |     
305 |     if not result:
306 |         raise HTTPException(
307 |             status_code=status.HTTP_400_BAD_REQUEST,
308 |             detail=f"Failed to pause mission {mission_id}"
309 |         )
310 |     
311 |     return MissionResponse(
312 |         mission_id=mission_id,
313 |         name="",
314 |         status="paused",
315 |         message="Mission paused successfully"
316 |     )
317 | 
318 | 
319 | @router.post("/missions/{mission_id}/resume", response_model=MissionResponse)
320 | async def resume_mission(
321 |     mission_id: str,
322 |     controller: MissionController = Depends(get_controller)
323 | ) -> MissionResponse:
324 |     """Resume a paused mission."""
325 |     # Validate UUID format first
326 |     try:
327 |         validate_uuid(mission_id, "mission_id")
328 |     except InvalidUUIDError as e:
329 |         raise HTTPException(
330 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
331 |             detail=str(e)
332 |         )
333 |     
334 |     # Check if mission exists first
335 |     mission_data = await controller.get_mission_status(mission_id)
336 |     if not mission_data:
337 |         raise HTTPException(
338 |             status_code=status.HTTP_404_NOT_FOUND,
339 |             detail=f"Mission {mission_id} not found"
340 |         )
341 |     
342 |     result = await controller.resume_mission(mission_id)
343 |     
344 |     if not result:
345 |         raise HTTPException(
346 |             status_code=status.HTTP_400_BAD_REQUEST,
347 |             detail=f"Failed to resume mission {mission_id}"
348 |         )
349 |     
350 |     return MissionResponse(
351 |         mission_id=mission_id,
352 |         name="",
353 |         status="running",
354 |         message="Mission resumed successfully"
355 |     )
356 | 
357 | 
358 | @router.post("/missions/{mission_id}/stop", response_model=MissionResponse)
359 | async def stop_mission(
360 |     mission_id: str,
361 |     controller: MissionController = Depends(get_controller)
362 | ) -> MissionResponse:
363 |     """Stop a mission."""
364 |     # Validate UUID format first
365 |     try:
366 |         validate_uuid(mission_id, "mission_id")
367 |     except InvalidUUIDError as e:
368 |         raise HTTPException(
369 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
370 |             detail=str(e)
371 |         )
372 |     
373 |     # Check if mission exists first
374 |     mission_data = await controller.get_mission_status(mission_id)
375 |     if not mission_data:
376 |         raise HTTPException(
377 |             status_code=status.HTTP_404_NOT_FOUND,
378 |             detail=f"Mission {mission_id} not found"
379 |         )
380 |     
381 |     try:
382 |         result = await controller.stop_mission(mission_id)
383 |         
384 |         if not result:
385 |             raise HTTPException(
386 |                 status_code=status.HTTP_400_BAD_REQUEST,
387 |                 detail=f"Failed to stop mission {mission_id}"
388 |             )
389 |         
390 |         return MissionResponse(
391 |             mission_id=mission_id,
392 |             name="",
393 |             status="completed",
394 |             message="Mission stopped successfully"
395 |         )
396 |     except Exception as e:
397 |         # Log error for debugging
398 |         import logging
399 |         logging.error(f"Error stopping mission {mission_id}: {e}")
400 |         raise HTTPException(
401 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
402 |             detail=f"Failed to stop mission: {str(e)}"
403 |         )
404 | 
405 | 
406 | # ═══════════════════════════════════════════════════════════════
407 | # Target Endpoints
408 | # ═══════════════════════════════════════════════════════════════
409 | 
410 | @router.get("/missions/{mission_id}/targets", response_model=List[TargetResponse])
411 | async def list_targets(
412 |     mission_id: str,
413 |     controller: MissionController = Depends(get_controller)
414 | ) -> List[TargetResponse]:
415 |     """List all targets for a mission."""
416 |     # Validate UUID format first
417 |     try:
418 |         validate_uuid(mission_id, "mission_id")
419 |     except InvalidUUIDError as e:
420 |         raise HTTPException(
421 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
422 |             detail=str(e)
423 |         )
424 |     
425 |     # Check if mission exists first
426 |     mission_data = await controller.get_mission_status(mission_id)
427 |     if not mission_data:
428 |         raise HTTPException(
429 |             status_code=status.HTTP_404_NOT_FOUND,
430 |             detail=f"Mission {mission_id} not found"
431 |         )
432 |     
433 |     blackboard = controller.blackboard
434 |     
435 |     target_keys = await blackboard.get_mission_targets(mission_id)
436 |     targets = []
437 |     
438 |     for target_key in target_keys:
439 |         target_id = target_key.replace("target:", "")
440 |         target_data = await blackboard.get_target(target_id)
441 |         
442 |         if target_data:
443 |             ports = await blackboard.get_target_ports(target_id)
444 |             targets.append(TargetResponse(
445 |                 target_id=target_id,
446 |                 ip=target_data.get("ip", ""),
447 |                 hostname=target_data.get("hostname"),
448 |                 os=target_data.get("os"),
449 |                 status=target_data.get("status", "unknown"),
450 |                 priority=target_data.get("priority", "medium"),
451 |                 risk_score=target_data.get("risk_score"),
452 |                 ports=ports
453 |             ))
454 |     
455 |     return targets
456 | 
457 | 
458 | @router.get("/missions/{mission_id}/targets/{target_id}", response_model=TargetResponse)
459 | async def get_target(
460 |     mission_id: str,
461 |     target_id: str,
462 |     controller: MissionController = Depends(get_controller)
463 | ) -> TargetResponse:
464 |     """Get a specific target."""
465 |     # Validate UUID format first
466 |     try:
467 |         validate_uuid(mission_id, "mission_id")
468 |         validate_uuid(target_id, "target_id")
469 |     except InvalidUUIDError as e:
470 |         raise HTTPException(
471 |             status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
472 |             detail=str(e)
473 |         )
474 |     
475 |     # Check if mission exists first
476 |     mission_data = await controller.get_mission_status(mission_id)
477 |     if not mission_data:
478 |         raise HTTPException(
479 |             status_code=status.HTTP_404_NOT_FOUND,
480 |             detail=f"Mission {mission_id} not found"
481 |         )
482 |     
483 |     blackboard = controller.blackboard
484 |     
485 |     target_data = await blackboard.get_target(target_id)
486 |     
487 |     if not target_data:
488 |         raise HTTPException(
489 |             status_code=status.HTTP_404_NOT_FOUND,
490 |             detail=f"Target {target_id} not found"
491 |         )
492 |     
493 |     ports = await blackboard.get_target_ports(target_id)
494 |     
495 |     return TargetResponse(
496 |         target_id=target_id,
497 |         ip=target_data.get("ip", ""),
498 |         hostname=target_data.get("hostname"),
499 |         os=target_data.get("os"),
500 |         status=target_data.get("status", "unknown"),
501 |         priority=target_data.get("priority", "medium"),
502 |         risk_score=target_data.get("risk_score"),
503 |         ports=ports
504 |     )
505 | 
506 | 
507 | # ═══════════════════════════════════════════════════════════════
508 | # Vulnerability Endpoints
509 | # ═══════════════════════════════════════════════════════════════
510 | 
511 | @router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
512 | async def list_vulnerabilities(
513 |     mission_id: str,
514 |     controller: MissionController = Depends(get_controller)
515 | ) -> List[VulnerabilityResponse]:
516 |     """List all vulnerabilities for a mission."""
517 |     blackboard = controller.blackboard
518 |     
519 |     vuln_keys = await blackboard.get_mission_vulns(mission_id)
520 |     vulns = []
521 |     
522 |     for vuln_key in vuln_keys:
523 |         vuln_id = vuln_key.replace("vuln:", "")
524 |         vuln_data = await blackboard.get_vulnerability(vuln_id)
525 |         
526 |         if vuln_data:
527 |             vulns.append(VulnerabilityResponse(
528 |                 vuln_id=vuln_id,
529 |                 target_id=str(vuln_data.get("target_id", "")),
530 |                 type=vuln_data.get("type", ""),
531 |                 name=vuln_data.get("name"),
532 |                 severity=vuln_data.get("severity", "medium"),
533 |                 cvss=vuln_data.get("cvss"),
534 |                 status=vuln_data.get("status", "discovered"),
535 |                 exploit_available=vuln_data.get("exploit_available", False)
536 |             ))
537 |     
538 |     return vulns
539 | 
540 | 
541 | # ═══════════════════════════════════════════════════════════════
542 | # Statistics Endpoint
543 | # ═══════════════════════════════════════════════════════════════
544 | 
545 | # ═══════════════════════════════════════════════════════════════
546 | # Credential Endpoints
547 | # ═══════════════════════════════════════════════════════════════
548 | 
549 | @router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
550 | async def list_credentials(
551 |     mission_id: str,
552 |     controller: MissionController = Depends(get_controller)
553 | ) -> List[CredentialResponse]:
554 |     """List all credentials for a mission."""
555 |     blackboard = controller.blackboard
556 |     
557 |     cred_keys = await blackboard.get_mission_creds(mission_id)
558 |     creds = []
559 |     
560 |     for cred_key in cred_keys:
561 |         cred_id = cred_key.replace("cred:", "")
562 |         cred_data = await blackboard.get_credential(cred_id)
563 |         
564 |         if cred_data:
565 |             creds.append(CredentialResponse(
566 |                 cred_id=cred_id,
567 |                 target_id=str(cred_data.get("target_id", "")),
568 |                 type=cred_data.get("type", ""),
569 |                 username=cred_data.get("username", ""),
570 |                 domain=cred_data.get("domain"),
571 |                 privilege_level=cred_data.get("privilege_level", "user"),
572 |                 source=cred_data.get("source"),
573 |                 verified=cred_data.get("verified", "false").lower() == "true",
574 |                 created_at=cred_data.get("created_at")
575 |             ))
576 |     
577 |     return creds
578 | 
579 | 
580 | # ═══════════════════════════════════════════════════════════════
581 | # Session Endpoints
582 | # ═══════════════════════════════════════════════════════════════
583 | 
584 | @router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
585 | async def list_sessions(
586 |     mission_id: str,
587 |     controller: MissionController = Depends(get_controller)
588 | ) -> List[SessionResponse]:
589 |     """List all active sessions for a mission."""
590 |     blackboard = controller.blackboard
591 |     
592 |     session_keys = await blackboard.get_mission_sessions(mission_id)
593 |     sessions = []
594 |     
595 |     for session_key in session_keys:
596 |         session_id = session_key.replace("session:", "")
597 |         session_data = await blackboard.get_session(session_id)
598 |         
599 |         if session_data:
600 |             sessions.append(SessionResponse(
601 |                 session_id=session_id,
602 |                 target_id=str(session_data.get("target_id", "")),
603 |                 type=session_data.get("type", "shell"),
604 |                 user=session_data.get("user", "unknown"),
605 |                 privilege=session_data.get("privilege", "user"),
606 |                 status=session_data.get("status", "unknown"),
607 |                 established_at=session_data.get("established_at"),
608 |                 last_activity=session_data.get("last_activity")
609 |             ))
610 |     
611 |     return sessions
612 | 
613 | 
614 | # ═══════════════════════════════════════════════════════════════
615 | # Statistics Endpoint
616 | # ═══════════════════════════════════════════════════════════════
617 | 
618 | @router.get("/missions/{mission_id}/stats")
619 | async def get_mission_stats(
620 |     mission_id: str,
621 |     controller: MissionController = Depends(get_controller)
622 | ) -> Dict[str, Any]:
623 |     """Get mission statistics."""
624 |     blackboard = controller.blackboard
625 |     
626 |     stats = await blackboard.get_mission_stats(mission_id)
627 |     goals = await blackboard.get_mission_goals(mission_id)
628 |     
629 |     # Count achieved goals
630 |     achieved = sum(1 for g in goals.values() if g == "achieved")
631 |     total = len(goals)
632 |     
633 |     return {
634 |         "targets_discovered": stats.targets_discovered,
635 |         "vulns_found": stats.vulns_found,
636 |         "creds_harvested": stats.creds_harvested,
637 |         "sessions_established": stats.sessions_established,
638 |         "goals_achieved": achieved,
639 |         "goals_total": total,
640 |         "completion_percentage": (achieved / total * 100) if total > 0 else 0
641 |     }
642 | 
643 | 
644 | # ═══════════════════════════════════════════════════════════════
645 | # HITL (Human-in-the-Loop) Endpoints
646 | # ═══════════════════════════════════════════════════════════════
647 | 
648 | @router.get("/missions/{mission_id}/approvals", response_model=List[PendingApprovalResponse])
649 | async def list_pending_approvals(
650 |     mission_id: str,
651 |     controller: MissionController = Depends(get_controller)
652 | ) -> List[PendingApprovalResponse]:
653 |     """
654 |     List all pending approval requests for a mission.
655 |     
656 |     These are high-risk actions waiting for user consent.
657 |     """
658 |     # Check if mission exists first
659 |     mission_data = await controller.get_mission_status(mission_id)
660 |     if not mission_data:
661 |         raise HTTPException(
662 |             status_code=status.HTTP_404_NOT_FOUND,
663 |             detail=f"Mission {mission_id} not found"
664 |         )
665 |     
666 |     pending = await controller.get_pending_approvals(mission_id)
667 |     return [PendingApprovalResponse(**p) for p in pending]
668 | 
669 | 
670 | @router.post("/missions/{mission_id}/approve/{action_id}", response_model=ApprovalResponse)
671 | async def approve_action(
672 |     mission_id: str,
673 |     action_id: str,
674 |     request_data: ApprovalRequest = None,
675 |     controller: MissionController = Depends(get_controller)
676 | ) -> ApprovalResponse:
677 |     """
678 |     Approve a pending action.
679 |     
680 |     This allows the action to proceed and resumes mission execution.
681 |     
682 |     - **action_id**: ID of the action to approve
683 |     - **user_comment**: Optional comment explaining the approval
684 |     """
685 |     # Check if mission exists first
686 |     mission_data = await controller.get_mission_status(mission_id)
687 |     if not mission_data:
688 |         raise HTTPException(
689 |             status_code=status.HTTP_404_NOT_FOUND,
690 |             detail=f"Mission {mission_id} not found"
691 |         )
692 |     
693 |     user_comment = request_data.user_comment if request_data else None
694 |     
695 |     result = await controller.approve_action(
696 |         mission_id=mission_id,
697 |         action_id=action_id,
698 |         user_comment=user_comment
699 |     )
700 |     
701 |     if not result:
702 |         raise HTTPException(
703 |             status_code=status.HTTP_404_NOT_FOUND,
704 |             detail=f"Action {action_id} not found or does not belong to mission {mission_id}"
705 |         )
706 |     
707 |     # Get current mission status
708 |     current_status = mission_data.get("status", "unknown")
709 |     
710 |     return ApprovalResponse(
711 |         success=True,
712 |         message="Action approved successfully. Mission execution resumed.",
713 |         action_id=action_id,
714 |         mission_status=current_status
715 |     )
716 | 
717 | 
718 | @router.post("/missions/{mission_id}/reject/{action_id}", response_model=ApprovalResponse)
719 | async def reject_action(
720 |     mission_id: str,
721 |     action_id: str,
722 |     request_data: RejectionRequest = None,
723 |     controller: MissionController = Depends(get_controller)
724 | ) -> ApprovalResponse:
725 |     """
726 |     Reject a pending action.
727 |     
728 |     The system will attempt to find an alternative approach.
729 |     
730 |     - **action_id**: ID of the action to reject
731 |     - **rejection_reason**: Reason for rejection
732 |     - **user_comment**: Optional additional comment
733 |     """
734 |     rejection_reason = request_data.rejection_reason if request_data else None
735 |     user_comment = request_data.user_comment if request_data else None
736 |     
737 |     result = await controller.reject_action(
738 |         mission_id=mission_id,
739 |         action_id=action_id,
740 |         rejection_reason=rejection_reason,
741 |         user_comment=user_comment
742 |     )
743 |     
744 |     if not result:
745 |         raise HTTPException(
746 |             status_code=status.HTTP_400_BAD_REQUEST,
747 |             detail=f"Failed to reject action {action_id}. It may not exist or belong to this mission."
748 |         )
749 |     
750 |     # Get current mission status
751 |     mission_data = await controller.get_mission_status(mission_id)
752 |     current_status = mission_data.get("status", "unknown") if mission_data else "unknown"
753 |     
754 |     return ApprovalResponse(
755 |         success=True,
756 |         message="Action rejected. System will seek alternatives.",
757 |         action_id=action_id,
758 |         mission_status=current_status
759 |     )
760 | 
761 | 
762 | @router.post("/missions/{mission_id}/chat", response_model=ChatMessageResponse)
763 | async def send_chat_message(
764 |     mission_id: str,
765 |     request_data: ChatRequest,
766 |     controller: MissionController = Depends(get_controller)
767 | ) -> ChatMessageResponse:
768 |     """
769 |     Send a chat message to interact with the mission.
770 |     
771 |     This allows users to:
772 |     - Ask about mission status
773 |     - Give instructions (pause, resume)
774 |     - Query pending approvals
775 |     
776 |     - **content**: Message content
777 |     - **related_task_id**: Optional related task
778 |     - **related_action_id**: Optional related approval action
779 |     """
780 |     try:
781 |         message = await controller.send_chat_message(
782 |             mission_id=mission_id,
783 |             content=request_data.content,
784 |             related_task_id=request_data.related_task_id,
785 |             related_action_id=request_data.related_action_id
786 |         )
787 |         
788 |         return ChatMessageResponse(
789 |             id=str(message.id),
790 |             role=message.role,
791 |             content=message.content,
792 |             timestamp=message.timestamp.isoformat(),
793 |             related_task_id=str(message.related_task_id) if message.related_task_id else None,
794 |             related_action_id=str(message.related_action_id) if message.related_action_id else None
795 |         )
796 |     except Exception as e:
797 |         # Log the error for debugging
798 |         import logging
799 |         logging.error(f"Chat message error for mission {mission_id}: {e}")
800 |         raise HTTPException(
801 |             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
802 |             detail=f"Failed to process chat message: {str(e)}"
803 |         )
804 | 
805 | 
806 | @router.get("/missions/{mission_id}/chat", response_model=List[ChatMessageResponse])
807 | async def get_chat_history(
808 |     mission_id: str,
809 |     limit: int = 50,
810 |     controller: MissionController = Depends(get_controller)
811 | ) -> List[ChatMessageResponse]:
812 |     """
813 |     Get chat history for a mission.
814 |     
815 |     - **limit**: Maximum number of messages to return (default 50)
816 |     """
817 |     history = await controller.get_chat_history(mission_id, limit)
818 |     return [ChatMessageResponse(**msg) for msg in history]

<environment_details>
# VSCode Visible Files
src/api/routes.py

# VSCode Open Tabs
../../Untitled-1,webapp/frontend/implementation_plan.md,webapp/frontend/client/src/lib/api.ts,webapp/frontend/client/src/types/index.ts,webapp/frontend/client/src/lib/websocket.ts,webapp/frontend/client/src/hooks/useWebSocket.ts,webapp/frontend/client/src/pages/Login.tsx,webapp/frontend/client/src/stores/authStore.ts,webapp/frontend/client/src/components/ProtectedRoute.tsx,webapp/frontend/client/src/App.tsx

# Actively Running Terminals
## Terminal 4 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 5 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``
## Terminal 6 (Active)
### Working Directory: `/root/RAGLOX_V3/webapp`
### Original command: ``

# Current Time
Current time in ISO 8601 UTC format: 2026-01-03T16:18:17.131Z
User time zone: UTC, UTC+0:00

# Current Cost
$0.41

# Current Mode
<slug>code</slug>
<name>Code</name>
<model>glm-4.6</model>
<tool_format>native</tool_format>
====

REMINDERS

Below is your current list of reminders for this task. Keep them updated as you progress.

| # | Content | Status |
|---|---------|--------|
| 1 | Fix Mission Stop endpoint (3 tests) - Ensure proper error handling without 500 errors | Pending |
| 2 | Fix Reject Action endpoint (4 tests) - Return 404 instead of 400 when action doesn't exist | Pending |
| 3 | Fix Chat Endpoints (3 tests) - Add mission existence checks for send_chat_message and get_chat_history | Pending |
| 4 | Fix Mission Data Endpoints (5 tests) - Add mission existence checks for list_targets, list_vulnerabilities, list_credentials, list_sessions, get_mission_stats | Pending |
| 5 | Fix Mission Invalid ID (1 test) - Return 422 instead of 404 for invalid mission_id format | Pending |


IMPORTANT: When task status changes, remember to call the `update_todo_list` tool to update your progress.

</environment_details>

---

**Assistant:**


Now I can see the current state of the file. Let me continue with the remaining fixes. I need to fix:
1. The vulnerabilities endpoint (add UUID validation and mission existence check)
2. The credentials endpoint (add UUID validation and mission existence check)
3. The sessions endpoint (add UUID validation and mission existence check)
4. The stats endpoint (add UUID validation and mission existence check)
5. The reject_action endpoint (add UUID validation and change 400 to 404)
6. The chat endpoints (add UUID validation and mission existence check)

Let me apply these fixes:

[Tool Use: apply_diff]
Path: src/api/routes.py
Diff: <<<<<<< SEARCH
:start_line:511
-------
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
=======
@router.get("/missions/{mission_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[VulnerabilityResponse]:
    """List all vulnerabilities for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    vuln_keys = await blackboard.get_mission_vulns(mission_id)
    vulns = []
    
    for vuln_key in vuln_keys:
        vuln_id = vuln_key.replace("vuln:", "")
        vuln_data = await blackboard.get_vulnerability(vuln_id)
        
        if vuln_data:
            vulns.append(VulnerabilityResponse(
                vuln_id=vuln_id,
                target_id=str(vuln_data.get("target_id", "")),
                type=vuln_data.get("type", ""),
                name=vuln_data.get("name"),
                severity=vuln_data.get("severity", "medium"),
                cvss=vuln_data.get("cvss"),
                status=vuln_data.get("status", "discovered"),
                exploit_available=vuln_data.get("exploit_available", False)
            ))
    
    return vulns
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:549
-------
@router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
async def list_credentials(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[CredentialResponse]:
    """List all credentials for a mission."""
    blackboard = controller.blackboard
    
    cred_keys = await blackboard.get_mission_creds(mission_id)
    creds = []
    
    for cred_key in cred_keys:
        cred_id = cred_key.replace("cred:", "")
        cred_data = await blackboard.get_credential(cred_id)
        
        if cred_data:
            creds.append(CredentialResponse(
                cred_id=cred_id,
                target_id=str(cred_data.get("target_id", "")),
                type=cred_data.get("type", ""),
                username=cred_data.get("username", ""),
                domain=cred_data.get("domain"),
                privilege_level=cred_data.get("privilege_level", "user"),
                source=cred_data.get("source"),
                verified=cred_data.get("verified", "false").lower() == "true",
                created_at=cred_data.get("created_at")
            ))
    
    return creds
=======
@router.get("/missions/{mission_id}/credentials", response_model=List[CredentialResponse])
async def list_credentials(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[CredentialResponse]:
    """List all credentials for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    cred_keys = await blackboard.get_mission_creds(mission_id)
    creds = []
    
    for cred_key in cred_keys:
        cred_id = cred_key.replace("cred:", "")
        cred_data = await blackboard.get_credential(cred_id)
        
        if cred_data:
            creds.append(CredentialResponse(
                cred_id=cred_id,
                target_id=str(cred_data.get("target_id", "")),
                type=cred_data.get("type", ""),
                username=cred_data.get("username", ""),
                domain=cred_data.get("domain"),
                privilege_level=cred_data.get("privilege_level", "user"),
                source=cred_data.get("source"),
                verified=cred_data.get("verified", "false").lower() == "true",
                created_at=cred_data.get("created_at")
            ))
    
    return creds
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:584
-------
@router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
async def list_sessions(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[SessionResponse]:
    """List all active sessions for a mission."""
    blackboard = controller.blackboard
    
    session_keys = await blackboard.get_mission_sessions(mission_id)
    sessions = []
    
    for session_key in session_keys:
        session_id = session_key.replace("session:", "")
        session_data = await blackboard.get_session(session_id)
        
        if session_data:
            sessions.append(SessionResponse(
                session_id=session_id,
                target_id=str(session_data.get("target_id", "")),
                type=session_data.get("type", "shell"),
                user=session_data.get("user", "unknown"),
                privilege=session_data.get("privilege", "user"),
                status=session_data.get("status", "unknown"),
                established_at=session_data.get("established_at"),
                last_activity=session_data.get("last_activity")
            ))
    
    return sessions
=======
@router.get("/missions/{mission_id}/sessions", response_model=List[SessionResponse])
async def list_sessions(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> List[SessionResponse]:
    """List all active sessions for a mission."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    session_keys = await blackboard.get_mission_sessions(mission_id)
    sessions = []
    
    for session_key in session_keys:
        session_id = session_key.replace("session:", "")
        session_data = await blackboard.get_session(session_id)
        
        if session_data:
            sessions.append(SessionResponse(
                session_id=session_id,
                target_id=str(session_data.get("target_id", "")),
                type=session_data.get("type", "shell"),
                user=session_data.get("user", "unknown"),
                privilege=session_data.get("privilege", "user"),
                status=session_data.get("status", "unknown"),
                established_at=session_data.get("established_at"),
                last_activity=session_data.get("last_activity")
            ))
    
    return sessions
>>>>>>> REPLACE

<<<<<<< SEARCH
:start_line:618
-------
@router.get("/missions/{mission_id}/stats")
async def get_mission_stats(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> Dict[str, Any]:
    """Get mission statistics."""
    blackboard = controller.blackboard
    
    stats = await blackboard.get_mission_stats(mission_id)
    goals = await blackboard.get_mission_goals(mission_id)
    
    # Count achieved goals
    achieved = sum(1 for g in goals.values() if g == "achieved")
    total = len(goals)
    
    return {
        "targets_discovered": stats.targets_discovered,
        "vulns_found": stats.vulns_found,
        "creds_harvested": stats.creds_harvested,
        "sessions_established": stats.sessions_established,
        "goals_achieved": achieved,
        "goals_total": total,
        "completion_percentage": (achieved / total * 100) if total > 0 else 0
    }
=======
@router.get("/missions/{mission_id}/stats")
async def get_mission_stats(
    mission_id: str,
    controller: MissionController = Depends(get_controller)
) -> Dict[str, Any]:
    """Get mission statistics."""
    # Validate UUID format first
    try:
        validate_uuid(mission_id, "mission_id")
    except InvalidUUIDError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    
    # Check if mission exists first
    mission_data = await controller.get_mission_status(mission_id)
    if not mission_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mission {mission_id} not found"
        )
    
    blackboard = controller.blackboard
    
    stats = await blackboard.get_mission_stats(mission_id)
    goals = await blackboard.get_mission_goals(mission_id)
    
    # Count achieved goals
    achieved = sum(1 for g in goals.values() if g == "achieved")
    total = len(goals)
    
    return {
        "targets_discovered": stats.targets_discovered,
        "vulns_found": stats.vulns_found,
        "creds_harvested": stats.creds_harvested,
        "sessions_established": stats.sessions_established,
        "goals_achieved": achieved,
        "goals_total": total,
        "completion_percentage": (achieved / total * 100) if total > 0 else 0
    }
>>>>>>> REPLACE
>>>>>>> REPLACE


