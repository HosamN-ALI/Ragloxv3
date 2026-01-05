RAGLOX
 3.0.0 
OAS 3.1
/openapi.json
Red Team Automation Platform with Blackboard Architecture

Missions


GET
/api/v1/missions
List Missions


POST
/api/v1/missions
Create Mission


GET
/api/v1/missions/{mission_id}
Get Mission


POST
/api/v1/missions/{mission_id}/start
Start Mission


POST
/api/v1/missions/{mission_id}/pause
Pause Mission


POST
/api/v1/missions/{mission_id}/resume
Resume Mission


POST
/api/v1/missions/{mission_id}/stop
Stop Mission


GET
/api/v1/missions/{mission_id}/targets
List Targets


GET
/api/v1/missions/{mission_id}/targets/{target_id}
Get Target


GET
/api/v1/missions/{mission_id}/vulnerabilities
List Vulnerabilities


GET
/api/v1/missions/{mission_id}/credentials
List Credentials


GET
/api/v1/missions/{mission_id}/sessions
List Sessions


GET
/api/v1/missions/{mission_id}/stats
Get Mission Stats


GET
/api/v1/missions/{mission_id}/approvals
List Pending Approvals


POST
/api/v1/missions/{mission_id}/approve/{action_id}
Approve Action


POST
/api/v1/missions/{mission_id}/reject/{action_id}
Reject Action


POST
/api/v1/missions/{mission_id}/chat
Send Chat Message


GET
/api/v1/missions/{mission_id}/chat
Get Chat History

Knowledge


GET
/api/v1/knowledge/stats
Get Knowledge Stats


GET
/api/v1/knowledge/techniques
List Techniques


GET
/api/v1/knowledge/techniques/{technique_id}
Get Technique


GET
/api/v1/knowledge/techniques/{technique_id}/modules
Get Technique Modules


GET
/api/v1/knowledge/modules
List Modules


GET
/api/v1/knowledge/modules/{module_id}
Get Module


GET
/api/v1/knowledge/tactics
List Tactics


GET
/api/v1/knowledge/tactics/{tactic_id}/techniques
Get Tactic Techniques


GET
/api/v1/knowledge/platforms
List Platforms


GET
/api/v1/knowledge/platforms/{platform}/modules
Get Platform Modules


GET
/api/v1/knowledge/search
Search Modules


POST
/api/v1/knowledge/search
Search Modules Post


POST
/api/v1/knowledge/best-module
Get Best Module For Task


GET
/api/v1/knowledge/exploit-modules
Get Exploit Modules


GET
/api/v1/knowledge/recon-modules
Get Recon Modules


GET
/api/v1/knowledge/credential-modules
Get Credential Modules


GET
/api/v1/knowledge/privesc-modules
Get Privesc Modules


GET
/api/v1/knowledge/nuclei/templates
List Nuclei Templates


GET
/api/v1/knowledge/nuclei/templates/{template_id}
Get Nuclei Template


GET
/api/v1/knowledge/nuclei/search
Search Nuclei Templates


GET
/api/v1/knowledge/nuclei/cve/{cve_id}
Get Nuclei Template By Cve


GET
/api/v1/knowledge/nuclei/severity/{severity}
Get Nuclei Templates By Severity


GET
/api/v1/knowledge/nuclei/critical
Get Critical Nuclei Templates


GET
/api/v1/knowledge/nuclei/rce
Get Rce Nuclei Templates


GET
/api/v1/knowledge/nuclei/sqli
Get Sqli Nuclei Templates


GET
/api/v1/knowledge/nuclei/xss
Get Xss Nuclei Templates

Root


GET
/
Root

Health


GET
/health
Health Check


Schemas
ApprovalRequestExpand allobject
ApprovalResponseExpand allobject
ChatMessageResponseExpand allobject
ChatRequestExpand allobject
CredentialResponseExpand allobject
HTTPValidationErrorExpand allobject
KnowledgeStatsResponseExpand allobject
MissionCreateExpand allobject
MissionResponseExpand allobject
MissionStatusResponseExpand allobject
ModuleResponseExpand allobject
NucleiTemplateResponseExpand allobject
PaginatedResponseExpand allobject
PendingApprovalResponseExpand allobject
RejectionRequestExpand allobject
SearchRequestExpand allobject
SessionResponseExpand allobject
TacticResponseExpand allobject
TargetResponseExpand allobject
TaskModuleRequestExpand allobject
TechniqueResponseExpand allobject
ValidationErrorExpand allobject
VulnerabilityResponseExpand allobject