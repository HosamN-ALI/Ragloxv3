# RAGLOX v3.0 - Backend-Frontend Integration Guide
## دليل الربط الشامل بين الباك-إند والفرونت-إند

> **الغرض:** هذه الوثيقة مخصصة للمطور الجديد الذي سيعيد بناء الفرونت-إند بأسلوب Manus.
> تحتوي على كل ما يحتاجه لفهم خريطة الباك-إند الكاملة والتفاعل مع الواجهة الأمامية.

---

## جدول المحتويات

1. [نظرة عامة على المعمارية](#1-نظرة-عامة-على-المعمارية)
2. [خريطة API الكاملة](#2-خريطة-api-الكاملة)
3. [نماذج البيانات (Data Models)](#3-نماذج-البيانات-data-models)
4. [WebSocket والأحداث الحية](#4-websocket-والأحداث-الحية)
5. [HITL - Human-in-the-Loop](#5-hitl---human-in-the-loop)
6. [Blackboard Pattern](#6-blackboard-pattern)
7. [Knowledge Base](#7-knowledge-base)
8. [تدفق البيانات (Data Flow)](#8-تدفق-البيانات-data-flow)
9. [الروابط والمعلومات الهامة](#9-الروابط-والمعلومات-الهامة)
10. [أمثلة عملية](#10-أمثلة-عملية)

---

## 1. نظرة عامة على المعمارية

### 1.1 Blackboard Architecture

RAGLOX يستخدم **Blackboard Pattern** - معمارية مشتركة حيث:
- **Blackboard (Redis):** المخزن المركزي للحالة المشتركة
- **Specialists:** وكلاء مستقلون يقرأون ويكتبون من/إلى Blackboard
- **Controller:** المنسق المركزي للمهام

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React)                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │  AI Chat     │  │  Terminal    │  │  Event Stream        │ │
│  │  Panel       │  │  Panel       │  │  (Plan/Timeline)     │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
└───────────────────────────┬─────────────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │  WebSocket  │  REST API
                    │  /ws        │  /api/v1/*
                    └──────┬──────┘
                           │
┌──────────────────────────┴──────────────────────────────────────┐
│                      BACKEND (FastAPI)                          │
│  ┌────────────────────────────────────────────────────────────┐│
│  │                    MissionController                        ││
│  │  - Mission lifecycle (create, start, pause, resume, stop)  ││
│  │  - Specialist coordination                                  ││
│  │  - Goal tracking & statistics                               ││
│  │  - HITL approval management                                 ││
│  └────────────────────────────────────────────────────────────┘│
│                              │                                  │
│  ┌───────────────────────────┴───────────────────────────────┐ │
│  │                     Blackboard (Redis)                     │ │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐ │ │
│  │  │Missions │ │ Targets │ │  Vulns  │ │ Creds/Sessions  │ │ │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘ │ │
│  │              ┌──────────────────────────┐                 │ │
│  │              │  Pub/Sub Events          │                 │ │
│  │              └──────────────────────────┘                 │ │
│  └───────────────────────────────────────────────────────────┘ │
│                              │                                  │
│  ┌───────────┐  ┌────────────┴─────────────┐  ┌──────────────┐│
│  │  Recon    │  │      Attack              │  │   Intel      ││
│  │Specialist │  │    Specialist            │  │ Specialist   ││
│  │ (scans)   │  │ (exploits)               │  │   (OSINT)    ││
│  └───────────┘  └──────────────────────────┘  └──────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 مكونات النظام

| المكون | الملف | الوصف |
|--------|-------|-------|
| **API Routes** | `src/api/routes.py` | نقاط نهاية REST API |
| **WebSocket** | `src/api/websocket.py` | الاتصال الحي للأحداث |
| **Main App** | `src/api/main.py` | تطبيق FastAPI الرئيسي |
| **Controller** | `src/controller/mission.py` | منسق المهام والمهمات |
| **Blackboard** | `src/core/blackboard.py` | الحالة المشتركة (Redis) |
| **Models** | `src/core/models.py` | نماذج البيانات Pydantic |
| **Knowledge** | `src/core/knowledge.py` | قاعدة المعرفة (RX Modules) |
| **Specialists** | `src/specialists/*.py` | الوكلاء المتخصصون |

---

## 2. خريطة API الكاملة

### 2.1 Base URL
```
http://172.245.232.188:8000/api/v1
```

### 2.2 Mission Endpoints

#### إنشاء مهمة جديدة
```http
POST /api/v1/missions
Content-Type: application/json

{
  "name": "Test Mission",
  "description": "Description here",
  "scope": ["192.168.1.0/24", "10.0.0.1"],
  "goals": ["domain_admin", "get_database_creds"],
  "constraints": {"stealth": true, "time_limit": 3600}
}

Response: {
  "mission_id": "uuid",
  "name": "Test Mission",
  "status": "created",
  "message": "Mission created successfully"
}
```

#### الحصول على قائمة المهمات
```http
GET /api/v1/missions

Response: ["uuid1", "uuid2", "uuid3"]
```

#### الحصول على تفاصيل مهمة
```http
GET /api/v1/missions/{mission_id}

Response: {
  "mission_id": "uuid",
  "name": "Field Acceptance Test",
  "status": "running",
  "scope": ["172.28.0.100"],
  "goals": {
    "get_database_creds": "pending",
    "establish_session": "achieved"
  },
  "statistics": {
    "targets_discovered": 1,
    "vulns_found": 2,
    "creds_harvested": 2,
    "sessions_established": 1,
    "goals_achieved": 1
  },
  "target_count": 1,
  "vuln_count": 2,
  "created_at": "2026-01-02T10:00:00",
  "started_at": "2026-01-02T10:05:00",
  "completed_at": null
}
```

#### التحكم بالمهمة
```http
POST /api/v1/missions/{mission_id}/start
POST /api/v1/missions/{mission_id}/pause
POST /api/v1/missions/{mission_id}/resume
POST /api/v1/missions/{mission_id}/stop

Response: {
  "mission_id": "uuid",
  "name": "",
  "status": "running|paused|completed",
  "message": "Mission started/paused/stopped successfully"
}
```

### 2.3 Target Endpoints

#### الحصول على الأهداف
```http
GET /api/v1/missions/{mission_id}/targets

Response: [
  {
    "target_id": "uuid",
    "ip": "172.28.0.100",
    "hostname": "ubuntu-server",
    "os": "Linux Ubuntu 22.04",
    "status": "scanned",
    "priority": "high",
    "risk_score": 8.5,
    "ports": {
      "22": "ssh",
      "80": "http",
      "5432": "postgresql"
    }
  }
]
```

#### الحصول على هدف محدد
```http
GET /api/v1/missions/{mission_id}/targets/{target_id}

Response: { /* same as above */ }
```

### 2.4 Vulnerability Endpoints

```http
GET /api/v1/missions/{mission_id}/vulnerabilities

Response: [
  {
    "vuln_id": "uuid",
    "target_id": "uuid",
    "type": "CVE-2021-44228",
    "name": "Log4Shell",
    "severity": "critical",
    "cvss": 10.0,
    "status": "discovered",
    "exploit_available": true
  },
  {
    "vuln_id": "uuid2",
    "target_id": "uuid",
    "type": "SSH Weak Password",
    "name": "SSH Weak Password",
    "severity": "high",
    "cvss": 7.5,
    "status": "exploited",
    "exploit_available": true
  }
]
```

### 2.5 Credential Endpoints

```http
GET /api/v1/missions/{mission_id}/credentials

Response: [
  {
    "cred_id": "uuid",
    "target_id": "uuid",
    "type": "password",
    "username": "admin",
    "domain": null,
    "privilege_level": "admin",
    "source": "brute_force",
    "verified": true,
    "created_at": "2026-01-02T10:30:00"
  }
]
```

### 2.6 Session Endpoints

```http
GET /api/v1/missions/{mission_id}/sessions

Response: [
  {
    "session_id": "uuid",
    "target_id": "uuid",
    "type": "ssh",
    "user": "root",
    "privilege": "root",
    "status": "active",
    "established_at": "2026-01-02T10:35:00",
    "last_activity": "2026-01-02T11:00:00"
  }
]
```

### 2.7 Statistics Endpoint

```http
GET /api/v1/missions/{mission_id}/stats

Response: {
  "targets_discovered": 1,
  "vulns_found": 2,
  "creds_harvested": 2,
  "sessions_established": 1,
  "goals_achieved": 1,
  "goals_total": 2,
  "completion_percentage": 50.0
}
```

### 2.8 HITL Endpoints (Human-in-the-Loop)

#### الحصول على الموافقات المعلقة
```http
GET /api/v1/missions/{mission_id}/approvals

Response: [
  {
    "action_id": "uuid",
    "action_type": "exploit",
    "action_description": "Execute EternalBlue against 172.28.0.100",
    "target_ip": "172.28.0.100",
    "risk_level": "critical",
    "risk_reasons": [
      "Could crash the target system",
      "May trigger security alerts"
    ],
    "potential_impact": "Full system compromise",
    "command_preview": "msf> use exploit/windows/smb/ms17_010_eternalblue",
    "requested_at": "2026-01-02T11:00:00",
    "expires_at": "2026-01-02T11:30:00"
  }
]
```

#### الموافقة على إجراء
```http
POST /api/v1/missions/{mission_id}/approve/{action_id}
Content-Type: application/json

{
  "user_comment": "Proceed with caution"
}

Response: {
  "success": true,
  "message": "Action approved successfully. Mission execution resumed.",
  "action_id": "uuid",
  "mission_status": "running"
}
```

#### رفض إجراء
```http
POST /api/v1/missions/{mission_id}/reject/{action_id}
Content-Type: application/json

{
  "rejection_reason": "Too risky for production environment",
  "user_comment": "Try alternative approach"
}

Response: {
  "success": true,
  "message": "Action rejected. System will seek alternatives.",
  "action_id": "uuid",
  "mission_status": "running"
}
```

### 2.9 Chat Endpoints

#### إرسال رسالة
```http
POST /api/v1/missions/{mission_id}/chat
Content-Type: application/json

{
  "content": "What is the current mission status?",
  "related_task_id": null,
  "related_action_id": null
}

Response: {
  "id": "uuid",
  "role": "user",
  "content": "What is the current mission status?",
  "timestamp": "2026-01-02T11:00:00",
  "related_task_id": null,
  "related_action_id": null
}
```

#### الحصول على سجل المحادثة
```http
GET /api/v1/missions/{mission_id}/chat?limit=50

Response: [
  {
    "id": "uuid",
    "role": "user",
    "content": "status",
    "timestamp": "2026-01-02T11:00:00"
  },
  {
    "id": "uuid2",
    "role": "system",
    "content": "📊 Mission Status: running\nTargets: 1\nVulnerabilities: 2\nGoals: 1/2",
    "timestamp": "2026-01-02T11:00:01"
  }
]
```

### 2.10 Knowledge Base Endpoints

```http
GET /api/v1/knowledge/techniques?platform=linux&limit=100&offset=0
GET /api/v1/knowledge/techniques/{technique_id}
GET /api/v1/knowledge/modules?technique_id=T1003&platform=linux&limit=100
GET /api/v1/knowledge/modules/{module_id}
GET /api/v1/knowledge/search?query=credential&platform=linux&limit=20
GET /api/v1/knowledge/statistics
```

### 2.11 Health Check

```http
GET /health

Response: {
  "status": "healthy",
  "components": {
    "api": "healthy",
    "blackboard": "healthy",
    "knowledge": "loaded"
  }
}
```

---

## 3. نماذج البيانات (Data Models)

### 3.1 Enums - القيم المحددة

#### MissionStatus - حالات المهمة
```typescript
enum MissionStatus {
  CREATED = "created",
  STARTING = "starting",
  RUNNING = "running",
  PAUSED = "paused",
  WAITING_FOR_APPROVAL = "waiting_for_approval",  // HITL
  COMPLETING = "completing",
  COMPLETED = "completed",
  FAILED = "failed",
  CANCELLED = "cancelled",
  ARCHIVED = "archived"
}
```

#### TargetStatus - حالات الهدف
```typescript
enum TargetStatus {
  DISCOVERED = "discovered",
  SCANNING = "scanning",
  SCANNED = "scanned",
  EXPLOITING = "exploiting",
  EXPLOITED = "exploited",
  OWNED = "owned",
  FAILED = "failed"
}
```

#### Priority - الأولوية
```typescript
enum Priority {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low"
}
```

#### Severity - الخطورة (للثغرات)
```typescript
enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info"
}
```

#### CredentialType - أنواع بيانات الاعتماد
```typescript
enum CredentialType {
  PASSWORD = "password",
  HASH = "hash",
  KEY = "key",
  TOKEN = "token",
  CERTIFICATE = "certificate"
}
```

#### PrivilegeLevel - مستويات الصلاحية
```typescript
enum PrivilegeLevel {
  USER = "user",
  ADMIN = "admin",
  SYSTEM = "system",
  ROOT = "root",
  DOMAIN_ADMIN = "domain_admin",
  UNKNOWN = "unknown"
}
```

#### SessionType - أنواع الجلسات
```typescript
enum SessionType {
  SHELL = "shell",
  METERPRETER = "meterpreter",
  SSH = "ssh",
  RDP = "rdp",
  WMI = "wmi",
  WINRM = "winrm",
  SMB = "smb"
}
```

#### SessionStatus - حالات الجلسة
```typescript
enum SessionStatus {
  ACTIVE = "active",
  IDLE = "idle",
  DEAD = "dead"
}
```

#### TaskType - أنواع المهام
```typescript
enum TaskType {
  NETWORK_SCAN = "network_scan",
  PORT_SCAN = "port_scan",
  SERVICE_ENUM = "service_enum",
  VULN_SCAN = "vuln_scan",
  OSINT_LOOKUP = "osint_lookup",
  EXPLOIT = "exploit",
  PRIVESC = "privesc",
  LATERAL = "lateral",
  CRED_HARVEST = "cred_harvest",
  PERSISTENCE = "persistence",
  EVASION = "evasion",
  CLEANUP = "cleanup"
}
```

#### SpecialistType - أنواع المتخصصين
```typescript
enum SpecialistType {
  RECON = "recon",
  VULN = "vuln",
  ATTACK = "attack",
  CRED = "cred",
  INTEL = "intel",
  PERSISTENCE = "persistence",
  EVASION = "evasion",
  CLEANUP = "cleanup",
  ANALYSIS = "analysis"
}
```

#### ActionType - أنواع الإجراءات (HITL)
```typescript
enum ActionType {
  EXPLOIT = "exploit",
  WRITE_OPERATION = "write",
  LATERAL_MOVEMENT = "lateral",
  PRIVILEGE_ESCALATION = "privesc",
  DATA_EXFILTRATION = "exfil",
  PERSISTENCE = "persistence",
  DESTRUCTIVE = "destructive"
}
```

#### RiskLevel - مستويات المخاطر (HITL)
```typescript
enum RiskLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical"
}
```

#### ApprovalStatus - حالات الموافقة
```typescript
enum ApprovalStatus {
  PENDING = "pending",
  APPROVED = "approved",
  REJECTED = "rejected",
  EXPIRED = "expired"
}
```

### 3.2 Core Entities - الكيانات الأساسية

#### Mission - المهمة
```typescript
interface Mission {
  id: string;  // UUID
  name: string;
  description?: string;
  status: MissionStatus;
  scope: string[];  // CIDRs, IPs, domains
  goals: Record<string, GoalStatus>;  // goal_name -> status
  constraints: Record<string, any>;
  
  // Timestamps
  created_at: string;  // ISO format
  started_at?: string;
  completed_at?: string;
  
  // Statistics
  targets_discovered: number;
  vulns_found: number;
  creds_harvested: number;
  sessions_established: number;
  goals_achieved: number;
}
```

#### Target - الهدف
```typescript
interface Target {
  id: string;
  mission_id: string;
  ip: string;
  hostname?: string;
  os?: string;
  os_version?: string;
  status: TargetStatus;
  priority: Priority;
  risk_score?: number;  // 0.0 - 10.0
  
  // Discovery
  discovered_by?: string;
  discovered_at: string;
  
  // Ports and Services
  ports: Record<number, string>;  // port -> service
  services: Service[];
}
```

#### Vulnerability - الثغرة
```typescript
interface Vulnerability {
  id: string;
  mission_id: string;
  target_id: string;
  
  // Identification
  type: string;  // CVE-XXXX-XXXXX or custom
  name?: string;
  description?: string;
  
  // Severity
  severity: Severity;
  cvss?: number;  // 0.0 - 10.0
  
  // Discovery
  discovered_by?: string;
  discovered_at: string;
  
  // Status
  status: string;  // discovered, verified, exploited, failed
  
  // Exploitation
  exploit_available: boolean;
  rx_modules: string[];  // RX module IDs
}
```

#### Credential - بيانات الاعتماد
```typescript
interface Credential {
  id: string;
  mission_id: string;
  target_id: string;
  
  // Credential Info
  type: CredentialType;
  username?: string;
  domain?: string;
  
  // Discovery
  source?: string;  // mimikatz, brute_force, intel:arthouse
  discovered_by?: string;
  discovered_at: string;
  
  // Verification
  verified: boolean;
  privilege_level: PrivilegeLevel;
  
  // Intel Integration
  reliability_score: number;  // 0.0 - 1.0
  source_metadata: Record<string, any>;
}
```

#### Session - الجلسة
```typescript
interface Session {
  id: string;
  mission_id: string;
  target_id: string;
  
  // Session Info
  type: SessionType;
  user?: string;
  privilege: PrivilegeLevel;
  
  // Lifecycle
  established_at: string;
  last_activity: string;
  closed_at?: string;
  status: SessionStatus;
  
  // How obtained
  via_vuln_id?: string;
  via_cred_id?: string;
}
```

#### Task - المهمة الداخلية
```typescript
interface Task {
  id: string;
  mission_id: string;
  
  // Task Info
  type: TaskType;
  specialist: SpecialistType;
  priority: number;  // 1-10
  
  // References
  target_id?: string;
  vuln_id?: string;
  cred_id?: string;
  session_id?: string;
  rx_module?: string;
  
  // Execution
  status: TaskStatus;
  assigned_to?: string;  // Worker ID
  started_at?: string;
  completed_at?: string;
  
  // Result
  result?: string;  // success, failure, partial
  result_data: Record<string, any>;
  error_message?: string;
  
  // Reflexion Logic
  error_context?: ErrorContext;
  execution_logs: ExecutionLog[];
  retry_count: number;
  max_retries: number;
}
```

### 3.3 HITL Models

#### ApprovalAction - إجراء ينتظر الموافقة
```typescript
interface ApprovalAction {
  id: string;
  mission_id: string;
  task_id?: string;
  
  // Action Details
  action_type: ActionType;
  action_description: string;
  target_ip?: string;
  target_hostname?: string;
  
  // Risk Assessment
  risk_level: RiskLevel;
  risk_reasons: string[];
  potential_impact?: string;
  
  // Execution Preview
  module_to_execute?: string;
  command_preview?: string;
  parameters: Record<string, any>;
  
  // Status
  status: ApprovalStatus;
  requested_at: string;
  expires_at?: string;
  
  // Response
  responded_at?: string;
  responded_by?: string;
  rejection_reason?: string;
  user_comment?: string;
}
```

#### ChatMessage - رسالة المحادثة
```typescript
interface ChatMessage {
  id: string;
  mission_id: string;
  
  // Content
  role: "user" | "system" | "assistant";
  content: string;
  
  // Context
  related_task_id?: string;
  related_action_id?: string;
  
  // Timestamp
  timestamp: string;
  metadata: Record<string, any>;
}
```

---

## 4. WebSocket والأحداث الحية

### 4.1 نقاط الاتصال

```typescript
// الاتصال العالمي - يستقبل جميع الأحداث
const ws = new WebSocket("ws://172.245.232.188:8000/ws");

// الاتصال الخاص بمهمة
const missionWs = new WebSocket(`ws://172.245.232.188:8000/ws/missions/${missionId}`);
```

### 4.2 أنواع الأحداث

#### WebSocketEventType
```typescript
type WebSocketEventType = 
  | "connected"           // اتصال ناجح
  | "pong"               // رد على ping
  | "subscribed"         // اشتراك ناجح
  | "error"              // خطأ
  | "new_target"         // هدف جديد مكتشف
  | "new_vuln"           // ثغرة جديدة
  | "new_cred"           // بيانات اعتماد جديدة
  | "new_session"        // جلسة جديدة
  | "goal_achieved"      // هدف تحقق
  | "status_change"      // تغيير حالة المهمة
  | "statistics"         // تحديث الإحصائيات
  | "approval_request"   // طلب موافقة HITL
  | "approval_response"  // رد على الموافقة
  | "chat_message";      // رسالة محادثة
```

### 4.3 شكل الرسائل

#### رسالة الاتصال
```json
{
  "type": "connected",
  "message": "Connected to RAGLOX v3.0",
  "timestamp": "2026-01-02T11:00:00"
}
```

#### رسالة اتصال بمهمة
```json
{
  "type": "connected",
  "mission_id": "6b14028c-7f30-4ce6-aad2-20f17eee39d0",
  "message": "Connected to mission 6b14028c-7f30-4ce6-aad2-20f17eee39d0",
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث هدف جديد
```json
{
  "type": "new_target",
  "mission_id": "uuid",
  "data": {
    "target_id": "uuid",
    "ip": "172.28.0.100",
    "hostname": "ubuntu-server"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث ثغرة جديدة
```json
{
  "type": "new_vuln",
  "mission_id": "uuid",
  "data": {
    "vuln_id": "uuid",
    "target_id": "uuid",
    "severity": "critical",
    "type": "CVE-2021-44228"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث بيانات اعتماد جديدة
```json
{
  "type": "new_cred",
  "mission_id": "uuid",
  "data": {
    "cred_id": "uuid",
    "target_id": "uuid",
    "username": "admin",
    "privilege_level": "admin"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث جلسة جديدة
```json
{
  "type": "new_session",
  "mission_id": "uuid",
  "data": {
    "session_id": "uuid",
    "target_id": "uuid",
    "type": "ssh",
    "privilege": "root"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث تحقيق هدف
```json
{
  "type": "goal_achieved",
  "mission_id": "uuid",
  "data": {
    "goal": "establish_session"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث تغيير الحالة
```json
{
  "type": "status_change",
  "mission_id": "uuid",
  "data": {
    "old_status": "created",
    "new_status": "running"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث طلب موافقة (HITL)
```json
{
  "type": "approval_request",
  "mission_id": "uuid",
  "data": {
    "action_id": "uuid",
    "action_type": "exploit",
    "action_description": "Execute EternalBlue against 172.28.0.100",
    "target_ip": "172.28.0.100",
    "target_hostname": "ubuntu-server",
    "risk_level": "critical",
    "risk_reasons": ["Could crash the target"],
    "potential_impact": "Full system compromise",
    "command_preview": "msf> use exploit/...",
    "expires_at": "2026-01-02T11:30:00"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث رد الموافقة
```json
{
  "type": "approval_response",
  "mission_id": "uuid",
  "data": {
    "action_id": "uuid",
    "approved": true,
    "rejection_reason": null,
    "user_comment": "Proceed with caution"
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### حدث رسالة محادثة
```json
{
  "type": "chat_message",
  "mission_id": "uuid",
  "data": {
    "message_id": "uuid",
    "role": "system",
    "content": "📊 Mission Status: running",
    "related_task_id": null,
    "related_action_id": null
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

### 4.4 إرسال رسائل للخادم

#### Ping/Pong (Keep-Alive)
```javascript
// إرسال
ws.send(JSON.stringify({ type: "ping" }));

// استقبال
{
  "type": "pong",
  "timestamp": "2026-01-02T11:00:00"
}
```

#### الاشتراك في أنواع أحداث محددة
```javascript
ws.send(JSON.stringify({
  type: "subscribe",
  events: ["new_target", "new_vuln", "approval_request"]
}));

// استقبال
{
  "type": "subscribed",
  "events": ["new_target", "new_vuln", "approval_request"],
  "timestamp": "2026-01-02T11:00:00"
}
```

---

## 5. HITL - Human-in-the-Loop

### 5.1 متى يتم طلب الموافقة

الباك-إند يطلب موافقة المستخدم عند:

1. **Exploit** - محاولة استغلال ثغرة
2. **Write Operation** - كتابة ملفات على النظام
3. **Lateral Movement** - الانتقال لأهداف أخرى
4. **Privilege Escalation** - رفع الصلاحيات
5. **Data Exfiltration** - استخراج البيانات
6. **Persistence** - تثبيت نقطة دخول دائمة
7. **Destructive Actions** - إجراءات مدمرة محتملة

### 5.2 تدفق HITL

```
┌─────────────────┐
│ System detects  │
│ high-risk action│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Mission status  │
│ -> WAITING_FOR_ │
│    APPROVAL     │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ WebSocket: approval_request event   │
│ - action_id, action_type            │
│ - risk_level, risk_reasons          │
│ - command_preview                   │
│ - expires_at                        │
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────┐
│ Frontend shows  │
│ approval dialog │
└────────┬────────┘
         │
    ┌────┴────┐
    │ User    │
    │ decides │
    └────┬────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐  ┌───────┐
│APPROVE│  │REJECT │
└───┬───┘  └───┬───┘
    │          │
    ▼          ▼
┌───────────────────────────────┐
│ POST /approve/{action_id}    │
│ or                           │
│ POST /reject/{action_id}     │
└────────┬──────────────────────┘
         │
         ▼
┌─────────────────┐
│ Mission resumes │
│ -> RUNNING      │
└─────────────────┘
```

### 5.3 واجهة الموافقة المقترحة (Manus-style)

```
┌────────────────────────────────────────────────────────────┐
│ ⚠️  Approval Required                           [CRITICAL] │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ Action: Execute EternalBlue Exploit                        │
│ Target: 172.28.0.100 (ubuntu-server)                       │
│                                                            │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Command Preview:                                       │ │
│ │ $ msfconsole -x "use exploit/windows/smb/ms17_010..."  │ │
│ └────────────────────────────────────────────────────────┘ │
│                                                            │
│ ⚠️ Risk Factors:                                           │
│ • Could crash the target system                            │
│ • May trigger IDS/IPS alerts                               │
│ • Network disruption possible                              │
│                                                            │
│ Potential Impact: Full system compromise with SYSTEM       │
│ privileges. Target may become unstable.                    │
│                                                            │
│ ⏱️ Expires in: 29:45                                       │
│                                                            │
│ ┌────────────────────────────────────────────────────────┐ │
│ │ Comment (optional):                                    │ │
│ │ [____________________________________________]         │ │
│ └────────────────────────────────────────────────────────┘ │
│                                                            │
│         [❌ Reject]                      [✅ Approve]       │
└────────────────────────────────────────────────────────────┘
```

---

## 6. Blackboard Pattern

### 6.1 Redis Key Structure

```
mission:{mission_id}:info          # Hash - معلومات المهمة
mission:{mission_id}:goals         # Hash - الأهداف وحالاتها
mission:{mission_id}:stats         # Hash - الإحصائيات
mission:{mission_id}:targets       # Set - مجموعة معرفات الأهداف
mission:{mission_id}:vulns         # Sorted Set - الثغرات (مرتبة بـ CVSS)
mission:{mission_id}:creds         # Set - بيانات الاعتماد
mission:{mission_id}:sessions      # Set - الجلسات
mission:{mission_id}:tasks:pending # Sorted Set - المهام المعلقة (بالأولوية)
mission:{mission_id}:tasks:running # Set - المهام الجارية
mission:{mission_id}:tasks:completed # List - المهام المكتملة
mission:{mission_id}:heartbeats    # Hash - نبضات المتخصصين
mission:{mission_id}:results       # Stream - سجل النتائج

target:{target_id}                 # Hash - معلومات الهدف
target:{target_id}:ports           # Hash - المنافذ المفتوحة

vuln:{vuln_id}                     # Hash - معلومات الثغرة
cred:{cred_id}                     # Hash - معلومات بيانات الاعتماد
session:{session_id}               # Hash - معلومات الجلسة
task:{task_id}                     # Hash - معلومات المهمة
```

### 6.2 Pub/Sub Channels

```
channel:mission:{mission_id}:tasks     # أحداث المهام الجديدة
channel:mission:{mission_id}:targets   # أحداث الأهداف الجديدة
channel:mission:{mission_id}:vulns     # أحداث الثغرات
channel:mission:{mission_id}:creds     # أحداث بيانات الاعتماد
channel:mission:{mission_id}:sessions  # أحداث الجلسات
channel:mission:{mission_id}:goals     # أحداث تحقيق الأهداف
channel:mission:{mission_id}:control   # أوامر التحكم (pause, resume, stop)
channel:mission:{mission_id}:approvals # أحداث HITL
channel:mission:{mission_id}:chat      # أحداث المحادثة
channel:mission:{mission_id}:analysis  # طلبات التحليل للـ LLM
```

---

## 7. Knowledge Base

### 7.1 RX Modules

قاعدة المعرفة تحتوي على **1,761 RX Module** من Atomic Red Team:

```typescript
interface RXModule {
  rx_module_id: string;      // e.g., "rx-t1003-001"
  index: number;
  technique_id: string;      // e.g., "T1003"
  technique_name: string;    // e.g., "OS Credential Dumping"
  description: string;
  execution: {
    platforms: string[];     // ["windows", "linux", "macos"]
    executor_type: string;   // "powershell", "bash", "sh", "cmd"
    command: string;         // الأمر الفعلي
    elevation_required: boolean;
    cleanup_command?: string;
  };
  variables: Variable[];     // متغيرات الإدخال
  prerequisites: Prerequisite[];
}
```

### 7.2 MITRE ATT&CK Mapping

```
Tactic (TA0001) ──► Technique (T1003) ──► RX Module (rx-t1003-001)
     │                    │                      │
     │                    │                      └── Command to execute
     │                    └── OS Credential Dumping
     └── Credential Access
```

### 7.3 Module Categories

| الفئة | التقنيات | الاستخدام |
|-------|----------|-----------|
| **Reconnaissance** | T1016, T1018, T1033, T1082 | اكتشاف الشبكة والنظام |
| **Credential Access** | T1003, T1555, T1552 | جمع بيانات الاعتماد |
| **Privilege Escalation** | T1055, T1068, T1548 | رفع الصلاحيات |
| **Lateral Movement** | T1021, T1210 | الانتقال بين الأهداف |
| **Execution** | T1059, T1204 | تنفيذ الأوامر |

---

## 8. تدفق البيانات (Data Flow)

### 8.1 Mission Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. CREATE MISSION                                               │
│    POST /api/v1/missions                                        │
│    └─► MissionController.create_mission()                       │
│        └─► Blackboard.create_mission() [Redis]                  │
│            └─► Status: CREATED                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. START MISSION                                                │
│    POST /api/v1/missions/{id}/start                             │
│    └─► MissionController.start_mission()                        │
│        ├─► Create initial NETWORK_SCAN task                     │
│        ├─► Start ReconSpecialist                                │
│        ├─► Start AttackSpecialist                               │
│        ├─► Start Monitor Loop (check goals, create tasks)       │
│        ├─► Start Watchdog Loop (detect zombie tasks)            │
│        └─► Status: RUNNING                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. TASK EXECUTION LOOP                                          │
│                                                                 │
│    ┌──────────────────────────────────────────────────────────┐│
│    │ ReconSpecialist                                          ││
│    │ ├─► Claim NETWORK_SCAN task                              ││
│    │ ├─► Execute nmap scan                                    ││
│    │ ├─► Add discovered targets to Blackboard                 ││
│    │ ├─► Publish new_target events                            ││
│    │ ├─► Create PORT_SCAN tasks for each target               ││
│    │ └─► Mark task complete                                   ││
│    └──────────────────────────────────────────────────────────┘│
│                              │                                  │
│                              ▼                                  │
│    ┌──────────────────────────────────────────────────────────┐│
│    │ ReconSpecialist (continued)                              ││
│    │ ├─► Claim PORT_SCAN tasks                                ││
│    │ ├─► Scan ports on target                                 ││
│    │ ├─► Add ports to target in Blackboard                    ││
│    │ ├─► Create SERVICE_ENUM tasks                            ││
│    │ └─► Create VULN_SCAN tasks (Nuclei)                      ││
│    └──────────────────────────────────────────────────────────┘│
│                              │                                  │
│                              ▼                                  │
│    ┌──────────────────────────────────────────────────────────┐│
│    │ AttackSpecialist                                         ││
│    │ ├─► Claim EXPLOIT tasks                                  ││
│    │ ├─► Check risk level                                     ││
│    │ │   └─► If HIGH/CRITICAL: Request HITL approval          ││
│    │ ├─► Execute RX Module                                    ││
│    │ ├─► Add credentials/sessions if successful               ││
│    │ └─► Check if goals achieved                              ││
│    └──────────────────────────────────────────────────────────┘│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. GOAL ACHIEVEMENT                                             │
│    ├─► Monitor detects all goals achieved                       │
│    ├─► Publish goal_achieved events                             │
│    ├─► Stop specialists                                         │
│    └─► Status: COMPLETED                                        │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Real-time Update Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ BACKEND                              │            FRONTEND      │
│                                      │                          │
│ ReconSpecialist                      │                          │
│ └─► add_discovered_target()          │                          │
│     └─► Blackboard.add_target()      │                          │
│         └─► Redis                    │                          │
│     └─► publish_event(NewTargetEvent)│                          │
│         └─► Redis Pub/Sub            │                          │
│                                      │                          │
│ MissionController                    │                          │
│ └─► monitors Redis channels          │                          │
│     └─► ConnectionManager            │                          │
│         .broadcast_to_mission()      │                          │
│             │                        │                          │
│             └────────────────────────┼────► WebSocket           │
│                                      │      └─► useWebSocket()  │
│                                      │          └─► Store update│
│                                      │              └─► UI      │
│                                      │                  re-render│
└─────────────────────────────────────────────────────────────────┘
```

### 8.3 Frontend Data Loading

```typescript
// 1. On App Mount
useEffect(() => {
  const { connect } = useWebSocket({ autoConnect: true });
  connect();
}, []);

// 2. Load Mission Data
const useMissionData = (missionId?: string) => {
  useEffect(() => {
    if (missionId) {
      // Load all data in parallel
      Promise.all([
        fetchMission(missionId),
        fetchTargets(missionId),
        fetchVulnerabilities(missionId),
        fetchCredentials(missionId),
        fetchSessions(missionId),
        fetchMissionStats(missionId)
      ]).then(([mission, targets, vulns, creds, sessions, stats]) => {
        // Update stores
        useMissionStore.setState({ currentMission: mission });
        useEventStore.setState({ targets, vulnerabilities: vulns });
        // etc.
      });
    }
  }, [missionId]);
};

// 3. Handle WebSocket Events
const processWebSocketMessage = (message: WebSocketMessage) => {
  switch (message.type) {
    case 'new_target':
      addTarget(message.data);
      break;
    case 'new_vuln':
      addVulnerability(message.data);
      break;
    case 'approval_request':
      addPendingApproval(message.data);
      break;
    // ... etc
  }
};
```

---

## 9. الروابط والمعلومات الهامة

### 9.1 URLs

| الخدمة | الرابط |
|--------|--------|
| **Frontend** | http://172.245.232.188:3000 |
| **Backend API** | http://172.245.232.188:8000 |
| **API Docs (Swagger)** | http://172.245.232.188:8000/docs |
| **API Docs (ReDoc)** | http://172.245.232.188:8000/redoc |
| **WebSocket Global** | ws://172.245.232.188:8000/ws |
| **WebSocket Mission** | ws://172.245.232.188:8000/ws/missions/{id} |

### 9.2 Integration & Testing Documents (New)

| Document | Description |
|----------|-------------|
| [**API Test Matrix**](./API_TEST_MATRIX.md) | Detailed list of all endpoints, requirements, and test scenarios. |
| [**Comprehensive Test Report**](./COMPREHENSIVE_TEST_REPORT.md) | Full breakdown of pass/fail status, bugs, and critical issues found during testing. |
| [**Frontend Integration Notes**](./FRONTEND_INTEGRATION_NOTES.md) | **Critical for Frontend Devs**: Integration guide, known bugs, workarounds, and error handling strategies. |

### 9.3 Test Mission Data

```
Mission ID: 6b14028c-7f30-4ce6-aad2-20f17eee39d0
Name: Field Acceptance Test
Target: 172.28.0.100 (Linux Ubuntu 22.04)
Ports: 22 (SSH), 80 (HTTP), 5432 (PostgreSQL)
Goals: get_database_creds, establish_session
Status: running

Targets: 1
Vulnerabilities: 2 (SSH Weak Password, DB Credentials in File)
Credentials: 2
Sessions: 1
```

### 9.4 Repository

```
GitHub PR: https://github.com/raglox/RAGLOX_V3/pull/9
Branch: genspark_ai_developer
```

### 9.5 Important Files

**Backend:**
```
webapp/src/api/routes.py          # API endpoints
webapp/src/api/websocket.py       # WebSocket handlers
webapp/src/api/main.py            # FastAPI app
webapp/src/controller/mission.py  # Mission controller
webapp/src/core/blackboard.py     # Redis state management
webapp/src/core/models.py         # Pydantic models
webapp/src/core/knowledge.py      # RX Modules knowledge base
webapp/src/specialists/recon.py   # Recon specialist
webapp/src/specialists/attack.py  # Attack specialist
webapp/src/specialists/base.py    # Base specialist class
```

**Frontend (Current - to be rebuilt):**
```
webapp/frontend/src/services/api.ts       # API client
webapp/frontend/src/hooks/useWebSocket.ts # WebSocket hook
webapp/frontend/src/hooks/useMissionData.ts # Mission data loader
webapp/frontend/src/stores/missionStore.ts # Zustand store
webapp/frontend/src/stores/eventStore.ts   # Events store
webapp/frontend/src/types/index.ts         # TypeScript types
```

---

## 10. أمثلة عملية

### 10.1 مثال: إنشاء وبدء مهمة

```typescript
// 1. Create Mission
const response = await fetch('/api/v1/missions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'Penetration Test - Production',
    description: 'Security assessment of production network',
    scope: ['192.168.1.0/24', '10.0.0.0/24'],
    goals: ['domain_admin', 'data_exfil'],
    constraints: { stealth: true, time_limit: 7200 }
  })
});

const { mission_id } = await response.json();

// 2. Start Mission
await fetch(`/api/v1/missions/${mission_id}/start`, {
  method: 'POST'
});

// 3. Connect WebSocket
const ws = new WebSocket(`ws://localhost:8000/ws/missions/${mission_id}`);

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  switch (message.type) {
    case 'new_target':
      console.log('New target discovered:', message.data.ip);
      break;
    case 'new_vuln':
      console.log('Vulnerability found:', message.data.type);
      break;
    case 'approval_request':
      showApprovalDialog(message.data);
      break;
  }
};
```

### 10.2 مثال: التعامل مع HITL Approval

```typescript
// When approval_request event received
const handleApprovalRequest = async (approval: ApprovalRequest) => {
  // Show dialog to user
  const userDecision = await showApprovalDialog({
    title: `Approval Required: ${approval.action_type}`,
    description: approval.action_description,
    target: approval.target_ip,
    riskLevel: approval.risk_level,
    riskReasons: approval.risk_reasons,
    commandPreview: approval.command_preview,
    expiresAt: approval.expires_at
  });

  if (userDecision.approved) {
    // Approve
    await fetch(`/api/v1/missions/${missionId}/approve/${approval.action_id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_comment: userDecision.comment
      })
    });
  } else {
    // Reject
    await fetch(`/api/v1/missions/${missionId}/reject/${approval.action_id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rejection_reason: userDecision.reason,
        user_comment: userDecision.comment
      })
    });
  }
};
```

### 10.3 مثال: عرض Timeline/Plan بأسلوب Manus

```typescript
interface PlanTask {
  id: string;
  title: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  type: TaskType;
  target?: string;
  command?: string;
  output?: string;
  timestamp: string;
}

// Convert backend events to Plan tasks
const convertToTimeline = (events: WebSocketMessage[]): PlanTask[] => {
  return events.map(event => ({
    id: event.data.task_id || event.data.target_id || event.data.vuln_id,
    title: getTaskTitle(event),
    status: getTaskStatus(event),
    type: event.data.type,
    target: event.data.target_ip,
    command: event.data.command_preview,
    output: event.data.result,
    timestamp: event.timestamp
  }));
};

// Render Manus-style timeline
const PlanView: React.FC<{ tasks: PlanTask[] }> = ({ tasks }) => (
  <div className="plan-container">
    {tasks.map(task => (
      <div key={task.id} className={`task-item ${task.status}`}>
        <div className="task-header">
          <StatusIcon status={task.status} />
          <span className="task-title">{task.title}</span>
          {task.status === 'completed' && <CheckIcon />}
        </div>
        
        {task.command && (
          <div className="task-command">
            <Badge>Executing command</Badge>
            <code>{task.command}</code>
          </div>
        )}
        
        {task.output && (
          <TerminalOutput content={task.output} />
        )}
      </div>
    ))}
  </div>
);
```

### 10.4 مثال: Chat Integration

```typescript
// Chat commands recognized by backend
const CHAT_COMMANDS = {
  'status': 'Get mission status',
  'pause': 'Pause the mission',
  'resume': 'Resume the mission', 
  'pending': 'List pending approvals',
  'help': 'Show available commands'
};

const sendChatMessage = async (content: string) => {
  const response = await fetch(`/api/v1/missions/${missionId}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content })
  });
  
  return response.json();
};

// WebSocket will deliver the system response
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  if (message.type === 'chat_message') {
    addMessageToChat({
      role: message.data.role,
      content: message.data.content,
      timestamp: message.timestamp
    });
  }
};
```

---

## 11. AI-to-Nuclei Logic Wiring 🧠

### 11.1 نظرة عامة

**AI-to-Nuclei Logic Wiring** هو تفعيل الربط الذكي بين نظام الذكاء الاصطناعي وقاعدة معرفة Nuclei Templates.

الهدف: عندما يكتشف النظام منفذاً معيناً (مثل 80 أو 443)، يقوم تلقائياً بـ:
1. تحليل "بصمة التقنية" (Technology Fingerprint)
2. البحث في Knowledge Base عن قوالب Nuclei المناسبة
3. اختيار قوالب Info/Low للاستطلاع الأولي
4. إرسال رسائل `[AI-PLAN]` عبر WebSocket للعرض في Execution Stream

### 11.2 رسائل AI-PLAN في الواجهة

#### 11.2.1 حدث WebSocket جديد: `ai_plan`

```javascript
// WebSocket event format
{
  "type": "mission_update",
  "mission_id": "uuid",
  "data": {
    "event": "ai_plan",
    "subtype": "nuclei_template_selection",
    "port": 80,
    "templates_count": 15,
    "message": "[AI-PLAN] Found Port 80. Selecting 15 Nuclei templates based on technology fingerprint...",
    "templates": ["apache-detect", "nginx-detect", "wordpress-detect", ...]
  },
  "timestamp": "2026-01-02T11:00:00"
}
```

#### 11.2.2 عرض الرسائل في UI

**الاستخدام في Execution Stream:**

```jsx
// React component example
const ExecutionStream = ({ missionId }) => {
  const [events, setEvents] = useState([]);
  
  useEffect(() => {
    const ws = new WebSocket(`ws://host:8000/ws/missions/${missionId}`);
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      // Handle AI-PLAN events specially
      if (data.type === 'mission_update' && data.data?.event === 'ai_plan') {
        setEvents(prev => [...prev, {
          type: 'ai_plan',
          icon: '🧠',
          color: 'purple',
          message: data.data.message,
          details: {
            port: data.data.port,
            templatesCount: data.data.templates_count,
            templates: data.data.templates
          },
          timestamp: data.timestamp
        }]);
      }
    };
  }, [missionId]);
  
  return (
    <div className="execution-stream">
      {events.map((event, idx) => (
        <EventCard key={idx} {...event} />
      ))}
    </div>
  );
};
```

### 11.3 صفحة Arsenal - البحث في Nuclei Templates

#### 11.3.1 Endpoints للبحث

```http
# البحث اللحظي في قوالب Nuclei
GET /api/v1/knowledge/nuclei/search?q=apache&severity=info&limit=20

Response:
[
  {
    "template_id": "apache-detect",
    "name": "Apache Detection",
    "severity": "info",
    "tags": ["http", "apache", "tech"],
    "protocol": ["http"],
    "description": "Detects Apache web server"
  },
  ...
]
```

```http
# الحصول على قالب بـ CVE ID
GET /api/v1/knowledge/nuclei/cve/CVE-2021-44228

Response:
{
  "template_id": "CVE-2021-44228",
  "name": "Log4Shell RCE",
  "severity": "critical",
  "cve_id": ["CVE-2021-44228"],
  "cvss_score": 10.0,
  "tags": ["cve", "rce", "log4j", "java"],
  "description": "Apache Log4j Remote Code Execution"
}
```

#### 11.3.2 مكون البحث اللحظي (Live Search)

```jsx
// React component for Arsenal page
const NucleiSearchPanel = () => {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  
  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (query.length >= 2) {
        searchNucleiTemplates();
      }
    }, 300);
    
    return () => clearTimeout(timer);
  }, [query, severity]);
  
  const searchNucleiTemplates = async () => {
    setLoading(true);
    const params = new URLSearchParams({ q: query });
    if (severity) params.append('severity', severity);
    
    const response = await fetch(`/api/v1/knowledge/nuclei/search?${params}`);
    const data = await response.json();
    setResults(data);
    setLoading(false);
  };
  
  return (
    <div className="nuclei-search-panel">
      <div className="search-controls">
        <input
          type="text"
          placeholder="Search Nuclei templates (e.g., CVE-2021-44228, apache, wordpress)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="search-input"
        />
        
        <select 
          value={severity} 
          onChange={(e) => setSeverity(e.target.value)}
          className="severity-filter"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>
      
      <div className="results-grid">
        {loading ? (
          <LoadingSpinner />
        ) : (
          results.map(template => (
            <NucleiTemplateCard key={template.template_id} template={template} />
          ))
        )}
      </div>
    </div>
  );
};
```

### 11.4 تدفق AI-to-Nuclei الكامل

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      AI-to-Nuclei Logic Wiring Flow                     │
└─────────────────────────────────────────────────────────────────────────┘

1. Port Discovery (ReconSpecialist)
   ┌─────────────────────┐
   │ Port 80 Discovered  │
   └──────────┬──────────┘
              │
              ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ [AI-PLAN] Technology Fingerprint: ["http", "apache", "nginx"]   │
   └──────────────────────────────────────────────────────────────────┘
              │
              ▼
2. Template Selection
   ┌──────────────────────────────────────────────────────────────────┐
   │ Knowledge Base Query:                                            │
   │ - get_nuclei_templates_by_severity("info", limit=100)           │
   │ - get_nuclei_templates_by_severity("low", limit=100)            │
   │ - search_nuclei_templates(query="http", severity="info")        │
   └──────────────────────────────────────────────────────────────────┘
              │
              ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ [AI-PLAN] Found Port 80. Selecting 15 Nuclei templates          │
   │           based on technology fingerprint...                     │
   └──────────────────────────────────────────────────────────────────┘
              │
              ▼
3. WebSocket Event
   ┌──────────────────────────────────────────────────────────────────┐
   │ Blackboard.log_result("ai_plan", {                              │
   │   "event": "nuclei_template_selection",                         │
   │   "port": 80,                                                   │
   │   "templates_count": 15,                                        │
   │   "message": "[AI-PLAN] Found Port 80. Selecting..."            │
   │ })                                                              │
   └──────────────────────────────────────────────────────────────────┘
              │
              ▼
4. Frontend Display
   ┌──────────────────────────────────────────────────────────────────┐
   │ 🧠 [AI-PLAN] Found Port 80. Selecting 15 Nuclei templates       │
   │              based on technology fingerprint...                  │
   │    ├── apache-detect                                            │
   │    ├── nginx-detect                                             │
   │    ├── wordpress-detect                                         │
   │    └── ...12 more templates                                     │
   └──────────────────────────────────────────────────────────────────┘


─────────────────────────────────────────────────────────────────────────

5. Exploit Failure (AnalysisSpecialist)
   ┌─────────────────────────────┐
   │ CVE-2021-44228 Exploit     │
   │ Failed (WAF Detected)       │
   └──────────────┬──────────────┘
                  │
                  ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ [AI-PLAN] Exploit failed for CVE-2021-44228.                    │
   │           Searching Nuclei Knowledge Base for alternatives...    │
   └──────────────────────────────────────────────────────────────────┘
                  │
                  ▼
6. Alternative Search
   ┌──────────────────────────────────────────────────────────────────┐
   │ Knowledge Base Query:                                            │
   │ - get_nuclei_template_by_cve("CVE-2021-44228")                  │
   │ - get_nuclei_templates_by_tag("waf-bypass", limit=10)           │
   │ - search_nuclei_templates("evasion", severity="medium")         │
   └──────────────────────────────────────────────────────────────────┘
                  │
                  ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ [AI-PLAN] Found Nuclei template for CVE-2021-44228.             │
   │           Suggesting alternative approach: evasion               │
   │           - waf-bypass-generic                                   │
   │           - log4j-bypass-waf                                     │
   └──────────────────────────────────────────────────────────────────┘
                  │
                  ▼
7. Decision with Nuclei Guidance
   ┌──────────────────────────────────────────────────────────────────┐
   │ {                                                               │
   │   "decision": "modify_approach",                                │
   │   "reasoning": "Defense detected. AI-PLAN suggests: Try         │
   │                WAF bypass techniques.",                         │
   │   "nuclei_approach": {                                          │
   │     "type": "evasion",                                          │
   │     "suggested_templates": ["waf-bypass-generic", ...],         │
   │     "reasoning": "These templates include WAF bypass..."        │
   │   }                                                             │
   │ }                                                               │
   └──────────────────────────────────────────────────────────────────┘
```

### 11.5 API Endpoints للاستخدام في Arsenal

| Endpoint | الوصف | الاستخدام |
|----------|-------|----------|
| `GET /api/v1/knowledge/nuclei/templates` | قائمة القوالب مع pagination | عرض كل القوالب |
| `GET /api/v1/knowledge/nuclei/search?q=...` | البحث اللحظي | البحث السريع |
| `GET /api/v1/knowledge/nuclei/cve/{cve_id}` | قالب محدد بـ CVE | تفاصيل CVE |
| `GET /api/v1/knowledge/nuclei/severity/{sev}` | قوالب حسب الشدة | فلترة |
| `GET /api/v1/knowledge/nuclei/critical` | القوالب الحرجة فقط | Quick access |
| `GET /api/v1/knowledge/nuclei/rce` | قوالب RCE | Quick access |

### 11.6 أيقونات وألوان للـ UI

```javascript
const AI_PLAN_STYLES = {
  icon: '🧠',
  color: '#9333ea', // purple-600
  backgroundColor: 'rgba(147, 51, 234, 0.1)',
  borderColor: 'rgba(147, 51, 234, 0.3)',
  
  // Badge colors for severity
  severity: {
    critical: { bg: '#dc2626', text: '#ffffff' }, // red-600
    high: { bg: '#ea580c', text: '#ffffff' },     // orange-600
    medium: { bg: '#ca8a04', text: '#ffffff' },   // yellow-600
    low: { bg: '#16a34a', text: '#ffffff' },      // green-600
    info: { bg: '#2563eb', text: '#ffffff' },     // blue-600
  }
};
```

---

## الخلاصة

هذه الوثيقة تغطي كل ما يحتاجه المطور لبناء فرونت-إند جديد بأسلوب Manus:

1. **API الكاملة** - كل endpoints مع أمثلة
2. **نماذج البيانات** - كل الـ Types و Enums
3. **WebSocket** - الأحداث الحية وأشكالها
4. **HITL** - نظام الموافقات البشرية
5. **تدفق البيانات** - من الباك-إند للفرونت-إند
6. **AI-to-Nuclei Logic Wiring** - تفعيل الذكاء مع Nuclei 🧠

للأسئلة أو التوضيحات، راجع ملفات الكود المصدري المذكورة أو API docs على `/docs`.

---

*آخر تحديث: 2026-01-02*
*الإصدار: 3.0.0*
*جديد: AI-to-Nuclei Logic Wiring ✅*
