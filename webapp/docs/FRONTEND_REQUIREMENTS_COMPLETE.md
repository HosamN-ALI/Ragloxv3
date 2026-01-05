# RAGLOX v3.0 - Frontend Requirements & Gap Analysis
## تحليل شامل لمتطلبات الواجهة والفجوات

---

## 📊 ملخص تنفيذي

| القسم | Backend APIs | Frontend موجود | الفجوة |
|-------|-------------|----------------|--------|
| **Missions** | 15 endpoints | ✅ 90% | 10% |
| **Knowledge** | 25 endpoints | ✅ 80% | 20% |
| **Exploitation** | 24 endpoints | ❌ 0% | 100% |
| **Infrastructure** | 12 endpoints | ❌ 0% | 100% |
| **Workflow** | 11 endpoints | ❌ 0% | 100% |
| **Security** | 15 endpoints | ❌ 0% | 100% |

---

## 🎯 الجزء الأول: API Endpoints الكاملة

### 1. Mission APIs (موجود جزئياً)

```typescript
// ✅ موجود في api.ts
POST   /api/v1/missions                          // إنشاء mission
GET    /api/v1/missions                          // قائمة missions
GET    /api/v1/missions/{id}                     // تفاصيل mission
POST   /api/v1/missions/{id}/start               // بدء mission
POST   /api/v1/missions/{id}/pause               // إيقاف مؤقت
POST   /api/v1/missions/{id}/resume              // استئناف
POST   /api/v1/missions/{id}/stop                // إيقاف نهائي
GET    /api/v1/missions/{id}/targets             // الأهداف
GET    /api/v1/missions/{id}/targets/{tid}       // هدف محدد
GET    /api/v1/missions/{id}/vulnerabilities     // الثغرات
GET    /api/v1/missions/{id}/credentials         // بيانات الاعتماد
GET    /api/v1/missions/{id}/sessions            // الجلسات
GET    /api/v1/missions/{id}/stats               // الإحصائيات
GET    /api/v1/missions/{id}/approvals           // الموافقات المعلقة
POST   /api/v1/missions/{id}/approve/{action_id} // قبول
POST   /api/v1/missions/{id}/reject/{action_id}  // رفض
POST   /api/v1/missions/{id}/chat                // إرسال رسالة
GET    /api/v1/missions/{id}/chat                // سجل المحادثة
```

### 2. Knowledge APIs (موجود جزئياً)

```typescript
// ✅ موجود في api.ts
GET    /api/v1/knowledge/stats                   // إحصائيات
GET    /api/v1/knowledge/techniques              // التقنيات
GET    /api/v1/knowledge/techniques/{id}         // تقنية محددة
GET    /api/v1/knowledge/techniques/{id}/modules // وحدات التقنية
GET    /api/v1/knowledge/modules                 // الوحدات
GET    /api/v1/knowledge/modules/{id}            // وحدة محددة
GET    /api/v1/knowledge/tactics                 // التكتيكات
GET    /api/v1/knowledge/platforms               // المنصات
GET    /api/v1/knowledge/search                  // بحث
POST   /api/v1/knowledge/search                  // بحث متقدم
POST   /api/v1/knowledge/best-module             // أفضل وحدة

// Nuclei Templates
GET    /api/v1/knowledge/nuclei/templates        // القوالب
GET    /api/v1/knowledge/nuclei/templates/{id}   // قالب محدد
GET    /api/v1/knowledge/nuclei/search           // بحث في القوالب
GET    /api/v1/knowledge/nuclei/cve/{cve_id}     // البحث بـ CVE
GET    /api/v1/knowledge/nuclei/severity/{sev}   // بحث بالخطورة
GET    /api/v1/knowledge/nuclei/critical         // القوالب الحرجة
GET    /api/v1/knowledge/nuclei/rce              // قوالب RCE
GET    /api/v1/knowledge/nuclei/sqli             // قوالب SQL Injection
GET    /api/v1/knowledge/nuclei/xss              // قوالب XSS
```

### 3. Exploitation APIs (❌ غير موجود في Frontend)

```typescript
// ⚠️ يجب إضافته
// C2 Sessions
GET    /api/v1/exploitation/c2/sessions          // قائمة الجلسات
GET    /api/v1/exploitation/c2/sessions/{id}     // تفاصيل جلسة
POST   /api/v1/exploitation/c2/sessions/{id}/execute    // تنفيذ أمر
DELETE /api/v1/exploitation/c2/sessions/{id}     // إنهاء جلسة
POST   /api/v1/exploitation/c2/sessions/{id}/proxy      // SOCKS proxy

// Status & Health
GET    /api/v1/exploitation/status/metasploit    // حالة Metasploit
GET    /api/v1/exploitation/status/exploitation  // حالة الاستغلال
GET    /api/v1/exploitation/health               // صحة النظام

// Exploits
GET    /api/v1/exploitation/exploits             // قائمة الاستغلالات
GET    /api/v1/exploitation/exploits/{id}        // تفاصيل استغلال
GET    /api/v1/exploitation/exploits/cve/{cve}   // البحث بـ CVE
GET    /api/v1/exploitation/exploits/stats       // إحصائيات
DELETE /api/v1/exploitation/cache/clear          // مسح الذاكرة المؤقتة

// Payloads
POST   /api/v1/exploitation/payloads/generate    // توليد payload
GET    /api/v1/exploitation/payloads/types       // أنواع payloads

// Post-Exploitation
POST   /api/v1/exploitation/post-exploitation/harvest   // جمع بيانات

// Pivoting
POST   /api/v1/exploitation/pivoting/port-forward       // Port forwarding
GET    /api/v1/exploitation/pivoting/routes      // مسارات الشبكة

// Specific Exploits
POST   /api/v1/exploitation/exploits/eternalblue/execute
POST   /api/v1/exploitation/exploits/eternalblue/check
POST   /api/v1/exploitation/exploits/log4shell/execute
POST   /api/v1/exploitation/exploits/log4shell/scan

// Metasploit Integration
GET    /api/v1/exploitation/metasploit/modules   // وحدات Metasploit
POST   /api/v1/exploitation/metasploit/execute   // تنفيذ وحدة
```

### 4. Infrastructure APIs (❌ غير موجود في Frontend)

```typescript
// ⚠️ يجب إضافته
// Environments (SSH/VM)
POST   /api/v1/infrastructure/environments       // إنشاء بيئة
GET    /api/v1/infrastructure/environments/{id}  // تفاصيل بيئة
GET    /api/v1/infrastructure/users/{uid}/environments  // بيئات المستخدم
DELETE /api/v1/infrastructure/environments/{id}  // حذف بيئة
POST   /api/v1/infrastructure/environments/{id}/reconnect  // إعادة اتصال

// Remote Execution
POST   /api/v1/infrastructure/environments/{id}/execute/command  // تنفيذ أمر
POST   /api/v1/infrastructure/environments/{id}/execute/script   // تنفيذ سكريبت
GET    /api/v1/infrastructure/environments/{id}/system-info      // معلومات النظام

// Health & Stats
GET    /api/v1/infrastructure/environments/{id}/health           // صحة البيئة
GET    /api/v1/infrastructure/environments/{id}/health/statistics
GET    /api/v1/infrastructure/statistics         // إحصائيات عامة
```

### 5. Workflow APIs (❌ غير موجود في Frontend)

```typescript
// ⚠️ يجب إضافته
POST   /api/v1/workflow/start                    // بدء workflow
GET    /api/v1/workflow/{mission_id}/status      // حالة workflow
GET    /api/v1/workflow/{mission_id}/phases      // مراحل workflow
POST   /api/v1/workflow/{mission_id}/pause       // إيقاف مؤقت
POST   /api/v1/workflow/{mission_id}/resume      // استئناف
POST   /api/v1/workflow/{mission_id}/stop        // إيقاف

// Tools
GET    /api/v1/workflow/tools                    // قائمة الأدوات
GET    /api/v1/workflow/tools/for-goal/{goal}    // أدوات لهدف محدد
GET    /api/v1/workflow/tools/{tool_name}        // تفاصيل أداة
POST   /api/v1/workflow/tools/install            // تثبيت أداة
GET    /api/v1/workflow/health                   // صحة workflow
```

### 6. Security APIs (❌ غير موجود في Frontend)

```typescript
// ⚠️ يجب إضافته
// Validation (SEC-03)
POST   /api/v1/security/validate/ip              // التحقق من IP
POST   /api/v1/security/validate/cidr            // التحقق من CIDR
POST   /api/v1/security/validate/uuid            // التحقق من UUID
POST   /api/v1/security/validate/hostname        // التحقق من hostname
POST   /api/v1/security/validate/port            // التحقق من port
POST   /api/v1/security/validate/cve             // التحقق من CVE
POST   /api/v1/security/validate/safe-string     // التحقق من النص الآمن
POST   /api/v1/security/validate/scope           // التحقق من النطاق
POST   /api/v1/security/validate/batch           // التحقق الجماعي

// Rate Limiting (SEC-04)
GET    /api/v1/security/rate-limit/info          // معلومات الحد
GET    /api/v1/security/rate-limit/status        // حالة الحد
POST   /api/v1/security/rate-limit/reset         // إعادة تعيين

// Health & Stats
GET    /api/v1/security/health                   // صحة الأمان
GET    /api/v1/security/stats                    // إحصائيات

// IP Management
POST   /api/v1/security/whitelist                // إضافة للقائمة البيضاء
```

### 7. Stats APIs (موجود جزئياً)

```typescript
// ⚠️ بعضها غير مستخدم
GET    /api/v1/stats/system                      // إحصائيات النظام
GET    /api/v1/stats/retry-policies              // سياسات إعادة المحاولة
GET    /api/v1/stats/sessions                    // إحصائيات الجلسات
GET    /api/v1/stats/circuit-breakers            // حالة circuit breakers
```

---

## 🔴 الجزء الثاني: الفجوات الحرجة في Frontend

### 1. صفحات مفقودة

| الصفحة | الأولوية | الوصف |
|--------|----------|-------|
| `/exploitation` | 🔴 عالية | إدارة C2 Sessions والاستغلالات |
| `/infrastructure` | 🔴 عالية | إدارة البيئات SSH/VM |
| `/workflow` | 🔴 عالية | عرض وإدارة سير العمل |
| `/tools` | 🟡 متوسطة | إدارة أدوات الاختراق |
| `/security` | 🟡 متوسطة | لوحة مراقبة الأمان |
| `/reports` | 🟡 متوسطة | إنشاء وتصدير التقارير |
| `/settings` | 🟢 منخفضة | إعدادات النظام |

### 2. مكونات UI مفقودة

```
❌ C2SessionPanel          - إدارة جلسات C2
❌ ExploitManager          - قائمة وتنفيذ الاستغلالات
❌ PayloadGenerator        - توليد payloads
❌ EnvironmentManager      - إدارة البيئات SSH/VM
❌ WorkflowVisualization   - رسم بياني للمراحل 9
❌ PhaseProgress           - تقدم كل مرحلة
❌ ToolInstaller           - تثبيت الأدوات
❌ SecurityDashboard       - لوحة الأمان
❌ ReportGenerator         - مولد التقارير
❌ AuditLog                - سجل المراجعة
```

### 3. Types مفقودة في TypeScript

```typescript
// ⚠️ يجب إضافتها إلى types/index.ts

// Exploitation Types
interface C2Session {
  session_id: string;
  target_ip: string;
  session_type: "meterpreter" | "shell" | "beacon";
  username: string;
  privilege: "user" | "admin" | "system";
  status: "active" | "dead" | "stale";
  established_at: string;
  last_seen: string;
  platform: string;
  arch: string;
}

interface Exploit {
  exploit_id: string;
  name: string;
  description: string;
  cve_ids: string[];
  platforms: string[];
  rank: "excellent" | "great" | "good" | "normal" | "low";
  disclosure_date: string;
  author: string;
  references: string[];
}

interface Payload {
  name: string;
  description: string;
  platform: string;
  arch: string;
  type: "reverse" | "bind" | "staged" | "stageless";
}

// Infrastructure Types
interface Environment {
  id: string;
  name: string;
  type: "ssh" | "winrm" | "local";
  host: string;
  port: number;
  username: string;
  status: "connected" | "disconnected" | "error";
  created_at: string;
  last_connected: string;
  system_info?: SystemInfo;
}

interface SystemInfo {
  hostname: string;
  os: string;
  kernel: string;
  arch: string;
  uptime: string;
  memory_total: number;
  memory_free: number;
}

// Workflow Types
interface WorkflowStatus {
  mission_id: string;
  current_phase: WorkflowPhase;
  phases_completed: WorkflowPhase[];
  phases_remaining: WorkflowPhase[];
  progress_percentage: number;
  started_at: string;
  estimated_completion: string;
}

type WorkflowPhase = 
  | "init"
  | "planning"
  | "reconnaissance"
  | "initial_access"
  | "post_exploitation"
  | "lateral_movement"
  | "goal_execution"
  | "reporting"
  | "cleanup";

interface PhaseResult {
  phase: WorkflowPhase;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  started_at?: string;
  completed_at?: string;
  findings: unknown[];
  actions_taken: number;
  errors: string[];
}

interface Tool {
  name: string;
  category: "recon" | "scanner" | "exploit" | "post_exploit" | "credential" | "lateral" | "utility";
  description: string;
  installed: boolean;
  version?: string;
  platforms: string[];
  dependencies: string[];
}
```

---

## 🟢 الجزء الثالث: ما هو موجود ويعمل

### 1. المكونات الموجودة والعاملة

```
✅ AIChatPanel        - محادثة AI
✅ TerminalPanel      - عرض Terminal
✅ ApprovalCard       - بطاقات HITL
✅ EventCard          - بطاقات الأحداث
✅ ArtifactCard       - عرض الاكتشافات
✅ PlanView           - عرض خطة AI
✅ Sidebar            - القائمة الجانبية
✅ DualPanelLayout    - التخطيط الثنائي
```

### 2. الصفحات الموجودة

```
✅ /                  - الصفحة الرئيسية
✅ /missions          - قائمة المهام
✅ /operations        - العمليات (Mission Details)
✅ /knowledge         - قاعدة المعرفة
✅ /login             - تسجيل الدخول
```

### 3. الـ Hooks الموجودة

```
✅ useWebSocket       - إدارة WebSocket
✅ useMissionData     - بيانات المهمة
✅ useMobile          - الاستجابة للموبايل
```

---

## 📋 الجزء الرابع: خطة التنفيذ

### المرحلة 1: Infrastructure & Exploitation (أولوية عالية - 3 أيام)

#### اليوم 1: Infrastructure Page
```
1. إنشاء /pages/Infrastructure.tsx
2. إنشاء مكونات:
   - EnvironmentList
   - EnvironmentCard
   - EnvironmentForm (create/edit)
   - RemoteTerminal
   - SystemInfoPanel
3. إضافة API functions في api.ts:
   - infrastructureApi
4. إضافة Types في types/index.ts
```

#### اليوم 2: Exploitation Page (Part 1)
```
1. إنشاء /pages/Exploitation.tsx
2. إنشاء مكونات:
   - C2SessionList
   - C2SessionDetail
   - SessionTerminal (تنفيذ أوامر)
   - ExploitLibrary
3. إضافة API functions:
   - exploitationApi
```

#### اليوم 3: Exploitation Page (Part 2)
```
1. مكونات إضافية:
   - PayloadGenerator
   - PivotingManager
   - PostExploitPanel
2. تكامل مع الصفحات الموجودة
```

### المرحلة 2: Workflow Visualization (أولوية عالية - 2 يوم)

#### اليوم 4: Workflow Page
```
1. إنشاء /pages/Workflow.tsx
2. إنشاء مكونات:
   - WorkflowDiagram (رسم بياني للمراحل 9)
   - PhaseCard
   - PhaseProgress
   - PhaseTimeline
3. إضافة workflowApi
```

#### اليوم 5: Tools Management
```
1. مكونات:
   - ToolsList
   - ToolCard
   - ToolInstaller
   - GoalToolsRecommendation
```

### المرحلة 3: Security & Reporting (أولوية متوسطة - 2 يوم)

#### اليوم 6: Security Dashboard
```
1. إنشاء /pages/Security.tsx
2. مكونات:
   - SecurityOverview
   - RateLimitStatus
   - ValidationStats
   - AuditLog
3. إضافة securityApi
```

#### اليوم 7: Reports
```
1. إنشاء /pages/Reports.tsx
2. مكونات:
   - ReportGenerator
   - ReportPreview
   - ExportOptions (PDF, JSON, HTML)
```

### المرحلة 4: Polish & Integration (1 يوم)

#### اليوم 8: التكامل النهائي
```
1. ربط جميع الصفحات
2. تحديث Sidebar بالروابط الجديدة
3. اختبار E2E للواجهة
4. تحسين UX/UI
5. Dark mode support
6. Mobile responsiveness
```

---

## 📁 هيكل الملفات المقترح

```
client/src/
├── pages/
│   ├── Home.tsx           ✅ موجود
│   ├── Missions.tsx       ✅ موجود
│   ├── Operations.tsx     ✅ موجود
│   ├── Knowledge.tsx      ✅ موجود
│   ├── Login.tsx          ✅ موجود
│   ├── Infrastructure.tsx ❌ جديد
│   ├── Exploitation.tsx   ❌ جديد
│   ├── Workflow.tsx       ❌ جديد
│   ├── Tools.tsx          ❌ جديد
│   ├── Security.tsx       ❌ جديد
│   └── Reports.tsx        ❌ جديد
│
├── components/
│   ├── manus/             ✅ موجود
│   ├── ui/                ✅ موجود
│   │
│   ├── infrastructure/    ❌ جديد
│   │   ├── EnvironmentList.tsx
│   │   ├── EnvironmentCard.tsx
│   │   ├── EnvironmentForm.tsx
│   │   ├── RemoteTerminal.tsx
│   │   └── SystemInfoPanel.tsx
│   │
│   ├── exploitation/      ❌ جديد
│   │   ├── C2SessionList.tsx
│   │   ├── C2SessionDetail.tsx
│   │   ├── SessionTerminal.tsx
│   │   ├── ExploitLibrary.tsx
│   │   ├── PayloadGenerator.tsx
│   │   └── PivotingManager.tsx
│   │
│   ├── workflow/          ❌ جديد
│   │   ├── WorkflowDiagram.tsx
│   │   ├── PhaseCard.tsx
│   │   ├── PhaseProgress.tsx
│   │   └── PhaseTimeline.tsx
│   │
│   ├── tools/             ❌ جديد
│   │   ├── ToolsList.tsx
│   │   ├── ToolCard.tsx
│   │   └── ToolInstaller.tsx
│   │
│   ├── security/          ❌ جديد
│   │   ├── SecurityOverview.tsx
│   │   ├── RateLimitStatus.tsx
│   │   └── AuditLog.tsx
│   │
│   └── reports/           ❌ جديد
│       ├── ReportGenerator.tsx
│       └── ReportPreview.tsx
│
├── lib/
│   └── api.ts             ✅ موجود (يحتاج تحديث)
│
└── types/
    └── index.ts           ✅ موجود (يحتاج تحديث)
```

---

## 🔧 التحديثات المطلوبة للملفات الموجودة

### 1. تحديث `client/src/lib/api.ts`

```typescript
// ⚠️ إضافة APIs الجديدة:

// Infrastructure API
export const infrastructureApi = {
  environments: {
    create: async (data: CreateEnvironmentRequest): Promise<Environment> => {...},
    list: async (userId?: string): Promise<Environment[]> => {...},
    get: async (id: string): Promise<Environment> => {...},
    delete: async (id: string): Promise<void> => {...},
    reconnect: async (id: string): Promise<void> => {...},
    executeCommand: async (id: string, command: string): Promise<ExecutionResult> => {...},
    executeScript: async (id: string, script: string): Promise<ExecutionResult> => {...},
    getSystemInfo: async (id: string): Promise<SystemInfo> => {...},
    getHealth: async (id: string): Promise<HealthStatus> => {...},
  },
  stats: async (): Promise<InfrastructureStats> => {...},
};

// Exploitation API
export const exploitationApi = {
  sessions: {
    list: async (): Promise<C2Session[]> => {...},
    get: async (id: string): Promise<C2Session> => {...},
    execute: async (id: string, command: string): Promise<CommandResult> => {...},
    close: async (id: string): Promise<void> => {...},
    proxy: async (id: string, config: ProxyConfig): Promise<ProxyResult> => {...},
  },
  exploits: {
    list: async (): Promise<Exploit[]> => {...},
    get: async (id: string): Promise<Exploit> => {...},
    searchByCve: async (cve: string): Promise<Exploit[]> => {...},
    stats: async (): Promise<ExploitStats> => {...},
  },
  payloads: {
    generate: async (config: PayloadConfig): Promise<PayloadResult> => {...},
    types: async (): Promise<string[]> => {...},
  },
  postExploit: {
    harvest: async (sessionId: string, config: HarvestConfig): Promise<HarvestResult> => {...},
  },
  pivoting: {
    portForward: async (config: PortForwardConfig): Promise<void> => {...},
    routes: async (): Promise<Route[]> => {...},
  },
  metasploit: {
    modules: async (): Promise<string[]> => {...},
    execute: async (module: string, options: object): Promise<ExecutionResult> => {...},
  },
  health: async (): Promise<ExploitationHealth> => {...},
};

// Workflow API
export const workflowApi = {
  start: async (missionId: string): Promise<WorkflowStatus> => {...},
  status: async (missionId: string): Promise<WorkflowStatus> => {...},
  phases: async (missionId: string): Promise<PhaseResult[]> => {...},
  pause: async (missionId: string): Promise<void> => {...},
  resume: async (missionId: string): Promise<void> => {...},
  stop: async (missionId: string): Promise<void> => {...},
  tools: {
    list: async (): Promise<Tool[]> => {...},
    forGoal: async (goal: string): Promise<Tool[]> => {...},
    get: async (name: string): Promise<Tool> => {...},
    install: async (name: string): Promise<InstallResult> => {...},
  },
  health: async (): Promise<WorkflowHealth> => {...},
};

// Security API
export const securityApi = {
  validate: {
    ip: async (ip: string): Promise<ValidationResult> => {...},
    cidr: async (cidr: string): Promise<ValidationResult> => {...},
    uuid: async (uuid: string): Promise<ValidationResult> => {...},
    hostname: async (hostname: string): Promise<ValidationResult> => {...},
    port: async (port: number): Promise<ValidationResult> => {...},
    cve: async (cve: string): Promise<ValidationResult> => {...},
    safeString: async (text: string): Promise<ValidationResult> => {...},
    scope: async (scope: string[]): Promise<ValidationResult> => {...},
    batch: async (items: ValidationItem[]): Promise<BatchValidationResult> => {...},
  },
  rateLimit: {
    info: async (): Promise<RateLimitInfo> => {...},
    status: async (): Promise<RateLimitStatus> => {...},
    reset: async (): Promise<void> => {...},
  },
  health: async (): Promise<SecurityHealth> => {...},
  stats: async (): Promise<SecurityStats> => {...},
};
```

### 2. تحديث `client/src/App.tsx`

```typescript
// ⚠️ إضافة Routes الجديدة:

import Infrastructure from "@/pages/Infrastructure";
import Exploitation from "@/pages/Exploitation";
import Workflow from "@/pages/Workflow";
import Tools from "@/pages/Tools";
import Security from "@/pages/Security";
import Reports from "@/pages/Reports";

// في Router:
<Route path="/infrastructure" element={<Infrastructure />} />
<Route path="/exploitation" element={<Exploitation />} />
<Route path="/workflow/:missionId?" element={<Workflow />} />
<Route path="/tools" element={<Tools />} />
<Route path="/security" element={<Security />} />
<Route path="/reports" element={<Reports />} />
```

### 3. تحديث `client/src/components/manus/Sidebar.tsx`

```typescript
// ⚠️ إضافة روابط جديدة:

const navItems = [
  { path: "/", icon: Home, label: "Dashboard" },
  { path: "/missions", icon: Target, label: "Missions" },
  { path: "/workflow", icon: GitBranch, label: "Workflow" },     // جديد
  { path: "/infrastructure", icon: Server, label: "Infrastructure" }, // جديد
  { path: "/exploitation", icon: Bug, label: "Exploitation" },   // جديد
  { path: "/tools", icon: Wrench, label: "Tools" },              // جديد
  { path: "/knowledge", icon: Database, label: "Knowledge" },
  { path: "/security", icon: Shield, label: "Security" },        // جديد
  { path: "/reports", icon: FileText, label: "Reports" },        // جديد
];
```

---

## ✅ Checklist للتطوير

### قبل البدء
- [ ] مراجعة هذه الوثيقة بالكامل
- [ ] فهم معمارية Backend
- [ ] فهم الـ Types الموجودة

### أثناء التطوير
- [ ] إنشاء صفحة Infrastructure
- [ ] إنشاء صفحة Exploitation
- [ ] إنشاء صفحة Workflow
- [ ] إنشاء صفحة Tools
- [ ] إنشاء صفحة Security
- [ ] إنشاء صفحة Reports
- [ ] تحديث api.ts
- [ ] تحديث types/index.ts
- [ ] تحديث Sidebar
- [ ] تحديث App.tsx routes

### بعد التطوير
- [ ] اختبار جميع الصفحات
- [ ] اختبار تكامل API
- [ ] اختبار WebSocket
- [ ] اختبار Mobile responsiveness
- [ ] اختبار Dark mode
- [ ] مراجعة الكود
- [ ] توثيق المكونات الجديدة

---

## 📞 معلومات الاتصال

- **Backend API Base**: `http://localhost:8000/api/v1`
- **WebSocket**: `ws://localhost:8000/ws`
- **Docs**: `http://localhost:8000/docs`

---

*آخر تحديث: 2026-01-05*
