# RAGLOX v3.0 - Redis Key Schema

## Blackboard Architecture - مخطط المفاتيح

### 1. Mission State (حالة المهمة)

```
mission:{mission_id}:info           # Hash - معلومات المهمة
  ├── id: "uuid"
  ├── name: "Pentest Company X"
  ├── status: "running|paused|completed|failed"
  ├── created_at: "2026-01-01T10:00:00Z"
  ├── started_at: "2026-01-01T10:05:00Z"
  ├── scope: '["192.168.1.0/24"]'
  └── goals: '["domain_admin", "data_exfil"]'

mission:{mission_id}:goals          # Hash - حالة الأهداف
  ├── domain_admin: "pending|in_progress|achieved|failed"
  ├── data_exfil: "pending|in_progress|achieved|failed"
  └── persistence: "pending|in_progress|achieved|failed"

mission:{mission_id}:stats          # Hash - الإحصائيات
  ├── targets_discovered: 10
  ├── vulns_found: 5
  ├── creds_harvested: 3
  ├── sessions_established: 2
  └── goals_achieved: 1
```

### 2. Targets (الأهداف)

```
mission:{mission_id}:targets        # Set - قائمة معرفات الأهداف
  └── ["target:uuid1", "target:uuid2", ...]

target:{target_id}                  # Hash - تفاصيل الهدف
  ├── id: "uuid"
  ├── mission_id: "uuid"
  ├── ip: "192.168.1.10"
  ├── hostname: "DC01"
  ├── os: "Windows Server 2019"
  ├── status: "discovered|scanning|exploited|owned"
  ├── discovered_at: "2026-01-01T10:10:00Z"
  ├── discovered_by: "recon_specialist"
  ├── priority: "critical|high|medium|low"
  └── risk_score: 8.5

target:{target_id}:ports            # Hash - المنافذ المفتوحة
  ├── 22: "ssh|OpenSSH 8.0"
  ├── 80: "http|Apache 2.4"
  ├── 443: "https|nginx 1.18"
  └── 3389: "rdp|Microsoft RDP"

target:{target_id}:services         # List - الخدمات المكتشفة
  └── [{"port": 80, "service": "http", "product": "Apache", "version": "2.4"}, ...]
```

### 3. Vulnerabilities (الثغرات)

```
mission:{mission_id}:vulns          # Sorted Set - الثغرات مرتبة بالخطورة
  └── [(vuln_id, cvss_score), ...]

vuln:{vuln_id}                      # Hash - تفاصيل الثغرة
  ├── id: "uuid"
  ├── mission_id: "uuid"
  ├── target_id: "uuid"
  ├── type: "CVE-2021-44228|MS17-010|weak_password"
  ├── severity: "critical|high|medium|low"
  ├── cvss: 9.8
  ├── description: "Log4j RCE vulnerability"
  ├── discovered_at: "2026-01-01T10:15:00Z"
  ├── discovered_by: "recon_specialist"
  ├── status: "discovered|verified|exploited|failed"
  ├── exploit_available: "true|false"
  └── rx_modules: '["rx-t1190-001", "rx-t1190-002"]'
```

### 4. Credentials (الاعتمادات)

```
mission:{mission_id}:creds          # Set - قائمة معرفات الاعتمادات
  └── ["cred:uuid1", "cred:uuid2", ...]

cred:{cred_id}                      # Hash - تفاصيل الاعتماد
  ├── id: "uuid"
  ├── mission_id: "uuid"
  ├── target_id: "uuid"
  ├── type: "password|hash|key|token"
  ├── username: "admin"
  ├── domain: "CORP"
  ├── value: "encrypted_value"
  ├── source: "mimikatz|brute_force|config_file"
  ├── discovered_at: "2026-01-01T10:20:00Z"
  ├── discovered_by: "attack_specialist"
  ├── verified: "true|false"
  └── privilege_level: "user|admin|domain_admin"
```

### 5. Sessions (الجلسات)

```
mission:{mission_id}:sessions       # Set - الجلسات النشطة
  └── ["session:uuid1", "session:uuid2", ...]

session:{session_id}                # Hash - تفاصيل الجلسة
  ├── id: "uuid"
  ├── mission_id: "uuid"
  ├── target_id: "uuid"
  ├── type: "shell|meterpreter|ssh|rdp"
  ├── user: "CORP\\admin"
  ├── privilege: "user|admin|system"
  ├── established_at: "2026-01-01T10:25:00Z"
  ├── last_activity: "2026-01-01T10:30:00Z"
  ├── status: "active|idle|dead"
  └── via_cred_id: "uuid"
```

### 6. Attack Paths (مسارات الهجوم)

```
mission:{mission_id}:paths          # List - مسارات الهجوم المكتشفة
  └── ["path:uuid1", "path:uuid2", ...]

path:{path_id}                      # Hash - تفاصيل المسار
  ├── id: "uuid"
  ├── mission_id: "uuid"
  ├── from_target: "uuid"
  ├── to_target: "uuid"
  ├── method: "pass_the_hash|rdp|ssh|smb"
  ├── requires_cred: "uuid"
  ├── discovered_at: "2026-01-01T10:30:00Z"
  └── status: "discovered|tested|working|failed"
```

### 7. Tasks (المهام)

```
mission:{mission_id}:tasks:pending    # Sorted Set - المهام المعلقة (بالأولوية)
mission:{mission_id}:tasks:running    # Set - المهام الجارية
mission:{mission_id}:tasks:completed  # List - المهام المكتملة

task:{task_id}                        # Hash - تفاصيل المهمة
  ├── id: "uuid"
  ├── mission_id: "uuid"
  ├── type: "scan|exploit|enum|persist|cleanup"
  ├── target_id: "uuid"
  ├── specialist: "recon|attack|analysis|persistence|evasion|cleanup"
  ├── rx_module: "rx-t1046-001"
  ├── priority: 1-10
  ├── status: "pending|running|completed|failed"
  ├── created_at: "2026-01-01T10:35:00Z"
  ├── started_at: "2026-01-01T10:36:00Z"
  ├── completed_at: "2026-01-01T10:40:00Z"
  ├── assigned_to: "worker_id"
  └── result: "success|failure|partial"
```

### 8. Results & Logs (سجل النتائج)

```
mission:{mission_id}:results        # Stream - سجل النتائج (للتتبع الزمني)
  └── [{"timestamp": "...", "type": "...", "data": {...}}, ...]

mission:{mission_id}:errors         # Stream - سجل الأخطاء
mission:{mission_id}:heartbeats     # Hash - نبضات المتخصصين
```

---

## Pub/Sub Channels (قنوات الإشعارات)

```
channel:mission:{mission_id}:targets    # إشعار باكتشاف هدف جديد
  └── {"event": "new_target", "target_id": "uuid", "priority": "high"}

channel:mission:{mission_id}:vulns      # إشعار باكتشاف ثغرة جديدة
  └── {"event": "new_vuln", "vuln_id": "uuid", "severity": "critical"}

channel:mission:{mission_id}:creds      # إشعار باكتشاف اعتماد جديد
  └── {"event": "new_cred", "cred_id": "uuid", "type": "domain_admin"}

channel:mission:{mission_id}:sessions   # إشعار بجلسة جديدة
  └── {"event": "new_session", "session_id": "uuid", "privilege": "admin"}

channel:mission:{mission_id}:tasks      # إشعار بمهمة جديدة
  └── {"event": "new_task", "task_id": "uuid", "specialist": "attack"}

channel:mission:{mission_id}:goals      # إشعار بتحقيق هدف
  └── {"event": "goal_achieved", "goal": "domain_admin"}

channel:mission:{mission_id}:control    # أوامر التحكم
  └── {"command": "pause|resume|stop"}
```

---

## TTL (Time To Live)

| نوع البيانات | TTL |
|-------------|-----|
| المهمات النشطة | لا انتهاء |
| المهمات المكتملة | 7 أيام ثم تُنقل لـ PostgreSQL |
| التخزين المؤقت | 1 ساعة |
| الجلسات الميتة | 24 ساعة |
