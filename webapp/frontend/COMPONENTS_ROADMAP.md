# RAGLOX v3.0 - خارطة طريق المكونات
## قائمة المكونات المطلوبة للواجهة الحقيقية

---

## 1. ملخص الحالة الحالية

### 1.1 المكونات الجاهزة (12 مكون)

| # | المكون | الملف | الحالة |
|---|--------|-------|--------|
| 1 | `DualPanelLayout` | `manus/DualPanelLayout.tsx` | ✅ جاهز |
| 2 | `AIChatPanel` | `manus/AIChatPanel.tsx` | ✅ جاهز |
| 3 | `TerminalPanel` | `manus/TerminalPanel.tsx` | ✅ جاهز |
| 4 | `Sidebar` | `manus/Sidebar.tsx` | ✅ جاهز |
| 5 | `ApprovalCard` | `manus/ApprovalCard.tsx` | ✅ جاهز |
| 6 | `AIPlanCard` | `manus/AIPlanCard.tsx` | ✅ جاهز |
| 7 | `EventCard` | `manus/EventCard.tsx` | ✅ جاهز |
| 8 | `PlanView` | `manus/PlanView.tsx` | ✅ جاهز |
| 9 | `CredentialCard` | `manus/ArtifactCard.tsx` | ✅ جاهز |
| 10 | `SessionCard` | `manus/ArtifactCard.tsx` | ✅ جاهز |
| 11 | `VulnerabilityCard` | `manus/ArtifactCard.tsx` | ✅ جاهز |
| 12 | `TargetCard` | `manus/ArtifactCard.tsx` | ✅ جاهز |

### 1.2 مكونات shadcn/ui المتوفرة (52 مكون)

جميع مكونات shadcn/ui الأساسية متوفرة ومُعدّلة للتصميم الداكن.

---

## 2. المكونات المطلوبة للواجهة الحقيقية

### 2.1 مكونات المهام (Missions)

#### `MissionCard`
```typescript
interface MissionCardProps {
  mission: Mission;
  onClick?: () => void;
  selected?: boolean;
}
```

**العناصر:**
- أيقونة الحالة (running, paused, completed)
- اسم المهمة
- الوصف (مختصر)
- شريط التقدم
- عدد الأهداف/الثغرات/الجلسات
- وقت البدء

**النمط:**
```css
.mission-card {
  background: #1f1f1f;
  border-radius: 12px;
  padding: 16px;
  box-shadow: var(--shadow-card);
}
```

---

#### `MissionList`
```typescript
interface MissionListProps {
  missions: Mission[];
  selectedId?: string;
  onSelect?: (mission: Mission) => void;
  loading?: boolean;
}
```

**العناصر:**
- قائمة MissionCard
- حالة التحميل (Skeleton)
- حالة الفراغ (Empty state)
- فلترة حسب الحالة

---

#### `MissionDetail`
```typescript
interface MissionDetailProps {
  mission: Mission;
  targets: Target[];
  vulnerabilities: Vulnerability[];
  credentials: Credential[];
  sessions: Session[];
}
```

**العناصر:**
- Header مع اسم المهمة والحالة
- Tabs: Overview, Targets, Vulnerabilities, Credentials, Sessions
- إحصائيات سريعة
- أزرار التحكم (Start, Pause, Stop)

---

### 2.2 مكونات الأهداف (Targets)

#### `TargetList`
```typescript
interface TargetListProps {
  targets: Target[];
  onSelect?: (target: Target) => void;
  selectedId?: string;
}
```

**العناصر:**
- جدول أو قائمة بطاقات
- أعمدة: IP, Hostname, OS, Status, Risk Score, Ports
- ترتيب وفلترة
- تلوين حسب Risk Score

---

#### `TargetDetail`
```typescript
interface TargetDetailProps {
  target: Target;
  vulnerabilities: Vulnerability[];
  credentials: Credential[];
  sessions: Session[];
}
```

---

### 2.3 مكونات الثغرات (Vulnerabilities)

#### `VulnerabilityList`
```typescript
interface VulnerabilityListProps {
  vulnerabilities: Vulnerability[];
  onSelect?: (vuln: Vulnerability) => void;
}
```

**العناصر:**
- جدول مع أعمدة: Name, Severity, CVSS, Target, Status
- شارات Severity ملونة (CRITICAL=أحمر, HIGH=برتقالي, MEDIUM=أصفر, LOW=أخضر)
- أيقونة Exploit Available

---

### 2.4 مكونات قاعدة المعرفة (Knowledge Base)

#### `TechniqueCard`
```typescript
interface TechniqueCardProps {
  technique: {
    technique_id: string;
    name: string;
    tactic: string;
    description: string;
    platforms: string[];
    module_count: number;
  };
  onClick?: () => void;
}
```

**العناصر:**
- MITRE ATT&CK ID
- اسم التقنية
- Tactic
- عدد الوحدات المتاحة
- المنصات المدعومة

---

#### `ModuleCard`
```typescript
interface ModuleCardProps {
  module: {
    module_id: string;
    name: string;
    type: string;
    platform: string;
    rank: string;
    description: string;
  };
  onClick?: () => void;
}
```

---

#### `KnowledgeSearch`
```typescript
interface KnowledgeSearchProps {
  onSearch: (query: string) => void;
  filters?: {
    platform?: string;
    tactic?: string;
    type?: string;
  };
}
```

---

### 2.5 مكونات الإحصائيات

#### `StatCard`
```typescript
interface StatCardProps {
  title: string;
  value: number | string;
  icon: LucideIcon;
  trend?: {
    value: number;
    direction: 'up' | 'down';
  };
  color?: 'default' | 'success' | 'warning' | 'critical';
}
```

---

#### `RiskMeter`
```typescript
interface RiskMeterProps {
  score: number; // 0-100
  label?: string;
  size?: 'sm' | 'md' | 'lg';
}
```

**النمط:**
- دائرة مع تدرج لوني (أخضر → أصفر → برتقالي → أحمر)
- الرقم في المنتصف
- Label تحت الدائرة

---

#### `MissionStats`
```typescript
interface MissionStatsProps {
  statistics: MissionStatistics;
}
```

**العناصر:**
- 4 StatCards في صف واحد
- Targets Discovered
- Vulnerabilities Found
- Credentials Harvested
- Sessions Established

---

### 2.6 مكونات الوقت الحقيقي

#### `LiveIndicator`
```typescript
interface LiveIndicatorProps {
  isLive: boolean;
  label?: string;
}
```

**النمط:**
```css
.live-indicator {
  display: flex;
  align-items: center;
  gap: 6px;
}

.live-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #4ade80;
  animation: pulse 2s ease-in-out infinite;
}
```

---

#### `ActivityFeed`
```typescript
interface ActivityFeedProps {
  events: WebSocketMessage[];
  maxItems?: number;
}
```

---

### 2.7 مكونات التنقل

#### `Breadcrumb`
```typescript
interface BreadcrumbProps {
  items: {
    label: string;
    href?: string;
  }[];
}
```

---

#### `PageHeader`
```typescript
interface PageHeaderProps {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  breadcrumb?: BreadcrumbProps['items'];
}
```

---

## 3. الصفحات المطلوبة

### 3.1 صفحة المهام `/missions`

**المكونات المستخدمة:**
- `PageHeader`
- `MissionList`
- `Button` (إنشاء مهمة جديدة)
- `Select` (فلترة الحالة)

**API Endpoints:**
- `GET /api/v1/missions`
- `POST /api/v1/missions`

---

### 3.2 صفحة تفاصيل المهمة `/missions/:id`

**المكونات المستخدمة:**
- `DualPanelLayout` (الموجود)
- `AIChatPanel` (الموجود)
- `TerminalPanel` (الموجود)

**API Endpoints:**
- `GET /api/v1/missions/{mission_id}`
- `GET /api/v1/missions/{mission_id}/targets`
- `GET /api/v1/missions/{mission_id}/vulnerabilities`
- `GET /api/v1/missions/{mission_id}/credentials`
- `GET /api/v1/missions/{mission_id}/sessions`
- `WebSocket: ws://172.245.232.188:8000/ws/{mission_id}`

---

### 3.3 صفحة قاعدة المعرفة `/knowledge`

**المكونات المستخدمة:**
- `PageHeader`
- `KnowledgeSearch`
- `Tabs` (Techniques, Modules, Tactics)
- `TechniqueCard` / `ModuleCard`

**API Endpoints:**
- `GET /api/v1/knowledge/stats`
- `GET /api/v1/knowledge/techniques`
- `GET /api/v1/knowledge/modules`
- `GET /api/v1/knowledge/tactics`
- `POST /api/v1/knowledge/search`

---

## 4. Hooks المطلوبة

### 4.1 `useMission`
```typescript
function useMission(missionId: string) {
  return {
    mission: Mission | null,
    targets: Target[],
    vulnerabilities: Vulnerability[],
    credentials: Credential[],
    sessions: Session[],
    isLoading: boolean,
    error: Error | null,
    refetch: () => void
  };
}
```

### 4.2 `useWebSocket`
```typescript
function useWebSocket(missionId: string) {
  return {
    isConnected: boolean,
    events: WebSocketMessage[],
    send: (message: any) => void,
    disconnect: () => void
  };
}
```

### 4.3 `useKnowledge`
```typescript
function useKnowledge() {
  return {
    techniques: Technique[],
    modules: Module[],
    tactics: Tactic[],
    search: (query: string) => Promise<SearchResult[]>,
    isLoading: boolean
  };
}
```

---

## 5. أولويات التنفيذ

### المرحلة 1: الأساسيات (الأسبوع الأول)

| # | المهمة | الأولوية |
|---|--------|----------|
| 1 | ربط WebSocket الحقيقي | 🔴 عالية |
| 2 | إنشاء `useMission` hook | 🔴 عالية |
| 3 | إنشاء `useWebSocket` hook | 🔴 عالية |
| 4 | تحديث `AIChatPanel` للبيانات الحقيقية | 🔴 عالية |
| 5 | تحديث `TerminalPanel` للبيانات الحقيقية | 🔴 عالية |

### المرحلة 2: صفحة المهام (الأسبوع الثاني)

| # | المهمة | الأولوية |
|---|--------|----------|
| 1 | إنشاء `MissionCard` | 🟠 متوسطة |
| 2 | إنشاء `MissionList` | 🟠 متوسطة |
| 3 | إنشاء صفحة `/missions` | 🟠 متوسطة |
| 4 | إنشاء `StatCard` | 🟠 متوسطة |
| 5 | إنشاء `MissionStats` | 🟠 متوسطة |

### المرحلة 3: قاعدة المعرفة (الأسبوع الثالث)

| # | المهمة | الأولوية |
|---|--------|----------|
| 1 | إنشاء `TechniqueCard` | 🟡 منخفضة |
| 2 | إنشاء `ModuleCard` | 🟡 منخفضة |
| 3 | إنشاء `KnowledgeSearch` | 🟡 منخفضة |
| 4 | إنشاء صفحة `/knowledge` | 🟡 منخفضة |
| 5 | إنشاء `useKnowledge` hook | 🟡 منخفضة |

---

## 6. ملاحظات التنفيذ

### 6.1 اتساق التصميم

جميع المكونات الجديدة يجب أن تتبع:

1. **الألوان:** استخدام CSS variables من `index.css`
2. **الزوايا:** `border-radius: 12px` للبطاقات
3. **الظلال:** `box-shadow: var(--shadow-card)`
4. **المسافات:** `padding: 16px`, `gap: 24px`
5. **الانتقالات:** `transition: all 200ms ease-out`

### 6.2 التعامل مع الأخطاء

كل مكون يجب أن يتعامل مع:
- حالة التحميل (Loading)
- حالة الخطأ (Error)
- حالة الفراغ (Empty)

### 6.3 الـ Accessibility

- استخدام `aria-label` للأزرار
- دعم لوحة المفاتيح
- تباين ألوان كافٍ

---

**تاريخ الإنشاء:** 2 يناير 2026  
**المؤلف:** Manus AI  
**الإصدار:** 1.0
