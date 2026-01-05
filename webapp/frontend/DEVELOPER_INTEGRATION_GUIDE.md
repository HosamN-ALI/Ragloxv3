# RAGLOX v3.0 - دليل المطور لدمج الـ Backend

## مقدمة

هذا الدليل موجه للمطور المسؤول عن دمج الـ Backend API مع واجهة RAGLOX v3.0. الواجهة الحالية هي **واجهة عرض (Mock UI)** تعمل ببيانات تجريبية ثابتة، وتحتاج إلى ربطها بالـ Backend الحقيقي لتصبح وظيفية بالكامل.

---

## الفهم الأساسي

### ما هي الواجهة الحالية؟

الواجهة الحالية هي **نموذج عرض (Mockup)** يُظهر التصميم النهائي المطلوب بأسلوب Manus AI. جميع البيانات المعروضة حالياً هي **بيانات تجريبية ثابتة (Hardcoded Mock Data)** موجودة داخل الكود.

### ما المطلوب؟

تحويل الواجهة من نموذج عرض إلى تطبيق وظيفي يتصل بـ:
1. **REST API** على `http://172.245.232.188:8000`
2. **WebSocket** على `ws://172.245.232.188:8000/ws/{mission_id}`

---

## هيكل المشروع

```
frontend/
├── client/
│   └── src/
│       ├── components/
│       │   ├── manus/           # المكونات المخصصة لـ RAGLOX
│       │   │   ├── AIChatPanel.tsx      # لوحة الدردشة الرئيسية
│       │   │   ├── TerminalPanel.tsx    # لوحة الطرفية
│       │   │   ├── DualPanelLayout.tsx  # التخطيط الرئيسي
│       │   │   ├── Sidebar.tsx          # الشريط الجانبي
│       │   │   ├── ApprovalCard.tsx     # بطاقة الموافقة
│       │   │   ├── AIPlanCard.tsx       # بطاقة الخطة
│       │   │   ├── ArtifactCard.tsx     # بطاقات الـ Artifacts
│       │   │   ├── EventCard.tsx        # بطاقة الحدث
│       │   │   └── PlanView.tsx         # عرض الخطة
│       │   └── ui/              # مكونات shadcn/ui
│       ├── hooks/
│       │   └── useMissionData.ts        # Hook للبيانات (يحتاج تحديث)
│       ├── lib/
│       │   └── api.ts                   # دوال الـ API (يحتاج تحديث)
│       ├── types/
│       │   └── index.ts                 # تعريفات الأنواع
│       ├── stores/
│       │   └── missionStore.ts          # Zustand store
│       └── pages/
│           ├── Home.tsx                 # الصفحة الرئيسية
│           └── Operations.tsx           # صفحة العمليات
├── DESIGN_SYSTEM.md             # نظام التصميم
├── COMPONENTS_ROADMAP.md        # خارطة طريق المكونات
└── API_DOCUMENTATION.md         # توثيق الـ API
```

---

## الملفات التي تحتاج تعديل

### 1. `client/src/lib/api.ts` - ملف الـ API

هذا الملف يحتوي على دوال الاتصال بالـ API. حالياً يستخدم بيانات تجريبية عند فشل الاتصال.

```typescript
// الموقع: client/src/lib/api.ts

// عنوان الـ API الحالي
const API_BASE_URL = 'http://172.245.232.188:8000';

// ما يجب تعديله:
// 1. إزالة البيانات التجريبية (MOCK_MISSIONS, MOCK_EVENTS, etc.)
// 2. التأكد من أن جميع الدوال تتصل بالـ API الحقيقي
// 3. إضافة معالجة الأخطاء المناسبة
```

**الدوال الموجودة:**

| الدالة | الوصف | الحالة |
|--------|-------|--------|
| `missionsApi.list()` | جلب قائمة المهام | يستخدم mock data |
| `missionsApi.get(id)` | جلب تفاصيل مهمة | يستخدم mock data |
| `missionsApi.create(data)` | إنشاء مهمة جديدة | غير مُنفذ |
| `missionsApi.start(id)` | بدء مهمة | غير مُنفذ |
| `missionsApi.stop(id)` | إيقاف مهمة | غير مُنفذ |
| `MissionWebSocket` | اتصال WebSocket | معطل حالياً |

---

### 2. `client/src/components/manus/AIChatPanel.tsx` - لوحة الدردشة

هذا المكون يعرض الأحداث والرسائل. حالياً يستخدم بيانات تجريبية ثابتة.

```typescript
// الموقع: client/src/components/manus/AIChatPanel.tsx

// البيانات التجريبية الحالية (يجب استبدالها):
const mockEvents = [
  {
    id: '1',
    type: 'step',
    title: 'تنفيذ الأمر الأول - عرض معلومات النظام',
    // ...
  },
  // ...
];

// ما يجب تعديله:
// 1. استبدال mockEvents بالبيانات من WebSocket
// 2. ربط الأحداث الجديدة بالـ state
// 3. تحديث الأحداث في الوقت الحقيقي
```

**الأحداث المدعومة:**

| نوع الحدث | الوصف | المكون |
|-----------|-------|--------|
| `step` | خطوة في الخطة | `EventItem` |
| `knowledge` | معرفة مسترجعة | شارة `Knowledge recalled` |
| `command` | أمر طرفية | شارة `Executing command` |
| `credential` | بيانات اعتماد | `CredentialCard` |
| `session` | جلسة SSH | `SessionCard` |
| `vulnerability` | ثغرة أمنية | `VulnerabilityCard` |
| `approval` | طلب موافقة | `ApprovalCard` |
| `plan` | خطة AI | `AIPlanCard` |

---

### 3. `client/src/components/manus/TerminalPanel.tsx` - لوحة الطرفية

هذا المكون يعرض مخرجات الطرفية. حالياً يستخدم بيانات ثابتة.

```typescript
// الموقع: client/src/components/manus/TerminalPanel.tsx

// البيانات التجريبية الحالية:
const mockTerminalOutput = `ubuntu@sandbox:~ $ df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/root        42G  9.8G   32G  24% /
...`;

// ما يجب تعديله:
// 1. استبدال mockTerminalOutput بالبيانات من WebSocket
// 2. إضافة تحديث تلقائي عند وصول مخرجات جديدة
// 3. دعم التمرير التلقائي للأسفل
```

---

### 4. `client/src/hooks/useMissionData.ts` - Hook البيانات

هذا الـ Hook مسؤول عن جلب بيانات المهمة.

```typescript
// الموقع: client/src/hooks/useMissionData.ts

// ما يجب تعديله:
// 1. ربط الـ Hook بالـ API الحقيقي
// 2. إضافة WebSocket listener
// 3. تحديث الـ state عند وصول بيانات جديدة
```

---

## خطوات الدمج

### الخطوة 1: ربط WebSocket

هذه هي الخطوة الأهم. يجب ربط WebSocket لاستقبال الأحداث في الوقت الحقيقي.

```typescript
// مثال على ربط WebSocket

import { useEffect, useState, useCallback } from 'react';

interface WebSocketMessage {
  type: 'event' | 'terminal' | 'status' | 'approval';
  data: any;
  timestamp: string;
}

export function useWebSocket(missionId: string) {
  const [isConnected, setIsConnected] = useState(false);
  const [events, setEvents] = useState<WebSocketMessage[]>([]);
  const [terminalOutput, setTerminalOutput] = useState<string>('');
  
  useEffect(() => {
    if (!missionId) return;
    
    const ws = new WebSocket(`ws://172.245.232.188:8000/ws/${missionId}`);
    
    ws.onopen = () => {
      console.log('[WebSocket] Connected');
      setIsConnected(true);
    };
    
    ws.onmessage = (event) => {
      const message: WebSocketMessage = JSON.parse(event.data);
      
      switch (message.type) {
        case 'event':
          setEvents(prev => [...prev, message]);
          break;
        case 'terminal':
          setTerminalOutput(prev => prev + message.data.output);
          break;
        case 'approval':
          // إضافة طلب موافقة جديد
          break;
        case 'status':
          // تحديث حالة المهمة
          break;
      }
    };
    
    ws.onclose = () => {
      console.log('[WebSocket] Disconnected');
      setIsConnected(false);
    };
    
    ws.onerror = (error) => {
      console.error('[WebSocket] Error:', error);
    };
    
    return () => ws.close();
  }, [missionId]);
  
  return { isConnected, events, terminalOutput };
}
```

---

### الخطوة 2: تحديث AIChatPanel

```typescript
// في AIChatPanel.tsx

import { useWebSocket } from '@/hooks/useWebSocket';

export function AIChatPanel({ missionId }: { missionId: string }) {
  const { isConnected, events, terminalOutput } = useWebSocket(missionId);
  
  // استبدال mockEvents بـ events من WebSocket
  // ...
}
```

---

### الخطوة 3: تحديث TerminalPanel

```typescript
// في TerminalPanel.tsx

interface TerminalPanelProps {
  output: string;  // من WebSocket
  isLive: boolean;
  command?: string;
  onClose: () => void;
}

export function TerminalPanel({ output, isLive, command, onClose }: TerminalPanelProps) {
  // استخدام output بدلاً من mockTerminalOutput
  // ...
}
```

---

### الخطوة 4: ربط الموافقات

```typescript
// دالة الموافقة على إجراء
async function approveAction(missionId: string, actionId: string) {
  const response = await fetch(
    `http://172.245.232.188:8000/api/v1/missions/${missionId}/approve/${actionId}`,
    { method: 'POST' }
  );
  return response.json();
}

// دالة رفض إجراء
async function rejectAction(missionId: string, actionId: string, reason: string) {
  const response = await fetch(
    `http://172.245.232.188:8000/api/v1/missions/${missionId}/reject/${actionId}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason })
    }
  );
  return response.json();
}
```

---

### الخطوة 5: ربط الدردشة

```typescript
// إرسال رسالة للـ AI
async function sendChatMessage(missionId: string, message: string) {
  const response = await fetch(
    `http://172.245.232.188:8000/api/v1/missions/${missionId}/chat`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    }
  );
  return response.json();
}

// جلب سجل الدردشة
async function getChatHistory(missionId: string) {
  const response = await fetch(
    `http://172.245.232.188:8000/api/v1/missions/${missionId}/chat`
  );
  return response.json();
}
```

---

## API Endpoints المطلوبة

### Missions API

| Method | Endpoint | الوصف |
|--------|----------|-------|
| `GET` | `/api/v1/missions` | قائمة المهام |
| `POST` | `/api/v1/missions` | إنشاء مهمة |
| `GET` | `/api/v1/missions/{id}` | تفاصيل مهمة |
| `POST` | `/api/v1/missions/{id}/start` | بدء مهمة |
| `POST` | `/api/v1/missions/{id}/pause` | إيقاف مؤقت |
| `POST` | `/api/v1/missions/{id}/resume` | استئناف |
| `POST` | `/api/v1/missions/{id}/stop` | إيقاف |
| `GET` | `/api/v1/missions/{id}/targets` | الأهداف |
| `GET` | `/api/v1/missions/{id}/vulnerabilities` | الثغرات |
| `GET` | `/api/v1/missions/{id}/credentials` | بيانات الاعتماد |
| `GET` | `/api/v1/missions/{id}/sessions` | الجلسات |
| `GET` | `/api/v1/missions/{id}/stats` | الإحصائيات |
| `GET` | `/api/v1/missions/{id}/approvals` | طلبات الموافقة |
| `POST` | `/api/v1/missions/{id}/approve/{action_id}` | موافقة |
| `POST` | `/api/v1/missions/{id}/reject/{action_id}` | رفض |
| `POST` | `/api/v1/missions/{id}/chat` | إرسال رسالة |
| `GET` | `/api/v1/missions/{id}/chat` | سجل الدردشة |

### WebSocket

| Endpoint | الوصف |
|----------|-------|
| `ws://172.245.232.188:8000/ws/{mission_id}` | تحديثات الوقت الحقيقي |

---

## أنواع البيانات (Types)

```typescript
// client/src/types/index.ts

interface Mission {
  id: string;
  name: string;
  description: string;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed';
  created_at: string;
  started_at?: string;
  completed_at?: string;
  target_count: number;
  vulnerability_count: number;
  credential_count: number;
  session_count: number;
}

interface Target {
  id: string;
  ip: string;
  hostname?: string;
  os?: string;
  status: 'discovered' | 'scanning' | 'exploiting' | 'compromised';
  risk_score: number;
  ports: Port[];
}

interface Vulnerability {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score?: number;
  cve_id?: string;
  target_id: string;
  description: string;
  exploit_available: boolean;
}

interface Credential {
  id: string;
  username: string;
  password?: string;
  hash?: string;
  service: string;
  target_id: string;
  source: string;
}

interface Session {
  id: string;
  type: 'ssh' | 'meterpreter' | 'shell';
  target_id: string;
  username: string;
  status: 'active' | 'closed';
  created_at: string;
}

interface ApprovalRequest {
  id: string;
  action_type: string;
  description: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  target?: string;
  command?: string;
  timeout_seconds: number;
  created_at: string;
}

interface WebSocketMessage {
  type: 'event' | 'terminal' | 'status' | 'approval' | 'chat';
  data: any;
  timestamp: string;
  mission_id: string;
}
```

---

## ملاحظات مهمة

### 1. البيانات التجريبية

جميع البيانات التجريبية موجودة في:
- `client/src/lib/api.ts` - `MOCK_MISSIONS`, `MOCK_EVENTS`
- `client/src/components/manus/AIChatPanel.tsx` - `mockEvents`
- `client/src/components/manus/TerminalPanel.tsx` - `mockTerminalOutput`

**يجب إزالة أو استبدال هذه البيانات بالبيانات الحقيقية من الـ API.**

### 2. معالجة الأخطاء

يجب إضافة معالجة مناسبة للأخطاء:
- فشل الاتصال بالـ API
- انقطاع WebSocket
- timeout للطلبات
- أخطاء الخادم (500)

### 3. حالات التحميل

يجب إضافة حالات تحميل (Loading states) لجميع الطلبات:
- Skeleton loaders للبطاقات
- Spinner للأزرار
- رسائل خطأ واضحة

### 4. التصميم

**لا تغير التصميم!** التصميم الحالي مبني على أسلوب Manus AI ومُعتمد. أي تغييرات يجب أن تكون وظيفية فقط.

---

## اختبار الدمج

### 1. اختبار الـ API

```bash
# اختبار جلب المهام
curl http://172.245.232.188:8000/api/v1/missions

# اختبار جلب تفاصيل مهمة
curl http://172.245.232.188:8000/api/v1/missions/6b14028c-7f30-4ce6-aad2-20f17eee39d0
```

### 2. اختبار WebSocket

```javascript
// في console المتصفح
const ws = new WebSocket('ws://172.245.232.188:8000/ws/6b14028c-7f30-4ce6-aad2-20f17eee39d0');
ws.onmessage = (e) => console.log(JSON.parse(e.data));
```

### 3. Mission ID للاختبار

```
6b14028c-7f30-4ce6-aad2-20f17eee39d0
```

---

## الأولويات

| الأولوية | المهمة | الملف |
|----------|--------|-------|
| 🔴 1 | ربط WebSocket | `hooks/useWebSocket.ts` (جديد) |
| 🔴 2 | تحديث AIChatPanel | `components/manus/AIChatPanel.tsx` |
| 🔴 3 | تحديث TerminalPanel | `components/manus/TerminalPanel.tsx` |
| 🟠 4 | ربط الموافقات | `components/manus/ApprovalCard.tsx` |
| 🟠 5 | ربط الدردشة | `components/manus/AIChatPanel.tsx` |
| 🟡 6 | صفحة المهام | `pages/Missions.tsx` (جديد) |

---

## الدعم

للأسئلة أو المشاكل:
1. راجع `API_DOCUMENTATION.md` لتوثيق الـ API
2. راجع `DESIGN_SYSTEM.md` لنظام التصميم
3. راجع `COMPONENTS_ROADMAP.md` لخارطة طريق المكونات

---

**تاريخ الإنشاء:** 2 يناير 2026  
**المؤلف:** Manus AI  
**الإصدار:** 1.0
