# 🔍 RAGLOX v3.0 - دليل الفحص الشامل للمسؤول (QA Testing Guide)

## 📋 معلومات المشروع

| البند | القيمة |
|-------|--------|
| **اسم المشروع** | RAGLOX v3.0 |
| **الوصف** | منصة أتمتة الفرق الحمراء باستخدام هندسة Blackboard |
| **إجمالي نقاط النهاية** | 141 API Endpoint |
| **التقنيات** | FastAPI, Redis, PostgreSQL, Stripe, WebSocket |
| **Repository** | https://github.com/HosamN-ALI/Ragloxv3 |

---

## 🚀 متطلبات التشغيل

### المتطلبات الأساسية
```bash
# 1. تثبيت Dependencies
pip install -r requirements.txt
# أو
pip install -e .

# 2. إعداد متغيرات البيئة
cp .env.example .env
# تعديل القيم حسب البيئة

# 3. تشغيل الخدمات المطلوبة
# - Redis (مطلوب للـ Blackboard)
# - PostgreSQL (مطلوب للمصادقة والبيانات)

# 4. تشغيل الخادم
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### متغيرات البيئة الأساسية
```env
# Database
DATABASE_URL=postgresql://raglox:password@localhost:5432/raglox

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET=your_secure_secret_min_32_chars

# Stripe (للفوترة)
STRIPE_ENABLED=true
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

---

## 📡 نقاط النهاية للفحص (141 Endpoint)

### 🏠 Root & Health
```
GET  /                 - الصفحة الرئيسية
GET  /health           - حالة صحة النظام
```

### 🔐 Authentication (13 endpoints)
```
POST /api/v1/auth/register                    - تسجيل مستخدم جديد
POST /api/v1/auth/login                       - تسجيل الدخول
POST /api/v1/auth/logout                      - تسجيل الخروج
POST /api/v1/auth/change-password             - تغيير كلمة المرور
GET  /api/v1/auth/me                          - معلومات المستخدم الحالي
PUT  /api/v1/auth/me                          - تحديث معلومات المستخدم
GET  /api/v1/auth/organization                - معلومات المؤسسة
POST /api/v1/auth/organization/invite         - دعوة عضو للمؤسسة
GET  /api/v1/auth/vm/status                   - حالة VM
POST /api/v1/auth/vm/reprovision              - إعادة توفير VM
GET  /api/v1/auth/admin/users                 - قائمة المستخدمين (Admin)
PUT  /api/v1/auth/admin/users/{id}/role       - تغيير دور المستخدم
PUT  /api/v1/auth/admin/users/{id}/status     - تغيير حالة المستخدم
```

### 💳 Billing (12 endpoints)
```
GET  /api/v1/billing/plans                    - قائمة الخطط
GET  /api/v1/billing/plans/{plan_id}          - تفاصيل خطة
GET  /api/v1/billing/subscription             - الاشتراك الحالي
POST /api/v1/billing/subscribe                - إنشاء اشتراك
POST /api/v1/billing/cancel                   - إلغاء الاشتراك
POST /api/v1/billing/reactivate               - إعادة تفعيل الاشتراك
GET  /api/v1/billing/invoices                 - قائمة الفواتير
GET  /api/v1/billing/invoices/upcoming        - الفاتورة القادمة
POST /api/v1/billing/checkout                 - جلسة Checkout
POST /api/v1/billing/portal                   - بوابة الفوترة
POST /api/v1/billing/webhook                  - Stripe Webhook
GET  /api/v1/billing/usage                    - استخدام المؤسسة
```

### 🎯 Missions (22 endpoints)
```
POST /api/v1/missions                         - إنشاء مهمة
GET  /api/v1/missions                         - قائمة المهام
GET  /api/v1/missions/{id}                    - تفاصيل مهمة
POST /api/v1/missions/{id}/start              - بدء مهمة
POST /api/v1/missions/{id}/pause              - إيقاف مؤقت
POST /api/v1/missions/{id}/resume             - استئناف
POST /api/v1/missions/{id}/stop               - إيقاف نهائي
GET  /api/v1/missions/{id}/targets            - أهداف المهمة
GET  /api/v1/missions/{id}/targets/{tid}      - تفاصيل هدف
GET  /api/v1/missions/{id}/vulnerabilities    - الثغرات المكتشفة
GET  /api/v1/missions/{id}/credentials        - بيانات الاعتماد
GET  /api/v1/missions/{id}/sessions           - الجلسات النشطة
GET  /api/v1/missions/{id}/stats              - إحصائيات المهمة
GET  /api/v1/missions/{id}/approvals          - الموافقات المعلقة (HITL)
POST /api/v1/missions/{id}/approve/{aid}      - الموافقة على إجراء
POST /api/v1/missions/{id}/reject/{aid}       - رفض إجراء
GET  /api/v1/missions/{id}/chat               - سجل المحادثة
POST /api/v1/missions/{id}/chat               - إرسال رسالة
GET  /api/v1/stats/system                     - إحصائيات النظام
GET  /api/v1/stats/sessions                   - إحصائيات الجلسات
GET  /api/v1/stats/retry-policies             - سياسات إعادة المحاولة
GET  /api/v1/stats/circuit-breakers           - حالة Circuit Breakers
```

### 💣 Exploitation (24 endpoints)
```
GET  /api/v1/exploitation/health              - صحة نظام الاستغلال
GET  /api/v1/exploitation/status/metasploit   - حالة Metasploit
GET  /api/v1/exploitation/status/exploitation - حالة الاستغلال
GET  /api/v1/exploitation/exploits            - قائمة الاستغلالات
GET  /api/v1/exploitation/exploits/{id}       - تفاصيل استغلال
GET  /api/v1/exploitation/exploits/cve/{cve}  - استغلال بـ CVE
GET  /api/v1/exploitation/exploits/stats      - إحصائيات
POST /api/v1/exploitation/exploits/log4shell/scan     - فحص Log4Shell
POST /api/v1/exploitation/exploits/log4shell/execute  - تنفيذ Log4Shell
POST /api/v1/exploitation/exploits/eternalblue/check  - فحص EternalBlue
POST /api/v1/exploitation/exploits/eternalblue/execute - تنفيذ EternalBlue
GET  /api/v1/exploitation/metasploit/modules  - وحدات Metasploit
POST /api/v1/exploitation/metasploit/execute  - تنفيذ وحدة
GET  /api/v1/exploitation/payloads/types      - أنواع Payloads
POST /api/v1/exploitation/payloads/generate   - توليد Payload
GET  /api/v1/exploitation/c2/sessions         - جلسات C2
GET  /api/v1/exploitation/c2/sessions/{id}    - تفاصيل جلسة
POST /api/v1/exploitation/c2/sessions/{id}/execute - تنفيذ أمر
POST /api/v1/exploitation/c2/sessions/{id}/proxy   - SOCKS Proxy
DELETE /api/v1/exploitation/c2/sessions/{id}  - إنهاء جلسة
POST /api/v1/exploitation/post-exploitation/harvest - جمع بيانات اعتماد
GET  /api/v1/exploitation/pivoting/routes     - مسارات الشبكة
POST /api/v1/exploitation/pivoting/port-forward - Port Forwarding
DELETE /api/v1/exploitation/cache/clear       - مسح Cache
```

### 📚 Knowledge Base (26 endpoints)
```
GET  /api/v1/knowledge/stats                  - إحصائيات قاعدة المعرفة
GET  /api/v1/knowledge/modules                - جميع الوحدات
GET  /api/v1/knowledge/modules/{id}           - تفاصيل وحدة
GET  /api/v1/knowledge/search                 - بحث
POST /api/v1/knowledge/search                 - بحث متقدم
POST /api/v1/knowledge/best-module            - أفضل وحدة
GET  /api/v1/knowledge/tactics                - التكتيكات
GET  /api/v1/knowledge/tactics/{id}/techniques - تقنيات التكتيك
GET  /api/v1/knowledge/techniques             - جميع التقنيات
GET  /api/v1/knowledge/techniques/{id}        - تفاصيل تقنية
GET  /api/v1/knowledge/techniques/{id}/modules - وحدات التقنية
GET  /api/v1/knowledge/platforms              - المنصات
GET  /api/v1/knowledge/platforms/{p}/modules  - وحدات المنصة
GET  /api/v1/knowledge/recon-modules          - وحدات الاستطلاع
GET  /api/v1/knowledge/exploit-modules        - وحدات الاستغلال
GET  /api/v1/knowledge/credential-modules     - وحدات بيانات الاعتماد
GET  /api/v1/knowledge/privesc-modules        - وحدات رفع الصلاحيات
GET  /api/v1/knowledge/nuclei/templates       - قوالب Nuclei
GET  /api/v1/knowledge/nuclei/templates/{id}  - تفاصيل قالب
GET  /api/v1/knowledge/nuclei/search          - بحث Nuclei
GET  /api/v1/knowledge/nuclei/severity/{s}    - حسب الخطورة
GET  /api/v1/knowledge/nuclei/cve/{cve}       - حسب CVE
GET  /api/v1/knowledge/nuclei/critical        - الحرجة
GET  /api/v1/knowledge/nuclei/rce             - RCE
GET  /api/v1/knowledge/nuclei/sqli            - SQL Injection
GET  /api/v1/knowledge/nuclei/xss             - XSS
```

### 🔒 Security (18 endpoints)
```
GET  /api/v1/security/health                  - صحة نظام الأمان
GET  /api/v1/security/rate-limits             - حدود المعدل
GET  /api/v1/security/rate-limits/status      - حالة Rate Limiting
GET  /api/v1/security/rate-limits/stats       - إحصائيات
POST /api/v1/security/rate-limits/reset       - إعادة تعيين
POST /api/v1/security/rate-limits/test        - اختبار
GET  /api/v1/security/validate/stats          - إحصائيات التحقق
POST /api/v1/security/validate/ip             - التحقق من IP
POST /api/v1/security/validate/cidr           - التحقق من CIDR
POST /api/v1/security/validate/hostname       - التحقق من Hostname
POST /api/v1/security/validate/port           - التحقق من Port
POST /api/v1/security/validate/uuid           - التحقق من UUID
POST /api/v1/security/validate/cve            - التحقق من CVE
POST /api/v1/security/validate/scope          - التحقق من النطاق
POST /api/v1/security/validate/safe-string    - نص آمن
POST /api/v1/security/validate/batch          - تحقق دفعي
POST /api/v1/security/check-injection         - فحص الحقن
```

### 🖥️ Terminal (3 endpoints)
```
GET  /api/v1/missions/{id}/commands           - الأوامر المتاحة
GET  /api/v1/missions/{id}/suggestions        - اقتراحات
GET  /api/v1/missions/{id}/terminal/output    - مخرجات Terminal
```

### 🔄 Workflow (11 endpoints)
```
GET  /api/v1/workflow/phases                  - مراحل العمل
GET  /api/v1/workflow/tools                   - الأدوات
GET  /api/v1/workflow/tools/{name}            - تفاصيل أداة
GET  /api/v1/workflow/tools/for-goal/{goal}   - أدوات للهدف
POST /api/v1/workflow/tools/install           - تثبيت أداة
POST /api/v1/workflow/start                   - بدء Workflow
GET  /api/v1/workflow/{id}/status             - حالة Workflow
GET  /api/v1/workflow/{id}/phases             - مراحل المهمة
POST /api/v1/workflow/{id}/pause              - إيقاف مؤقت
POST /api/v1/workflow/{id}/resume             - استئناف
POST /api/v1/workflow/{id}/stop               - إيقاف نهائي
```

### ☁️ Infrastructure (12 endpoints)
```
POST   /api/v1/infrastructure/environments              - إنشاء بيئة
GET    /api/v1/infrastructure/environments/{id}         - تفاصيل بيئة
DELETE /api/v1/infrastructure/environments/{id}         - حذف بيئة
GET    /api/v1/infrastructure/environments/{id}/health  - صحة البيئة
GET    /api/v1/infrastructure/environments/{id}/health/statistics - إحصائيات
GET    /api/v1/infrastructure/environments/{id}/system-info - معلومات النظام
POST   /api/v1/infrastructure/environments/{id}/execute/command - تنفيذ أمر
POST   /api/v1/infrastructure/environments/{id}/execute/script  - تنفيذ سكربت
POST   /api/v1/infrastructure/environments/{id}/reconnect      - إعادة الاتصال
GET    /api/v1/infrastructure/users/{id}/environments   - بيئات المستخدم
GET    /api/v1/infrastructure/statistics               - إحصائيات
```

---

## ✅ سيناريوهات الفحص (Test Scenarios)

### 1️⃣ تدفق المصادقة (Authentication Flow)
```bash
# 1. تسجيل مستخدم جديد
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "full_name": "Test User",
    "organization_name": "Test Org"
  }'

# 2. تسجيل الدخول
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
# احفظ الـ access_token

# 3. الحصول على معلومات المستخدم
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer {TOKEN}"

# 4. تحديث المعلومات
curl -X PUT http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"full_name": "Updated Name"}'

# 5. تسجيل الخروج
curl -X POST http://localhost:8000/api/v1/auth/logout \
  -H "Authorization: Bearer {TOKEN}"
```

### 2️⃣ تدفق إنشاء وإدارة مهمة (Mission Flow)
```bash
# 1. إنشاء مهمة
curl -X POST http://localhost:8000/api/v1/missions \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Mission",
    "description": "Testing penetration test",
    "scope": ["192.168.1.0/24"],
    "goals": ["network_map", "vuln_discovery"],
    "constraints": {"max_concurrent_scans": 5}
  }'

# 2. بدء المهمة
curl -X POST http://localhost:8000/api/v1/missions/{MISSION_ID}/start \
  -H "Authorization: Bearer {TOKEN}"

# 3. مراقبة الحالة
curl http://localhost:8000/api/v1/missions/{MISSION_ID} \
  -H "Authorization: Bearer {TOKEN}"

# 4. عرض الأهداف المكتشفة
curl http://localhost:8000/api/v1/missions/{MISSION_ID}/targets \
  -H "Authorization: Bearer {TOKEN}"

# 5. عرض الثغرات
curl http://localhost:8000/api/v1/missions/{MISSION_ID}/vulnerabilities \
  -H "Authorization: Bearer {TOKEN}"

# 6. إيقاف المهمة
curl -X POST http://localhost:8000/api/v1/missions/{MISSION_ID}/stop \
  -H "Authorization: Bearer {TOKEN}"
```

### 3️⃣ تدفق الفوترة (Billing Flow)
```bash
# 1. عرض الخطط المتاحة (بدون مصادقة)
curl http://localhost:8000/api/v1/billing/plans

# 2. عرض الاشتراك الحالي
curl http://localhost:8000/api/v1/billing/subscription \
  -H "Authorization: Bearer {TOKEN}"

# 3. إنشاء Checkout Session
curl -X POST http://localhost:8000/api/v1/billing/checkout \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "professional",
    "billing_cycle": "monthly",
    "success_url": "https://app.raglox.io/success",
    "cancel_url": "https://app.raglox.io/cancel"
  }'

# 4. عرض الاستخدام
curl http://localhost:8000/api/v1/billing/usage \
  -H "Authorization: Bearer {TOKEN}"

# 5. عرض الفواتير
curl http://localhost:8000/api/v1/billing/invoices \
  -H "Authorization: Bearer {TOKEN}"
```

### 4️⃣ تدفق HITL (Human-in-the-Loop)
```bash
# 1. عرض الموافقات المعلقة
curl http://localhost:8000/api/v1/missions/{MISSION_ID}/approvals \
  -H "Authorization: Bearer {TOKEN}"

# 2. الموافقة على إجراء
curl -X POST http://localhost:8000/api/v1/missions/{MISSION_ID}/approve/{ACTION_ID} \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"user_comment": "Approved after review"}'

# 3. رفض إجراء
curl -X POST http://localhost:8000/api/v1/missions/{MISSION_ID}/reject/{ACTION_ID} \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "rejection_reason": "Too risky",
    "user_comment": "Consider alternative approach"
  }'

# 4. إرسال رسالة محادثة
curl -X POST http://localhost:8000/api/v1/missions/{MISSION_ID}/chat \
  -H "Authorization: Bearer {TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"content": "What is the current progress?"}'
```

---

## 🧪 نقاط الفحص الرئيسية (Key Test Points)

### ✅ Security Checks
- [ ] JWT Token validation يعمل صحيحاً
- [ ] Rate Limiting يمنع الطلبات الزائدة
- [ ] Input Validation يمنع SQL Injection / XSS
- [ ] Organization isolation - لا يمكن الوصول لبيانات مؤسسة أخرى
- [ ] CORS headers صحيحة

### ✅ Authentication
- [ ] Registration يُنشئ مستخدم ومؤسسة
- [ ] Login يُعيد JWT token صالح
- [ ] Token expiry يعمل صحيحاً
- [ ] Logout يُبطل الـ token
- [ ] Password change يعمل

### ✅ Billing (Stripe)
- [ ] Plans endpoint يعمل بدون auth
- [ ] Subscription endpoint يتطلب auth
- [ ] Checkout session يُنشئ URL صالح
- [ ] Webhook يستقبل ويعالج الأحداث
- [ ] Usage limits تُطبّق حسب الخطة

### ✅ Missions
- [ ] Create mission يعمل مع scope صالح
- [ ] Start/Pause/Resume/Stop تعمل
- [ ] Targets/Vulnerabilities تُحدّث بشكل حقيقي
- [ ] Stats تعكس الحالة الفعلية
- [ ] HITL approvals تُوقف/تستأنف المهمة

### ✅ Real-time Features
- [ ] WebSocket connection يعمل
- [ ] Events تُبث في الوقت الفعلي
- [ ] Chat messages تُرسل/تُستلم

### ✅ Knowledge Base
- [ ] Search يعمل بدقة
- [ ] Modules تُحمّل صحيحاً (1761 module)
- [ ] Techniques mapped correctly (327 technique)
- [ ] Nuclei templates available (11927 template)

---

## 🔧 Troubleshooting

### مشكلة: JWT_SECRET not set
```bash
export JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
```

### مشكلة: Redis not connected
```bash
# تشغيل Redis
docker run -d -p 6379:6379 redis:alpine
# أو
redis-server
```

### مشكلة: PostgreSQL not connected
```bash
# تشغيل PostgreSQL
docker run -d -p 5432:5432 \
  -e POSTGRES_USER=raglox \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=raglox \
  postgres:15-alpine
```

### مشكلة: Stripe not configured
```bash
export STRIPE_SECRET_KEY="sk_test_..."
export STRIPE_PUBLISHABLE_KEY="pk_test_..."
export STRIPE_WEBHOOK_SECRET="whsec_..."
```

---

## 📊 Expected Results

### Health Check Response
```json
{
  "status": "healthy",
  "components": {
    "api": "healthy",
    "blackboard": "healthy",
    "knowledge": "loaded"
  }
}
```

### Billing Plans Response
```json
[
  {
    "id": "free",
    "name": "Free",
    "price_monthly": 0,
    "price_yearly": 0,
    "features": {"max_users": 3, "max_missions_per_month": 5}
  },
  {
    "id": "starter",
    "name": "Starter",
    "price_monthly": 49,
    "price_yearly": 490,
    "features": {"max_users": 10, "max_missions_per_month": 25}
  },
  {
    "id": "professional",
    "name": "Professional",
    "price_monthly": 199,
    "price_yearly": 1990,
    "features": {"max_users": 50, "max_missions_per_month": 100}
  },
  {
    "id": "enterprise",
    "name": "Enterprise",
    "price_monthly": 499,
    "price_yearly": 4990,
    "features": {"max_users": 1000, "max_missions_per_month": 10000}
  }
]
```

---

## 📝 تقرير الفحص (Test Report Template)

```markdown
# RAGLOX v3.0 QA Test Report

**تاريخ الفحص:** ____/____/____
**المختبر:** ______________
**البيئة:** Development / Staging / Production

## ملخص النتائج

| الفئة | إجمالي | ناجح | فاشل | متخطى |
|-------|--------|------|------|-------|
| Authentication | 13 | __ | __ | __ |
| Billing | 12 | __ | __ | __ |
| Missions | 22 | __ | __ | __ |
| Exploitation | 24 | __ | __ | __ |
| Knowledge | 26 | __ | __ | __ |
| Security | 18 | __ | __ | __ |
| Workflow | 11 | __ | __ | __ |
| Infrastructure | 12 | __ | __ | __ |
| **الإجمالي** | 141 | __ | __ | __ |

## المشاكل المكتشفة
1. _______________
2. _______________

## التوصيات
1. _______________
2. _______________

## الموافقة على النشر
- [ ] جاهز للنشر
- [ ] يحتاج إصلاحات
- [ ] يحتاج مراجعة إضافية
```

---

## 🔗 روابط مفيدة

- **API Documentation:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI Schema:** http://localhost:8000/openapi.json
- **Stripe Dashboard:** https://dashboard.stripe.com/test
- **GitHub Repository:** https://github.com/HosamN-ALI/Ragloxv3

---

**ملاحظة:** هذا الدليل للفحص في بيئة الاختبار. تأكد من استخدام بيانات اختبار فقط ولا تستخدم بيانات حقيقية أو مفاتيح إنتاج.
