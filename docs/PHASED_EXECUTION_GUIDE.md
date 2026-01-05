# 📋 RAGLOX v3.0 - دليل التنفيذ المرحلي

**Document ID:** RAGLOX-PEG-2026-001  
**Version:** 1.0.0  
**Date:** 2026-01-05  
**Status:** READY FOR EXECUTION

---

## 🎯 نظرة عامة سريعة

### الجدول الزمني الكلي
```
الأسبوع 1-2  ████████ المرحلة 1: الحرجة (13 عنصر)
الأسبوع 3-4  ████████ المرحلة 2: العالية (26 عنصر)
الأسبوع 5-6  ████████ المرحلة 3: المتوسطة (20 عنصر)
الأسبوع 7-8  ████████ المرحلة 4: المنخفضة (8 عناصر)
```

### ملخص الأولويات
| الأولوية | العدد | الجهد الكلي | التأثير |
|----------|-------|-------------|---------|
| 🔴 حرجة | 13 | ~15 يوم | حجب الإنتاج |
| 🟠 عالية | 26 | ~25 يوم | جودة الخدمة |
| 🟡 متوسطة | 20 | ~20 يوم | التحسين |
| 🟢 منخفضة | 8 | ~6 أيام | الصقل |

---

## 🔴 المرحلة 1: الأولوية الحرجة

### 📅 الأسبوع الأول

#### اليوم 1-3: SEC-01 - معالجة الاستثناءات العامة

**الملخص:** 287 موقع يستخدم `except Exception:` يحتاج للإصلاح

**خطوات التنفيذ:**

```bash
# 1. فحص الوضع الحالي
cd /root/RAGLOX_V3/webapp
grep -rn "except Exception" src/ --include="*.py" | wc -l
# Output: 287

# 2. قائمة الملفات مرتبة بعدد المواقع
grep -rn "except Exception" src/ --include="*.py" | cut -d: -f1 | sort | uniq -c | sort -rn
```

**قائمة الملفات (مرتبة بالأولوية):**

| # | الملف | المواقع | الأولوية | حالة |
|---|-------|---------|----------|------|
| 1 | `src/specialists/base.py` | 16 | حرج | ⬜ |
| 2 | `src/specialists/recon.py` | 8 | حرج | ⬜ |
| 3 | `src/core/llm/local_provider.py` | 6 | حرج | ⬜ |
| 4 | `src/specialists/analysis.py` | 5 | عالي | ⬜ |
| 5 | `src/specialists/intel.py` | 3 | عالي | ⬜ |
| 6 | `src/executors/base.py` | 3 | عالي | ⬜ |
| 7 | `src/executors/winrm.py` | 3 | عالي | ⬜ |
| 8 | `src/api/websocket.py` | 2 | حرج | ⬜ |
| 9 | `src/core/llm/blackbox_provider.py` | 2 | متوسط | ⬜ |
| 10 | `src/core/strategic_scorer.py` | 2 | متوسط | ⬜ |
| ... | (المزيد من الملفات) | ~237 | متفاوت | ⬜ |

**نموذج الإصلاح:**

```python
# ❌ قبل (غير آمن)
try:
    result = await self.execute_task(task)
except Exception as e:
    logger.error(f"Task failed: {e}")
    return None

# ✅ بعد (آمن)
from src.core.exceptions import (
    TaskExecutionError,
    NetworkError,
    TimeoutError as RagloxTimeout
)

try:
    result = await self.execute_task(task)
except (ConnectionError, socket.error) as e:
    logger.warning(
        "network_error",
        task_id=task.id,
        error_type=type(e).__name__,
        correlation_id=self._correlation_id
    )
    raise NetworkError(f"Network error during task execution") from e
except asyncio.TimeoutError as e:
    logger.warning(
        "timeout_error",
        task_id=task.id,
        timeout_seconds=self._timeout,
        correlation_id=self._correlation_id
    )
    raise RagloxTimeout(f"Task timed out after {self._timeout}s") from e
except ValueError as e:
    logger.error(
        "validation_error",
        task_id=task.id,
        error=str(e),
        correlation_id=self._correlation_id
    )
    raise TaskExecutionError(f"Invalid task configuration: {e}") from e
except Exception as e:
    # فقط كشبكة أمان نهائية
    logger.exception(
        "unexpected_error",
        task_id=task.id,
        error_type=type(e).__name__,
        correlation_id=self._correlation_id
    )
    raise TaskExecutionError(f"Unexpected error: {type(e).__name__}") from e
```

**أوامر التحقق:**
```bash
# تحقق من عدد المواقع المتبقية
grep -rn "except Exception" src/ --include="*.py" | wc -l

# تشغيل الاختبارات
pytest tests/ -v --tb=short

# فحص الأمان
bandit -r src/ -ll
```

---

#### اليوم 4: SEC-02 - أمان بيانات الاعتماد

**المهام:**

1. **إنشاء CredentialVault** (`src/core/security/credential_vault.py`)
   
2. **تحديث الملفات المتأثرة:**
   - `src/specialists/intel.py`
   - `src/specialists/attack.py`
   - `src/exploitation/adapters/metasploit_adapter.py`

3. **إضافة Decorator للإخفاء:**
```python
@mask_credentials
async def connect(self, host: str, password: str):
    # password لن يظهر في logs
    ...
```

---

#### اليوم 5: SEC-03 - تعزيز التحقق من المدخلات

**المهام:**

1. **تحديث نماذج Pydantic** في `src/core/validators.py`
2. **إضافة التحقق للـ API routes**
3. **اختبارات التحقق**

```bash
# تشغيل اختبارات التحقق
pytest tests/api_suite/test_*.py -k "validation" -v
```

---

### 📅 الأسبوع الثاني

#### اليوم 1: SEC-04 - Rate Limiting

**المهام:**

1. **تثبيت المكتبة:**
```bash
pip install slowapi redis
```

2. **إنشاء middleware** (`src/api/middleware/rate_limiter.py`)

3. **تكوين في `main.py`**

4. **اختبار الحدود:**
```bash
# اختبار Rate Limiting
for i in {1..15}; do
  curl -X POST http://localhost:8000/api/v1/missions \
    -H "Content-Type: application/json" \
    -d '{"name":"test","scope":["10.0.0.0/24"]}'
  echo " - Request $i"
done
```

---

#### اليوم 2: SEC-05 - تقوية JWT

**المهام:**

1. **تحديث `src/core/config.py`:**
   - إزالة القيمة الافتراضية
   - إضافة التحقق من الطول
   - إضافة فحص الـ entropy

2. **تحديث `.env.example`:**
```env
# JWT Configuration
JWT_SECRET=  # Required! Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
```

3. **اختبار الفشل:**
```bash
# يجب أن يفشل التطبيق بدون JWT_SECRET
unset JWT_SECRET
python -m src.api.main  # Should fail with ValidationError
```

---

#### اليوم 3-5: REL-01 - Redis High Availability

**المهام:**

1. **إنشاء `infrastructure/docker-compose.ha.yml`**

2. **إنشاء `infrastructure/redis/sentinel.conf`**

3. **تحديث `src/core/blackboard.py`** لدعم Sentinel

4. **تحديث `src/core/config.py`:**
```python
# Redis Sentinel settings
redis_sentinel_enabled: bool = Field(default=False)
redis_sentinels: List[tuple] = Field(default=[("localhost", 26379)])
redis_master_name: str = Field(default="raglox-master")
```

5. **اختبار Failover:**
```bash
# تشغيل HA stack
docker-compose -f infrastructure/docker-compose.ha.yml up -d

# محاكاة فشل Master
docker stop raglox-redis-master

# التحقق من Failover
redis-cli -p 26379 sentinel get-master-addr-by-name raglox-master
```

---

#### اليوم 6: REL-02 - استمرارية الموافقات

**المهام:**

1. **تحديث `src/controller/mission.py`:**
   - `request_approval()` → Redis
   - `get_pending_approval()` → Redis
   - `approve_action()` → Redis
   - `reject_action()` → Redis

2. **إضافة TTL للموافقات المنتهية**

3. **اختبار الاستمرارية:**
```bash
# إنشاء طلب موافقة
curl -X POST http://localhost:8000/api/v1/missions/{id}/approvals -d '{...}'

# إعادة تشغيل الخدمة
docker restart raglox-api

# التحقق من وجود الموافقة
curl http://localhost:8000/api/v1/missions/{id}/approvals
```

---

#### اليوم 7: REL-03 - Circuit Breaker

**المهام:**

1. **إنشاء `src/core/circuit_breaker.py`**

2. **تطبيق على الخدمات:**
   - MetasploitAdapter
   - ElasticsearchProvider
   - LLMProvider

3. **إضافة حالة Circuit إلى Health Check:**
```json
{
  "status": "healthy",
  "services": {
    "metasploit": {"status": "up", "circuit": "closed"},
    "elasticsearch": {"status": "degraded", "circuit": "open"},
    "llm": {"status": "up", "circuit": "half_open"}
  }
}
```

---

## 🟠 المرحلة 2: الأولوية العالية

### 📅 الأسبوع الثالث

#### TEST-01: إصلاح أخطاء تجميع الاختبارات (يوم 1)

**الأخطاء المُحددة:**

1. **SyntaxError في 3 ملفات:**
   - `tests/test_controller.py`
   - `tests/test_logic_trigger_chain.py`
   - `tests/test_performance.py`

2. **NameError: RealExploitationEngine في 4 ملفات:**
   - `tests/test_integration.py`
   - `tests/test_nuclei_ai_wiring.py`
   - `tests/test_nuclei_integration.py`
   - `tests/test_specialists.py`

**الإصلاح:**
```bash
# فحص الأخطاء
cd /root/RAGLOX_V3/webapp
pytest --collect-only 2>&1 | grep -B2 "ERROR"

# إصلاح import
# في الملفات المتأثرة:
from src.specialists.attack import RealExploitationEngine
# أو إذا لم يكن موجوداً:
try:
    from src.specialists.attack import RealExploitationEngine
except ImportError:
    RealExploitationEngine = None  # للاختبارات المشروطة
```

---

#### TEST-02: رفع تغطية الاختبارات (يوم 2-5)

**الأهداف:**

| اليوم | المكون | من | إلى | الاختبارات المطلوبة |
|-------|--------|-----|-----|---------------------|
| 2 | `exploitation/` | 20% | 50% | adapters, payloads |
| 3 | `exploitation/` | 50% | 90% | c2, post_exploitation |
| 4 | `specialists/` | 35% | 60% | attack, recon |
| 5 | `specialists/` | 60% | 85% | intel, analysis |

**أوامر:**
```bash
# تشغيل مع تقرير التغطية
pytest --cov=src --cov-report=html --cov-report=term-missing

# فتح التقرير
open htmlcov/index.html
```

---

### 📅 الأسبوع الرابع

#### HIGH-02: Structured Logging (يوم 1-2)

```bash
# تثبيت structlog
pip install structlog

# تكوين الـ logging في جميع الملفات
```

#### HIGH-14: Prometheus Metrics (يوم 3-4)

```bash
# تثبيت prometheus-client
pip install prometheus-client

# إضافة /metrics endpoint
```

#### HIGH-15: OpenTelemetry Tracing (يوم 5-6)

```bash
# تثبيت OpenTelemetry
pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation-fastapi
```

---

## 🟡 المرحلة 3: الأولوية المتوسطة

### 📅 الأسبوع الخامس

| اليوم | المهمة | الوصف |
|-------|--------|-------|
| 1 | MED-01 | تقليل تكرار الكود |
| 2 | MED-02 | استخراج Magic Numbers |
| 3-4 | MED-03 | إعادة هيكلة الدوال الطويلة |
| 5 | MED-04 + MED-05 | إزالة الكود الميت + تنظيم imports |

### 📅 الأسبوع السادس

| اليوم | المهمة | الوصف |
|-------|--------|-------|
| 1-2 | MED-06 | اختبارات الأداء |
| 3-4 | MED-07 | إعداد Load Testing |
| 5 | MED-08 | اختبارات Chaos Engineering |

---

## 🟢 المرحلة 4: الأولوية المنخفضة

### 📅 الأسبوع السابع والثامن

| اليوم | المهمة | الوصف |
|-------|--------|-------|
| 1 | LOW-01 | تنظيف التعليقات |
| 2 | LOW-02 | تحسين README |
| 3 | LOW-03 + LOW-04 | دليل المساهمة + أتمتة Changelog |
| 4 | LOW-05 + LOW-06 | تحديث Badges + أمثلة التكوين |
| 5 | LOW-07 + LOW-08 | تحليل الأداء + تحسين الذاكرة |

---

## ✅ معايير الإنجاز (Definition of Done)

لكل مهمة، يجب التحقق من:

- [ ] الكود مُنفذ ومُراجع
- [ ] اختبارات وحدة (تغطية ≥ 80%)
- [ ] اختبارات تكامل ناجحة
- [ ] التوثيق مُحدث
- [ ] مراجعة الأمان (للعناصر الأمنية)
- [ ] تقييم تأثير الأداء
- [ ] PR مدمج في main

---

## 🔧 أوامر يومية مفيدة

```bash
# فحص التقدم
cd /root/RAGLOX_V3/webapp

# عدد الاستثناءات العامة المتبقية
grep -rn "except Exception" src/ --include="*.py" | wc -l

# تشغيل الاختبارات
pytest tests/ -v --tb=short

# تقرير التغطية
pytest --cov=src --cov-report=term-missing

# فحص الأنماط
ruff check src/
mypy src/ --strict
black src/ --check

# فحص الأمان
bandit -r src/ -ll
pip-audit
```

---

## 📞 جهات الاتصال للتصعيد

| المشكلة | جهة الاتصال |
|---------|-------------|
| حظر تقني | قائد الفريق |
| مشكلة أمنية | فريق الأمان |
| تأخير في المرحلة | قائد المشروع |
| مشكلة بنية تحتية | فريق DevOps |

---

**آخر تحديث:** 2026-01-05  
**المراجعة القادمة:** 2026-01-06
