# ⚡ RAGLOX v3.0 - دليل البدء السريع للإصلاحات

**الإصدار:** 1.0.0  
**التاريخ:** 2026-01-05  
**الحالة:** جاهز للتنفيذ الفوري

---

## 🚀 ابدأ الآن

### الخطوة 1: إعداد البيئة

```bash
# الانتقال للمشروع
cd /root/RAGLOX_V3/webapp

# تفعيل البيئة الافتراضية (إذا وُجدت)
source venv/bin/activate

# تثبيت الأدوات المطلوبة
pip install bandit ruff mypy black isort structlog slowapi circuitbreaker
```

---

### الخطوة 2: تقييم الوضع الحالي

```bash
# 1. عدد الاستثناءات العامة
echo "=== Generic Exceptions ==="
grep -rn "except Exception" src/ --include="*.py" | wc -l

# 2. أخطاء الاختبارات
echo "=== Test Collection Errors ==="
pytest --collect-only 2>&1 | grep "ERROR" | wc -l

# 3. تغطية الاختبارات الحالية
echo "=== Current Coverage ==="
pytest --cov=src --cov-report=term-missing 2>/dev/null | tail -20

# 4. فحص الأمان
echo "=== Security Scan ==="
bandit -r src/ -ll -q 2>/dev/null | tail -10
```

---

## 🔴 أولوية #1: SEC-01 - الاستثناءات العامة

### 🎯 الهدف
تحويل 287 `except Exception:` إلى استثناءات محددة

### ⏱️ الوقت المقدر: 3 أيام

### 📋 خطوات التنفيذ

#### 1. احصل على قائمة الملفات
```bash
cd /root/RAGLOX_V3/webapp
grep -rn "except Exception" src/ --include="*.py" | cut -d: -f1 | sort | uniq -c | sort -rn > /tmp/exception_files.txt
head -20 /tmp/exception_files.txt
```

#### 2. ابدأ بالملفات الأكثر تأثيراً
```
الترتيب المقترح:
1. src/specialists/base.py (16 مواقع) - الأساس لجميع المتخصصين
2. src/api/websocket.py (2 مواقع) - نقطة دخول المستخدم
3. src/specialists/attack.py - المتخصص الأهم
4. src/specialists/recon.py (8 مواقع)
5. البقية...
```

#### 3. نموذج الإصلاح السريع

**قبل:**
```python
except Exception as e:
    logger.error(f"Error: {e}")
```

**بعد:**
```python
except (ConnectionError, TimeoutError) as e:
    logger.warning("network_error", error=str(e))
    raise NetworkError("Connection failed") from e
except ValueError as e:
    logger.warning("validation_error", error=str(e))
    raise ValidationError(str(e)) from e
except Exception as e:
    logger.exception("unexpected_error")  # Stack trace للتشخيص
    raise InternalError("Unexpected error occurred") from e
```

#### 4. تحقق من كل إصلاح
```bash
# بعد تعديل كل ملف
pytest tests/ -v --tb=short -x  # يتوقف عند أول فشل
```

---

## 🔴 أولوية #2: TEST-01 - إصلاح أخطاء الاختبارات

### 🎯 الهدف
إصلاح 7 أخطاء تجميع الاختبارات

### ⏱️ الوقت المقدر: 2-4 ساعات

### 📋 الأخطاء والحلول

#### 1. SyntaxError (3 ملفات)
```bash
# الملفات المتأثرة
tests/test_controller.py
tests/test_logic_trigger_chain.py
tests/test_performance.py

# ابحث عن السطر المشكل
python -m py_compile tests/test_controller.py
# سيُظهر رقم السطر والخطأ

# عادة: backslash في نهاية السطر بشكل خاطئ
# أو: مسافات/tabs مختلطة
```

#### 2. NameError: RealExploitationEngine (4 ملفات)
```bash
# الملفات المتأثرة
tests/test_integration.py
tests/test_nuclei_ai_wiring.py
tests/test_nuclei_integration.py
tests/test_specialists.py

# الحل: إضافة الـ import الصحيح
# في بداية كل ملف:
```

```python
# إضافة في أعلى الملف
try:
    from src.specialists.attack import RealExploitationEngine
except ImportError:
    # للاختبارات التي لا تحتاج الـ class فعلياً
    RealExploitationEngine = None

# أو إذا كان الـ class في مكان آخر:
from src.exploitation.core.engine import RealExploitationEngine
```

#### 3. التحقق من الإصلاح
```bash
pytest --collect-only 2>&1 | grep "ERROR"
# يجب أن يكون الناتج فارغاً
```

---

## 🔴 أولوية #3: SEC-04 - Rate Limiting

### 🎯 الهدف
حماية الـ API من الإساءة

### ⏱️ الوقت المقدر: 2-3 ساعات

### 📋 خطوات التنفيذ

#### 1. تثبيت المكتبة
```bash
pip install slowapi
```

#### 2. إنشاء الملف
```bash
mkdir -p src/api/middleware
touch src/api/middleware/__init__.py
```

#### 3. إنشاء rate_limiter.py
```python
# src/api/middleware/rate_limiter.py
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request
from fastapi.responses import JSONResponse

limiter = Limiter(key_func=get_remote_address)

async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "rate_limit_exceeded", "retry_after": exc.retry_after},
        headers={"Retry-After": str(exc.retry_after)}
    )
```

#### 4. تحديث main.py
```python
# في src/api/main.py
from src.api.middleware.rate_limiter import limiter, rate_limit_handler
from slowapi.errors import RateLimitExceeded

# بعد إنشاء app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
```

#### 5. تطبيق على الـ routes
```python
# في أي route file
from src.api.middleware.rate_limiter import limiter

@router.post("/missions")
@limiter.limit("10/minute")
async def create_mission(request: Request, ...):
    ...
```

---

## 📊 تتبع التقدم اليومي

### قالب التقرير اليومي

```markdown
## تقرير التقدم - [التاريخ]

### ما تم إنجازه اليوم
- [ ] SEC-01: إصلاح X ملف (Y موقع)
- [ ] TEST-01: إصلاح X خطأ

### المقاييس
- الاستثناءات العامة المتبقية: XXX
- أخطاء الاختبارات المتبقية: X
- نسبة التغطية: XX%

### العوائق
- (أي مشاكل واجهتها)

### خطة الغد
- (المهام المخططة)
```

---

## 🔧 أوامر مفيدة للنسخ السريع

```bash
# === الفحص اليومي ===
cd /root/RAGLOX_V3/webapp && \
echo "Exceptions: $(grep -rn 'except Exception' src/ --include='*.py' | wc -l)" && \
echo "Test Errors: $(pytest --collect-only 2>&1 | grep 'ERROR' | wc -l)"

# === تشغيل الاختبارات ===
pytest tests/ -v --tb=short

# === تقرير التغطية ===
pytest --cov=src --cov-report=html && open htmlcov/index.html

# === فحص الأمان ===
bandit -r src/ -ll

# === فحص الأنماط ===
ruff check src/
mypy src/ --strict
black src/ --check
isort src/ --check
```

---

## ✅ قائمة المراجعة قبل الـ Commit

```markdown
- [ ] جميع الاختبارات تمر: `pytest tests/ -v`
- [ ] لا أخطاء تجميع: `pytest --collect-only`
- [ ] الأنماط صحيحة: `ruff check src/ && black src/ --check`
- [ ] لا تحذيرات أمنية: `bandit -r src/ -ll`
- [ ] التوثيق مُحدث
```

---

## 📞 الدعم السريع

| المشكلة | الحل |
|---------|------|
| "Module not found" | تحقق من `PYTHONPATH` و `__init__.py` |
| "Test collection error" | `pytest --collect-only 2>&1 | grep -B5 ERROR` |
| "Import error" | تحقق من المسار في `pyproject.toml` |
| "Permission denied" | `chmod +x script.py` |

---

**ابدأ الآن مع SEC-01! 🚀**

```bash
cd /root/RAGLOX_V3/webapp
grep -rn "except Exception" src/specialists/base.py
```
