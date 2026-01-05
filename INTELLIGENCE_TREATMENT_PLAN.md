# RAGLOX v3.0 - خطة العلاج الذكي الشاملة
# Intelligence Treatment Plan - من أداة أتمتة إلى شريك ذكي

> **التقييم الحالي**: 6.5/10 (متوسط-متقدم) - أداة أتمتة ذكية محدودة
> **الهدف**: 9/10 - شريك تفكير ذكي (Thought Partner) لفرق Red Team المحترفة
> **تاريخ الإنشاء**: 2026-01-02

---

## 📋 الملخص التنفيذي

### الحالة الراهنة
RAGLOX v3.0 يعمل حالياً كأداة **Limited Intelligent Automation** وليس كـ **Thought Partner**:
- **80% Scripted Automation** مقابل **20% Agentic Reasoning**
- استدعاء LLM في ~10-15% من الحالات فقط
- القواعد ثابتة (Hardcoded) وغير تكيفية
- النظام **Reactive** فقط ولا يفكر مسبقاً (No Proactive Planning)

### أهداف الخطة العلاجية
1. **الحفاظ على مزايا LLM** - لا نفقد قدرات الذكاء الاصطناعي الحالية
2. **الحفاظ على المعرفة المضمنة** - مسارات Knowledge Base تبقى فعالة
3. **تعزيز التعلم التكيفي** - تحويل النظام من Reactive إلى Adaptive
4. **ربط المكونات ذكياً** - Cross-Workspace Intelligence

---

## 🏗️ الهيكل المعماري المقترح - Hybrid Intelligence Architecture

### المبدأ الأساسي: "LLM as Advisor, Knowledge as Foundation"

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     RAGLOX v3.0 Hybrid Intelligence Layer                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │   Operational   │◄──►│  Intelligence   │◄──►│    Strategic    │         │
│  │     Memory      │    │   Coordinator   │    │     Scorer      │         │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘         │
│           │                      │                      │                   │
│           ▼                      ▼                      ▼                   │
│  ┌─────────────────────────────────────────────────────────────────┐       │
│  │                     Shared Decision Context                      │       │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │       │
│  │  │  Historical │  │   Current   │  │  Predictive │              │       │
│  │  │   Patterns  │  │   Context   │  │   Scoring   │              │       │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │       │
│  └─────────────────────────────────────────────────────────────────┘       │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                          EXISTING COMPONENTS (Enhanced)                     │
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │  Recon         │    │   Analysis      │    │    Attack       │         │
│  │  Specialist    │◄──►│   Specialist    │◄──►│   Specialist    │         │
│  │  (Enhanced)    │    │   (Enhanced)    │    │   (Enhanced)    │         │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘         │
│           │                      │                      │                   │
│           └──────────────────────┼──────────────────────┘                   │
│                                  ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐       │
│  │                        Blackboard (Enhanced)                     │       │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │       │
│  │  │   Targets   │  │    Vulns    │  │   Sessions  │              │       │
│  │  │             │  │             │  │             │              │       │
│  │  └─────────────┘  └─────────────┘  └─────────────┘              │       │
│  │  ┌─────────────────────────────────────────────────┐            │       │
│  │  │        NEW: Operational Memory Store            │            │       │
│  │  │   (Decision History, Success Patterns, Failures)│            │       │
│  │  └─────────────────────────────────────────────────┘            │       │
│  └─────────────────────────────────────────────────────────────────┘       │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           KNOWLEDGE LAYER (Preserved)                       │
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │    Embedded     │    │     Nuclei      │    │      LLM        │         │
│  │   Knowledge     │◄──►│   Templates     │◄──►│    Service      │         │
│  │   (RX Modules)  │    │   (CVE DB)      │    │   (Advisor)     │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧠 المكون 1: Operational Memory (الذاكرة التشغيلية)

### المشكلة الحالية
```python
# analysis.py - السطر 183
self._analysis_history: List[Dict[str, Any]] = []

# المشكلة: يُكتب إليه ولا يُقرأ أبداً في اتخاذ القرارات!
```

### الحل المقترح

**ملف جديد: `/src/core/operational_memory.py`**

```python
"""
RAGLOX v3.0 - Operational Memory
ذاكرة تشغيلية مشتركة للتعلم من التجارب السابقة

المبدأ: كل قرار يُسجَّل، كل فشل يُحلَّل، كل نجاح يُستفاد منه
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import json
from collections import defaultdict


class DecisionOutcome(Enum):
    """نتائج القرارات"""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


class OperationalContext(Enum):
    """سياق العملية"""
    EXPLOIT = "exploit"
    RECON = "recon"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    CRED_HARVEST = "cred_harvest"


@dataclass
class DecisionRecord:
    """سجل قرار واحد"""
    id: UUID = field(default_factory=uuid4)
    mission_id: UUID = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # السياق
    context: OperationalContext = OperationalContext.EXPLOIT
    target_id: Optional[str] = None
    vuln_type: Optional[str] = None
    target_os: Optional[str] = None
    target_services: List[str] = field(default_factory=list)
    
    # القرار
    decision_type: str = ""  # retry, modify, skip, escalate
    decision_source: str = ""  # llm, rules, memory
    parameters_used: Dict[str, Any] = field(default_factory=dict)
    
    # النتيجة
    outcome: DecisionOutcome = DecisionOutcome.FAILURE
    outcome_details: Dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    
    # للتعلم
    success_factors: List[str] = field(default_factory=list)
    failure_factors: List[str] = field(default_factory=list)
    lessons_learned: List[str] = field(default_factory=list)


class OperationalMemory:
    """
    الذاكرة التشغيلية للنظام - مركز التعلم التكيفي
    
    المسؤوليات:
    1. تسجيل كل قرار ونتيجته
    2. استخلاص أنماط النجاح والفشل
    3. توفير توصيات مبنية على التجارب السابقة
    4. تحديث احتمالات النجاح ديناميكياً
    """
    
    # TTL للذاكرة قصيرة المدى (ساعة واحدة)
    SHORT_TERM_TTL = timedelta(hours=1)
    
    # TTL للذاكرة طويلة المدى (30 يوم)
    LONG_TERM_TTL = timedelta(days=30)
    
    def __init__(self, blackboard=None, redis_client=None):
        """
        Args:
            blackboard: Blackboard instance للتخزين المشترك
            redis_client: Redis client للتخزين المستمر
        """
        self._blackboard = blackboard
        self._redis = redis_client
        
        # ذاكرة محلية (في الـ process)
        self._short_term: Dict[str, DecisionRecord] = {}
        self._pattern_cache: Dict[str, Dict] = {}
        
        # إحصائيات محسوبة
        self._success_rates: Dict[str, float] = defaultdict(lambda: 0.5)
        self._technique_effectiveness: Dict[str, Dict] = {}
        
    # ═══════════════════════════════════════════════════════════
    # التسجيل - كل قرار يُسجَّل
    # ═══════════════════════════════════════════════════════════
    
    async def record_decision(
        self,
        mission_id: UUID,
        context: OperationalContext,
        decision_type: str,
        decision_source: str,
        parameters: Dict[str, Any],
        target_info: Optional[Dict] = None,
        vuln_info: Optional[Dict] = None
    ) -> UUID:
        """
        تسجيل قرار جديد قبل التنفيذ.
        
        Returns:
            UUID للقرار للتحديث لاحقاً
        """
        record = DecisionRecord(
            mission_id=mission_id,
            context=context,
            decision_type=decision_type,
            decision_source=decision_source,
            parameters_used=parameters,
            target_id=target_info.get("id") if target_info else None,
            target_os=target_info.get("os") if target_info else None,
            target_services=target_info.get("services", []) if target_info else [],
            vuln_type=vuln_info.get("type") if vuln_info else None
        )
        
        # تخزين في الذاكرة القصيرة
        self._short_term[str(record.id)] = record
        
        # تخزين في Redis إذا متاح
        if self._redis:
            await self._persist_record(record)
        
        return record.id
    
    async def update_outcome(
        self,
        decision_id: UUID,
        outcome: DecisionOutcome,
        details: Dict[str, Any],
        duration_ms: int = 0,
        lessons: Optional[List[str]] = None
    ) -> None:
        """
        تحديث نتيجة القرار بعد التنفيذ.
        
        هذه الخطوة حاسمة - بدونها لا يوجد تعلم!
        """
        record_key = str(decision_id)
        
        if record_key not in self._short_term:
            # محاولة استرجاع من Redis
            record = await self._fetch_record(decision_id)
            if not record:
                return
            self._short_term[record_key] = record
        
        record = self._short_term[record_key]
        record.outcome = outcome
        record.outcome_details = details
        record.duration_ms = duration_ms
        
        if lessons:
            record.lessons_learned = lessons
        
        # استخلاص عوامل النجاح/الفشل
        self._extract_factors(record)
        
        # تحديث الإحصائيات
        await self._update_statistics(record)
        
        # تخزين التحديث
        if self._redis:
            await self._persist_record(record)
    
    # ═══════════════════════════════════════════════════════════
    # الاستعلام - التعلم من التجارب
    # ═══════════════════════════════════════════════════════════
    
    async def get_similar_experiences(
        self,
        context: OperationalContext,
        target_os: Optional[str] = None,
        vuln_type: Optional[str] = None,
        limit: int = 10
    ) -> List[DecisionRecord]:
        """
        البحث عن تجارب مشابهة للسياق الحالي.
        
        هذا هو قلب التعلم التكيفي - نتعلم من الماضي!
        
        Args:
            context: نوع العملية
            target_os: نظام التشغيل المستهدف
            vuln_type: نوع الثغرة
            limit: الحد الأقصى للنتائج
            
        Returns:
            قائمة بالتجارب المشابهة مرتبة بالأحدث
        """
        matches = []
        
        # بحث في الذاكرة المحلية
        for record in self._short_term.values():
            score = self._calculate_similarity(record, context, target_os, vuln_type)
            if score > 0.5:  # عتبة التشابه
                matches.append((score, record))
        
        # بحث في Redis إذا لم نجد كفاية
        if len(matches) < limit and self._redis:
            redis_matches = await self._search_redis(context, target_os, vuln_type, limit)
            for record in redis_matches:
                score = self._calculate_similarity(record, context, target_os, vuln_type)
                matches.append((score, record))
        
        # ترتيب بالتشابه ثم بالوقت
        matches.sort(key=lambda x: (x[0], x[1].timestamp), reverse=True)
        
        return [m[1] for m in matches[:limit]]
    
    async def get_success_rate_for_context(
        self,
        context: OperationalContext,
        target_os: Optional[str] = None,
        vuln_type: Optional[str] = None
    ) -> Tuple[float, int]:
        """
        حساب معدل النجاح لسياق معين بناءً على التجارب.
        
        Returns:
            (success_rate, sample_count)
        """
        cache_key = f"{context.value}:{target_os or 'any'}:{vuln_type or 'any'}"
        
        if cache_key in self._success_rates:
            experiences = await self.get_similar_experiences(context, target_os, vuln_type, limit=50)
            if experiences:
                successes = sum(1 for e in experiences if e.outcome == DecisionOutcome.SUCCESS)
                rate = successes / len(experiences)
                self._success_rates[cache_key] = rate
                return rate, len(experiences)
        
        return self._success_rates[cache_key], 0
    
    async def get_best_approach_for_context(
        self,
        context: OperationalContext,
        target_os: Optional[str] = None,
        vuln_type: Optional[str] = None,
        available_modules: Optional[List[str]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        استنتاج أفضل نهج بناءً على التجارب السابقة.
        
        هذا هو "التفكير" المبني على الذاكرة!
        
        Returns:
            Dict مع التوصيات أو None إذا لا توجد بيانات كافية
        """
        experiences = await self.get_similar_experiences(context, target_os, vuln_type, limit=20)
        
        if len(experiences) < 3:
            # بيانات غير كافية للتوصية
            return None
        
        # تحليل الأنماط الناجحة
        successful = [e for e in experiences if e.outcome == DecisionOutcome.SUCCESS]
        failed = [e for e in experiences if e.outcome == DecisionOutcome.FAILURE]
        
        if not successful:
            return {
                "confidence": "low",
                "recommendation": "no_success_pattern",
                "common_failure_factors": self._extract_common_factors(failed),
                "suggested_action": "escalate_to_llm"
            }
        
        # استخلاص أنماط النجاح
        success_patterns = self._extract_success_patterns(successful)
        
        # فلترة بالموديولات المتاحة
        if available_modules:
            relevant_patterns = [
                p for p in success_patterns 
                if p.get("module") in available_modules
            ]
            if relevant_patterns:
                success_patterns = relevant_patterns
        
        return {
            "confidence": "high" if len(successful) >= 5 else "medium",
            "success_rate": len(successful) / len(experiences),
            "recommended_approach": success_patterns[0] if success_patterns else None,
            "alternative_approaches": success_patterns[1:3] if len(success_patterns) > 1 else [],
            "avoid_factors": self._extract_common_factors(failed)[:3],
            "sample_size": len(experiences)
        }
    
    # ═══════════════════════════════════════════════════════════
    # التحليل - استخلاص الأنماط
    # ═══════════════════════════════════════════════════════════
    
    def _calculate_similarity(
        self,
        record: DecisionRecord,
        context: OperationalContext,
        target_os: Optional[str],
        vuln_type: Optional[str]
    ) -> float:
        """حساب درجة التشابه بين سجل والسياق الحالي."""
        score = 0.0
        
        # تطابق السياق (أهم عامل)
        if record.context == context:
            score += 0.4
        
        # تطابق نظام التشغيل
        if target_os and record.target_os:
            if target_os.lower() in record.target_os.lower():
                score += 0.3
            elif ("windows" in target_os.lower()) == ("windows" in record.target_os.lower()):
                score += 0.15
        
        # تطابق نوع الثغرة
        if vuln_type and record.vuln_type:
            if vuln_type == record.vuln_type:
                score += 0.3
            elif vuln_type.split("-")[0] == record.vuln_type.split("-")[0]:
                score += 0.15
        
        return score
    
    def _extract_factors(self, record: DecisionRecord) -> None:
        """استخلاص عوامل النجاح/الفشل من نتيجة القرار."""
        details = record.outcome_details
        
        if record.outcome == DecisionOutcome.SUCCESS:
            # عوامل النجاح
            if details.get("evasion_used"):
                record.success_factors.append("evasion_technique")
            if details.get("encoded_payload"):
                record.success_factors.append("payload_encoding")
            if details.get("timing_optimized"):
                record.success_factors.append("timing_optimization")
            if record.parameters_used.get("module"):
                record.success_factors.append(f"module:{record.parameters_used['module']}")
                
        elif record.outcome == DecisionOutcome.FAILURE:
            # عوامل الفشل
            error_type = details.get("error_type", "unknown")
            record.failure_factors.append(f"error:{error_type}")
            
            if details.get("detected_defenses"):
                for defense in details["detected_defenses"]:
                    record.failure_factors.append(f"defense:{defense}")
            
            if details.get("timeout"):
                record.failure_factors.append("timeout")
    
    def _extract_success_patterns(self, successful: List[DecisionRecord]) -> List[Dict]:
        """استخلاص أنماط النجاح من التجارب الناجحة."""
        patterns = defaultdict(lambda: {"count": 0, "factors": [], "parameters": {}})
        
        for record in successful:
            # تجميع بالموديول المستخدم
            module = record.parameters_used.get("module", "default")
            pattern = patterns[module]
            pattern["count"] += 1
            pattern["module"] = module
            pattern["factors"].extend(record.success_factors)
            
            # تجميع البارامترات الناجحة
            for key, value in record.parameters_used.items():
                if key not in pattern["parameters"]:
                    pattern["parameters"][key] = []
                pattern["parameters"][key].append(value)
        
        # ترتيب بعدد النجاحات
        sorted_patterns = sorted(
            patterns.values(), 
            key=lambda x: x["count"], 
            reverse=True
        )
        
        # تنظيف وإرجاع
        result = []
        for p in sorted_patterns:
            result.append({
                "module": p["module"],
                "success_count": p["count"],
                "common_factors": list(set(p["factors"]))[:5],
                "recommended_parameters": {
                    k: max(set(v), key=v.count) 
                    for k, v in p["parameters"].items()
                }
            })
        
        return result
    
    def _extract_common_factors(self, records: List[DecisionRecord]) -> List[str]:
        """استخلاص العوامل المشتركة من مجموعة سجلات."""
        all_factors = []
        for record in records:
            all_factors.extend(record.failure_factors or record.success_factors)
        
        if not all_factors:
            return []
        
        # عد التكرارات
        factor_counts = defaultdict(int)
        for factor in all_factors:
            factor_counts[factor] += 1
        
        # ترتيب بالتكرار
        sorted_factors = sorted(
            factor_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        return [f[0] for f in sorted_factors[:5]]
    
    async def _update_statistics(self, record: DecisionRecord) -> None:
        """تحديث الإحصائيات بعد كل قرار."""
        context_key = f"{record.context.value}:{record.target_os or 'any'}"
        
        # هذا يُفعَّل إعادة حساب معدل النجاح
        if context_key in self._success_rates:
            del self._success_rates[context_key]
    
    # ═══════════════════════════════════════════════════════════
    # التخزين المستمر (Redis)
    # ═══════════════════════════════════════════════════════════
    
    async def _persist_record(self, record: DecisionRecord) -> None:
        """تخزين سجل في Redis."""
        if not self._redis:
            return
        
        key = f"opmem:record:{record.id}"
        data = {
            "id": str(record.id),
            "mission_id": str(record.mission_id) if record.mission_id else None,
            "timestamp": record.timestamp.isoformat(),
            "context": record.context.value,
            "target_id": record.target_id,
            "vuln_type": record.vuln_type,
            "target_os": record.target_os,
            "decision_type": record.decision_type,
            "decision_source": record.decision_source,
            "parameters_used": json.dumps(record.parameters_used),
            "outcome": record.outcome.value,
            "outcome_details": json.dumps(record.outcome_details),
            "duration_ms": record.duration_ms,
            "success_factors": json.dumps(record.success_factors),
            "failure_factors": json.dumps(record.failure_factors),
            "lessons_learned": json.dumps(record.lessons_learned)
        }
        
        await self._redis.hset(key, mapping=data)
        await self._redis.expire(key, int(self.LONG_TERM_TTL.total_seconds()))
        
        # إضافة للفهرس
        index_key = f"opmem:index:{record.context.value}"
        await self._redis.zadd(index_key, {str(record.id): record.timestamp.timestamp()})
    
    async def _fetch_record(self, record_id: UUID) -> Optional[DecisionRecord]:
        """استرجاع سجل من Redis."""
        if not self._redis:
            return None
        
        key = f"opmem:record:{record_id}"
        data = await self._redis.hgetall(key)
        
        if not data:
            return None
        
        return DecisionRecord(
            id=UUID(data["id"]),
            mission_id=UUID(data["mission_id"]) if data.get("mission_id") else None,
            timestamp=datetime.fromisoformat(data["timestamp"]),
            context=OperationalContext(data["context"]),
            target_id=data.get("target_id"),
            vuln_type=data.get("vuln_type"),
            target_os=data.get("target_os"),
            decision_type=data.get("decision_type", ""),
            decision_source=data.get("decision_source", ""),
            parameters_used=json.loads(data.get("parameters_used", "{}")),
            outcome=DecisionOutcome(data.get("outcome", "failure")),
            outcome_details=json.loads(data.get("outcome_details", "{}")),
            duration_ms=int(data.get("duration_ms", 0)),
            success_factors=json.loads(data.get("success_factors", "[]")),
            failure_factors=json.loads(data.get("failure_factors", "[]")),
            lessons_learned=json.loads(data.get("lessons_learned", "[]"))
        )
    
    async def _search_redis(
        self,
        context: OperationalContext,
        target_os: Optional[str],
        vuln_type: Optional[str],
        limit: int
    ) -> List[DecisionRecord]:
        """البحث في Redis عن سجلات مشابهة."""
        if not self._redis:
            return []
        
        # البحث في فهرس السياق
        index_key = f"opmem:index:{context.value}"
        record_ids = await self._redis.zrevrange(index_key, 0, limit * 2)
        
        records = []
        for rid in record_ids:
            record = await self._fetch_record(UUID(rid))
            if record:
                records.append(record)
        
        return records[:limit]
```

### كيفية الدمج مع AnalysisSpecialist

```python
# في analysis.py - تعديل _make_decision

async def _make_decision(self, ...):
    # 1. استشارة الذاكرة التشغيلية أولاً
    memory_recommendation = await self.operational_memory.get_best_approach_for_context(
        context=OperationalContext.EXPLOIT,
        target_os=self._get_target_platform(context["target_info"]),
        vuln_type=context.get("vuln_info", {}).get("type")
    )
    
    if memory_recommendation and memory_recommendation["confidence"] == "high":
        # لدينا توصية واثقة من الذاكرة
        self.logger.info(f"[MEMORY] Using learned pattern: {memory_recommendation['recommended_approach']}")
        return self._apply_memory_recommendation(memory_recommendation)
    
    # 2. إذا الذاكرة غير واثقة، استشر LLM
    if self.llm_enabled and memory_recommendation and memory_recommendation["confidence"] == "medium":
        # نمرر توصية الذاكرة كـ context لـ LLM
        return await self._llm_decision_with_memory_context(
            ...,
            memory_hint=memory_recommendation
        )
    
    # 3. الـ fallback الحالي (rule-based)
    return await self._rule_based_fallback(...)
```

---

## 🔗 المكون 2: Intelligence Coordinator (منسق الذكاء)

### المشكلة الحالية
لا يوجد ربط ذكي بين اكتشافات ReconSpecialist وقرارات AttackSpecialist:
- ReconSpecialist يكتشف خدمات ويُخزّنها
- AttackSpecialist يقرأها بشكل منفصل
- لا يوجد ربط بين "ماذا اكتشفنا" و "كيف نهاجم"

### الحل المقترح

**ملف جديد: `/src/core/intelligence_coordinator.py`**

```python
"""
RAGLOX v3.0 - Intelligence Coordinator
منسق الذكاء للربط الذكي بين المكونات

المبدأ: كل اكتشاف يُحلَّل استراتيجياً، كل هجوم يُخطَّط له مسبقاً
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from collections import defaultdict


class AttackPathType(Enum):
    """أنواع مسارات الهجوم"""
    DIRECT_EXPLOIT = "direct_exploit"       # ثغرة مباشرة
    CREDENTIAL_BASED = "credential_based"   # عبر بيانات اعتماد
    CHAIN_EXPLOIT = "chain_exploit"         # سلسلة ثغرات
    LATERAL_PIVOT = "lateral_pivot"         # محور جانبي
    PRIVILEGE_CHAIN = "privilege_chain"     # سلسلة تصعيد


@dataclass
class AttackPath:
    """مسار هجوم مقترح"""
    id: UUID = field(default_factory=uuid4)
    path_type: AttackPathType = AttackPathType.DIRECT_EXPLOIT
    
    # الأهداف
    source_target: Optional[str] = None  # من أين نبدأ
    destination_target: str = ""          # الهدف النهائي
    
    # الخطوات
    steps: List[Dict[str, Any]] = field(default_factory=list)
    
    # التقييم
    success_probability: float = 0.5
    stealth_score: float = 0.5          # 1.0 = صامت تماماً
    time_estimate_minutes: int = 30
    risk_level: str = "medium"
    
    # المتطلبات
    prerequisites: List[str] = field(default_factory=list)
    required_credentials: List[str] = field(default_factory=list)
    required_sessions: List[str] = field(default_factory=list)
    
    # الأسباب
    reasoning: str = ""
    alternative_paths: List[UUID] = field(default_factory=list)


class IntelligenceCoordinator:
    """
    منسق الذكاء - الدماغ الاستراتيجي للنظام
    
    المسؤوليات:
    1. ربط الاكتشافات من ReconSpecialist بخطط الهجوم
    2. توليد مسارات هجوم ذكية متعددة
    3. تقييم كل مسار استراتيجياً
    4. تنسيق البيانات بين جميع المكونات
    """
    
    def __init__(
        self,
        blackboard=None,
        operational_memory=None,
        knowledge_base=None,
        llm_service=None
    ):
        """
        Args:
            blackboard: Blackboard للوصول للبيانات المشتركة
            operational_memory: ذاكرة التجارب السابقة
            knowledge_base: قاعدة المعرفة (RX Modules, Nuclei)
            llm_service: خدمة LLM للتحليل المتقدم
        """
        self._blackboard = blackboard
        self._memory = operational_memory
        self._knowledge = knowledge_base
        self._llm = llm_service
        
        # كاش لمسارات الهجوم المحسوبة
        self._path_cache: Dict[str, List[AttackPath]] = {}
        
        # خريطة العلاقات بين الأهداف
        self._target_graph: Dict[str, Set[str]] = defaultdict(set)
        
        # بيانات الاعتماد المرتبطة بالأهداف
        self._credential_map: Dict[str, List[str]] = defaultdict(list)
    
    # ═══════════════════════════════════════════════════════════
    # تحليل الاكتشافات
    # ═══════════════════════════════════════════════════════════
    
    async def process_recon_results(
        self,
        mission_id: str,
        target_id: str,
        services: List[Dict],
        vulnerabilities: List[Dict],
        credentials: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        معالجة نتائج الاستطلاع وتوليد رؤى استراتيجية.
        
        هذا هو الجسر بين Recon و Attack!
        
        Args:
            mission_id: معرف المهمة
            target_id: معرف الهدف
            services: الخدمات المكتشفة
            vulnerabilities: الثغرات المكتشفة
            credentials: بيانات الاعتماد (إن وجدت)
            
        Returns:
            Dict مع التحليل الاستراتيجي والتوصيات
        """
        analysis = {
            "target_id": target_id,
            "timestamp": datetime.utcnow().isoformat(),
            "strategic_value": "unknown",
            "attack_surface": [],
            "recommended_paths": [],
            "immediate_actions": [],
            "deferred_actions": [],
            "coordination_notes": []
        }
        
        # 1. تقييم سطح الهجوم
        attack_surface = await self._analyze_attack_surface(services, vulnerabilities)
        analysis["attack_surface"] = attack_surface
        
        # 2. حساب القيمة الاستراتيجية
        strategic_value = self._calculate_strategic_value(
            services, vulnerabilities, credentials
        )
        analysis["strategic_value"] = strategic_value
        
        # 3. توليد مسارات الهجوم
        paths = await self.generate_attack_paths(
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities,
            credentials=credentials
        )
        analysis["recommended_paths"] = [
            self._path_to_dict(p) for p in paths[:5]  # أفضل 5 مسارات
        ]
        
        # 4. تحديد الإجراءات الفورية والمؤجلة
        immediate, deferred = self._categorize_actions(paths, strategic_value)
        analysis["immediate_actions"] = immediate
        analysis["deferred_actions"] = deferred
        
        # 5. ملاحظات التنسيق
        analysis["coordination_notes"] = self._generate_coordination_notes(
            target_id, paths, attack_surface
        )
        
        # تخزين التحليل
        if self._blackboard:
            await self._store_analysis(mission_id, target_id, analysis)
        
        return analysis
    
    async def _analyze_attack_surface(
        self,
        services: List[Dict],
        vulnerabilities: List[Dict]
    ) -> List[Dict]:
        """تحليل سطح الهجوم المتاح."""
        surface = []
        
        for service in services:
            entry = {
                "service": service.get("name"),
                "port": service.get("port"),
                "exposure_level": "high" if service.get("port") in [22, 80, 443, 445, 3389] else "medium",
                "related_vulns": [],
                "attack_vectors": []
            }
            
            # ربط الثغرات بالخدمات
            for vuln in vulnerabilities:
                if self._vuln_matches_service(vuln, service):
                    entry["related_vulns"].append({
                        "id": vuln.get("id"),
                        "type": vuln.get("type"),
                        "severity": vuln.get("severity")
                    })
            
            # تحديد ناقلات الهجوم
            entry["attack_vectors"] = self._determine_attack_vectors(service, entry["related_vulns"])
            
            surface.append(entry)
        
        return surface
    
    def _calculate_strategic_value(
        self,
        services: List[Dict],
        vulnerabilities: List[Dict],
        credentials: Optional[List[Dict]]
    ) -> str:
        """حساب القيمة الاستراتيجية للهدف."""
        score = 0
        
        # قيمة الخدمات
        high_value_services = {"ldap", "kerberos", "smb", "rdp", "winrm", "ssh"}
        for service in services:
            if service.get("name", "").lower() in high_value_services:
                score += 20
            else:
                score += 5
        
        # قيمة الثغرات
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "").lower()
            if severity == "critical":
                score += 30
            elif severity == "high":
                score += 20
            elif severity == "medium":
                score += 10
        
        # قيمة بيانات الاعتماد
        if credentials:
            for cred in credentials:
                priv = cred.get("privilege_level", "user")
                if priv in ("domain_admin", "admin"):
                    score += 50
                elif priv == "user":
                    score += 15
        
        # تصنيف
        if score >= 100:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 30:
            return "medium"
        return "low"
    
    # ═══════════════════════════════════════════════════════════
    # توليد مسارات الهجوم
    # ═══════════════════════════════════════════════════════════
    
    async def generate_attack_paths(
        self,
        target_id: str,
        services: List[Dict],
        vulnerabilities: List[Dict],
        credentials: Optional[List[Dict]] = None,
        from_target: Optional[str] = None
    ) -> List[AttackPath]:
        """
        توليد مسارات هجوم ذكية متعددة.
        
        هذا هو التفكير الاستراتيجي!
        
        Args:
            target_id: الهدف المراد مهاجمته
            services: الخدمات المتاحة
            vulnerabilities: الثغرات المكتشفة
            credentials: بيانات اعتماد متاحة
            from_target: هدف البداية (للحركة الجانبية)
            
        Returns:
            قائمة مسارات مرتبة بالأفضلية
        """
        paths = []
        
        # 1. مسارات الاستغلال المباشر
        for vuln in vulnerabilities:
            if vuln.get("severity") in ("critical", "high") and vuln.get("exploit_available"):
                path = await self._create_direct_exploit_path(target_id, vuln, services)
                if path:
                    paths.append(path)
        
        # 2. مسارات عبر بيانات الاعتماد
        if credentials:
            for cred in credentials:
                path = await self._create_credential_path(target_id, cred, services)
                if path:
                    paths.append(path)
        
        # 3. مسارات السلسلة (Chain)
        chain_paths = await self._create_chain_paths(target_id, vulnerabilities, services)
        paths.extend(chain_paths)
        
        # 4. مسارات الحركة الجانبية
        if from_target:
            lateral_path = await self._create_lateral_path(from_target, target_id, credentials)
            if lateral_path:
                paths.append(lateral_path)
        
        # استشارة الذاكرة لتحسين الاحتمالات
        paths = await self._enhance_paths_with_memory(paths)
        
        # ترتيب بالأفضلية
        paths.sort(key=lambda p: (
            p.success_probability * 0.4 +
            p.stealth_score * 0.3 +
            (1 - p.time_estimate_minutes / 120) * 0.3
        ), reverse=True)
        
        return paths
    
    async def _create_direct_exploit_path(
        self,
        target_id: str,
        vuln: Dict,
        services: List[Dict]
    ) -> Optional[AttackPath]:
        """إنشاء مسار استغلال مباشر."""
        # البحث عن موديول مناسب
        module = None
        if self._knowledge:
            modules = self._knowledge.search_modules(vuln.get("type", ""), limit=1)
            if modules:
                module = modules[0]
        
        steps = [
            {
                "action": "exploit",
                "target": target_id,
                "vuln_id": vuln.get("id"),
                "module": module.get("rx_module_id") if module else None,
                "description": f"Exploit {vuln.get('type')} vulnerability"
            }
        ]
        
        # إضافة خطوة تصعيد إذا لزم
        if vuln.get("initial_privilege", "user") not in ("admin", "system", "root"):
            steps.append({
                "action": "privesc",
                "target": target_id,
                "description": "Privilege escalation required"
            })
        
        return AttackPath(
            path_type=AttackPathType.DIRECT_EXPLOIT,
            destination_target=target_id,
            steps=steps,
            success_probability=self._estimate_exploit_probability(vuln, module),
            stealth_score=self._estimate_stealth_score(vuln, "direct"),
            time_estimate_minutes=15 if module else 30,
            risk_level=vuln.get("severity", "medium"),
            reasoning=f"Direct exploitation of {vuln.get('type')} - {vuln.get('severity')} severity"
        )
    
    async def _create_credential_path(
        self,
        target_id: str,
        cred: Dict,
        services: List[Dict]
    ) -> Optional[AttackPath]:
        """إنشاء مسار عبر بيانات الاعتماد."""
        # تحديد الخدمة المناسبة
        suitable_service = None
        for service in services:
            svc_name = service.get("name", "").lower()
            if svc_name in ("ssh", "smb", "rdp", "winrm"):
                suitable_service = service
                break
        
        if not suitable_service:
            return None
        
        steps = [
            {
                "action": "authenticate",
                "target": target_id,
                "service": suitable_service.get("name"),
                "port": suitable_service.get("port"),
                "cred_id": cred.get("id"),
                "description": f"Authenticate via {suitable_service.get('name')}"
            }
        ]
        
        # تصعيد إذا لزم
        if cred.get("privilege_level") not in ("admin", "domain_admin"):
            steps.append({
                "action": "privesc",
                "target": target_id,
                "description": "Privilege escalation after authentication"
            })
        
        return AttackPath(
            path_type=AttackPathType.CREDENTIAL_BASED,
            destination_target=target_id,
            steps=steps,
            success_probability=0.7 if cred.get("verified") else 0.5,
            stealth_score=0.8,  # بيانات الاعتماد أقل ضجيجاً
            time_estimate_minutes=10,
            risk_level="low",
            required_credentials=[cred.get("id")],
            reasoning=f"Credential-based access via {suitable_service.get('name')}"
        )
    
    async def _create_chain_paths(
        self,
        target_id: str,
        vulnerabilities: List[Dict],
        services: List[Dict]
    ) -> List[AttackPath]:
        """إنشاء مسارات سلسلة الثغرات."""
        chains = []
        
        # البحث عن ثغرات يمكن تسلسلها
        info_vulns = [v for v in vulnerabilities if v.get("severity") in ("info", "low")]
        exploit_vulns = [v for v in vulnerabilities if v.get("severity") in ("high", "critical")]
        
        for info_vuln in info_vulns[:2]:  # أول ثغرتين للمعلومات
            for exploit_vuln in exploit_vulns[:2]:  # أول ثغرتين للاستغلال
                chain = AttackPath(
                    path_type=AttackPathType.CHAIN_EXPLOIT,
                    destination_target=target_id,
                    steps=[
                        {
                            "action": "recon",
                            "vuln_id": info_vuln.get("id"),
                            "description": f"Gather info via {info_vuln.get('type')}"
                        },
                        {
                            "action": "exploit",
                            "vuln_id": exploit_vuln.get("id"),
                            "description": f"Exploit {exploit_vuln.get('type')}"
                        }
                    ],
                    success_probability=0.4,  # سلاسل أصعب
                    stealth_score=0.6,
                    time_estimate_minutes=45,
                    risk_level="medium",
                    reasoning=f"Chain: {info_vuln.get('type')} → {exploit_vuln.get('type')}"
                )
                chains.append(chain)
        
        return chains
    
    async def _create_lateral_path(
        self,
        from_target: str,
        to_target: str,
        credentials: Optional[List[Dict]]
    ) -> Optional[AttackPath]:
        """إنشاء مسار حركة جانبية."""
        if not credentials:
            return None
        
        # اختيار أفضل بيانات اعتماد للحركة الجانبية
        best_cred = max(
            credentials,
            key=lambda c: 1 if c.get("privilege_level") == "domain_admin" else 
                         0.7 if c.get("privilege_level") == "admin" else 0.3
        )
        
        return AttackPath(
            path_type=AttackPathType.LATERAL_PIVOT,
            source_target=from_target,
            destination_target=to_target,
            steps=[
                {
                    "action": "lateral_move",
                    "from": from_target,
                    "to": to_target,
                    "cred_id": best_cred.get("id"),
                    "method": "pass_the_hash" if best_cred.get("type") == "hash" else "ssh",
                    "description": f"Lateral movement from {from_target} to {to_target}"
                }
            ],
            success_probability=0.6,
            stealth_score=0.5,  # الحركة الجانبية ملحوظة نسبياً
            time_estimate_minutes=20,
            risk_level="medium",
            required_credentials=[best_cred.get("id")],
            required_sessions=[from_target],
            reasoning=f"Pivot from compromised {from_target} to {to_target}"
        )
    
    async def _enhance_paths_with_memory(
        self,
        paths: List[AttackPath]
    ) -> List[AttackPath]:
        """تحسين المسارات باستخدام الذاكرة التشغيلية."""
        if not self._memory:
            return paths
        
        for path in paths:
            # البحث عن تجارب مشابهة
            context = self._path_type_to_context(path.path_type)
            experiences = await self._memory.get_similar_experiences(
                context=context,
                limit=5
            )
            
            if experiences:
                # تعديل الاحتمالية بناءً على التجارب
                successes = sum(1 for e in experiences 
                              if e.outcome.value == "success")
                if len(experiences) >= 3:
                    historical_rate = successes / len(experiences)
                    # مزج الاحتمالية التقديرية مع التاريخية
                    path.success_probability = (
                        path.success_probability * 0.4 +
                        historical_rate * 0.6
                    )
        
        return paths
    
    # ═══════════════════════════════════════════════════════════
    # المساعدات
    # ═══════════════════════════════════════════════════════════
    
    def _vuln_matches_service(self, vuln: Dict, service: Dict) -> bool:
        """التحقق من تطابق الثغرة مع الخدمة."""
        vuln_type = vuln.get("type", "").lower()
        service_name = service.get("name", "").lower()
        port = service.get("port")
        
        # تطابقات معروفة
        matches = {
            "ssh": ["ssh", "openssh", "cve-2018-15473"],
            "smb": ["smb", "ms17-010", "eternalblue", "cve-2017-0144"],
            "rdp": ["rdp", "bluekeep", "cve-2019-0708"],
            "http": ["http", "web", "log4j", "cve-2021-44228"]
        }
        
        for svc, patterns in matches.items():
            if service_name == svc or (port and str(port) in ["22", "445", "3389", "80", "443"]):
                for pattern in patterns:
                    if pattern in vuln_type:
                        return True
        
        return False
    
    def _determine_attack_vectors(
        self,
        service: Dict,
        vulns: List[Dict]
    ) -> List[str]:
        """تحديد ناقلات الهجوم المتاحة."""
        vectors = []
        service_name = service.get("name", "").lower()
        
        # ناقلات مبنية على الخدمة
        service_vectors = {
            "ssh": ["brute_force", "key_auth", "exploit"],
            "smb": ["pass_the_hash", "exploit", "share_enum"],
            "rdp": ["brute_force", "exploit", "rdp_relay"],
            "http": ["web_exploit", "injection", "auth_bypass"],
            "https": ["web_exploit", "injection", "ssl_stripping"]
        }
        
        if service_name in service_vectors:
            vectors.extend(service_vectors[service_name])
        
        # ناقلات مبنية على الثغرات
        for vuln in vulns:
            severity = vuln.get("severity", "").lower()
            if severity in ("critical", "high"):
                if "rce" in vuln.get("type", "").lower():
                    vectors.append("remote_code_execution")
                elif "auth" in vuln.get("type", "").lower():
                    vectors.append("auth_bypass")
        
        return list(set(vectors))
    
    def _estimate_exploit_probability(
        self,
        vuln: Dict,
        module: Optional[Dict]
    ) -> float:
        """تقدير احتمالية نجاح الاستغلال."""
        base = 0.4
        
        # تعديل بناءً على الخطورة
        severity = vuln.get("severity", "medium").lower()
        severity_boost = {"critical": 0.2, "high": 0.15, "medium": 0.1, "low": 0.05}
        base += severity_boost.get(severity, 0)
        
        # تعديل بناءً على الموديول
        if module:
            reliability = module.get("reliability", "medium")
            if reliability == "high":
                base += 0.2
            elif reliability == "medium":
                base += 0.1
        
        return min(base, 0.95)
    
    def _estimate_stealth_score(self, vuln: Dict, method: str) -> float:
        """تقدير درجة التخفي."""
        scores = {
            "credential": 0.9,
            "direct": 0.5,
            "chain": 0.6,
            "lateral": 0.4
        }
        return scores.get(method, 0.5)
    
    def _categorize_actions(
        self,
        paths: List[AttackPath],
        strategic_value: str
    ) -> Tuple[List[Dict], List[Dict]]:
        """تصنيف الإجراءات إلى فورية ومؤجلة."""
        immediate = []
        deferred = []
        
        for path in paths[:5]:  # أفضل 5 مسارات
            action = {
                "path_id": str(path.id),
                "type": path.path_type.value,
                "probability": path.success_probability,
                "first_step": path.steps[0] if path.steps else None
            }
            
            # فورية: احتمالية عالية أو قيمة استراتيجية حرجة
            if path.success_probability > 0.6 or strategic_value == "critical":
                immediate.append(action)
            else:
                deferred.append(action)
        
        return immediate, deferred
    
    def _generate_coordination_notes(
        self,
        target_id: str,
        paths: List[AttackPath],
        attack_surface: List[Dict]
    ) -> List[str]:
        """توليد ملاحظات التنسيق."""
        notes = []
        
        # ملاحظات حول الأولويات
        if paths:
            best_path = paths[0]
            notes.append(
                f"Priority: {best_path.path_type.value} with "
                f"{best_path.success_probability:.0%} success probability"
            )
        
        # ملاحظات حول سطح الهجوم
        critical_services = [
            s for s in attack_surface 
            if s.get("exposure_level") == "high" and s.get("related_vulns")
        ]
        if critical_services:
            notes.append(
                f"Critical exposure: {len(critical_services)} high-exposure "
                f"services with known vulnerabilities"
            )
        
        return notes
    
    def _path_to_dict(self, path: AttackPath) -> Dict:
        """تحويل مسار إلى قاموس."""
        return {
            "id": str(path.id),
            "type": path.path_type.value,
            "source": path.source_target,
            "destination": path.destination_target,
            "steps": path.steps,
            "success_probability": path.success_probability,
            "stealth_score": path.stealth_score,
            "time_estimate_minutes": path.time_estimate_minutes,
            "risk_level": path.risk_level,
            "reasoning": path.reasoning
        }
    
    def _path_type_to_context(self, path_type: AttackPathType):
        """تحويل نوع المسار إلى سياق للذاكرة."""
        from .operational_memory import OperationalContext
        
        mapping = {
            AttackPathType.DIRECT_EXPLOIT: OperationalContext.EXPLOIT,
            AttackPathType.CREDENTIAL_BASED: OperationalContext.EXPLOIT,
            AttackPathType.CHAIN_EXPLOIT: OperationalContext.EXPLOIT,
            AttackPathType.LATERAL_PIVOT: OperationalContext.LATERAL,
            AttackPathType.PRIVILEGE_CHAIN: OperationalContext.PRIVESC
        }
        return mapping.get(path_type, OperationalContext.EXPLOIT)
    
    async def _store_analysis(
        self,
        mission_id: str,
        target_id: str,
        analysis: Dict
    ) -> None:
        """تخزين التحليل في Blackboard."""
        if self._blackboard:
            await self._blackboard.log_result(
                mission_id,
                "strategic_analysis",
                {
                    "target_id": target_id,
                    "analysis": analysis
                }
            )
```

---

## 📊 المكون 3: Strategic Vulnerability Scorer (نظام التقييم الاستراتيجي)

### المشكلة الحالية
التقييم الحالي يعتمد على CVSS فقط، وهذا غير كافٍ:
- CVSS لا يأخذ أهمية الأصل في الاعتبار
- لا يوجد ربط بسلسلة الهجوم
- لا يوجد تقييم لاحتمالية الاختراق الفعلي

### الحل المقترح

**ملف جديد: `/src/core/strategic_scorer.py`**

```python
"""
RAGLOX v3.0 - Strategic Vulnerability Scorer
نظام تقييم استراتيجي للثغرات يتجاوز CVSS

المبدأ: الثغرة الأخطر ليست بالضرورة الأعلى CVSS
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime


class AssetCriticality(Enum):
    """أهمية الأصل"""
    CROWN_JEWEL = "crown_jewel"      # Domain Controller, Database الرئيسية
    HIGH = "high"                     # خوادم الإنتاج
    MEDIUM = "medium"                 # خوادم التطوير
    LOW = "low"                       # أجهزة المستخدمين
    UNKNOWN = "unknown"


class ChainPosition(Enum):
    """موقع الثغرة في سلسلة الهجوم"""
    INITIAL_ACCESS = "initial_access"    # نقطة الدخول
    PIVOT_POINT = "pivot_point"          # نقطة محورية
    PRIVILEGE_GATE = "privilege_gate"    # بوابة تصعيد
    DATA_ACCESS = "data_access"          # وصول للبيانات
    LATERAL_ENABLER = "lateral_enabler"  # تمكين الحركة الجانبية


@dataclass
class StrategicScore:
    """النتيجة الاستراتيجية للثغرة"""
    vuln_id: str
    
    # النتائج الفرعية (0-10)
    cvss_score: float = 5.0
    asset_criticality_score: float = 5.0
    chain_position_score: float = 5.0
    exploit_probability_score: float = 5.0
    stealth_factor_score: float = 5.0
    
    # النتيجة النهائية المرجحة
    strategic_score: float = 5.0
    
    # التفاصيل
    reasoning: List[str] = field(default_factory=list)
    recommended_priority: int = 5  # 1-10, 10 = الأعلى
    
    # السياق
    asset_criticality: AssetCriticality = AssetCriticality.UNKNOWN
    chain_position: Optional[ChainPosition] = None
    
    # الأوزان المستخدمة (للشفافية)
    weights_used: Dict[str, float] = field(default_factory=dict)


class StrategicScorer:
    """
    نظام التقييم الاستراتيجي للثغرات
    
    يحسب النتيجة الاستراتيجية بناءً على:
    1. CVSS (الخطورة التقنية)
    2. أهمية الأصل (Asset Criticality)
    3. موقع السلسلة (Chain Position)
    4. احتمالية الاستغلال الفعلي
    5. عامل التخفي (للعمليات الاحترافية)
    """
    
    # الأوزان الافتراضية
    DEFAULT_WEIGHTS = {
        "cvss": 0.25,
        "asset_criticality": 0.25,
        "chain_position": 0.20,
        "exploit_probability": 0.20,
        "stealth_factor": 0.10
    }
    
    # أوزان للوضع الهجومي (Aggressive)
    AGGRESSIVE_WEIGHTS = {
        "cvss": 0.30,
        "asset_criticality": 0.30,
        "chain_position": 0.20,
        "exploit_probability": 0.15,
        "stealth_factor": 0.05
    }
    
    # أوزان للوضع الخفي (Stealth)
    STEALTH_WEIGHTS = {
        "cvss": 0.15,
        "asset_criticality": 0.20,
        "chain_position": 0.20,
        "exploit_probability": 0.20,
        "stealth_factor": 0.25
    }
    
    def __init__(
        self,
        knowledge_base=None,
        operational_memory=None,
        weights: Optional[Dict[str, float]] = None
    ):
        """
        Args:
            knowledge_base: قاعدة المعرفة لتقييم الموديولات
            operational_memory: الذاكرة لتقييم احتمالية النجاح
            weights: أوزان مخصصة أو None للافتراضي
        """
        self._knowledge = knowledge_base
        self._memory = operational_memory
        self._weights = weights or self.DEFAULT_WEIGHTS
        
        # كاش للتقييمات
        self._score_cache: Dict[str, StrategicScore] = {}
    
    def set_mode(self, mode: str) -> None:
        """تغيير وضع التقييم."""
        if mode == "aggressive":
            self._weights = self.AGGRESSIVE_WEIGHTS
        elif mode == "stealth":
            self._weights = self.STEALTH_WEIGHTS
        else:
            self._weights = self.DEFAULT_WEIGHTS
    
    async def score_vulnerability(
        self,
        vuln: Dict[str, Any],
        target: Dict[str, Any],
        mission_context: Optional[Dict] = None
    ) -> StrategicScore:
        """
        حساب النتيجة الاستراتيجية لثغرة.
        
        Args:
            vuln: بيانات الثغرة
            target: بيانات الهدف
            mission_context: سياق المهمة (أهداف، قيود)
            
        Returns:
            StrategicScore مع كل التفاصيل
        """
        vuln_id = vuln.get("id", "unknown")
        
        # التحقق من الكاش
        cache_key = f"{vuln_id}:{target.get('id', '')}"
        if cache_key in self._score_cache:
            return self._score_cache[cache_key]
        
        result = StrategicScore(vuln_id=vuln_id)
        reasoning = []
        
        # 1. نتيجة CVSS
        cvss = self._calculate_cvss_score(vuln)
        result.cvss_score = cvss
        reasoning.append(f"CVSS: {cvss:.1f}/10")
        
        # 2. أهمية الأصل
        asset_score, criticality = self._calculate_asset_criticality(target)
        result.asset_criticality_score = asset_score
        result.asset_criticality = criticality
        reasoning.append(f"Asset Criticality: {criticality.value} ({asset_score:.1f}/10)")
        
        # 3. موقع السلسلة
        chain_score, position = await self._calculate_chain_position(vuln, target, mission_context)
        result.chain_position_score = chain_score
        result.chain_position = position
        if position:
            reasoning.append(f"Chain Position: {position.value} ({chain_score:.1f}/10)")
        
        # 4. احتمالية الاستغلال
        exploit_score = await self._calculate_exploit_probability(vuln, target)
        result.exploit_probability_score = exploit_score
        reasoning.append(f"Exploit Probability: {exploit_score:.1f}/10")
        
        # 5. عامل التخفي
        stealth_score = self._calculate_stealth_factor(vuln)
        result.stealth_factor_score = stealth_score
        reasoning.append(f"Stealth Factor: {stealth_score:.1f}/10")
        
        # حساب النتيجة النهائية
        strategic_score = (
            cvss * self._weights["cvss"] +
            asset_score * self._weights["asset_criticality"] +
            chain_score * self._weights["chain_position"] +
            exploit_score * self._weights["exploit_probability"] +
            stealth_score * self._weights["stealth_factor"]
        )
        
        result.strategic_score = round(strategic_score, 2)
        result.reasoning = reasoning
        result.recommended_priority = self._calculate_priority(strategic_score)
        result.weights_used = self._weights.copy()
        
        # حفظ في الكاش
        self._score_cache[cache_key] = result
        
        return result
    
    async def rank_vulnerabilities(
        self,
        vulnerabilities: List[Dict],
        target: Dict[str, Any],
        mission_context: Optional[Dict] = None,
        limit: int = 10
    ) -> List[Tuple[Dict, StrategicScore]]:
        """
        ترتيب قائمة ثغرات بالأولوية الاستراتيجية.
        
        Args:
            vulnerabilities: قائمة الثغرات
            target: بيانات الهدف
            mission_context: سياق المهمة
            limit: الحد الأقصى للنتائج
            
        Returns:
            قائمة من (ثغرة, نتيجة) مرتبة بالأفضلية
        """
        scored = []
        
        for vuln in vulnerabilities:
            score = await self.score_vulnerability(vuln, target, mission_context)
            scored.append((vuln, score))
        
        # ترتيب بالنتيجة الاستراتيجية
        scored.sort(key=lambda x: x[1].strategic_score, reverse=True)
        
        return scored[:limit]
    
    # ═══════════════════════════════════════════════════════════
    # حسابات النتائج الفرعية
    # ═══════════════════════════════════════════════════════════
    
    def _calculate_cvss_score(self, vuln: Dict) -> float:
        """استخراج أو حساب نتيجة CVSS."""
        # محاولة استخراج CVSS الموجود
        cvss = vuln.get("cvss", vuln.get("cvss_score"))
        if cvss is not None:
            return float(cvss)
        
        # تقدير من الخطورة
        severity = vuln.get("severity", "medium").lower()
        severity_map = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.5,
            "info": 1.0
        }
        return severity_map.get(severity, 5.0)
    
    def _calculate_asset_criticality(
        self,
        target: Dict
    ) -> Tuple[float, AssetCriticality]:
        """حساب أهمية الأصل."""
        # مؤشرات الأهمية
        indicators = {
            "crown_jewel": [
                "domain controller", "dc", "ad", "active directory",
                "database", "sql", "oracle", "mongodb",
                "backup", "pki", "ca", "certificate"
            ],
            "high": [
                "server", "production", "prod", "web", "api",
                "mail", "exchange", "file server"
            ],
            "medium": [
                "dev", "development", "staging", "test", "qa"
            ],
            "low": [
                "workstation", "desktop", "laptop", "endpoint"
            ]
        }
        
        # البحث في معلومات الهدف
        target_str = " ".join([
            str(target.get("hostname", "")),
            str(target.get("os", "")),
            str(target.get("services", "")),
            str(target.get("tags", ""))
        ]).lower()
        
        for level, keywords in indicators.items():
            for keyword in keywords:
                if keyword in target_str:
                    criticality = AssetCriticality(level)
                    score = {
                        "crown_jewel": 10.0,
                        "high": 8.0,
                        "medium": 5.0,
                        "low": 3.0
                    }[level]
                    return score, criticality
        
        return 5.0, AssetCriticality.UNKNOWN
    
    async def _calculate_chain_position(
        self,
        vuln: Dict,
        target: Dict,
        mission_context: Optional[Dict]
    ) -> Tuple[float, Optional[ChainPosition]]:
        """حساب قيمة موقع الثغرة في سلسلة الهجوم."""
        vuln_type = vuln.get("type", "").lower()
        services = target.get("services", [])
        
        # تحديد الموقع
        position = None
        score = 5.0
        
        # نقطة الدخول
        if any(s in vuln_type for s in ["rce", "remote", "initial", "external"]):
            position = ChainPosition.INITIAL_ACCESS
            score = 9.0
        
        # بوابة التصعيد
        elif any(s in vuln_type for s in ["privesc", "elevation", "root", "admin", "system"]):
            position = ChainPosition.PRIVILEGE_GATE
            score = 8.5
        
        # الوصول للبيانات
        elif any(s in vuln_type for s in ["sql", "database", "exfil", "data", "leak"]):
            position = ChainPosition.DATA_ACCESS
            score = 8.0
        
        # تمكين الحركة الجانبية
        elif any(s in vuln_type for s in ["smb", "rdp", "ssh", "psexec", "wmi"]):
            position = ChainPosition.LATERAL_ENABLER
            score = 7.5
        
        # نقطة محورية
        elif any(s in str(services) for s in ["ldap", "kerberos", "ad"]):
            position = ChainPosition.PIVOT_POINT
            score = 8.0
        
        # تعديل بناءً على أهداف المهمة
        if mission_context:
            goals = mission_context.get("goals", [])
            if "domain_admin" in goals and position == ChainPosition.PRIVILEGE_GATE:
                score += 1.0
            elif "data_exfil" in goals and position == ChainPosition.DATA_ACCESS:
                score += 1.0
        
        return min(score, 10.0), position
    
    async def _calculate_exploit_probability(
        self,
        vuln: Dict,
        target: Dict
    ) -> float:
        """حساب احتمالية الاستغلال الفعلي."""
        base = 5.0
        
        # عوامل إيجابية
        if vuln.get("exploit_available"):
            base += 2.0
        
        if vuln.get("metasploit_module"):
            base += 1.5
        
        if vuln.get("nuclei_template"):
            base += 1.0
        
        # عمر الثغرة (أقدم = أكثر استقراراً)
        vuln_type = vuln.get("type", "")
        if vuln_type.startswith("CVE-"):
            try:
                year = int(vuln_type.split("-")[1])
                age = datetime.utcnow().year - year
                if age >= 2:
                    base += 0.5
            except:
                pass
        
        # استشارة الذاكرة
        if self._memory:
            from .operational_memory import OperationalContext
            rate, count = await self._memory.get_success_rate_for_context(
                context=OperationalContext.EXPLOIT,
                vuln_type=vuln_type
            )
            if count >= 3:
                base = (base + rate * 10) / 2
        
        # عوامل سلبية
        target_os = target.get("os", "").lower()
        if "hardened" in target_os or "secure" in target_os:
            base -= 1.0
        
        return min(max(base, 0), 10.0)
    
    def _calculate_stealth_factor(self, vuln: Dict) -> float:
        """حساب عامل التخفي."""
        score = 5.0
        vuln_type = vuln.get("type", "").lower()
        
        # ثغرات صاخبة
        noisy_patterns = [
            "bruteforce", "spray", "scan", "flood",
            "dos", "ddos", "crash"
        ]
        for pattern in noisy_patterns:
            if pattern in vuln_type:
                score -= 2.0
        
        # ثغرات هادئة
        quiet_patterns = [
            "auth_bypass", "credential", "token",
            "session", "cookie", "jwt"
        ]
        for pattern in quiet_patterns:
            if pattern in vuln_type:
                score += 1.5
        
        # Living off the land
        if vuln.get("lolbins_compatible"):
            score += 1.0
        
        return min(max(score, 0), 10.0)
    
    def _calculate_priority(self, strategic_score: float) -> int:
        """تحويل النتيجة الاستراتيجية إلى أولوية."""
        if strategic_score >= 9:
            return 10
        elif strategic_score >= 8:
            return 9
        elif strategic_score >= 7:
            return 8
        elif strategic_score >= 6:
            return 7
        elif strategic_score >= 5:
            return 6
        elif strategic_score >= 4:
            return 5
        elif strategic_score >= 3:
            return 4
        else:
            return 3
```

---

## 🥷 المكون 4: Stealth Profiles (ملفات التخفي)

### المشكلة الحالية
لا يوجد تحكم في مستوى الضجيج/التخفي أثناء العمليات.

### الحل المقترح

**ملف جديد: `/src/core/stealth_profiles.py`**

```python
"""
RAGLOX v3.0 - Stealth Profiles
ملفات تعريف التخفي للعمليات الاحترافية

المبدأ: Red Team المحترف يتصرف كـ APT، لا كـ Script Kiddie
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import random


class StealthLevel(Enum):
    """مستويات التخفي"""
    SILENT = "silent"           # صامت تماماً - عمليات APT
    QUIET = "quiet"             # هادئ - عمليات مستهدفة
    NORMAL = "normal"           # عادي - توازن
    AGGRESSIVE = "aggressive"   # عدواني - سرعة على التخفي
    NOISY = "noisy"            # صاخب - اختبار فقط


@dataclass
class StealthProfile:
    """ملف تعريف التخفي"""
    name: str
    level: StealthLevel
    
    # التوقيت
    min_delay_seconds: float = 1.0
    max_delay_seconds: float = 5.0
    jitter_percent: float = 0.2       # تذبذب عشوائي
    
    # معدلات الطلبات
    max_requests_per_minute: int = 10
    max_connections_per_target: int = 3
    
    # السلوك
    use_evasion: bool = True
    encode_payloads: bool = True
    randomize_user_agent: bool = True
    avoid_signatures: bool = True
    
    # أوقات النشاط (للمحاكاة الحقيقية)
    work_hours_only: bool = False     # فقط ساعات العمل
    avoid_peak_hours: bool = True     # تجنب أوقات الذروة
    
    # الأدوات المسموحة
    allowed_techniques: List[str] = field(default_factory=list)
    blocked_techniques: List[str] = field(default_factory=list)
    
    # تسجيل الأحداث
    log_all_actions: bool = True
    mask_ips: bool = False


class StealthManager:
    """
    مدير التخفي - يتحكم في سلوك النظام حسب الملف الشخصي
    """
    
    # الملفات الشخصية المضمنة
    BUILTIN_PROFILES = {
        "apt_simulation": StealthProfile(
            name="apt_simulation",
            level=StealthLevel.SILENT,
            min_delay_seconds=30.0,
            max_delay_seconds=300.0,
            jitter_percent=0.5,
            max_requests_per_minute=2,
            max_connections_per_target=1,
            use_evasion=True,
            encode_payloads=True,
            randomize_user_agent=True,
            avoid_signatures=True,
            work_hours_only=True,
            avoid_peak_hours=True,
            blocked_techniques=[
                "bruteforce", "spray", "scan_all_ports",
                "loud_exploit", "ddos"
            ]
        ),
        
        "red_team_standard": StealthProfile(
            name="red_team_standard",
            level=StealthLevel.QUIET,
            min_delay_seconds=5.0,
            max_delay_seconds=30.0,
            jitter_percent=0.3,
            max_requests_per_minute=5,
            max_connections_per_target=2,
            use_evasion=True,
            encode_payloads=True,
            randomize_user_agent=True,
            avoid_signatures=True,
            work_hours_only=False,
            avoid_peak_hours=True
        ),
        
        "pentest_normal": StealthProfile(
            name="pentest_normal",
            level=StealthLevel.NORMAL,
            min_delay_seconds=1.0,
            max_delay_seconds=10.0,
            jitter_percent=0.2,
            max_requests_per_minute=15,
            max_connections_per_target=5,
            use_evasion=True,
            encode_payloads=False,
            randomize_user_agent=True,
            avoid_signatures=False
        ),
        
        "vulnerability_assessment": StealthProfile(
            name="vulnerability_assessment",
            level=StealthLevel.AGGRESSIVE,
            min_delay_seconds=0.1,
            max_delay_seconds=1.0,
            jitter_percent=0.1,
            max_requests_per_minute=60,
            max_connections_per_target=10,
            use_evasion=False,
            encode_payloads=False,
            randomize_user_agent=False,
            avoid_signatures=False
        ),
        
        "testing_only": StealthProfile(
            name="testing_only",
            level=StealthLevel.NOISY,
            min_delay_seconds=0.0,
            max_delay_seconds=0.1,
            jitter_percent=0.0,
            max_requests_per_minute=1000,
            max_connections_per_target=50,
            use_evasion=False,
            encode_payloads=False,
            randomize_user_agent=False,
            avoid_signatures=False
        )
    }
    
    def __init__(self, profile_name: str = "pentest_normal"):
        """
        Args:
            profile_name: اسم الملف الشخصي
        """
        self._profile = self.BUILTIN_PROFILES.get(
            profile_name,
            self.BUILTIN_PROFILES["pentest_normal"]
        )
        self._request_counts: Dict[str, int] = {}
        self._last_request_times: Dict[str, float] = {}
    
    @property
    def profile(self) -> StealthProfile:
        return self._profile
    
    def set_profile(self, profile_name: str) -> None:
        """تغيير الملف الشخصي."""
        if profile_name in self.BUILTIN_PROFILES:
            self._profile = self.BUILTIN_PROFILES[profile_name]
        else:
            raise ValueError(f"Unknown profile: {profile_name}")
    
    def set_custom_profile(self, profile: StealthProfile) -> None:
        """تعيين ملف شخصي مخصص."""
        self._profile = profile
    
    def get_delay(self) -> float:
        """
        الحصول على التأخير التالي بناءً على الملف الشخصي.
        
        Returns:
            التأخير بالثواني مع jitter
        """
        base_delay = random.uniform(
            self._profile.min_delay_seconds,
            self._profile.max_delay_seconds
        )
        
        # إضافة jitter
        jitter = base_delay * self._profile.jitter_percent
        actual_delay = base_delay + random.uniform(-jitter, jitter)
        
        return max(0, actual_delay)
    
    def can_make_request(self, target: str) -> bool:
        """
        التحقق من إمكانية إرسال طلب جديد.
        
        Args:
            target: الهدف
            
        Returns:
            True إذا مسموح
        """
        import time
        current_minute = int(time.time() / 60)
        key = f"{target}:{current_minute}"
        
        count = self._request_counts.get(key, 0)
        return count < self._profile.max_requests_per_minute
    
    def record_request(self, target: str) -> None:
        """تسجيل طلب جديد."""
        import time
        current_minute = int(time.time() / 60)
        key = f"{target}:{current_minute}"
        
        self._request_counts[key] = self._request_counts.get(key, 0) + 1
        self._last_request_times[target] = time.time()
    
    def is_technique_allowed(self, technique: str) -> bool:
        """التحقق من السماح بتقنية معينة."""
        if technique in self._profile.blocked_techniques:
            return False
        
        if self._profile.allowed_techniques:
            return technique in self._profile.allowed_techniques
        
        return True
    
    def should_use_evasion(self) -> bool:
        """هل يجب استخدام تقنيات التجنب؟"""
        return self._profile.use_evasion
    
    def should_encode_payload(self) -> bool:
        """هل يجب ترميز الحمولة؟"""
        return self._profile.encode_payloads
    
    def get_user_agent(self) -> str:
        """الحصول على User-Agent."""
        if not self._profile.randomize_user_agent:
            return "RAGLOX/3.0"
        
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101",
        ]
        return random.choice(agents)
    
    def is_good_time_to_operate(self) -> bool:
        """هل هذا وقت مناسب للعمل؟"""
        from datetime import datetime
        now = datetime.now()
        hour = now.hour
        
        if self._profile.work_hours_only:
            # ساعات العمل: 9-18
            if hour < 9 or hour >= 18:
                return False
        
        if self._profile.avoid_peak_hours:
            # تجنب أوقات الذروة: 9-10 و 14-15
            if hour in [9, 10, 14, 15]:
                return False
        
        return True
    
    def get_execution_context(self) -> Dict[str, Any]:
        """الحصول على سياق التنفيذ للمكونات الأخرى."""
        return {
            "profile_name": self._profile.name,
            "stealth_level": self._profile.level.value,
            "use_evasion": self._profile.use_evasion,
            "encode_payloads": self._profile.encode_payloads,
            "avoid_signatures": self._profile.avoid_signatures,
            "max_requests_per_minute": self._profile.max_requests_per_minute,
            "delay_range": (self._profile.min_delay_seconds, self._profile.max_delay_seconds)
        }
```

---

## 🔧 التعديلات المقترحة على المكونات الحالية

### تعديلات AnalysisSpecialist

```python
# ═══════════════════════════════════════════════════════════
# التعديل 1: قراءة _analysis_history في القرارات
# ═══════════════════════════════════════════════════════════

# في analysis.py، تعديل _make_decision

async def _make_decision(self, ...):
    """
    اتخاذ القرار مع الاستفادة من التاريخ التحليلي.
    
    التغيير: الآن نقرأ _analysis_history قبل اتخاذ القرار!
    """
    # جديد: استشارة التاريخ أولاً
    historical_insight = self._get_historical_insight(
        category=category,
        vuln_type=context.get("vuln_info", {}).get("type"),
        target_os=self._get_target_platform(context["target_info"])
    )
    
    if historical_insight and historical_insight["confidence"] == "high":
        self.logger.info(f"[HISTORY] Using learned pattern: {historical_insight['recommendation']}")
        # تطبيق التوصية من التاريخ
        return self._apply_historical_insight(historical_insight, context, strategy)
    
    # باقي الكود الحالي...
    # ...

def _get_historical_insight(
    self,
    category: str,
    vuln_type: Optional[str],
    target_os: Optional[str]
) -> Optional[Dict]:
    """
    استخلاص رؤى من التاريخ التحليلي.
    
    هذه الدالة الجديدة تقرأ من _analysis_history!
    """
    if len(self._analysis_history) < 3:
        return None  # بيانات غير كافية
    
    # فلترة التجارب المشابهة
    similar = [
        record for record in self._analysis_history[-50:]  # آخر 50 تجربة
        if record.get("category") == category
    ]
    
    if vuln_type:
        similar = [r for r in similar if r.get("vuln_type") == vuln_type] or similar
    
    if len(similar) < 3:
        return None
    
    # تحليل الأنماط
    decisions = [r.get("decision") for r in similar]
    most_common = max(set(decisions), key=decisions.count)
    frequency = decisions.count(most_common) / len(decisions)
    
    if frequency >= 0.6:  # 60%+ تكرار
        return {
            "confidence": "high" if frequency >= 0.8 else "medium",
            "recommendation": most_common,
            "frequency": frequency,
            "sample_size": len(similar),
            "reasoning": f"Historical pattern: {most_common} worked in {frequency:.0%} of similar cases"
        }
    
    return None

def _apply_historical_insight(
    self,
    insight: Dict,
    context: Dict,
    strategy: Dict
) -> Dict:
    """تطبيق الرؤية التاريخية كقرار."""
    decision_type = insight["recommendation"]
    
    base_decision = {
        "decision": decision_type,
        "reasoning": insight["reasoning"],
        "recommendations": strategy["recommendations"],
        "decision_source": "historical_learning",
        "confidence": insight["confidence"],
        "sample_size": insight["sample_size"]
    }
    
    # إضافة تفاصيل حسب نوع القرار
    if decision_type == "modify_approach" and context.get("alternative_modules"):
        base_decision["new_module"] = context["alternative_modules"][0].get("rx_module_id")
        self._stats["modifications_recommended"] += 1
    elif decision_type == "retry":
        base_decision["delay_seconds"] = strategy["retry_delay"]
        self._stats["retries_recommended"] += 1
    elif decision_type == "skip":
        self._stats["skips_recommended"] += 1
    elif decision_type == "escalate":
        self._stats["escalations"] += 1
    
    return base_decision
```

### تعديلات ReconSpecialist

```python
# ═══════════════════════════════════════════════════════════
# التعديل 1: إزالة المنافذ الثابتة واستبدالها بالديناميكية
# ═══════════════════════════════════════════════════════════

# في recon.py، تعديل __init__

def __init__(self, ...):
    # ...
    
    # بدلاً من:
    # self._common_ports = [21, 22, 23, ...]  # ثابت!
    
    # الجديد: منافذ ديناميكية حسب السياق
    self._port_profiles = {
        "quick": [22, 80, 443, 445, 3389],
        "standard": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080],
        "comprehensive": list(range(1, 1025)) + [3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017],
        "stealth": [22, 80, 443],  # الحد الأدنى للتخفي
    }
    
    # المنافذ تُحدد بناءً على الملف الشخصي
    self._active_port_profile = "standard"
    
    # مدير التخفي (جديد)
    self._stealth_manager: Optional[StealthManager] = None

@property
def common_ports(self) -> List[int]:
    """المنافذ الحالية بناءً على الملف الشخصي."""
    return self._port_profiles.get(self._active_port_profile, self._port_profiles["standard"])

def set_stealth_manager(self, manager: StealthManager) -> None:
    """تعيين مدير التخفي وتعديل الملف الشخصي."""
    self._stealth_manager = manager
    
    # تعديل المنافذ حسب مستوى التخفي
    level = manager.profile.level
    if level == StealthLevel.SILENT:
        self._active_port_profile = "stealth"
    elif level == StealthLevel.QUIET:
        self._active_port_profile = "quick"
    elif level == StealthLevel.AGGRESSIVE:
        self._active_port_profile = "comprehensive"
    else:
        self._active_port_profile = "standard"

# ═══════════════════════════════════════════════════════════
# التعديل 2: تكامل مع Intelligence Coordinator
# ═══════════════════════════════════════════════════════════

async def _execute_service_enum(self, task: Dict[str, Any]) -> Dict[str, Any]:
    """
    تعداد الخدمات مع التنسيق الذكي.
    
    التغيير: إرسال النتائج إلى Intelligence Coordinator!
    """
    # ... الكود الحالي لاكتشاف الخدمات ...
    
    # جديد: إرسال للتحليل الاستراتيجي
    if self._intelligence_coordinator:
        strategic_analysis = await self._intelligence_coordinator.process_recon_results(
            mission_id=self._current_mission_id,
            target_id=target_id,
            services=services_found,
            vulnerabilities=await self._get_target_vulns(target_id),
            credentials=await self._get_available_creds(target_id)
        )
        
        # تسجيل التحليل
        self.logger.info(
            f"[STRATEGIC] Target {target_id} value: {strategic_analysis['strategic_value']}, "
            f"Recommended paths: {len(strategic_analysis['recommended_paths'])}"
        )
        
        # إضافة للنتيجة
        result["strategic_analysis"] = strategic_analysis
    
    return result
```

### تعديلات AttackSpecialist

```python
# ═══════════════════════════════════════════════════════════
# التعديل 1: استبدال random.random() ببيانات تاريخية
# ═══════════════════════════════════════════════════════════

# في attack.py، تعديل _simulate_exploit

async def _simulate_exploit(
    self, 
    vuln_type: str, 
    rx_module: Optional[Dict[str, Any]] = None
) -> bool:
    """
    محاكاة الاستغلال باستخدام بيانات تاريخية بدلاً من العشوائية.
    
    التغيير: لا نستخدم random.random() للقرارات الحاسمة!
    """
    # الحصول على معدل النجاح الديناميكي
    success_rate = await self._get_dynamic_exploit_success_rate(vuln_type, rx_module)
    
    # جديد: استشارة الذاكرة التشغيلية
    if self._operational_memory:
        from ..core.operational_memory import OperationalContext
        
        memory_rate, sample_count = await self._operational_memory.get_success_rate_for_context(
            context=OperationalContext.EXPLOIT,
            vuln_type=vuln_type
        )
        
        if sample_count >= 5:  # بيانات كافية
            # ترجيح الذاكرة على التقدير
            success_rate = (success_rate * 0.3) + (memory_rate * 0.7)
            self.logger.info(
                f"[MEMORY] Exploit success rate adjusted by history: "
                f"{success_rate:.2f} (from {sample_count} samples)"
            )
    
    # تأخير المحاكاة
    await asyncio.sleep(0.5)
    
    # القرار النهائي (لا يزال عشوائي لكن مُوجَّه بالبيانات)
    import random
    return random.random() < success_rate

# ═══════════════════════════════════════════════════════════
# التعديل 2: تسجيل كل محاولة في الذاكرة التشغيلية
# ═══════════════════════════════════════════════════════════

async def _execute_exploit(self, task: Dict[str, Any]) -> Dict[str, Any]:
    """
    تنفيذ الاستغلال مع التسجيل في الذاكرة.
    
    التغيير: كل محاولة تُسجَّل للتعلم منها!
    """
    # تسجيل قبل التنفيذ
    decision_id = None
    if self._operational_memory:
        from ..core.operational_memory import OperationalContext
        
        decision_id = await self._operational_memory.record_decision(
            mission_id=UUID(self._current_mission_id) if self._current_mission_id else None,
            context=OperationalContext.EXPLOIT,
            decision_type="exploit_attempt",
            decision_source="attack_specialist",
            parameters={
                "vuln_type": vuln.get("type") if vuln else None,
                "rx_module": rx_module,
                "target_id": target_id
            },
            target_info=target,
            vuln_info=vuln
        )
    
    # ... الكود الحالي للاستغلال ...
    
    # تسجيل النتيجة
    if decision_id and self._operational_memory:
        from ..core.operational_memory import DecisionOutcome
        
        await self._operational_memory.update_outcome(
            decision_id=decision_id,
            outcome=DecisionOutcome.SUCCESS if success else DecisionOutcome.FAILURE,
            details={
                "session_id": session_id if success else None,
                "error_context": error_context,
                "execution_mode": execution_mode
            },
            duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
        )
    
    return result

# ═══════════════════════════════════════════════════════════
# التعديل 3: استخدام Strategic Scorer لترتيب الثغرات
# ═══════════════════════════════════════════════════════════

async def prioritize_vulnerabilities(
    self,
    vulnerabilities: List[Dict],
    target: Dict
) -> List[Dict]:
    """
    ترتيب الثغرات باستخدام التقييم الاستراتيجي.
    
    جديد: بدلاً من الترتيب بـ CVSS فقط!
    """
    if not self._strategic_scorer:
        # fallback للترتيب القديم
        return sorted(
            vulnerabilities,
            key=lambda v: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                v.get("severity", "").lower(), 0
            ),
            reverse=True
        )
    
    # الترتيب الاستراتيجي
    ranked = await self._strategic_scorer.rank_vulnerabilities(
        vulnerabilities=vulnerabilities,
        target=target,
        mission_context={"goals": await self._get_mission_goals()}
    )
    
    # تسجيل
    for vuln, score in ranked[:3]:
        self.logger.info(
            f"[STRATEGIC] Vuln {vuln.get('type')}: "
            f"Strategic={score.strategic_score:.2f}, "
            f"Priority={score.recommended_priority}, "
            f"Reason={score.reasoning[0] if score.reasoning else 'N/A'}"
        )
    
    return [vuln for vuln, _ in ranked]
```

---

## 📅 خارطة الطريق للتنفيذ

### المرحلة 1: الأساسيات (2-3 أسابيع)
- [ ] إنشاء OperationalMemory
- [ ] دمج قراءة _analysis_history في AnalysisSpecialist
- [ ] استبدال random.random() ببيانات تاريخية في AttackSpecialist
- [ ] إضافة تسجيل القرارات في كل محاولة

### المرحلة 2: التنسيق (1-2 شهر)
- [ ] إنشاء IntelligenceCoordinator
- [ ] دمج Strategic Vulnerability Scorer
- [ ] ربط ReconSpecialist بالتحليل الاستراتيجي
- [ ] إنشاء مسارات الهجوم الذكية

### المرحلة 3: التحسين (3+ أشهر)
- [ ] إضافة Stealth Profiles
- [ ] تدريب نموذج LLM متخصص للقرارات الهجومية
- [ ] رسم خريطة الهجوم آلياً
- [ ] تعلم مستمر من كل مهمة

---

## 📊 مقاييس النجاح

| المقياس | الحالي | الهدف |
|---------|--------|-------|
| نسبة الذكاء Agentic | 20% | 60%+ |
| استخدام الذاكرة في القرارات | 0% | 70%+ |
| التعلم من الفشل | لا يوجد | كل فشل يُحلَّل |
| ربط Recon-Attack | ضعيف | ذكي ومنسق |
| تقييم الثغرات | CVSS فقط | استراتيجي متعدد الأبعاد |

---

## 🎯 الخلاصة

هذه الخطة العلاجية:
1. **تحافظ على LLM** - يبقى كمستشار للقرارات المعقدة
2. **تحافظ على Knowledge Base** - تبقى الأساس للبيانات التقنية
3. **تضيف الذاكرة** - التعلم من التجارب السابقة
4. **تضيف التنسيق** - ربط ذكي بين المكونات
5. **تضيف الاستراتيجية** - تقييم يتجاوز CVSS

النتيجة المتوقعة: تحويل RAGLOX من **أداة أتمتة ذكية** إلى **شريك تفكير** حقيقي لفرق Red Team المحترفة.
