# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Operational Memory
# ذاكرة تشغيلية مشتركة للتعلم من التجارب السابقة
#
# المبدأ: كل قرار يُسجَّل، كل فشل يُحلَّل، كل نجاح يُستفاد منه
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from .blackboard import Blackboard


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
    ANALYSIS = "analysis"


@dataclass
class DecisionRecord:
    """سجل قرار واحد"""
    id: UUID = field(default_factory=uuid4)
    mission_id: Optional[UUID] = None
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
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس للتخزين."""
        return {
            "id": str(self.id),
            "mission_id": str(self.mission_id) if self.mission_id else None,
            "timestamp": self.timestamp.isoformat(),
            "context": self.context.value,
            "target_id": self.target_id,
            "vuln_type": self.vuln_type,
            "target_os": self.target_os,
            "target_services": self.target_services,
            "decision_type": self.decision_type,
            "decision_source": self.decision_source,
            "parameters_used": self.parameters_used,
            "outcome": self.outcome.value,
            "outcome_details": self.outcome_details,
            "duration_ms": self.duration_ms,
            "success_factors": self.success_factors,
            "failure_factors": self.failure_factors,
            "lessons_learned": self.lessons_learned,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionRecord":
        """إنشاء من قاموس."""
        return cls(
            id=UUID(data["id"]) if data.get("id") else uuid4(),
            mission_id=UUID(data["mission_id"]) if data.get("mission_id") else None,
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.utcnow(),
            context=OperationalContext(data.get("context", "exploit")),
            target_id=data.get("target_id"),
            vuln_type=data.get("vuln_type"),
            target_os=data.get("target_os"),
            target_services=data.get("target_services", []),
            decision_type=data.get("decision_type", ""),
            decision_source=data.get("decision_source", ""),
            parameters_used=data.get("parameters_used", {}),
            outcome=DecisionOutcome(data.get("outcome", "failure")),
            outcome_details=data.get("outcome_details", {}),
            duration_ms=data.get("duration_ms", 0),
            success_factors=data.get("success_factors", []),
            failure_factors=data.get("failure_factors", []),
            lessons_learned=data.get("lessons_learned", []),
        )


class OperationalMemory:
    """
    الذاكرة التشغيلية للنظام - مركز التعلم التكيفي
    
    المسؤوليات:
    1. تسجيل كل قرار ونتيجته
    2. استخلاص أنماط النجاح والفشل
    3. توفير توصيات مبنية على التجارب السابقة
    4. تحديث احتمالات النجاح ديناميكياً
    
    Usage:
        memory = OperationalMemory(blackboard=bb)
        
        # تسجيل قرار
        decision_id = await memory.record_decision(
            mission_id=mission.id,
            context=OperationalContext.EXPLOIT,
            decision_type="exploit_attempt",
            decision_source="attack_specialist",
            parameters={"module": "ms17_010", "target": "192.168.1.10"}
        )
        
        # تحديث النتيجة
        await memory.update_outcome(
            decision_id=decision_id,
            outcome=DecisionOutcome.SUCCESS,
            details={"session_id": "sess_123"}
        )
        
        # الاستعلام عن تجارب مشابهة
        experiences = await memory.get_similar_experiences(
            context=OperationalContext.EXPLOIT,
            vuln_type="MS17-010"
        )
    """
    
    # TTL للذاكرة قصيرة المدى (ساعة واحدة)
    SHORT_TERM_TTL = timedelta(hours=1)
    
    # TTL للذاكرة طويلة المدى (30 يوم)
    LONG_TERM_TTL = timedelta(days=30)
    
    # الحد الأقصى للسجلات في الذاكرة المحلية
    MAX_LOCAL_RECORDS = 1000
    
    def __init__(
        self,
        blackboard: Optional["Blackboard"] = None,
        redis_client=None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Args:
            blackboard: Blackboard instance للتخزين المشترك
            redis_client: Redis client للتخزين المستمر
            logger: Logger instance
        """
        self._blackboard = blackboard
        self._redis = redis_client
        self.logger = logger or logging.getLogger(__name__)
        
        # ذاكرة محلية (في الـ process)
        self._short_term: Dict[str, DecisionRecord] = {}
        self._pattern_cache: Dict[str, Dict] = {}
        
        # إحصائيات محسوبة
        self._success_rates: Dict[str, float] = defaultdict(lambda: 0.5)
        self._technique_effectiveness: Dict[str, Dict] = {}
        
        # إحصائيات عامة
        self._stats = {
            "total_decisions_recorded": 0,
            "total_outcomes_updated": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }
        
        self.logger.info("OperationalMemory initialized")
    
    # ═══════════════════════════════════════════════════════════
    # التسجيل - كل قرار يُسجَّل
    # ═══════════════════════════════════════════════════════════
    
    async def record_decision(
        self,
        mission_id: Optional[UUID],
        context: OperationalContext,
        decision_type: str,
        decision_source: str,
        parameters: Dict[str, Any],
        target_info: Optional[Dict] = None,
        vuln_info: Optional[Dict] = None
    ) -> UUID:
        """
        تسجيل قرار جديد قبل التنفيذ.
        
        Args:
            mission_id: معرف المهمة
            context: سياق العملية (exploit, recon, etc.)
            decision_type: نوع القرار (exploit_attempt, retry, etc.)
            decision_source: مصدر القرار (llm, rules, memory)
            parameters: البارامترات المستخدمة
            target_info: معلومات الهدف
            vuln_info: معلومات الثغرة
            
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
        self._stats["total_decisions_recorded"] += 1
        
        # تنظيف الذاكرة إذا امتلأت
        if len(self._short_term) > self.MAX_LOCAL_RECORDS:
            await self._cleanup_old_records()
        
        # تخزين في Redis إذا متاح
        if self._redis:
            await self._persist_record(record)
        
        # تسجيل في Blackboard للرؤية
        if self._blackboard and mission_id:
            try:
                await self._blackboard.log_result(
                    str(mission_id),
                    "operational_memory",
                    {
                        "event": "decision_recorded",
                        "decision_id": str(record.id),
                        "context": context.value,
                        "decision_type": decision_type,
                        "decision_source": decision_source,
                    }
                )
            except Exception as e:
                self.logger.debug(f"Failed to log to blackboard: {e}")
        
        self.logger.debug(
            f"Decision recorded: {record.id} - {context.value}/{decision_type} "
            f"from {decision_source}"
        )
        
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
        
        Args:
            decision_id: معرف القرار
            outcome: نتيجة القرار
            details: تفاصيل النتيجة
            duration_ms: مدة التنفيذ بالميلي ثانية
            lessons: الدروس المستفادة
        """
        record_key = str(decision_id)
        
        if record_key not in self._short_term:
            # محاولة استرجاع من Redis
            record = await self._fetch_record(decision_id)
            if not record:
                self.logger.warning(f"Decision record not found: {decision_id}")
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
        
        # إبطال الكاش ذي الصلة
        self._invalidate_cache(record)
        
        # تخزين التحديث
        if self._redis:
            await self._persist_record(record)
        
        self._stats["total_outcomes_updated"] += 1
        
        self.logger.debug(
            f"Outcome updated: {decision_id} - {outcome.value} "
            f"(duration: {duration_ms}ms)"
        )
    
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
        # التحقق من الكاش
        cache_key = f"similar:{context.value}:{target_os or 'any'}:{vuln_type or 'any'}"
        if cache_key in self._pattern_cache:
            cached = self._pattern_cache[cache_key]
            if datetime.utcnow() - cached["timestamp"] < timedelta(minutes=5):
                self._stats["cache_hits"] += 1
                return cached["results"][:limit]
        
        self._stats["cache_misses"] += 1
        matches = []
        
        # بحث في الذاكرة المحلية
        for record in self._short_term.values():
            # تجاهل السجلات بدون نتائج
            if record.outcome == DecisionOutcome.FAILURE and not record.outcome_details:
                continue
            
            score = self._calculate_similarity(record, context, target_os, vuln_type)
            if score > 0.3:  # عتبة التشابه
                matches.append((score, record))
        
        # بحث في Redis إذا لم نجد كفاية
        if len(matches) < limit and self._redis:
            redis_matches = await self._search_redis(context, target_os, vuln_type, limit * 2)
            for record in redis_matches:
                if str(record.id) not in self._short_term:
                    score = self._calculate_similarity(record, context, target_os, vuln_type)
                    if score > 0.3:
                        matches.append((score, record))
        
        # ترتيب بالتشابه ثم بالوقت
        matches.sort(key=lambda x: (x[0], x[1].timestamp), reverse=True)
        
        results = [m[1] for m in matches[:limit]]
        
        # تخزين في الكاش
        self._pattern_cache[cache_key] = {
            "timestamp": datetime.utcnow(),
            "results": results
        }
        
        return results
    
    async def get_success_rate_for_context(
        self,
        context: OperationalContext,
        target_os: Optional[str] = None,
        vuln_type: Optional[str] = None
    ) -> Tuple[float, int]:
        """
        حساب معدل النجاح لسياق معين بناءً على التجارب.
        
        Args:
            context: سياق العملية
            target_os: نظام التشغيل
            vuln_type: نوع الثغرة
            
        Returns:
            (success_rate, sample_count)
        """
        cache_key = f"rate:{context.value}:{target_os or 'any'}:{vuln_type or 'any'}"
        
        # الحصول على التجارب المشابهة
        experiences = await self.get_similar_experiences(
            context, target_os, vuln_type, limit=50
        )
        
        if not experiences:
            return self._success_rates.get(cache_key, 0.5), 0
        
        # حساب معدل النجاح
        successes = sum(1 for e in experiences if e.outcome == DecisionOutcome.SUCCESS)
        rate = successes / len(experiences)
        
        # تخزين في الكاش
        self._success_rates[cache_key] = rate
        
        return rate, len(experiences)
    
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
        
        Args:
            context: سياق العملية
            target_os: نظام التشغيل
            vuln_type: نوع الثغرة
            available_modules: الموديولات المتاحة
            
        Returns:
            Dict مع التوصيات أو None إذا لا توجد بيانات كافية
        """
        experiences = await self.get_similar_experiences(
            context, target_os, vuln_type, limit=20
        )
        
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
                "suggested_action": "escalate_to_llm",
                "sample_size": len(experiences)
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
        
        # تحديد مستوى الثقة
        success_rate = len(successful) / len(experiences)
        if success_rate >= 0.7 and len(successful) >= 5:
            confidence = "high"
        elif success_rate >= 0.5 and len(successful) >= 3:
            confidence = "medium"
        else:
            confidence = "low"
        
        return {
            "confidence": confidence,
            "success_rate": success_rate,
            "recommended_approach": success_patterns[0] if success_patterns else None,
            "alternative_approaches": success_patterns[1:3] if len(success_patterns) > 1 else [],
            "avoid_factors": self._extract_common_factors(failed)[:3],
            "sample_size": len(experiences),
            "successful_count": len(successful),
            "failed_count": len(failed)
        }
    
    async def get_technique_effectiveness(
        self,
        technique_id: str,
        platform: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        الحصول على فعالية تقنية معينة.
        
        Args:
            technique_id: معرف التقنية
            platform: المنصة (windows/linux)
            
        Returns:
            Dict مع إحصائيات الفعالية
        """
        cache_key = f"tech:{technique_id}:{platform or 'any'}"
        
        if cache_key in self._technique_effectiveness:
            cached = self._technique_effectiveness[cache_key]
            if datetime.utcnow() - cached.get("timestamp", datetime.min) < timedelta(minutes=10):
                return cached
        
        # البحث عن تجارب استخدمت هذه التقنية
        relevant = []
        for record in self._short_term.values():
            params = record.parameters_used
            if params.get("technique_id") == technique_id or params.get("module", "").startswith(technique_id):
                if platform is None or record.target_os == platform:
                    relevant.append(record)
        
        if not relevant:
            return {
                "technique_id": technique_id,
                "sample_count": 0,
                "effectiveness": 0.5,
                "confidence": "none"
            }
        
        successes = sum(1 for r in relevant if r.outcome == DecisionOutcome.SUCCESS)
        effectiveness = successes / len(relevant)
        
        result = {
            "technique_id": technique_id,
            "platform": platform,
            "sample_count": len(relevant),
            "success_count": successes,
            "failure_count": len(relevant) - successes,
            "effectiveness": effectiveness,
            "confidence": "high" if len(relevant) >= 10 else "medium" if len(relevant) >= 5 else "low",
            "avg_duration_ms": sum(r.duration_ms for r in relevant) / len(relevant),
            "timestamp": datetime.utcnow()
        }
        
        self._technique_effectiveness[cache_key] = result
        return result
    
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
            target_os_lower = target_os.lower()
            record_os_lower = record.target_os.lower()
            
            if target_os_lower == record_os_lower:
                score += 0.3
            elif ("windows" in target_os_lower) == ("windows" in record_os_lower):
                score += 0.15
            elif ("linux" in target_os_lower) == ("linux" in record_os_lower):
                score += 0.15
        
        # تطابق نوع الثغرة
        if vuln_type and record.vuln_type:
            if vuln_type.upper() == record.vuln_type.upper():
                score += 0.3
            elif vuln_type.split("-")[0].upper() == record.vuln_type.split("-")[0].upper():
                # نفس العائلة (مثل CVE-2021 vs CVE-2021)
                score += 0.15
            elif any(k in vuln_type.lower() for k in ["smb", "rdp", "ssh", "http"]):
                # نفس البروتوكول
                if any(k in record.vuln_type.lower() for k in ["smb", "rdp", "ssh", "http"]):
                    score += 0.1
        
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
            if details.get("stealth_mode"):
                record.success_factors.append("stealth_mode")
            if details.get("credential_based"):
                record.success_factors.append("credential_based")
                
        elif record.outcome == DecisionOutcome.FAILURE:
            # عوامل الفشل
            error_type = details.get("error_type", "unknown")
            record.failure_factors.append(f"error:{error_type}")
            
            if details.get("detected_defenses"):
                for defense in details["detected_defenses"]:
                    record.failure_factors.append(f"defense:{defense}")
            
            if details.get("timeout"):
                record.failure_factors.append("timeout")
            
            if details.get("connection_refused"):
                record.failure_factors.append("connection_refused")
            
            if details.get("auth_failed"):
                record.failure_factors.append("auth_failed")
        
        elif record.outcome == DecisionOutcome.BLOCKED:
            record.failure_factors.append("blocked_by_defense")
            if details.get("defense_type"):
                record.failure_factors.append(f"defense:{details['defense_type']}")
        
        elif record.outcome == DecisionOutcome.TIMEOUT:
            record.failure_factors.append("timeout")
            record.failure_factors.append(f"duration_exceeded:{record.duration_ms}")
    
    def _extract_success_patterns(
        self,
        successful: List[DecisionRecord]
    ) -> List[Dict[str, Any]]:
        """استخلاص أنماط النجاح من التجارب الناجحة."""
        patterns: Dict[str, Dict] = defaultdict(lambda: {
            "count": 0, 
            "factors": [], 
            "parameters": {},
            "avg_duration": 0,
            "total_duration": 0
        })
        
        for record in successful:
            # تجميع بالموديول المستخدم
            module = record.parameters_used.get("module", "default")
            pattern = patterns[module]
            pattern["count"] += 1
            pattern["module"] = module
            pattern["factors"].extend(record.success_factors)
            pattern["total_duration"] += record.duration_ms
            
            # تجميع البارامترات الناجحة
            for key, value in record.parameters_used.items():
                if key not in pattern["parameters"]:
                    pattern["parameters"][key] = []
                if value not in pattern["parameters"][key]:
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
            if p["count"] > 0:
                avg_duration = p["total_duration"] / p["count"]
                result.append({
                    "module": p["module"],
                    "success_count": p["count"],
                    "common_factors": list(set(p["factors"]))[:5],
                    "avg_duration_ms": avg_duration,
                    "recommended_parameters": {
                        k: max(set(v), key=v.count) if v else None
                        for k, v in p["parameters"].items()
                    }
                })
        
        return result
    
    def _extract_common_factors(
        self,
        records: List[DecisionRecord]
    ) -> List[str]:
        """استخلاص العوامل المشتركة من مجموعة سجلات."""
        all_factors = []
        for record in records:
            all_factors.extend(record.failure_factors or record.success_factors)
        
        if not all_factors:
            return []
        
        # عد التكرارات
        factor_counts: Dict[str, int] = defaultdict(int)
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
        context_key = f"rate:{record.context.value}:{record.target_os or 'any'}:{record.vuln_type or 'any'}"
        
        # إبطال معدل النجاح المخزن
        if context_key in self._success_rates:
            del self._success_rates[context_key]
    
    def _invalidate_cache(self, record: DecisionRecord) -> None:
        """إبطال الكاش ذي الصلة بعد تحديث."""
        keys_to_remove = []
        
        for key in self._pattern_cache:
            if record.context.value in key:
                keys_to_remove.append(key)
            if record.target_os and record.target_os in key:
                keys_to_remove.append(key)
            if record.vuln_type and record.vuln_type in key:
                keys_to_remove.append(key)
        
        for key in set(keys_to_remove):
            self._pattern_cache.pop(key, None)
    
    async def _cleanup_old_records(self) -> None:
        """تنظيف السجلات القديمة من الذاكرة المحلية."""
        cutoff = datetime.utcnow() - self.SHORT_TERM_TTL
        
        to_remove = [
            key for key, record in self._short_term.items()
            if record.timestamp < cutoff
        ]
        
        for key in to_remove:
            del self._short_term[key]
        
        if to_remove:
            self.logger.debug(f"Cleaned up {len(to_remove)} old records from memory")
    
    # ═══════════════════════════════════════════════════════════
    # التخزين المستمر (Redis)
    # ═══════════════════════════════════════════════════════════
    
    async def _persist_record(self, record: DecisionRecord) -> None:
        """تخزين سجل في Redis."""
        if not self._redis:
            return
        
        try:
            key = f"opmem:record:{record.id}"
            data = record.to_dict()
            
            # تخزين كـ JSON string
            await self._redis.set(
                key, 
                json.dumps(data),
                ex=int(self.LONG_TERM_TTL.total_seconds())
            )
            
            # إضافة للفهرس
            index_key = f"opmem:index:{record.context.value}"
            await self._redis.zadd(
                index_key, 
                {str(record.id): record.timestamp.timestamp()}
            )
            
        except Exception as e:
            self.logger.error(f"Failed to persist record to Redis: {e}")
    
    async def _fetch_record(self, record_id: UUID) -> Optional[DecisionRecord]:
        """استرجاع سجل من Redis."""
        if not self._redis:
            return None
        
        try:
            key = f"opmem:record:{record_id}"
            data = await self._redis.get(key)
            
            if not data:
                return None
            
            return DecisionRecord.from_dict(json.loads(data))
            
        except Exception as e:
            self.logger.error(f"Failed to fetch record from Redis: {e}")
            return None
    
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
        
        try:
            # البحث في فهرس السياق
            index_key = f"opmem:index:{context.value}"
            record_ids = await self._redis.zrevrange(index_key, 0, limit * 2)
            
            records = []
            for rid in record_ids:
                if isinstance(rid, bytes):
                    rid = rid.decode()
                record = await self._fetch_record(UUID(rid))
                if record:
                    records.append(record)
            
            return records[:limit]
            
        except Exception as e:
            self.logger.error(f"Failed to search Redis: {e}")
            return []
    
    # ═══════════════════════════════════════════════════════════
    # الإحصائيات والتقارير
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """الحصول على إحصائيات الذاكرة."""
        return {
            **self._stats,
            "local_records_count": len(self._short_term),
            "cache_size": len(self._pattern_cache),
            "success_rates_cached": len(self._success_rates),
        }
    
    def clear_cache(self) -> None:
        """مسح الكاش."""
        self._pattern_cache.clear()
        self._success_rates.clear()
        self._technique_effectiveness.clear()
        self.logger.info("Cache cleared")
    
    async def export_records(
        self,
        context: Optional[OperationalContext] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """تصدير السجلات للتحليل."""
        records = []
        
        for record in self._short_term.values():
            if context is None or record.context == context:
                records.append(record.to_dict())
        
        # ترتيب بالوقت
        records.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return records[:limit]


# ═══════════════════════════════════════════════════════════
# Factory functions
# ═══════════════════════════════════════════════════════════

_global_memory: Optional[OperationalMemory] = None


def get_operational_memory() -> OperationalMemory:
    """الحصول على instance عالمي للذاكرة التشغيلية."""
    global _global_memory
    if _global_memory is None:
        _global_memory = OperationalMemory()
    return _global_memory


def init_operational_memory(
    blackboard: Optional["Blackboard"] = None,
    redis_client=None
) -> OperationalMemory:
    """تهيئة الذاكرة التشغيلية العالمية."""
    global _global_memory
    _global_memory = OperationalMemory(
        blackboard=blackboard,
        redis_client=redis_client
    )
    return _global_memory


def reset_operational_memory() -> None:
    """إعادة تعيين الذاكرة التشغيلية العالمية."""
    global _global_memory
    _global_memory = None
