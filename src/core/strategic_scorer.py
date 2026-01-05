# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Strategic Scorer
# نظام التقييم الاستراتيجي للثغرات ومسارات الهجوم
#
# المبدأ: كل ثغرة تُقيَّم بناءً على القيمة الاستراتيجية والسياق التشغيلي
# ═══════════════════════════════════════════════════════════════

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from .blackboard import Blackboard
    from .operational_memory import OperationalMemory, DecisionRecord, DecisionOutcome
    from .knowledge import EmbeddedKnowledge


class RiskLevel(Enum):
    """مستويات المخاطر"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExploitDifficulty(Enum):
    """صعوبة الاستغلال"""
    TRIVIAL = "trivial"       # لا يتطلب تفاعل/تدخل
    EASY = "easy"             # يتطلب تفاعل بسيط
    MODERATE = "moderate"     # يتطلب ظروف معينة
    DIFFICULT = "difficult"   # يتطلب عدة شروط
    EXPERT = "expert"         # يتطلب خبرة متقدمة


class ImpactScope(Enum):
    """نطاق التأثير"""
    LOCAL = "local"           # الجهاز المستهدف فقط
    NETWORK = "network"       # الشبكة المحلية
    DOMAIN = "domain"         # النطاق/المجال
    ENTERPRISE = "enterprise" # المؤسسة كاملة


@dataclass
class VulnerabilityScore:
    """نتيجة تقييم ثغرة"""
    vuln_id: str
    vuln_type: str
    
    # الدرجات الأساسية
    base_score: float = 0.0        # CVSS أو ما يعادله
    strategic_score: float = 0.0   # القيمة الاستراتيجية
    exploit_score: float = 0.0     # قابلية الاستغلال
    memory_score: float = 0.0      # من تجارب سابقة
    
    # الدرجة المركبة
    composite_score: float = 0.0
    
    # المعدِّلات
    modifiers: Dict[str, float] = field(default_factory=dict)
    
    # السياق
    target_os: Optional[str] = None
    target_services: List[str] = field(default_factory=list)
    
    # التحليل
    difficulty: ExploitDifficulty = ExploitDifficulty.MODERATE
    impact_scope: ImpactScope = ImpactScope.LOCAL
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    # التوصيات
    recommended_modules: List[str] = field(default_factory=list)
    recommended_parameters: Dict[str, Any] = field(default_factory=dict)
    
    # الأسباب
    scoring_reasoning: List[str] = field(default_factory=list)
    confidence: str = "medium"  # high, medium, low
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس."""
        return {
            "vuln_id": self.vuln_id,
            "vuln_type": self.vuln_type,
            "base_score": self.base_score,
            "strategic_score": self.strategic_score,
            "exploit_score": self.exploit_score,
            "memory_score": self.memory_score,
            "composite_score": self.composite_score,
            "modifiers": self.modifiers,
            "target_os": self.target_os,
            "target_services": self.target_services,
            "difficulty": self.difficulty.value,
            "impact_scope": self.impact_scope.value,
            "risk_level": self.risk_level.value,
            "recommended_modules": self.recommended_modules,
            "recommended_parameters": self.recommended_parameters,
            "scoring_reasoning": self.scoring_reasoning,
            "confidence": self.confidence,
        }


@dataclass 
class PrioritizedTarget:
    """هدف مُرتَّب بالأولوية"""
    target_id: str
    target_ip: str
    
    # الدرجة الكلية
    priority_score: float = 0.0
    
    # مكونات الدرجة
    attack_surface_score: float = 0.0    # عدد وجودة نقاط الدخول
    strategic_value_score: float = 0.0   # الأهمية الاستراتيجية
    accessibility_score: float = 0.0     # سهولة الوصول
    intelligence_score: float = 0.0      # توفر معلومات الاستخبارات
    
    # الثغرات المرتبة
    ranked_vulnerabilities: List[VulnerabilityScore] = field(default_factory=list)
    
    # المسارات المقترحة
    attack_paths: List[str] = field(default_factory=list)
    
    # الأسباب
    prioritization_reasoning: List[str] = field(default_factory=list)


class StrategicScorer:
    """
    نظام التقييم الاستراتيجي - الدماغ التحليلي للهجمات
    
    المسؤوليات:
    1. تقييم الثغرات بناءً على السياق الاستراتيجي
    2. ترتيب الأهداف حسب الأولوية الذكية
    3. دمج بيانات الذاكرة التشغيلية في التقييم
    4. توفير توصيات مدروسة للهجمات
    
    Usage:
        scorer = StrategicScorer(blackboard=bb, memory=mem, knowledge=kb)
        
        # تقييم ثغرة
        score = await scorer.score_vulnerability(
            vuln_type="CVE-2021-44228",
            target_info={"os": "linux", "services": ["http"]}
        )
        
        # ترتيب الأهداف
        targets = await scorer.prioritize_targets(
            mission_id="mission_123",
            goals=["domain_admin"]
        )
        
        # ترتيب الثغرات لهدف معين
        vulns = await scorer.rank_vulnerabilities_for_target(
            target_id="target_456",
            vulnerabilities=[...],
            mission_goals=["data_exfiltration"]
        )
    """
    
    # ═══════════════════════════════════════════════════════════
    # ثوابت التقييم
    # ═══════════════════════════════════════════════════════════
    
    # أوزان الدرجات في الحساب المركب
    SCORE_WEIGHTS = {
        "base": 0.25,         # CVSS/الدرجة الأساسية
        "strategic": 0.30,    # القيمة الاستراتيجية
        "exploit": 0.25,      # قابلية الاستغلال
        "memory": 0.20,       # من التجارب السابقة
    }
    
    # خدمات عالية القيمة الاستراتيجية
    HIGH_VALUE_SERVICES = {
        "ldap": 0.95,
        "kerberos": 0.95,
        "domain_controller": 1.0,
        "active_directory": 1.0,
        "exchange": 0.85,
        "sharepoint": 0.80,
        "mssql": 0.75,
        "oracle": 0.75,
        "rdp": 0.70,
        "winrm": 0.70,
        "ssh": 0.60,
        "smb": 0.65,
        "ftp": 0.40,
        "http": 0.50,
        "https": 0.55,
    }
    
    # معدِّلات نوع الثغرة
    VULN_TYPE_MODIFIERS = {
        "rce": 1.0,              # Remote Code Execution
        "sqli": 0.85,            # SQL Injection
        "auth_bypass": 0.80,     # Authentication Bypass
        "privesc": 0.75,         # Privilege Escalation
        "lfi": 0.65,             # Local File Inclusion
        "rfi": 0.70,             # Remote File Inclusion
        "ssrf": 0.60,            # Server-Side Request Forgery
        "xxe": 0.55,             # XML External Entity
        "xss": 0.30,             # Cross-Site Scripting
        "info_disclosure": 0.25, # Information Disclosure
    }
    
    # تطابقات CVE المعروفة بالأولوية العالية
    HIGH_PRIORITY_CVES = {
        "CVE-2021-44228": 1.0,   # Log4Shell
        "CVE-2021-4034": 0.95,   # PwnKit
        "CVE-2020-0796": 0.95,   # SMBGhost
        "CVE-2019-0708": 0.90,   # BlueKeep
        "CVE-2017-0144": 0.90,   # EternalBlue
        "CVE-2021-34527": 0.85,  # PrintNightmare
        "CVE-2020-1472": 0.95,   # Zerologon
        "CVE-2021-26855": 0.90,  # ProxyLogon
        "CVE-2021-31207": 0.85,  # ProxyShell
        "CVE-2022-26134": 0.85,  # Confluence RCE
        "CVE-2023-44487": 0.80,  # HTTP/2 Rapid Reset
    }
    
    # معدِّلات صعوبة الاستغلال
    DIFFICULTY_MODIFIERS = {
        ExploitDifficulty.TRIVIAL: 1.0,
        ExploitDifficulty.EASY: 0.85,
        ExploitDifficulty.MODERATE: 0.65,
        ExploitDifficulty.DIFFICULT: 0.45,
        ExploitDifficulty.EXPERT: 0.25,
    }
    
    def __init__(
        self,
        blackboard: Optional["Blackboard"] = None,
        operational_memory: Optional["OperationalMemory"] = None,
        knowledge_base: Optional["EmbeddedKnowledge"] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Args:
            blackboard: Blackboard للوصول للبيانات المشتركة
            operational_memory: ذاكرة التجارب السابقة
            knowledge_base: قاعدة المعرفة
            logger: Logger instance
        """
        self._blackboard = blackboard
        self._memory = operational_memory
        self._knowledge = knowledge_base
        self.logger = logger or logging.getLogger(__name__)
        
        # كاش للتقييمات
        self._score_cache: Dict[str, VulnerabilityScore] = {}
        self._target_cache: Dict[str, PrioritizedTarget] = {}
        
        # إحصائيات
        self._stats = {
            "vulnerabilities_scored": 0,
            "targets_prioritized": 0,
            "cache_hits": 0,
            "memory_consultations": 0,
        }
        
        self.logger.info("StrategicScorer initialized")
    
    # ═══════════════════════════════════════════════════════════
    # تقييم الثغرات
    # ═══════════════════════════════════════════════════════════
    
    async def score_vulnerability(
        self,
        vuln_id: str,
        vuln_type: str,
        target_info: Optional[Dict[str, Any]] = None,
        cvss_score: Optional[float] = None,
        mission_goals: Optional[List[str]] = None,
        use_cache: bool = True
    ) -> VulnerabilityScore:
        """
        تقييم ثغرة بناءً على السياق الاستراتيجي.
        
        Args:
            vuln_id: معرف الثغرة (مثل CVE-2021-44228)
            vuln_type: نوع الثغرة (مثل rce, sqli)
            target_info: معلومات الهدف (os, services)
            cvss_score: درجة CVSS إذا متاحة
            mission_goals: أهداف المهمة الحالية
            use_cache: استخدام الكاش
            
        Returns:
            VulnerabilityScore مع التقييم الكامل
        """
        # التحقق من الكاش
        cache_key = f"{vuln_id}:{vuln_type}:{target_info.get('id') if target_info else 'none'}"
        if use_cache and cache_key in self._score_cache:
            self._stats["cache_hits"] += 1
            return self._score_cache[cache_key]
        
        score = VulnerabilityScore(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            target_os=target_info.get("os") if target_info else None,
            target_services=target_info.get("services", []) if target_info else []
        )
        
        reasoning = []
        
        # 1. الدرجة الأساسية (Base Score)
        score.base_score = await self._calculate_base_score(
            vuln_id, vuln_type, cvss_score, reasoning
        )
        
        # 2. الدرجة الاستراتيجية (Strategic Score)
        score.strategic_score = await self._calculate_strategic_score(
            vuln_id, vuln_type, target_info, mission_goals, reasoning
        )
        
        # 3. درجة قابلية الاستغلال (Exploit Score)
        score.exploit_score, score.difficulty = await self._calculate_exploit_score(
            vuln_id, vuln_type, target_info, reasoning
        )
        
        # 4. درجة الذاكرة (Memory Score)
        if self._memory:
            score.memory_score = await self._calculate_memory_score(
                vuln_type, target_info, reasoning
            )
            self._stats["memory_consultations"] += 1
        else:
            score.memory_score = 0.5  # محايد
        
        # 5. حساب الدرجة المركبة
        score.composite_score = self._calculate_composite_score(score)
        
        # 6. تحديد مستوى المخاطر
        score.risk_level = self._determine_risk_level(score.composite_score)
        
        # 7. تحديد نطاق التأثير
        score.impact_scope = self._determine_impact_scope(vuln_type, target_info)
        
        # 8. استخراج التوصيات
        await self._extract_recommendations(score, target_info)
        
        score.scoring_reasoning = reasoning
        score.confidence = self._determine_confidence(len(reasoning), score.memory_score)
        
        # تخزين في الكاش
        self._score_cache[cache_key] = score
        self._stats["vulnerabilities_scored"] += 1
        
        self.logger.debug(
            f"Scored vulnerability {vuln_id}: composite={score.composite_score:.2f}, "
            f"risk={score.risk_level.value}"
        )
        
        return score
    
    async def _calculate_base_score(
        self,
        vuln_id: str,
        vuln_type: str,
        cvss_score: Optional[float],
        reasoning: List[str]
    ) -> float:
        """حساب الدرجة الأساسية."""
        
        # إذا متاح CVSS
        if cvss_score is not None:
            normalized = cvss_score / 10.0
            reasoning.append(f"Base: CVSS score {cvss_score}/10 = {normalized:.2f}")
            return normalized
        
        # التحقق من CVEs المعروفة
        vuln_upper = vuln_id.upper()
        if vuln_upper in self.HIGH_PRIORITY_CVES:
            score = self.HIGH_PRIORITY_CVES[vuln_upper]
            reasoning.append(f"Base: Known high-priority CVE = {score:.2f}")
            return score
        
        # استخدام نوع الثغرة
        vuln_type_lower = vuln_type.lower()
        for vtype, modifier in self.VULN_TYPE_MODIFIERS.items():
            if vtype in vuln_type_lower:
                reasoning.append(f"Base: Vulnerability type '{vtype}' = {modifier:.2f}")
                return modifier
        
        # افتراضي
        reasoning.append("Base: Unknown type, default = 0.5")
        return 0.5
    
    async def _calculate_strategic_score(
        self,
        vuln_id: str,
        vuln_type: str,
        target_info: Optional[Dict[str, Any]],
        mission_goals: Optional[List[str]],
        reasoning: List[str]
    ) -> float:
        """حساب القيمة الاستراتيجية."""
        
        score = 0.5  # أساس محايد
        
        if target_info:
            services = target_info.get("services", [])
            
            # تقييم الخدمات
            for service in services:
                service_lower = service.lower()
                for svc, value in self.HIGH_VALUE_SERVICES.items():
                    if svc in service_lower:
                        if value > score:
                            score = value
                            reasoning.append(
                                f"Strategic: High-value service '{svc}' = {value:.2f}"
                            )
                        break
            
            # معدِّل Domain Controller
            is_dc = target_info.get("is_domain_controller", False)
            if is_dc or any("dc" in s.lower() or "domain" in s.lower() for s in services):
                score = min(1.0, score + 0.2)
                reasoning.append("Strategic: Domain Controller bonus +0.2")
        
        # تقييم مقابل أهداف المهمة
        if mission_goals:
            goal_bonus = self._evaluate_goal_alignment(vuln_type, mission_goals)
            if goal_bonus > 0:
                score = min(1.0, score + goal_bonus)
                reasoning.append(f"Strategic: Goal alignment bonus +{goal_bonus:.2f}")
        
        return score
    
    def _evaluate_goal_alignment(
        self,
        vuln_type: str,
        mission_goals: List[str]
    ) -> float:
        """تقييم توافق الثغرة مع أهداف المهمة."""
        
        alignment_map = {
            "domain_admin": ["rce", "privesc", "auth_bypass", "kerberos"],
            "data_exfiltration": ["sqli", "lfi", "rce", "auth_bypass"],
            "persistence": ["rce", "webshell", "backdoor"],
            "lateral_movement": ["rce", "smb", "rdp", "auth_bypass"],
            "credential_theft": ["sqli", "auth_bypass", "rce", "mimikatz"],
        }
        
        bonus = 0.0
        vuln_lower = vuln_type.lower()
        
        for goal in mission_goals:
            goal_lower = goal.lower()
            for goal_key, vuln_types in alignment_map.items():
                if goal_key in goal_lower:
                    for vtype in vuln_types:
                        if vtype in vuln_lower:
                            bonus = max(bonus, 0.15)
                            break
        
        return bonus
    
    async def _calculate_exploit_score(
        self,
        vuln_id: str,
        vuln_type: str,
        target_info: Optional[Dict[str, Any]],
        reasoning: List[str]
    ) -> Tuple[float, ExploitDifficulty]:
        """حساب قابلية الاستغلال."""
        
        difficulty = ExploitDifficulty.MODERATE
        
        # تحديد الصعوبة
        vuln_lower = vuln_type.lower()
        
        # تحديد مبني على نوع الثغرة
        if any(t in vuln_lower for t in ["rce", "command_injection"]):
            difficulty = ExploitDifficulty.EASY
        elif any(t in vuln_lower for t in ["sqli", "lfi"]):
            difficulty = ExploitDifficulty.EASY
        elif any(t in vuln_lower for t in ["auth_bypass", "privesc"]):
            difficulty = ExploitDifficulty.MODERATE
        elif any(t in vuln_lower for t in ["deserialization", "ssrf"]):
            difficulty = ExploitDifficulty.DIFFICULT
        elif any(t in vuln_lower for t in ["race_condition", "memory_corruption"]):
            difficulty = ExploitDifficulty.EXPERT
        
        # معدِّل من Knowledge Base
        if self._knowledge:
            kb_reliability = await self._get_kb_reliability(vuln_id, vuln_type)
            if kb_reliability > 0.8:
                # موديول موثوق = أسهل
                if difficulty == ExploitDifficulty.MODERATE:
                    difficulty = ExploitDifficulty.EASY
                elif difficulty == ExploitDifficulty.DIFFICULT:
                    difficulty = ExploitDifficulty.MODERATE
        
        score = self.DIFFICULTY_MODIFIERS[difficulty]
        reasoning.append(f"Exploit: Difficulty '{difficulty.value}' = {score:.2f}")
        
        # معدِّل نظام التشغيل
        if target_info and target_info.get("os"):
            os_lower = target_info["os"].lower()
            if "windows" in os_lower and "server" in os_lower:
                score *= 0.9  # Windows Server أصعب قليلاً
            elif "linux" in os_lower:
                score *= 1.05  # Linux غالباً أسهل للاستغلال
            score = min(1.0, score)
        
        return score, difficulty
    
    async def _get_kb_reliability(
        self,
        vuln_id: str,
        vuln_type: str
    ) -> float:
        """الحصول على موثوقية الموديول من KB."""
        
        try:
            if self._knowledge:
                modules = await self._knowledge.search_modules_for_vulnerability(vuln_type)
                if modules:
                    avg_reliability = sum(m.get("reliability", 0.5) for m in modules) / len(modules)
                    return avg_reliability
        except Exception as e:
            self.logger.warning(f"KB reliability check failed: {e}")
        
        return 0.5
    
    async def _calculate_memory_score(
        self,
        vuln_type: str,
        target_info: Optional[Dict[str, Any]],
        reasoning: List[str]
    ) -> float:
        """حساب الدرجة من الذاكرة التشغيلية."""
        
        if not self._memory:
            return 0.5
        
        try:
            from .operational_memory import OperationalContext
            
            # البحث عن تجارب مشابهة
            experiences = await self._memory.get_similar_experiences(
                context=OperationalContext.EXPLOIT,
                target_os=target_info.get("os") if target_info else None,
                vuln_type=vuln_type,
                limit=20
            )
            
            if not experiences:
                reasoning.append("Memory: No similar experiences, default = 0.5")
                return 0.5
            
            # حساب معدل النجاح
            from .operational_memory import DecisionOutcome
            successes = sum(1 for e in experiences if e.outcome == DecisionOutcome.SUCCESS)
            success_rate = successes / len(experiences)
            
            reasoning.append(
                f"Memory: {successes}/{len(experiences)} successful = {success_rate:.2f}"
            )
            
            return success_rate
            
        except Exception as e:
            self.logger.warning(f"Memory score calculation failed: {e}")
            return 0.5
    
    def _calculate_composite_score(self, score: VulnerabilityScore) -> float:
        """حساب الدرجة المركبة."""
        
        composite = (
            score.base_score * self.SCORE_WEIGHTS["base"] +
            score.strategic_score * self.SCORE_WEIGHTS["strategic"] +
            score.exploit_score * self.SCORE_WEIGHTS["exploit"] +
            score.memory_score * self.SCORE_WEIGHTS["memory"]
        )
        
        # تطبيق المعدِّلات
        for name, modifier in score.modifiers.items():
            composite *= modifier
        
        return min(1.0, max(0.0, composite))
    
    def _determine_risk_level(self, composite_score: float) -> RiskLevel:
        """تحديد مستوى المخاطر."""
        
        if composite_score >= 0.9:
            return RiskLevel.CRITICAL
        elif composite_score >= 0.7:
            return RiskLevel.HIGH
        elif composite_score >= 0.5:
            return RiskLevel.MEDIUM
        elif composite_score >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _determine_impact_scope(
        self,
        vuln_type: str,
        target_info: Optional[Dict[str, Any]]
    ) -> ImpactScope:
        """تحديد نطاق التأثير."""
        
        vuln_lower = vuln_type.lower()
        
        # تحديد من نوع الثغرة
        if any(t in vuln_lower for t in ["domain", "kerberos", "ad", "zerologon"]):
            return ImpactScope.DOMAIN
        
        if any(t in vuln_lower for t in ["smb", "lateral", "worm"]):
            return ImpactScope.NETWORK
        
        if target_info:
            services = target_info.get("services", [])
            if any("domain" in s.lower() or "dc" in s.lower() for s in services):
                return ImpactScope.DOMAIN
            if any("exchange" in s.lower() or "sharepoint" in s.lower() for s in services):
                return ImpactScope.ENTERPRISE
        
        return ImpactScope.LOCAL
    
    async def _extract_recommendations(
        self,
        score: VulnerabilityScore,
        target_info: Optional[Dict[str, Any]]
    ) -> None:
        """استخراج التوصيات للاستغلال."""
        
        recommendations = []
        
        # من Knowledge Base
        if self._knowledge:
            try:
                modules = await self._knowledge.search_modules_for_vulnerability(score.vuln_type)
                if modules:
                    # ترتيب بالموثوقية
                    sorted_modules = sorted(
                        modules,
                        key=lambda m: m.get("reliability", 0),
                        reverse=True
                    )
                    recommendations = [m.get("name", "") for m in sorted_modules[:3]]
            except Exception as e:
                self.logger.warning(f"KB recommendation extraction failed: {e}")
        
        # من الذاكرة
        if self._memory:
            try:
                from .operational_memory import OperationalContext
                best_approach = await self._memory.get_best_approach_for_context(
                    context=OperationalContext.EXPLOIT,
                    target_os=score.target_os,
                    vuln_type=score.vuln_type
                )
                
                if best_approach and best_approach.get("recommended_approach"):
                    rec_module = best_approach["recommended_approach"].get("module")
                    if rec_module and rec_module not in recommendations:
                        recommendations.insert(0, rec_module)
                    
                    score.recommended_parameters = best_approach["recommended_approach"].get(
                        "recommended_parameters", {}
                    )
            except Exception as e:
                self.logger.warning(f"Memory recommendation extraction failed: {e}")
        
        score.recommended_modules = recommendations[:5]
    
    def _determine_confidence(self, reasoning_count: int, memory_score: float) -> str:
        """تحديد مستوى الثقة في التقييم."""
        
        if reasoning_count >= 5 and memory_score != 0.5:
            return "high"
        elif reasoning_count >= 3:
            return "medium"
        else:
            return "low"
    
    # ═══════════════════════════════════════════════════════════
    # ترتيب الأهداف
    # ═══════════════════════════════════════════════════════════
    
    async def prioritize_targets(
        self,
        mission_id: str,
        targets: List[Dict[str, Any]],
        vulnerabilities: Dict[str, List[Dict[str, Any]]],
        mission_goals: Optional[List[str]] = None
    ) -> List[PrioritizedTarget]:
        """
        ترتيب الأهداف حسب الأولوية الاستراتيجية.
        
        Args:
            mission_id: معرف المهمة
            targets: قائمة الأهداف
            vulnerabilities: خريطة الثغرات لكل هدف
            mission_goals: أهداف المهمة
            
        Returns:
            قائمة PrioritizedTarget مرتبة بالأولوية
        """
        prioritized = []
        
        for target in targets:
            target_id = target.get("id", "")
            target_ip = target.get("ip", "")
            
            pt = PrioritizedTarget(
                target_id=target_id,
                target_ip=target_ip
            )
            
            reasoning = []
            
            # 1. Attack Surface Score
            target_vulns = vulnerabilities.get(target_id, [])
            pt.attack_surface_score = self._calculate_attack_surface(
                target, target_vulns, reasoning
            )
            
            # 2. Strategic Value Score
            pt.strategic_value_score = self._calculate_target_value(
                target, mission_goals, reasoning
            )
            
            # 3. Accessibility Score
            pt.accessibility_score = self._calculate_accessibility(
                target, reasoning
            )
            
            # 4. Intelligence Score
            if self._memory:
                pt.intelligence_score = await self._calculate_intelligence_score(
                    target, reasoning
                )
            else:
                pt.intelligence_score = 0.5
            
            # 5. حساب الدرجة الكلية
            pt.priority_score = (
                pt.attack_surface_score * 0.30 +
                pt.strategic_value_score * 0.35 +
                pt.accessibility_score * 0.20 +
                pt.intelligence_score * 0.15
            )
            
            # 6. تقييم الثغرات
            for vuln in target_vulns:
                vuln_score = await self.score_vulnerability(
                    vuln_id=vuln.get("id", ""),
                    vuln_type=vuln.get("type", ""),
                    target_info=target,
                    cvss_score=vuln.get("cvss"),
                    mission_goals=mission_goals
                )
                pt.ranked_vulnerabilities.append(vuln_score)
            
            # ترتيب الثغرات
            pt.ranked_vulnerabilities.sort(
                key=lambda v: v.composite_score,
                reverse=True
            )
            
            pt.prioritization_reasoning = reasoning
            prioritized.append(pt)
        
        # ترتيب الأهداف
        prioritized.sort(key=lambda t: t.priority_score, reverse=True)
        
        self._stats["targets_prioritized"] += len(prioritized)
        
        self.logger.info(
            f"Prioritized {len(prioritized)} targets for mission {mission_id}"
        )
        
        return prioritized
    
    def _calculate_attack_surface(
        self,
        target: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        reasoning: List[str]
    ) -> float:
        """حساب سطح الهجوم."""
        
        score = 0.0
        
        # عدد المنافذ المفتوحة
        ports = target.get("ports", [])
        port_score = min(1.0, len(ports) * 0.05)
        score += port_score * 0.3
        
        # عدد الثغرات
        vuln_count = len(vulnerabilities)
        vuln_score = min(1.0, vuln_count * 0.1)
        score += vuln_score * 0.4
        
        # جودة الثغرات (حسب الشدة)
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity") == "high")
        quality_score = min(1.0, (critical * 0.3 + high * 0.15))
        score += quality_score * 0.3
        
        reasoning.append(
            f"Attack Surface: {len(ports)} ports, {vuln_count} vulns, "
            f"{critical} critical = {score:.2f}"
        )
        
        return min(1.0, score)
    
    def _calculate_target_value(
        self,
        target: Dict[str, Any],
        mission_goals: Optional[List[str]],
        reasoning: List[str]
    ) -> float:
        """حساب القيمة الاستراتيجية للهدف."""
        
        score = 0.3  # أساس
        
        services = target.get("services", [])
        
        # تقييم الخدمات
        for service in services:
            service_lower = service.lower() if isinstance(service, str) else str(service).lower()
            for svc_name, svc_value in self.HIGH_VALUE_SERVICES.items():
                if svc_name in service_lower:
                    score = max(score, svc_value)
                    break
        
        # معدِّل Domain Controller
        if target.get("is_domain_controller"):
            score = 1.0
            reasoning.append("Target Value: Domain Controller = 1.0")
            return score
        
        # توافق مع الأهداف
        if mission_goals:
            if "domain_admin" in mission_goals and any(
                "ldap" in str(s).lower() or "kerberos" in str(s).lower()
                for s in services
            ):
                score = min(1.0, score + 0.2)
        
        reasoning.append(f"Target Value: Services assessment = {score:.2f}")
        
        return score
    
    def _calculate_accessibility(
        self,
        target: Dict[str, Any],
        reasoning: List[str]
    ) -> float:
        """حساب سهولة الوصول."""
        
        score = 0.5
        
        # الوصول المباشر
        if target.get("direct_access"):
            score = 0.8
        
        # خلف جدار ناري
        if target.get("behind_firewall"):
            score *= 0.6
        
        # وجود جلسة سابقة
        if target.get("has_session"):
            score = min(1.0, score + 0.3)
        
        reasoning.append(f"Accessibility: {score:.2f}")
        
        return score
    
    async def _calculate_intelligence_score(
        self,
        target: Dict[str, Any],
        reasoning: List[str]
    ) -> float:
        """حساب توفر معلومات الاستخبارات."""
        
        if not self._memory:
            return 0.5
        
        try:
            from .operational_memory import OperationalContext
            
            experiences = await self._memory.get_similar_experiences(
                context=OperationalContext.EXPLOIT,
                target_os=target.get("os"),
                limit=10
            )
            
            if experiences:
                # كلما زادت التجارب، زادت المعلومات
                score = min(1.0, 0.3 + len(experiences) * 0.07)
                reasoning.append(
                    f"Intelligence: {len(experiences)} related experiences = {score:.2f}"
                )
                return score
            
        except Exception as e:
            self.logger.warning(f"Intelligence score calculation failed: {e}")
        
        reasoning.append("Intelligence: No data, default = 0.5")
        return 0.5
    
    # ═══════════════════════════════════════════════════════════
    # ترتيب الثغرات لهدف معين
    # ═══════════════════════════════════════════════════════════
    
    async def rank_vulnerabilities_for_target(
        self,
        target_id: str,
        target_info: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        mission_goals: Optional[List[str]] = None
    ) -> List[VulnerabilityScore]:
        """
        ترتيب الثغرات لهدف معين.
        
        Args:
            target_id: معرف الهدف
            target_info: معلومات الهدف
            vulnerabilities: قائمة الثغرات
            mission_goals: أهداف المهمة
            
        Returns:
            قائمة VulnerabilityScore مرتبة بالأولوية
        """
        scores = []
        
        for vuln in vulnerabilities:
            score = await self.score_vulnerability(
                vuln_id=vuln.get("id", ""),
                vuln_type=vuln.get("type", ""),
                target_info=target_info,
                cvss_score=vuln.get("cvss"),
                mission_goals=mission_goals
            )
            scores.append(score)
        
        # ترتيب بالدرجة المركبة
        scores.sort(key=lambda s: s.composite_score, reverse=True)
        
        self.logger.debug(
            f"Ranked {len(scores)} vulnerabilities for target {target_id}"
        )
        
        return scores
    
    # ═══════════════════════════════════════════════════════════
    # الحساب السريع (بدون تفاصيل)
    # ═══════════════════════════════════════════════════════════
    
    async def quick_score(
        self,
        vuln_type: str,
        target_os: Optional[str] = None
    ) -> float:
        """
        تقييم سريع للثغرة - للاستخدام في حلقات التكرار.
        
        Args:
            vuln_type: نوع الثغرة
            target_os: نظام التشغيل
            
        Returns:
            درجة من 0 إلى 1
        """
        cache_key = f"quick:{vuln_type}:{target_os or 'any'}"
        
        if cache_key in self._score_cache:
            return self._score_cache[cache_key].composite_score
        
        # تقييم أساسي سريع
        score = 0.5
        
        vuln_lower = vuln_type.lower()
        
        # نوع الثغرة
        for vtype, modifier in self.VULN_TYPE_MODIFIERS.items():
            if vtype in vuln_lower:
                score = modifier
                break
        
        # معدِّل من الذاكرة (إذا متاحة وسريعة)
        if self._memory and vuln_type in self._memory._success_rates:
            memory_rate = self._memory._success_rates[vuln_type]
            score = (score + memory_rate) / 2
        
        return min(1.0, max(0.0, score))
    
    # ═══════════════════════════════════════════════════════════
    # المرافق والإحصائيات
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """الحصول على إحصائيات المقيِّم."""
        return {
            **self._stats,
            "cache_size": len(self._score_cache),
            "target_cache_size": len(self._target_cache),
        }
    
    def clear_cache(self) -> None:
        """مسح الكاش."""
        self._score_cache.clear()
        self._target_cache.clear()
        self.logger.info("StrategicScorer cache cleared")
    
    async def get_dynamic_success_rate(
        self,
        vuln_type: str,
        target_os: Optional[str] = None,
        module_name: Optional[str] = None
    ) -> float:
        """
        حساب معدل نجاح ديناميكي - بديل لـ random.random() في AttackSpecialist.
        
        هذه الدالة هي المدخل الرئيسي لاستبدال العشوائية بالذكاء!
        
        Args:
            vuln_type: نوع الثغرة
            target_os: نظام التشغيل
            module_name: اسم الموديول
            
        Returns:
            معدل نجاح من 0 إلى 1
        """
        # أساس من نوع الثغرة
        base_rate = await self.quick_score(vuln_type, target_os)
        
        # معدِّل من KB
        kb_modifier = 1.0
        if self._knowledge and module_name:
            try:
                reliability = await self._get_kb_reliability(module_name, vuln_type)
                kb_modifier = 0.8 + (reliability * 0.4)  # 0.8 - 1.2
            except Exception:
                pass
        
        # معدِّل من الذاكرة
        memory_modifier = 1.0
        if self._memory:
            try:
                from .operational_memory import OperationalContext
                rate, count = await self._memory.get_success_rate_for_context(
                    context=OperationalContext.EXPLOIT,
                    target_os=target_os,
                    vuln_type=vuln_type
                )
                if count >= 3:
                    memory_modifier = 0.8 + (rate * 0.4)  # 0.8 - 1.2
            except Exception:
                pass
        
        final_rate = base_rate * kb_modifier * memory_modifier
        
        return min(1.0, max(0.1, final_rate))  # حد أدنى 10%
