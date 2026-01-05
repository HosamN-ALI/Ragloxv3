# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Stealth Profiles
# نظام ملفات التخفي لإدارة سلوك العمليات الصامتة
#
# المبدأ: كل عملية لها بصمة، إدارة البصمة جزء من الذكاء
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from .blackboard import Blackboard
    from .operational_memory import OperationalMemory


class StealthLevel(Enum):
    """مستويات التخفي"""
    PARANOID = "paranoid"       # أقصى تخفي - بطيء جداً
    COVERT = "covert"           # تخفي عالي - بطيء
    NORMAL = "normal"           # متوازن
    AGGRESSIVE = "aggressive"   # سريع - أقل تخفي
    LOUD = "loud"               # لا تخفي - للتدريب فقط


class DetectionRisk(Enum):
    """مستويات خطر الاكتشاف"""
    CRITICAL = "critical"   # اكتشاف مؤكد تقريباً
    HIGH = "high"           # احتمالية عالية
    MEDIUM = "medium"       # احتمالية متوسطة
    LOW = "low"             # احتمالية منخفضة
    MINIMAL = "minimal"     # شبه معدوم


class DefenseType(Enum):
    """أنواع الدفاعات"""
    EDR = "edr"                     # Endpoint Detection & Response
    AV = "antivirus"                # مضاد الفيروسات
    IDS = "ids"                     # Intrusion Detection System
    IPS = "ips"                     # Intrusion Prevention System
    SIEM = "siem"                   # Security Information & Event Management
    FIREWALL = "firewall"           # جدار ناري
    DLP = "dlp"                     # Data Loss Prevention
    HONEYPOT = "honeypot"           # فخاخ الاكتشاف
    WAF = "waf"                     # Web Application Firewall
    SANDBOX = "sandbox"             # بيئة عزل


@dataclass
class DefenseProfile:
    """ملف الدفاعات المكتشفة"""
    target_id: str
    detected_defenses: List[DefenseType] = field(default_factory=list)
    confidence_levels: Dict[str, float] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    # أنماط السلوك المكتشفة
    detection_patterns: List[Dict[str, Any]] = field(default_factory=list)
    
    # التوصيات
    evasion_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس."""
        return {
            "target_id": self.target_id,
            "detected_defenses": [d.value for d in self.detected_defenses],
            "confidence_levels": self.confidence_levels,
            "last_updated": self.last_updated.isoformat(),
            "detection_patterns": self.detection_patterns,
            "evasion_recommendations": self.evasion_recommendations,
        }


@dataclass
class StealthParameters:
    """معاملات التخفي للعملية"""
    # التوقيت
    min_delay_ms: int = 0
    max_delay_ms: int = 0
    jitter_percent: float = 0.0
    
    # حدود العمليات
    max_concurrent_operations: int = 10
    max_operations_per_minute: int = 60
    max_failed_attempts: int = 5
    
    # تقنيات التخفي
    use_encoding: bool = False
    encoding_type: Optional[str] = None
    use_fragmentation: bool = False
    fragment_size: int = 0
    use_encryption: bool = False
    
    # التهرب
    rotate_user_agents: bool = False
    randomize_headers: bool = False
    use_proxy_chain: bool = False
    
    # السلوك
    mimic_normal_traffic: bool = False
    avoid_peak_hours: bool = False
    cleanup_artifacts: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس."""
        return {
            "timing": {
                "min_delay_ms": self.min_delay_ms,
                "max_delay_ms": self.max_delay_ms,
                "jitter_percent": self.jitter_percent,
            },
            "limits": {
                "max_concurrent_operations": self.max_concurrent_operations,
                "max_operations_per_minute": self.max_operations_per_minute,
                "max_failed_attempts": self.max_failed_attempts,
            },
            "techniques": {
                "use_encoding": self.use_encoding,
                "encoding_type": self.encoding_type,
                "use_fragmentation": self.use_fragmentation,
                "fragment_size": self.fragment_size,
                "use_encryption": self.use_encryption,
            },
            "evasion": {
                "rotate_user_agents": self.rotate_user_agents,
                "randomize_headers": self.randomize_headers,
                "use_proxy_chain": self.use_proxy_chain,
            },
            "behavior": {
                "mimic_normal_traffic": self.mimic_normal_traffic,
                "avoid_peak_hours": self.avoid_peak_hours,
                "cleanup_artifacts": self.cleanup_artifacts,
            },
        }


@dataclass
class OperationFootprint:
    """بصمة عملية"""
    operation_id: UUID = field(default_factory=uuid4)
    operation_type: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # التفاصيل
    target_id: str = ""
    source_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    
    # البصمة
    packet_count: int = 0
    bytes_transferred: int = 0
    duration_ms: int = 0
    
    # المؤشرات
    indicators: List[str] = field(default_factory=list)
    
    # خطر الاكتشاف
    detection_risk: DetectionRisk = DetectionRisk.MEDIUM


# ═══════════════════════════════════════════════════════════════
# ملفات التخفي المُعدَّة مسبقاً
# ═══════════════════════════════════════════════════════════════

STEALTH_PROFILES: Dict[StealthLevel, StealthParameters] = {
    StealthLevel.PARANOID: StealthParameters(
        min_delay_ms=30000,     # 30 ثانية
        max_delay_ms=120000,    # 2 دقيقة
        jitter_percent=50.0,
        max_concurrent_operations=1,
        max_operations_per_minute=2,
        max_failed_attempts=1,
        use_encoding=True,
        encoding_type="base64_custom",
        use_fragmentation=True,
        fragment_size=64,
        use_encryption=True,
        rotate_user_agents=True,
        randomize_headers=True,
        use_proxy_chain=True,
        mimic_normal_traffic=True,
        avoid_peak_hours=True,
        cleanup_artifacts=True,
    ),
    
    StealthLevel.COVERT: StealthParameters(
        min_delay_ms=5000,      # 5 ثواني
        max_delay_ms=30000,     # 30 ثانية
        jitter_percent=30.0,
        max_concurrent_operations=2,
        max_operations_per_minute=10,
        max_failed_attempts=2,
        use_encoding=True,
        encoding_type="base64",
        use_fragmentation=True,
        fragment_size=256,
        use_encryption=True,
        rotate_user_agents=True,
        randomize_headers=True,
        use_proxy_chain=False,
        mimic_normal_traffic=True,
        avoid_peak_hours=False,
        cleanup_artifacts=True,
    ),
    
    StealthLevel.NORMAL: StealthParameters(
        min_delay_ms=1000,      # 1 ثانية
        max_delay_ms=5000,      # 5 ثواني
        jitter_percent=20.0,
        max_concurrent_operations=5,
        max_operations_per_minute=30,
        max_failed_attempts=3,
        use_encoding=True,
        encoding_type="base64",
        use_fragmentation=False,
        fragment_size=0,
        use_encryption=False,
        rotate_user_agents=True,
        randomize_headers=False,
        use_proxy_chain=False,
        mimic_normal_traffic=False,
        avoid_peak_hours=False,
        cleanup_artifacts=True,
    ),
    
    StealthLevel.AGGRESSIVE: StealthParameters(
        min_delay_ms=100,       # 100 مللي ثانية
        max_delay_ms=1000,      # 1 ثانية
        jitter_percent=10.0,
        max_concurrent_operations=10,
        max_operations_per_minute=120,
        max_failed_attempts=5,
        use_encoding=False,
        encoding_type=None,
        use_fragmentation=False,
        fragment_size=0,
        use_encryption=False,
        rotate_user_agents=False,
        randomize_headers=False,
        use_proxy_chain=False,
        mimic_normal_traffic=False,
        avoid_peak_hours=False,
        cleanup_artifacts=True,
    ),
    
    StealthLevel.LOUD: StealthParameters(
        min_delay_ms=0,
        max_delay_ms=100,
        jitter_percent=0.0,
        max_concurrent_operations=50,
        max_operations_per_minute=1000,
        max_failed_attempts=10,
        use_encoding=False,
        encoding_type=None,
        use_fragmentation=False,
        fragment_size=0,
        use_encryption=False,
        rotate_user_agents=False,
        randomize_headers=False,
        use_proxy_chain=False,
        mimic_normal_traffic=False,
        avoid_peak_hours=False,
        cleanup_artifacts=False,
    ),
}


# ═══════════════════════════════════════════════════════════════
# خرائط التهرب من الدفاعات
# ═══════════════════════════════════════════════════════════════

EVASION_TECHNIQUES: Dict[DefenseType, List[Dict[str, Any]]] = {
    DefenseType.EDR: [
        {
            "name": "process_hollowing",
            "description": "حقن في عملية شرعية",
            "effectiveness": 0.7,
            "complexity": "high",
        },
        {
            "name": "parent_pid_spoofing",
            "description": "تزوير العملية الأم",
            "effectiveness": 0.65,
            "complexity": "medium",
        },
        {
            "name": "direct_syscalls",
            "description": "استدعاءات نظام مباشرة",
            "effectiveness": 0.8,
            "complexity": "high",
        },
        {
            "name": "memory_only_execution",
            "description": "تنفيذ في الذاكرة فقط",
            "effectiveness": 0.75,
            "complexity": "medium",
        },
    ],
    
    DefenseType.AV: [
        {
            "name": "payload_encoding",
            "description": "ترميز الحمولة",
            "effectiveness": 0.6,
            "complexity": "low",
        },
        {
            "name": "custom_crypter",
            "description": "تشفير مخصص",
            "effectiveness": 0.8,
            "complexity": "high",
        },
        {
            "name": "signature_mutation",
            "description": "تغيير البصمة",
            "effectiveness": 0.7,
            "complexity": "medium",
        },
        {
            "name": "living_off_the_land",
            "description": "استخدام أدوات النظام",
            "effectiveness": 0.85,
            "complexity": "low",
        },
    ],
    
    DefenseType.IDS: [
        {
            "name": "traffic_fragmentation",
            "description": "تجزئة حركة المرور",
            "effectiveness": 0.6,
            "complexity": "medium",
        },
        {
            "name": "protocol_tunneling",
            "description": "نفق بروتوكولات",
            "effectiveness": 0.7,
            "complexity": "medium",
        },
        {
            "name": "timing_obfuscation",
            "description": "تشويش التوقيت",
            "effectiveness": 0.55,
            "complexity": "low",
        },
        {
            "name": "encrypted_channels",
            "description": "قنوات مشفرة",
            "effectiveness": 0.75,
            "complexity": "medium",
        },
    ],
    
    DefenseType.FIREWALL: [
        {
            "name": "port_hopping",
            "description": "تبديل المنافذ",
            "effectiveness": 0.5,
            "complexity": "low",
        },
        {
            "name": "allowed_port_tunneling",
            "description": "نفق عبر منافذ مسموحة",
            "effectiveness": 0.8,
            "complexity": "medium",
        },
        {
            "name": "dns_tunneling",
            "description": "نفق DNS",
            "effectiveness": 0.75,
            "complexity": "medium",
        },
        {
            "name": "http_tunneling",
            "description": "نفق HTTP/HTTPS",
            "effectiveness": 0.85,
            "complexity": "low",
        },
    ],
    
    DefenseType.WAF: [
        {
            "name": "encoding_bypass",
            "description": "تجاوز بالترميز",
            "effectiveness": 0.55,
            "complexity": "low",
        },
        {
            "name": "parameter_pollution",
            "description": "تلويث المعاملات",
            "effectiveness": 0.6,
            "complexity": "medium",
        },
        {
            "name": "case_manipulation",
            "description": "التلاعب بالحالة",
            "effectiveness": 0.4,
            "complexity": "low",
        },
        {
            "name": "chunked_transfer",
            "description": "نقل مجزأ",
            "effectiveness": 0.65,
            "complexity": "medium",
        },
    ],
}


class StealthManager:
    """
    مدير التخفي - التحكم في السلوك الصامت للعمليات
    
    المسؤوليات:
    1. إدارة مستويات التخفي للمهام
    2. تتبع الدفاعات المكتشفة
    3. توفير توصيات التهرب
    4. مراقبة البصمة التشغيلية
    
    Usage:
        manager = StealthManager(blackboard=bb)
        
        # تحديد معاملات التخفي
        params = manager.get_stealth_parameters(StealthLevel.COVERT)
        
        # تقييم خطر العملية
        risk = await manager.assess_operation_risk(
            operation_type="port_scan",
            target_id="target_123"
        )
        
        # الحصول على توصيات التهرب
        evasion = manager.get_evasion_recommendations(
            defenses=[DefenseType.EDR, DefenseType.AV]
        )
    """
    
    def __init__(
        self,
        blackboard: Optional["Blackboard"] = None,
        operational_memory: Optional["OperationalMemory"] = None,
        default_level: StealthLevel = StealthLevel.NORMAL,
        logger: Optional[logging.Logger] = None
    ):
        """
        Args:
            blackboard: Blackboard للوصول للبيانات المشتركة
            operational_memory: ذاكرة التجارب السابقة
            default_level: مستوى التخفي الافتراضي
            logger: Logger instance
        """
        self._blackboard = blackboard
        self._memory = operational_memory
        self._default_level = default_level
        self.logger = logger or logging.getLogger(__name__)
        
        # المستوى الحالي لكل مهمة
        self._mission_levels: Dict[str, StealthLevel] = {}
        
        # ملفات الدفاعات المكتشفة لكل هدف
        self._defense_profiles: Dict[str, DefenseProfile] = {}
        
        # سجل البصمات
        self._footprint_history: List[OperationFootprint] = []
        
        # عدادات العمليات
        self._operation_counters: Dict[str, int] = defaultdict(int)
        self._last_operation_times: Dict[str, datetime] = {}
        
        # إحصائيات
        self._stats = {
            "operations_regulated": 0,
            "operations_delayed": 0,
            "operations_blocked": 0,
            "detections_recorded": 0,
        }
        
        self.logger.info(f"StealthManager initialized with default level: {default_level.value}")
    
    # ═══════════════════════════════════════════════════════════
    # إدارة مستوى التخفي
    # ═══════════════════════════════════════════════════════════
    
    def get_stealth_parameters(
        self,
        level: Optional[StealthLevel] = None,
        mission_id: Optional[str] = None
    ) -> StealthParameters:
        """
        الحصول على معاملات التخفي.
        
        Args:
            level: مستوى التخفي المطلوب
            mission_id: معرف المهمة لاستخدام مستواها
            
        Returns:
            StealthParameters للمستوى المحدد
        """
        if level is None and mission_id:
            level = self._mission_levels.get(mission_id, self._default_level)
        elif level is None:
            level = self._default_level
        
        return STEALTH_PROFILES[level]
    
    def set_mission_stealth_level(
        self,
        mission_id: str,
        level: StealthLevel
    ) -> None:
        """تعيين مستوى التخفي لمهمة."""
        self._mission_levels[mission_id] = level
        self.logger.info(f"Mission {mission_id} stealth level set to {level.value}")
    
    def get_mission_stealth_level(
        self,
        mission_id: str
    ) -> StealthLevel:
        """الحصول على مستوى تخفي المهمة."""
        return self._mission_levels.get(mission_id, self._default_level)
    
    # ═══════════════════════════════════════════════════════════
    # تنظيم العمليات
    # ═══════════════════════════════════════════════════════════
    
    async def regulate_operation(
        self,
        operation_type: str,
        target_id: str,
        mission_id: Optional[str] = None
    ) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        تنظيم عملية قبل تنفيذها.
        
        Args:
            operation_type: نوع العملية
            target_id: معرف الهدف
            mission_id: معرف المهمة
            
        Returns:
            (can_proceed, delay_ms, reason)
        """
        params = self.get_stealth_parameters(mission_id=mission_id)
        
        # التحقق من حد المحاولات الفاشلة
        failed_key = f"{target_id}:failed"
        if self._operation_counters[failed_key] >= params.max_failed_attempts:
            self._stats["operations_blocked"] += 1
            return (
                False,
                None,
                f"Max failed attempts ({params.max_failed_attempts}) reached for target"
            )
        
        # التحقق من معدل العمليات
        minute_key = f"{target_id}:minute"
        current_minute = datetime.utcnow().replace(second=0, microsecond=0)
        last_minute = self._last_operation_times.get(minute_key)
        
        if last_minute and last_minute == current_minute:
            if self._operation_counters[minute_key] >= params.max_operations_per_minute:
                self._stats["operations_blocked"] += 1
                wait_time = 60 - datetime.utcnow().second
                return (
                    False,
                    wait_time * 1000,
                    f"Rate limit ({params.max_operations_per_minute}/min) reached"
                )
        else:
            # دقيقة جديدة
            self._operation_counters[minute_key] = 0
            self._last_operation_times[minute_key] = current_minute
        
        # حساب التأخير
        import random
        base_delay = random.randint(params.min_delay_ms, params.max_delay_ms)
        
        if params.jitter_percent > 0:
            jitter = base_delay * (params.jitter_percent / 100)
            base_delay += random.randint(int(-jitter), int(jitter))
        
        # تحديث العدادات
        self._operation_counters[minute_key] += 1
        self._stats["operations_regulated"] += 1
        
        if base_delay > 0:
            self._stats["operations_delayed"] += 1
        
        return (True, max(0, base_delay), None)
    
    async def apply_delay(
        self,
        delay_ms: int,
        operation_type: Optional[str] = None
    ) -> None:
        """تطبيق التأخير."""
        if delay_ms > 0:
            self.logger.debug(
                f"Applying {delay_ms}ms delay for operation: {operation_type or 'unknown'}"
            )
            await asyncio.sleep(delay_ms / 1000.0)
    
    def record_operation_failure(
        self,
        target_id: str,
        operation_type: str
    ) -> None:
        """تسجيل فشل عملية."""
        failed_key = f"{target_id}:failed"
        self._operation_counters[failed_key] += 1
    
    def reset_failure_count(self, target_id: str) -> None:
        """إعادة تعيين عداد الفشل."""
        failed_key = f"{target_id}:failed"
        self._operation_counters[failed_key] = 0
    
    # ═══════════════════════════════════════════════════════════
    # تقييم المخاطر
    # ═══════════════════════════════════════════════════════════
    
    async def assess_operation_risk(
        self,
        operation_type: str,
        target_id: str,
        mission_id: Optional[str] = None
    ) -> Tuple[DetectionRisk, List[str]]:
        """
        تقييم خطر اكتشاف العملية.
        
        Args:
            operation_type: نوع العملية
            target_id: معرف الهدف
            mission_id: معرف المهمة
            
        Returns:
            (DetectionRisk, list of risk factors)
        """
        risk_factors = []
        risk_score = 0.0
        
        # 1. خطر نوع العملية
        operation_risks = {
            "port_scan": 0.3,
            "vuln_scan": 0.5,
            "exploit": 0.7,
            "privesc": 0.6,
            "lateral_movement": 0.8,
            "credential_harvest": 0.7,
            "data_exfiltration": 0.9,
        }
        
        op_risk = operation_risks.get(operation_type.lower(), 0.5)
        risk_score += op_risk
        risk_factors.append(f"Operation type '{operation_type}' risk: {op_risk:.2f}")
        
        # 2. خطر الدفاعات المكتشفة
        if target_id in self._defense_profiles:
            profile = self._defense_profiles[target_id]
            defense_count = len(profile.detected_defenses)
            
            if defense_count > 0:
                defense_risk = min(0.5, defense_count * 0.1)
                risk_score += defense_risk
                risk_factors.append(
                    f"Detected {defense_count} defense(s): {defense_risk:.2f}"
                )
                
                # خطر أنواع معينة
                if DefenseType.EDR in profile.detected_defenses:
                    risk_score += 0.15
                    risk_factors.append("EDR detected: +0.15")
                
                if DefenseType.IPS in profile.detected_defenses:
                    risk_score += 0.1
                    risk_factors.append("IPS detected: +0.1")
        
        # 3. خطر السجل التاريخي
        if self._memory:
            try:
                from .operational_memory import OperationalContext, DecisionOutcome
                
                experiences = await self._memory.get_similar_experiences(
                    context=OperationalContext.EXPLOIT,
                    limit=10
                )
                
                blocked = sum(
                    1 for e in experiences
                    if e.outcome == DecisionOutcome.BLOCKED
                )
                
                if blocked > 0:
                    history_risk = min(0.3, blocked * 0.1)
                    risk_score += history_risk
                    risk_factors.append(
                        f"Historical blocks ({blocked}): +{history_risk:.2f}"
                    )
            except Exception as e:
                self.logger.warning(f"Historical risk assessment failed: {e}")
        
        # 4. مستوى التخفي الحالي
        level = self.get_mission_stealth_level(mission_id) if mission_id else self._default_level
        
        level_modifiers = {
            StealthLevel.PARANOID: -0.2,
            StealthLevel.COVERT: -0.1,
            StealthLevel.NORMAL: 0.0,
            StealthLevel.AGGRESSIVE: 0.15,
            StealthLevel.LOUD: 0.3,
        }
        
        level_mod = level_modifiers.get(level, 0.0)
        risk_score += level_mod
        risk_factors.append(f"Stealth level '{level.value}' modifier: {level_mod:+.2f}")
        
        # تحويل إلى مستوى
        risk_score = max(0.0, min(1.0, risk_score / 2))  # تطبيع
        
        if risk_score >= 0.8:
            risk_level = DetectionRisk.CRITICAL
        elif risk_score >= 0.6:
            risk_level = DetectionRisk.HIGH
        elif risk_score >= 0.4:
            risk_level = DetectionRisk.MEDIUM
        elif risk_score >= 0.2:
            risk_level = DetectionRisk.LOW
        else:
            risk_level = DetectionRisk.MINIMAL
        
        return (risk_level, risk_factors)
    
    # ═══════════════════════════════════════════════════════════
    # إدارة الدفاعات
    # ═══════════════════════════════════════════════════════════
    
    def record_detected_defense(
        self,
        target_id: str,
        defense_type: DefenseType,
        confidence: float = 0.8,
        detection_pattern: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        تسجيل دفاع مكتشف.
        
        Args:
            target_id: معرف الهدف
            defense_type: نوع الدفاع
            confidence: مستوى الثقة
            detection_pattern: نمط الاكتشاف
        """
        if target_id not in self._defense_profiles:
            self._defense_profiles[target_id] = DefenseProfile(target_id=target_id)
        
        profile = self._defense_profiles[target_id]
        
        if defense_type not in profile.detected_defenses:
            profile.detected_defenses.append(defense_type)
        
        profile.confidence_levels[defense_type.value] = confidence
        profile.last_updated = datetime.utcnow()
        
        if detection_pattern:
            profile.detection_patterns.append(detection_pattern)
        
        # تحديث التوصيات
        profile.evasion_recommendations = self._generate_evasion_recommendations(profile)
        
        self._stats["detections_recorded"] += 1
        
        self.logger.info(
            f"Recorded defense for target {target_id}: "
            f"{defense_type.value} (confidence: {confidence:.2f})"
        )
    
    def get_defense_profile(self, target_id: str) -> Optional[DefenseProfile]:
        """الحصول على ملف الدفاعات لهدف."""
        return self._defense_profiles.get(target_id)
    
    def _generate_evasion_recommendations(
        self,
        profile: DefenseProfile
    ) -> List[str]:
        """توليد توصيات التهرب بناءً على الدفاعات."""
        
        recommendations = []
        
        for defense in profile.detected_defenses:
            if defense in EVASION_TECHNIQUES:
                techniques = EVASION_TECHNIQUES[defense]
                
                # أخذ أفضل تقنيتين
                sorted_techniques = sorted(
                    techniques,
                    key=lambda t: t["effectiveness"],
                    reverse=True
                )[:2]
                
                for tech in sorted_techniques:
                    rec = (
                        f"For {defense.value}: {tech['name']} - "
                        f"{tech['description']} "
                        f"(effectiveness: {tech['effectiveness']:.0%})"
                    )
                    recommendations.append(rec)
        
        return recommendations
    
    # ═══════════════════════════════════════════════════════════
    # توصيات التهرب
    # ═══════════════════════════════════════════════════════════
    
    def get_evasion_recommendations(
        self,
        defenses: List[DefenseType],
        complexity_limit: str = "high"
    ) -> List[Dict[str, Any]]:
        """
        الحصول على توصيات التهرب لدفاعات محددة.
        
        Args:
            defenses: قائمة الدفاعات
            complexity_limit: حد التعقيد (low, medium, high)
            
        Returns:
            قائمة تقنيات التهرب المناسبة
        """
        complexity_order = ["low", "medium", "high"]
        max_complexity = complexity_order.index(complexity_limit)
        
        all_techniques = []
        
        for defense in defenses:
            if defense in EVASION_TECHNIQUES:
                for tech in EVASION_TECHNIQUES[defense]:
                    tech_complexity = complexity_order.index(tech["complexity"])
                    
                    if tech_complexity <= max_complexity:
                        all_techniques.append({
                            **tech,
                            "for_defense": defense.value,
                        })
        
        # ترتيب بالفعالية
        all_techniques.sort(key=lambda t: t["effectiveness"], reverse=True)
        
        return all_techniques
    
    def get_best_evasion_for_operation(
        self,
        operation_type: str,
        target_id: str
    ) -> List[Dict[str, Any]]:
        """
        الحصول على أفضل تقنيات التهرب لعملية وهدف.
        
        Args:
            operation_type: نوع العملية
            target_id: معرف الهدف
            
        Returns:
            قائمة أفضل تقنيات التهرب
        """
        profile = self._defense_profiles.get(target_id)
        
        if not profile or not profile.detected_defenses:
            # لا توجد دفاعات معروفة - توصيات عامة
            return [
                {
                    "name": "basic_encoding",
                    "description": "ترميز أساسي للحمولة",
                    "effectiveness": 0.5,
                    "complexity": "low",
                },
                {
                    "name": "timing_variation",
                    "description": "تنويع التوقيت",
                    "effectiveness": 0.4,
                    "complexity": "low",
                },
            ]
        
        return self.get_evasion_recommendations(profile.detected_defenses)
    
    # ═══════════════════════════════════════════════════════════
    # تتبع البصمة
    # ═══════════════════════════════════════════════════════════
    
    def record_footprint(
        self,
        operation_type: str,
        target_id: str,
        packet_count: int = 0,
        bytes_transferred: int = 0,
        duration_ms: int = 0,
        indicators: Optional[List[str]] = None
    ) -> OperationFootprint:
        """
        تسجيل بصمة عملية.
        
        Args:
            operation_type: نوع العملية
            target_id: معرف الهدف
            packet_count: عدد الحزم
            bytes_transferred: حجم البيانات
            duration_ms: المدة
            indicators: مؤشرات إضافية
            
        Returns:
            OperationFootprint المسجلة
        """
        footprint = OperationFootprint(
            operation_type=operation_type,
            target_id=target_id,
            packet_count=packet_count,
            bytes_transferred=bytes_transferred,
            duration_ms=duration_ms,
            indicators=indicators or []
        )
        
        self._footprint_history.append(footprint)
        
        # حد السجل
        if len(self._footprint_history) > 1000:
            self._footprint_history = self._footprint_history[-500:]
        
        return footprint
    
    def get_footprint_summary(
        self,
        target_id: Optional[str] = None,
        operation_type: Optional[str] = None,
        last_hours: int = 24
    ) -> Dict[str, Any]:
        """
        ملخص البصمات.
        
        Args:
            target_id: تصفية بالهدف
            operation_type: تصفية بنوع العملية
            last_hours: الفترة الزمنية
            
        Returns:
            ملخص البصمات
        """
        cutoff = datetime.utcnow() - timedelta(hours=last_hours)
        
        filtered = [
            fp for fp in self._footprint_history
            if fp.timestamp >= cutoff
            and (target_id is None or fp.target_id == target_id)
            and (operation_type is None or fp.operation_type == operation_type)
        ]
        
        if not filtered:
            return {"count": 0, "total_packets": 0, "total_bytes": 0}
        
        return {
            "count": len(filtered),
            "total_packets": sum(fp.packet_count for fp in filtered),
            "total_bytes": sum(fp.bytes_transferred for fp in filtered),
            "total_duration_ms": sum(fp.duration_ms for fp in filtered),
            "operation_types": list(set(fp.operation_type for fp in filtered)),
            "unique_targets": len(set(fp.target_id for fp in filtered)),
        }
    
    # ═══════════════════════════════════════════════════════════
    # التكيف الديناميكي
    # ═══════════════════════════════════════════════════════════
    
    async def adapt_stealth_level(
        self,
        mission_id: str,
        detection_event: bool = False,
        blocked_event: bool = False
    ) -> StealthLevel:
        """
        تكيف مستوى التخفي بناءً على الأحداث.
        
        Args:
            mission_id: معرف المهمة
            detection_event: حدث اكتشاف
            blocked_event: حدث حظر
            
        Returns:
            المستوى الجديد
        """
        current = self.get_mission_stealth_level(mission_id)
        
        levels = list(StealthLevel)
        current_idx = levels.index(current)
        
        if blocked_event:
            # حظر = زيادة التخفي بمستويين
            new_idx = max(0, current_idx - 2)
        elif detection_event:
            # اكتشاف = زيادة التخفي بمستوى واحد
            new_idx = max(0, current_idx - 1)
        else:
            # لا تغيير
            return current
        
        new_level = levels[new_idx]
        
        if new_level != current:
            self.set_mission_stealth_level(mission_id, new_level)
            self.logger.warning(
                f"Adapted stealth level for mission {mission_id}: "
                f"{current.value} -> {new_level.value}"
            )
        
        return new_level
    
    # ═══════════════════════════════════════════════════════════
    # المرافق والإحصائيات
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """الحصول على الإحصائيات."""
        return {
            **self._stats,
            "active_missions": len(self._mission_levels),
            "known_targets": len(self._defense_profiles),
            "footprint_records": len(self._footprint_history),
        }
    
    def get_operational_guidance(
        self,
        operation_type: str,
        target_id: str,
        mission_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        الحصول على إرشادات شاملة للعملية.
        
        Args:
            operation_type: نوع العملية
            target_id: معرف الهدف
            mission_id: معرف المهمة
            
        Returns:
            إرشادات شاملة
        """
        params = self.get_stealth_parameters(mission_id=mission_id)
        level = self.get_mission_stealth_level(mission_id) if mission_id else self._default_level
        
        profile = self._defense_profiles.get(target_id)
        defenses = profile.detected_defenses if profile else []
        
        evasion = self.get_best_evasion_for_operation(operation_type, target_id)
        
        return {
            "stealth_level": level.value,
            "parameters": params.to_dict(),
            "detected_defenses": [d.value for d in defenses],
            "evasion_techniques": evasion[:3],
            "recommendations": [
                f"Use delay range: {params.min_delay_ms}-{params.max_delay_ms}ms",
                f"Max concurrent ops: {params.max_concurrent_operations}",
                f"Cleanup artifacts: {params.cleanup_artifacts}",
            ],
        }
