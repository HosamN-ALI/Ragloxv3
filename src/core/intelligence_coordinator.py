# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intelligence Coordinator
# منسق الذكاء للربط الذكي بين المكونات
#
# المبدأ: كل اكتشاف يُحلَّل استراتيجياً، كل هجوم يُخطَّط له مسبقاً
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from .blackboard import Blackboard
    from .operational_memory import OperationalMemory
    from .knowledge import EmbeddedKnowledge
    from .llm.service import LLMService


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
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس."""
        return {
            "id": str(self.id),
            "type": self.path_type.value,
            "source": self.source_target,
            "destination": self.destination_target,
            "steps": self.steps,
            "success_probability": self.success_probability,
            "stealth_score": self.stealth_score,
            "time_estimate_minutes": self.time_estimate_minutes,
            "risk_level": self.risk_level,
            "prerequisites": self.prerequisites,
            "required_credentials": self.required_credentials,
            "required_sessions": self.required_sessions,
            "reasoning": self.reasoning,
            "alternative_paths": [str(p) for p in self.alternative_paths]
        }


@dataclass
class StrategicAnalysis:
    """نتيجة التحليل الاستراتيجي"""
    target_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # القيمة الاستراتيجية
    strategic_value: str = "unknown"  # critical, high, medium, low
    
    # سطح الهجوم
    attack_surface: List[Dict[str, Any]] = field(default_factory=list)
    
    # المسارات المقترحة
    recommended_paths: List[AttackPath] = field(default_factory=list)
    
    # الإجراءات
    immediate_actions: List[Dict[str, Any]] = field(default_factory=list)
    deferred_actions: List[Dict[str, Any]] = field(default_factory=list)
    
    # ملاحظات
    coordination_notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """تحويل إلى قاموس."""
        return {
            "target_id": self.target_id,
            "timestamp": self.timestamp.isoformat(),
            "strategic_value": self.strategic_value,
            "attack_surface": self.attack_surface,
            "recommended_paths": [p.to_dict() for p in self.recommended_paths],
            "immediate_actions": self.immediate_actions,
            "deferred_actions": self.deferred_actions,
            "coordination_notes": self.coordination_notes
        }


class IntelligenceCoordinator:
    """
    منسق الذكاء - الدماغ الاستراتيجي للنظام
    
    المسؤوليات:
    1. ربط الاكتشافات من ReconSpecialist بخطط الهجوم
    2. توليد مسارات هجوم ذكية متعددة
    3. تقييم كل مسار استراتيجياً
    4. تنسيق البيانات بين جميع المكونات
    
    Usage:
        coordinator = IntelligenceCoordinator(blackboard=bb, memory=mem)
        
        # معالجة نتائج الاستطلاع
        analysis = await coordinator.process_recon_results(
            mission_id="mission_123",
            target_id="target_456",
            services=[{"name": "ssh", "port": 22}],
            vulnerabilities=[{"type": "CVE-2021-44228", "severity": "critical"}]
        )
        
        # توليد مسارات هجوم
        paths = await coordinator.generate_attack_paths(
            target_id="target_456",
            services=services,
            vulnerabilities=vulns
        )
    """
    
    # خدمات عالية القيمة
    HIGH_VALUE_SERVICES = {
        "ldap", "kerberos", "smb", "rdp", "winrm", "ssh",
        "mssql", "mysql", "postgresql", "oracle", "mongodb",
        "exchange", "sharepoint", "ad", "dc"
    }
    
    # تطابقات الثغرات والخدمات
    VULN_SERVICE_MATCHES = {
        "ssh": ["ssh", "openssh", "cve-2018-15473"],
        "smb": ["smb", "ms17-010", "eternalblue", "cve-2017-0144", "cve-2020-0796"],
        "rdp": ["rdp", "bluekeep", "cve-2019-0708"],
        "http": ["http", "web", "log4j", "cve-2021-44228", "apache", "nginx"],
        "mssql": ["mssql", "sql", "cve-2020-0618"],
    }
    
    def __init__(
        self,
        blackboard: Optional["Blackboard"] = None,
        operational_memory: Optional["OperationalMemory"] = None,
        knowledge_base: Optional["EmbeddedKnowledge"] = None,
        llm_service: Optional["LLMService"] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Args:
            blackboard: Blackboard للوصول للبيانات المشتركة
            operational_memory: ذاكرة التجارب السابقة
            knowledge_base: قاعدة المعرفة (RX Modules, Nuclei)
            llm_service: خدمة LLM للتحليل المتقدم
            logger: Logger instance
        """
        self._blackboard = blackboard
        self._memory = operational_memory
        self._knowledge = knowledge_base
        self._llm = llm_service
        self.logger = logger or logging.getLogger(__name__)
        
        # كاش لمسارات الهجوم المحسوبة
        self._path_cache: Dict[str, List[AttackPath]] = {}
        
        # خريطة العلاقات بين الأهداف
        self._target_graph: Dict[str, Set[str]] = defaultdict(set)
        
        # بيانات الاعتماد المرتبطة بالأهداف
        self._credential_map: Dict[str, List[str]] = defaultdict(list)
        
        # إحصائيات
        self._stats = {
            "analyses_performed": 0,
            "paths_generated": 0,
            "cache_hits": 0,
        }
        
        self.logger.info("IntelligenceCoordinator initialized")
    
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
    ) -> StrategicAnalysis:
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
            StrategicAnalysis مع التحليل الكامل
        """
        self.logger.info(f"Processing recon results for target {target_id}")
        self._stats["analyses_performed"] += 1
        
        analysis = StrategicAnalysis(target_id=target_id)
        
        # 1. تقييم سطح الهجوم
        attack_surface = await self._analyze_attack_surface(services, vulnerabilities)
        analysis.attack_surface = attack_surface
        
        # 2. حساب القيمة الاستراتيجية
        strategic_value = self._calculate_strategic_value(
            services, vulnerabilities, credentials
        )
        analysis.strategic_value = strategic_value
        
        # 3. توليد مسارات الهجوم
        paths = await self.generate_attack_paths(
            target_id=target_id,
            services=services,
            vulnerabilities=vulnerabilities,
            credentials=credentials
        )
        analysis.recommended_paths = paths[:5]  # أفضل 5 مسارات
        
        # 4. تحديد الإجراءات الفورية والمؤجلة
        immediate, deferred = self._categorize_actions(paths, strategic_value)
        analysis.immediate_actions = immediate
        analysis.deferred_actions = deferred
        
        # 5. ملاحظات التنسيق
        analysis.coordination_notes = self._generate_coordination_notes(
            target_id, paths, attack_surface
        )
        
        # تخزين التحليل
        if self._blackboard:
            await self._store_analysis(mission_id, target_id, analysis)
        
        self.logger.info(
            f"Strategic analysis complete for {target_id}: "
            f"value={strategic_value}, paths={len(paths)}"
        )
        
        return analysis
    
    async def _analyze_attack_surface(
        self,
        services: List[Dict],
        vulnerabilities: List[Dict]
    ) -> List[Dict[str, Any]]:
        """تحليل سطح الهجوم المتاح."""
        surface = []
        
        for service in services:
            service_name = service.get("name", "").lower()
            port = service.get("port")
            
            # تحديد مستوى التعرض
            if port in [22, 80, 443, 445, 3389]:
                exposure = "high"
            elif port in [21, 25, 110, 143, 3306, 5432]:
                exposure = "medium"
            else:
                exposure = "low"
            
            entry = {
                "service": service_name,
                "port": port,
                "exposure_level": exposure,
                "related_vulns": [],
                "attack_vectors": [],
                "priority_score": 0
            }
            
            # ربط الثغرات بالخدمات
            for vuln in vulnerabilities:
                if self._vuln_matches_service(vuln, service):
                    entry["related_vulns"].append({
                        "id": vuln.get("id"),
                        "type": vuln.get("type"),
                        "severity": vuln.get("severity"),
                        "exploit_available": vuln.get("exploit_available", False)
                    })
            
            # تحديد ناقلات الهجوم
            entry["attack_vectors"] = self._determine_attack_vectors(
                service, entry["related_vulns"]
            )
            
            # حساب الأولوية
            entry["priority_score"] = self._calculate_surface_priority(entry)
            
            surface.append(entry)
        
        # ترتيب بالأولوية
        surface.sort(key=lambda x: x["priority_score"], reverse=True)
        
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
        for service in services:
            service_name = service.get("name", "").lower()
            if service_name in self.HIGH_VALUE_SERVICES:
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
            
            # مكافأة للثغرات مع استغلال متاح
            if vuln.get("exploit_available"):
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
    
    def _calculate_surface_priority(self, surface_entry: Dict) -> float:
        """حساب أولوية عنصر سطح الهجوم."""
        priority = 0.0
        
        # مستوى التعرض
        exposure_scores = {"high": 3.0, "medium": 2.0, "low": 1.0}
        priority += exposure_scores.get(surface_entry.get("exposure_level", "low"), 1.0)
        
        # عدد الثغرات
        vulns = surface_entry.get("related_vulns", [])
        priority += len(vulns) * 2
        
        # خطورة الثغرات
        for vuln in vulns:
            severity = vuln.get("severity", "").lower()
            if severity == "critical":
                priority += 5
            elif severity == "high":
                priority += 3
            elif severity == "medium":
                priority += 1
        
        # ناقلات الهجوم
        priority += len(surface_entry.get("attack_vectors", []))
        
        return priority
    
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
        
        # التحقق من الكاش
        cache_key = f"{target_id}:{len(services)}:{len(vulnerabilities)}"
        if cache_key in self._path_cache:
            self._stats["cache_hits"] += 1
            return self._path_cache[cache_key]
        
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
        
        # ترتيب بالأفضلية (معادلة مرجحة)
        paths.sort(key=lambda p: (
            p.success_probability * 0.4 +
            p.stealth_score * 0.3 +
            (1 - min(p.time_estimate_minutes, 120) / 120) * 0.3
        ), reverse=True)
        
        # تخزين في الكاش
        self._path_cache[cache_key] = paths
        self._stats["paths_generated"] += len(paths)
        
        return paths
    
    async def _create_direct_exploit_path(
        self,
        target_id: str,
        vuln: Dict,
        services: List[Dict]
    ) -> Optional[AttackPath]:
        """إنشاء مسار استغلال مباشر."""
        vuln_type = vuln.get("type", "")
        
        # البحث عن موديول مناسب
        module = None
        if self._knowledge and hasattr(self._knowledge, 'search_modules'):
            try:
                modules = self._knowledge.search_modules(vuln_type, limit=1)
                if modules:
                    module = modules[0]
            except Exception:
                pass
        
        steps = [
            {
                "step_number": 1,
                "action": "exploit",
                "target": target_id,
                "vuln_id": vuln.get("id"),
                "vuln_type": vuln_type,
                "module": module.get("rx_module_id") if module else None,
                "description": f"Exploit {vuln_type} vulnerability"
            }
        ]
        
        # تحديد الامتياز المبدئي
        initial_privilege = vuln.get("initial_privilege", "user")
        
        # إضافة خطوة تصعيد إذا لزم
        if initial_privilege not in ("admin", "system", "root", "domain_admin"):
            steps.append({
                "step_number": 2,
                "action": "privesc",
                "target": target_id,
                "description": "Privilege escalation required",
                "from_privilege": initial_privilege,
                "to_privilege": "admin"
            })
        
        # حساب احتمالية النجاح
        success_prob = self._estimate_exploit_probability(vuln, module)
        
        # حساب درجة التخفي
        stealth = self._estimate_stealth_score(vuln_type, "direct")
        
        return AttackPath(
            path_type=AttackPathType.DIRECT_EXPLOIT,
            destination_target=target_id,
            steps=steps,
            success_probability=success_prob,
            stealth_score=stealth,
            time_estimate_minutes=15 if module else 30,
            risk_level=vuln.get("severity", "medium"),
            reasoning=f"Direct exploitation of {vuln_type} - {vuln.get('severity', 'unknown')} severity"
        )
    
    async def _create_credential_path(
        self,
        target_id: str,
        cred: Dict,
        services: List[Dict]
    ) -> Optional[AttackPath]:
        """إنشاء مسار عبر بيانات الاعتماد."""
        # تحديد الخدمة المناسبة
        auth_services = {
            "ssh": [22],
            "smb": [445, 139],
            "rdp": [3389],
            "winrm": [5985, 5986],
            "mssql": [1433],
            "mysql": [3306],
            "postgresql": [5432]
        }
        
        suitable_service = None
        for service in services:
            port = service.get("port")
            svc_name = service.get("name", "").lower()
            
            for auth_svc, ports in auth_services.items():
                if port in ports or auth_svc in svc_name:
                    suitable_service = {
                        "name": auth_svc,
                        "port": port
                    }
                    break
            
            if suitable_service:
                break
        
        if not suitable_service:
            return None
        
        steps = [
            {
                "step_number": 1,
                "action": "authenticate",
                "target": target_id,
                "service": suitable_service.get("name"),
                "port": suitable_service.get("port"),
                "cred_id": cred.get("id"),
                "username": cred.get("username"),
                "description": f"Authenticate via {suitable_service.get('name')}"
            }
        ]
        
        # تصعيد إذا لزم
        priv_level = cred.get("privilege_level", "user")
        if priv_level not in ("admin", "domain_admin", "system", "root"):
            steps.append({
                "step_number": 2,
                "action": "privesc",
                "target": target_id,
                "description": "Privilege escalation after authentication",
                "from_privilege": priv_level,
                "to_privilege": "admin"
            })
        
        # احتمالية النجاح أعلى لبيانات الاعتماد المتحققة
        success_prob = 0.75 if cred.get("verified") else 0.55
        
        # إضافة مكافأة لبيانات Intel
        if cred.get("source", "").startswith("intel:"):
            success_prob = min(success_prob + 0.1, 0.9)
        
        return AttackPath(
            path_type=AttackPathType.CREDENTIAL_BASED,
            destination_target=target_id,
            steps=steps,
            success_probability=success_prob,
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
        
        if not info_vulns or not exploit_vulns:
            return chains
        
        # إنشاء سلاسل محتملة
        for info_vuln in info_vulns[:2]:  # أول ثغرتين للمعلومات
            for exploit_vuln in exploit_vulns[:2]:  # أول ثغرتين للاستغلال
                chain = AttackPath(
                    path_type=AttackPathType.CHAIN_EXPLOIT,
                    destination_target=target_id,
                    steps=[
                        {
                            "step_number": 1,
                            "action": "recon",
                            "vuln_id": info_vuln.get("id"),
                            "vuln_type": info_vuln.get("type"),
                            "description": f"Gather info via {info_vuln.get('type')}"
                        },
                        {
                            "step_number": 2,
                            "action": "exploit",
                            "vuln_id": exploit_vuln.get("id"),
                            "vuln_type": exploit_vuln.get("type"),
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
        def cred_priority(c):
            priv = c.get("privilege_level", "user")
            if priv == "domain_admin":
                return 1.0
            elif priv == "admin":
                return 0.7
            return 0.3
        
        best_cred = max(credentials, key=cred_priority)
        
        # تحديد طريقة الحركة
        cred_type = best_cred.get("type", "password")
        method = "pass_the_hash" if cred_type == "hash" else "ssh_key" if cred_type == "key" else "password"
        
        return AttackPath(
            path_type=AttackPathType.LATERAL_PIVOT,
            source_target=from_target,
            destination_target=to_target,
            steps=[
                {
                    "step_number": 1,
                    "action": "lateral_move",
                    "from": from_target,
                    "to": to_target,
                    "cred_id": best_cred.get("id"),
                    "method": method,
                    "description": f"Lateral movement from {from_target} to {to_target}"
                }
            ],
            success_probability=0.6,
            stealth_score=0.5,  # الحركة الجانبية ملحوظة نسبياً
            time_estimate_minutes=20,
            risk_level="medium",
            required_credentials=[best_cred.get("id")],
            required_sessions=[from_target],
            reasoning=f"Pivot from compromised {from_target} to {to_target} using {method}"
        )
    
    async def _enhance_paths_with_memory(
        self,
        paths: List[AttackPath]
    ) -> List[AttackPath]:
        """تحسين المسارات باستخدام الذاكرة التشغيلية."""
        if not self._memory:
            return paths
        
        from .operational_memory import OperationalContext
        
        for path in paths:
            try:
                # تحديد السياق
                context = self._path_type_to_context(path.path_type)
                
                # البحث عن تجارب مشابهة
                rate, count = await self._memory.get_success_rate_for_context(
                    context=context,
                    vuln_type=path.steps[0].get("vuln_type") if path.steps else None
                )
                
                if count >= 3:
                    # تعديل الاحتمالية بناءً على التجارب
                    # مزج الاحتمالية التقديرية مع التاريخية
                    path.success_probability = (
                        path.success_probability * 0.4 +
                        rate * 0.6
                    )
                    
                    # إضافة ملاحظة
                    path.reasoning += f" [Memory: {count} similar experiences, {rate:.0%} success rate]"
            
            except Exception as e:
                self.logger.debug(f"Error enhancing path with memory: {e}")
        
        return paths
    
    # ═══════════════════════════════════════════════════════════
    # المساعدات
    # ═══════════════════════════════════════════════════════════
    
    def _vuln_matches_service(self, vuln: Dict, service: Dict) -> bool:
        """التحقق من تطابق الثغرة مع الخدمة."""
        vuln_type = vuln.get("type", "").lower()
        service_name = service.get("name", "").lower()
        port = service.get("port")
        
        for svc, patterns in self.VULN_SERVICE_MATCHES.items():
            if service_name == svc or svc in service_name:
                for pattern in patterns:
                    if pattern in vuln_type:
                        return True
        
        # تطابق بالمنفذ
        port_service_map = {
            22: ["ssh"],
            80: ["http", "web"],
            443: ["https", "ssl"],
            445: ["smb", "ms17"],
            3389: ["rdp", "bluekeep"],
            3306: ["mysql"],
            5432: ["postgresql"]
        }
        
        if port in port_service_map:
            for pattern in port_service_map[port]:
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
            "smb": ["pass_the_hash", "exploit", "share_enum", "relay"],
            "rdp": ["brute_force", "exploit", "rdp_relay"],
            "http": ["web_exploit", "injection", "auth_bypass"],
            "https": ["web_exploit", "injection", "ssl_stripping"],
            "ldap": ["ldap_injection", "password_spray"],
            "kerberos": ["kerberoasting", "asreproasting", "golden_ticket"],
            "mssql": ["sql_injection", "xp_cmdshell"],
            "mysql": ["sql_injection", "udf_injection"],
        }
        
        if service_name in service_vectors:
            vectors.extend(service_vectors[service_name])
        
        # ناقلات مبنية على الثغرات
        for vuln in vulns:
            vuln_type = vuln.get("type", "").lower()
            severity = vuln.get("severity", "").lower()
            
            if severity in ("critical", "high"):
                if "rce" in vuln_type or "remote" in vuln_type:
                    vectors.append("remote_code_execution")
                elif "auth" in vuln_type:
                    vectors.append("auth_bypass")
                elif "injection" in vuln_type:
                    vectors.append("injection")
        
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
        severity_boost = {
            "critical": 0.2, 
            "high": 0.15, 
            "medium": 0.1, 
            "low": 0.05
        }
        base += severity_boost.get(severity, 0)
        
        # تعديل بناءً على توفر الاستغلال
        if vuln.get("exploit_available"):
            base += 0.15
        
        # تعديل بناءً على الموديول
        if module:
            reliability = module.get("reliability", "medium")
            if reliability == "high":
                base += 0.2
            elif reliability == "medium":
                base += 0.1
        
        return min(base, 0.95)
    
    def _estimate_stealth_score(self, vuln_type: str, method: str) -> float:
        """تقدير درجة التخفي."""
        base_scores = {
            "credential": 0.9,
            "direct": 0.5,
            "chain": 0.6,
            "lateral": 0.4
        }
        
        score = base_scores.get(method, 0.5)
        
        # تعديل بناءً على نوع الثغرة
        vuln_lower = vuln_type.lower()
        
        # ثغرات صاخبة
        noisy_patterns = ["bruteforce", "spray", "scan", "flood", "dos"]
        for pattern in noisy_patterns:
            if pattern in vuln_lower:
                score -= 0.2
        
        # ثغرات هادئة
        quiet_patterns = ["auth_bypass", "credential", "token", "session"]
        for pattern in quiet_patterns:
            if pattern in vuln_lower:
                score += 0.1
        
        return max(0.1, min(score, 1.0))
    
    def _categorize_actions(
        self,
        paths: List[AttackPath],
        strategic_value: str
    ) -> Tuple[List[Dict], List[Dict]]:
        """تصنيف الإجراءات إلى فورية ومؤجلة."""
        immediate = []
        deferred = []
        
        for path in paths[:10]:  # أفضل 10 مسارات
            action = {
                "path_id": str(path.id),
                "type": path.path_type.value,
                "probability": path.success_probability,
                "stealth": path.stealth_score,
                "first_step": path.steps[0] if path.steps else None,
                "reasoning": path.reasoning
            }
            
            # فورية: احتمالية عالية أو قيمة استراتيجية حرجة
            if path.success_probability > 0.6 or strategic_value == "critical":
                immediate.append(action)
            elif path.success_probability > 0.4:
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
            
            if best_path.stealth_score >= 0.7:
                notes.append("Recommended path is relatively stealthy")
            elif best_path.stealth_score <= 0.4:
                notes.append("WARNING: Recommended path may be detected")
        
        # ملاحظات حول سطح الهجوم
        critical_surfaces = [
            s for s in attack_surface 
            if s.get("exposure_level") == "high" and s.get("related_vulns")
        ]
        if critical_surfaces:
            notes.append(
                f"Critical exposure: {len(critical_surfaces)} high-exposure "
                f"services with known vulnerabilities"
            )
        
        # ملاحظات حول المتطلبات
        cred_paths = [p for p in paths if p.required_credentials]
        if cred_paths:
            notes.append(
                f"{len(cred_paths)} paths require credentials - "
                "consider credential harvesting"
            )
        
        return notes
    
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
        analysis: StrategicAnalysis
    ) -> None:
        """تخزين التحليل في Blackboard."""
        if self._blackboard:
            try:
                await self._blackboard.log_result(
                    mission_id,
                    "strategic_analysis",
                    {
                        "target_id": target_id,
                        "strategic_value": analysis.strategic_value,
                        "paths_count": len(analysis.recommended_paths),
                        "immediate_actions_count": len(analysis.immediate_actions),
                        "analysis": analysis.to_dict()
                    }
                )
            except Exception as e:
                self.logger.error(f"Failed to store analysis: {e}")
    
    # ═══════════════════════════════════════════════════════════
    # ربط الأهداف
    # ═══════════════════════════════════════════════════════════
    
    def link_targets(self, target1: str, target2: str) -> None:
        """ربط هدفين (علاقة شبكية)."""
        self._target_graph[target1].add(target2)
        self._target_graph[target2].add(target1)
    
    def get_linked_targets(self, target_id: str) -> Set[str]:
        """الحصول على الأهداف المرتبطة."""
        return self._target_graph.get(target_id, set())
    
    def map_credential_to_target(self, cred_id: str, target_id: str) -> None:
        """ربط بيانات اعتماد بهدف."""
        if cred_id not in self._credential_map[target_id]:
            self._credential_map[target_id].append(cred_id)
    
    def get_credentials_for_target(self, target_id: str) -> List[str]:
        """الحصول على بيانات الاعتماد المرتبطة بهدف."""
        return self._credential_map.get(target_id, [])
    
    # ═══════════════════════════════════════════════════════════
    # الإحصائيات
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """الحصول على الإحصائيات."""
        return {
            **self._stats,
            "cached_paths": len(self._path_cache),
            "linked_targets": sum(len(v) for v in self._target_graph.values()) // 2,
            "credential_mappings": sum(len(v) for v in self._credential_map.values()),
        }
    
    def clear_cache(self) -> None:
        """مسح الكاش."""
        self._path_cache.clear()
        self.logger.info("Path cache cleared")


# ═══════════════════════════════════════════════════════════
# Factory functions
# ═══════════════════════════════════════════════════════════

_global_coordinator: Optional[IntelligenceCoordinator] = None


def get_intelligence_coordinator() -> IntelligenceCoordinator:
    """الحصول على instance عالمي للمنسق."""
    global _global_coordinator
    if _global_coordinator is None:
        _global_coordinator = IntelligenceCoordinator()
    return _global_coordinator


def init_intelligence_coordinator(
    blackboard: Optional["Blackboard"] = None,
    operational_memory: Optional["OperationalMemory"] = None,
    knowledge_base: Optional["EmbeddedKnowledge"] = None,
    llm_service: Optional["LLMService"] = None
) -> IntelligenceCoordinator:
    """تهيئة المنسق العالمي."""
    global _global_coordinator
    _global_coordinator = IntelligenceCoordinator(
        blackboard=blackboard,
        operational_memory=operational_memory,
        knowledge_base=knowledge_base,
        llm_service=llm_service
    )
    return _global_coordinator


def reset_intelligence_coordinator() -> None:
    """إعادة تعيين المنسق العالمي."""
    global _global_coordinator
    _global_coordinator = None
