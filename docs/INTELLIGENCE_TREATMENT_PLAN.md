# خطة العلاج الذكية لنظام RAGLOX v3.0
## Hybrid Intelligence Treatment Plan
### "لا نفقد الغاية ولا الوسيلة"

---

## 📋 الفلسفة التوجيهية

### المعادلة الذهبية:
```
الذكاء الهجين = (قواعد معرفية مضمنة × استدلال LLM) + ذاكرة تشغيلية
```

### المبادئ الأساسية:
1. **LLM ليس البديل** - LLM يُعزز القواعد المضمنة، لا يُلغيها
2. **المعرفة المضمنة هي الأساس** - سريعة، موثوقة، قابلة للتدقيق
3. **LLM للقرارات الصعبة** - عندما القواعد لا تكفي
4. **الذاكرة للتعلم** - التاريخ يُحسّن المستقبل

---

## 🏗️ هندسة الذكاء الهجين (Hybrid Intelligence Architecture)

### الطبقة 1: Knowledge-First Decision Layer

```
┌─────────────────────────────────────────────────────────────┐
│                    طبقة القرار الأولى                        │
│         (Knowledge-First Decision Layer)                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │   Nuclei    │    │ RX Modules  │    │   MITRE     │    │
│  │  Templates  │    │  (1,761)    │    │  Techniques │    │
│  │  (11,927)   │    │             │    │   (327)     │    │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    │
│         │                  │                  │            │
│         └──────────────────┼──────────────────┘            │
│                            ▼                               │
│              ┌─────────────────────────┐                   │
│              │   EmbeddedKnowledge     │                   │
│              │   (Decision Engine v1)  │                   │
│              └───────────┬─────────────┘                   │
│                          │                                 │
│              ┌───────────▼─────────────┐                   │
│              │    Decision Confident?   │                   │
│              │    (Confidence > 0.75)   │                   │
│              └───────────┬─────────────┘                   │
│                    Yes ┌─┴─┐ No                            │
│                        │   │                               │
│              ┌─────────▼─┐ └─────────────────────┐         │
│              │  Execute  │        Escalate to   │         │
│              │  Directly │        LLM Layer     │         │
│              └───────────┘                      ▼         │
│                                    ┌─────────────────┐    │
│                                    │   LLM Service   │    │
│                                    │ (Decision v2)   │    │
│                                    └─────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### الطبقة 2: Operational Memory Layer

```
┌─────────────────────────────────────────────────────────────┐
│                   طبقة الذاكرة التشغيلية                     │
│           (Operational Memory Layer)                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │              Redis + Vector Store                   │    │
│  │                                                     │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │    │
│  │  │ Action       │  │ Defense      │  │ Success  │  │    │
│  │  │ Outcomes     │  │ Signatures   │  │ Patterns │  │    │
│  │  │ History      │  │ Mapping      │  │ Cache    │  │    │
│  │  └──────────────┘  └──────────────┘  └──────────┘  │    │
│  │                                                     │    │
│  │  ┌──────────────────────────────────────────────┐  │    │
│  │  │        Similarity Search Engine              │  │    │
│  │  │   (Find similar past situations)             │  │    │
│  │  └──────────────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  Query Interface:                                           │
│  - query_similar_outcomes(action, context) -> List[Outcome]│
│  - get_historical_success_rate(action, target) -> float    │
│  - get_defense_bypass_history(defense_type) -> List[Bypass]│
│  - record_outcome(action, result, context) -> void         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### الطبقة 3: Intelligence Coordinator

```
┌─────────────────────────────────────────────────────────────┐
│                   منسق الذكاء المركزي                        │
│        (Intelligence Coordinator - The Brain)               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│         ┌────────────┐ ┌────────────┐ ┌────────────┐       │
│         │   Recon    │ │   Attack   │ │  Analysis  │       │
│         │ Specialist │ │ Specialist │ │ Specialist │       │
│         └─────┬──────┘ └─────┬──────┘ └─────┬──────┘       │
│               │              │              │               │
│               └──────────────┼──────────────┘               │
│                              ▼                              │
│              ┌───────────────────────────────┐              │
│              │   IntelligenceCoordinator     │              │
│              │                               │              │
│              │  - Cross-Workspace Insights   │              │
│              │  - Attack Graph Generation    │              │
│              │  - Credential Correlation     │              │
│              │  - Strategic Target Selection │              │
│              │  - Mission Goal Optimization  │              │
│              └───────────────────────────────┘              │
│                              │                              │
│                              ▼                              │
│              ┌───────────────────────────────┐              │
│              │      Unified World Model      │              │
│              │   (Complete Mission State)    │              │
│              └───────────────────────────────┘              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 المكونات الجديدة المطلوبة

### 1. OperationalMemory Module

**الملف:** `src/core/memory/operational.py`

```python
"""
OperationalMemory - الذاكرة التشغيلية للنظام

الغرض: تخزين واسترجاع نتائج العمليات السابقة لتحسين القرارات المستقبلية
بدلاً من استخدام random.random() أو magic numbers

المبدأ: "من لا يتعلم من التاريخ محكوم عليه بتكراره"
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from uuid import UUID
import json
import hashlib

from ..blackboard import Blackboard


@dataclass
class ActionOutcome:
    """سجل نتيجة عملية واحدة"""
    action_type: str           # EXPLOIT, PRIVESC, LATERAL, etc.
    module_id: Optional[str]   # RX Module used
    target_context: Dict       # OS, services, ports, etc.
    defense_context: List[str] # Detected defenses
    result: str                # success, failed, blocked, timeout
    error_category: Optional[str]  # If failed: network, defense, etc.
    timestamp: datetime
    mission_id: UUID
    
    # Similarity key for fast lookups
    @property
    def context_signature(self) -> str:
        """Generate a signature for similarity matching"""
        key_parts = [
            self.action_type,
            self.target_context.get("os", "unknown"),
            ",".join(sorted(self.defense_context)),
        ]
        return hashlib.md5("|".join(key_parts).encode()).hexdigest()[:16]


class OperationalMemory:
    """
    الذاكرة التشغيلية - تخزن وتسترجع نتائج العمليات
    
    الاستخدام:
    - قبل تنفيذ عملية: query للحصول على historical success rate
    - بعد تنفيذ عملية: record لتخزين النتيجة
    - في التحليل: get_similar_failures للتعلم من الماضي
    """
    
    def __init__(self, blackboard: Blackboard):
        self.blackboard = blackboard
        self._local_cache: Dict[str, List[ActionOutcome]] = {}
        
    async def record_outcome(
        self,
        action_type: str,
        module_id: Optional[str],
        target_context: Dict,
        defense_context: List[str],
        result: str,
        error_category: Optional[str] = None,
        mission_id: Optional[UUID] = None
    ) -> None:
        """
        تسجيل نتيجة عملية
        
        يُستدعى بعد كل تنفيذ (نجاح أو فشل)
        """
        outcome = ActionOutcome(
            action_type=action_type,
            module_id=module_id,
            target_context=target_context,
            defense_context=defense_context,
            result=result,
            error_category=error_category,
            timestamp=datetime.utcnow(),
            mission_id=mission_id or UUID('00000000-0000-0000-0000-000000000000')
        )
        
        # Store in Redis stream
        await self.blackboard.redis.xadd(
            "memory:outcomes",
            {
                "data": json.dumps(outcome.__dict__, default=str),
                "signature": outcome.context_signature,
                "result": result,
            }
        )
        
        # Update local cache
        sig = outcome.context_signature
        if sig not in self._local_cache:
            self._local_cache[sig] = []
        self._local_cache[sig].append(outcome)
    
    async def get_historical_success_rate(
        self,
        action_type: str,
        target_context: Dict,
        defense_context: List[str],
        min_samples: int = 3
    ) -> Tuple[float, int]:
        """
        احصل على معدل النجاح التاريخي لسياق مشابه
        
        Returns:
            Tuple of (success_rate, sample_count)
            If sample_count < min_samples, returns (0.5, sample_count) as default
        """
        # Build signature for lookup
        key_parts = [
            action_type,
            target_context.get("os", "unknown"),
            ",".join(sorted(defense_context)),
        ]
        signature = hashlib.md5("|".join(key_parts).encode()).hexdigest()[:16]
        
        # Query from Redis
        outcomes = await self._query_by_signature(signature)
        
        if len(outcomes) < min_samples:
            return 0.5, len(outcomes)  # Default rate when insufficient data
        
        successes = sum(1 for o in outcomes if o["result"] == "success")
        return successes / len(outcomes), len(outcomes)
    
    async def get_similar_failures(
        self,
        action_type: str,
        error_category: str,
        limit: int = 10
    ) -> List[Dict]:
        """
        استرجاع إخفاقات مشابهة للتعلم منها
        
        يُستخدم بواسطة AnalysisSpecialist لفهم أنماط الفشل
        """
        # Query failures with same action type and error category
        results = await self.blackboard.redis.xrevrange(
            "memory:outcomes",
            count=100
        )
        
        similar = []
        for entry_id, fields in results:
            data = json.loads(fields.get("data", "{}"))
            if (data.get("action_type") == action_type and 
                data.get("error_category") == error_category and
                data.get("result") == "failed"):
                similar.append(data)
                if len(similar) >= limit:
                    break
        
        return similar
    
    async def get_defense_bypass_history(
        self,
        defense_type: str,
        limit: int = 20
    ) -> List[Dict]:
        """
        استرجاع تاريخ تجاوز دفاع معين
        
        يعيد العمليات الناجحة التي واجهت نفس الدفاع
        """
        results = await self.blackboard.redis.xrevrange(
            "memory:outcomes",
            count=500
        )
        
        bypasses = []
        for entry_id, fields in results:
            data = json.loads(fields.get("data", "{}"))
            if (defense_type in data.get("defense_context", []) and
                data.get("result") == "success"):
                bypasses.append({
                    "module_id": data.get("module_id"),
                    "target_context": data.get("target_context"),
                    "timestamp": data.get("timestamp"),
                })
                if len(bypasses) >= limit:
                    break
        
        return bypasses
    
    async def _query_by_signature(self, signature: str) -> List[Dict]:
        """Query outcomes by context signature"""
        # Check local cache first
        if signature in self._local_cache:
            return [o.__dict__ for o in self._local_cache[signature]]
        
        # Query Redis
        results = await self.blackboard.redis.xrevrange(
            "memory:outcomes",
            count=100
        )
        
        matching = []
        for entry_id, fields in results:
            if fields.get("signature") == signature:
                matching.append(json.loads(fields.get("data", "{}")))
        
        return matching


# Singleton instance
_operational_memory: Optional[OperationalMemory] = None

def get_operational_memory(blackboard: Blackboard = None) -> OperationalMemory:
    """Get or create the operational memory instance"""
    global _operational_memory
    if _operational_memory is None:
        if blackboard is None:
            raise ValueError("Blackboard required for first initialization")
        _operational_memory = OperationalMemory(blackboard)
    return _operational_memory
```

---

### 2. IntelligenceCoordinator Module

**الملف:** `src/core/intelligence/coordinator.py`

```python
"""
IntelligenceCoordinator - منسق الذكاء المركزي

الغرض: ربط اكتشافات جميع الـ Specialists وتوليد رؤى عبر-مساحات العمل

المبدأ: "الكل أكبر من مجموع أجزائه"
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from ..blackboard import Blackboard
from ..knowledge import EmbeddedKnowledge
from ..memory.operational import OperationalMemory
from ..llm.service import LLMService


@dataclass
class TargetInsight:
    """رؤية محسّنة عن هدف"""
    target_id: str
    strategic_value: float          # 0-1 based on multiple factors
    attack_readiness: float         # 0-1 how ready we are to attack
    recommended_approach: str       # Best attack vector
    credential_availability: int    # Number of relevant credentials
    related_targets: List[str]      # Similar targets in network


@dataclass
class AttackPath:
    """مسار هجوم مقترح"""
    steps: List[Dict]
    total_confidence: float
    estimated_time_minutes: int
    required_resources: List[str]
    risk_level: str  # low, medium, high


class IntelligenceCoordinator:
    """
    منسق الذكاء - يربط بين Workspaces المختلفة
    
    المسؤوليات:
    1. Cross-Target Credential Correlation
    2. Attack Graph Generation
    3. Strategic Target Prioritization
    4. Mission Goal Optimization
    """
    
    def __init__(
        self,
        blackboard: Blackboard,
        knowledge: EmbeddedKnowledge,
        memory: OperationalMemory,
        llm_service: Optional[LLMService] = None
    ):
        self.blackboard = blackboard
        self.knowledge = knowledge
        self.memory = memory
        self.llm_service = llm_service
    
    # ═══════════════════════════════════════════════════════════
    # Cross-Target Credential Correlation
    # ═══════════════════════════════════════════════════════════
    
    async def correlate_credential_with_targets(
        self,
        credential_id: str,
        mission_id: str
    ) -> List[Tuple[str, float]]:
        """
        لكل credential، حدد targets أخرى يمكن استخدامه عليها
        
        القواعد المضمنة (لا تحتاج LLM):
        1. نفس الـ Domain -> احتمالية عالية
        2. نفس الـ OS Version -> احتمالية متوسطة
        3. نفس الـ Service (SMB, SSH) -> احتمالية متوسطة
        
        Returns:
            List of (target_id, probability) tuples
        """
        cred = await self.blackboard.get_credential(credential_id)
        if not cred:
            return []
        
        cred_domain = cred.get("domain")
        cred_type = cred.get("type")  # hash, password, etc.
        
        # Get all targets in mission
        all_targets = await self.blackboard.get_mission_targets(mission_id)
        
        correlations = []
        
        for target_key in all_targets:
            target_id = target_key.replace("target:", "")
            target = await self.blackboard.get_target(target_id)
            if not target:
                continue
            
            # Skip already-owned targets
            if target.get("status") in ("exploited", "owned"):
                continue
            
            probability = 0.0
            
            # Rule 1: Domain match (Knowledge-based)
            if cred_domain and cred_domain == target.get("domain"):
                probability += 0.4
            
            # Rule 2: Same OS family
            target_os = (target.get("os") or "").lower()
            if cred_type == "hash" and "windows" in target_os:
                probability += 0.25  # NTLM hashes work on Windows
            elif cred_type == "password":
                probability += 0.15  # Passwords more universal
            
            # Rule 3: Check ports for compatible services
            ports = await self.blackboard.get_target_ports(target_id)
            if cred_type == "hash" and "445" in ports:
                probability += 0.2  # SMB for pass-the-hash
            if "22" in ports or "3389" in ports:
                probability += 0.1  # SSH/RDP for password auth
            
            # Rule 4: Historical success (Memory-based)
            hist_rate, samples = await self.memory.get_historical_success_rate(
                action_type="LATERAL",
                target_context={"os": target_os},
                defense_context=[]
            )
            if samples >= 3:
                probability = (probability * 0.7) + (hist_rate * 0.3)
            
            if probability > 0.3:
                correlations.append((target_id, round(probability, 2)))
        
        # Sort by probability
        return sorted(correlations, key=lambda x: x[1], reverse=True)
    
    # ═══════════════════════════════════════════════════════════
    # Strategic Target Prioritization
    # ═══════════════════════════════════════════════════════════
    
    async def calculate_strategic_target_value(
        self,
        target_id: str,
        mission_id: str,
        mission_goals: List[str]
    ) -> TargetInsight:
        """
        حساب القيمة الاستراتيجية للهدف
        
        لا يعتمد على CVSS فقط!
        
        العوامل (Knowledge-based):
        1. Asset Criticality (30%)
        2. Attack Readiness (25%)
        3. Goal Proximity (20%)
        4. Historical Success on Similar (15%)
        5. Credential Availability (10%)
        """
        target = await self.blackboard.get_target(target_id)
        if not target:
            return TargetInsight(
                target_id=target_id,
                strategic_value=0.0,
                attack_readiness=0.0,
                recommended_approach="unknown",
                credential_availability=0,
                related_targets=[]
            )
        
        target_ip = target.get("ip", "")
        target_os = (target.get("os") or "").lower()
        hostname = (target.get("hostname") or "").lower()
        
        # Factor 1: Asset Criticality (Knowledge-based rules)
        criticality = 0.3  # Default
        critical_indicators = ["dc", "domain", "ad", "exchange", "sql", "db", "backup"]
        for indicator in critical_indicators:
            if indicator in hostname:
                criticality = 0.8
                break
        if "server" in target_os:
            criticality = max(criticality, 0.6)
        
        # Factor 2: Attack Readiness
        vulns = await self._get_target_vulns(target_id, mission_id)
        creds = await self._get_target_creds(target_id, mission_id)
        
        readiness = 0.0
        if vulns:
            # Check for exploitable vulns
            high_vulns = [v for v in vulns if v.get("severity") in ("critical", "high")]
            readiness += min(len(high_vulns) * 0.2, 0.5)
        if creds:
            readiness += min(len(creds) * 0.15, 0.3)
        
        # Factor 3: Goal Proximity (Simple keyword matching)
        goal_proximity = 0.0
        for goal in mission_goals:
            goal_lower = goal.lower()
            if "domain" in goal_lower and any(x in hostname for x in ["dc", "domain", "ad"]):
                goal_proximity = 0.9
                break
            if "database" in goal_lower and any(x in hostname for x in ["sql", "db", "mysql"]):
                goal_proximity = 0.8
                break
            if "credential" in goal_lower:
                goal_proximity = 0.5  # Any target can yield creds
        
        # Factor 4: Historical Success Rate
        hist_rate, samples = await self.memory.get_historical_success_rate(
            action_type="EXPLOIT",
            target_context={"os": target_os},
            defense_context=[]
        )
        history_factor = hist_rate if samples >= 3 else 0.5
        
        # Factor 5: Credential Availability
        cred_factor = min(len(creds) * 0.1, 0.3) if creds else 0.0
        
        # Calculate final strategic value
        strategic_value = (
            criticality * 0.30 +
            readiness * 0.25 +
            goal_proximity * 0.20 +
            history_factor * 0.15 +
            cred_factor * 0.10
        )
        
        # Determine recommended approach
        recommended_approach = await self._determine_best_approach(
            target, vulns, creds, target_os
        )
        
        # Find related targets
        related = await self._find_related_targets(target, mission_id)
        
        return TargetInsight(
            target_id=target_id,
            strategic_value=round(strategic_value, 2),
            attack_readiness=round(readiness, 2),
            recommended_approach=recommended_approach,
            credential_availability=len(creds) if creds else 0,
            related_targets=related[:5]
        )
    
    # ═══════════════════════════════════════════════════════════
    # Attack Graph Generation
    # ═══════════════════════════════════════════════════════════
    
    async def generate_attack_path(
        self,
        source_session_id: Optional[str],
        target_id: str,
        mission_id: str,
        use_llm: bool = False
    ) -> Optional[AttackPath]:
        """
        توليد مسار هجوم من النقطة الحالية إلى الهدف
        
        الوضع الافتراضي: Knowledge-based (سريع، موثوق)
        use_llm=True: يستخدم LLM للحالات المعقدة
        """
        # Get available resources
        sessions = await self.blackboard.get_mission_sessions(mission_id)
        creds = await self.blackboard.get_mission_creds(mission_id)
        vulns = await self.blackboard.get_mission_vulns(mission_id)
        
        # Knowledge-based path generation
        steps = []
        
        # Step 1: If no session, need initial access
        if not source_session_id and not sessions:
            # Look for exploitable vulns on target
            target_vulns = await self._get_target_vulns(target_id, mission_id)
            if target_vulns:
                best_vuln = max(target_vulns, key=lambda v: self._vuln_score(v))
                steps.append({
                    "action": "EXPLOIT",
                    "target_id": target_id,
                    "vuln_id": best_vuln.get("id"),
                    "confidence": 0.7 if best_vuln.get("severity") == "critical" else 0.5
                })
            else:
                # Look for credentials
                target_creds = await self._get_target_creds(target_id, mission_id)
                if target_creds:
                    steps.append({
                        "action": "CREDENTIAL_AUTH",
                        "target_id": target_id,
                        "cred_id": target_creds[0].get("id"),
                        "confidence": 0.6
                    })
        
        # Step 2: If we have session but need to reach target
        elif source_session_id:
            # Check if we need lateral movement
            steps.append({
                "action": "LATERAL",
                "from_session": source_session_id,
                "target_id": target_id,
                "confidence": 0.5
            })
        
        # Step 3: Privilege escalation if needed
        steps.append({
            "action": "PRIVESC",
            "target_id": target_id,
            "confidence": 0.4
        })
        
        # Step 4: Credential harvesting
        steps.append({
            "action": "CRED_HARVEST",
            "target_id": target_id,
            "confidence": 0.6
        })
        
        # Use LLM for complex path optimization (optional)
        if use_llm and self.llm_service and len(steps) > 3:
            optimized = await self._llm_optimize_path(steps, mission_id)
            if optimized:
                steps = optimized
        
        # Calculate totals
        total_confidence = 1.0
        for step in steps:
            total_confidence *= step.get("confidence", 0.5)
        
        return AttackPath(
            steps=steps,
            total_confidence=round(total_confidence, 2),
            estimated_time_minutes=len(steps) * 5,
            required_resources=["session" if source_session_id else "vuln_or_cred"],
            risk_level="medium"
        )
    
    # ═══════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════
    
    async def _get_target_vulns(self, target_id: str, mission_id: str) -> List[Dict]:
        """Get vulnerabilities for a target"""
        all_vulns = await self.blackboard.get_mission_vulns(mission_id)
        target_vulns = []
        
        for vuln_key in all_vulns:
            vuln_id = vuln_key.replace("vuln:", "")
            vuln = await self.blackboard.get_vulnerability(vuln_id)
            if vuln and str(vuln.get("target_id", "")).replace("target:", "") == target_id:
                target_vulns.append(vuln)
        
        return target_vulns
    
    async def _get_target_creds(self, target_id: str, mission_id: str) -> List[Dict]:
        """Get credentials relevant to a target"""
        all_creds = await self.blackboard.get_mission_creds(mission_id)
        target_creds = []
        
        for cred_key in all_creds:
            cred_id = cred_key.replace("cred:", "")
            cred = await self.blackboard.get_credential(cred_id)
            if cred:
                cred_target = str(cred.get("target_id", "")).replace("target:", "")
                if cred_target == target_id or cred.get("domain"):
                    target_creds.append(cred)
        
        return target_creds
    
    async def _determine_best_approach(
        self,
        target: Dict,
        vulns: List[Dict],
        creds: List[Dict],
        target_os: str
    ) -> str:
        """Determine best attack approach for target"""
        # Priority 1: Critical vulns
        critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
        if critical_vulns:
            return f"exploit_vuln:{critical_vulns[0].get('type', 'unknown')}"
        
        # Priority 2: High-reliability credentials
        intel_creds = [c for c in creds if c.get("source", "").startswith("intel:")]
        if intel_creds:
            return "credential_auth:intel"
        
        # Priority 3: Any credentials
        if creds:
            return "credential_auth:harvested"
        
        # Priority 4: High vulns
        high_vulns = [v for v in vulns if v.get("severity") == "high"]
        if high_vulns:
            return f"exploit_vuln:{high_vulns[0].get('type', 'unknown')}"
        
        # Default
        return "reconnaissance_needed"
    
    async def _find_related_targets(
        self,
        target: Dict,
        mission_id: str
    ) -> List[str]:
        """Find targets similar to this one"""
        target_os = (target.get("os") or "").lower()
        target_domain = target.get("domain")
        
        all_targets = await self.blackboard.get_mission_targets(mission_id)
        related = []
        
        for t_key in all_targets:
            t_id = t_key.replace("target:", "")
            if t_id == str(target.get("id", "")):
                continue
            
            t = await self.blackboard.get_target(t_id)
            if not t:
                continue
            
            t_os = (t.get("os") or "").lower()
            
            # Same OS family
            if "windows" in target_os and "windows" in t_os:
                related.append(t_id)
            elif "linux" in target_os and "linux" in t_os:
                related.append(t_id)
            # Same domain
            elif target_domain and t.get("domain") == target_domain:
                related.append(t_id)
        
        return related
    
    def _vuln_score(self, vuln: Dict) -> float:
        """Score vulnerability for prioritization"""
        severity_scores = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0
        }
        return severity_scores.get(vuln.get("severity", "").lower(), 5.0)
    
    async def _llm_optimize_path(
        self,
        steps: List[Dict],
        mission_id: str
    ) -> Optional[List[Dict]]:
        """Use LLM to optimize attack path (optional enhancement)"""
        if not self.llm_service:
            return None
        
        # This would call LLM for complex path optimization
        # For now, return None to use knowledge-based path
        return None
```

---

### 3. Strategic Decision Engine (تحسين AnalysisSpecialist)

**التعديلات على:** `src/specialists/analysis.py`

```python
# إضافات للـ AnalysisSpecialist

class AnalysisSpecialist(BaseSpecialist):
    
    def __init__(self, ...):
        # ... existing init ...
        
        # NEW: Operational Memory integration
        self._memory: Optional[OperationalMemory] = None
        
        # NEW: Decision confidence thresholds
        self.KNOWLEDGE_CONFIDENCE_THRESHOLD = 0.75
        self.LLM_ESCALATION_THRESHOLD = 0.50
    
    @property
    def memory(self) -> OperationalMemory:
        """Get operational memory instance"""
        if self._memory is None:
            from ..core.memory.operational import get_operational_memory
            self._memory = get_operational_memory(self.blackboard)
        return self._memory
    
    async def _make_decision(
        self,
        original_task: Dict[str, Any],
        error_context: Dict[str, Any],
        execution_logs: List[Dict[str, Any]],
        category: str,
        strategy: Dict[str, Any],
        context: Dict[str, Any],
        retry_count: int,
        max_retries: int
    ) -> Dict[str, Any]:
        """
        قرار هجين: Knowledge-First + LLM-Enhanced
        
        المنهج:
        1. أولاً: استشر الذاكرة التشغيلية (التاريخ)
        2. ثانياً: طبّق القواعد المضمنة
        3. ثالثاً: قيّم مستوى الثقة
        4. رابعاً: إذا الثقة منخفضة -> استشر LLM
        """
        
        # ═══════════════════════════════════════════════════════════
        # الخطوة 1: استشارة الذاكرة التشغيلية
        # ═══════════════════════════════════════════════════════════
        
        historical_insight = await self._consult_operational_memory(
            original_task, error_context, context
        )
        
        # ═══════════════════════════════════════════════════════════
        # الخطوة 2: تطبيق القواعد المضمنة مع السياق التاريخي
        # ═══════════════════════════════════════════════════════════
        
        knowledge_decision, confidence = await self._knowledge_based_decision(
            original_task=original_task,
            error_context=error_context,
            category=category,
            strategy=strategy,
            context=context,
            historical_insight=historical_insight,
            retry_count=retry_count,
            max_retries=max_retries
        )
        
        # ═══════════════════════════════════════════════════════════
        # الخطوة 3: تقييم ما إذا كنا نحتاج LLM
        # ═══════════════════════════════════════════════════════════
        
        needs_llm = self._should_escalate_to_llm(
            confidence=confidence,
            category=category,
            context=context,
            historical_insight=historical_insight
        )
        
        # ═══════════════════════════════════════════════════════════
        # الخطوة 4: استشارة LLM إذا لزم الأمر
        # ═══════════════════════════════════════════════════════════
        
        if needs_llm and self.llm_enabled:
            self.logger.info(
                f"[HYBRID] Knowledge confidence={confidence:.2f}, escalating to LLM"
            )
            llm_decision = await self._llm_decision(
                original_task, error_context, execution_logs, context
            )
            
            # Merge knowledge and LLM insights
            final_decision = self._merge_decisions(
                knowledge_decision, llm_decision, confidence
            )
        else:
            self.logger.info(
                f"[HYBRID] Knowledge confidence={confidence:.2f}, using knowledge-based decision"
            )
            final_decision = knowledge_decision
        
        # ═══════════════════════════════════════════════════════════
        # الخطوة 5: تسجيل القرار في الذاكرة التشغيلية
        # ═══════════════════════════════════════════════════════════
        
        # Record this decision for future learning (will be updated with outcome later)
        await self._record_decision_to_memory(
            original_task, final_decision, context
        )
        
        return final_decision
    
    async def _consult_operational_memory(
        self,
        task: Dict,
        error_context: Dict,
        context: Dict
    ) -> Dict[str, Any]:
        """
        استشارة الذاكرة التشغيلية للحصول على رؤى تاريخية
        """
        insight = {
            "historical_success_rate": 0.5,
            "sample_count": 0,
            "similar_failures": [],
            "successful_bypasses": []
        }
        
        try:
            # Get historical success rate for this action type
            task_type = task.get("type", "UNKNOWN")
            target_info = context.get("target_info") or {}
            target_os = (target_info.get("os") or "unknown").lower()
            defenses = context.get("detected_defenses", [])
            
            success_rate, samples = await self.memory.get_historical_success_rate(
                action_type=task_type,
                target_context={"os": target_os},
                defense_context=defenses
            )
            insight["historical_success_rate"] = success_rate
            insight["sample_count"] = samples
            
            # Get similar failures
            error_category = self._categorize_error(error_context.get("error_type", "unknown"))
            similar = await self.memory.get_similar_failures(
                action_type=task_type,
                error_category=error_category,
                limit=5
            )
            insight["similar_failures"] = similar
            
            # Get defense bypass history if defenses detected
            if defenses:
                for defense in defenses[:2]:
                    bypasses = await self.memory.get_defense_bypass_history(
                        defense_type=defense,
                        limit=5
                    )
                    insight["successful_bypasses"].extend(bypasses)
            
        except Exception as e:
            self.logger.warning(f"Error consulting memory: {e}")
        
        return insight
    
    async def _knowledge_based_decision(
        self,
        original_task: Dict,
        error_context: Dict,
        category: str,
        strategy: Dict,
        context: Dict,
        historical_insight: Dict,
        retry_count: int,
        max_retries: int
    ) -> Tuple[Dict, float]:
        """
        قرار قائم على المعرفة مع حساب مستوى الثقة
        
        Returns:
            Tuple of (decision_dict, confidence_score)
        """
        confidence = 0.5  # Base confidence
        
        # Adjust confidence based on historical data
        hist_samples = historical_insight.get("sample_count", 0)
        if hist_samples >= 5:
            # Good historical data -> higher confidence
            confidence += 0.2
        elif hist_samples >= 3:
            confidence += 0.1
        
        # Check for successful bypasses in history
        if historical_insight.get("successful_bypasses"):
            confidence += 0.15
        
        # Defense detected handling (IMPROVED)
        if category == "defense":
            # First: check memory for successful bypasses
            bypasses = historical_insight.get("successful_bypasses", [])
            if bypasses:
                best_bypass = bypasses[0]
                confidence += 0.1
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": f"Historical bypass found: {best_bypass.get('module_id')}",
                    "new_module": best_bypass.get("module_id"),
                    "modified_parameters": {"use_evasion": True},
                    "confidence": confidence,
                    "source": "historical_memory"
                }, confidence
            
            # Second: check Nuclei alternatives
            nuclei_alts = context.get("nuclei_alternatives", {})
            if nuclei_alts.get("alternative_approaches"):
                best_approach = nuclei_alts["alternative_approaches"][0]
                confidence += 0.05
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": f"Nuclei suggests: {best_approach.get('description')}",
                    "nuclei_approach": best_approach,
                    "confidence": confidence,
                    "source": "nuclei_knowledge"
                }, confidence
            
            # Third: KB alternatives
            if context.get("alternative_modules"):
                self._stats["modifications_recommended"] += 1
                return {
                    "decision": "modify_approach",
                    "reasoning": "KB alternative module available",
                    "new_module": context["alternative_modules"][0].get("rx_module_id"),
                    "confidence": confidence,
                    "source": "embedded_knowledge"
                }, confidence
            
            # No alternatives - low confidence
            confidence = 0.3
            return {
                "decision": "skip",
                "reasoning": "Defense detected, no alternatives found",
                "confidence": confidence,
                "source": "rule_based"
            }, confidence
        
        # Network issues - use historical success rate
        if category == "network":
            hist_rate = historical_insight.get("historical_success_rate", 0.5)
            
            # If history shows low success, don't waste retries
            if hist_rate < 0.2 and hist_samples >= 3:
                confidence = 0.7
                return {
                    "decision": "skip",
                    "reasoning": f"Historical success rate too low ({hist_rate:.0%})",
                    "confidence": confidence,
                    "source": "historical_memory"
                }, confidence
            
            if retry_count < max_retries:
                confidence = 0.6 + (hist_rate * 0.2)
                return {
                    "decision": "retry",
                    "reasoning": f"Network issue - retry {retry_count + 1}/{max_retries}",
                    "delay_seconds": strategy["retry_delay"],
                    "confidence": confidence,
                    "source": "rule_based"
                }, confidence
        
        # Authentication - check if we have better creds in memory
        if category == "authentication":
            if retry_count < max_retries:
                confidence = 0.5
                return {
                    "decision": "retry",
                    "reasoning": "Auth failed - may be transient",
                    "confidence": confidence,
                    "source": "rule_based"
                }, confidence
            else:
                # Suggest credential harvesting
                confidence = 0.6
                return {
                    "decision": "modify_approach",
                    "reasoning": "Need different credentials",
                    "modified_parameters": {"harvest_more_creds": True},
                    "confidence": confidence,
                    "source": "rule_based"
                }, confidence
        
        # Vulnerability patched
        if category == "vulnerability":
            # Before skipping, check if Nuclei suggests recon
            nuclei_alts = context.get("nuclei_alternatives", {})
            recon_approaches = [
                a for a in nuclei_alts.get("alternative_approaches", [])
                if a.get("type") == "reconnaissance"
            ]
            
            if recon_approaches:
                confidence = 0.55
                return {
                    "decision": "modify_approach",
                    "reasoning": "Patched - suggest additional recon",
                    "nuclei_approach": recon_approaches[0],
                    "confidence": confidence,
                    "source": "nuclei_knowledge"
                }, confidence
            
            confidence = 0.75
            return {
                "decision": "skip",
                "reasoning": "Target appears patched",
                "confidence": confidence,
                "source": "rule_based"
            }, confidence
        
        # Unknown - low confidence, may need LLM
        confidence = 0.4
        return {
            "decision": "escalate",
            "reasoning": "Unknown error type",
            "confidence": confidence,
            "source": "rule_based"
        }, confidence
    
    def _should_escalate_to_llm(
        self,
        confidence: float,
        category: str,
        context: Dict,
        historical_insight: Dict
    ) -> bool:
        """
        تحديد ما إذا كان يجب تصعيد القرار إلى LLM
        
        LLM يُستدعى فقط عندما:
        1. الثقة منخفضة (< 0.5)
        2. سيناريو معقد (عدة دفاعات)
        3. لا توجد بيانات تاريخية كافية
        """
        # Low confidence -> need LLM
        if confidence < self.LLM_ESCALATION_THRESHOLD:
            return True
        
        # Complex defense scenario
        defenses = context.get("detected_defenses", [])
        if len(defenses) > 2:
            return True
        
        # Many alternatives to choose from
        alternatives = context.get("alternative_modules", [])
        if len(alternatives) > 5:
            return True
        
        # Insufficient historical data and not a simple case
        samples = historical_insight.get("sample_count", 0)
        if samples < 3 and category in ("defense", "unknown"):
            return True
        
        return False
    
    def _merge_decisions(
        self,
        knowledge_decision: Dict,
        llm_decision: Dict,
        knowledge_confidence: float
    ) -> Dict:
        """
        دمج قرار المعرفة وقرار LLM
        
        القواعد:
        - إذا اتفقا -> استخدم LLM (أكثر تفصيلاً)
        - إذا اختلفا + knowledge_confidence > 0.6 -> استخدم Knowledge
        - إذا اختلفا + knowledge_confidence <= 0.6 -> استخدم LLM
        """
        knowledge_action = knowledge_decision.get("decision")
        llm_action = llm_decision.get("decision")
        
        # If they agree, use LLM decision (more detailed)
        if knowledge_action == llm_action:
            final = llm_decision.copy()
            final["merged"] = True
            final["agreement"] = True
            return final
        
        # If they disagree, use confidence to decide
        if knowledge_confidence > 0.6:
            self.logger.info(
                f"[MERGE] Decisions differ: Knowledge={knowledge_action}, LLM={llm_action}. "
                f"Using Knowledge (confidence={knowledge_confidence:.2f})"
            )
            final = knowledge_decision.copy()
            final["merged"] = True
            final["llm_suggestion"] = llm_action
            return final
        else:
            self.logger.info(
                f"[MERGE] Decisions differ: Knowledge={knowledge_action}, LLM={llm_action}. "
                f"Using LLM (knowledge_confidence={knowledge_confidence:.2f})"
            )
            final = llm_decision.copy()
            final["merged"] = True
            final["knowledge_suggestion"] = knowledge_action
            return final
    
    async def _record_decision_to_memory(
        self,
        task: Dict,
        decision: Dict,
        context: Dict
    ) -> None:
        """تسجيل القرار للتعلم المستقبلي"""
        # Note: The outcome will be recorded separately when we know if it succeeded
        # This just logs the decision for analysis
        if self.blackboard and self._current_mission_id:
            await self.blackboard.log_result(
                self._current_mission_id,
                "decision_made",
                {
                    "task_id": task.get("id"),
                    "decision": decision.get("decision"),
                    "confidence": decision.get("confidence"),
                    "source": decision.get("source"),
                    "merged": decision.get("merged", False)
                }
            )
```

---

### 4. تحسين AttackSpecialist مع الذاكرة التشغيلية

**التعديلات على:** `src/specialists/attack.py`

```python
# تعديلات على AttackSpecialist

class AttackSpecialist(BaseSpecialist):
    
    @property
    def memory(self) -> OperationalMemory:
        """Get operational memory instance"""
        if not hasattr(self, '_memory') or self._memory is None:
            from ..core.memory.operational import get_operational_memory
            self._memory = get_operational_memory(self.blackboard)
        return self._memory
    
    async def _get_dynamic_exploit_success_rate(
        self,
        vuln_type: str,
        rx_module: Optional[Dict[str, Any]] = None
    ) -> float:
        """
        حساب معدل نجاح الاستغلال ديناميكياً
        
        الأولوية:
        1. البيانات التاريخية من الذاكرة التشغيلية (الأكثر موثوقية)
        2. بيانات Knowledge Base
        3. قواعد احتياطية (الأقل موثوقية)
        """
        
        # ═══════════════════════════════════════════════════════════
        # الخطوة 1: استشارة الذاكرة التشغيلية (الأولوية القصوى)
        # ═══════════════════════════════════════════════════════════
        
        try:
            # Get target context
            target_os = "unknown"
            if hasattr(self, '_current_target_os'):
                target_os = self._current_target_os
            
            hist_rate, samples = await self.memory.get_historical_success_rate(
                action_type="EXPLOIT",
                target_context={"os": target_os, "vuln_type": vuln_type},
                defense_context=[]
            )
            
            if samples >= 5:
                # Strong historical data - use it directly
                self.logger.debug(
                    f"[MEMORY] Using historical rate for {vuln_type}: "
                    f"{hist_rate:.2f} (n={samples})"
                )
                return hist_rate
            elif samples >= 3:
                # Some data - blend with KB rate
                kb_rate = await self._get_kb_success_rate(vuln_type, rx_module)
                blended = (hist_rate * 0.6) + (kb_rate * 0.4)
                self.logger.debug(
                    f"[MEMORY] Blending rates: hist={hist_rate:.2f}, kb={kb_rate:.2f}, "
                    f"final={blended:.2f}"
                )
                return blended
        except Exception as e:
            self.logger.warning(f"Memory query failed: {e}")
        
        # ═══════════════════════════════════════════════════════════
        # الخطوة 2: استشارة Knowledge Base
        # ═══════════════════════════════════════════════════════════
        
        return await self._get_kb_success_rate(vuln_type, rx_module)
    
    async def _get_kb_success_rate(
        self,
        vuln_type: str,
        rx_module: Optional[Dict[str, Any]]
    ) -> float:
        """Get success rate from Knowledge Base"""
        
        base_rate = 0.35  # Conservative default
        
        if rx_module:
            base_rate = 0.5  # Module exists in KB
            
            reliability = rx_module.get("reliability")
            if reliability == "high":
                base_rate = 0.70
            elif reliability == "medium":
                base_rate = 0.50
            elif reliability == "low":
                base_rate = 0.35
            
            # References boost
            refs = rx_module.get("references", [])
            if len(refs) >= 3:
                base_rate = min(base_rate + 0.08, 0.90)
            
            # Evasion support
            if rx_module.get("supports_evasion"):
                base_rate = min(base_rate + 0.05, 0.90)
        
        # Query KB for additional data
        if self.knowledge and self.knowledge.is_loaded():
            try:
                modules = self.knowledge.search_modules(query=vuln_type, limit=1)
                if modules:
                    cvss = modules[0].get("cvss", 5.0)
                    cvss_factor = min(cvss / 10.0, 0.95)
                    # Blend CVSS with base rate
                    base_rate = (base_rate * 0.7) + (cvss_factor * 0.3)
            except Exception:
                pass
        
        return round(base_rate, 2)
    
    async def _execute_exploit(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        تنفيذ الاستغلال مع تسجيل النتيجة في الذاكرة
        """
        # ... existing exploit logic ...
        
        result = await self._do_exploit(task)  # Original implementation
        
        # ═══════════════════════════════════════════════════════════
        # تسجيل النتيجة في الذاكرة التشغيلية
        # ═══════════════════════════════════════════════════════════
        
        try:
            target_info = await self._get_target_info(task.get("target_id"))
            vuln_info = await self._get_vuln_info(task.get("vuln_id"))
            
            await self.memory.record_outcome(
                action_type="EXPLOIT",
                module_id=task.get("rx_module"),
                target_context={
                    "os": target_info.get("os", "unknown") if target_info else "unknown",
                    "vuln_type": vuln_info.get("type") if vuln_info else "unknown"
                },
                defense_context=[],  # Would be populated if defenses detected
                result="success" if result.get("success") else "failed",
                error_category=result.get("error_context", {}).get("error_type"),
                mission_id=UUID(self._current_mission_id) if self._current_mission_id else None
            )
        except Exception as e:
            self.logger.warning(f"Failed to record outcome: {e}")
        
        return result
```

---

## 🔄 مخطط التدفق الهجين

```
┌─────────────────────────────────────────────────────────────────────┐
│                     تدفق القرار الهجين                              │
│                  Hybrid Decision Flow                               │
└─────────────────────────────────────────────────────────────────────┘

       ┌─────────────┐
       │  Task/Event │
       └──────┬──────┘
              │
              ▼
    ┌─────────────────────┐
    │ 1. Query Operational│
    │    Memory           │
    │    (Historical Data)│
    └──────────┬──────────┘
              │
              ▼
    ┌─────────────────────┐
    │ 2. Apply Embedded   │
    │    Knowledge Rules  │
    │    (Nuclei + MITRE) │
    └──────────┬──────────┘
              │
              ▼
    ┌─────────────────────┐
    │ 3. Calculate        │
    │    Confidence Score │
    └──────────┬──────────┘
              │
         ┌────┴────┐
         │         │
    Conf > 0.6   Conf <= 0.6
         │         │
         ▼         ▼
    ┌─────────┐ ┌─────────────┐
    │ Execute │ │ 4. Consult  │
    │ Decision│ │    LLM      │
    └────┬────┘ └──────┬──────┘
         │            │
         │            ▼
         │     ┌─────────────┐
         │     │ 5. Merge    │
         │     │   Decisions │
         │     └──────┬──────┘
         │            │
         └─────┬──────┘
               │
               ▼
    ┌─────────────────────┐
    │ 6. Execute Action   │
    └──────────┬──────────┘
              │
              ▼
    ┌─────────────────────┐
    │ 7. Record Outcome   │
    │    to Memory        │
    │    (For Learning)   │
    └─────────────────────┘
```

---

## 📊 مقارنة: قبل وبعد

| الجانب | قبل (الحالي) | بعد (الهجين) |
|--------|-------------|--------------|
| مصدر Success Rate | `random.random()` + magic numbers | Historical Memory + KB + Fallback |
| استخدام التاريخ | يُكتب ولا يُقرأ | يُقرأ ويُكتب (bidirectional) |
| LLM Usage | ~15% من الحالات | عند الحاجة فقط (confidence < 0.6) |
| Cross-Workspace | لا يوجد | IntelligenceCoordinator |
| تعلم من الإخفاقات | غير موجود | Memory-based learning |
| تكلفة LLM | ثابتة | مُحسّنة (أقل استدعاءات) |
| موثوقية القرار | تعتمد على القواعد | تعتمد على البيانات |

---

## 📅 خطة التنفيذ المرحلية

### المرحلة 1: الذاكرة التشغيلية (الأسبوع 1-2)

```bash
# الملفات الجديدة
src/core/memory/__init__.py
src/core/memory/operational.py

# التعديلات
src/specialists/attack.py  # Add memory integration
src/specialists/analysis.py  # Add memory integration
```

**الاختبارات:**
- `tests/test_operational_memory.py`
- تأكد من أن الذاكرة تُحسّن دقة التوقعات

### المرحلة 2: تحسين محرك القرار (الأسبوع 2-3)

```bash
# التعديلات
src/specialists/analysis.py  # Hybrid decision engine
src/core/llm/prompts.py  # Add memory context to prompts
```

**الاختبارات:**
- `tests/test_hybrid_decisions.py`
- قياس: LLM calls قبل وبعد

### المرحلة 3: منسق الذكاء (الأسبوع 3-4)

```bash
# الملفات الجديدة
src/core/intelligence/__init__.py
src/core/intelligence/coordinator.py

# التعديلات
src/specialists/base.py  # Add coordinator access
src/controller/mission.py  # Integrate coordinator
```

**الاختبارات:**
- `tests/test_intelligence_coordinator.py`
- `tests/test_cross_workspace_correlation.py`

### المرحلة 4: التكامل والتحسين (الأسبوع 4-5)

- تكامل شامل
- اختبارات End-to-End
- قياس الأداء
- توثيق

---

## 📈 مقاييس النجاح

1. **تقليل استدعاءات LLM بـ 40%** مع الحفاظ على جودة القرارات
2. **زيادة دقة توقع Success Rate بـ 30%** (مقارنة بـ random)
3. **تحسين Cross-Workspace Correlation** - اكتشاف فرص lateral movement تلقائياً
4. **تقليل تكرار الإخفاقات** - عدم تكرار نفس الخطأ مرتين

---

## 🎯 الخلاصة

هذه الخطة تحقق **"عدم فقدان الغاية ولا الوسيلة"**:

- **الغاية (LLM)**: يبقى متاحاً للقرارات المعقدة، لكن يُستدعى بذكاء
- **الوسيلة (Embedded Knowledge)**: تبقى الأساس، مُعززة بذاكرة تشغيلية
- **النتيجة**: نظام **هجين** يجمع بين سرعة القواعد وذكاء LLM
