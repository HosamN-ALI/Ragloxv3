"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Intelligence Layer Integration Tests
═══════════════════════════════════════════════════════════════════════════════

Comprehensive integration testing for the 3 new intelligence components:
1. AdaptiveLearningLayer
2. DefenseIntelligence  
3. StrategicAttackPlanner

Tests verify full integration with existing components:
- IntelligenceCoordinator
- StrategicScorer
- OperationalMemory

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Intelligence Layer imports
from src.intelligence import (
    AdaptiveLearningLayer,
    DefenseIntelligence,
    StrategicAttackPlanner,
    AttackStage,
    OptimizationGoal,
    DefenseType,
)

# Core imports
from src.core.intelligence_coordinator import IntelligenceCoordinator, AttackPathType
from src.core.strategic_scorer import StrategicScorer, RiskLevel
from src.core.operational_memory import OperationalMemory, OperationalContext, DecisionOutcome


# ═══════════════════════════════════════════════════════════════════════════════
# Test Utilities
# ═══════════════════════════════════════════════════════════════════════════════

class TestResult:
    """Test result tracker."""
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.duration_ms = 0
        self.error = None
        self.details = {}
    
    def to_dict(self):
        return {
            "name": self.name,
            "passed": self.passed,
            "duration_ms": self.duration_ms,
            "error": str(self.error) if self.error else None,
            "details": self.details
        }


def print_test_header(test_name: str):
    """Print test header."""
    print(f"\n{'='*80}")
    print(f"🧪 TEST: {test_name}")
    print(f"{'='*80}")


def print_test_result(result: TestResult):
    """Print test result."""
    status = "✅ PASSED" if result.passed else "❌ FAILED"
    print(f"{status} - {result.name} ({result.duration_ms}ms)")
    if result.error:
        print(f"   Error: {result.error}")
    if result.details:
        for key, value in result.details.items():
            print(f"   {key}: {value}")


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Test Suite
# ═══════════════════════════════════════════════════════════════════════════════

class IntelligenceIntegrationTests:
    """
    Comprehensive integration tests for Intelligence Layer.
    
    Tests:
    1. AdaptiveLearningLayer integration
    2. DefenseIntelligence integration
    3. StrategicAttackPlanner integration
    4. Full stack integration (all 3 + existing components)
    5. Performance benchmarks
    """
    
    def __init__(self):
        self.results: List[TestResult] = []
        
        # Initialize components
        self.learning = AdaptiveLearningLayer(
            storage_path="./data/learning_test",
            auto_save=False
        )
        
        self.defense_intel = DefenseIntelligence()
        
        self.coordinator = IntelligenceCoordinator()
        self.scorer = StrategicScorer()
        self.memory = OperationalMemory()
        
        self.planner = StrategicAttackPlanner(
            intelligence_coordinator=self.coordinator,
            strategic_scorer=self.scorer,
            operational_memory=self.memory,
            adaptive_learning=self.learning,
            defense_intelligence=self.defense_intel
        )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Test 1: AdaptiveLearningLayer Integration
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_adaptive_learning_integration(self):
        """Test AdaptiveLearningLayer learns from operations."""
        result = TestResult("AdaptiveLearningLayer Integration")
        start_time = time.time()
        
        try:
            # Simulate 10 operations with varying outcomes
            operations = [
                {
                    "operation_type": "exploit",
                    "technique_id": "T1190",
                    "target_info": {"os": "linux", "services": ["http"]},
                    "parameters": {"module": "log4shell", "port": 80},
                    "result": {"success": True, "duration_ms": 1500, "metrics": {"sessions": 1}}
                },
                {
                    "operation_type": "exploit",
                    "technique_id": "T1190",
                    "target_info": {"os": "linux", "services": ["http"]},
                    "parameters": {"module": "log4shell", "port": 8080},
                    "result": {"success": True, "duration_ms": 1200, "metrics": {"sessions": 1}}
                },
                {
                    "operation_type": "exploit",
                    "technique_id": "T1078",
                    "target_info": {"os": "windows", "services": ["rdp"]},
                    "parameters": {"module": "rdp_bruteforce", "port": 3389},
                    "result": {"success": False, "error_message": "Connection refused", "duration_ms": 5000}
                },
            ]
            
            # Learn from operations
            for op in operations:
                await self.learning.learn_from_operation(
                    operation_type=op["operation_type"],
                    technique_id=op["technique_id"],
                    target_info=op["target_info"],
                    parameters=op["parameters"],
                    result=op["result"]
                )
            
            # Test recommendations
            params = self.learning.suggest_parameters(
                operation_type="exploit",
                technique_id="T1190",
                target_info={"os": "linux", "services": ["http"]}
            )
            
            # Test skip detection
            should_skip, reason = self.learning.should_skip_operation(
                operation_type="exploit",
                technique_id="T1078",
                target_info={"os": "windows", "services": ["rdp"]}
            )
            
            # Verify learning
            stats = self.learning.get_learning_stats()
            
            result.passed = (
                stats["total_operations"] >= 3 and
                stats["success_rate"] > 0.5 and
                len(params) > 0
            )
            
            result.details = {
                "operations_learned": stats["total_operations"],
                "success_rate": f"{stats['success_rate']:.1%}",
                "patterns_discovered": stats["patterns_discovered"],
                "recommendations_made": stats["recommendations_made"],
                "param_suggestions": len(params),
                "skip_recommendation": should_skip
            }
            
        except Exception as e:
            result.error = e
            result.passed = False
        
        result.duration_ms = int((time.time() - start_time) * 1000)
        self.results.append(result)
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Test 2: DefenseIntelligence Integration
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_defense_intelligence_integration(self):
        """Test DefenseIntelligence detects defenses and suggests evasions."""
        result = TestResult("DefenseIntelligence Integration")
        start_time = time.time()
        
        try:
            # Simulate operation results with defense indicators
            operation_results = [
                {
                    "target_id": "target_001",
                    "result": {
                        "error_message": "Connection filtered by firewall",
                        "ports_filtered": 100,
                        "ports_open": 2
                    },
                    "logs": [
                        {"message": "Port 445 filtered"},
                        {"message": "Connection timeout on port 3389"}
                    ]
                },
                {
                    "target_id": "target_002",
                    "result": {
                        "http_status": 403,
                        "error_message": "Request blocked by WAF",
                        "headers": {"X-WAF": "Cloudflare"}
                    },
                    "logs": []
                }
            ]
            
            all_defenses = []
            all_evasions = []
            
            # Detect defenses
            for op_result in operation_results:
                defenses = self.defense_intel.detect_defenses(
                    target_id=op_result["target_id"],
                    operation_result=op_result["result"],
                    execution_logs=op_result["logs"]
                )
                all_defenses.extend(defenses)
                
                if defenses:
                    # Get evasion suggestions
                    evasions = self.defense_intel.suggest_evasion_techniques(
                        detected_defenses=defenses,
                        operation_type="scan"
                    )
                    all_evasions.extend(evasions)
                    
                    # Create evasion plan
                    plan = self.defense_intel.create_evasion_plan(
                        detected_defenses=defenses,
                        operation_type="scan"
                    )
            
            # Get defense profile
            profile_1 = self.defense_intel.get_target_defense_profile("target_001")
            profile_2 = self.defense_intel.get_target_defense_profile("target_002")
            
            result.passed = (
                len(all_defenses) >= 2 and
                len(all_evasions) > 0 and
                profile_1["defenses"] and
                profile_2["defenses"]
            )
            
            result.details = {
                "defenses_detected": len(all_defenses),
                "defense_types": list(set(d.defense_type.value for d in all_defenses)),
                "evasion_techniques_suggested": len(all_evasions),
                "target1_defenses": len(profile_1["defenses"]),
                "target2_defenses": len(profile_2["defenses"])
            }
            
        except Exception as e:
            result.error = e
            result.passed = False
        
        result.duration_ms = int((time.time() - start_time) * 1000)
        self.results.append(result)
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Test 3: StrategicAttackPlanner Integration
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_strategic_planner_integration(self):
        """Test StrategicAttackPlanner generates complete campaigns."""
        result = TestResult("StrategicAttackPlanner Integration")
        start_time = time.time()
        
        try:
            # Mock targets
            targets = [
                {"id": "target_001", "ip": "192.168.1.10", "hostname": "server1.local"},
                {"id": "target_002", "ip": "192.168.1.20", "hostname": "server2.local"},
                {"id": "target_003", "ip": "192.168.1.30", "hostname": "dc.local"},
            ]
            
            # Mock discovered data
            discovered_data = {
                "services": {
                    "target_001": [{"name": "http", "port": 80}, {"name": "ssh", "port": 22}],
                    "target_002": [{"name": "smb", "port": 445}, {"name": "rdp", "port": 3389}],
                    "target_003": [{"name": "ldap", "port": 389}, {"name": "kerberos", "port": 88}],
                },
                "vulnerabilities": {
                    "target_001": [
                        {"id": "CVE-2021-44228", "type": "log4j_rce", "severity": "critical"}
                    ],
                    "target_002": [
                        {"id": "CVE-2020-0796", "type": "smbghost", "severity": "critical"}
                    ]
                },
                "credentials": [
                    {"id": "cred_001", "username": "admin", "type": "password"}
                ]
            }
            
            # Test 1: Domain Admin campaign
            campaign_domain = await self.planner.plan_campaign(
                mission_id="mission_test_001",
                mission_goals=["domain_admin"],
                targets=targets,
                discovered_data=discovered_data,
                constraints={"stealth_level": "high"}
            )
            
            # Test 2: Data Exfiltration campaign
            campaign_exfil = await self.planner.plan_campaign(
                mission_id="mission_test_002",
                mission_goals=["data_exfiltration"],
                targets=targets,
                discovered_data=discovered_data,
                constraints={"speed_priority": True}
            )
            
            # Test 3: Optimization
            optimized_stealth = await self.planner.optimize_for_stealth(campaign_domain)
            optimized_speed = await self.planner.optimize_for_speed(campaign_exfil)
            
            result.passed = (
                len(campaign_domain.stages) >= 4 and
                len(campaign_exfil.stages) >= 3 and
                campaign_domain.overall_success_probability > 0 and
                optimized_stealth.overall_detection_risk < campaign_domain.overall_detection_risk and
                optimized_speed.total_estimated_duration_minutes < campaign_exfil.total_estimated_duration_minutes
            )
            
            result.details = {
                "domain_campaign_stages": len(campaign_domain.stages),
                "domain_success_prob": f"{campaign_domain.overall_success_probability:.1%}",
                "domain_detection_risk": f"{campaign_domain.overall_detection_risk:.1%}",
                "domain_duration": f"{campaign_domain.total_estimated_duration_minutes}min",
                "exfil_campaign_stages": len(campaign_exfil.stages),
                "exfil_success_prob": f"{campaign_exfil.overall_success_probability:.1%}",
                "stealth_optimization_detection": f"{optimized_stealth.overall_detection_risk:.1%}",
                "speed_optimization_duration": f"{optimized_speed.total_estimated_duration_minutes}min"
            }
            
        except Exception as e:
            result.error = e
            result.passed = False
        
        result.duration_ms = int((time.time() - start_time) * 1000)
        self.results.append(result)
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Test 4: Full Stack Integration
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_full_stack_integration(self):
        """Test all intelligence components working together."""
        result = TestResult("Full Stack Integration")
        start_time = time.time()
        
        try:
            # Scenario: Complete attack workflow
            
            # Step 1: Recon results → IntelligenceCoordinator
            targets = [{"id": "target_full", "ip": "10.0.0.10", "os": "linux"}]
            services = [{"name": "http", "port": 8080, "version": "nginx/1.18.0"}]
            vulnerabilities = [
                {"id": "CVE-2021-44228", "type": "log4j_rce", "severity": "critical", "exploit_available": True}
            ]
            
            # Step 2: Strategic analysis
            analysis = await self.coordinator.process_recon_results(
                mission_id="mission_full_stack",
                target_id="target_full",
                services=services,
                vulnerabilities=vulnerabilities
            )
            
            # Step 3: Vulnerability scoring
            vuln_score = await self.scorer.score_vulnerability(
                vuln_id="CVE-2021-44228",
                vuln_type="log4j_rce",
                target_info=targets[0],
                mission_goals=["initial_access"]
            )
            
            # Step 4: Generate campaign with all intelligence
            campaign = await self.planner.plan_campaign(
                mission_id="mission_full_stack",
                mission_goals=["initial_access", "persistence"],
                targets=targets,
                discovered_data={
                    "services": {"target_full": services},
                    "vulnerabilities": {"target_full": vulnerabilities}
                },
                constraints={"stealth_level": "normal"}
            )
            
            # Step 5: Simulate operation execution with learning
            operation_result = {
                "success": True,
                "duration_ms": 2500,
                "metrics": {"sessions_opened": 1}
            }
            
            await self.learning.learn_from_operation(
                operation_type="exploit",
                technique_id="T1190",
                target_info=targets[0],
                parameters={"module": "log4shell"},
                result=operation_result
            )
            
            # Step 6: Simulate defense detection
            defense_result = {
                "error_message": "Rate limit exceeded",
                "http_status": 429
            }
            
            defenses = self.defense_intel.detect_defenses(
                target_id="target_full",
                operation_result=defense_result,
                execution_logs=[]
            )
            
            result.passed = (
                analysis.strategic_value in ["high", "critical"] and
                vuln_score.composite_score > 0.7 and
                len(campaign.stages) >= 2 and
                self.learning.stats.total_operations > 0
            )
            
            result.details = {
                "strategic_value": analysis.strategic_value,
                "attack_paths_found": len(analysis.recommended_paths),
                "vuln_composite_score": f"{vuln_score.composite_score:.2f}",
                "campaign_stages": len(campaign.stages),
                "learning_operations": self.learning.stats.total_operations,
                "defenses_detected": len(defenses)
            }
            
        except Exception as e:
            result.error = e
            result.passed = False
        
        result.duration_ms = int((time.time() - start_time) * 1000)
        self.results.append(result)
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Test 5: Performance Benchmarks
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_performance_benchmarks(self):
        """Benchmark performance of intelligence components."""
        result = TestResult("Performance Benchmarks")
        start_time = time.time()
        
        try:
            benchmarks = {}
            
            # Benchmark 1: Campaign generation speed
            targets = [{"id": f"target_{i}", "ip": f"10.0.0.{i}"} for i in range(10)]
            
            campaign_start = time.time()
            campaign = await self.planner.plan_campaign(
                mission_id="benchmark_mission",
                mission_goals=["domain_admin"],
                targets=targets,
                constraints={}
            )
            benchmarks["campaign_generation_ms"] = int((time.time() - campaign_start) * 1000)
            
            # Benchmark 2: Learning speed (100 operations)
            learning_start = time.time()
            for i in range(100):
                await self.learning.learn_from_operation(
                    operation_type="scan",
                    technique_id="T1046",
                    target_info={"os": "linux"},
                    parameters={"port": 80 + i},
                    result={"success": i % 2 == 0, "duration_ms": 100}
                )
            benchmarks["learning_100_ops_ms"] = int((time.time() - learning_start) * 1000)
            
            # Benchmark 3: Defense detection speed
            defense_start = time.time()
            for i in range(50):
                self.defense_intel.detect_defenses(
                    target_id=f"target_{i}",
                    operation_result={"error_message": "Connection refused"},
                    execution_logs=[]
                )
            benchmarks["defense_detection_50x_ms"] = int((time.time() - defense_start) * 1000)
            
            # Performance thresholds
            result.passed = (
                benchmarks["campaign_generation_ms"] < 5000 and  # < 5 seconds
                benchmarks["learning_100_ops_ms"] < 10000 and     # < 10 seconds
                benchmarks["defense_detection_50x_ms"] < 2000     # < 2 seconds
            )
            
            result.details = benchmarks
            
        except Exception as e:
            result.error = e
            result.passed = False
        
        result.duration_ms = int((time.time() - start_time) * 1000)
        self.results.append(result)
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Test Runner
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def run_all_tests(self):
        """Run all integration tests."""
        print("\n" + "="*80)
        print("🧪 RAGLOX v3.0 - Intelligence Layer Integration Tests")
        print("="*80)
        
        tests = [
            ("AdaptiveLearningLayer Integration", self.test_adaptive_learning_integration),
            ("DefenseIntelligence Integration", self.test_defense_intelligence_integration),
            ("StrategicAttackPlanner Integration", self.test_strategic_planner_integration),
            ("Full Stack Integration", self.test_full_stack_integration),
            ("Performance Benchmarks", self.test_performance_benchmarks),
        ]
        
        for test_name, test_func in tests:
            print_test_header(test_name)
            result = await test_func()
            print_test_result(result)
        
        # Summary
        print("\n" + "="*80)
        print("📊 TEST SUMMARY")
        print("="*80)
        
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        success_rate = (passed / total * 100) if total > 0 else 0
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed} ✅")
        print(f"Failed: {failed} ❌")
        print(f"Success Rate: {success_rate:.1f}%")
        print(f"Total Duration: {sum(r.duration_ms for r in self.results)}ms")
        
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "success_rate": success_rate,
            "results": [r.to_dict() for r in self.results]
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main test runner."""
    tester = IntelligenceIntegrationTests()
    summary = await tester.run_all_tests()
    
    # Save results
    import json
    output_path = Path(__file__).parent / "intelligence_integration_results.json"
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"\n✅ Results saved to: {output_path}")
    
    # Exit with appropriate code
    exit_code = 0 if summary["success_rate"] == 100 else 1
    return exit_code


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
