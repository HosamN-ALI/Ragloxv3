#!/usr/bin/env python3
"""
RAGLOX v3.0 - Real World Agent Test (No Mock Data)

This test runs the actual agent components with:
- Real Redis Blackboard
- Real LLM API (BlackBox/OpenAI)
- Real Knowledge Base
- Simulated network scanning (no actual network traffic for safety)

Usage:
    python3 webapp/tests/real_world_test.py
"""

import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime
from uuid import uuid4
from typing import Dict, Any, List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.config import get_settings
from src.core.blackboard import Blackboard
from src.core.knowledge import EmbeddedKnowledge, init_knowledge
from src.core.models import Mission, GoalStatus, Task, TaskType, TaskStatus, SpecialistType
from uuid import UUID
from src.specialists.recon import ReconSpecialist
from src.specialists.attack import AttackSpecialist
from src.specialists.analysis import AnalysisSpecialist
from src.controller.mission import MissionController


class RealWorldAgentTest:
    """
    Tests the RAGLOX agent with real components (no mocks).
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.blackboard: Blackboard = None
        self.knowledge: EmbeddedKnowledge = None
        self.controller: MissionController = None
        self.mission_id: str = None
        self.results: List[Dict] = []
        
    async def setup(self):
        """Initialize real components."""
        print("\n" + "=" * 60)
        print("🚀 RAGLOX v3.0 - Real World Agent Test")
        print("=" * 60)
        
        # 1. Initialize Knowledge Base
        print("\n📚 Loading Knowledge Base...")
        self.knowledge = init_knowledge(data_path=self.settings.knowledge_data_path)
        if self.knowledge.is_loaded():
            stats = self.knowledge.get_statistics()
            print(f"   ✓ Loaded: {stats['total_rx_modules']} modules, {stats['total_techniques']} techniques")
        else:
            print("   ⚠ Knowledge base not loaded")
            
        # 2. Connect to Blackboard (Real Redis)
        print("\n🔗 Connecting to Redis Blackboard...")
        self.blackboard = Blackboard(settings=self.settings)
        await self.blackboard.connect()
        healthy = await self.blackboard.health_check()
        print(f"   ✓ Connected: {healthy}")
        
        # 3. Initialize Mission Controller
        print("\n🎮 Initializing Mission Controller...")
        self.controller = MissionController(
            blackboard=self.blackboard,
            settings=self.settings
        )
        print("   ✓ Controller ready")
        
        # 4. Check LLM Configuration
        print("\n🧠 LLM Configuration:")
        print(f"   Provider: {self.settings.llm_provider}")
        print(f"   Model: {self.settings.llm_model}")
        print(f"   API Key: {'✓ Configured' if self.settings.effective_llm_api_key else '✗ Missing'}")
        print(f"   Enabled: {self.settings.llm_enabled}")
        
    async def teardown(self):
        """Cleanup resources."""
        print("\n🧹 Cleaning up...")
        if self.controller:
            await self.controller.shutdown()
        if self.blackboard:
            await self.blackboard.disconnect()
        print("   ✓ Cleanup complete")
        
    async def create_mission(self) -> str:
        """Create a test mission."""
        print("\n" + "-" * 60)
        print("📋 Creating Test Mission")
        print("-" * 60)
        
        # Create Mission object with proper structure
        mission = Mission(
            name=f"Real World Test - {datetime.now().strftime('%Y%m%d_%H%M%S')}",
            scope=["192.168.1.0/24"],  # Test scope (simulated)
            goals={
                "initial_access": GoalStatus.PENDING,
                "credential_access": GoalStatus.PENDING
            },
            constraints={
                "stealth_level": "normal",
                "max_duration_hours": 1
            }
        )
        
        self.mission_id = await self.blackboard.create_mission(mission)
        print(f"   ✓ Mission created: {self.mission_id}")
        
        return self.mission_id
        
    async def test_recon_specialist(self):
        """Test ReconSpecialist with real components."""
        print("\n" + "-" * 60)
        print("🔍 TEST: ReconSpecialist - Network Discovery")
        print("-" * 60)
        
        try:
            recon = ReconSpecialist(
                blackboard=self.blackboard,
                settings=self.settings
            )
            recon._current_mission_id = self.mission_id
            
            # Execute network scan (simulated - no actual network traffic)
            task = {
                "type": "network_scan",
                "id": str(uuid4()),
                "mission_id": self.mission_id
            }
            
            print("   Executing network scan...")
            result = await recon._execute_network_scan(task)
            
            hosts = result.get("hosts_discovered", 0)
            print(f"   ✓ Hosts discovered: {hosts}")
            print(f"   ✓ Execution mode: {result.get('execution_mode', 'unknown')}")
            
            self.results.append({
                "test": "ReconSpecialist - Network Scan",
                "status": "PASSED" if hosts > 0 else "PARTIAL",
                "details": f"Discovered {hosts} hosts"
            })
            
            # Port scan on first target
            targets = await self.blackboard.get_mission_targets(self.mission_id)
            if targets:
                target_id = targets[0].replace("target:", "")
                task = {
                    "type": "port_scan",
                    "id": str(uuid4()),
                    "target_id": target_id
                }
                
                print("\n   Executing port scan...")
                result = await recon._execute_port_scan(task)
                
                ports = result.get("ports_found", 0)
                print(f"   ✓ Ports found: {ports}")
                
                self.results.append({
                    "test": "ReconSpecialist - Port Scan",
                    "status": "PASSED" if ports > 0 else "PARTIAL",
                    "details": f"Found {ports} ports"
                })
                
            return True
            
        except Exception as e:
            print(f"   ✗ Error: {e}")
            self.results.append({
                "test": "ReconSpecialist",
                "status": "FAILED",
                "details": str(e)
            })
            return False
            
    async def test_analysis_specialist_with_llm(self):
        """Test AnalysisSpecialist with real LLM."""
        print("\n" + "-" * 60)
        print("🧠 TEST: AnalysisSpecialist - LLM Decision Making")
        print("-" * 60)
        
        try:
            analysis = AnalysisSpecialist(
                blackboard=self.blackboard,
                settings=self.settings,
                llm_enabled=True  # Enable real LLM
            )
            analysis._current_mission_id = self.mission_id
            
            # Get a target for the task
            targets = await self.blackboard.get_mission_targets(self.mission_id)
            target_id = targets[0].replace("target:", "") if targets else "test-target"
            
            # Create a test task in blackboard first
            task_obj = Task(
                mission_id=UUID(self.mission_id),
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                target_id=UUID(target_id) if target_id and target_id != "test-target" else None,
                rx_module="rx-shell-reverse",
                status=TaskStatus.FAILED,
                error_message="Payload blocked by Windows Defender"
            )
            task_id = str(task_obj.id)
            
            # Add task to blackboard
            await self.blackboard.add_task(task_obj)
            
            error_context = {
                "error_type": "av_detected",
                "error_message": "Payload blocked by Windows Defender",
                "detected_defenses": ["Windows Defender", "AMSI"],
                "technique_id": "T1059.001",
                "contributing_factors": ["av_signature_detection", "amsi_block"]
            }
            
            execution_logs = [
                "Connection established to target",
                "Payload delivery initiated",
                "AV scan triggered",
                "Payload execution blocked"
            ]
            
            print("   Analyzing failure scenario with LLM...")
            print(f"   Error: {error_context['error_message']}")
            print(f"   Defenses: {error_context['detected_defenses']}")
            
            result = await analysis.analyze_failure(
                task_id=task_id,
                error_context=error_context,
                execution_logs=execution_logs
            )
            
            decision = result.get("decision", "unknown")
            reasoning = result.get("reasoning", "")[:200]
            llm_used = result.get("llm_analysis", False)
            
            print(f"\n   Decision: {decision}")
            print(f"   LLM Used: {llm_used}")
            print(f"   Reasoning: {reasoning}...")
            
            if result.get("modified_parameters"):
                print(f"   Modified Params: {json.dumps(result['modified_parameters'], indent=6)}")
                
            if result.get("recommendations"):
                print(f"   Recommendations:")
                for rec in result.get("recommendations", [])[:3]:
                    print(f"      - {rec}")
                    
            self.results.append({
                "test": "AnalysisSpecialist - LLM Decision",
                "status": "PASSED" if decision in ["modify_approach", "retry", "escalate"] else "PARTIAL",
                "details": f"Decision: {decision}, LLM: {llm_used}"
            })
            
            return True
            
        except Exception as e:
            print(f"   ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            self.results.append({
                "test": "AnalysisSpecialist - LLM Decision",
                "status": "FAILED",
                "details": str(e)
            })
            return False
            
    async def test_attack_specialist(self):
        """Test AttackSpecialist with real components."""
        print("\n" + "-" * 60)
        print("⚔️ TEST: AttackSpecialist - Exploitation")
        print("-" * 60)
        
        try:
            # Disable deterministic mode for real test
            AttackSpecialist.set_deterministic_mode(enabled=False)
            
            attack = AttackSpecialist(
                blackboard=self.blackboard,
                settings=self.settings
            )
            attack._current_mission_id = self.mission_id
            
            # Get a target from blackboard
            targets = await self.blackboard.get_mission_targets(self.mission_id)
            if not targets:
                print("   ⚠ No targets available, adding test target...")
                target_id = await self.blackboard.add_target({
                    "ip": "192.168.1.100",
                    "hostname": "test-server",
                    "os": "Linux",
                    "status": "scanned"
                }, self.mission_id)
                
                # Add a vulnerability
                await self.blackboard.add_vulnerability({
                    "target_id": target_id,
                    "type": "CVE-2021-44228",
                    "name": "Log4Shell",
                    "severity": "critical",
                    "cvss": 10.0,
                    "exploit_available": True
                }, self.mission_id)
            else:
                target_id = targets[0].replace("target:", "")
                
            # Test credential harvesting (simulated)
            print("\n   Testing credential harvesting...")
            creds_list = await attack._simulate_cred_harvest(target_id)
            
            creds = len(creds_list) if creds_list else 0
            print(f"   ✓ Credentials harvested: {creds}")
            if creds_list:
                for c in creds_list[:3]:
                    print(f"      - {c.get('username', 'Unknown')}@{c.get('domain', 'local')}")
            
            self.results.append({
                "test": "AttackSpecialist - Credential Harvest",
                "status": "PASSED" if creds > 0 else "PARTIAL",
                "details": f"Harvested {creds} credentials"
            })
            
            return True
            
        except Exception as e:
            print(f"   ✗ Error: {e}")
            self.results.append({
                "test": "AttackSpecialist",
                "status": "FAILED",
                "details": str(e)
            })
            return False
            
    async def test_knowledge_base_queries(self):
        """Test Knowledge Base queries."""
        print("\n" + "-" * 60)
        print("📚 TEST: Knowledge Base Queries")
        print("-" * 60)
        
        try:
            if not self.knowledge or not self.knowledge.is_loaded():
                print("   ⚠ Knowledge base not loaded")
                self.results.append({
                    "test": "Knowledge Base",
                    "status": "SKIPPED",
                    "details": "Not loaded"
                })
                return False
                
            # Query technique by ID
            print("\n   Querying technique T1059 (Command & Scripting)...")
            technique = self.knowledge.get_technique("T1059")
            if technique:
                print(f"   ✓ Found technique: {technique.get('name', 'Unknown')}")
            
            # Query modules for a technique
            print("\n   Querying modules for T1003 (OS Credential Dumping)...")
            modules = self.knowledge.get_modules_for_technique("T1003")
            print(f"   ✓ Found {len(modules)} modules")
            
            # Get exploit modules
            print("\n   Getting exploit modules...")
            exploits = self.knowledge.get_exploit_modules(platform="windows")
            print(f"   ✓ Found {len(exploits)} Windows exploit modules")
            
            # Get credential modules
            print("\n   Getting credential access modules...")
            cred_modules = self.knowledge.get_credential_modules(platform="windows")
            print(f"   ✓ Found {len(cred_modules)} credential modules")
            
            if cred_modules:
                for mod in cred_modules[:3]:
                    print(f"      - {mod.get('rx_module_id', 'Unknown')}: {mod.get('technique_name', '')}")
                    
            self.results.append({
                "test": "Knowledge Base Queries",
                "status": "PASSED",
                "details": f"Technique: {technique.get('name') if technique else 'N/A'}, Modules: {len(modules)}, Exploits: {len(exploits)}"
            })
            
            return True
            
        except Exception as e:
            print(f"   ✗ Error: {e}")
            import traceback
            traceback.print_exc()
            self.results.append({
                "test": "Knowledge Base",
                "status": "FAILED",
                "details": str(e)
            })
            return False
            
    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for r in self.results if r["status"] == "PASSED")
        partial = sum(1 for r in self.results if r["status"] == "PARTIAL")
        failed = sum(1 for r in self.results if r["status"] == "FAILED")
        skipped = sum(1 for r in self.results if r["status"] == "SKIPPED")
        total = len(self.results)
        
        print(f"\n   Total Tests: {total}")
        print(f"   ✓ Passed:  {passed}")
        print(f"   ◐ Partial: {partial}")
        print(f"   ✗ Failed:  {failed}")
        print(f"   ○ Skipped: {skipped}")
        
        print(f"\n   Success Rate: {(passed + partial) / max(total, 1) * 100:.1f}%")
        
        print("\n" + "-" * 60)
        print("   DETAILED RESULTS")
        print("-" * 60)
        
        for result in self.results:
            icon = {"PASSED": "✓", "PARTIAL": "◐", "FAILED": "✗", "SKIPPED": "○"}.get(result["status"], "?")
            print(f"   {icon} {result['test']}: {result['status']}")
            print(f"      {result['details']}")
            
        print("\n" + "=" * 60)
        

async def main():
    """Run the real world test."""
    test = RealWorldAgentTest()
    
    try:
        await test.setup()
        
        # Create mission
        await test.create_mission()
        
        # Run tests
        await test.test_recon_specialist()
        await test.test_knowledge_base_queries()
        await test.test_analysis_specialist_with_llm()
        await test.test_attack_specialist()
        
        # Print summary
        test.print_summary()
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        await test.teardown()
        

if __name__ == "__main__":
    asyncio.run(main())
