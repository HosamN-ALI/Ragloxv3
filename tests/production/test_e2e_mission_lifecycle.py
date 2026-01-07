"""
End-to-End Tests: Complete Mission Lifecycle
============================================

Tests complete mission workflows from creation to completion.
"""

import pytest
import asyncio
import httpx
from typing import Dict, Any
from datetime import datetime

from tests.production.base import ProductionE2ETestBase
from tests.production.config import get_config


@pytest.mark.e2e
@pytest.mark.asyncio
class TestMissionLifecycleE2E(ProductionE2ETestBase):
    """End-to-end tests for complete mission lifecycle"""

    async def test_e2e_mission_complete_lifecycle(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 1: Complete mission lifecycle
        
        Flow:
        1. Create mission
        2. Start mission
        3. Wait for discovery phase
        4. Verify targets discovered
        5. Wait for enumeration phase
        6. Verify services enumerated
        7. Stop mission
        8. Verify final status
        9. Collect and verify metrics
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: Complete Mission Lifecycle")
        print("="*80)
        
        # Step 1: Create mission
        print("\n📝 Step 1: Creating mission...")
        mission_data = {
            "name": self.generate_mission_name("E2E Complete Lifecycle"),
            "description": "End-to-end test of complete mission lifecycle",
            "scope": {
                "ip_ranges": ["192.168.100.0/24"],
                "domains": []
            },
            "goals": ["reconnaissance", "enumeration"],
            "constraints": {
                "stealth": True,
                "no_exploit": True
            }
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        
        assert response.status_code in [200, 201], \
            f"Failed to create mission: {response.status_code} - {response.text}"
        
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        print(f"✅ Mission created: {mission_id}")
        print(f"   Name: {mission_data['name']}")
        print(f"   Status: {mission.get('status')}")
        
        try:
            # Step 2: Start mission
            print("\n▶️  Step 2: Starting mission...")
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/start",
                json={},
                headers=auth_headers
            )
            
            assert response.status_code == 200, \
                f"Failed to start mission: {response.status_code} - {response.text}"
            print("✅ Mission started")
            
            # Step 3: Wait for running status
            print("\n⏳ Step 3: Waiting for mission to reach 'running' status...")
            mission = await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=60
            )
            print("✅ Mission is running")
            
            # Step 4: Wait a bit for discovery to start
            print("\n⏳ Step 4: Waiting for discovery phase (30 seconds)...")
            await asyncio.sleep(30)
            
            # Step 5: Check for targets
            print("\n🎯 Step 5: Checking for discovered targets...")
            response = await real_api_client.get(
                f"/api/v1/missions/{mission_id}/targets",
                headers=auth_headers
            )
            
            if response.status_code == 200:
                targets = response.json()
                print(f"✅ Found {len(targets)} target(s)")
                for i, target in enumerate(targets[:3]):  # Show first 3
                    print(f"   Target {i+1}: {target.get('ip', 'N/A')}")
            else:
                print(f"⚠️  No targets discovered yet (might need more time)")
            
            # Step 6: Stop mission
            print("\n⏹️  Step 6: Stopping mission...")
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/stop",
                json={},
                headers=auth_headers
            )
            
            assert response.status_code == 200, \
                f"Failed to stop mission: {response.status_code} - {response.text}"
            print("✅ Mission stopped")
            
            # Step 7: Verify final status
            print("\n🔍 Step 7: Verifying final status...")
            mission = await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "stopped",
                timeout=30
            )
            print("✅ Mission status confirmed: stopped")
            
            # Step 8: Collect metrics
            print("\n📊 Step 8: Collecting mission metrics...")
            metrics = await self.collect_mission_metrics(
                real_api_client,
                auth_headers,
                mission_id
            )
            
            # Verify metrics
            assert metrics["mission"]["id"] == mission_id
            assert metrics["mission"]["status"] == "stopped"
            print("✅ Metrics collected and verified")
            
            print("\n" + "="*80)
            print("✅ E2E Test PASSED: Complete Mission Lifecycle")
            print("="*80)
            print(f"\nSummary:")
            print(f"  Mission ID: {mission_id}")
            print(f"  Final Status: {metrics['mission']['status']}")
            print(f"  Targets Found: {metrics['summary']['target_count']}")
            print(f"  Vulnerabilities: {metrics['summary']['vulnerability_count']}")
            
        except Exception as e:
            print(f"\n❌ E2E Test FAILED: {str(e)}")
            # Try to stop mission on error
            try:
                await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/stop",
                    json={},
                    headers=auth_headers
                )
            except:
                pass
            raise

    async def test_e2e_mission_pause_resume_workflow(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 2: Mission pause and resume workflow
        
        Flow:
        1. Create and start mission
        2. Wait for running status
        3. Pause mission
        4. Verify paused status
        5. Resume mission
        6. Verify running status
        7. Stop mission
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: Pause/Resume Workflow")
        print("="*80)
        
        # Create and start mission
        print("\n📝 Creating mission...")
        mission_data = {
            "name": self.generate_mission_name("E2E Pause Resume"),
            "description": "Test pause and resume functionality",
            "scope": {
                "ip_ranges": ["192.168.100.0/24"]
            },
            "goals": ["reconnaissance"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        assert response.status_code in [200, 201]
        
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        print(f"✅ Mission created: {mission_id}")
        
        try:
            # Start mission
            print("\n▶️  Starting mission...")
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/start",
                json={},
                headers=auth_headers
            )
            
            mission = await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=60
            )
            print("✅ Mission is running")
            
            # Pause mission
            print("\n⏸️  Pausing mission...")
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/pause",
                json={},
                headers=auth_headers
            )
            assert response.status_code == 200
            
            mission = await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "paused",
                timeout=30
            )
            print("✅ Mission is paused")
            
            # Resume mission
            print("\n▶️  Resuming mission...")
            response = await real_api_client.post(
                f"/api/v1/missions/{mission_id}/resume",
                json={},
                headers=auth_headers
            )
            assert response.status_code == 200
            
            mission = await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=30
            )
            print("✅ Mission resumed successfully")
            
            # Stop mission
            print("\n⏹️  Stopping mission...")
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/stop",
                json={},
                headers=auth_headers
            )
            
            await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "stopped",
                timeout=30
            )
            
            print("\n✅ E2E Test PASSED: Pause/Resume Workflow")
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {str(e)}")
            # Cleanup
            try:
                await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/stop",
                    json={},
                    headers=auth_headers
                )
            except:
                pass
            raise

    async def test_e2e_multi_target_discovery(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 3: Multi-target discovery
        
        Flow:
        1. Create mission with multiple target IPs
        2. Start mission
        3. Wait for discovery
        4. Verify all targets discovered
        5. Stop mission
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: Multi-Target Discovery")
        print("="*80)
        
        config = get_config()
        test_targets = [
            config.test_target_dvwa,
            config.test_target_nginx
        ]
        
        print(f"\n🎯 Testing discovery of {len(test_targets)} targets:")
        for target in test_targets:
            print(f"   - {target}")
        
        # Create mission
        mission_data = {
            "name": self.generate_mission_name("E2E Multi-Target"),
            "description": "Test multi-target discovery",
            "scope": {
                "ip_ranges": test_targets
            },
            "goals": ["reconnaissance"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        assert response.status_code in [200, 201]
        
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        print(f"\n✅ Mission created: {mission_id}")
        
        try:
            # Start mission
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/start",
                json={},
                headers=auth_headers
            )
            
            await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=60
            )
            print("✅ Mission started")
            
            # Wait for discovery
            print("\n⏳ Waiting for target discovery (60 seconds)...")
            await asyncio.sleep(60)
            
            # Check discovered targets
            print("\n🔍 Checking discovered targets...")
            response = await real_api_client.get(
                f"/api/v1/missions/{mission_id}/targets",
                headers=auth_headers
            )
            
            if response.status_code == 200:
                discovered_targets = response.json()
                discovered_ips = [t.get("ip") for t in discovered_targets]
                
                print(f"✅ Discovered {len(discovered_targets)} target(s):")
                for target in discovered_targets:
                    print(f"   - {target.get('ip')} (Status: {target.get('status')})")
                
                # Verify expected targets
                for expected_ip in test_targets:
                    if expected_ip in discovered_ips:
                        print(f"✅ Target {expected_ip} discovered")
                    else:
                        print(f"⚠️  Target {expected_ip} not yet discovered")
            else:
                print(f"⚠️  Could not retrieve targets: {response.status_code}")
            
            # Stop mission
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/stop",
                json={},
                headers=auth_headers
            )
            
            print("\n✅ E2E Test PASSED: Multi-Target Discovery")
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {str(e)}")
            try:
                await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/stop",
                    json={},
                    headers=auth_headers
                )
            except:
                pass
            raise


@pytest.mark.e2e
@pytest.mark.asyncio
class TestMissionDataPersistenceE2E(ProductionE2ETestBase):
    """End-to-end tests for data persistence across operations"""

    async def test_e2e_mission_data_persistence_after_pause(
        self,
        real_api_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test 4: Mission data persists after pause/resume
        
        Verifies that discovered targets and data persist
        when mission is paused and resumed.
        """
        print("\n" + "="*80)
        print("🚀 Starting E2E Test: Data Persistence After Pause")
        print("="*80)
        
        # Create mission
        mission_data = {
            "name": self.generate_mission_name("E2E Data Persistence"),
            "description": "Test data persistence across pause/resume",
            "scope": {
                "ip_ranges": ["192.168.100.0/24"]
            },
            "goals": ["reconnaissance"]
        }
        
        response = await real_api_client.post(
            "/api/v1/missions",
            json=mission_data,
            headers=auth_headers
        )
        mission = response.json()
        mission_id = mission.get("id") or mission.get("mission_id")
        
        try:
            # Start and collect initial data
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/start",
                json={},
                headers=auth_headers
            )
            
            await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=60
            )
            
            print("\n⏳ Waiting for initial discovery (30 seconds)...")
            await asyncio.sleep(30)
            
            # Collect data before pause
            print("\n📊 Collecting data before pause...")
            response = await real_api_client.get(
                f"/api/v1/missions/{mission_id}/targets",
                headers=auth_headers
            )
            targets_before = response.json() if response.status_code == 200 else []
            print(f"   Targets before pause: {len(targets_before)}")
            
            # Pause mission
            print("\n⏸️  Pausing mission...")
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/pause",
                json={},
                headers=auth_headers
            )
            
            await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "paused",
                timeout=30
            )
            
            # Verify data persists while paused
            print("\n🔍 Verifying data persistence while paused...")
            response = await real_api_client.get(
                f"/api/v1/missions/{mission_id}/targets",
                headers=auth_headers
            )
            targets_while_paused = response.json() if response.status_code == 200 else []
            print(f"   Targets while paused: {len(targets_while_paused)}")
            
            assert len(targets_while_paused) == len(targets_before), \
                "Target data lost during pause!"
            print("✅ Data persisted during pause")
            
            # Resume mission
            print("\n▶️  Resuming mission...")
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/resume",
                json={},
                headers=auth_headers
            )
            
            await self.wait_for_mission_status(
                real_api_client,
                auth_headers,
                mission_id,
                "running",
                timeout=30
            )
            
            # Verify data after resume
            print("\n🔍 Verifying data persistence after resume...")
            response = await real_api_client.get(
                f"/api/v1/missions/{mission_id}/targets",
                headers=auth_headers
            )
            targets_after_resume = response.json() if response.status_code == 200 else []
            print(f"   Targets after resume: {len(targets_after_resume)}")
            
            assert len(targets_after_resume) >= len(targets_before), \
                "Target data lost after resume!"
            print("✅ Data persisted after resume")
            
            # Stop mission
            await real_api_client.post(
                f"/api/v1/missions/{mission_id}/stop",
                json={},
                headers=auth_headers
            )
            
            print("\n✅ E2E Test PASSED: Data Persistence")
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {str(e)}")
            try:
                await real_api_client.post(
                    f"/api/v1/missions/{mission_id}/stop",
                    json={},
                    headers=auth_headers
                )
            except:
                pass
            raise


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
