#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Simple Deserialization Test (No pytest required)
# Verify that complex fields are properly deserialized from Redis
# ═══════════════════════════════════════════════════════════════

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from uuid import uuid4
from core.blackboard import Blackboard
from core.models import Vulnerability, Severity


async def test_vulnerability_metadata_deserialization():
    """Test that vulnerability metadata (dict) is properly deserialized."""
    print("=" * 70)
    print("TEST 1: Vulnerability Metadata Deserialization")
    print("=" * 70)
    
    # Setup
    blackboard = Blackboard()
    
    try:
        await blackboard.connect()
        print("✅ Connected to Redis")
        
        # Create vulnerability with complex metadata
        mission_id = uuid4()
        target_id = uuid4()
        
        vuln = Vulnerability(
            mission_id=mission_id,
            target_id=target_id,
            type="CVE-2021-44228",
            name="Log4Shell",
            description="Log4j RCE",
            severity=Severity.CRITICAL,
            metadata={
                "nuclei_template": "CVE-2021-44228",
                "curl_command": "curl -X POST http://target/api",
                "matcher_name": "status-code",
                "extracted_results": ["version: 2.14.0"],
                "tags": ["rce", "java", "critical"],
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
            },
            rx_modules=["rx-cve_2021_44228", "rx-log4shell-v2"]
        )
        
        print(f"✅ Created vulnerability: {vuln.type}")
        print(f"   - metadata type (before storage): {type(vuln.metadata)}")
        print(f"   - rx_modules type (before storage): {type(vuln.rx_modules)}")
        
        # Store vulnerability
        vuln_id = await blackboard.add_vulnerability(vuln)
        print(f"✅ Stored vulnerability with ID: {vuln_id}")
        
        # Retrieve vulnerability
        retrieved = await blackboard.get_vulnerability(vuln_id)
        print(f"✅ Retrieved vulnerability from Redis")
        
        # Check metadata type
        metadata = retrieved["metadata"]
        metadata_type = type(metadata).__name__
        print(f"\n📊 After retrieval:")
        print(f"   - metadata type: {metadata_type}")
        print(f"   - metadata value: {metadata if isinstance(metadata, dict) else f'STRING: {metadata[:50]}...'}")
        
        if isinstance(metadata, dict):
            print("   ✅ metadata is dict (CORRECT)")
            print(f"   - curl_command accessible: {bool(metadata.get('curl_command'))}")
            print(f"   - matcher_name: {metadata.get('matcher_name')}")
            print(f"   - extracted_results: {metadata.get('extracted_results')}")
        else:
            print(f"   ❌ metadata is {metadata_type} (WRONG - should be dict)")
            return False
        
        # Check rx_modules type
        rx_modules = retrieved["rx_modules"]
        rx_modules_type = type(rx_modules).__name__
        print(f"\n   - rx_modules type: {rx_modules_type}")
        print(f"   - rx_modules value: {rx_modules if isinstance(rx_modules, list) else f'STRING: {rx_modules[:50]}...'}")
        
        if isinstance(rx_modules, list):
            print("   ✅ rx_modules is list (CORRECT)")
            print(f"   - Can iterate: {len(rx_modules)} items")
            print(f"   - First module: {rx_modules[0]}")
        else:
            print(f"   ❌ rx_modules is {rx_modules_type} (WRONG - should be list)")
            return False
        
        print("\n" + "=" * 70)
        print("✅ TEST 1 PASSED: All fields properly deserialized")
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 1 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        await blackboard.disconnect()


async def test_attack_specialist_usage():
    """Test that AttackSpecialist can use vulnerability data without errors."""
    print("\n" + "=" * 70)
    print("TEST 2: AttackSpecialist Usage Simulation")
    print("=" * 70)
    
    # Setup
    blackboard = Blackboard()
    
    try:
        await blackboard.connect()
        print("✅ Connected to Redis")
        
        # Create and store vulnerability
        mission_id = uuid4()
        target_id = uuid4()
        
        vuln = Vulnerability(
            mission_id=mission_id,
            target_id=target_id,
            type="MS17-010",
            name="EternalBlue",
            description="SMB RCE",
            severity=Severity.CRITICAL,
            rx_modules=["rx-ms17_010", "rx-eternalblue-v2"],
            metadata={
                "port": 445,
                "service": "smb",
                "extracted_data": {"os": "Windows Server 2016"}
            }
        )
        
        vuln_id = await blackboard.add_vulnerability(vuln)
        print(f"✅ Stored vulnerability: {vuln.type}")
        
        # Simulate AttackSpecialist retrieving and using it
        retrieved = await blackboard.get_vulnerability(vuln_id)
        print(f"✅ Retrieved vulnerability")
        
        # Test common usage patterns that would fail with string instead of list/dict
        rx_modules = retrieved["rx_modules"]
        
        print("\n📊 Testing AttackSpecialist usage patterns:")
        
        # Pattern 1: Iterate rx_modules (would fail if string)
        try:
            modules_list = []
            for module in rx_modules:
                modules_list.append(module)
                if not module.startswith("rx-"):
                    raise ValueError(f"Module should start with rx-, got: {module}")
            print(f"   ✅ Can iterate rx_modules: {modules_list}")
        except Exception as e:
            print(f"   ❌ Iteration failed: {e}")
            return False
        
        # Pattern 2: Index rx_modules (would fail if string)
        try:
            first_module = rx_modules[0]
            print(f"   ✅ Can index rx_modules[0]: {first_module}")
            if first_module != "rx-ms17_010":
                print(f"   ⚠️  Expected 'rx-ms17_010', got '{first_module}'")
        except Exception as e:
            print(f"   ❌ Indexing failed: {e}")
            return False
        
        # Pattern 3: Access nested metadata
        try:
            metadata = retrieved["metadata"]
            port = metadata["port"]
            extracted = metadata["extracted_data"]
            os_info = extracted["os"]
            print(f"   ✅ Can access nested metadata:")
            print(f"      - port: {port}")
            print(f"      - extracted_data.os: {os_info}")
        except Exception as e:
            print(f"   ❌ Metadata access failed: {e}")
            return False
        
        print("\n" + "=" * 70)
        print("✅ TEST 2 PASSED: AttackSpecialist can use data correctly")
        print("=" * 70)
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 2 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        await blackboard.disconnect()


async def main():
    """Run all tests."""
    print("\n" + "🔍" * 35)
    print("RAGLOX v3.0 - Critical Deserialization Fix Verification")
    print("🔍" * 35 + "\n")
    
    # Run tests
    test1_passed = await test_vulnerability_metadata_deserialization()
    test2_passed = await test_attack_specialist_usage()
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Test 1 (Metadata Deserialization): {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"Test 2 (AttackSpecialist Usage):   {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    print("=" * 70)
    
    if test1_passed and test2_passed:
        print("\n🎉 ALL TESTS PASSED - Critical bug fix verified! 🎉")
        print("✅ System is GO for frontend integration")
        return 0
    else:
        print("\n❌ SOME TESTS FAILED - Fix needs more work")
        print("🔴 System is NO-GO for frontend integration")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
