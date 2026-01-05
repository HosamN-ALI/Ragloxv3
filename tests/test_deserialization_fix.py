# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Test JSON Deserialization Fix
# Verify that complex fields are properly deserialized from Redis
# ═══════════════════════════════════════════════════════════════

import pytest
import asyncio
from uuid import uuid4
from unittest.mock import AsyncMock

from src.core.blackboard import Blackboard
from src.core.models import Vulnerability, Severity


def create_mock_redis():
    """Create a mock Redis client for testing."""
    mock = AsyncMock()
    storage = {}
    
    async def mock_hset(key, mapping=None, **kwargs):
        if key not in storage:
            storage[key] = {}
        if mapping:
            storage[key].update(mapping)
        return len(mapping) if mapping else 0
    
    async def mock_hgetall(key):
        return storage.get(key, {})
    
    async def mock_sadd(key, *values):
        return len(values)
    
    async def mock_ping():
        return True
    
    async def mock_publish(channel, message):
        return 1
    
    mock.hset = mock_hset
    mock.hgetall = mock_hgetall
    mock.sadd = mock_sadd
    mock.ping = mock_ping
    mock.publish = mock_publish
    mock.close = AsyncMock()
    
    return mock


@pytest.mark.asyncio
async def test_vulnerability_metadata_deserialization():
    """
    Test that vulnerability metadata (dict) is properly deserialized.
    
    This is the critical bug fix - ensuring that when we store a Vulnerability
    with complex metadata, we get back a proper dict, not a JSON string.
    """
    # Setup with mock Redis
    blackboard = Blackboard()
    blackboard._redis = create_mock_redis()
    blackboard._connected = True
    
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
    
    # Store vulnerability
    vuln_id = await blackboard.add_vulnerability(vuln)
    
    # Retrieve vulnerability
    retrieved = await blackboard.get_vulnerability(vuln_id)
    
    # Assert: metadata should be a dict, not a string
    assert retrieved is not None, "Vulnerability should be retrieved"
    assert "metadata" in retrieved, "metadata field should exist"
    
    # CRITICAL CHECK: metadata should be a dict
    metadata = retrieved["metadata"]
    assert isinstance(metadata, dict), (
        f"metadata should be dict, got {type(metadata).__name__}. "
        f"Value: {metadata!r}"
    )
    
    # Verify metadata contents
    assert metadata["nuclei_template"] == "CVE-2021-44228"
    assert metadata["curl_command"] == "curl -X POST http://target/api"
    assert metadata["matcher_name"] == "status-code"
    assert isinstance(metadata["extracted_results"], list)
    assert len(metadata["extracted_results"]) == 1
    assert metadata["extracted_results"][0] == "version: 2.14.0"
    
    # CRITICAL CHECK: rx_modules should be a list
    rx_modules = retrieved["rx_modules"]
    assert isinstance(rx_modules, list), (
        f"rx_modules should be list, got {type(rx_modules).__name__}. "
        f"Value: {rx_modules!r}"
    )
    assert len(rx_modules) == 2
    assert "rx-cve_2021_44228" in rx_modules
    assert "rx-log4shell-v2" in rx_modules
    
    print("✅ Deserialization test PASSED")
    print(f"   - metadata is dict: {isinstance(metadata, dict)}")
    print(f"   - rx_modules is list: {isinstance(rx_modules, list)}")
    print(f"   - All nested fields accessible: {bool(metadata['extracted_results'])}")


@pytest.mark.asyncio
async def test_attack_specialist_can_use_vulnerability():
    """
    Test that AttackSpecialist can use vulnerability data without errors.
    
    This verifies the full data flow: Vulnerability → Redis → Retrieval → Usage
    """
    # Setup with mock Redis
    blackboard = Blackboard()
    blackboard._redis = create_mock_redis()
    blackboard._connected = True
    
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
    
    # Simulate AttackSpecialist retrieving and using it
    retrieved = await blackboard.get_vulnerability(vuln_id)
    
    # Test common usage patterns that would fail with string instead of list/dict
    rx_modules = retrieved["rx_modules"]
    
    # This would fail if rx_modules is a string: iterating would give characters
    for module in rx_modules:
        assert module.startswith("rx-"), f"Module should start with rx-, got: {module}"
    
    # This would fail if rx_modules is a string: index would give character
    first_module = rx_modules[0]
    assert first_module == "rx-ms17_010", f"First module should be rx-ms17_010, got: {first_module}"
    
    # Test metadata access
    metadata = retrieved["metadata"]
    assert metadata["port"] == 445 or metadata["port"] == "445"  # Accept int or string
    assert "service" in metadata
    assert "extracted_data" in metadata
    assert isinstance(metadata["extracted_data"], dict)
    
    print("✅ AttackSpecialist usage test PASSED")
    print(f"   - Can iterate rx_modules: {len(list(rx_modules))}")
    print(f"   - Can index rx_modules: {rx_modules[0]}")
    print(f"   - Can access nested metadata: {metadata['extracted_data']['os']}")


if __name__ == "__main__":
    # Run tests manually
    print("Running deserialization fix tests...")
    print()
    
    asyncio.run(test_vulnerability_metadata_deserialization())
    print()
    asyncio.run(test_attack_specialist_can_use_vulnerability())
    
    print()
    print("=" * 70)
    print("All deserialization tests PASSED ✅")
    print("Critical bug fix verified!")
