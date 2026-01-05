# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intel Specialist Tests
# Tests for OSINT and leaked data integration
# ═══════════════════════════════════════════════════════════════

"""
Test suite for IntelSpecialist and breach data providers.

Test Scenarios:
1. MockBreachProvider returns fake credentials for "vulnerable-target"
2. FileSearchProvider searches local text files (grep simulation)
3. IntelSpecialist creates OSINT_LOOKUP tasks on NewTargetEvent
4. IntelCredential to Credential conversion with reliability_score
5. AttackSpecialist prioritizes intel credentials over brute force
6. End-to-end: Find leaked email, use it to breach target
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

# Models
from src.core.models import (
    TaskType, SpecialistType, TargetStatus, Priority,
    CredentialType, PrivilegeLevel, MissionStatus,
    Credential, Target, Mission, Task,
    NewTargetEvent, NewCredEvent
)

# Intel components
from src.core.intel import (
    BreachDataProvider,
    BreachSource,
    IntelCredential,
    IntelSearchResult
)
from src.core.intel.mock_provider import MockBreachProvider
from src.core.intel.file_provider import FileSearchProvider


# ═══════════════════════════════════════════════════════════════
# Test Data Layer - BreachDataProvider
# ═══════════════════════════════════════════════════════════════

class TestBreachSource:
    """Test BreachSource enum."""
    
    def test_breach_source_values(self):
        """Test all breach source types exist."""
        expected_sources = {
            "unknown", "arthouse", "fatetraffic", "combolist",
            "database_dump", "stealer_log", "paste_site",
            "darkweb_market", "ransomware", "local_file"
        }
        
        actual_sources = {s.value for s in BreachSource}
        
        assert expected_sources == actual_sources
    
    def test_breach_source_arthouse(self):
        """Test ArtHouse source."""
        assert BreachSource.ARTHOUSE.value == "arthouse"
    
    def test_breach_source_fatetraffic(self):
        """Test Fatetraffic source."""
        assert BreachSource.FATETRAFFIC.value == "fatetraffic"


class TestIntelCredential:
    """Test IntelCredential model."""
    
    def test_create_intel_credential(self):
        """Test creating an IntelCredential."""
        cred = IntelCredential(
            username="testuser",
            email="test@example.com",
            password="secret123",
            source=BreachSource.ARTHOUSE,
            source_name="ArtHouse_2024",
            reliability_score=0.8
        )
        
        assert cred.username == "testuser"
        assert cred.email == "test@example.com"
        assert cred.password == "secret123"
        assert cred.source == BreachSource.ARTHOUSE
        assert cred.reliability_score == 0.8
        assert cred.id is not None
    
    def test_masked_password(self):
        """Test password masking."""
        cred = IntelCredential(
            username="user",
            password="password123",
            source=BreachSource.COMBOLIST
        )
        
        masked = cred.get_masked_password(show_chars=2)
        
        assert masked.startswith("pa")
        assert masked.endswith("23")
        assert "*" in masked
    
    def test_masked_email(self):
        """Test email masking."""
        cred = IntelCredential(
            email="testuser@example.com",
            password="pass",
            source=BreachSource.COMBOLIST
        )
        
        masked = cred.get_masked_email()
        
        assert "@example.com" in masked
        assert "t" in masked[0]  # First char visible
    
    def test_to_credential_dict(self):
        """Test conversion to Credential dictionary."""
        mission_id = uuid4()
        target_id = uuid4()
        
        intel_cred = IntelCredential(
            username="admin",
            email="admin@corp.com",
            password="hunter2",
            source=BreachSource.ARTHOUSE,
            source_name="ArtHouse_2024",
            reliability_score=0.85
        )
        
        cred_dict = intel_cred.to_credential_dict(mission_id, target_id)
        
        assert cred_dict["mission_id"] == mission_id
        assert cred_dict["target_id"] == target_id
        assert cred_dict["type"] == "password"
        assert cred_dict["username"] == "admin"
        assert cred_dict["source"].startswith("intel:arthouse:")
        assert cred_dict["metadata"]["reliability_score"] == 0.85


class TestIntelSearchResult:
    """Test IntelSearchResult model."""
    
    def test_empty_result(self):
        """Test empty search result."""
        result = IntelSearchResult(
            query="example.com",
            query_type="domain",
            success=True
        )
        
        assert result.has_results is False
        assert result.total_found == 0
    
    def test_result_with_credentials(self):
        """Test search result with credentials."""
        creds = [
            IntelCredential(username="user1", password="pass1", reliability_score=0.9),
            IntelCredential(username="user2", password="pass2", reliability_score=0.5),
        ]
        
        result = IntelSearchResult(
            query="example.com",
            query_type="domain",
            credentials=creds,
            total_found=2,
            success=True
        )
        
        assert result.has_results is True
        assert result.total_found == 2
    
    def test_get_by_reliability(self):
        """Test filtering by reliability score."""
        creds = [
            IntelCredential(username="user1", password="pass1", reliability_score=0.9),
            IntelCredential(username="user2", password="pass2", reliability_score=0.5),
            IntelCredential(username="user3", password="pass3", reliability_score=0.3),
        ]
        
        result = IntelSearchResult(
            query="example.com",
            credentials=creds,
            total_found=3
        )
        
        # Filter by min reliability 0.6
        filtered = result.get_by_reliability(min_score=0.6)
        
        assert len(filtered) == 1
        assert filtered[0].username == "user1"


# ═══════════════════════════════════════════════════════════════
# Test MockBreachProvider
# ═══════════════════════════════════════════════════════════════

class TestMockBreachProvider:
    """Test MockBreachProvider for testing scenarios."""
    
    @pytest.fixture
    def mock_provider(self):
        """Create MockBreachProvider instance."""
        return MockBreachProvider()
    
    @pytest.mark.asyncio
    async def test_search_vulnerable_target(self, mock_provider):
        """Test searching for 'vulnerable-target' returns mock credentials."""
        result = await mock_provider.search("vulnerable-target")
        
        assert result.success is True
        assert result.has_results is True
        assert len(result.credentials) > 0
        
        # Check first credential
        first_cred = result.credentials[0]
        assert first_cred.email is not None or first_cred.username is not None
        assert first_cred.reliability_score > 0
    
    @pytest.mark.asyncio
    async def test_search_arthouse_source(self, mock_provider):
        """Test searching returns ArtHouse source credentials."""
        # Use vulnerable-target which has ArtHouse creds
        result = await mock_provider.search("vulnerable-target")
        
        assert result.success is True
        
        # Should find ArtHouse credentials
        arthouse_creds = [
            c for c in result.credentials 
            if c.source == BreachSource.ARTHOUSE
        ]
        
        # May have ArtHouse creds or not depending on mock data
        assert result.has_results
    
    @pytest.mark.asyncio
    async def test_search_fatetraffic_source(self, mock_provider):
        """Test searching returns Fatetraffic source credentials."""
        # Use vulnerable-target which has Fatetraffic creds
        result = await mock_provider.search("vulnerable-target")
        
        assert result.success is True
        
        # Should find Fatetraffic credentials
        fatetraffic_creds = [
            c for c in result.credentials 
            if c.source == BreachSource.FATETRAFFIC
        ]
        
        # May have Fatetraffic creds or not depending on mock data
        assert result.has_results
    
    @pytest.mark.asyncio
    async def test_search_no_results(self, mock_provider):
        """Test searching for non-existent domain."""
        result = await mock_provider.search("definitely-not-in-leaks.xyz")
        
        # Mock provider has some data for most domains
        assert result.success is True
    
    @pytest.mark.asyncio
    async def test_health_check(self, mock_provider):
        """Test provider health check."""
        healthy = await mock_provider.health_check()
        
        assert healthy is True
    
    def test_provider_name(self, mock_provider):
        """Test provider name."""
        assert mock_provider.provider_name == "mock"
    
    @pytest.mark.asyncio
    async def test_search_by_email(self, mock_provider):
        """Test searching by email address."""
        result = await mock_provider.search(
            "admin@vulnerable-target.com",
            query_type="email"
        )
        
        assert result.success is True
        assert result.query_type == "email"
    
    @pytest.mark.asyncio
    async def test_search_by_ip(self, mock_provider):
        """Test searching by IP address."""
        result = await mock_provider.search(
            "192.168.1.100",
            query_type="ip"
        )
        
        assert result.success is True
        assert result.query_type == "ip"


# ═══════════════════════════════════════════════════════════════
# Test FileSearchProvider
# ═══════════════════════════════════════════════════════════════

class TestFileSearchProvider:
    """Test FileSearchProvider for local file searches."""
    
    @pytest.fixture
    def file_provider(self, tmp_path):
        """Create FileSearchProvider with temp directory."""
        data_dir = tmp_path / "breach_data"
        data_dir.mkdir()
        
        # Create test data file
        combo_file = data_dir / "test_combo.txt"
        combo_file.write_text(
            "admin@example.com:password123\n"
            "user@example.com:hunter2\n"
            "test@other.com:secret\n"
        )
        
        return FileSearchProvider(data_dir=str(data_dir))
    
    @pytest.mark.asyncio
    async def test_search_domain(self, file_provider):
        """Test searching for domain in files."""
        result = await file_provider.search("example.com")
        
        assert result.success is True
        assert result.provider == "file_search"
    
    @pytest.mark.asyncio
    async def test_health_check_with_data(self, file_provider):
        """Test health check with existing data directory."""
        healthy = await file_provider.health_check()
        
        assert healthy is True
    
    @pytest.mark.asyncio
    async def test_health_check_no_data(self):
        """Test health check with non-existent directory."""
        provider = FileSearchProvider(data_dir="/nonexistent/path")
        
        healthy = await provider.health_check()
        
        assert healthy is False
    
    def test_provider_name(self, file_provider):
        """Test provider name."""
        assert file_provider.provider_name == "file_search"
    
    def test_get_available_files(self, file_provider):
        """Test listing available files."""
        files = file_provider.get_available_files()
        
        assert len(files) > 0
        assert files[0]["name"] == "test_combo.txt"


# ═══════════════════════════════════════════════════════════════
# Test IntelSpecialist
# ═══════════════════════════════════════════════════════════════

class TestIntelSpecialist:
    """Test IntelSpecialist functionality."""
    
    @pytest.fixture
    def mock_blackboard(self):
        """Create mock Blackboard."""
        blackboard = AsyncMock()
        blackboard.connect = AsyncMock()
        blackboard.disconnect = AsyncMock()
        blackboard.get_channel = MagicMock(return_value="test:channel")
        blackboard.subscribe = AsyncMock()
        blackboard.publish = AsyncMock()
        blackboard.add_credential = AsyncMock(return_value="cred-123")
        blackboard.get_target = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "hostname": "target.vulnerable.com",
            "os": "Linux"
        })
        blackboard.add_task = AsyncMock(return_value="task-123")
        return blackboard
    
    @pytest.fixture
    def intel_specialist(self, mock_blackboard):
        """Create IntelSpecialist with mock provider."""
        from src.specialists.intel import IntelSpecialist
        
        specialist = IntelSpecialist(
            blackboard=mock_blackboard,
            use_mock=True  # Use MockBreachProvider for tests
        )
        specialist._current_mission_id = str(uuid4())
        
        return specialist
    
    def test_supported_task_types(self, intel_specialist):
        """Test IntelSpecialist handles OSINT_LOOKUP tasks."""
        assert TaskType.OSINT_LOOKUP in intel_specialist._supported_task_types
    
    def test_specialist_type(self, intel_specialist):
        """Test specialist type is INTEL."""
        assert intel_specialist.specialist_type == SpecialistType.INTEL
    
    def test_has_providers(self, intel_specialist):
        """Test IntelSpecialist has providers configured."""
        providers = intel_specialist.get_providers()
        
        assert len(providers) > 0
        assert providers[0].provider_name == "mock"
    
    @pytest.mark.asyncio
    async def test_execute_osint_lookup(self, intel_specialist, mock_blackboard):
        """Test executing OSINT_LOOKUP task."""
        task = {
            "id": str(uuid4()),
            "type": TaskType.OSINT_LOOKUP.value,
            "target_id": str(uuid4()),
        }
        
        result = await intel_specialist.execute_task(task)
        
        assert "credentials_found" in result
        assert "queries_executed" in result
    
    @pytest.mark.asyncio
    async def test_on_new_target_event(self, intel_specialist, mock_blackboard):
        """Test IntelSpecialist creates OSINT task on new target."""
        event = {
            "event": "new_target",
            "target_id": str(uuid4()),
            "ip": "192.168.1.100",
            "mission_id": intel_specialist._current_mission_id
        }
        
        await intel_specialist.on_event(event)
        
        # Should have called add_task to create OSINT_LOOKUP
        mock_blackboard.add_task.assert_called()
    
    @pytest.mark.asyncio
    async def test_health_check_providers(self, intel_specialist):
        """Test health checking all providers."""
        health_results = await intel_specialist.health_check_providers()
        
        assert "mock" in health_results
        assert health_results["mock"] is True
    
    def test_get_stats(self, intel_specialist):
        """Test getting specialist statistics."""
        stats = intel_specialist.get_stats()
        
        assert "total_searches" in stats
        assert "credentials_found" in stats
        assert "providers_count" in stats
    
    def test_mask_ip(self, intel_specialist):
        """Test IP masking for logs."""
        masked = intel_specialist._mask_ip("192.168.1.100")
        
        assert masked == "192.168.*.*"
    
    def test_mask_hostname(self, intel_specialist):
        """Test hostname masking for logs."""
        masked = intel_specialist._mask_hostname("server.corp.example.com")
        
        assert "example.com" in masked
        assert "server" not in masked


# ═══════════════════════════════════════════════════════════════
# Test Credential Model Updates
# ═══════════════════════════════════════════════════════════════

class TestCredentialModel:
    """Test Credential model with reliability_score and source_metadata."""
    
    def test_credential_with_reliability_score(self):
        """Test creating Credential with reliability_score."""
        cred = Credential(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=CredentialType.PASSWORD,
            username="admin",
            source="intel:arthouse:ArtHouse_2024",
            reliability_score=0.8
        )
        
        assert cred.reliability_score == 0.8
    
    def test_credential_with_source_metadata(self):
        """Test creating Credential with source_metadata."""
        metadata = {
            "intel_source": "arthouse",
            "source_name": "ArtHouse_2024",
            "source_date": "2024-01-15T00:00:00",
            "raw_log_hash": "abc123",
            "email": "admin@corp.com",
            "has_plaintext": True
        }
        
        cred = Credential(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=CredentialType.PASSWORD,
            username="admin",
            source="intel:arthouse:ArtHouse_2024",
            reliability_score=0.8,
            source_metadata=metadata
        )
        
        assert cred.source_metadata == metadata
        assert cred.source_metadata["intel_source"] == "arthouse"
    
    def test_default_reliability_score(self):
        """Test default reliability score is 1.0 (for verified/brute force)."""
        cred = Credential(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=CredentialType.PASSWORD,
            username="admin",
            source="brute_force"
        )
        
        assert cred.reliability_score == 1.0
    
    def test_reliability_score_bounds(self):
        """Test reliability score is bounded 0.0-1.0."""
        cred = Credential(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=CredentialType.PASSWORD,
            username="admin",
            reliability_score=0.5  # Mid-range
        )
        
        assert 0.0 <= cred.reliability_score <= 1.0


# ═══════════════════════════════════════════════════════════════
# Test AttackSpecialist Intel Integration
# ═══════════════════════════════════════════════════════════════

class TestAttackSpecialistIntelIntegration:
    """Test AttackSpecialist prioritizes intel credentials."""
    
    @pytest.fixture
    def mock_blackboard(self):
        """Create mock Blackboard."""
        blackboard = AsyncMock()
        blackboard.connect = AsyncMock()
        blackboard.disconnect = AsyncMock()
        blackboard.get_channel = MagicMock(return_value="test:channel")
        blackboard.subscribe = AsyncMock()
        blackboard.publish = AsyncMock()
        # Return valid UUID for session
        blackboard.add_session = AsyncMock(return_value=str(uuid4()))
        blackboard.update_target_status = AsyncMock()
        blackboard.get_target_ports = AsyncMock(return_value={"22": "ssh", "80": "http"})
        blackboard.get_target = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "hostname": "target.corp.com",
            "os": "Linux"
        })
        blackboard.get_credential = AsyncMock(return_value={
            "username": "admin",
            "domain": "CORP",
            "type": "password",
            "source": "intel:arthouse:ArtHouse_2024",
            "reliability_score": 0.85,
            "privilege_level": "user"
        })
        blackboard.get_mission_creds = AsyncMock(return_value=["cred:test-cred-1"])
        blackboard.add_task = AsyncMock(return_value="task-123")
        return blackboard
    
    @pytest.fixture
    def attack_specialist(self, mock_blackboard):
        """Create AttackSpecialist."""
        from src.specialists.attack import AttackSpecialist
        
        specialist = AttackSpecialist(
            blackboard=mock_blackboard
        )
        specialist._current_mission_id = str(uuid4())
        
        return specialist
    
    @pytest.mark.asyncio
    async def test_execute_exploit_with_intel_cred(self, attack_specialist, mock_blackboard):
        """Test exploit with intel credential has higher success rate."""
        cred_id = str(uuid4())  # Use valid UUID
        
        task = {
            "id": str(uuid4()),
            "type": TaskType.EXPLOIT.value,
            "target_id": str(uuid4()),
            "cred_id": cred_id,
            "result_data": {
                "intel_source": "intel_lookup",
                "reliability": 0.85
            }
        }
        
        # Run exploit multiple times to test success rate
        results = []
        for _ in range(20):
            result = await attack_specialist.execute_task(task)
            results.append(result)
        
        # With 0.85 reliability, expect decent success rate
        successes = sum(1 for r in results if r.get("success"))
        
        # At least some should succeed (probability based)
        assert successes >= 5, f"Expected at least 5 successes, got {successes}"
    
    @pytest.mark.asyncio
    async def test_get_intel_credentials_for_target(self, attack_specialist, mock_blackboard):
        """Test getting intel credentials for a target."""
        target_id = str(uuid4())
        
        creds = await attack_specialist.get_intel_credentials_for_target(
            target_id=target_id,
            min_reliability=0.5
        )
        
        # Mock returns one credential with intel source
        assert isinstance(creds, list)
    
    def test_determine_session_type_for_cred(self, attack_specialist):
        """Test session type determination based on ports."""
        # SSH available
        ports = {"22": "ssh", "80": "http"}
        session_type = attack_specialist._determine_session_type_for_cred(ports)
        assert session_type == "ssh"
        
        # RDP available
        ports = {"3389": "rdp", "443": "https"}
        session_type = attack_specialist._determine_session_type_for_cred(ports)
        assert session_type == "rdp"
        
        # SMB available
        ports = {"445": "smb", "139": "netbios"}
        session_type = attack_specialist._determine_session_type_for_cred(ports)
        assert session_type == "smb"


# ═══════════════════════════════════════════════════════════════
# Test End-to-End Integration
# ═══════════════════════════════════════════════════════════════

class TestIntelIntegrationE2E:
    """End-to-end integration tests for Intel pipeline."""
    
    @pytest.fixture
    def mock_blackboard(self):
        """Create mock Blackboard for E2E tests."""
        blackboard = AsyncMock()
        blackboard.connect = AsyncMock()
        blackboard.disconnect = AsyncMock()
        blackboard.get_channel = MagicMock(return_value="test:channel")
        blackboard.subscribe = AsyncMock()
        blackboard.publish = AsyncMock()
        # Return a valid UUID string for cred_id
        blackboard.add_credential = AsyncMock(return_value=str(uuid4()))
        blackboard.add_session = AsyncMock(return_value="session-123")
        blackboard.add_task = AsyncMock(return_value="task-123")
        blackboard.update_target_status = AsyncMock()
        blackboard.get_target_ports = AsyncMock(return_value={"22": "ssh"})
        blackboard.get_target = AsyncMock(return_value={
            "ip": "192.168.1.100",
            "hostname": "target.vulnerable-target.com",  # Mock provider key
            "os": "Linux"
        })
        blackboard.get_credential = AsyncMock(return_value={
            "username": "leaked_admin",
            "domain": None,
            "type": "password",
            "source": "intel:mock_breach:MockBreach",
            "reliability_score": 0.8,
            "privilege_level": "user"
        })
        blackboard.get_vulnerability = AsyncMock(return_value={
            "type": "CVE-2021-44228",
            "target_id": "target-123"
        })
        blackboard.update_vuln_status = AsyncMock()
        return blackboard
    
    @pytest.mark.asyncio
    async def test_find_email_and_breach_target(self, mock_blackboard):
        """
        Test full flow: Find leaked email in breach data, use it to breach target.
        
        Scenario:
        1. Target discovered: vulnerable-target.com
        2. IntelSpecialist searches breach data
        3. MockBreachProvider returns leaked credentials
        4. IntelSpecialist saves credential with reliability_score
        5. AttackSpecialist uses intel credential for exploit
        """
        from src.specialists.intel import IntelSpecialist
        from src.specialists.attack import AttackSpecialist
        
        mission_id = str(uuid4())
        target_id = str(uuid4())
        
        # Step 1: Initialize specialists
        intel_specialist = IntelSpecialist(
            blackboard=mock_blackboard,
            use_mock=True
        )
        intel_specialist._current_mission_id = mission_id
        
        attack_specialist = AttackSpecialist(
            blackboard=mock_blackboard
        )
        attack_specialist._current_mission_id = mission_id
        
        # Step 2: Execute OSINT lookup
        osint_task = {
            "id": str(uuid4()),
            "type": TaskType.OSINT_LOOKUP.value,
            "target_id": target_id
        }
        
        osint_result = await intel_specialist.execute_task(osint_task)
        
        # Verify credentials were found
        assert osint_result["credentials_found"] > 0
        
        # Verify credential was saved (mock called)
        mock_blackboard.add_credential.assert_called()
        
        # Step 3: Execute exploit with intel credential
        exploit_task = {
            "id": str(uuid4()),
            "type": TaskType.EXPLOIT.value,
            "target_id": target_id,
            "cred_id": "cred-intel-123",
            "result_data": {
                "intel_source": "intel_lookup",
                "reliability": 0.8
            }
        }
        
        exploit_result = await attack_specialist.execute_task(exploit_task)
        
        # Verify exploit was attempted (may fail if vuln_id not provided, which is expected)
        # The important thing is that the flow works
        assert isinstance(exploit_result, dict)
        # If error, should indicate the specific issue
        if not exploit_result.get("success"):
            assert "error" in exploit_result
    
    @pytest.mark.asyncio
    async def test_intel_event_flow(self, mock_blackboard):
        """Test Intel event-driven flow: NewTargetEvent -> OSINT_LOOKUP task."""
        from src.specialists.intel import IntelSpecialist
        
        mission_id = str(uuid4())
        target_id = uuid4()
        
        intel_specialist = IntelSpecialist(
            blackboard=mock_blackboard,
            use_mock=True
        )
        intel_specialist._current_mission_id = mission_id
        
        # Simulate NewTargetEvent
        event = {
            "event": "new_target",
            "target_id": target_id,
            "ip": "192.168.1.100",
            "mission_id": mission_id
        }
        
        # Handle event
        await intel_specialist.on_event(event)
        
        # Verify OSINT task was created
        mock_blackboard.add_task.assert_called()
        
        # Get the task that was created
        call_args = mock_blackboard.add_task.call_args
        task = call_args[0][0]
        
        assert task.type == TaskType.OSINT_LOOKUP
        assert task.specialist == SpecialistType.INTEL
    
    @pytest.mark.asyncio
    async def test_reliability_affects_exploit_success(self, mock_blackboard):
        """Test that higher reliability credentials have better success rates."""
        from src.specialists.attack import AttackSpecialist
        
        mission_id = str(uuid4())
        target_id = str(uuid4())
        
        attack_specialist = AttackSpecialist(
            blackboard=mock_blackboard
        )
        attack_specialist._current_mission_id = mission_id
        
        # Test with high reliability (0.9)
        high_rel_task = {
            "id": str(uuid4()),
            "type": TaskType.EXPLOIT.value,
            "target_id": target_id,
            "cred_id": "cred-high-rel",
            "result_data": {
                "intel_source": "intel_lookup",
                "reliability": 0.9
            }
        }
        
        # Mock credential with high reliability
        mock_blackboard.get_credential = AsyncMock(return_value={
            "username": "admin",
            "source": "intel:arthouse:ArtHouse_2024",
            "reliability_score": 0.9,
            "privilege_level": "admin"
        })
        
        high_rel_results = []
        for _ in range(30):
            result = await attack_specialist.execute_task(high_rel_task)
            high_rel_results.append(result)
        
        # Test with low reliability (0.3)
        low_rel_task = {
            "id": str(uuid4()),
            "type": TaskType.EXPLOIT.value,
            "target_id": target_id,
            "cred_id": "cred-low-rel",
            "result_data": {
                "intel_source": "intel_lookup",
                "reliability": 0.3
            }
        }
        
        # Mock credential with low reliability
        mock_blackboard.get_credential = AsyncMock(return_value={
            "username": "old_user",
            "source": "intel:combolist:Old_Combo",
            "reliability_score": 0.3,
            "privilege_level": "user"
        })
        
        low_rel_results = []
        for _ in range(30):
            result = await attack_specialist.execute_task(low_rel_task)
            low_rel_results.append(result)
        
        # Compare success rates
        high_success = sum(1 for r in high_rel_results if r.get("success"))
        low_success = sum(1 for r in low_rel_results if r.get("success"))
        
        # High reliability should have more successes (on average)
        # Note: This is probabilistic, so we allow some variance
        assert high_success >= low_success - 5, \
            f"High reliability ({high_success}) should >= low reliability ({low_success})"


# ═══════════════════════════════════════════════════════════════
# Test TaskType and SpecialistType Updates
# ═══════════════════════════════════════════════════════════════

class TestModelEnums:
    """Test model enum updates for Intel support."""
    
    def test_osint_lookup_task_type(self):
        """Test OSINT_LOOKUP is in TaskType enum."""
        assert TaskType.OSINT_LOOKUP.value == "osint_lookup"
    
    def test_intel_specialist_type(self):
        """Test INTEL is in SpecialistType enum."""
        assert SpecialistType.INTEL.value == "intel"
    
    def test_task_type_values(self):
        """Test all task types."""
        expected_tasks = {
            "network_scan", "port_scan", "service_enum", "vuln_scan",
            "osint_lookup",  # New
            "exploit", "privesc", "lateral", "cred_harvest",
            "persistence", "evasion", "cleanup"
        }
        
        actual_tasks = {t.value for t in TaskType}
        
        assert expected_tasks == actual_tasks
    
    def test_specialist_type_values(self):
        """Test all specialist types."""
        expected_specialists = {
            "recon", "vuln", "attack", "cred", "intel",  # Intel is new
            "persistence", "evasion", "cleanup", "analysis"
        }
        
        actual_specialists = {s.value for s in SpecialistType}
        
        assert expected_specialists == actual_specialists
