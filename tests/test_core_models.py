# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Core Models Tests
# Testing all Pydantic models and enums
# ═══════════════════════════════════════════════════════════════

import pytest
from datetime import datetime
from uuid import UUID, uuid4

from src.core.models import (
    # Enums
    MissionStatus, TargetStatus, Priority, Severity,
    CredentialType, PrivilegeLevel, SessionStatus, SessionType,
    TaskStatus, TaskType, SpecialistType, GoalStatus, PathStatus,
    # Models
    BaseEntity, Mission, MissionCreate, MissionStats,
    Target, Port, Service, Vulnerability, Credential,
    Session, Task, AttackPath, BlackboardEvent,
    NewTargetEvent, NewVulnEvent, NewCredEvent, NewSessionEvent,
    NewTaskEvent, GoalAchievedEvent, ControlEvent
)


# ═══════════════════════════════════════════════════════════════
# Enum Tests
# ═══════════════════════════════════════════════════════════════

class TestEnums:
    """Test all enum definitions."""
    
    def test_mission_status_values(self):
        """Test MissionStatus enum has all required values."""
        expected = {'created', 'starting', 'running', 'paused', 
                   'completing', 'completed', 'failed', 'cancelled', 'archived'}
        actual = {status.value for status in MissionStatus}
        assert actual == expected, f"Missing statuses: {expected - actual}"
    
    def test_target_status_values(self):
        """Test TargetStatus enum."""
        expected = {'discovered', 'scanning', 'scanned', 'exploiting',
                   'exploited', 'owned', 'failed'}
        actual = {status.value for status in TargetStatus}
        assert actual == expected
    
    def test_severity_values(self):
        """Test Severity enum matches PostgreSQL constraint."""
        expected = {'critical', 'high', 'medium', 'low', 'info'}
        actual = {s.value for s in Severity}
        assert actual == expected
    
    def test_credential_type_values(self):
        """Test CredentialType matches PostgreSQL constraint."""
        expected = {'password', 'hash', 'key', 'token', 'certificate'}
        actual = {t.value for t in CredentialType}
        assert actual == expected
    
    def test_privilege_level_values(self):
        """Test PrivilegeLevel enum."""
        expected = {'user', 'admin', 'system', 'root', 'domain_admin', 'unknown'}
        actual = {p.value for p in PrivilegeLevel}
        assert actual == expected
    
    def test_task_type_values(self):
        """Test TaskType enum covers all specialist operations."""
        expected = {'network_scan', 'port_scan', 'service_enum', 'vuln_scan',
                   'exploit', 'privesc', 'lateral', 'cred_harvest',
                   'persistence', 'evasion', 'cleanup'}
        actual = {t.value for t in TaskType}
        assert actual == expected
    
    def test_specialist_type_values(self):
        """Test SpecialistType enum."""
        expected = {'recon', 'vuln', 'attack', 'cred', 'persistence',
                   'evasion', 'cleanup', 'analysis'}
        actual = {s.value for s in SpecialistType}
        assert actual == expected


# ═══════════════════════════════════════════════════════════════
# Model Tests
# ═══════════════════════════════════════════════════════════════

class TestBaseEntity:
    """Test BaseEntity model."""
    
    def test_auto_id_generation(self):
        """Test UUID is auto-generated."""
        entity = BaseEntity()
        assert entity.id is not None
        assert isinstance(entity.id, UUID)
    
    def test_auto_timestamp(self):
        """Test created_at is auto-generated."""
        entity = BaseEntity()
        assert entity.created_at is not None
        assert isinstance(entity.created_at, datetime)
    
    def test_metadata_default(self):
        """Test metadata defaults to empty dict."""
        entity = BaseEntity()
        assert entity.metadata == {}


class TestMission:
    """Test Mission model."""
    
    def test_create_mission(self):
        """Test creating a mission."""
        mission = Mission(
            name="Test Pentest",
            scope=["192.168.1.0/24"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        assert mission.name == "Test Pentest"
        assert mission.status == MissionStatus.CREATED
        assert "192.168.1.0/24" in mission.scope
    
    def test_mission_default_stats(self):
        """Test mission statistics default to zero."""
        mission = Mission(name="Test", scope=["10.0.0.0/8"], goals={})
        assert mission.targets_discovered == 0
        assert mission.vulns_found == 0
        assert mission.creds_harvested == 0
        assert mission.sessions_established == 0
        assert mission.goals_achieved == 0
    
    def test_mission_create_validation(self):
        """Test MissionCreate validation."""
        # Valid creation
        mission_data = MissionCreate(
            name="Valid Mission",
            scope=["192.168.0.0/16"],
            goals=["domain_admin"]
        )
        assert mission_data.name == "Valid Mission"
        
        # Empty name should fail
        with pytest.raises(ValueError):
            MissionCreate(name="", scope=["192.168.0.0/16"], goals=["test"])
        
        # Empty scope should fail
        with pytest.raises(ValueError):
            MissionCreate(name="Test", scope=[], goals=["test"])
        
        # Empty goals should fail
        with pytest.raises(ValueError):
            MissionCreate(name="Test", scope=["192.168.0.0/16"], goals=[])


class TestTarget:
    """Test Target model."""
    
    def test_create_target(self):
        """Test creating a target."""
        mission_id = uuid4()
        target = Target(
            mission_id=mission_id,
            ip="192.168.1.100",
            hostname="server01"
        )
        assert target.ip == "192.168.1.100"
        assert target.hostname == "server01"
        assert target.status == TargetStatus.DISCOVERED
        assert target.priority == Priority.MEDIUM
    
    def test_target_with_ports(self):
        """Test target with port information."""
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5",
            ports={22: "ssh", 80: "http", 443: "https"}
        )
        assert 22 in target.ports
        assert target.ports[22] == "ssh"
    
    def test_target_services(self):
        """Test target with services."""
        service = Service(
            port=22,
            protocol="tcp",
            name="ssh",
            product="OpenSSH",
            version="8.4"
        )
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.5",
            services=[service]
        )
        assert len(target.services) == 1
        assert target.services[0].name == "ssh"


class TestVulnerability:
    """Test Vulnerability model."""
    
    def test_create_vulnerability(self):
        """Test creating a vulnerability."""
        vuln = Vulnerability(
            mission_id=uuid4(),
            target_id=uuid4(),
            type="CVE-2021-44228",
            name="Log4Shell",
            severity=Severity.CRITICAL,
            cvss=10.0
        )
        assert vuln.type == "CVE-2021-44228"
        assert vuln.severity == Severity.CRITICAL
        assert vuln.cvss == 10.0
        assert vuln.exploit_available == False
    
    def test_vulnerability_with_rx_modules(self):
        """Test vulnerability with RX modules."""
        vuln = Vulnerability(
            mission_id=uuid4(),
            target_id=uuid4(),
            type="MS17-010",
            severity=Severity.CRITICAL,
            rx_modules=["rx-eternalblue", "rx-ms17-010-check"]
        )
        assert len(vuln.rx_modules) == 2


class TestCredential:
    """Test Credential model."""
    
    def test_create_credential(self):
        """Test creating a credential."""
        cred = Credential(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=CredentialType.PASSWORD,
            username="admin",
            domain="CORP"
        )
        assert cred.username == "admin"
        assert cred.type == CredentialType.PASSWORD
        assert cred.verified == False
        assert cred.privilege_level == PrivilegeLevel.UNKNOWN
    
    def test_credential_with_encryption(self):
        """Test credential with encrypted value."""
        cred = Credential(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=CredentialType.HASH,
            username="administrator",
            value_encrypted=b"encrypted_ntlm_hash",
            privilege_level=PrivilegeLevel.DOMAIN_ADMIN
        )
        assert cred.value_encrypted == b"encrypted_ntlm_hash"


class TestSession:
    """Test Session model."""
    
    def test_create_session(self):
        """Test creating a session."""
        session = Session(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=SessionType.METERPRETER,
            user="SYSTEM",
            privilege=PrivilegeLevel.SYSTEM
        )
        assert session.type == SessionType.METERPRETER
        assert session.status == SessionStatus.ACTIVE
        assert session.privilege == PrivilegeLevel.SYSTEM


class TestTask:
    """Test Task model."""
    
    def test_create_task(self):
        """Test creating a task."""
        task = Task(
            mission_id=uuid4(),
            type=TaskType.PORT_SCAN,
            specialist=SpecialistType.RECON,
            priority=8
        )
        assert task.type == TaskType.PORT_SCAN
        assert task.specialist == SpecialistType.RECON
        assert task.priority == 8
        assert task.status == TaskStatus.PENDING
    
    def test_task_priority_validation(self):
        """Test task priority is within range 1-10."""
        # Valid priority
        task = Task(
            mission_id=uuid4(),
            type=TaskType.EXPLOIT,
            specialist=SpecialistType.ATTACK,
            priority=5
        )
        assert task.priority == 5
        
        # Invalid priority should fail
        with pytest.raises(ValueError):
            Task(
                mission_id=uuid4(),
                type=TaskType.EXPLOIT,
                specialist=SpecialistType.ATTACK,
                priority=11
            )


class TestAttackPath:
    """Test AttackPath model."""
    
    def test_create_attack_path(self):
        """Test creating an attack path."""
        from_target = uuid4()
        to_target = uuid4()
        
        path = AttackPath(
            mission_id=uuid4(),
            from_target_id=from_target,
            to_target_id=to_target,
            method="pass_the_hash"
        )
        assert path.from_target_id == from_target
        assert path.to_target_id == to_target
        assert path.method == "pass_the_hash"
        assert path.status == PathStatus.DISCOVERED


# ═══════════════════════════════════════════════════════════════
# Event Tests
# ═══════════════════════════════════════════════════════════════

class TestEvents:
    """Test Pub/Sub event models."""
    
    def test_new_target_event(self):
        """Test NewTargetEvent."""
        mission_id = uuid4()
        target_id = uuid4()
        
        event = NewTargetEvent(
            mission_id=mission_id,
            target_id=target_id,
            ip="192.168.1.50",
            priority=Priority.HIGH
        )
        assert event.event == "new_target"
        assert event.target_id == target_id
        assert event.needs_deep_scan == True
    
    def test_new_vuln_event(self):
        """Test NewVulnEvent."""
        event = NewVulnEvent(
            mission_id=uuid4(),
            vuln_id=uuid4(),
            target_id=uuid4(),
            severity=Severity.CRITICAL,
            exploit_available=True
        )
        assert event.event == "new_vuln"
        assert event.severity == Severity.CRITICAL
    
    def test_goal_achieved_event(self):
        """Test GoalAchievedEvent."""
        event = GoalAchievedEvent(
            mission_id=uuid4(),
            goal="domain_admin",
            via_cred_id=uuid4()
        )
        assert event.event == "goal_achieved"
        assert event.goal == "domain_admin"
    
    def test_event_json_serialization(self):
        """Test event can be serialized to JSON."""
        event = NewTargetEvent(
            mission_id=uuid4(),
            target_id=uuid4(),
            ip="10.0.0.1"
        )
        json_str = event.model_dump_json()
        assert "new_target" in json_str
        assert "10.0.0.1" in json_str


# ═══════════════════════════════════════════════════════════════
# Integration Tests - Model to Redis Compatibility
# ═══════════════════════════════════════════════════════════════

class TestRedisCompatibility:
    """Test models can be serialized for Redis storage."""
    
    def test_mission_to_dict(self):
        """Test mission can be converted to dict for Redis."""
        mission = Mission(
            name="Redis Test",
            scope=["192.168.0.0/16"],
            goals={"domain_admin": GoalStatus.PENDING}
        )
        data = mission.model_dump()
        
        assert "id" in data
        assert "name" in data
        assert data["status"] == "created"  # enum should be value
    
    def test_target_serialization(self):
        """Test target serialization preserves data."""
        target = Target(
            mission_id=uuid4(),
            ip="10.0.0.1",
            ports={22: "ssh", 80: "http"}
        )
        data = target.model_dump()
        
        assert data["ip"] == "10.0.0.1"
        assert isinstance(data["ports"], dict)
        assert data["ports"][22] == "ssh"
    
    def test_credential_bytes_handling(self):
        """Test credential with bytes value."""
        cred = Credential(
            mission_id=uuid4(),
            target_id=uuid4(),
            type=CredentialType.HASH,
            username="test",
            value_encrypted=b"test_encrypted_value"
        )
        data = cred.model_dump()
        
        # Bytes should be preserved
        assert isinstance(data["value_encrypted"], bytes)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
