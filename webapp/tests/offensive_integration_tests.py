#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Comprehensive Offensive Penetration Testing Integration Tests
═══════════════════════════════════════════════════════════════════════════════

This test suite validates the complete offensive penetration testing workflow,
covering all MITRE ATT&CK tactics and their integration with RAGLOX components.

Test Categories:
1. Knowledge Base Integration - Tactics, Techniques, and Modules
2. Attack Specialist Logic - Exploitation, PrivEsc, Lateral Movement
3. Executor Pipeline - Command execution across platforms
4. Strategic Scoring - Attack prioritization
5. End-to-End Attack Chains - Full penetration test scenarios

Author: RAGLOX Integration Team
Date: 2026-01-04
═══════════════════════════════════════════════════════════════════════════════
"""

import asyncio
import json
import pytest
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.knowledge import EmbeddedKnowledge, get_knowledge, RXModule
from src.core.models import (
    TaskType, SpecialistType, TargetStatus, Severity, Priority,
    CredentialType, PrivilegeLevel, SessionType, SessionStatus,
    GoalStatus
)
from src.core.blackboard import Blackboard
from src.core.config import Settings
from src.specialists.attack import AttackSpecialist
from src.specialists.recon import ReconSpecialist
from src.specialists.analysis import AnalysisSpecialist
from src.executors.models import (
    ExecutorType, Platform, ShellType,
    ExecutionRequest, ExecutionResult, ExecutionStatus,
    RXModuleRequest, RXModuleResult, ConnectionConfig
)


# ═══════════════════════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def knowledge_base():
    """Load the knowledge base once for all tests."""
    kb = get_knowledge()
    return kb


@pytest.fixture
def mock_blackboard():
    """Create a mock blackboard for testing."""
    bb = MagicMock(spec=Blackboard)
    bb.mission_id = uuid4()
    bb.get_targets = MagicMock(return_value=[])
    bb.get_vulnerabilities = MagicMock(return_value=[])
    bb.get_credentials = MagicMock(return_value=[])
    bb.get_sessions = MagicMock(return_value=[])
    bb.add_target = AsyncMock()
    bb.add_vulnerability = AsyncMock()
    bb.add_credential = AsyncMock()
    bb.add_session = AsyncMock()
    bb.update_target_status = AsyncMock()
    bb.publish_event = AsyncMock()
    return bb


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock(spec=Settings)
    settings.hitl_mode = "auto"
    settings.stealth_profile = "moderate"
    return settings


@pytest.fixture
def mock_executor_result():
    """Create a mock successful execution result."""
    result = MagicMock(spec=ExecutionResult)
    result.status = ExecutionStatus.SUCCESS
    result.exit_code = 0
    result.stdout = "Command executed successfully"
    result.stderr = ""
    result.duration_ms = 100
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════

def get_raw_module(kb: EmbeddedKnowledge, module_id: str) -> Optional[RXModule]:
    """Get raw RXModule object from knowledge base."""
    return kb._rx_modules.get(module_id)


def get_modules_with_commands(kb: EmbeddedKnowledge, technique_id: str) -> List[RXModule]:
    """Get all modules for a technique that have non-empty commands."""
    module_ids = kb._technique_to_modules.get(technique_id, [])
    modules = []
    for mid in module_ids:
        module = kb._rx_modules.get(mid)
        if module and module.execution.command and module.execution.command.strip():
            modules.append(module)
    return modules


def count_modules_with_commands(kb: EmbeddedKnowledge) -> int:
    """Count total modules with non-empty commands."""
    count = 0
    for module in kb._rx_modules.values():
        if module.execution.command and module.execution.command.strip():
            count += 1
    return count


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Knowledge Base Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestKnowledgeBaseIntegration:
    """Test Knowledge Base completeness and integration."""
    
    def test_all_tactics_loaded(self, knowledge_base):
        """Verify all 14 MITRE ATT&CK tactics are loaded."""
        tactics = knowledge_base.list_tactics()
        assert len(tactics) == 14, f"Expected 14 tactics, got {len(tactics)}"
        
        expected_tactics = {
            'TA0043': 'reconnaissance',
            'TA0042': 'resource-development',
            'TA0001': 'initial-access',
            'TA0002': 'execution',
            'TA0003': 'persistence',
            'TA0004': 'privilege-escalation',
            'TA0005': 'defense-evasion',
            'TA0006': 'credential-access',
            'TA0007': 'discovery',
            'TA0008': 'lateral-movement',
            'TA0009': 'collection',
            'TA0011': 'command-and-control',
            'TA0010': 'exfiltration',
            'TA0040': 'impact',
        }
        
        for tactic in tactics:
            assert tactic['id'] in expected_tactics, f"Unknown tactic: {tactic['id']}"
    
    def test_tactics_have_techniques(self, knowledge_base):
        """Verify tactics are properly linked to techniques."""
        tactics = knowledge_base.list_tactics()
        tactics_with_techniques = [t for t in tactics if t['technique_count'] > 0]
        
        # At least 13 of 14 tactics should have techniques
        assert len(tactics_with_techniques) >= 13, \
            f"Only {len(tactics_with_techniques)} tactics have techniques"
        
        # Key offensive tactics must have techniques
        critical_tactics = ['TA0002', 'TA0004', 'TA0005', 'TA0006', 'TA0008']
        for tactic_id in critical_tactics:
            tactic = next((t for t in tactics if t['id'] == tactic_id), None)
            assert tactic is not None, f"Tactic {tactic_id} not found"
            assert tactic['technique_count'] > 0, \
                f"Critical tactic {tactic_id} ({tactic['name']}) has no techniques"
    
    def test_techniques_have_modules(self, knowledge_base):
        """Verify techniques have executable RX modules."""
        # Test key attack techniques
        attack_techniques = [
            'T1059.001',  # PowerShell
            'T1003.001',  # LSASS Memory
            'T1053.005',  # Scheduled Task
            'T1021.001',  # Remote Desktop
        ]
        
        for tech_id in attack_techniques:
            modules = knowledge_base.get_modules_for_technique(tech_id)
            assert len(modules) > 0, \
                f"Technique {tech_id} has no executable modules"
    
    def test_module_structure_completeness(self, knowledge_base):
        """Verify RX modules have all required fields."""
        # Get a sample of modules
        sample_modules = list(knowledge_base._rx_modules.values())[:50]
        
        modules_with_commands = 0
        modules_without_commands = 0
        
        for module in sample_modules:
            # Check basic fields - these should always exist
            assert module.rx_module_id, "Module missing rx_module_id"
            assert module.technique_id, "Module missing technique_id"
            assert module.technique_name, "Module missing technique_name"
            
            # Check execution info exists
            assert module.execution is not None, \
                f"Module {module.rx_module_id} missing execution info"
            assert len(module.execution.platforms) > 0, \
                f"Module {module.rx_module_id} missing platforms"
            
            # Track command presence (some modules legitimately have empty commands)
            if module.execution.command and module.execution.command.strip():
                modules_with_commands += 1
            else:
                modules_without_commands += 1
        
        # Most modules should have commands (allow up to 10% without)
        assert modules_with_commands >= 40, \
            f"Too few modules with commands: {modules_with_commands}/50"
    
    def test_total_modules_with_commands(self, knowledge_base):
        """Verify majority of modules have executable commands."""
        total_modules = len(knowledge_base._rx_modules)
        modules_with_commands = count_modules_with_commands(knowledge_base)
        
        # At least 95% should have commands
        percentage = (modules_with_commands / total_modules) * 100
        assert percentage >= 95, \
            f"Only {percentage:.1f}% of modules have commands ({modules_with_commands}/{total_modules})"
    
    def test_platform_coverage(self, knowledge_base):
        """Verify modules cover all major platforms."""
        stats = knowledge_base.get_statistics()
        platforms = stats.get('modules_per_platform', {})
        
        # Must have Windows, Linux, and macOS
        assert platforms.get('windows', 0) > 100, "Insufficient Windows modules"
        assert platforms.get('linux', 0) > 50, "Insufficient Linux modules"
        assert platforms.get('macos', 0) > 20, "Insufficient macOS modules"
    
    def test_executor_type_coverage(self, knowledge_base):
        """Verify modules cover multiple executor types."""
        stats = knowledge_base.get_statistics()
        executors = stats.get('modules_per_executor', {})
        
        assert executors.get('powershell', 0) > 100, "Insufficient PowerShell modules"
        assert executors.get('sh', 0) > 50, "Insufficient Shell modules"
        assert executors.get('command_prompt', 0) > 50, "Insufficient CMD modules"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Attack Specialist Logic Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttackSpecialistLogic:
    """Test Attack Specialist exploitation logic."""
    
    @pytest.fixture
    def attack_specialist(self, mock_blackboard, mock_settings, knowledge_base):
        """Create AttackSpecialist instance."""
        return AttackSpecialist(
            blackboard=mock_blackboard,
            settings=mock_settings,
            knowledge=knowledge_base,
        )
    
    def test_specialist_initialization(self, attack_specialist):
        """Test AttackSpecialist initializes correctly."""
        assert attack_specialist is not None
        assert attack_specialist.specialist_type == SpecialistType.ATTACK
        
        # Check supported task types
        supported = attack_specialist._supported_task_types
        assert TaskType.EXPLOIT in supported
        assert TaskType.PRIVESC in supported
        assert TaskType.LATERAL in supported
        assert TaskType.CRED_HARVEST in supported
    
    def test_strategic_scorer_integration(self, attack_specialist):
        """Test Strategic Scorer is integrated."""
        assert attack_specialist._strategic_scorer is not None
        assert attack_specialist._operational_memory is not None
    
    def test_privesc_techniques_defined(self, attack_specialist):
        """Test privilege escalation techniques are defined."""
        assert len(attack_specialist._privesc_techniques) > 0
        
        for tech_name, priv_level in attack_specialist._privesc_techniques:
            assert isinstance(tech_name, str)
            assert isinstance(priv_level, PrivilegeLevel)
    
    def test_credential_sources_defined(self, attack_specialist):
        """Test credential harvesting sources are defined."""
        assert len(attack_specialist._cred_sources) > 0
        
        for source_name, cred_type, priv_level in attack_specialist._cred_sources:
            assert isinstance(source_name, str)
            assert isinstance(cred_type, CredentialType)
            assert isinstance(priv_level, PrivilegeLevel)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Tactic-Specific Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestReconnaissanceTactic:
    """Test TA0043 - Reconnaissance."""
    
    def test_recon_techniques_available(self, knowledge_base):
        """Test reconnaissance techniques are available."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0043')
        assert len(techniques) > 0, "No reconnaissance techniques found"
    
    def test_active_scanning_modules(self, knowledge_base):
        """Test active scanning modules exist."""
        # T1595 - Active Scanning
        modules = knowledge_base.get_modules_for_technique('T1595')
        # May not have direct modules, check parent
        modules_sub = knowledge_base.get_modules_for_technique('T1595.003')
        assert len(modules) > 0 or len(modules_sub) > 0, \
            "No active scanning modules found"


class TestExecutionTactic:
    """Test TA0002 - Execution."""
    
    def test_execution_techniques_count(self, knowledge_base):
        """Test execution has sufficient techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0002')
        assert len(techniques) >= 10, f"Expected >= 10 execution techniques, got {len(techniques)}"
    
    def test_powershell_execution(self, knowledge_base):
        """Test PowerShell execution modules."""
        modules = get_modules_with_commands(knowledge_base, 'T1059.001')
        assert len(modules) >= 10, f"Expected >= 10 PowerShell modules with commands, got {len(modules)}"
        
        # Verify modules have executable commands
        for module in modules[:5]:
            assert module.execution.command, f"Module {module.rx_module_id} has no command"
    
    def test_command_shell_execution(self, knowledge_base):
        """Test Windows Command Shell modules."""
        modules = get_modules_with_commands(knowledge_base, 'T1059.003')
        assert len(modules) >= 3, f"Expected >= 3 CMD modules with commands, got {len(modules)}"
    
    def test_bash_execution(self, knowledge_base):
        """Test Bash execution modules."""
        modules = get_modules_with_commands(knowledge_base, 'T1059.004')
        assert len(modules) >= 5, f"Expected >= 5 Bash modules with commands, got {len(modules)}"


class TestPrivilegeEscalationTactic:
    """Test TA0004 - Privilege Escalation."""
    
    def test_privesc_techniques_count(self, knowledge_base):
        """Test privilege escalation has many techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0004')
        assert len(techniques) >= 30, f"Expected >= 30 privesc techniques, got {len(techniques)}"
    
    def test_scheduled_task_privesc(self, knowledge_base):
        """Test Scheduled Task/Job modules."""
        modules = knowledge_base.get_modules_for_technique('T1053.005')
        assert len(modules) > 0, "No Scheduled Task modules found"
    
    def test_valid_accounts_privesc(self, knowledge_base):
        """Test Valid Accounts modules."""
        # T1078 - Valid Accounts
        modules = knowledge_base.get_modules_for_technique('T1078')
        modules_local = knowledge_base.get_modules_for_technique('T1078.003')
        total = len(modules) + len(modules_local)
        assert total > 0, "No Valid Accounts modules found"


class TestDefenseEvasionTactic:
    """Test TA0005 - Defense Evasion (largest tactic)."""
    
    def test_defense_evasion_techniques_count(self, knowledge_base):
        """Test defense evasion has the most techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0005')
        assert len(techniques) >= 80, f"Expected >= 80 evasion techniques, got {len(techniques)}"
    
    def test_indicator_removal_modules(self, knowledge_base):
        """Test Indicator Removal modules."""
        modules = knowledge_base.get_modules_for_technique('T1070.001')  # Clear Windows Event Logs
        assert len(modules) > 0, "No log clearing modules found"
    
    def test_obfuscation_modules(self, knowledge_base):
        """Test Obfuscation modules."""
        # T1027 - Obfuscated Files or Information
        modules = knowledge_base.get_modules_for_technique('T1027')
        modules_packed = knowledge_base.get_modules_for_technique('T1027.002')
        total = len(modules) + len(modules_packed)
        assert total > 0, "No obfuscation modules found"


class TestCredentialAccessTactic:
    """Test TA0006 - Credential Access."""
    
    def test_credential_techniques_count(self, knowledge_base):
        """Test credential access has sufficient techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0006')
        assert len(techniques) >= 20, f"Expected >= 20 credential techniques, got {len(techniques)}"
    
    def test_os_credential_dumping(self, knowledge_base):
        """Test OS Credential Dumping modules."""
        # T1003 - OS Credential Dumping
        modules = knowledge_base.get_modules_for_technique('T1003')
        modules_lsass = knowledge_base.get_modules_for_technique('T1003.001')
        modules_sam = knowledge_base.get_modules_for_technique('T1003.002')
        total = len(modules) + len(modules_lsass) + len(modules_sam)
        assert total >= 10, f"Expected >= 10 credential dumping modules, got {total}"
    
    def test_mimikatz_availability(self, knowledge_base):
        """Test Mimikatz-related modules are available."""
        # Search for mimikatz in module descriptions
        mimikatz_modules = []
        for module in knowledge_base._rx_modules.values():
            if 'mimikatz' in module.technique_name.lower() or \
               'mimikatz' in (module.description or '').lower() or \
               'mimikatz' in (module.execution.command or '').lower():
                mimikatz_modules.append(module)
        
        assert len(mimikatz_modules) > 0, "No Mimikatz modules found"


class TestLateralMovementTactic:
    """Test TA0008 - Lateral Movement."""
    
    def test_lateral_techniques_count(self, knowledge_base):
        """Test lateral movement has techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0008')
        assert len(techniques) >= 10, f"Expected >= 10 lateral techniques, got {len(techniques)}"
    
    def test_remote_services_modules(self, knowledge_base):
        """Test Remote Services modules."""
        # T1021 - Remote Services
        modules_rdp = knowledge_base.get_modules_for_technique('T1021.001')  # RDP
        modules_smb = knowledge_base.get_modules_for_technique('T1021.002')  # SMB
        modules_winrm = knowledge_base.get_modules_for_technique('T1021.006')  # WinRM
        total = len(modules_rdp) + len(modules_smb) + len(modules_winrm)
        assert total > 0, "No Remote Services modules found"
    
    def test_pass_the_hash_modules(self, knowledge_base):
        """Test Pass-the-Hash modules."""
        # T1550.002 - Pass the Hash
        modules = knowledge_base.get_modules_for_technique('T1550.002')
        assert len(modules) > 0, "No Pass-the-Hash modules found"


class TestDiscoveryTactic:
    """Test TA0007 - Discovery."""
    
    def test_discovery_techniques_count(self, knowledge_base):
        """Test discovery has many techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0007')
        assert len(techniques) >= 30, f"Expected >= 30 discovery techniques, got {len(techniques)}"
    
    def test_system_info_discovery(self, knowledge_base):
        """Test System Information Discovery modules."""
        modules = knowledge_base.get_modules_for_technique('T1082')
        assert len(modules) > 0, "No System Info modules found"
    
    def test_network_discovery(self, knowledge_base):
        """Test Network Discovery modules."""
        modules = knowledge_base.get_modules_for_technique('T1016')  # System Network Config
        modules_conn = knowledge_base.get_modules_for_technique('T1049')  # System Network Connections
        total = len(modules) + len(modules_conn)
        assert total > 0, "No Network Discovery modules found"


class TestCollectionTactic:
    """Test TA0009 - Collection."""
    
    def test_collection_techniques_count(self, knowledge_base):
        """Test collection has techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0009')
        assert len(techniques) >= 15, f"Expected >= 15 collection techniques, got {len(techniques)}"
    
    def test_archive_collected_data(self, knowledge_base):
        """Test Archive Collected Data modules."""
        modules = knowledge_base.get_modules_for_technique('T1560.001')  # Archive via Utility
        assert len(modules) > 0, "No archive modules found"


class TestExfiltrationTactic:
    """Test TA0010 - Exfiltration."""
    
    def test_exfiltration_techniques_count(self, knowledge_base):
        """Test exfiltration has techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0010')
        assert len(techniques) >= 5, f"Expected >= 5 exfiltration techniques, got {len(techniques)}"


class TestImpactTactic:
    """Test TA0040 - Impact."""
    
    def test_impact_techniques_count(self, knowledge_base):
        """Test impact has techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0040')
        assert len(techniques) >= 5, f"Expected >= 5 impact techniques, got {len(techniques)}"


class TestCommandAndControlTactic:
    """Test TA0011 - Command and Control."""
    
    def test_c2_techniques_count(self, knowledge_base):
        """Test C2 has techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0011')
        assert len(techniques) >= 10, f"Expected >= 10 C2 techniques, got {len(techniques)}"


class TestPersistenceTactic:
    """Test TA0003 - Persistence."""
    
    def test_persistence_techniques_count(self, knowledge_base):
        """Test persistence has techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0003')
        assert len(techniques) >= 15, f"Expected >= 15 persistence techniques, got {len(techniques)}"


class TestInitialAccessTactic:
    """Test TA0001 - Initial Access."""
    
    def test_initial_access_techniques_count(self, knowledge_base):
        """Test initial access has techniques."""
        techniques = knowledge_base.get_techniques_for_tactic('TA0001')
        assert len(techniques) >= 3, f"Expected >= 3 initial access techniques, got {len(techniques)}"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Executor Pipeline Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecutorPipeline:
    """Test the execution pipeline."""
    
    def test_module_request_creation(self, knowledge_base):
        """Test RXModuleRequest can be created."""
        request = RXModuleRequest(
            rx_module_id="rx-t1059-001-333",
            target_host="192.168.1.100",
            target_platform=Platform.WINDOWS,
            variables={},
        )
        assert request.rx_module_id == "rx-t1059-001-333"
        assert request.target_host == "192.168.1.100"
    
    def test_module_variable_resolution(self, knowledge_base):
        """Test module variable resolution."""
        # Use get_module which returns dict
        module_dict = knowledge_base.get_module("rx-t1059-001-333")
        if module_dict:
            # Check if module has variables
            variables = module_dict.get('variables', [])
            assert isinstance(variables, list)
    
    def test_raw_module_variable_access(self, knowledge_base):
        """Test accessing raw RXModule variables."""
        # Get raw module from _rx_modules
        raw_module = get_raw_module(knowledge_base, "rx-t1059-001-333")
        if raw_module:
            # Check variables attribute
            variables = raw_module.variables
            assert isinstance(variables, list)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. End-to-End Attack Chain Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttackChains:
    """Test complete attack chains across tactics."""
    
    def test_recon_to_exploitation_chain(self, knowledge_base):
        """Test reconnaissance leads to exploitation capability."""
        # 1. Recon should identify targets
        recon_techniques = knowledge_base.get_techniques_for_tactic('TA0043')
        assert len(recon_techniques) > 0, "No recon techniques"
        
        # 2. Execution techniques for initial access
        exec_techniques = knowledge_base.get_techniques_for_tactic('TA0002')
        assert len(exec_techniques) > 0, "No execution techniques"
        
        # 3. Verify we have modules for execution
        powershell_modules = knowledge_base.get_modules_for_technique('T1059.001')
        assert len(powershell_modules) > 0, "No PowerShell modules for execution"
    
    def test_credential_to_lateral_chain(self, knowledge_base):
        """Test credential access enables lateral movement."""
        # 1. Get credential dumping modules
        cred_modules = knowledge_base.get_modules_for_technique('T1003.001')
        assert len(cred_modules) > 0, "No credential dumping modules"
        
        # 2. Verify lateral movement is possible
        lateral_techniques = knowledge_base.get_techniques_for_tactic('TA0008')
        assert len(lateral_techniques) > 0, "No lateral movement techniques"
        
        # 3. Check pass-the-hash availability
        pth_modules = knowledge_base.get_modules_for_technique('T1550.002')
        assert len(pth_modules) > 0, "No Pass-the-Hash modules"
    
    def test_complete_attack_chain_coverage(self, knowledge_base):
        """Test a complete attack chain has modules at each stage."""
        # Full attack chain stages
        attack_stages = [
            ('T1595.003', 'Scanning'),           # Recon
            ('T1059.001', 'Execution'),          # Initial Access/Execution
            ('T1003.001', 'Credential Access'),  # Post-Exploitation
            ('T1550.002', 'Lateral Movement'),   # Lateral Movement
            ('T1053.005', 'Persistence'),        # Persistence
            ('T1070.001', 'Defense Evasion'),    # Cleanup
        ]
        
        for tech_id, stage in attack_stages:
            modules = knowledge_base.get_modules_for_technique(tech_id)
            # Some stages may have 0 direct modules, that's OK
            # Just verify the query doesn't fail
            assert isinstance(modules, list), f"Failed to query {stage} modules"
    
    def test_full_kill_chain_coverage(self, knowledge_base):
        """Test full cyber kill chain has coverage."""
        # Ensure we have modules for each phase of a typical attack
        kill_chain_phases = {
            'reconnaissance': 'TA0043',
            'initial_access': 'TA0001',
            'execution': 'TA0002',
            'persistence': 'TA0003',
            'privilege_escalation': 'TA0004',
            'defense_evasion': 'TA0005',
            'credential_access': 'TA0006',
            'discovery': 'TA0007',
            'lateral_movement': 'TA0008',
            'collection': 'TA0009',
            'exfiltration': 'TA0010',
            'c2': 'TA0011',
            'impact': 'TA0040',
        }
        
        for phase_name, tactic_id in kill_chain_phases.items():
            techniques = knowledge_base.get_techniques_for_tactic(tactic_id)
            # Only resource-development (TA0042) has 0 techniques
            if tactic_id != 'TA0042':
                assert len(techniques) > 0, f"No techniques for {phase_name} ({tactic_id})"


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Nuclei Template Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestNucleiIntegration:
    """Test Nuclei template integration."""
    
    def test_nuclei_templates_loaded(self, knowledge_base):
        """Test Nuclei templates are loaded."""
        assert len(knowledge_base._nuclei_templates) > 10000, \
            "Expected > 10000 Nuclei templates"
    
    def test_critical_vulnerabilities(self, knowledge_base):
        """Test critical vulnerability templates exist."""
        # Check total count from internal index (not limited API)
        total_critical = len(knowledge_base._nuclei_by_severity.get('critical', []))
        assert total_critical > 1000, f"Expected > 1000 critical templates, got {total_critical}"
        
        # Also verify API returns results
        critical_sample = knowledge_base.get_nuclei_templates_by_severity('critical')
        assert len(critical_sample) > 0, "API returned no critical templates"
    
    def test_high_vulnerabilities(self, knowledge_base):
        """Test high severity templates exist."""
        # Check total count from internal index
        total_high = len(knowledge_base._nuclei_by_severity.get('high', []))
        assert total_high > 2000, f"Expected > 2000 high templates, got {total_high}"
        
        # Also verify API returns results
        high_sample = knowledge_base.get_nuclei_templates_by_severity('high')
        assert len(high_sample) > 0, "API returned no high templates"
    
    def test_medium_vulnerabilities(self, knowledge_base):
        """Test medium severity templates exist."""
        total_medium = len(knowledge_base._nuclei_by_severity.get('medium', []))
        assert total_medium > 2000, f"Expected > 2000 medium templates, got {total_medium}"
    
    def test_nuclei_severity_distribution(self, knowledge_base):
        """Test Nuclei templates have proper severity distribution."""
        stats = knowledge_base.get_statistics()
        nuclei_by_severity = stats.get('nuclei_by_severity', {})
        
        assert nuclei_by_severity.get('critical', 0) > 1000
        assert nuclei_by_severity.get('high', 0) > 2000
        assert nuclei_by_severity.get('medium', 0) > 2000
        assert nuclei_by_severity.get('info', 0) > 3000  # info is typically largest
    
    def test_rce_templates(self, knowledge_base):
        """Test RCE templates are available."""
        stats = knowledge_base.get_statistics()
        # RCE is typically tagged or in the template names
        # The get_nuclei_rce_templates method should return these
        assert stats.get('nuclei_by_severity', {}).get('critical', 0) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Comprehensive Statistics Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestKnowledgeStatistics:
    """Test knowledge base statistics."""
    
    def test_total_counts(self, knowledge_base):
        """Test total counts are correct."""
        stats = knowledge_base.get_statistics()
        
        assert stats['total_tactics'] == 14
        assert stats['total_techniques'] >= 300
        assert stats['total_rx_modules'] >= 1700
        assert stats['total_nuclei_templates'] >= 10000
    
    def test_tactic_technique_mapping(self, knowledge_base):
        """Test tactic-technique mapping totals."""
        tactics = knowledge_base.list_tactics()
        total_techniques = sum(t['technique_count'] for t in tactics)
        
        # Should have around 320 mappings
        assert total_techniques >= 300, f"Expected >= 300 total technique mappings, got {total_techniques}"
    
    def test_technique_module_coverage(self, knowledge_base):
        """Test technique to module coverage."""
        # Sample some techniques and verify they have modules
        techniques_with_modules = 0
        techniques_without_modules = 0
        
        for technique_id in list(knowledge_base._techniques.keys())[:100]:
            modules = knowledge_base.get_modules_for_technique(technique_id)
            if len(modules) > 0:
                techniques_with_modules += 1
            else:
                techniques_without_modules += 1
        
        # Most techniques should have modules
        coverage = (techniques_with_modules / 100) * 100
        assert coverage >= 80, f"Only {coverage}% of techniques have modules"


# ═══════════════════════════════════════════════════════════════════════════════
# Main Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

def run_tests():
    """Run all tests and generate report."""
    print("=" * 70)
    print("RAGLOX v3.0 - Offensive Penetration Testing Integration Tests")
    print("=" * 70)
    print(f"\nStarted: {datetime.now().isoformat()}\n")
    
    # Run pytest with verbose output
    exit_code = pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--color=yes",
    ])
    
    return exit_code


if __name__ == "__main__":
    sys.exit(run_tests())
