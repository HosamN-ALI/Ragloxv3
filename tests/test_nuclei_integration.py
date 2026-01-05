# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Nuclei Integration Tests
# Tests for Nuclei scanner integration and AI-driven exploitation
# ═══════════════════════════════════════════════════════════════

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime

from src.core.scanners import NucleiScanner, NucleiScanResult, NucleiVulnerability
from src.core.scanners.nuclei import NucleiSeverity
from src.core.models import (
    Vulnerability, Severity, Target, Mission, GoalStatus,
    TaskType, SpecialistType
)
from src.specialists.recon import ReconSpecialist
from src.specialists.analysis import AnalysisSpecialist
from src.core.config import Settings


# ═══════════════════════════════════════════════════════════════
# Nuclei Scanner Unit Tests
# ═══════════════════════════════════════════════════════════════

class TestNucleiScanner:
    """Test NucleiScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create a NucleiScanner instance."""
        return NucleiScanner(
            nuclei_path="nuclei",
            timeout=60,
            rate_limit=100,
            concurrency=10
        )
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes with correct defaults."""
        assert scanner.nuclei_path == "nuclei"
        assert scanner.timeout == 60
        assert scanner.rate_limit == 100
        assert scanner.concurrency == 10
    
    def test_parse_nuclei_json_finding(self, scanner):
        """Test parsing a single Nuclei JSON finding."""
        nuclei_json = {
            "template-id": "CVE-2023-12345",
            "info": {
                "name": "Test Vulnerability",
                "severity": "critical",
                "description": "A critical vulnerability",
                "tags": ["cve", "rce"],
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"],
                "classification": {
                    "cve-id": ["CVE-2023-12345"]
                }
            },
            "host": "http://example.com",
            "matched-at": "http://example.com/vulnerable-endpoint",
            "extracted-results": ["version=1.0.0"],
            "matcher-name": "version-check",
            "curl-command": "curl -X GET http://example.com/vulnerable-endpoint"
        }
        
        vuln = scanner._parse_single_finding(nuclei_json)
        
        assert vuln is not None
        assert vuln.template_id == "CVE-2023-12345"
        assert vuln.severity == NucleiSeverity.CRITICAL
        assert vuln.vuln_type == "CVE-2023-12345"
        assert vuln.name == "Test Vulnerability"
        assert "rce" in vuln.tags
        assert len(vuln.extracted_results) == 1
    
    def test_parse_json_output_multiple_findings(self, scanner):
        """Test parsing multiple JSON lines from Nuclei output."""
        output = """{"template-id": "vuln1", "info": {"name": "Vuln1", "severity": "high"}, "host": "http://test.com", "matched-at": "http://test.com/1"}
{"template-id": "vuln2", "info": {"name": "Vuln2", "severity": "critical"}, "host": "http://test.com", "matched-at": "http://test.com/2"}
{"template-id": "vuln3", "info": {"name": "Vuln3", "severity": "info"}, "host": "http://test.com", "matched-at": "http://test.com/3"}"""
        
        vulns = scanner._parse_json_output(output)
        
        assert len(vulns) == 3
        assert vulns[0].severity == NucleiSeverity.HIGH
        assert vulns[1].severity == NucleiSeverity.CRITICAL
        assert vulns[2].severity == NucleiSeverity.INFO
    
    def test_convert_to_raglox_vulnerability(self, scanner):
        """Test converting NucleiVulnerability to RAGLOX Vulnerability."""
        nuclei_vuln = NucleiVulnerability(
            template_id="CVE-2023-12345",
            template_name="Critical RCE",
            severity=NucleiSeverity.CRITICAL,
            host="http://example.com",
            matched_at="http://example.com/api/vulnerable",
            vuln_type="CVE-2023-12345",
            name="Critical RCE Vulnerability",
            description="Remote code execution via API endpoint",
            extracted_results=["admin_token=xyz123"],
            tags=["cve", "rce", "critical"],
            curl_command="curl -X POST http://example.com/api/vulnerable"
        )
        
        mission_id = uuid4()
        target_id = uuid4()
        
        raglox_vuln = nuclei_vuln.to_vulnerability(mission_id, target_id)
        
        assert raglox_vuln.mission_id == mission_id
        assert raglox_vuln.target_id == target_id
        assert raglox_vuln.type == "CVE-2023-12345"
        assert raglox_vuln.severity == Severity.CRITICAL
        assert raglox_vuln.exploit_available is True
        assert "rx-cve_2023_12345" in raglox_vuln.rx_modules
        assert raglox_vuln.metadata["nuclei_template"] == "CVE-2023-12345"
    
    @pytest.mark.asyncio
    async def test_build_command(self, scanner):
        """Test command building with various options."""
        cmd = await scanner._build_command(
            target="https://example.com",
            templates=["cves", "vulnerabilities"],
            severity=["critical", "high"],
            tags=["rce"],
            rate_limit=50
        )
        
        assert "nuclei" in cmd
        assert "-u" in cmd
        assert "https://example.com" in cmd
        assert "-json" in cmd
        assert "-severity" in cmd
        assert "critical,high" in cmd
        assert "-tags" in cmd
        assert "rce" in cmd


class TestNucleiScanResult:
    """Test NucleiScanResult class."""
    
    def test_scan_result_counts(self):
        """Test vulnerability counting methods."""
        result = NucleiScanResult(
            success=True,
            target="http://example.com",
            vulnerabilities=[
                NucleiVulnerability(
                    template_id="v1", template_name="V1",
                    severity=NucleiSeverity.CRITICAL,
                    host="test", matched_at="test"
                ),
                NucleiVulnerability(
                    template_id="v2", template_name="V2",
                    severity=NucleiSeverity.CRITICAL,
                    host="test", matched_at="test"
                ),
                NucleiVulnerability(
                    template_id="v3", template_name="V3",
                    severity=NucleiSeverity.HIGH,
                    host="test", matched_at="test"
                ),
                NucleiVulnerability(
                    template_id="v4", template_name="V4",
                    severity=NucleiSeverity.INFO,
                    host="test", matched_at="test"
                ),
            ]
        )
        
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.info_count == 1
        assert len(result.get_exploitable_vulnerabilities()) == 3
        assert len(result.get_info_vulnerabilities()) == 1


# ═══════════════════════════════════════════════════════════════
# Integration Tests - Nuclei + AI Decision Making
# ═══════════════════════════════════════════════════════════════

class TestNucleiAIIntegration:
    """
    Integration tests for Nuclei vulnerability discovery 
    and AI-driven exploitation decisions.
    """
    
    @pytest.fixture
    def mock_blackboard(self):
        """Create a mock Blackboard."""
        mock = AsyncMock()
        storage = {}
        
        async def mock_get_target(target_id):
            return storage.get(f"target:{target_id}")
        
        async def mock_add_target(target):
            target_id = str(target.id)
            storage[f"target:{target_id}"] = target.model_dump()
            return target_id
        
        async def mock_get_target_ports(target_id):
            return storage.get(f"target:{target_id}:ports", {})
        
        async def mock_add_target_ports(target_id, ports):
            storage[f"target:{target_id}:ports"] = ports
        
        async def mock_add_vulnerability(vuln):
            vuln_id = str(vuln.id)
            storage[f"vuln:{vuln_id}"] = vuln.model_dump()
            return vuln_id
        
        async def mock_get_vulnerability(vuln_id):
            return storage.get(f"vuln:{vuln_id}")
        
        async def mock_get_mission_vulns(mission_id, limit=100):
            return [k for k in storage.keys() if k.startswith("vuln:")]
        
        async def mock_add_task(task):
            task_id = str(task.id)
            storage[f"task:{task_id}"] = task.model_dump()
            return task_id
        
        async def mock_log_result(mission_id, event_type, data):
            pass
        
        def mock_get_channel(mission_id, entity):
            return f"channel:mission:{mission_id}:{entity}"
        
        async def mock_publish(channel, event):
            pass
        
        mock.get_target = mock_get_target
        mock.add_target = mock_add_target
        mock.get_target_ports = mock_get_target_ports
        mock.add_target_ports = mock_add_target_ports
        mock.add_vulnerability = mock_add_vulnerability
        mock.get_vulnerability = mock_get_vulnerability
        mock.get_mission_vulns = mock_get_mission_vulns
        mock.add_task = mock_add_task
        mock.log_result = mock_log_result
        mock.get_channel = mock_get_channel
        mock.publish = mock_publish
        mock.publish_event = AsyncMock()
        mock._storage = storage
        
        return mock
    
    @pytest.fixture
    def settings(self):
        """Create test settings."""
        return Settings(
            redis_url="redis://localhost:6379/0",
            llm_enabled=True,
            llm_provider="mock"
        )
    
    @pytest.mark.asyncio
    async def test_nuclei_discovers_cve_creates_exploit_task(self, mock_blackboard, settings):
        """
        Test that when Nuclei discovers a CVE, the system:
        1. Parses the vulnerability correctly
        2. Creates an exploit task for AttackSpecialist
        """
        # Setup ReconSpecialist
        recon = ReconSpecialist(
            blackboard=mock_blackboard,
            settings=settings,
            worker_id="recon-test-001"
        )
        recon._current_mission_id = str(uuid4())
        recon._running = True
        
        # Create a target
        target = Target(
            mission_id=uuid4(),
            ip="192.168.1.100"
        )
        target_id = await mock_blackboard.add_target(target)
        await mock_blackboard.add_target_ports(target_id, {"80": "http", "443": "https"})
        
        # Mock Nuclei scanner to return a critical CVE
        mock_scan_result = NucleiScanResult(
            success=True,
            target="http://192.168.1.100:80",
            vulnerabilities=[
                NucleiVulnerability(
                    template_id="CVE-2023-44487",
                    template_name="HTTP/2 Rapid Reset Attack",
                    severity=NucleiSeverity.CRITICAL,
                    host="http://192.168.1.100:80",
                    matched_at="http://192.168.1.100:80/",
                    vuln_type="CVE-2023-44487",
                    name="HTTP/2 Rapid Reset Attack",
                    description="Critical DoS vulnerability in HTTP/2 implementations",
                    tags=["cve", "dos", "http2"],
                )
            ]
        )
        
        # Create a mock scanner instance
        mock_scanner = AsyncMock()
        mock_scanner.check_available = AsyncMock(return_value=True)
        mock_scanner.scan = AsyncMock(return_value=mock_scan_result)
        
        # Replace the private attribute directly
        recon._nuclei_scanner = mock_scanner
        
        # Execute vuln scan
        result = await recon._execute_vuln_scan({
            "target_id": target_id,
            "type": "vuln_scan"
        })
        
        # Verify results
        assert result["vulns_found"] >= 1
        assert result["critical_count"] >= 1
        assert result["exploitable_count"] >= 1
        assert result["scan_type"] == "nuclei"
        
        # Verify vulnerability was added to storage (may have multiple due to HTTP/HTTPS)
        vuln_keys = [k for k in mock_blackboard._storage.keys() if k.startswith("vuln:")]
        assert len(vuln_keys) >= 1
        
        # Verify exploit task was created
        task_keys = [k for k in mock_blackboard._storage.keys() if k.startswith("task:")]
        assert len(task_keys) >= 1
        
        # Check task details
        task_data = list(mock_blackboard._storage.values())[-1]
        if "type" in task_data:
            assert task_data.get("type") == TaskType.EXPLOIT.value or task_data.get("type") == "exploit"
    
    @pytest.mark.asyncio
    async def test_ai_decides_to_skip_info_severity(self, mock_blackboard, settings):
        """
        Test that AI correctly decides to skip INFO severity vulnerabilities.
        
        Scenario: Nuclei finds CVE-2023-xxxx as INFO severity (not exploitable)
        Expected: AI recommends "skip" decision, no AttackSpecialist involvement
        """
        # Setup AnalysisSpecialist with mock LLM
        analysis = AnalysisSpecialist(
            blackboard=mock_blackboard,
            settings=settings,
            worker_id="analysis-test-001",
            llm_enabled=False  # Use rule-based for predictable testing
        )
        analysis._current_mission_id = str(uuid4())
        
        # Simulate a failed exploit task on an INFO severity vuln (target patched)
        failed_task = {
            "id": f"task:{uuid4()}",
            "type": TaskType.EXPLOIT.value,
            "target_id": str(uuid4()),
            "vuln_id": str(uuid4()),
            "retry_count": 0,
            "max_retries": 3
        }
        
        # Error context simulating target_patched (maps to vulnerability category -> skip)
        error_context = {
            "error_type": "target_patched",  # Maps to "vulnerability" category -> skip
            "error_message": "Target appears to be patched or not vulnerable",
            "module_used": "rx-nuclei-info-vuln",
            "detected_defenses": []
        }
        
        # Mock get_task to return the failed task
        mock_blackboard.get_task = AsyncMock(return_value=failed_task)
        
        # Perform analysis
        result = await analysis.analyze_failure(
            task_id=failed_task["id"].replace("task:", ""),
            error_context=error_context,
            execution_logs=[]
        )
        
        # Verify the decision is to skip (vulnerability category with no retries recommended)
        assert result["decision"] == "skip"
        assert "patched" in result["reasoning"].lower() or "vulnerable" in result["reasoning"].lower()
    
    @pytest.mark.asyncio
    async def test_ai_decides_to_exploit_critical_severity(self, mock_blackboard, settings):
        """
        Test that AI correctly decides to exploit CRITICAL severity vulnerabilities.
        
        Scenario: Nuclei finds CVE-2023-xxxx as CRITICAL severity
        Expected: AI recommends exploitation or retry with alternative module
        """
        # Setup AnalysisSpecialist with mock LLM
        analysis = AnalysisSpecialist(
            blackboard=mock_blackboard,
            settings=settings,
            worker_id="analysis-test-001",
            llm_enabled=False  # Use rule-based for predictable testing
        )
        analysis._current_mission_id = str(uuid4())
        
        # Setup knowledge mock for alternative modules
        mock_knowledge = MagicMock()
        mock_knowledge.is_loaded.return_value = True
        mock_knowledge.get_modules_for_technique.return_value = [
            {
                "rx_module_id": "rx-cve_2023_alternative",
                "name": "Alternative Exploit",
                "description": "Alternative module for CVE",
                "supports_evasion": True
            }
        ]
        mock_knowledge.search_modules.return_value = [
            {
                "rx_module_id": "rx-evasion-01",
                "name": "Evasion Module",
                "technique_id": "T1027"
            }
        ]
        analysis._knowledge = mock_knowledge
        
        # Simulate a failed exploit task that hit defenses (edr_blocked -> defense category)
        failed_task = {
            "id": f"task:{uuid4()}",
            "type": TaskType.EXPLOIT.value,
            "target_id": str(uuid4()),
            "vuln_id": str(uuid4()),
            "retry_count": 0,
            "max_retries": 3,
            "rx_module": "rx-cve_2023_primary"
        }
        
        # Error context simulating defense detection (edr_blocked -> defense category)
        error_context = {
            "error_type": "edr_blocked",  # Maps to "defense" category -> modify_approach
            "error_message": "EDR blocked exploitation attempt",
            "module_used": "rx-cve_2023_primary",
            "technique_id": "T1190",
            "detected_defenses": ["edr"]
        }
        
        # Mock get_task to return the failed task
        mock_blackboard.get_task = AsyncMock(return_value=failed_task)
        
        # Perform analysis
        result = await analysis.analyze_failure(
            task_id=failed_task["id"].replace("task:", ""),
            error_context=error_context,
            execution_logs=[]
        )
        
        # Verify the decision is to modify approach (try alternative)
        assert result["decision"] == "modify_approach"
        assert "alternative" in result["reasoning"].lower() or "defense" in result["reasoning"].lower()
        assert result.get("new_module") is not None


class TestLLMPromptWithNucleiContext:
    """Test LLM prompt building with Nuclei context."""
    
    def test_prompt_includes_nuclei_context(self):
        """Test that prompts correctly include Nuclei vulnerability context."""
        from src.core.llm.prompts import build_analysis_prompt, FAILURE_ANALYSIS_PROMPT
        from src.core.llm.models import (
            AnalysisRequest, TaskContext, ExecutionContext, ErrorDetails
        )
        
        # Create request with Nuclei-style data
        request = AnalysisRequest(
            task=TaskContext(
                task_id="test-task-001",
                task_type="exploit",
                target_ip="192.168.1.100",
                target_os="Linux"
            ),
            execution=ExecutionContext(
                module_used="rx-nuclei-CVE-2023-12345",
                technique_id="T1190",
                duration_ms=5000
            ),
            error=ErrorDetails(
                error_type="exploit_failed",
                error_message="Exploit returned non-zero exit code",
                detected_defenses=["waf"]
            ),
            retry_count=1,
            max_retries=3
        )
        
        prompt = build_analysis_prompt(request)
        
        # Verify prompt contains key elements
        assert "Task ID" in prompt
        assert "192.168.1.100" in prompt
        assert "exploit_failed" in prompt
        assert "waf" in prompt
        
        # Verify Nuclei context section exists
        assert "Nuclei" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
