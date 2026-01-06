# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Multi-Stage Penetration Testing Scenarios
# Real-world attack scenarios with multiple phases
# ═══════════════════════════════════════════════════════════════════════════════

"""
Multi-Stage Penetration Testing Scenario Tests

These tests simulate real penetration testing workflows:
1. Initial Reconnaissance
2. Vulnerability Assessment
3. Exploitation (against authorized targets)
4. Post-Exploitation
5. Lateral Movement Preparation

IMPORTANT: Only run against systems you own or have explicit authorization to test.
"""

import os
import sys
import time
import pytest
import asyncio
import logging
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))

try:
    from .conftest import TestExecutionResult, RealTestConfig
except ImportError:
    from conftest import TestExecutionResult, RealTestConfig

logger = logging.getLogger("raglox.tests.scenarios")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario Data Structures
# ═══════════════════════════════════════════════════════════════════════════════

class ScenarioPhase(Enum):
    """Phases of a penetration testing scenario."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    CLEANUP = "cleanup"


@dataclass
class PhaseResult:
    """Result of a scenario phase."""
    phase: ScenarioPhase
    success: bool
    duration_ms: float
    findings: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    next_phase_inputs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScenarioResult:
    """Complete scenario execution result."""
    name: str
    target: str
    phases: List[PhaseResult] = field(default_factory=list)
    total_duration_ms: float = 0
    success: bool = False
    summary: Dict[str, Any] = field(default_factory=dict)
    
    def add_phase(self, phase_result: PhaseResult):
        self.phases.append(phase_result)
        self.total_duration_ms += phase_result.duration_ms
    
    def generate_summary(self) -> Dict[str, Any]:
        successful_phases = [p for p in self.phases if p.success]
        total_findings = sum(len(p.findings) for p in self.phases)
        
        self.summary = {
            "scenario": self.name,
            "target": self.target,
            "total_phases": len(self.phases),
            "successful_phases": len(successful_phases),
            "total_findings": total_findings,
            "total_duration_ms": self.total_duration_ms,
            "phases": [
                {
                    "name": p.phase.value,
                    "success": p.success,
                    "findings_count": len(p.findings),
                    "duration_ms": p.duration_ms
                }
                for p in self.phases
            ]
        }
        self.success = len(successful_phases) == len(self.phases)
        return self.summary


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 1: Basic Network Reconnaissance
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario01BasicRecon:
    """
    Scenario 01: Basic Network Reconnaissance
    
    Phases:
    1. Host Discovery
    2. Port Scanning
    3. Service Detection
    4. OS Fingerprinting
    """
    
    @pytest.mark.asyncio
    async def test_scenario_01_full(self, ssh_executor, test_config, result_collector):
        """
        SCENARIO-01: Complete Basic Recon
        Full reconnaissance workflow against localhost.
        """
        start = time.time()
        scenario = ScenarioResult(
            name="Basic Network Reconnaissance",
            target="127.0.0.1"
        )
        
        try:
            from executors.models import ExecutionRequest
            
            # Phase 1: Host Discovery (Ping)
            phase1_start = time.time()
            findings1 = []
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ping -c 2 -W 2 127.0.0.1 && echo 'HOST_UP' || echo 'HOST_DOWN'",
                    timeout=30
                )
            )
            
            host_up = "HOST_UP" in result.stdout
            findings1.append({
                "type": "host_discovery",
                "target": "127.0.0.1",
                "status": "up" if host_up else "down",
                "method": "icmp_ping"
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.RECONNAISSANCE,
                success=host_up,
                duration_ms=(time.time() - phase1_start) * 1000,
                findings=findings1,
                next_phase_inputs={"target_ip": "127.0.0.1", "host_status": "up" if host_up else "down"}
            ))
            
            # Phase 2: Port Scanning
            phase2_start = time.time()
            findings2 = []
            
            # Check if nmap available
            nmap_available = await ssh_executor.check_tool_available('nmap')
            
            if nmap_available:
                result = await ssh_executor.execute(
                    ExecutionRequest(
                        command="nmap -sT -p 21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080 --open -oG - 127.0.0.1 2>/dev/null",
                        timeout=120
                    )
                )
                
                # Parse open ports
                import re
                for line in result.stdout.split('\n'):
                    if 'Ports:' in line:
                        ports = re.findall(r'(\d+)/open/([^/]*)/([^/]*)/([^,]*)', line)
                        for port, state, proto, service in ports:
                            findings2.append({
                                "type": "open_port",
                                "port": int(port),
                                "protocol": proto,
                                "service": service.strip(),
                                "state": "open"
                            })
            else:
                # Fallback to netcat/bash
                for port in [22, 80, 443]:
                    result = await ssh_executor.execute(
                        ExecutionRequest(
                            command=f"(echo > /dev/tcp/127.0.0.1/{port}) 2>/dev/null && echo 'OPEN' || echo 'CLOSED'",
                            timeout=5
                        )
                    )
                    if "OPEN" in result.stdout:
                        findings2.append({
                            "type": "open_port",
                            "port": port,
                            "protocol": "tcp",
                            "service": "unknown",
                            "state": "open"
                        })
            
            open_ports = [f["port"] for f in findings2]
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.SCANNING,
                success=True,
                duration_ms=(time.time() - phase2_start) * 1000,
                findings=findings2,
                next_phase_inputs={"open_ports": open_ports}
            ))
            
            # Phase 3: Service Detection
            phase3_start = time.time()
            findings3 = []
            
            if nmap_available and open_ports:
                ports_str = ",".join(str(p) for p in open_ports[:10])
                result = await ssh_executor.execute(
                    ExecutionRequest(
                        command=f"nmap -sV -p {ports_str} 127.0.0.1 2>/dev/null",
                        timeout=180
                    )
                )
                
                # Parse service versions
                for line in result.stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_proto = parts[0]
                            port = int(port_proto.split('/')[0])
                            service_info = ' '.join(parts[2:])
                            findings3.append({
                                "type": "service_version",
                                "port": port,
                                "service_info": service_info[:200]
                            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.ENUMERATION,
                success=True,
                duration_ms=(time.time() - phase3_start) * 1000,
                findings=findings3
            ))
            
            # Phase 4: OS Fingerprinting
            phase4_start = time.time()
            findings4 = []
            
            # Get OS info from system
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="uname -a && cat /etc/os-release 2>/dev/null | head -5",
                    timeout=30
                )
            )
            
            findings4.append({
                "type": "os_info",
                "method": "local_query",
                "info": result.stdout[:500]
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.RECONNAISSANCE,
                success=True,
                duration_ms=(time.time() - phase4_start) * 1000,
                findings=findings4
            ))
            
            # Generate summary
            summary = scenario.generate_summary()
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 01: Basic Recon",
                passed=scenario.success,
                duration_ms=duration,
                output=json.dumps(summary, indent=2),
                metadata=summary
            ))
            
            logger.info(f"✅ Scenario 01 completed in {duration:.0f}ms")
            logger.info(f"   Phases: {summary['successful_phases']}/{summary['total_phases']}")
            logger.info(f"   Findings: {summary['total_findings']}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 01: Basic Recon",
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Scenario failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 2: Web Application Assessment
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario02WebAppAssessment:
    """
    Scenario 02: Web Application Assessment
    
    Phases:
    1. Web Service Discovery
    2. Technology Detection
    3. Directory/File Enumeration
    4. Header Analysis
    5. Vulnerability Checks
    """
    
    @pytest.mark.asyncio
    async def test_scenario_02_web_assessment(self, ssh_executor, test_config, result_collector):
        """
        SCENARIO-02: Web Application Assessment
        Full web application security assessment against a test endpoint.
        """
        start = time.time()
        scenario = ScenarioResult(
            name="Web Application Assessment",
            target="httpstat.us"  # Safe public test endpoint
        )
        
        try:
            from executors.models import ExecutionRequest
            
            # Check curl availability
            curl_available = await ssh_executor.check_tool_available('curl')
            if not curl_available:
                pytest.skip("curl not installed")
            
            # Phase 1: Web Service Discovery
            phase1_start = time.time()
            findings1 = []
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="curl -sI https://httpstat.us/200 --connect-timeout 10 2>/dev/null | head -1",
                    timeout=30
                )
            )
            
            http_version = result.stdout.strip()
            web_accessible = "HTTP" in http_version
            
            findings1.append({
                "type": "web_discovery",
                "target": "httpstat.us",
                "accessible": web_accessible,
                "http_response": http_version
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.RECONNAISSANCE,
                success=web_accessible,
                duration_ms=(time.time() - phase1_start) * 1000,
                findings=findings1
            ))
            
            if not web_accessible:
                scenario.generate_summary()
                return
            
            # Phase 2: Technology Detection (Headers Analysis)
            phase2_start = time.time()
            findings2 = []
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="curl -sI https://httpstat.us/200 --connect-timeout 10 2>/dev/null",
                    timeout=30
                )
            )
            
            headers = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Security headers check
            security_headers = [
                'x-frame-options',
                'x-content-type-options',
                'x-xss-protection',
                'content-security-policy',
                'strict-transport-security'
            ]
            
            for header in security_headers:
                present = header in headers
                findings2.append({
                    "type": "security_header",
                    "header": header,
                    "present": present,
                    "value": headers.get(header, "NOT SET")[:200]
                })
            
            # Server header (potential info disclosure)
            if 'server' in headers:
                findings2.append({
                    "type": "info_disclosure",
                    "header": "Server",
                    "value": headers['server'],
                    "severity": "low"
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.ENUMERATION,
                success=True,
                duration_ms=(time.time() - phase2_start) * 1000,
                findings=findings2,
                artifacts={"headers": headers}
            ))
            
            # Phase 3: HTTP Methods Check
            phase3_start = time.time()
            findings3 = []
            
            # Test common HTTP methods
            methods = ['GET', 'HEAD', 'OPTIONS', 'POST']
            for method in methods:
                result = await ssh_executor.execute(
                    ExecutionRequest(
                        command=f"curl -s -o /dev/null -w '%{{http_code}}' -X {method} https://httpstat.us/200 --connect-timeout 5 2>/dev/null",
                        timeout=15
                    )
                )
                
                status_code = result.stdout.strip()
                findings3.append({
                    "type": "http_method",
                    "method": method,
                    "status_code": status_code,
                    "allowed": status_code not in ['405', '501']
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.VULNERABILITY_ASSESSMENT,
                success=True,
                duration_ms=(time.time() - phase3_start) * 1000,
                findings=findings3
            ))
            
            # Phase 4: Common Vulnerability Checks
            phase4_start = time.time()
            findings4 = []
            
            # Test for different HTTP status codes (useful for testing)
            test_codes = [200, 301, 404, 500]
            for code in test_codes:
                result = await ssh_executor.execute(
                    ExecutionRequest(
                        command=f"curl -s -o /dev/null -w '%{{http_code}}' https://httpstat.us/{code} --connect-timeout 5 2>/dev/null",
                        timeout=15
                    )
                )
                
                actual_code = result.stdout.strip()
                findings4.append({
                    "type": "status_code_test",
                    "expected": str(code),
                    "actual": actual_code,
                    "match": str(code) == actual_code
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.VULNERABILITY_ASSESSMENT,
                success=True,
                duration_ms=(time.time() - phase4_start) * 1000,
                findings=findings4
            ))
            
            # Generate summary
            summary = scenario.generate_summary()
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 02: Web Assessment",
                passed=scenario.success,
                duration_ms=duration,
                output=json.dumps(summary, indent=2),
                metadata=summary
            ))
            
            logger.info(f"✅ Scenario 02 completed in {duration:.0f}ms")
            logger.info(f"   Phases: {summary['successful_phases']}/{summary['total_phases']}")
            logger.info(f"   Findings: {summary['total_findings']}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 02: Web Assessment",
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Scenario failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 3: Post-Exploitation Enumeration
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario03PostExploitation:
    """
    Scenario 03: Post-Exploitation Enumeration
    
    Simulate post-exploitation reconnaissance after gaining access.
    
    Phases:
    1. User/System Enumeration
    2. Network Discovery
    3. Sensitive File Search
    4. Credential Hunting
    5. Privilege Escalation Vector Discovery
    """
    
    @pytest.mark.asyncio
    async def test_scenario_03_post_exploitation(self, ssh_executor, test_config, result_collector):
        """
        SCENARIO-03: Post-Exploitation Enumeration
        Comprehensive post-exploitation information gathering.
        """
        start = time.time()
        scenario = ScenarioResult(
            name="Post-Exploitation Enumeration",
            target=test_config.ssh_host or "localhost"
        )
        
        try:
            from executors.models import ExecutionRequest
            
            # Phase 1: System & User Enumeration
            phase1_start = time.time()
            findings1 = []
            
            # Get current user context
            result = await ssh_executor.execute(
                ExecutionRequest(command="id", timeout=10)
            )
            findings1.append({
                "type": "current_user",
                "info": result.stdout.strip()
            })
            
            # Get hostname
            result = await ssh_executor.execute(
                ExecutionRequest(command="hostname", timeout=10)
            )
            findings1.append({
                "type": "hostname",
                "value": result.stdout.strip()
            })
            
            # Get OS info
            result = await ssh_executor.execute(
                ExecutionRequest(command="uname -a", timeout=10)
            )
            findings1.append({
                "type": "kernel_info",
                "value": result.stdout.strip()
            })
            
            # List users with shell
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="cat /etc/passwd 2>/dev/null | grep -v 'nologin\\|false' | cut -d: -f1,3,4",
                    timeout=10
                )
            )
            users = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            findings1.append({
                "type": "shell_users",
                "count": len(users),
                "users": users[:20]
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.POST_EXPLOITATION,
                success=True,
                duration_ms=(time.time() - phase1_start) * 1000,
                findings=findings1
            ))
            
            # Phase 2: Network Discovery
            phase2_start = time.time()
            findings2 = []
            
            # Get IP addresses
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ip addr show 2>/dev/null | grep 'inet ' | awk '{print $2}'",
                    timeout=10
                )
            )
            ips = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            findings2.append({
                "type": "local_ips",
                "ips": ips
            })
            
            # Get default gateway
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ip route | grep default | awk '{print $3}'",
                    timeout=10
                )
            )
            findings2.append({
                "type": "default_gateway",
                "gateway": result.stdout.strip()
            })
            
            # Get ARP table
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ip neigh 2>/dev/null | head -20",
                    timeout=10
                )
            )
            neighbors = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            findings2.append({
                "type": "arp_neighbors",
                "count": len(neighbors),
                "entries": neighbors[:10]
            })
            
            # Get listening services
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ss -tlnp 2>/dev/null | tail -n +2",
                    timeout=10
                )
            )
            services = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            findings2.append({
                "type": "listening_services",
                "count": len(services),
                "services": services[:15]
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.POST_EXPLOITATION,
                success=True,
                duration_ms=(time.time() - phase2_start) * 1000,
                findings=findings2
            ))
            
            # Phase 3: Sensitive File Discovery (Safe)
            phase3_start = time.time()
            findings3 = []
            
            # Check for common sensitive files (existence only)
            sensitive_files = [
                '/etc/shadow',
                '/etc/sudoers',
                '/root/.ssh/authorized_keys',
                '/root/.bash_history',
                '/etc/crontab'
            ]
            
            for filepath in sensitive_files:
                result = await ssh_executor.execute(
                    ExecutionRequest(
                        command=f"test -r {filepath} && echo 'READABLE' || echo 'NOT_READABLE'",
                        timeout=5
                    )
                )
                readable = "READABLE" in result.stdout
                findings3.append({
                    "type": "sensitive_file",
                    "path": filepath,
                    "readable": readable,
                    "severity": "high" if readable and 'shadow' in filepath else "medium"
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.POST_EXPLOITATION,
                success=True,
                duration_ms=(time.time() - phase3_start) * 1000,
                findings=findings3
            ))
            
            # Phase 4: SUID/SGID Binary Discovery
            phase4_start = time.time()
            findings4 = []
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="find /usr/bin /usr/sbin /bin /sbin -perm -4000 -o -perm -2000 2>/dev/null | head -30",
                    timeout=60
                )
            )
            
            suid_bins = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            # Check for known exploitable SUID binaries
            exploitable = ['nmap', 'vim', 'find', 'bash', 'python', 'perl', 'awk', 'less', 'more', 'nano']
            potentially_exploitable = [b for b in suid_bins if any(e in b.lower() for e in exploitable)]
            
            findings4.append({
                "type": "suid_binaries",
                "total_count": len(suid_bins),
                "potentially_exploitable": potentially_exploitable[:10],
                "all_suid": suid_bins[:20]
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.PRIVILEGE_ESCALATION,
                success=True,
                duration_ms=(time.time() - phase4_start) * 1000,
                findings=findings4
            ))
            
            # Phase 5: Sudo Privileges Check
            phase5_start = time.time()
            findings5 = []
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="sudo -l 2>/dev/null || echo 'SUDO_CHECK_FAILED'",
                    timeout=15
                )
            )
            
            if "SUDO_CHECK_FAILED" not in result.stdout:
                findings5.append({
                    "type": "sudo_privileges",
                    "can_check": True,
                    "output": result.stdout[:1000]
                })
            else:
                findings5.append({
                    "type": "sudo_privileges",
                    "can_check": False,
                    "reason": "sudo -l failed"
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.PRIVILEGE_ESCALATION,
                success=True,
                duration_ms=(time.time() - phase5_start) * 1000,
                findings=findings5
            ))
            
            # Generate summary
            summary = scenario.generate_summary()
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 03: Post-Exploitation",
                passed=scenario.success,
                duration_ms=duration,
                output=json.dumps(summary, indent=2),
                metadata=summary
            ))
            
            logger.info(f"✅ Scenario 03 completed in {duration:.0f}ms")
            logger.info(f"   Phases: {summary['successful_phases']}/{summary['total_phases']}")
            logger.info(f"   Findings: {summary['total_findings']}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 03: Post-Exploitation",
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Scenario failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario 4: Full Attack Chain Simulation
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenario04FullAttackChain:
    """
    Scenario 04: Full Attack Chain Simulation
    
    Complete attack chain from recon to cleanup.
    Safe mode - no actual exploitation.
    
    Phases:
    1. External Reconnaissance
    2. Initial Access (SSH connection)
    3. Post-Exploitation Enum
    4. Data Discovery
    5. Evidence of Persistence Methods
    6. Cleanup
    """
    
    @pytest.mark.asyncio
    async def test_scenario_04_attack_chain(self, ssh_executor, test_config, result_collector):
        """
        SCENARIO-04: Full Attack Chain Simulation
        Complete simulated attack workflow.
        """
        start = time.time()
        scenario = ScenarioResult(
            name="Full Attack Chain Simulation",
            target=test_config.ssh_host or "localhost"
        )
        
        try:
            from executors.models import ExecutionRequest
            
            # Phase 1: External Reconnaissance (Pre-Access)
            phase1_start = time.time()
            findings1 = []
            
            # Simulate external recon by checking accessible services
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ss -tln | grep LISTEN | awk '{print $4}' | sed 's/.*://' | sort -u | head -10",
                    timeout=15
                )
            )
            
            ports = [p.strip() for p in result.stdout.split('\n') if p.strip()]
            findings1.append({
                "type": "external_recon",
                "discovered_ports": ports,
                "attack_surface": len(ports)
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.RECONNAISSANCE,
                success=True,
                duration_ms=(time.time() - phase1_start) * 1000,
                findings=findings1
            ))
            
            # Phase 2: Initial Access Verification
            phase2_start = time.time()
            findings2 = []
            
            # Verify we have shell access
            result = await ssh_executor.execute(
                ExecutionRequest(command="echo 'SHELL_ACCESS_CONFIRMED'", timeout=10)
            )
            
            shell_access = "SHELL_ACCESS_CONFIRMED" in result.stdout
            
            # Get access context
            result = await ssh_executor.execute(
                ExecutionRequest(command="whoami && groups", timeout=10)
            )
            
            findings2.append({
                "type": "initial_access",
                "method": "SSH",
                "success": shell_access,
                "context": result.stdout.strip()
            })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.EXPLOITATION,
                success=shell_access,
                duration_ms=(time.time() - phase2_start) * 1000,
                findings=findings2
            ))
            
            # Phase 3: Rapid Enumeration
            phase3_start = time.time()
            findings3 = []
            
            # Quick system info
            cmds = [
                ("kernel", "uname -r"),
                ("arch", "uname -m"),
                ("distro", "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'"),
                ("uptime", "uptime -p 2>/dev/null || uptime"),
            ]
            
            for name, cmd in cmds:
                result = await ssh_executor.execute(
                    ExecutionRequest(command=cmd, timeout=10)
                )
                findings3.append({
                    "type": "system_enum",
                    "category": name,
                    "value": result.stdout.strip()[:200]
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.POST_EXPLOITATION,
                success=True,
                duration_ms=(time.time() - phase3_start) * 1000,
                findings=findings3
            ))
            
            # Phase 4: Data Discovery
            phase4_start = time.time()
            findings4 = []
            
            # Find interesting files (limited search)
            patterns = [
                ("config_files", "find /etc -name '*.conf' 2>/dev/null | head -10"),
                ("log_files", "find /var/log -name '*.log' 2>/dev/null | head -10"),
                ("backup_files", "find /home /root /var -name '*.bak' -o -name '*.backup' 2>/dev/null | head -5"),
            ]
            
            for name, cmd in patterns:
                result = await ssh_executor.execute(
                    ExecutionRequest(command=cmd, timeout=30)
                )
                files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
                findings4.append({
                    "type": "data_discovery",
                    "category": name,
                    "count": len(files),
                    "samples": files[:5]
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.DATA_EXFILTRATION,
                success=True,
                duration_ms=(time.time() - phase4_start) * 1000,
                findings=findings4
            ))
            
            # Phase 5: Persistence Methods Analysis
            phase5_start = time.time()
            findings5 = []
            
            # Check for common persistence locations
            persistence_checks = [
                ("cron_user", "crontab -l 2>/dev/null | wc -l"),
                ("cron_system", "ls /etc/cron.d/ 2>/dev/null | wc -l"),
                ("ssh_keys", "test -d ~/.ssh && ls ~/.ssh 2>/dev/null | wc -l || echo '0'"),
                ("systemd_user", "ls ~/.config/systemd/user/*.service 2>/dev/null | wc -l || echo '0'"),
            ]
            
            for name, cmd in persistence_checks:
                result = await ssh_executor.execute(
                    ExecutionRequest(command=cmd, timeout=10)
                )
                count = result.stdout.strip()
                findings5.append({
                    "type": "persistence_check",
                    "method": name,
                    "count": count,
                    "potential": int(count) > 0 if count.isdigit() else False
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.PERSISTENCE,
                success=True,
                duration_ms=(time.time() - phase5_start) * 1000,
                findings=findings5
            ))
            
            # Phase 6: Cleanup (Simulated)
            phase6_start = time.time()
            findings6 = []
            
            # Log cleanup actions (not actually doing cleanup in safe mode)
            cleanup_actions = [
                "Clear bash history: history -c (not executed)",
                "Remove temp files: rm -rf /tmp/raglox_* (not executed)",
                "Clear auth logs: (requires root, not executed)",
            ]
            
            for action in cleanup_actions:
                findings6.append({
                    "type": "cleanup_action",
                    "action": action,
                    "executed": False,
                    "reason": "Safe mode - simulation only"
                })
            
            scenario.add_phase(PhaseResult(
                phase=ScenarioPhase.CLEANUP,
                success=True,
                duration_ms=(time.time() - phase6_start) * 1000,
                findings=findings6
            ))
            
            # Generate summary
            summary = scenario.generate_summary()
            
            # Add attack chain specific metrics
            summary["attack_chain_metrics"] = {
                "total_phases": len(scenario.phases),
                "kill_chain_coverage": [p.phase.value for p in scenario.phases],
                "total_findings": sum(len(p.findings) for p in scenario.phases),
                "risk_level": "SIMULATION"
            }
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 04: Full Attack Chain",
                passed=scenario.success,
                duration_ms=duration,
                output=json.dumps(summary, indent=2),
                metadata=summary
            ))
            
            logger.info(f"✅ Scenario 04 completed in {duration:.0f}ms")
            logger.info(f"   Attack Chain Phases: {len(scenario.phases)}")
            logger.info(f"   Total Findings: {summary['total_findings']}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name="Scenario 04: Full Attack Chain",
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Scenario failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Scenario Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

class TestScenarioOrchestrator:
    """Run multiple scenarios and generate comprehensive report."""
    
    @pytest.mark.asyncio
    async def test_all_scenarios_report(self, ssh_executor, test_config, result_collector):
        """
        Run all scenarios and generate comprehensive report.
        """
        # This test just generates a final report from all collected results
        report = result_collector.generate_report()
        
        logger.info("\n" + "="*60)
        logger.info("RAGLOX MULTI-STAGE SCENARIO TEST REPORT")
        logger.info("="*60)
        logger.info(f"Total Tests: {report['summary']['total']}")
        logger.info(f"Passed: {report['summary']['passed']}")
        logger.info(f"Failed: {report['summary']['failed']}")
        logger.info(f"Pass Rate: {report['summary']['pass_rate']}")
        logger.info("="*60)


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone Runner
# ═══════════════════════════════════════════════════════════════════════════════

async def run_scenarios_standalone():
    """Run scenarios without pytest."""
    from .conftest import RealTestConfig, TestResultCollector
    
    config = RealTestConfig.from_env()
    
    if not config.has_valid_ssh:
        print("❌ SSH not configured for scenario tests")
        return False
    
    print(f"🎯 Running multi-stage scenarios against {config.ssh_host}")
    print("This may take several minutes...")
    
    # Run simplified scenario
    try:
        from executors.ssh import SSHExecutor
        from executors.models import SSHConfig, ExecutionRequest
        from pydantic import SecretStr
        
        ssh_config = SSHConfig(
            host=config.ssh_host,
            port=config.ssh_port,
            username=config.ssh_user,
            password=SecretStr(config.ssh_password) if config.ssh_password else None,
            private_key=config.ssh_key_path,
            timeout=120,
        )
        
        executor = SSHExecutor(ssh_config)
        await executor.connect()
        
        print("\n📍 Phase 1: System Recon")
        result = await executor.execute(ExecutionRequest(command="uname -a", timeout=10))
        print(f"   System: {result.stdout.strip()[:60]}")
        
        print("\n📍 Phase 2: Network Recon")
        result = await executor.execute(ExecutionRequest(command="ip addr show | grep 'inet ' | wc -l", timeout=10))
        print(f"   Network interfaces: {result.stdout.strip()}")
        
        print("\n📍 Phase 3: Service Enum")
        result = await executor.execute(ExecutionRequest(command="ss -tln | grep LISTEN | wc -l", timeout=10))
        print(f"   Listening services: {result.stdout.strip()}")
        
        print("\n📍 Phase 4: User Enum")
        result = await executor.execute(ExecutionRequest(command="cat /etc/passwd | wc -l", timeout=10))
        print(f"   Total users: {result.stdout.strip()}")
        
        await executor.disconnect()
        
        print("\n✅ Scenario completed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Scenario failed: {e}")
        return False


if __name__ == "__main__":
    import asyncio
    success = asyncio.run(run_scenarios_standalone())
    sys.exit(0 if success else 1)
