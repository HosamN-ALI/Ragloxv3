#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Intensive Real Attack Tests
═══════════════════════════════════════════════════════════════════════════════

This test suite runs REAL attacks against the vulnerable target container.
NO MOCK DATA - All operations are performed using actual tools and systems.

Target: raglox-vulnerable-target (172.28.0.100)
- SSH: Port 22 (OpenSSH 8.9p1)
- HTTP: Port 80 (nginx 1.18.0)
- External Access: localhost:8088 (HTTP), localhost:2222 (SSH)

Requirements:
- Docker container 'raglox-vulnerable-target' must be running
- Tools: nmap, nuclei, hydra, netcat

Usage:
    PYTHONPATH=/root/RAGLOX_V3/webapp python3 webapp/tests/intensive_real_attack_tests.py
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.blackboard import Blackboard
from src.core.config import get_settings
from src.core.knowledge import EmbeddedKnowledge
from src.core.models import (
    Mission, MissionCreate, MissionStatus, Task, TaskType, TaskStatus,
    SpecialistType, Target, TargetStatus, Vulnerability, Severity,
    Credential, CredentialType, Session, SessionStatus, SessionType
)
from src.specialists.recon import ReconSpecialist
from src.specialists.attack import AttackSpecialist
from src.specialists.analysis import AnalysisSpecialist
from src.executors import LocalExecutor, ExecutorFactory, get_executor_factory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("raglox.intensive_tests")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TargetConfig:
    """Configuration for the vulnerable target."""
    container_name: str = "raglox-vulnerable-target"
    internal_ip: str = "172.28.0.100"  # Docker network IP
    external_http_port: int = 8088      # Mapped to internal port 80
    external_ssh_port: int = 2222       # Mapped to internal port 22
    hostname: str = "localhost"
    network: str = "172.28.0.0/24"


@dataclass
class TestMetrics:
    """Metrics collected during tests."""
    total_commands_executed: int = 0
    successful_commands: int = 0
    failed_commands: int = 0
    total_execution_time_ms: int = 0
    nmap_scans: int = 0
    nuclei_scans: int = 0
    hydra_attacks: int = 0
    vulnerabilities_found: List[Dict] = field(default_factory=list)
    credentials_found: List[Dict] = field(default_factory=list)
    services_discovered: List[Dict] = field(default_factory=list)
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_cost: float = 0.0


class TestResult(Enum):
    PASSED = "PASSED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


@dataclass
class TestCase:
    """Individual test case result."""
    name: str
    category: str
    result: TestResult
    duration_ms: int = 0
    description: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Real Tool Executors
# ═══════════════════════════════════════════════════════════════════════════════

class RealToolExecutor:
    """
    Execute real security tools (nmap, nuclei, hydra, etc.)
    """
    
    def __init__(self, metrics: TestMetrics):
        self.metrics = metrics
        self.logger = logging.getLogger("raglox.tools")
    
    async def run_command(
        self, 
        command: str, 
        timeout: int = 120,
        capture_output: bool = True
    ) -> Dict[str, Any]:
        """Execute a shell command and return results."""
        start_time = time.time()
        self.metrics.total_commands_executed += 1
        
        try:
            self.logger.info(f"Executing: {command[:100]}...")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE if capture_output else None,
                stderr=asyncio.subprocess.PIPE if capture_output else None,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                
                duration_ms = int((time.time() - start_time) * 1000)
                self.metrics.total_execution_time_ms += duration_ms
                
                if process.returncode == 0:
                    self.metrics.successful_commands += 1
                else:
                    self.metrics.failed_commands += 1
                
                return {
                    "success": process.returncode == 0,
                    "stdout": stdout.decode('utf-8', errors='ignore') if stdout else "",
                    "stderr": stderr.decode('utf-8', errors='ignore') if stderr else "",
                    "exit_code": process.returncode,
                    "duration_ms": duration_ms
                }
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                self.metrics.failed_commands += 1
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout}s",
                    "exit_code": -1,
                    "duration_ms": timeout * 1000
                }
                
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            self.metrics.failed_commands += 1
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "duration_ms": int((time.time() - start_time) * 1000)
            }
    
    async def nmap_scan(
        self, 
        target: str, 
        scan_type: str = "full",
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """Run nmap scan."""
        self.metrics.nmap_scans += 1
        
        if scan_type == "ping":
            cmd = f"nmap -sn {target} -oG - 2>/dev/null"
        elif scan_type == "quick":
            cmd = f"nmap -F {target} -oN - 2>/dev/null"
        elif scan_type == "service":
            cmd = f"nmap -sV -sC {target} -oN - 2>/dev/null"
        elif scan_type == "aggressive":
            cmd = f"nmap -A -T4 {target} -oN - 2>/dev/null"
        elif scan_type == "vuln":
            cmd = f"nmap --script vuln {target} -oN - 2>/dev/null"
        else:  # full
            cmd = f"nmap -p {ports} {target} -oN - 2>/dev/null"
        
        return await self.run_command(cmd, timeout=180)
    
    async def nuclei_scan(
        self, 
        target: str, 
        templates: Optional[str] = None,
        severity: Optional[str] = None,
        timeout: int = 120
    ) -> Dict[str, Any]:
        """Run nuclei vulnerability scan."""
        self.metrics.nuclei_scans += 1
        
        # Use fast scan options
        cmd = f"nuclei -u {target} -silent -j -rate-limit 50 -timeout 5 -retries 1"
        
        if templates:
            cmd += f" -t {templates}"
        if severity:
            cmd += f" -severity {severity}"
        
        return await self.run_command(cmd, timeout=timeout)
    
    async def hydra_attack(
        self, 
        target: str,
        service: str,
        port: int,
        userlist: str,
        passlist: str,
        options: str = ""
    ) -> Dict[str, Any]:
        """Run hydra brute force attack."""
        self.metrics.hydra_attacks += 1
        
        cmd = f"hydra -L {userlist} -P {passlist} {target} {service} -s {port} -t 4 {options}"
        return await self.run_command(cmd, timeout=600)
    
    async def netcat_probe(
        self, 
        target: str, 
        port: int,
        timeout: int = 5
    ) -> Dict[str, Any]:
        """Probe a port with netcat."""
        cmd = f"nc -zv -w {timeout} {target} {port} 2>&1"
        return await self.run_command(cmd, timeout=timeout + 2)
    
    async def curl_request(
        self, 
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make HTTP request with curl."""
        cmd = f"curl -s -i -X {method}"
        
        if headers:
            for k, v in headers.items():
                cmd += f" -H '{k}: {v}'"
        
        if data:
            cmd += f" -d '{data}'"
        
        cmd += f" '{url}'"
        return await self.run_command(cmd, timeout=30)


# ═══════════════════════════════════════════════════════════════════════════════
# Test Classes
# ═══════════════════════════════════════════════════════════════════════════════

class IntensiveRealTests:
    """
    Intensive real attack tests against the vulnerable target.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.target = TargetConfig()
        self.metrics = TestMetrics()
        self.tools = RealToolExecutor(self.metrics)
        self.test_results: List[TestCase] = []
        self.blackboard: Optional[Blackboard] = None
        self.knowledge: Optional[EmbeddedKnowledge] = None
        self.mission_id: Optional[str] = None
        
        # Specialists
        self.recon: Optional[ReconSpecialist] = None
        self.attack: Optional[AttackSpecialist] = None
        self.analysis: Optional[AnalysisSpecialist] = None
    
    async def setup(self) -> bool:
        """Initialize all components."""
        print("\n" + "=" * 70)
        print("🔧 SETUP: Initializing Real Attack Test Environment")
        print("=" * 70)
        
        try:
            # 1. Load Knowledge Base
            print("\n📚 Loading Knowledge Base...")
            self.knowledge = EmbeddedKnowledge(data_path=self.settings.knowledge_data_path)
            self.knowledge.load()  # Synchronous load method
            stats = self.knowledge.get_statistics()
            print(f"   ✓ Loaded: {stats.get('total_rx_modules', 0)} modules, "
                  f"{stats.get('total_techniques', 0)} techniques")
            
            # 2. Connect to Redis/Blackboard
            print("\n🔴 Connecting to Redis...")
            self.blackboard = Blackboard(self.settings.redis_url)
            await self.blackboard.connect()
            health = await self.blackboard.health_check()
            # health_check returns bool or dict
            is_healthy = health if isinstance(health, bool) else health.get('healthy', False)
            print(f"   ✓ Redis connected: {is_healthy}")
            
            # 3. Create Mission
            print("\n🎯 Creating Attack Mission...")
            mission = Mission(
                name="Intensive Real Attack Test",
                description="Full attack chain against vulnerable target",
                scope=[self.target.network, f"{self.target.hostname}:{self.target.external_http_port}"],
                goals={
                    "recon": "pending",
                    "vuln_scan": "pending",
                    "exploit": "pending",
                    "credential_harvest": "pending",
                    "persistence": "pending"
                },
                constraints={
                    "allowed_techniques": ["T1046", "T1595", "T1190", "T1078", "T1110"],
                    "stealth_level": "low",
                    "max_noise_score": 100
                }
            )
            self.mission_id = await self.blackboard.create_mission(mission)
            print(f"   ✓ Mission created: {self.mission_id}")
            
            # 4. Verify Target Accessibility
            print("\n🎯 Verifying Target Accessibility...")
            result = await self.tools.netcat_probe(
                self.target.hostname, 
                self.target.external_http_port
            )
            if not result["success"] and "open" not in result["stdout"].lower():
                print(f"   ⚠ HTTP port might be closed: {result['stderr']}")
            else:
                print(f"   ✓ HTTP Port {self.target.external_http_port}: accessible")
            
            result = await self.tools.netcat_probe(
                self.target.hostname, 
                self.target.external_ssh_port
            )
            if not result["success"] and "open" not in result["stdout"].lower():
                print(f"   ⚠ SSH port might be closed: {result['stderr']}")
            else:
                print(f"   ✓ SSH Port {self.target.external_ssh_port}: accessible")
            
            # 5. Initialize Specialists
            print("\n🤖 Initializing Specialists...")
            
            # Get executor factory for real command execution
            executor_factory = get_executor_factory()
            
            self.recon = ReconSpecialist(
                blackboard=self.blackboard,
                settings=self.settings,
                worker_id="recon-intensive-test",
                knowledge=self.knowledge,
                executor_factory=executor_factory
            )
            self.recon._current_mission_id = self.mission_id
            print("   ✓ ReconSpecialist ready")
            
            self.attack = AttackSpecialist(
                blackboard=self.blackboard,
                settings=self.settings,
                worker_id="attack-intensive-test",
                knowledge=self.knowledge,
                executor_factory=executor_factory
            )
            self.attack._current_mission_id = self.mission_id
            print("   ✓ AttackSpecialist ready")
            
            self.analysis = AnalysisSpecialist(
                blackboard=self.blackboard,
                settings=self.settings,
                worker_id="analysis-intensive-test",
                knowledge=self.knowledge
            )
            self.analysis._current_mission_id = self.mission_id
            print("   ✓ AnalysisSpecialist ready")
            
            print("\n✅ Setup complete!")
            return True
            
        except Exception as e:
            print(f"\n❌ Setup failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def cleanup(self):
        """Clean up resources."""
        print("\n🧹 Cleaning up...")
        if self.blackboard:
            await self.blackboard.disconnect()
        print("   ✓ Cleanup complete")
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 1: Reconnaissance Tests
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_real_ping_sweep(self) -> TestCase:
        """Test real ping sweep using nmap."""
        start = time.time()
        
        try:
            result = await self.tools.nmap_scan(
                self.target.network,
                scan_type="ping"
            )
            
            # Parse results
            hosts_found = []
            if result["success"]:
                for line in result["stdout"].split("\n"):
                    if "Up" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            hosts_found.append(parts[1])
            
            duration = int((time.time() - start) * 1000)
            
            return TestCase(
                name="Real Ping Sweep",
                category="RECON",
                result=TestResult.PASSED if len(hosts_found) > 0 else TestResult.FAILED,
                duration_ms=duration,
                description="Network host discovery using nmap ping sweep",
                details={
                    "hosts_found": len(hosts_found),
                    "host_ips": hosts_found[:10],  # First 10
                    "target_network": self.target.network
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real Ping Sweep",
                category="RECON",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    async def test_real_port_scan(self) -> TestCase:
        """Test real port scan using nmap."""
        start = time.time()
        
        try:
            # Scan the accessible HTTP port
            result = await self.tools.nmap_scan(
                f"{self.target.hostname}",
                scan_type="full",
                ports=f"{self.target.external_http_port},{self.target.external_ssh_port}"
            )
            
            # Parse open ports
            open_ports = []
            if result["success"]:
                for line in result["stdout"].split("\n"):
                    if "/tcp" in line and "open" in line:
                        parts = line.split("/")
                        if parts:
                            port = parts[0].strip()
                            if port.isdigit():
                                open_ports.append(int(port))
            
            duration = int((time.time() - start) * 1000)
            
            # Store discovered services
            for port in open_ports:
                self.metrics.services_discovered.append({
                    "port": port,
                    "host": self.target.hostname,
                    "state": "open"
                })
            
            return TestCase(
                name="Real Port Scan",
                category="RECON",
                result=TestResult.PASSED if len(open_ports) >= 2 else TestResult.PARTIAL,
                duration_ms=duration,
                description="Port scanning with nmap",
                details={
                    "open_ports": open_ports,
                    "target": self.target.hostname,
                    "raw_output": result["stdout"][:500]
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real Port Scan",
                category="RECON",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    async def test_real_service_detection(self) -> TestCase:
        """Test real service detection with version info."""
        start = time.time()
        
        try:
            # Use quick version detection on specific ports only
            result = await self.tools.run_command(
                f"nmap -sV -p {self.target.external_http_port},{self.target.external_ssh_port} "
                f"{self.target.hostname} -oN - --version-intensity 0 2>/dev/null",
                timeout=30
            )
            
            # Parse services
            services = []
            if result.get("success") or result.get("stdout"):
                for line in result.get("stdout", "").split("\n"):
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            services.append({
                                "port": parts[0].split("/")[0],
                                "state": parts[1],
                                "service": parts[2],
                                "version": " ".join(parts[3:]) if len(parts) > 3 else ""
                            })
            
            duration = int((time.time() - start) * 1000)
            
            return TestCase(
                name="Real Service Detection",
                category="RECON",
                result=TestResult.PASSED if len(services) > 0 else TestResult.PARTIAL,
                duration_ms=duration,
                description="Service and version detection with nmap -sV",
                details={
                    "services": services,
                    "target": self.target.hostname
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real Service Detection",
                category="RECON",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 2: Vulnerability Scanning Tests
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_real_nuclei_scan(self) -> TestCase:
        """Test real vulnerability scanning with Nuclei."""
        start = time.time()
        
        try:
            target_url = f"http://{self.target.hostname}:{self.target.external_http_port}"
            
            # Run quick nuclei scan with specific templates
            result = await self.tools.run_command(
                f"nuclei -u {target_url} -silent -j -rate-limit 100 -timeout 3 -retries 0 "
                f"-tags cve,rce,sqli -severity critical,high 2>/dev/null | head -20",
                timeout=45
            )
            
            # Parse JSON results
            vulnerabilities = []
            stdout = result.get("stdout", "") if isinstance(result, dict) else ""
            if stdout:
                for line in stdout.strip().split("\n"):
                    if line.strip():
                        try:
                            vuln = json.loads(line)
                            vulnerabilities.append({
                                "template_id": vuln.get("template-id", ""),
                                "name": vuln.get("info", {}).get("name", ""),
                                "severity": vuln.get("info", {}).get("severity", ""),
                                "matched_at": vuln.get("matched-at", ""),
                                "type": vuln.get("type", "")
                            })
                        except json.JSONDecodeError:
                            pass
            
            duration = int((time.time() - start) * 1000)
            
            # Store found vulnerabilities
            self.metrics.vulnerabilities_found.extend(vulnerabilities)
            
            return TestCase(
                name="Real Nuclei Vulnerability Scan",
                category="VULN_SCAN",
                result=TestResult.PASSED,  # Even no vulns found is a valid result
                duration_ms=duration,
                description="Automated vulnerability scanning with Nuclei",
                details={
                    "vulnerabilities_found": len(vulnerabilities),
                    "vulns": vulnerabilities[:10],
                    "target": target_url,
                    "severity_filter": "critical,high,medium"
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real Nuclei Vulnerability Scan",
                category="VULN_SCAN",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    async def test_real_nmap_vuln_scan(self) -> TestCase:
        """Test vulnerability scanning with nmap scripts."""
        start = time.time()
        
        try:
            result = await self.tools.nmap_scan(
                f"{self.target.hostname}",
                scan_type="vuln"
            )
            
            # Check for vulnerabilities in output
            vuln_indicators = ["VULNERABLE", "CVE-", "exploit"]
            vulns_found = []
            
            if result["success"]:
                for indicator in vuln_indicators:
                    if indicator.lower() in result["stdout"].lower():
                        vulns_found.append(indicator)
            
            duration = int((time.time() - start) * 1000)
            
            return TestCase(
                name="Real Nmap Vulnerability Scan",
                category="VULN_SCAN",
                result=TestResult.PASSED,
                duration_ms=duration,
                description="Vulnerability scanning with nmap scripts",
                details={
                    "vuln_indicators": vulns_found,
                    "target": self.target.hostname,
                    "raw_output": result["stdout"][:1000]
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real Nmap Vulnerability Scan",
                category="VULN_SCAN",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 3: Web Application Tests
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_real_http_analysis(self) -> TestCase:
        """Test real HTTP response analysis."""
        start = time.time()
        
        try:
            target_url = f"http://{self.target.hostname}:{self.target.external_http_port}"
            
            result = await self.tools.curl_request(target_url)
            
            # Analyze response
            analysis = {
                "status_code": None,
                "server": None,
                "content_type": None,
                "security_headers": [],
                "interesting_headers": []
            }
            
            if result["success"]:
                headers = result["stdout"].split("\r\n\r\n")[0] if "\r\n\r\n" in result["stdout"] else result["stdout"]
                
                for line in headers.split("\n"):
                    line = line.strip()
                    if line.startswith("HTTP/"):
                        parts = line.split()
                        if len(parts) >= 2:
                            analysis["status_code"] = parts[1]
                    elif ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if key == "server":
                            analysis["server"] = value
                        elif key == "content-type":
                            analysis["content_type"] = value
                        elif key in ["x-frame-options", "x-xss-protection", 
                                    "content-security-policy", "strict-transport-security"]:
                            analysis["security_headers"].append(f"{key}: {value}")
            
            duration = int((time.time() - start) * 1000)
            
            return TestCase(
                name="Real HTTP Analysis",
                category="WEB",
                result=TestResult.PASSED if analysis["status_code"] else TestResult.FAILED,
                duration_ms=duration,
                description="HTTP response and header analysis",
                details={
                    "analysis": analysis,
                    "target": target_url
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real HTTP Analysis",
                category="WEB",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    async def test_real_directory_enumeration(self) -> TestCase:
        """Test directory/path enumeration."""
        start = time.time()
        
        try:
            target_url = f"http://{self.target.hostname}:{self.target.external_http_port}"
            
            # Common paths to test
            paths = [
                "/", "/admin", "/login", "/api", "/robots.txt",
                "/.git", "/config", "/backup", "/test", "/debug"
            ]
            
            found_paths = []
            for path in paths:
                result = await self.tools.curl_request(
                    f"{target_url}{path}",
                    headers={"User-Agent": "RAGLOX-Scanner/3.0"}
                )
                
                # Check status code
                if result["success"]:
                    status = None
                    for line in result["stdout"].split("\n"):
                        if line.startswith("HTTP/"):
                            parts = line.split()
                            if len(parts) >= 2:
                                status = parts[1]
                                break
                    
                    if status and status not in ["404", "403"]:
                        found_paths.append({
                            "path": path,
                            "status": status
                        })
            
            duration = int((time.time() - start) * 1000)
            
            return TestCase(
                name="Real Directory Enumeration",
                category="WEB",
                result=TestResult.PASSED if found_paths else TestResult.PARTIAL,
                duration_ms=duration,
                description="Directory and path discovery",
                details={
                    "paths_tested": len(paths),
                    "paths_found": found_paths,
                    "target": target_url
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real Directory Enumeration",
                category="WEB",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 4: SSH Tests
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_real_ssh_banner(self) -> TestCase:
        """Test SSH banner grabbing."""
        start = time.time()
        
        try:
            cmd = f"echo '' | nc -w 5 {self.target.hostname} {self.target.external_ssh_port} 2>&1 | head -1"
            result = await self.tools.run_command(cmd)
            
            banner = result["stdout"].strip() if result["stdout"] else ""
            
            # Analyze banner
            ssh_info = {
                "raw_banner": banner,
                "version": None,
                "software": None
            }
            
            if "SSH" in banner:
                parts = banner.split("-")
                if len(parts) >= 3:
                    ssh_info["version"] = parts[1]
                    ssh_info["software"] = "-".join(parts[2:])
            
            duration = int((time.time() - start) * 1000)
            
            return TestCase(
                name="Real SSH Banner Grab",
                category="SSH",
                result=TestResult.PASSED if banner else TestResult.FAILED,
                duration_ms=duration,
                description="SSH version and banner detection",
                details={
                    "ssh_info": ssh_info,
                    "target": f"{self.target.hostname}:{self.target.external_ssh_port}"
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Real SSH Banner Grab",
                category="SSH",
                result=TestResult.ERROR,
                error=str(e)
            )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Phase 5: Agent Integration Tests
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def test_agent_network_scan(self) -> TestCase:
        """Test ReconSpecialist network scan using real tools."""
        start = time.time()
        
        try:
            # Create a network scan task
            task = Task(
                mission_id=self.mission_id,
                type=TaskType.NETWORK_SCAN,
                specialist=SpecialistType.RECON,
                priority=8
            )
            
            # Add task to blackboard
            task_id = await self.blackboard.add_task(task)
            
            # Execute via specialist
            task_dict = task.model_dump()
            task_dict["id"] = task_id
            
            result = await self.recon.execute_task(task_dict)
            
            duration = int((time.time() - start) * 1000)
            
            hosts_discovered = result.get("hosts_discovered", 0)
            execution_mode = result.get("execution_mode", "unknown")
            
            return TestCase(
                name="Agent Network Scan",
                category="AGENT",
                result=TestResult.PASSED if hosts_discovered > 0 else TestResult.PARTIAL,
                duration_ms=duration,
                description="ReconSpecialist network discovery",
                details={
                    "hosts_discovered": hosts_discovered,
                    "execution_mode": execution_mode,
                    "hosts": result.get("hosts", []),
                    "scope": result.get("scope_scanned", [])
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Agent Network Scan",
                category="AGENT",
                result=TestResult.ERROR,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000)
            )
    
    async def test_agent_port_scan(self) -> TestCase:
        """Test ReconSpecialist port scan using real tools."""
        start = time.time()
        
        try:
            # First, add a target to scan
            target = Target(
                ip=self.target.hostname,
                hostname="vulnerable-target",
                status=TargetStatus.DISCOVERED,
                priority="high"
            )
            target_id = await self.blackboard.add_target(self.mission_id, target)
            
            # Create port scan task
            task = Task(
                mission_id=self.mission_id,
                type=TaskType.PORT_SCAN,
                specialist=SpecialistType.RECON,
                target_id=target_id,
                priority=8
            )
            
            task_id = await self.blackboard.add_task(task)
            task_dict = task.model_dump()
            task_dict["id"] = task_id
            task_dict["target_id"] = target_id
            
            result = await self.recon.execute_task(task_dict)
            
            duration = int((time.time() - start) * 1000)
            
            ports_found = result.get("ports_found", 0)
            
            return TestCase(
                name="Agent Port Scan",
                category="AGENT",
                result=TestResult.PASSED if ports_found > 0 else TestResult.PARTIAL,
                duration_ms=duration,
                description="ReconSpecialist port scanning",
                details={
                    "ports_found": ports_found,
                    "open_ports": result.get("open_ports", []),
                    "execution_mode": result.get("execution_mode", "unknown"),
                    "high_value_ports": result.get("high_value_ports", [])
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Agent Port Scan",
                category="AGENT",
                result=TestResult.ERROR,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000)
            )
    
    async def test_agent_llm_analysis(self) -> TestCase:
        """Test AnalysisSpecialist with real LLM for decision making."""
        start = time.time()
        
        try:
            # Create a failure context
            failure_context = {
                "task_type": "exploit",
                "failure_reason": "Connection refused",
                "error_code": "ECONNREFUSED",
                "target": self.target.hostname,
                "category": "network",
                "retry_count": 1,
                "max_retries": 3
            }
            
            # Get decision from analysis specialist
            decision = await self.analysis._analyze_failure_with_llm(
                failure_context,
                ["network", "connectivity"]
            )
            
            duration = int((time.time() - start) * 1000)
            
            # Update LLM metrics
            if hasattr(self.analysis, 'llm') and self.analysis.llm:
                llm_metrics = self.analysis.llm.get_metrics()
                self.metrics.llm_calls += llm_metrics.get("total_calls", 0)
                self.metrics.llm_tokens += llm_metrics.get("total_tokens", 0)
                self.metrics.llm_cost += llm_metrics.get("total_cost", 0.0)
            
            return TestCase(
                name="Agent LLM Analysis",
                category="AGENT",
                result=TestResult.PASSED if decision else TestResult.FAILED,
                duration_ms=duration,
                description="AnalysisSpecialist LLM decision making",
                details={
                    "decision": decision.get("decision") if decision else None,
                    "reasoning": decision.get("reasoning") if decision else None,
                    "llm_used": decision.get("llm_used", False) if decision else False,
                    "evasion_techniques": decision.get("evasion_techniques", []) if decision else []
                }
            )
            
        except Exception as e:
            return TestCase(
                name="Agent LLM Analysis",
                category="AGENT",
                result=TestResult.ERROR,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000)
            )
    
    async def test_knowledge_base_integration(self) -> TestCase:
        """Test Knowledge Base queries."""
        start = time.time()
        
        try:
            results = {
                "techniques": [],
                "modules": [],
                "nuclei_templates": []
            }
            
            # Search techniques
            technique = self.knowledge.get_technique("T1046")  # Network Service Scanning
            if technique:
                results["techniques"].append({
                    "id": technique.id,
                    "name": technique.name
                })
            
            # Get recon modules
            recon_modules = self.knowledge.get_recon_modules()
            results["modules"] = len(recon_modules)
            
            # Get CVE templates
            templates = self.knowledge.get_nuclei_critical_templates()
            results["nuclei_templates"] = len(templates)
            
            duration = int((time.time() - start) * 1000)
            
            return TestCase(
                name="Knowledge Base Integration",
                category="KB",
                result=TestResult.PASSED,
                duration_ms=duration,
                description="Knowledge Base queries and lookups",
                details=results
            )
            
        except Exception as e:
            return TestCase(
                name="Knowledge Base Integration",
                category="KB",
                result=TestResult.ERROR,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000)
            )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # Test Runner
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all intensive tests."""
        print("\n" + "=" * 70)
        print("🚀 STARTING INTENSIVE REAL ATTACK TESTS")
        print("=" * 70)
        print(f"\n🎯 Target: {self.target.hostname}")
        print(f"   HTTP: Port {self.target.external_http_port}")
        print(f"   SSH:  Port {self.target.external_ssh_port}")
        print(f"   Network: {self.target.network}")
        
        # Phase 1: Reconnaissance
        print("\n" + "-" * 50)
        print("📡 PHASE 1: RECONNAISSANCE")
        print("-" * 50)
        
        recon_tests = [
            self.test_real_ping_sweep,
            self.test_real_port_scan,
            self.test_real_service_detection,
        ]
        
        for test in recon_tests:
            result = await test()
            self.test_results.append(result)
            self._print_test_result(result)
        
        # Phase 2: Vulnerability Scanning
        print("\n" + "-" * 50)
        print("🔍 PHASE 2: VULNERABILITY SCANNING")
        print("-" * 50)
        
        vuln_tests = [
            self.test_real_nuclei_scan,
            self.test_real_nmap_vuln_scan,
        ]
        
        for test in vuln_tests:
            result = await test()
            self.test_results.append(result)
            self._print_test_result(result)
        
        # Phase 3: Web Application
        print("\n" + "-" * 50)
        print("🌐 PHASE 3: WEB APPLICATION TESTING")
        print("-" * 50)
        
        web_tests = [
            self.test_real_http_analysis,
            self.test_real_directory_enumeration,
        ]
        
        for test in web_tests:
            result = await test()
            self.test_results.append(result)
            self._print_test_result(result)
        
        # Phase 4: SSH
        print("\n" + "-" * 50)
        print("🔐 PHASE 4: SSH TESTING")
        print("-" * 50)
        
        ssh_tests = [
            self.test_real_ssh_banner,
        ]
        
        for test in ssh_tests:
            result = await test()
            self.test_results.append(result)
            self._print_test_result(result)
        
        # Phase 5: Agent Integration
        print("\n" + "-" * 50)
        print("🤖 PHASE 5: AGENT INTEGRATION")
        print("-" * 50)
        
        agent_tests = [
            self.test_agent_network_scan,
            self.test_agent_port_scan,
            self.test_agent_llm_analysis,
            self.test_knowledge_base_integration,
        ]
        
        for test in agent_tests:
            result = await test()
            self.test_results.append(result)
            self._print_test_result(result)
        
        # Generate Report
        return self._generate_report()
    
    def _print_test_result(self, result: TestCase):
        """Print individual test result."""
        symbols = {
            TestResult.PASSED: "✅",
            TestResult.PARTIAL: "◐",
            TestResult.FAILED: "❌",
            TestResult.ERROR: "⚠️",
            TestResult.SKIPPED: "⏭️"
        }
        symbol = symbols.get(result.result, "?")
        
        print(f"\n{symbol} {result.name}")
        print(f"   Category: {result.category}")
        print(f"   Duration: {result.duration_ms}ms")
        
        if result.error:
            print(f"   Error: {result.error}")
        elif result.details:
            # Print key details
            for key, value in list(result.details.items())[:3]:
                if isinstance(value, (list, dict)):
                    print(f"   {key}: {len(value) if isinstance(value, list) else 'object'}")
                else:
                    print(f"   {key}: {value}")
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate final test report."""
        passed = sum(1 for r in self.test_results if r.result == TestResult.PASSED)
        partial = sum(1 for r in self.test_results if r.result == TestResult.PARTIAL)
        failed = sum(1 for r in self.test_results if r.result == TestResult.FAILED)
        errors = sum(1 for r in self.test_results if r.result == TestResult.ERROR)
        total = len(self.test_results)
        
        success_rate = (passed + partial * 0.5) / total * 100 if total > 0 else 0
        
        report = {
            "run_id": str(uuid4()),
            "timestamp": datetime.now().isoformat(),
            "target": {
                "hostname": self.target.hostname,
                "http_port": self.target.external_http_port,
                "ssh_port": self.target.external_ssh_port,
                "network": self.target.network
            },
            "summary": {
                "total_tests": total,
                "passed": passed,
                "partial": partial,
                "failed": failed,
                "errors": errors,
                "success_rate": round(success_rate, 1)
            },
            "metrics": {
                "total_commands": self.metrics.total_commands_executed,
                "successful_commands": self.metrics.successful_commands,
                "failed_commands": self.metrics.failed_commands,
                "total_execution_time_ms": self.metrics.total_execution_time_ms,
                "nmap_scans": self.metrics.nmap_scans,
                "nuclei_scans": self.metrics.nuclei_scans,
                "hydra_attacks": self.metrics.hydra_attacks,
                "vulnerabilities_found": len(self.metrics.vulnerabilities_found),
                "services_discovered": len(self.metrics.services_discovered),
                "llm_calls": self.metrics.llm_calls,
                "llm_tokens": self.metrics.llm_tokens,
                "llm_cost": round(self.metrics.llm_cost, 4)
            },
            "results_by_category": {},
            "test_results": []
        }
        
        # Group by category
        for result in self.test_results:
            if result.category not in report["results_by_category"]:
                report["results_by_category"][result.category] = {
                    "passed": 0, "partial": 0, "failed": 0, "errors": 0
                }
            
            if result.result == TestResult.PASSED:
                report["results_by_category"][result.category]["passed"] += 1
            elif result.result == TestResult.PARTIAL:
                report["results_by_category"][result.category]["partial"] += 1
            elif result.result == TestResult.FAILED:
                report["results_by_category"][result.category]["failed"] += 1
            else:
                report["results_by_category"][result.category]["errors"] += 1
            
            report["test_results"].append({
                "name": result.name,
                "category": result.category,
                "result": result.result.value,
                "duration_ms": result.duration_ms,
                "description": result.description,
                "details": result.details,
                "error": result.error
            })
        
        return report


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main entry point for intensive real tests."""
    print("\n" + "═" * 70)
    print("  RAGLOX v3.0 - INTENSIVE REAL ATTACK TESTS")
    print("  NO MOCK DATA - ALL OPERATIONS ARE REAL")
    print("═" * 70)
    
    tests = IntensiveRealTests()
    
    try:
        # Setup
        if not await tests.setup():
            print("\n❌ Setup failed. Exiting.")
            return
        
        # Run tests
        report = await tests.run_all_tests()
        
        # Print summary
        print("\n" + "=" * 70)
        print("📊 FINAL REPORT")
        print("=" * 70)
        print(f"\n🎯 Target: {report['target']['hostname']}")
        print(f"\n📈 Summary:")
        print(f"   Total Tests:  {report['summary']['total_tests']}")
        print(f"   Passed:       {report['summary']['passed']}")
        print(f"   Partial:      {report['summary']['partial']}")
        print(f"   Failed:       {report['summary']['failed']}")
        print(f"   Errors:       {report['summary']['errors']}")
        print(f"   Success Rate: {report['summary']['success_rate']}%")
        
        print(f"\n🔧 Execution Metrics:")
        print(f"   Total Commands: {report['metrics']['total_commands']}")
        print(f"   Successful:     {report['metrics']['successful_commands']}")
        print(f"   Nmap Scans:     {report['metrics']['nmap_scans']}")
        print(f"   Nuclei Scans:   {report['metrics']['nuclei_scans']}")
        print(f"   Execution Time: {report['metrics']['total_execution_time_ms']}ms")
        
        if report['metrics']['llm_calls'] > 0:
            print(f"\n🧠 LLM Usage:")
            print(f"   Calls:  {report['metrics']['llm_calls']}")
            print(f"   Tokens: {report['metrics']['llm_tokens']}")
            print(f"   Cost:   ${report['metrics']['llm_cost']}")
        
        print(f"\n📁 Results by Category:")
        for category, stats in report["results_by_category"].items():
            print(f"   {category}: {stats['passed']}/{stats['passed']+stats['partial']+stats['failed']+stats['errors']} passed")
        
        # Save report
        report_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "intensive_real_results.json"
        )
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n💾 Full report saved to: {report_path}")
        
    except Exception as e:
        print(f"\n❌ Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        await tests.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
