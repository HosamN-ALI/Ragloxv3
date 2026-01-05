#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Quick Real Tools Test
═══════════════════════════════════════════════════════════════════════════════

Quick test to verify security tools work against the vulnerable target.
NO BLACKBOARD - Direct tool execution only.

Target: raglox-vulnerable-target
- HTTP: localhost:8088 → 172.28.0.100:80
- SSH:  localhost:2222 → 172.28.0.100:22

Tools Tested:
- nmap (network/port scanning)
- nuclei (vulnerability scanning)
- netcat (port probing)
- curl (HTTP requests)

Usage:
    PYTHONPATH=/root/RAGLOX_V3/webapp python3 webapp/tests/quick_real_tools_test.py
"""

import asyncio
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TargetConfig:
    """Vulnerable target configuration."""
    hostname: str = "localhost"
    http_port: int = 8088
    ssh_port: int = 2222
    internal_ip: str = "172.28.0.100"
    network: str = "172.28.0.0/24"


@dataclass
class TestResult:
    """Individual test result."""
    name: str
    status: str  # PASSED, FAILED, ERROR
    duration_ms: int
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Tool Executor
# ═══════════════════════════════════════════════════════════════════════════════

class ToolExecutor:
    """Execute security tools directly."""
    
    @staticmethod
    async def run_command(cmd: str, timeout: int = 30) -> Dict[str, Any]:
        """Run a shell command and return result."""
        start = time.time()
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout
                )
                
                return {
                    "success": proc.returncode == 0,
                    "stdout": stdout.decode('utf-8', errors='ignore'),
                    "stderr": stderr.decode('utf-8', errors='ignore'),
                    "exit_code": proc.returncode,
                    "duration_ms": int((time.time() - start) * 1000)
                }
                
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Timeout after {timeout}s",
                    "exit_code": -1,
                    "duration_ms": timeout * 1000
                }
                
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "duration_ms": int((time.time() - start) * 1000)
            }


# ═══════════════════════════════════════════════════════════════════════════════
# Test Suite
# ═══════════════════════════════════════════════════════════════════════════════

class QuickRealToolsTest:
    """Quick tests for real security tools."""
    
    def __init__(self):
        self.target = TargetConfig()
        self.executor = ToolExecutor()
        self.results: List[TestResult] = []
    
    async def test_nmap_ping_sweep(self) -> TestResult:
        """Test nmap host discovery."""
        print("\n🔍 Test: Nmap Host Discovery")
        start = time.time()
        
        try:
            # Ping sweep on network
            cmd = f"nmap -sn {self.target.network} -oG - 2>/dev/null"
            result = await self.executor.run_command(cmd, timeout=60)
            
            # Count discovered hosts
            hosts_found = 0
            if result["success"]:
                for line in result["stdout"].split("\n"):
                    if "Up" in line or "Status: Up" in line:
                        hosts_found += 1
            
            duration = int((time.time() - start) * 1000)
            status = "PASSED" if hosts_found > 0 else "FAILED"
            
            print(f"   Result: {status}")
            print(f"   Hosts Found: {hosts_found}")
            print(f"   Duration: {duration}ms")
            
            return TestResult(
                name="Nmap Ping Sweep",
                status=status,
                duration_ms=duration,
                details={
                    "hosts_found": hosts_found,
                    "network": self.target.network
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Nmap Ping Sweep",
                status="ERROR",
                duration_ms=int((time.time() - start) * 1000),
                error=str(e)
            )
    
    async def test_nmap_port_scan(self) -> TestResult:
        """Test nmap port scanning."""
        print("\n🔍 Test: Nmap Port Scan")
        start = time.time()
        
        try:
            # Scan specific ports
            cmd = f"nmap -p {self.target.http_port},{self.target.ssh_port} {self.target.hostname} -oN - 2>/dev/null"
            result = await self.executor.run_command(cmd, timeout=30)
            
            # Parse open ports
            open_ports = []
            if result["success"]:
                for line in result["stdout"].split("\n"):
                    if "/tcp" in line and "open" in line:
                        port = line.split("/")[0].strip()
                        if port.isdigit():
                            open_ports.append(int(port))
            
            duration = int((time.time() - start) * 1000)
            status = "PASSED" if len(open_ports) >= 2 else "FAILED"
            
            print(f"   Result: {status}")
            print(f"   Open Ports: {open_ports}")
            print(f"   Duration: {duration}ms")
            
            return TestResult(
                name="Nmap Port Scan",
                status=status,
                duration_ms=duration,
                details={
                    "open_ports": open_ports,
                    "target": self.target.hostname
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Nmap Port Scan",
                status="ERROR",
                duration_ms=int((time.time() - start) * 1000),
                error=str(e)
            )
    
    async def test_nmap_service_detection(self) -> TestResult:
        """Test nmap service/version detection."""
        print("\n🔍 Test: Nmap Service Detection")
        start = time.time()
        
        try:
            # Service detection on known open ports
            cmd = f"nmap -sV -p {self.target.http_port},{self.target.ssh_port} {self.target.hostname} -oN - 2>/dev/null"
            result = await self.executor.run_command(cmd, timeout=60)
            
            # Parse services
            services = []
            if result["success"]:
                for line in result["stdout"].split("\n"):
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
            status = "PASSED" if len(services) > 0 else "FAILED"
            
            print(f"   Result: {status}")
            print(f"   Services Found: {len(services)}")
            for svc in services:
                print(f"      - Port {svc['port']}: {svc['service']} {svc['version']}")
            print(f"   Duration: {duration}ms")
            
            return TestResult(
                name="Nmap Service Detection",
                status=status,
                duration_ms=duration,
                details={"services": services}
            )
            
        except Exception as e:
            return TestResult(
                name="Nmap Service Detection",
                status="ERROR",
                duration_ms=int((time.time() - start) * 1000),
                error=str(e)
            )
    
    async def test_nuclei_scan(self) -> TestResult:
        """Test Nuclei vulnerability scanner."""
        print("\n🔍 Test: Nuclei Vulnerability Scan")
        start = time.time()
        
        try:
            target_url = f"http://{self.target.hostname}:{self.target.http_port}"
            
            # Run nuclei with high severity templates
            cmd = f"nuclei -u {target_url} -silent -j -severity high,critical -timeout 5 2>/dev/null"
            result = await self.executor.run_command(cmd, timeout=120)
            
            # Parse results
            vulns = []
            if result["stdout"]:
                for line in result["stdout"].strip().split("\n"):
                    if line.strip():
                        try:
                            vuln_data = json.loads(line)
                            vulns.append({
                                "template": vuln_data.get("template-id", "unknown"),
                                "name": vuln_data.get("info", {}).get("name", ""),
                                "severity": vuln_data.get("info", {}).get("severity", ""),
                            })
                        except:
                            pass
            
            duration = int((time.time() - start) * 1000)
            status = "PASSED"  # Even 0 vulns is valid
            
            print(f"   Result: {status}")
            print(f"   Vulnerabilities Found: {len(vulns)}")
            for v in vulns[:5]:
                print(f"      - {v['template']}: {v['name']} ({v['severity']})")
            print(f"   Duration: {duration}ms")
            
            return TestResult(
                name="Nuclei Vulnerability Scan",
                status=status,
                duration_ms=duration,
                details={
                    "vulnerabilities": len(vulns),
                    "vulns": vulns[:10]
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Nuclei Vulnerability Scan",
                status="ERROR",
                duration_ms=int((time.time() - start) * 1000),
                error=str(e)
            )
    
    async def test_netcat_probe(self) -> TestResult:
        """Test netcat port probing."""
        print("\n🔍 Test: Netcat Port Probe")
        start = time.time()
        
        try:
            # Test HTTP port
            cmd = f"nc -zv -w 5 {self.target.hostname} {self.target.http_port} 2>&1"
            result = await self.executor.run_command(cmd, timeout=10)
            
            http_open = "open" in result["stdout"].lower() or "succeeded" in result["stdout"].lower()
            
            # Test SSH port
            cmd = f"nc -zv -w 5 {self.target.hostname} {self.target.ssh_port} 2>&1"
            result2 = await self.executor.run_command(cmd, timeout=10)
            
            ssh_open = "open" in result2["stdout"].lower() or "succeeded" in result2["stdout"].lower()
            
            duration = int((time.time() - start) * 1000)
            status = "PASSED" if (http_open and ssh_open) else "FAILED"
            
            print(f"   Result: {status}")
            print(f"   HTTP Port {self.target.http_port}: {'Open' if http_open else 'Closed'}")
            print(f"   SSH Port {self.target.ssh_port}: {'Open' if ssh_open else 'Closed'}")
            print(f"   Duration: {duration}ms")
            
            return TestResult(
                name="Netcat Port Probe",
                status=status,
                duration_ms=duration,
                details={
                    "http_open": http_open,
                    "ssh_open": ssh_open
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Netcat Port Probe",
                status="ERROR",
                duration_ms=int((time.time() - start) * 1000),
                error=str(e)
            )
    
    async def test_curl_http(self) -> TestResult:
        """Test HTTP requests with curl."""
        print("\n🔍 Test: Curl HTTP Request")
        start = time.time()
        
        try:
            target_url = f"http://{self.target.hostname}:{self.target.http_port}"
            cmd = f"curl -s -i -m 10 {target_url} 2>&1"
            result = await self.executor.run_command(cmd, timeout=15)
            
            # Parse HTTP response
            status_code = None
            server = None
            
            if result["success"]:
                for line in result["stdout"].split("\n"):
                    if line.startswith("HTTP/"):
                        parts = line.split()
                        if len(parts) >= 2:
                            status_code = parts[1]
                    elif line.lower().startswith("server:"):
                        server = line.split(":", 1)[1].strip()
            
            duration = int((time.time() - start) * 1000)
            status = "PASSED" if status_code else "FAILED"
            
            print(f"   Result: {status}")
            print(f"   Status Code: {status_code or 'N/A'}")
            print(f"   Server: {server or 'Unknown'}")
            print(f"   Duration: {duration}ms")
            
            return TestResult(
                name="Curl HTTP Request",
                status=status,
                duration_ms=duration,
                details={
                    "status_code": status_code,
                    "server": server,
                    "url": target_url
                }
            )
            
        except Exception as e:
            return TestResult(
                name="Curl HTTP Request",
                status="ERROR",
                duration_ms=int((time.time() - start) * 1000),
                error=str(e)
            )
    
    async def run_all_tests(self):
        """Run all quick tests."""
        print("\n" + "=" * 70)
        print("🚀 RAGLOX v3.0 - Quick Real Tools Test")
        print("=" * 70)
        print(f"\nTarget: {self.target.hostname}")
        print(f"HTTP Port: {self.target.http_port}")
        print(f"SSH Port: {self.target.ssh_port}")
        print(f"Network: {self.target.network}")
        
        # Run tests
        tests = [
            self.test_nmap_ping_sweep,
            self.test_nmap_port_scan,
            self.test_nmap_service_detection,
            self.test_netcat_probe,
            self.test_curl_http,
            self.test_nuclei_scan,
        ]
        
        for test_func in tests:
            result = await test_func()
            self.results.append(result)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary."""
        print("\n" + "=" * 70)
        print("📊 TEST SUMMARY")
        print("=" * 70)
        
        passed = sum(1 for r in self.results if r.status == "PASSED")
        failed = sum(1 for r in self.results if r.status == "FAILED")
        errors = sum(1 for r in self.results if r.status == "ERROR")
        total = len(self.results)
        
        print(f"\nTotal Tests: {total}")
        print(f"✅ Passed:  {passed}")
        print(f"❌ Failed:  {failed}")
        print(f"⚠️  Errors:  {errors}")
        print(f"\nSuccess Rate: {passed / max(total, 1) * 100:.1f}%")
        
        # Detailed results
        print("\n" + "-" * 70)
        print("DETAILED RESULTS")
        print("-" * 70)
        
        for r in self.results:
            icon = "✅" if r.status == "PASSED" else "❌" if r.status == "FAILED" else "⚠️"
            print(f"\n{icon} {r.name}: {r.status} ({r.duration_ms}ms)")
            if r.error:
                print(f"   Error: {r.error}")
            else:
                for key, value in list(r.details.items())[:3]:
                    print(f"   {key}: {value}")
        
        # Save results
        report = {
            "timestamp": datetime.now().isoformat(),
            "target": {
                "hostname": self.target.hostname,
                "http_port": self.target.http_port,
                "ssh_port": self.target.ssh_port
            },
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "errors": errors,
                "success_rate": round(passed / max(total, 1) * 100, 1)
            },
            "results": [
                {
                    "name": r.name,
                    "status": r.status,
                    "duration_ms": r.duration_ms,
                    "details": r.details,
                    "error": r.error
                }
                for r in self.results
            ]
        }
        
        report_path = "tests/quick_tools_results.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Report saved: {report_path}")
        print("\n" + "=" * 70)


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Run quick real tools test."""
    test = QuickRealToolsTest()
    
    try:
        await test.run_all_tests()
    except KeyboardInterrupt:
        print("\n\n⚠️ Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
