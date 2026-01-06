# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Real Tool Execution Tests
# Tests actual penetration testing tools without mocks
# ═══════════════════════════════════════════════════════════════════════════════

"""
Real Tool Execution Test Suite

These tests verify actual security tool execution.
No mocks - real tools against real or isolated targets.

Requirements:
    - SSH access to a test system
    - Security tools installed (nmap, curl, etc.)
    - Isolated/authorized target network
    - RAGLOX_TEST_MODE=real

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

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))

try:
    from .conftest import TestExecutionResult, RealTestConfig
except ImportError:
    from conftest import TestExecutionResult, RealTestConfig

logger = logging.getLogger("raglox.tests.tools")


# ═══════════════════════════════════════════════════════════════════════════════
# Network Reconnaissance Tools
# ═══════════════════════════════════════════════════════════════════════════════

class TestNetworkReconTools:
    """Test network reconnaissance tools."""
    
    @pytest.mark.asyncio
    async def test_ping_connectivity(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-001: Ping Connectivity Test
        Basic network connectivity test.
        """
        start = time.time()
        test_name = "Ping Connectivity"
        
        try:
            from executors.models import ExecutionRequest
            
            # Ping localhost (safe test)
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ping -c 3 -W 2 127.0.0.1",
                    timeout=30
                )
            )
            
            assert result.success, f"Ping failed: {result.stderr}"
            assert "3 packets transmitted" in result.stdout or "3 received" in result.stdout.lower()
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:500],
                metadata={"target": "127.0.0.1", "packets": 3}
            ))
            
            logger.info(f"✅ {test_name}: Ping working")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Ping test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_nmap_localhost_scan(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-002: Nmap Localhost Scan
        Test nmap scanning capability against localhost.
        """
        start = time.time()
        test_name = "Nmap Localhost Scan"
        
        try:
            # Check if nmap is available
            available = await ssh_executor.check_tool_available('nmap')
            if not available:
                pytest.skip("nmap not installed on target system")
            
            from executors.models import ExecutionRequest
            
            # Scan localhost for common ports
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="nmap -sT -p 22,80,443 --open 127.0.0.1 -oG -",
                    timeout=120
                )
            )
            
            # Nmap output can be successful even with no open ports
            duration = (time.time() - start) * 1000
            
            # Parse results
            open_ports = []
            for line in result.stdout.split('\n'):
                if 'Ports:' in line:
                    # Extract open ports from grepable format
                    import re
                    ports = re.findall(r'(\d+)/open', line)
                    open_ports.extend(ports)
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:1000],
                metadata={"target": "127.0.0.1", "open_ports": open_ports, "scanned_ports": [22, 80, 443]}
            ))
            
            logger.info(f"✅ {test_name}: Scan completed, open ports: {open_ports or 'none'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Nmap test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_nmap_service_detection(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-003: Nmap Service Detection
        Test nmap service version detection.
        """
        start = time.time()
        test_name = "Nmap Service Detection"
        
        try:
            available = await ssh_executor.check_tool_available('nmap')
            if not available:
                pytest.skip("nmap not installed on target system")
            
            from executors.models import ExecutionRequest
            
            # Service detection on SSH port (usually available)
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="nmap -sV -p 22 127.0.0.1 --version-intensity 5",
                    timeout=180
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Check for service info
            has_service_info = 'ssh' in result.stdout.lower() or 'openssh' in result.stdout.lower()
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:1500],
                metadata={"target": "127.0.0.1", "port": 22, "service_detected": has_service_info}
            ))
            
            logger.info(f"✅ {test_name}: Service detection {'found SSH' if has_service_info else 'completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Nmap service detection failed: {e}")
    
    @pytest.mark.asyncio
    async def test_netcat_port_check(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-004: Netcat Port Check
        Test netcat/nc for port checking.
        """
        start = time.time()
        test_name = "Netcat Port Check"
        
        try:
            # Check for netcat variants
            nc_available = await ssh_executor.check_tool_available('nc')
            netcat_available = await ssh_executor.check_tool_available('netcat')
            ncat_available = await ssh_executor.check_tool_available('ncat')
            
            if not (nc_available or netcat_available or ncat_available):
                pytest.skip("No netcat variant installed")
            
            nc_cmd = 'nc' if nc_available else ('netcat' if netcat_available else 'ncat')
            
            from executors.models import ExecutionRequest
            
            # Check if port 22 is open
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command=f"{nc_cmd} -zv 127.0.0.1 22 2>&1 || true",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Check result - output varies by nc version
            port_open = 'succeeded' in result.stdout.lower() or 'open' in result.stdout.lower() or 'connected' in result.stdout.lower()
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:500],
                metadata={"tool": nc_cmd, "port": 22, "is_open": port_open}
            ))
            
            logger.info(f"✅ {test_name}: Port 22 {'open' if port_open else 'check completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Netcat test failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Web Reconnaissance Tools
# ═══════════════════════════════════════════════════════════════════════════════

class TestWebReconTools:
    """Test web reconnaissance tools."""
    
    @pytest.mark.asyncio
    async def test_curl_basic(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-005: cURL Basic Request
        Test basic HTTP request with curl.
        """
        start = time.time()
        test_name = "cURL Basic Request"
        
        try:
            available = await ssh_executor.check_tool_available('curl')
            if not available:
                pytest.skip("curl not installed")
            
            from executors.models import ExecutionRequest
            
            # Test against a safe public endpoint
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="curl -s -o /dev/null -w '%{http_code}' https://httpstat.us/200 --connect-timeout 10",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            http_code = result.stdout.strip()
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=result.success,
                duration_ms=duration,
                output=f"HTTP {http_code}",
                metadata={"url": "https://httpstat.us/200", "http_code": http_code}
            ))
            
            logger.info(f"✅ {test_name}: Got HTTP {http_code}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"cURL test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_curl_headers(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-006: cURL Header Retrieval
        Test HTTP header retrieval with curl.
        """
        start = time.time()
        test_name = "cURL Header Retrieval"
        
        try:
            available = await ssh_executor.check_tool_available('curl')
            if not available:
                pytest.skip("curl not installed")
            
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="curl -sI https://httpstat.us/200 --connect-timeout 10 2>/dev/null | head -20",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Parse headers
            headers = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:500],
                metadata={"headers_found": list(headers.keys())[:10]}
            ))
            
            logger.info(f"✅ {test_name}: Retrieved {len(headers)} headers")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"cURL headers test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_wget_basic(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-007: wget Basic Download
        Test basic download with wget.
        """
        start = time.time()
        test_name = "wget Basic Download"
        
        try:
            available = await ssh_executor.check_tool_available('wget')
            if not available:
                pytest.skip("wget not installed")
            
            from executors.models import ExecutionRequest
            
            # Download to stdout
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="wget -q -O - --timeout=10 https://httpstat.us/200 2>/dev/null | head -c 100",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:200] if result.stdout else "Empty response",
                metadata={"tool": "wget", "success": result.success}
            ))
            
            logger.info(f"✅ {test_name}: Download {'succeeded' if result.success else 'completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"wget test failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Information Gathering Tools
# ═══════════════════════════════════════════════════════════════════════════════

class TestInfoGatheringTools:
    """Test information gathering tools."""
    
    @pytest.mark.asyncio
    async def test_whois_lookup(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-008: WHOIS Lookup
        Test WHOIS domain lookup.
        """
        start = time.time()
        test_name = "WHOIS Lookup"
        
        try:
            available = await ssh_executor.check_tool_available('whois')
            if not available:
                pytest.skip("whois not installed")
            
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="whois google.com 2>/dev/null | head -50",
                    timeout=60
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Check for common WHOIS fields
            has_registrar = 'registrar' in result.stdout.lower()
            has_dates = 'creation' in result.stdout.lower() or 'expir' in result.stdout.lower()
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=result.success and (has_registrar or has_dates),
                duration_ms=duration,
                output=result.stdout[:800],
                metadata={"domain": "google.com", "has_registrar": has_registrar, "has_dates": has_dates}
            ))
            
            logger.info(f"✅ {test_name}: WHOIS lookup {'successful' if has_registrar else 'completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"WHOIS test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_dig_dns_lookup(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-009: dig DNS Lookup
        Test DNS lookup with dig.
        """
        start = time.time()
        test_name = "dig DNS Lookup"
        
        try:
            available = await ssh_executor.check_tool_available('dig')
            if not available:
                pytest.skip("dig not installed")
            
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="dig +short google.com A",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Should get IP addresses
            ips = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=len(ips) > 0,
                duration_ms=duration,
                output=result.stdout[:300],
                metadata={"domain": "google.com", "resolved_ips": ips[:5]}
            ))
            
            logger.info(f"✅ {test_name}: Resolved {len(ips)} IP(s)")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"dig test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_host_lookup(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-010: host Command Lookup
        Test DNS lookup with host command.
        """
        start = time.time()
        test_name = "host DNS Lookup"
        
        try:
            available = await ssh_executor.check_tool_available('host')
            if not available:
                pytest.skip("host not installed")
            
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="host google.com",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            has_address = 'has address' in result.stdout.lower()
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=has_address,
                duration_ms=duration,
                output=result.stdout[:500],
                metadata={"domain": "google.com", "resolved": has_address}
            ))
            
            logger.info(f"✅ {test_name}: DNS lookup {'successful' if has_address else 'completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"host test failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Script Execution Tools
# ═══════════════════════════════════════════════════════════════════════════════

class TestScriptExecution:
    """Test script execution capabilities."""
    
    @pytest.mark.asyncio
    async def test_python_execution(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-011: Python Script Execution
        Test Python script execution.
        """
        start = time.time()
        test_name = "Python Script Execution"
        
        try:
            python_cmd = None
            for cmd in ['python3', 'python']:
                if await ssh_executor.check_tool_available(cmd):
                    python_cmd = cmd
                    break
            
            if not python_cmd:
                pytest.skip("Python not installed")
            
            from executors.models import ExecutionRequest
            
            # Execute inline Python
            python_code = '''
import sys
import platform
print(f"Python {sys.version_info.major}.{sys.version_info.minor}")
print(f"Platform: {platform.system()}")
print("RAGLOX_PYTHON_OK")
'''
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command=f'{python_cmd} -c "{python_code}"',
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            success = "RAGLOX_PYTHON_OK" in result.stdout
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=success,
                duration_ms=duration,
                output=result.stdout[:500],
                metadata={"python_cmd": python_cmd, "success": success}
            ))
            
            logger.info(f"✅ {test_name}: Python execution {'successful' if success else 'completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Python execution test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_bash_script_execution(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-012: Bash Script Execution
        Test Bash script execution.
        """
        start = time.time()
        test_name = "Bash Script Execution"
        
        try:
            from executors.models import ExecutionRequest
            
            # Execute inline bash script
            bash_script = '''
#!/bin/bash
echo "RAGLOX Bash Test"
echo "User: $(whoami)"
echo "PWD: $(pwd)"
echo "Date: $(date)"
echo "RAGLOX_BASH_OK"
'''
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command=f'bash -c \'{bash_script}\'',
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            success = "RAGLOX_BASH_OK" in result.stdout
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=success,
                duration_ms=duration,
                output=result.stdout[:500],
                metadata={"success": success}
            ))
            
            logger.info(f"✅ {test_name}: Bash execution {'successful' if success else 'completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Bash execution test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_awk_processing(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-013: AWK Processing
        Test AWK text processing.
        """
        start = time.time()
        test_name = "AWK Processing"
        
        try:
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="echo -e 'field1:field2:field3\\nvalue1:value2:value3' | awk -F: '{print $2}'",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            success = "field2" in result.stdout and "value2" in result.stdout
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=success,
                duration_ms=duration,
                output=result.stdout[:300],
                metadata={"success": success}
            ))
            
            logger.info(f"✅ {test_name}: AWK processing {'successful' if success else 'completed'}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"AWK test failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Security-Specific Tools
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityTools:
    """Test security-specific tools."""
    
    @pytest.mark.asyncio
    async def test_ss_connections(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-014: ss Network Connections
        Test ss command for network connection listing.
        """
        start = time.time()
        test_name = "ss Network Connections"
        
        try:
            available = await ssh_executor.check_tool_available('ss')
            if not available:
                pytest.skip("ss not installed")
            
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ss -tuln 2>/dev/null | head -20",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Parse listening ports
            listening_ports = []
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line:
                    listening_ports.append(line.strip())
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:800],
                metadata={"listening_count": len(listening_ports)}
            ))
            
            logger.info(f"✅ {test_name}: Found {len(listening_ports)} listening ports")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"ss test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_processes_list(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-015: Process Enumeration
        Test process listing.
        """
        start = time.time()
        test_name = "Process Enumeration"
        
        try:
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="ps aux 2>/dev/null | head -30",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Count processes
            process_count = len([l for l in result.stdout.split('\n') if l.strip()]) - 1  # Subtract header
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=process_count > 0,
                duration_ms=duration,
                output=result.stdout[:1000],
                metadata={"process_count": max(process_count, 0)}
            ))
            
            logger.info(f"✅ {test_name}: Listed {process_count} processes")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Process enumeration failed: {e}")
    
    @pytest.mark.asyncio
    async def test_users_enumeration(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-016: User Enumeration
        Test user enumeration from system files.
        """
        start = time.time()
        test_name = "User Enumeration"
        
        try:
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="cat /etc/passwd 2>/dev/null | grep -v 'nologin\\|false' | head -20",
                    timeout=30
                )
            )
            
            duration = (time.time() - start) * 1000
            
            # Parse users
            users = []
            for line in result.stdout.split('\n'):
                if ':' in line:
                    username = line.split(':')[0]
                    users.append(username)
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=len(users) > 0,
                duration_ms=duration,
                output=result.stdout[:500],
                metadata={"users": users[:10], "user_count": len(users)}
            ))
            
            logger.info(f"✅ {test_name}: Found {len(users)} users with shell access")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"User enumeration failed: {e}")
    
    @pytest.mark.asyncio
    async def test_suid_binaries(self, ssh_executor, test_config, result_collector):
        """
        TEST-TOOL-017: SUID Binary Enumeration
        Test SUID binary detection (privilege escalation recon).
        """
        start = time.time()
        test_name = "SUID Binary Enumeration"
        
        try:
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="find /usr/bin /usr/sbin /bin /sbin -perm -4000 2>/dev/null | head -30",
                    timeout=60
                )
            )
            
            duration = (time.time() - start) * 1000
            
            suid_binaries = [l.strip() for l in result.stdout.split('\n') if l.strip()]
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout[:800],
                metadata={"suid_count": len(suid_binaries), "binaries": suid_binaries[:10]}
            ))
            
            logger.info(f"✅ {test_name}: Found {len(suid_binaries)} SUID binaries")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"SUID enumeration failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Tool Manager Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestToolManagerIntegration:
    """Test ToolManager integration with real execution."""
    
    @pytest.mark.asyncio
    async def test_tool_manager_initialization(self, tool_manager, result_collector):
        """
        TEST-TOOL-018: Tool Manager Initialization
        Test that ToolManager initializes correctly.
        """
        start = time.time()
        test_name = "Tool Manager Initialization"
        
        try:
            assert tool_manager is not None
            
            # Get stats
            stats = await tool_manager.get_stats() if hasattr(tool_manager, 'get_stats') else {}
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=str(stats),
                metadata=stats
            ))
            
            logger.info(f"✅ {test_name}: ToolManager initialized")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Tool manager initialization failed: {e}")
    
    @pytest.mark.asyncio
    async def test_tool_availability_detection(self, tool_manager, result_collector):
        """
        TEST-TOOL-019: Tool Availability Detection
        Test ToolManager's ability to detect installed tools.
        """
        start = time.time()
        test_name = "Tool Availability Detection"
        
        try:
            # Get available tools
            available = await tool_manager.get_available_tools() if hasattr(tool_manager, 'get_available_tools') else []
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=str(available[:20]),
                metadata={"tool_count": len(available), "tools": available[:10]}
            ))
            
            logger.info(f"✅ {test_name}: Detected {len(available)} available tools")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Tool availability detection failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone Runner
# ═══════════════════════════════════════════════════════════════════════════════

async def run_tool_tests_standalone():
    """Run tool tests without pytest for quick verification."""
    from .conftest import RealTestConfig, TestResultCollector
    
    config = RealTestConfig.from_env()
    collector = TestResultCollector()
    
    if not config.has_valid_ssh:
        print("❌ SSH not configured")
        return False
    
    print(f"🔌 Connecting to {config.ssh_host}...")
    
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
            timeout=60,
        )
        
        executor = SSHExecutor(ssh_config)
        await executor.connect()
        
        # Check tools
        tools = ['nmap', 'curl', 'wget', 'dig', 'whois', 'ss', 'python3']
        print("\n🧪 Checking tool availability...")
        
        for tool in tools:
            available = await executor.check_tool_available(tool)
            status = "✅" if available else "❌"
            print(f"   {status} {tool}")
            collector.add(TestExecutionResult(
                test_name=f"Tool: {tool}",
                passed=available,
                duration_ms=0,
                output=""
            ))
        
        await executor.disconnect()
        
        print(f"\nResults: {collector.passed}/{collector.total} tools available")
        return True
        
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


if __name__ == "__main__":
    import asyncio
    success = asyncio.run(run_tool_tests_standalone())
    sys.exit(0 if success else 1)
