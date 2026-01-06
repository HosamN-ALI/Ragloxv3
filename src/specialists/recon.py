# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Recon Specialist
# Reconnaissance specialist for network and target discovery
# With Nuclei Integration and AI-Driven Scanning
# Enhanced with Intelligence Coordinator and Stealth Management
# ═══════════════════════════════════════════════════════════════

import asyncio
import ipaddress
import re
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID

from .base import BaseSpecialist
from ..core.models import (
    TaskType, SpecialistType, TargetStatus, Severity, Priority,
    Port, Service
)
from ..core.blackboard import Blackboard
from ..core.config import Settings
from ..core.knowledge import EmbeddedKnowledge, NucleiTemplate
from ..core.scanners import NucleiScanner, NucleiScanResult

# Hybrid Intelligence Layer imports
from ..core.intelligence_coordinator import (
    IntelligenceCoordinator,
    AttackPath,
    AttackPathType,
    StrategicAnalysis,
)
from ..core.stealth_profiles import (
    StealthManager,
    StealthLevel,
    DetectionRisk,
)

if TYPE_CHECKING:
    from ..executors import RXModuleRunner, ExecutorFactory

# Pre-compiled regex for parsing JSON from LLM responses
_JSON_CODE_BLOCK_PATTERN = re.compile(r'```(?:json)?\s*([\s\S]*?)\s*```')


class ReconSpecialist(BaseSpecialist):
    """
    Recon Specialist - Handles reconnaissance and discovery tasks.
    
    Responsibilities:
    - Network scanning (discovering hosts)
    - Port scanning (identifying open ports)
    - Service enumeration (identifying services)
    - OS fingerprinting
    - Vulnerability scanning (basic checks)
    
    Task Types Handled:
    - NETWORK_SCAN: Discover hosts in a network range
    - PORT_SCAN: Scan ports on discovered targets
    - SERVICE_ENUM: Enumerate services on open ports
    - VULN_SCAN: Basic vulnerability scanning
    
    Reads From Blackboard:
    - Mission scope (target ranges)
    - Existing targets
    - Task queue
    
    Writes To Blackboard:
    - New targets
    - Target ports
    - Target services
    - Basic vulnerabilities
    - Creates tasks for other specialists
    """
    
    def __init__(
        self,
        blackboard: Optional[Blackboard] = None,
        settings: Optional[Settings] = None,
        worker_id: Optional[str] = None,
        knowledge: Optional[EmbeddedKnowledge] = None,
        runner: Optional['RXModuleRunner'] = None,
        executor_factory: Optional['ExecutorFactory'] = None,
        intelligence_coordinator: Optional[IntelligenceCoordinator] = None,
        stealth_manager: Optional[StealthManager] = None,
        environment_manager: Optional[Any] = None,
    ):
        super().__init__(
            specialist_type=SpecialistType.RECON,
            blackboard=blackboard,
            settings=settings,
            worker_id=worker_id,
            knowledge=knowledge,
            runner=runner,
            executor_factory=executor_factory,
            environment_manager=environment_manager
        )
        
        # Task types this specialist handles
        self._supported_task_types = {
            TaskType.NETWORK_SCAN,
            TaskType.PORT_SCAN,
            TaskType.SERVICE_ENUM,
            TaskType.VULN_SCAN
        }
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Intelligence Coordinator & Stealth Manager
        # ═══════════════════════════════════════════════════════════
        self._intelligence_coordinator = intelligence_coordinator or IntelligenceCoordinator(
            blackboard=blackboard,
            knowledge_base=knowledge,
            logger=self.logger
        )
        self._stealth_manager = stealth_manager or StealthManager(
            blackboard=blackboard,
            default_level=StealthLevel.NORMAL,
            logger=self.logger
        )
        
        # ═══════════════════════════════════════════════════════════
        # Dynamic Port Profiles (replaces static _common_ports)
        # Ports are now prioritized based on strategic value
        # ═══════════════════════════════════════════════════════════
        self._port_profiles = {
            "high_value": {
                "ports": [88, 389, 636, 3268, 3269, 445, 135],  # Kerberos, LDAP, AD
                "description": "Domain services - highest strategic value",
                "priority": 10,
            },
            "admin_services": {
                "ports": [22, 3389, 5985, 5986],  # SSH, RDP, WinRM
                "description": "Administrative access ports",
                "priority": 9,
            },
            "databases": {
                "ports": [1433, 1521, 3306, 5432, 27017, 6379],
                "description": "Database services - data targets",
                "priority": 8,
            },
            "web_services": {
                "ports": [80, 443, 8080, 8443, 8000, 8888, 9443],
                "description": "Web services - attack surface",
                "priority": 7,
            },
            "standard_services": {
                "ports": [21, 23, 25, 53, 110, 143, 993, 995, 139, 111, 5900],
                "description": "Standard network services",
                "priority": 5,
            },
        }
        
        # Flattened common ports list (for backward compatibility)
        self._common_ports = self._get_prioritized_ports()
        
        # Service detection patterns (simplified for MVP)
        self._service_patterns = {
            21: ("ftp", "FTP"),
            22: ("ssh", "SSH"),
            23: ("telnet", "Telnet"),
            25: ("smtp", "SMTP"),
            53: ("dns", "DNS"),
            80: ("http", "HTTP"),
            110: ("pop3", "POP3"),
            135: ("msrpc", "MSRPC"),
            139: ("netbios-ssn", "NetBIOS"),
            143: ("imap", "IMAP"),
            443: ("https", "HTTPS"),
            445: ("microsoft-ds", "SMB"),
            993: ("imaps", "IMAPS"),
            995: ("pop3s", "POP3S"),
            1433: ("mssql", "MSSQL"),
            1521: ("oracle", "Oracle"),
            3306: ("mysql", "MySQL"),
            3389: ("rdp", "RDP"),
            5432: ("postgresql", "PostgreSQL"),
            5900: ("vnc", "VNC"),
            6379: ("redis", "Redis"),
            8080: ("http-proxy", "HTTP-Proxy"),
            8443: ("https-alt", "HTTPS-Alt")
        }
        
        # Known vulnerable services (simplified for MVP)
        self._vuln_checks = {
            "ssh": [("CVE-2018-15473", "SSH User Enumeration", Severity.MEDIUM)],
            "smb": [("MS17-010", "EternalBlue", Severity.CRITICAL)],
            "rdp": [("CVE-2019-0708", "BlueKeep", Severity.CRITICAL)],
            "http": [("CVE-2021-44228", "Log4Shell", Severity.CRITICAL)],
        }
        
        # Nuclei scanner instance (lazy-loaded)
        self._nuclei_scanner: Optional[NucleiScanner] = None
        
        # AI consultation settings (configurable via settings)
        self._ai_consultation_enabled = True
        # Threshold can be overridden via settings.nuclei_ai_consultation_threshold
        self._ai_consultation_threshold = getattr(
            self.settings, 'nuclei_ai_consultation_threshold', 10
        )  # Consult LLM if more than N subdomains
        
        # Port-to-technology fingerprints for intelligent template selection
        self._port_technology_map = {
            80: ["http", "apache", "nginx", "iis", "web"],
            443: ["https", "ssl", "tls", "web", "apache", "nginx"],
            8080: ["http-proxy", "tomcat", "jenkins", "web"],
            8443: ["https-alt", "tomcat", "web"],
            3000: ["nodejs", "express", "react"],
            5000: ["flask", "python", "api"],
            8000: ["django", "python", "uvicorn"],
            9000: ["php-fpm", "sonarqube"],
            4443: ["api", "web"],
            21: ["ftp"],
            22: ["ssh"],
            25: ["smtp", "mail"],
            3306: ["mysql", "mariadb"],
            5432: ["postgresql", "postgres"],
            6379: ["redis"],
            27017: ["mongodb"],
            # High-value AD/Domain ports
            88: ["kerberos", "ad", "domain"],
            389: ["ldap", "ad", "domain"],
            636: ["ldaps", "ad", "domain"],
            3268: ["gc", "globalcatalog", "ad"],
            3269: ["gcs", "globalcatalog-ssl", "ad"],
        }
        
        # Statistics
        self._stats = {
            "scans_performed": 0,
            "targets_discovered": 0,
            "vulns_found": 0,
            "intelligence_consultations": 0,
            "stealth_delays_applied": 0,
        }
        
        self.logger.info("ReconSpecialist initialized with Intelligence Coordinator integration")
    
    def _get_prioritized_ports(self) -> List[int]:
        """
        Get ports list prioritized by strategic value.
        High-value ports come first.
        """
        ports_with_priority = []
        for profile_name, profile in self._port_profiles.items():
            for port in profile["ports"]:
                ports_with_priority.append((port, profile["priority"]))
        
        # Sort by priority (descending) and deduplicate
        sorted_ports = sorted(ports_with_priority, key=lambda x: x[1], reverse=True)
        seen = set()
        unique_ports = []
        for port, _ in sorted_ports:
            if port not in seen:
                seen.add(port)
                unique_ports.append(port)
        
        return unique_ports
    
    @property
    def nuclei_scanner(self) -> NucleiScanner:
        """Get or initialize the Nuclei scanner instance."""
        if self._nuclei_scanner is None:
            self._nuclei_scanner = NucleiScanner()
        return self._nuclei_scanner
    
    # ═══════════════════════════════════════════════════════════
    # Task Execution
    # ═══════════════════════════════════════════════════════════
    
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a reconnaissance task."""
        task_type = task.get("type")
        
        handlers = {
            TaskType.NETWORK_SCAN.value: self._execute_network_scan,
            TaskType.PORT_SCAN.value: self._execute_port_scan,
            TaskType.SERVICE_ENUM.value: self._execute_service_enum,
            TaskType.VULN_SCAN.value: self._execute_vuln_scan,
        }
        
        handler = handlers.get(task_type)
        if not handler:
            raise ValueError(f"Unsupported task type: {task_type}")
        
        return await handler(task)
    
    async def _execute_network_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a network scan to discover hosts.
        
        Uses RXModuleRunner for real execution or falls back to simulation.
        """
        self.logger.info(f"Executing network scan for mission {self._current_mission_id}")
        
        # Get mission scope
        mission = await self.blackboard.get_mission(self._current_mission_id)
        if not mission:
            return {"error": "Mission not found", "hosts_discovered": 0}
        
        # Parse scope from mission
        scope = mission.get("scope", "[]")
        if isinstance(scope, str):
            import json
            scope = json.loads(scope)
        
        discovered_hosts = []
        execution_mode = "real" if self.is_real_execution_mode else "simulated"
        
        for cidr in scope:
            try:
                if self.is_real_execution_mode:
                    # Real execution using Runner
                    hosts = await self._real_host_discovery(cidr, task.get("id"))
                else:
                    # Simulated host discovery
                    hosts = await self._simulate_host_discovery(cidr)
                discovered_hosts.extend(hosts)
            except Exception as e:
                self.logger.error(f"Error scanning {cidr}: {e}")
        
        # Add discovered targets to Blackboard
        for host in discovered_hosts:
            await self.add_discovered_target(
                ip=host["ip"],
                hostname=host.get("hostname"),
                os=host.get("os"),
                priority=host.get("priority", "medium"),
                needs_deep_scan=True
            )
            
            # Create port scan task for each target
            target_ids = await self.blackboard.get_mission_targets(self._current_mission_id)
            if target_ids:
                # Get the most recent target (just added)
                latest_target_key = target_ids[-1] if target_ids else None
                if latest_target_key:
                    target_id = latest_target_key.replace("target:", "")
                    await self.create_task(
                        task_type=TaskType.PORT_SCAN,
                        target_specialist=SpecialistType.RECON,
                        priority=7,
                        target_id=target_id
                    )
        
        return {
            "hosts_discovered": len(discovered_hosts),
            "scope_scanned": scope,
            "hosts": [h["ip"] for h in discovered_hosts],
            "execution_mode": execution_mode
        }
    
    async def _real_host_discovery(self, cidr: str, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Real host discovery using ping sweep or nmap.
        
        Args:
            cidr: Network range to scan
            task_id: Task ID for logging
            
        Returns:
            List of discovered hosts
        """
        hosts = []
        
        try:
            # Try to use nmap ping sweep via direct command
            # This works on localhost for discovering local network hosts
            result = await self.execute_command_direct(
                command=f"nmap -sn {cidr} -oG - 2>/dev/null | grep 'Up' | awk '{{print $2}}'",
                target_host="localhost",
                target_platform="linux",
                timeout=120
            )
            
            if result["success"] and result["stdout"].strip():
                # Parse nmap output
                for line in result["stdout"].strip().split('\n'):
                    ip = line.strip()
                    if ip and self._is_valid_ip(ip):
                        hosts.append({
                            "ip": ip,
                            "hostname": None,
                            "os": "Unknown",
                            "priority": "medium"
                        })
                        
                # Log execution
                if task_id:
                    await self.log_execution_to_blackboard(task_id, result)
                    
            else:
                # Fallback to ping sweep if nmap not available
                self.logger.info("nmap not available, falling back to ping sweep")
                hosts = await self._ping_sweep(cidr, task_id)
                
        except Exception as e:
            self.logger.error(f"Real host discovery failed: {e}")
            # Fall back to simulation
            hosts = await self._simulate_host_discovery(cidr)
        
        return hosts
    
    async def _ping_sweep(self, cidr: str, task_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Simple ping sweep for host discovery.
        """
        hosts = []
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Limit to first 10 hosts for quick discovery
            for ip in list(network.hosts())[:10]:
                result = await self.execute_command_direct(
                    command=f"ping -c 1 -W 1 {ip} > /dev/null 2>&1 && echo UP || echo DOWN",
                    target_host="localhost",
                    target_platform="linux",
                    timeout=5
                )
                
                if result["success"] and "UP" in result["stdout"]:
                    hosts.append({
                        "ip": str(ip),
                        "hostname": None,
                        "os": "Unknown",
                        "priority": "medium"
                    })
        except Exception as e:
            self.logger.error(f"Ping sweep failed: {e}")
        
        return hosts
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    async def _simulate_host_discovery(self, cidr: str) -> List[Dict[str, Any]]:
        """
        Simulate host discovery in a network range.
        
        In production, replace with actual scanning logic.
        Always returns at least one host for testing purposes.
        """
        hosts = []
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # For MVP, simulate finding some hosts
            # In real implementation, would use ICMP, TCP SYN, etc.
            sample_hosts = list(network.hosts())[:10]  # Sample more hosts
            
            for ip in sample_hosts:
                # Simulate some being "alive"
                if hash(str(ip)) % 3 == 0:  # ~33% "alive" for simulation
                    hosts.append({
                        "ip": str(ip),
                        "hostname": f"host-{str(ip).replace('.', '-')}",
                        "os": "Linux",
                        "priority": "medium"
                    })
            
            # Ensure at least one host is returned for testing
            if not hosts and sample_hosts:
                first_host = sample_hosts[0]
                hosts.append({
                    "ip": str(first_host),
                    "hostname": f"host-{str(first_host).replace('.', '-')}",
                    "os": "Linux",
                    "priority": "medium"
                })
                self.logger.debug(f"No hosts matched hash filter, returning first host: {first_host}")
                
        except Exception as e:
            self.logger.error(f"Error parsing CIDR {cidr}: {e}")
        
        return hosts
    
    async def _execute_port_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a port scan on a target.
        
        Uses RXModuleRunner for real execution or falls back to simulation.
        Enhanced with Stealth Management for operation regulation.
        """
        target_id = task.get("target_id")
        if not target_id:
            return {"error": "No target_id specified", "ports_found": 0}
        
        # Clean target_id if needed
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        target = await self.blackboard.get_target(target_id)
        if not target:
            return {"error": f"Target {target_id} not found", "ports_found": 0}
        
        target_ip = target.get("ip")
        target_os = (target.get("os") or "linux").lower()
        self.logger.info(f"Port scanning target {target_ip}")
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Stealth Regulation
        # ═══════════════════════════════════════════════════════════
        can_proceed, delay_ms, block_reason = await self._stealth_manager.regulate_operation(
            operation_type="port_scan",
            target_id=target_id,
            mission_id=self._current_mission_id
        )
        
        if not can_proceed:
            self.logger.warning(f"Port scan blocked by stealth manager: {block_reason}")
            return {
                "error": f"Operation blocked: {block_reason}",
                "ports_found": 0,
                "stealth_blocked": True
            }
        
        if delay_ms and delay_ms > 0:
            self.logger.debug(f"Applying stealth delay: {delay_ms}ms")
            await self._stealth_manager.apply_delay(delay_ms, "port_scan")
            self._stats["stealth_delays_applied"] += 1
        
        execution_mode = "real" if self.is_real_execution_mode else "simulated"
        
        if self.is_real_execution_mode:
            # Real port scan
            open_ports = await self._real_port_scan(target_ip, target_os, task.get("id"))
        else:
            # Simulate port scan
            open_ports = await self._simulate_port_scan(target_ip)
        
        # Update target with port information
        if open_ports:
            port_mapping = {
                port: self._service_patterns.get(port, ("unknown", "Unknown"))[0]
                for port in open_ports
            }
            await self.blackboard.add_target_ports(target_id, port_mapping)
            
            # Update target status
            await self.blackboard.update_target_status(target_id, TargetStatus.SCANNED)
            
            # Create service enumeration task
            await self.create_task(
                task_type=TaskType.SERVICE_ENUM,
                target_specialist=SpecialistType.RECON,
                priority=6,
                target_id=target_id
            )
        
        # ═══════════════════════════════════════════════════════════
        # Hybrid Intelligence: Process recon results through coordinator
        # ═══════════════════════════════════════════════════════════
        strategic_analysis = None
        if open_ports:
            # Identify high-value ports discovered
            high_value_ports = self._identify_high_value_ports(open_ports)
            if high_value_ports:
                self.logger.info(
                    f"[INTELLIGENCE] High-value ports discovered on {target_ip}: {high_value_ports}"
                )
                
                # Process through Intelligence Coordinator
                services = [
                    {"name": self._service_patterns.get(p, ("unknown", "Unknown"))[0], "port": p}
                    for p in open_ports
                ]
                
                try:
                    strategic_analysis = await self._intelligence_coordinator.process_recon_results(
                        mission_id=self._current_mission_id,
                        target_id=target_id,
                        services=services,
                        vulnerabilities=[]
                    )
                    self._stats["intelligence_consultations"] += 1
                    
                    # Log strategic insights
                    if strategic_analysis:
                        self.logger.info(
                            f"[INTELLIGENCE] Strategic value: {strategic_analysis.strategic_value}, "
                            f"Recommended paths: {len(strategic_analysis.recommended_paths)}"
                        )
                except Exception as e:
                    self.logger.warning(f"Intelligence processing failed: {e}")
        
        self._stats["scans_performed"] += 1
        
        result = {
            "target_ip": target_ip,
            "ports_found": len(open_ports),
            "open_ports": open_ports,
            "execution_mode": execution_mode,
        }
        
        if strategic_analysis:
            result["strategic_analysis"] = {
                "value": strategic_analysis.strategic_value,
                "attack_surface": len(strategic_analysis.attack_surface),
                "recommended_paths": len(strategic_analysis.recommended_paths),
            }
        
        return result
    
    def _identify_high_value_ports(self, ports: List[int]) -> List[int]:
        """
        Identify high-value ports from a list of open ports.
        
        These are ports that indicate high-value services like:
        - Domain Controllers (88, 389, 636, etc.)
        - Administrative access (22, 3389, 5985)
        - Databases (1433, 3306, etc.)
        """
        high_value = []
        
        # Domain/AD ports
        domain_ports = {88, 389, 636, 3268, 3269, 445, 135}
        
        # Admin ports
        admin_ports = {22, 3389, 5985, 5986}
        
        # Database ports
        db_ports = {1433, 1521, 3306, 5432, 27017, 6379}
        
        all_high_value = domain_ports | admin_ports | db_ports
        
        for port in ports:
            if port in all_high_value:
                high_value.append(port)
        
        return high_value
    
    async def _real_port_scan(
        self, 
        target_ip: str, 
        target_os: str,
        task_id: Optional[str] = None
    ) -> List[int]:
        """
        Real port scan using nmap or netcat.
        
        Args:
            target_ip: Target IP to scan
            target_os: Target OS
            task_id: Task ID for logging
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        try:
            # Try nmap SYN scan (fastest, requires root)
            ports_str = ",".join(str(p) for p in self._common_ports)
            
            result = await self.execute_command_direct(
                command=f"nmap -sS -p {ports_str} --open {target_ip} -oG - 2>/dev/null | grep Ports",
                target_host="localhost",
                target_platform="linux",
                timeout=60
            )
            
            if result["success"] and result["stdout"].strip():
                # Parse nmap output: Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
                ports_match = re.search(r'Ports:\s*(.+)', result["stdout"])
                if ports_match:
                    ports_data = ports_match.group(1)
                    for port_info in ports_data.split(','):
                        port_match = re.match(r'(\d+)/open', port_info.strip())
                        if port_match:
                            open_ports.append(int(port_match.group(1)))
                            
                if task_id:
                    await self.log_execution_to_blackboard(task_id, result)
            else:
                # Fallback to TCP connect scan
                self.logger.info("nmap SYN scan failed, trying connect scan")
                open_ports = await self._tcp_connect_scan(target_ip, task_id)
                
        except Exception as e:
            self.logger.error(f"Real port scan failed: {e}")
            # Fall back to simulation
            open_ports = await self._simulate_port_scan(target_ip)
        
        return sorted(set(open_ports))
    
    async def _tcp_connect_scan(
        self, 
        target_ip: str,
        task_id: Optional[str] = None
    ) -> List[int]:
        """
        TCP connect scan using netcat or bash.
        """
        open_ports = []
        
        # Scan common ports
        for port in self._common_ports[:15]:  # Limit for speed
            try:
                result = await self.execute_command_direct(
                    command=f"timeout 1 bash -c 'echo > /dev/tcp/{target_ip}/{port}' 2>/dev/null && echo OPEN || echo CLOSED",
                    target_host="localhost",
                    target_platform="linux",
                    timeout=3
                )
                
                if result["success"] and "OPEN" in result["stdout"]:
                    open_ports.append(port)
                    
            except Exception:
                pass  # Port likely closed
        
        return open_ports
    
    async def _simulate_port_scan(self, ip: str) -> List[int]:
        """
        Simulate port scanning.
        
        In production, replace with actual TCP/UDP scanning.
        """
        # Simulate finding some open ports based on IP hash
        open_ports = []
        ip_hash = hash(ip)
        
        for port in self._common_ports:
            # Simulate ~20% of ports being open
            if (ip_hash + port) % 5 == 0:
                open_ports.append(port)
        
        # Always include some common ports for testing
        if 22 not in open_ports and ip_hash % 2 == 0:
            open_ports.append(22)
        if 80 not in open_ports:
            open_ports.append(80)
        if 443 not in open_ports and ip_hash % 3 == 0:
            open_ports.append(443)
        
        return sorted(set(open_ports))
    
    async def _execute_service_enum(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enumerate services on a target.
        
        This method now integrates with the Nuclei Knowledge Base to
        automatically select Info/Low severity templates for web ports.
        """
        target_id = task.get("target_id")
        if not target_id:
            return {"error": "No target_id specified", "services_found": 0}
        
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        target = await self.blackboard.get_target(target_id)
        if not target:
            return {"error": f"Target {target_id} not found", "services_found": 0}
        
        # Get open ports
        ports = await self.blackboard.get_target_ports(target_id)
        
        services_found = []
        nuclei_templates_selected = []
        ai_plan_messages = []
        
        for port_str, service_name in ports.items():
            port = int(port_str)
            
            # Get service details
            service_info = self._service_patterns.get(port, (service_name, "Unknown"))
            
            service = {
                "port": port,
                "name": service_info[0],
                "product": service_info[1],
                "version": "Unknown"  # In real impl, would do banner grabbing
            }
            services_found.append(service)
            
            # ═══════════════════════════════════════════════════════════
            # AI-PLAN: Intelligent Nuclei Template Selection
            # Automatically select Info/Low templates for web ports (80/443)
            # ═══════════════════════════════════════════════════════════
            if port in (80, 443, 8080, 8443, 3000, 5000, 8000):
                templates = await self._select_nuclei_templates_for_port(
                    port=port,
                    target_id=target_id,
                    service_info=service_info
                )
                if templates:
                    nuclei_templates_selected.extend(templates)
                    ai_plan_msg = (
                        f"[AI-PLAN] Found Port {port}. Selecting {len(templates)} "
                        f"Nuclei templates based on technology fingerprint..."
                    )
                    ai_plan_messages.append(ai_plan_msg)
                    self.logger.info(ai_plan_msg)
                    
                    # Log to execution stream via Blackboard
                    if self.blackboard and self._current_mission_id:
                        await self.blackboard.log_result(
                            self._current_mission_id,
                            "ai_plan",
                            {
                                "event": "nuclei_template_selection",
                                "port": port,
                                "templates_count": len(templates),
                                "message": ai_plan_msg,
                                "templates": [t.get("template_id") for t in templates[:10]]
                            }
                        )
            
            # Check for known vulnerabilities
            if service_info[0] in self._vuln_checks:
                for vuln_id, vuln_name, severity in self._vuln_checks[service_info[0]]:
                    await self.add_discovered_vulnerability(
                        target_id=target_id,
                        vuln_type=vuln_id,
                        name=vuln_name,
                        severity=severity,
                        description=f"Potential {vuln_name} vulnerability on port {port}",
                        exploit_available=True,
                        rx_modules=[f"rx-{vuln_id.lower().replace('-', '_')}"]
                    )
        
        # Create vuln scan task if web templates were selected
        if nuclei_templates_selected:
            await self.create_task(
                task_type=TaskType.VULN_SCAN,
                target_specialist=SpecialistType.RECON,
                priority=8,
                target_id=target_id,
                nuclei_templates=[t.get("template_id") for t in nuclei_templates_selected[:50]]
            )
        
        return {
            "services_found": len(services_found),
            "services": services_found,
            "ai_plan_messages": ai_plan_messages,
            "nuclei_templates_selected": len(nuclei_templates_selected)
        }
    
    async def _select_nuclei_templates_for_port(
        self,
        port: int,
        target_id: str,
        service_info: tuple
    ) -> List[Dict[str, Any]]:
        """
        AI-Driven Nuclei Template Selection based on port and technology fingerprint.
        
        This implements the intelligent template selection for the AI-to-Nuclei Logic Wiring:
        - For ports 80/443: Select Info/Low severity templates for initial recon
        - Use technology fingerprints to narrow down relevant templates
        - Prioritize templates based on service detection
        
        Args:
            port: The open port number
            target_id: Target identifier
            service_info: Tuple of (service_name, product_name)
            
        Returns:
            List of selected Nuclei template dicts
        """
        if not self.knowledge or not self.knowledge.is_loaded():
            self.logger.warning("Knowledge base not loaded, skipping AI template selection")
            return []
        
        selected_templates = []
        
        # Get technology fingerprints for this port
        tech_fingerprints = self._port_technology_map.get(port, [])
        service_name = service_info[0].lower() if service_info else ""
        
        # Add service name to fingerprints
        if service_name and service_name not in tech_fingerprints:
            tech_fingerprints = [service_name] + tech_fingerprints
        
        self.logger.info(
            f"[AI-PLAN] Technology fingerprint for port {port}: {tech_fingerprints}"
        )
        
        # Query Knowledge Base for Info/Low severity templates
        # These are ideal for initial reconnaissance without being too noisy
        for severity in ["info", "low"]:
            templates = self.knowledge.get_nuclei_templates_by_severity(
                severity=severity,
                limit=100
            )
            
            # Filter templates based on technology fingerprint
            for template in templates:
                template_tags = [t.lower() for t in template.get("tags", [])]
                template_name = template.get("name", "").lower()
                template_id = template.get("template_id", "").lower()
                
                # Check if template matches our technology fingerprint
                for tech in tech_fingerprints:
                    if (
                        tech in template_tags or
                        tech in template_name or
                        tech in template_id
                    ):
                        selected_templates.append(template)
                        break
        
        # Also search for templates matching the service
        if service_name:
            search_results = self.knowledge.search_nuclei_templates(
                query=service_name,
                severity="info",
                limit=20
            )
            for template in search_results:
                if template not in selected_templates:
                    selected_templates.append(template)
            
            # Also get low severity for deeper analysis
            search_results_low = self.knowledge.search_nuclei_templates(
                query=service_name,
                severity="low",
                limit=20
            )
            for template in search_results_low:
                if template not in selected_templates:
                    selected_templates.append(template)
        
        # Deduplicate by template_id
        seen_ids = set()
        unique_templates = []
        for t in selected_templates:
            tid = t.get("template_id")
            if tid and tid not in seen_ids:
                seen_ids.add(tid)
                unique_templates.append(t)
        
        self.logger.info(
            f"[AI-PLAN] Selected {len(unique_templates)} Nuclei templates for port {port}"
        )
        
        return unique_templates[:50]  # Limit to 50 templates
    
    async def _execute_vuln_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a vulnerability scan on a target using Nuclei.
        
        This method integrates the Nuclei scanner for comprehensive
        vulnerability detection and optionally consults the LLM
        for intelligent scan strategy decisions.
        """
        target_id = task.get("target_id")
        if not target_id:
            return {"error": "No target_id specified", "vulns_found": 0}
        
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        target = await self.blackboard.get_target(target_id)
        if not target:
            return {"error": f"Target {target_id} not found", "vulns_found": 0}
        
        target_ip = target.get("ip")
        target_ports = await self.blackboard.get_target_ports(target_id)
        
        # Determine scan targets (for web services)
        web_targets = []
        web_ports_found = []
        for port_str, service in target_ports.items():
            port = int(port_str)
            if port in (80, 8080, 8000, 3000, 5000):
                web_targets.append(f"http://{target_ip}:{port}")
                web_ports_found.append(port)
            elif port in (443, 8443, 4443):
                web_targets.append(f"https://{target_ip}:{port}")
                web_ports_found.append(port)
        
        # ═══════════════════════════════════════════════════════════
        # AI-PLAN: Log discovery of web ports
        # ═══════════════════════════════════════════════════════════
        if web_ports_found:
            ai_plan_msg = (
                f"[AI-PLAN] Found {len(web_ports_found)} web port(s): {web_ports_found}. "
                f"Initiating intelligent Nuclei template selection..."
            )
            self.logger.info(ai_plan_msg)
            
            if self.blackboard and self._current_mission_id:
                await self.blackboard.log_result(
                    self._current_mission_id,
                    "ai_plan",
                    {
                        "event": "web_ports_discovered",
                        "ports": web_ports_found,
                        "target_id": target_id,
                        "message": ai_plan_msg
                    }
                )
        
        # If no web targets, scan the IP directly
        if not web_targets:
            web_targets = [target_ip]
        
        # Consult LLM for scan strategy if enabled and many targets
        scan_strategy = None
        if self._ai_consultation_enabled and len(web_targets) > self._ai_consultation_threshold:
            scan_strategy = await self._consult_llm_for_scan_strategy(
                target_id=target_id,
                targets=web_targets,
                target_info=target
            )
        
        # Apply AI-recommended strategy or use defaults
        severity_filter = ["critical", "high"]
        templates = None
        
        if scan_strategy:
            severity_filter = scan_strategy.get("severity_filter", severity_filter)
            templates = scan_strategy.get("templates")
            focused_targets = scan_strategy.get("focused_targets")
            if focused_targets:
                web_targets = focused_targets
        
        # Execute Nuclei scan
        vulns_found = []
        nuclei_available = await self.nuclei_scanner.check_available()
        
        if nuclei_available:
            self.logger.info(f"Running Nuclei scan on {len(web_targets)} target(s)")
            
            for web_target in web_targets:
                result = await self.nuclei_scanner.scan(
                    target=web_target,
                    templates=templates,
                    severity=severity_filter,
                    include_request_response=True,
                )
                
                if result.success:
                    # Convert Nuclei findings to RAGLOX vulnerabilities
                    for nuclei_vuln in result.vulnerabilities:
                        raglox_vuln = nuclei_vuln.to_vulnerability(
                            mission_id=UUID(self._current_mission_id),
                            target_id=UUID(target_id)
                        )
                        vuln_id = await self.blackboard.add_vulnerability(raglox_vuln)
                        
                        # Get severity value safely (may be enum or string)
                        severity_val = raglox_vuln.severity
                        if hasattr(severity_val, 'value'):
                            severity_val = severity_val.value
                        
                        vulns_found.append({
                            "vuln_id": vuln_id,
                            "type": raglox_vuln.type,
                            "severity": severity_val,
                            "name": raglox_vuln.name,
                            "exploitable": nuclei_vuln.severity.value in ("critical", "high")
                        })
                        
                        self.logger.info(
                            f"Nuclei found {nuclei_vuln.severity.value} vuln: "
                            f"{nuclei_vuln.name} ({nuclei_vuln.vuln_type or nuclei_vuln.template_id})"
                        )
                else:
                    self.logger.warning(f"Nuclei scan failed: {result.error_message}")
        else:
            # Fall back to basic vulnerability checks
            self.logger.warning("Nuclei not available, using basic vuln checks")
            existing_vulns = await self.blackboard.get_mission_vulns(self._current_mission_id)
            vulns_found = [{"vuln_id": v.replace("vuln:", ""), "type": "basic"} for v in existing_vulns]
        
        # Create exploit tasks for critical/high severity vulnerabilities
        exploitable_vulns = [v for v in vulns_found if v.get("exploitable")]
        for vuln in exploitable_vulns:
            await self.create_task(
                task_type=TaskType.EXPLOIT,
                target_specialist=SpecialistType.ATTACK,
                priority=9 if vuln.get("severity") == "critical" else 8,
                target_id=target_id,
                vuln_id=vuln.get("vuln_id")
            )
        
        return {
            "target_id": target_id,
            "vulns_found": len(vulns_found),
            "critical_count": sum(1 for v in vulns_found if v.get("severity") == "critical"),
            "high_count": sum(1 for v in vulns_found if v.get("severity") == "high"),
            "exploitable_count": len(exploitable_vulns),
            "vulnerabilities": vulns_found[:20],  # Limit response size
            "scan_type": "nuclei" if nuclei_available else "basic",
            "ai_strategy_used": scan_strategy is not None
        }
    
    async def _consult_llm_for_scan_strategy(
        self,
        target_id: str,
        targets: List[str],
        target_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Consult the LLM (via AnalysisSpecialist) for scan strategy.
        
        This implements the AI-driven decision making:
        "Found 50 subdomains, should I scan all with Nuclei or focus on
        targets containing 'admin'?"
        
        Args:
            target_id: Target identifier
            targets: List of target URLs/IPs to potentially scan
            target_info: Target metadata
            
        Returns:
            Scan strategy dict or None if LLM unavailable/disabled
        """
        try:
            # Try to get LLM service
            from ..core.llm.service import get_llm_service
            
            llm_service = get_llm_service()
            if not llm_service or not llm_service.providers:
                return None
            
            # Build consultation prompt
            prompt = self._build_scan_strategy_prompt(targets, target_info)
            
            # Query LLM
            from ..core.llm.models import CompletionRequest
            
            request = CompletionRequest(
                prompt=prompt,
                max_tokens=500,
                temperature=0.3,
            )
            
            response = await llm_service.complete(request)
            
            if response.success and response.content:
                return self._parse_scan_strategy_response(response.content, targets)
            
        except Exception as e:
            self.logger.warning(f"LLM consultation failed: {e}")
        
        return None
    
    def _build_scan_strategy_prompt(
        self,
        targets: List[str],
        target_info: Dict[str, Any]
    ) -> str:
        """Build the LLM prompt for scan strategy consultation."""
        # Analyze target patterns
        admin_targets = [t for t in targets if "admin" in t.lower()]
        api_targets = [t for t in targets if "api" in t.lower()]
        dev_targets = [t for t in targets if any(x in t.lower() for x in ["dev", "staging", "test"])]
        
        return f"""You are a security expert advising on scan strategy.

## Situation:
I discovered {len(targets)} web targets for scanning with Nuclei:
- Total targets: {len(targets)}
- Admin-related targets: {len(admin_targets)} (e.g., {admin_targets[:3]})
- API endpoints: {len(api_targets)} (e.g., {api_targets[:3]})
- Dev/Staging: {len(dev_targets)} (e.g., {dev_targets[:3]})

Target OS: {target_info.get('os', 'Unknown')}
Target Priority: {target_info.get('priority', 'medium')}

## Question:
Should I scan all {len(targets)} targets with Nuclei (time-consuming) or focus on high-value targets?

## Response Format (JSON only):
{{
    "strategy": "focused" or "full",
    "reasoning": "brief explanation",
    "focused_targets": ["list of targets to prioritize"] or null,
    "severity_filter": ["critical", "high"] or ["critical", "high", "medium"],
    "templates": ["specific templates"] or null
}}

Respond with JSON only."""
    
    def _parse_scan_strategy_response(
        self,
        response: str,
        all_targets: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Parse LLM response into scan strategy."""
        import json
        
        try:
            # Try to extract JSON from response using pre-compiled regex
            if "```" in response:
                # Extract from code block
                match = _JSON_CODE_BLOCK_PATTERN.search(response)
                if match:
                    response = match.group(1)
            
            strategy = json.loads(response)
            
            # Validate and normalize
            result = {
                "severity_filter": strategy.get("severity_filter", ["critical", "high"]),
                "templates": strategy.get("templates"),
            }
            
            # Handle focused targets
            if strategy.get("strategy") == "focused" and strategy.get("focused_targets"):
                # Ensure focused targets are subset of all targets
                focused = [t for t in strategy["focused_targets"] if t in all_targets]
                if focused:
                    result["focused_targets"] = focused
            
            self.logger.info(f"LLM recommended scan strategy: {strategy.get('strategy')}")
            return result
            
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse LLM scan strategy response")
            return None
    
    # ═══════════════════════════════════════════════════════════
    # Event Handling
    # ═══════════════════════════════════════════════════════════
    
    async def on_event(self, event: Dict[str, Any]) -> None:
        """Handle Pub/Sub events."""
        event_type = event.get("event")
        
        if event_type == "new_target":
            # New target discovered - might create scan tasks
            target_id = event.get("target_id")
            needs_deep_scan = event.get("needs_deep_scan", False)
            
            if needs_deep_scan:
                self.logger.info(f"New target {target_id} needs deep scan")
                # Port scan task would already be created by the discovery
        
        elif event_type == "control":
            command = event.get("command")
            if command == "pause":
                await self.pause()
            elif command == "resume":
                await self.resume()
            elif command == "stop":
                await self.stop()
    
    # ═══════════════════════════════════════════════════════════
    # Channel Subscriptions
    # ═══════════════════════════════════════════════════════════
    
    def _get_channels_to_subscribe(self, mission_id: str) -> List[str]:
        """Get channels for Recon specialist."""
        return [
            self.blackboard.get_channel(mission_id, "tasks"),
            self.blackboard.get_channel(mission_id, "targets"),
            self.blackboard.get_channel(mission_id, "control"),
        ]
