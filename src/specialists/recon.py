# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Recon Specialist
# Reconnaissance specialist for network and target discovery
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
from ..core.knowledge import EmbeddedKnowledge

if TYPE_CHECKING:
    from ..executors import RXModuleRunner, ExecutorFactory


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
        executor_factory: Optional['ExecutorFactory'] = None
    ):
        super().__init__(
            specialist_type=SpecialistType.RECON,
            blackboard=blackboard,
            settings=settings,
            worker_id=worker_id,
            knowledge=knowledge,
            runner=runner,
            executor_factory=executor_factory
        )
        
        # Task types this specialist handles
        self._supported_task_types = {
            TaskType.NETWORK_SCAN,
            TaskType.PORT_SCAN,
            TaskType.SERVICE_ENUM,
            TaskType.VULN_SCAN
        }
        
        # Common ports to scan (MVP - simplified)
        self._common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443
        ]
        
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
        """
        hosts = []
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            
            # For MVP, simulate finding some hosts
            # In real implementation, would use ICMP, TCP SYN, etc.
            sample_hosts = list(network.hosts())[:5]  # Limit for simulation
            
            for ip in sample_hosts:
                # Simulate some being "alive"
                if hash(str(ip)) % 3 == 0:  # ~33% "alive" for simulation
                    hosts.append({
                        "ip": str(ip),
                        "hostname": f"host-{str(ip).replace('.', '-')}",
                        "os": "Unknown",
                        "priority": "medium"
                    })
        except Exception as e:
            self.logger.error(f"Error parsing CIDR {cidr}: {e}")
        
        return hosts
    
    async def _execute_port_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a port scan on a target.
        
        Uses RXModuleRunner for real execution or falls back to simulation.
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
        
        return {
            "target_ip": target_ip,
            "ports_found": len(open_ports),
            "open_ports": open_ports,
            "execution_mode": execution_mode
        }
    
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
        
        return {
            "services_found": len(services_found),
            "services": services_found
        }
    
    async def _execute_vuln_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a vulnerability scan on a target.
        """
        target_id = task.get("target_id")
        if not target_id:
            return {"error": "No target_id specified", "vulns_found": 0}
        
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        target = await self.blackboard.get_target(target_id)
        if not target:
            return {"error": f"Target {target_id} not found", "vulns_found": 0}
        
        # Get existing vulnerabilities for this target
        existing_vulns = await self.blackboard.get_mission_vulns(self._current_mission_id)
        
        # In a real implementation, would run various vuln checks here
        # For MVP, we've already added basic vulns in service enumeration
        
        return {
            "target_id": target_id,
            "vulns_found": len(existing_vulns),
            "scan_type": "basic"
        }
    
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
