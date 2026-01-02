# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Attack Specialist
# Exploitation and lateral movement specialist
# ═══════════════════════════════════════════════════════════════

import asyncio
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID

from .base import BaseSpecialist
from ..core.models import (
    TaskType, SpecialistType, TargetStatus, Severity, Priority,
    CredentialType, PrivilegeLevel, SessionType, SessionStatus,
    GoalAchievedEvent, GoalStatus
)
from ..core.blackboard import Blackboard
from ..core.config import Settings
from ..core.knowledge import EmbeddedKnowledge

if TYPE_CHECKING:
    from ..executors import RXModuleRunner, ExecutorFactory


class AttackSpecialist(BaseSpecialist):
    """
    Attack Specialist - Handles exploitation and lateral movement.
    
    Responsibilities:
    - Exploiting discovered vulnerabilities
    - Privilege escalation
    - Lateral movement
    - Credential harvesting from compromised systems
    
    Task Types Handled:
    - EXPLOIT: Exploit a vulnerability to gain access
    - PRIVESC: Privilege escalation on compromised host
    - LATERAL: Lateral movement to other hosts
    - CRED_HARVEST: Harvest credentials from compromised host
    
    Reads From Blackboard:
    - Discovered vulnerabilities
    - Discovered credentials
    - Active sessions
    - Attack paths
    
    Writes To Blackboard:
    - New sessions (on successful exploit)
    - New credentials (from harvesting)
    - Attack paths
    - Session status updates
    - Goal achievements
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
            specialist_type=SpecialistType.ATTACK,
            blackboard=blackboard,
            settings=settings,
            worker_id=worker_id,
            knowledge=knowledge,
            runner=runner,
            executor_factory=executor_factory
        )
        
        # Task types this specialist handles
        self._supported_task_types = {
            TaskType.EXPLOIT,
            TaskType.PRIVESC,
            TaskType.LATERAL,
            TaskType.CRED_HARVEST
        }
        
        # Simulated exploit success rates (for MVP)
        self._exploit_success_rates = {
            "MS17-010": 0.85,       # EternalBlue - high success
            "CVE-2019-0708": 0.75,  # BlueKeep
            "CVE-2021-44228": 0.90, # Log4Shell - very high
            "CVE-2018-15473": 0.60, # SSH User Enum
            "default": 0.50
        }
        
        # Privilege escalation techniques
        self._privesc_techniques = [
            ("kernel_exploit", 0.60, PrivilegeLevel.ROOT),
            ("service_misconfig", 0.70, PrivilegeLevel.SYSTEM),
            ("token_impersonation", 0.65, PrivilegeLevel.ADMIN),
            ("unquoted_service_path", 0.55, PrivilegeLevel.SYSTEM),
        ]
        
        # Credential sources
        self._cred_sources = [
            ("mimikatz", CredentialType.HASH, PrivilegeLevel.DOMAIN_ADMIN),
            ("lsass_dump", CredentialType.HASH, PrivilegeLevel.ADMIN),
            ("sam_dump", CredentialType.HASH, PrivilegeLevel.USER),
            ("browser_creds", CredentialType.PASSWORD, PrivilegeLevel.USER),
            ("config_files", CredentialType.PASSWORD, PrivilegeLevel.USER),
        ]
    
    # ═══════════════════════════════════════════════════════════
    # Task Execution
    # ═══════════════════════════════════════════════════════════
    
    async def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an attack task."""
        task_type = task.get("type")
        
        handlers = {
            TaskType.EXPLOIT.value: self._execute_exploit,
            TaskType.PRIVESC.value: self._execute_privesc,
            TaskType.LATERAL.value: self._execute_lateral,
            TaskType.CRED_HARVEST.value: self._execute_cred_harvest,
        }
        
        handler = handlers.get(task_type)
        if not handler:
            raise ValueError(f"Unsupported task type: {task_type}")
        
        return await handler(task)
    
    async def _execute_exploit(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exploit a vulnerability to gain access.
        
        Uses RXModuleRunner for real execution or falls back to simulation.
        """
        vuln_id = task.get("vuln_id")
        target_id = task.get("target_id")
        rx_module = task.get("rx_module")
        task_id = task.get("id")
        
        # Get target details
        target = None
        target_ip = None
        target_platform = "linux"  # Default
        
        if target_id:
            clean_target_id = target_id.replace("target:", "") if isinstance(target_id, str) else str(target_id)
            target = await self.blackboard.get_target(clean_target_id)
            if target:
                target_ip = target.get("ip")
                target_os = (target.get("os") or "").lower()
                if "windows" in target_os:
                    target_platform = "windows"
                elif "linux" in target_os:
                    target_platform = "linux"
        
        if not vuln_id:
            return {"error": "No vuln_id specified", "success": False}
        
        # Clean IDs
        if isinstance(vuln_id, str) and vuln_id.startswith("vuln:"):
            vuln_id = vuln_id.replace("vuln:", "")
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        # Get vulnerability details
        vuln = await self.blackboard.get_vulnerability(vuln_id)
        if not vuln:
            return {"error": f"Vulnerability {vuln_id} not found", "success": False}
        
        vuln_type = vuln.get("type", "default")
        if not target_id:
            target_id = vuln.get("target_id")
        
        self.logger.info(f"Exploiting {vuln_type} on target {target_id}")
        
        # Try to find RX module from knowledge base if not provided
        rx_module_info = None
        if not rx_module and self.knowledge and self.knowledge.is_loaded():
            rx_module_info = self.get_module_for_vuln(vuln_type, target_platform)
            if rx_module_info:
                rx_module = rx_module_info.get("rx_module_id")
                self.logger.info(f"Found RX module from knowledge base: {rx_module}")
        
        execution_mode = "real" if self.is_real_execution_mode and rx_module else "simulated"
        success = False
        error_context = None
        
        if self.is_real_execution_mode and rx_module and target_ip:
            # Real execution using RXModuleRunner
            exec_result = await self._real_exploit(
                rx_module_id=rx_module,
                target_ip=target_ip,
                target_platform=target_platform,
                vuln_type=vuln_type,
                task_id=task_id
            )
            success = exec_result.get("success", False)
            error_context = exec_result.get("error_context")
            
            # Log execution to Blackboard for Reflexion analysis
            if task_id:
                await self.log_execution_to_blackboard(task_id, exec_result)
        else:
            # Simulate exploit attempt
            success = await self._simulate_exploit(vuln_type, rx_module_info)
        
        if success:
            # Determine session type based on exploit
            session_type = self._determine_session_type(vuln_type)
            
            # Determine initial privilege level
            initial_privilege = self._determine_initial_privilege(vuln_type)
            
            # Create session
            session_id = await self.add_established_session(
                target_id=target_id,
                session_type=session_type,
                user="unknown",  # Would be determined by post-exploit recon
                privilege=initial_privilege,
                via_vuln_id=vuln_id
            )
            
            # Update vulnerability status
            await self.blackboard.update_vuln_status(vuln_id, "exploited")
            
            # Update target status
            await self.blackboard.update_target_status(target_id, TargetStatus.EXPLOITED)
            
            # Create follow-up tasks
            if initial_privilege in (PrivilegeLevel.USER, PrivilegeLevel.UNKNOWN):
                # Need privesc
                await self.create_task(
                    task_type=TaskType.PRIVESC,
                    target_specialist=SpecialistType.ATTACK,
                    priority=8,
                    target_id=target_id,
                    session_id=session_id
                )
            else:
                # Already privileged - harvest creds
                await self.create_task(
                    task_type=TaskType.CRED_HARVEST,
                    target_specialist=SpecialistType.ATTACK,
                    priority=7,
                    target_id=target_id,
                    session_id=session_id
                )
            
            return {
                "success": True,
                "vuln_type": vuln_type,
                "session_id": session_id,
                "privilege": initial_privilege.value,
                "session_type": session_type,
                "execution_mode": execution_mode
            }
        else:
            return {
                "success": False,
                "vuln_type": vuln_type,
                "reason": "Exploit failed",
                "error_context": error_context,
                "execution_mode": execution_mode
            }
    
    async def _real_exploit(
        self,
        rx_module_id: str,
        target_ip: str,
        target_platform: str,
        vuln_type: str,
        task_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a real exploit using RXModuleRunner.
        
        Args:
            rx_module_id: RX Module ID to execute
            target_ip: Target IP address
            target_platform: Target platform
            vuln_type: Vulnerability type
            task_id: Task ID for logging
            
        Returns:
            Execution result dictionary
        """
        try:
            # Build variables for the module
            variables = {
                "target_ip": target_ip,
                "target_host": target_ip,
                "rhost": target_ip,
                "RHOST": target_ip,
            }
            
            # Execute the module
            result = await self.execute_rx_module(
                rx_module_id=rx_module_id,
                target_host=target_ip,
                target_platform=target_platform,
                variables=variables,
                task_id=task_id,
                check_prerequisites=True,
                timeout=300
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Real exploit execution failed: {e}")
            return {
                "success": False,
                "error_context": {
                    "error_type": "execution_exception",
                    "error_message": str(e),
                    "module_used": rx_module_id,
                    "vuln_type": vuln_type
                }
            }
    
    async def _simulate_exploit(
        self, 
        vuln_type: str, 
        rx_module: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Simulate exploit attempt.
        
        Uses RX module information from knowledge base if available.
        In production, would call actual exploit modules.
        """
        import random
        
        # Base success rate
        success_rate = self._exploit_success_rates.get(
            vuln_type,
            self._exploit_success_rates["default"]
        )
        
        # Adjust success rate based on RX module availability
        if rx_module:
            # Having a known RX module increases success rate
            success_rate = min(success_rate + 0.1, 0.95)
            
            # Check if elevation is required
            execution = rx_module.get("execution", {})
            if execution.get("elevation_required"):
                # Elevation required slightly reduces initial success
                success_rate -= 0.05
        
        # Simulate attempt with some delay
        await asyncio.sleep(0.5)  # Simulate execution time
        
        return random.random() < success_rate
    
    def _determine_session_type(self, vuln_type: str) -> str:
        """Determine session type based on exploit."""
        session_map = {
            "MS17-010": "meterpreter",
            "CVE-2019-0708": "meterpreter",
            "CVE-2021-44228": "shell",
            "default": "shell"
        }
        return session_map.get(vuln_type, session_map["default"])
    
    def _determine_initial_privilege(self, vuln_type: str) -> PrivilegeLevel:
        """Determine initial privilege level from exploit."""
        priv_map = {
            "MS17-010": PrivilegeLevel.SYSTEM,  # EternalBlue gives SYSTEM
            "CVE-2019-0708": PrivilegeLevel.SYSTEM,  # BlueKeep gives SYSTEM
            "CVE-2021-44228": PrivilegeLevel.USER,  # Log4Shell - service user
            "default": PrivilegeLevel.USER
        }
        return priv_map.get(vuln_type, priv_map["default"])
    
    async def _execute_privesc(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute privilege escalation.
        """
        target_id = task.get("target_id")
        session_id = task.get("session_id")
        
        if not target_id:
            return {"error": "No target_id specified", "success": False}
        
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        if isinstance(session_id, str) and session_id.startswith("session:"):
            session_id = session_id.replace("session:", "")
        
        self.logger.info(f"Attempting privesc on target {target_id}")
        
        # Try privesc techniques
        for technique_name, success_rate, target_privilege in self._privesc_techniques:
            import random
            
            if random.random() < success_rate:
                self.logger.info(f"Privesc succeeded using {technique_name}")
                
                # Update session privilege (or create new elevated session)
                new_session_id = await self.add_established_session(
                    target_id=target_id,
                    session_type="shell",
                    user="SYSTEM" if target_privilege == PrivilegeLevel.SYSTEM else "root",
                    privilege=target_privilege
                )
                
                # Update target status
                await self.blackboard.update_target_status(target_id, TargetStatus.OWNED)
                
                # Create cred harvest task
                await self.create_task(
                    task_type=TaskType.CRED_HARVEST,
                    target_specialist=SpecialistType.ATTACK,
                    priority=7,
                    target_id=target_id,
                    session_id=new_session_id
                )
                
                # Check if this achieves domain_admin goal
                if target_privilege == PrivilegeLevel.DOMAIN_ADMIN:
                    await self._check_goal_achievement("domain_admin")
                
                return {
                    "success": True,
                    "technique": technique_name,
                    "new_privilege": target_privilege.value,
                    "session_id": new_session_id
                }
        
        return {
            "success": False,
            "reason": "All privesc techniques failed"
        }
    
    async def _execute_lateral(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute lateral movement to another host.
        """
        from_target_id = task.get("target_id")
        cred_id = task.get("cred_id")
        
        if not from_target_id or not cred_id:
            return {"error": "Missing target_id or cred_id", "success": False}
        
        if isinstance(from_target_id, str) and from_target_id.startswith("target:"):
            from_target_id = from_target_id.replace("target:", "")
        if isinstance(cred_id, str) and cred_id.startswith("cred:"):
            cred_id = cred_id.replace("cred:", "")
        
        # Get credential
        cred = await self.blackboard.get_credential(cred_id)
        if not cred:
            return {"error": f"Credential {cred_id} not found", "success": False}
        
        # Get other targets in mission
        all_targets = await self.blackboard.get_mission_targets(self._current_mission_id)
        
        successful_laterals = []
        
        for target_key in all_targets:
            to_target_id = target_key.replace("target:", "")
            if to_target_id == from_target_id:
                continue
            
            target = await self.blackboard.get_target(to_target_id)
            if not target:
                continue
            
            # Skip already owned targets
            if target.get("status") in ("exploited", "owned"):
                continue
            
            # Simulate lateral movement attempt
            import random
            if random.random() < 0.6:  # 60% success rate
                # Create session on new target
                session_id = await self.add_established_session(
                    target_id=to_target_id,
                    session_type="smb" if cred.get("type") == "hash" else "ssh",
                    user=cred.get("username"),
                    privilege=PrivilegeLevel(cred.get("privilege_level", "user")),
                    via_cred_id=cred_id
                )
                
                await self.blackboard.update_target_status(to_target_id, TargetStatus.EXPLOITED)
                
                successful_laterals.append({
                    "target_id": to_target_id,
                    "target_ip": target.get("ip"),
                    "session_id": session_id
                })
        
        return {
            "success": len(successful_laterals) > 0,
            "from_target": from_target_id,
            "laterals_succeeded": len(successful_laterals),
            "lateral_targets": successful_laterals
        }
    
    async def _execute_cred_harvest(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Harvest credentials from a compromised host.
        
        Uses RXModuleRunner for real credential harvesting or simulation.
        """
        target_id = task.get("target_id")
        session_id = task.get("session_id")
        task_id = task.get("id")
        
        if not target_id:
            return {"error": "No target_id specified", "creds_found": 0}
        
        if isinstance(target_id, str) and target_id.startswith("target:"):
            target_id = target_id.replace("target:", "")
        
        # Get target details
        target = await self.blackboard.get_target(target_id)
        target_ip = target.get("ip") if target else None
        target_os = (target.get("os") or "").lower() if target else "linux"
        target_platform = "windows" if "windows" in target_os else "linux"
        
        self.logger.info(f"Harvesting credentials from target {target_id}")
        
        harvested_creds = []
        execution_mode = "real" if self.is_real_execution_mode and target_ip else "simulated"
        
        if self.is_real_execution_mode and target_ip:
            # Try real credential harvesting
            harvested_creds = await self._real_cred_harvest(
                target_id=target_id,
                target_ip=target_ip,
                target_platform=target_platform,
                task_id=task_id
            )
        else:
            # Simulate credential harvesting
            harvested_creds = await self._simulate_cred_harvest(target_id)
        
        # Process harvested credentials
        for cred in harvested_creds:
            priv_level = PrivilegeLevel(cred.get("privilege", "user"))
            
            # Check for domain_admin achievement
            if priv_level == PrivilegeLevel.DOMAIN_ADMIN:
                await self._check_goal_achievement("domain_admin")
            
            # Create lateral movement tasks for valuable creds
            if priv_level in (PrivilegeLevel.DOMAIN_ADMIN, PrivilegeLevel.ADMIN):
                await self.create_task(
                    task_type=TaskType.LATERAL,
                    target_specialist=SpecialistType.ATTACK,
                    priority=8,
                    target_id=target_id,
                    cred_id=cred.get("cred_id")
                )
        
        return {
            "creds_found": len(harvested_creds),
            "credentials": harvested_creds,
            "execution_mode": execution_mode
        }
    
    async def _real_cred_harvest(
        self,
        target_id: str,
        target_ip: str,
        target_platform: str,
        task_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Real credential harvesting using RX modules.
        """
        harvested_creds = []
        
        # Get credential harvesting modules from knowledge base
        cred_modules = self.get_credential_modules(platform=target_platform)
        
        if not cred_modules:
            # Fall back to simulation
            return await self._simulate_cred_harvest(target_id)
        
        # Try top 3 credential modules
        for module in cred_modules[:3]:
            rx_module_id = module.get("rx_module_id")
            if not rx_module_id:
                continue
            
            try:
                result = await self.execute_rx_module(
                    rx_module_id=rx_module_id,
                    target_host=target_ip,
                    target_platform=target_platform,
                    task_id=task_id,
                    timeout=120
                )
                
                if result.get("success"):
                    # Parse credentials from output
                    parsed_creds = self._parse_credentials_from_output(
                        result.get("stdout", ""),
                        result.get("parsed_data", {}),
                        target_id
                    )
                    
                    for cred_data in parsed_creds:
                        cred_id = await self.add_discovered_credential(
                            target_id=target_id,
                            cred_type=cred_data["type"],
                            username=cred_data["username"],
                            domain=cred_data.get("domain"),
                            value_encrypted=cred_data.get("value", b""),
                            source=rx_module_id,
                            verified=False,
                            privilege_level=cred_data.get("privilege", PrivilegeLevel.USER)
                        )
                        
                        harvested_creds.append({
                            "cred_id": cred_id,
                            "username": cred_data["username"],
                            "domain": cred_data.get("domain"),
                            "type": cred_data["type"].value,
                            "source": rx_module_id,
                            "privilege": cred_data.get("privilege", PrivilegeLevel.USER).value
                        })
                
                # Log execution
                if task_id:
                    await self.log_execution_to_blackboard(task_id, result)
                    
            except Exception as e:
                self.logger.error(f"Error executing cred module {rx_module_id}: {e}")
        
        # If no creds found via real modules, try simulation
        if not harvested_creds:
            harvested_creds = await self._simulate_cred_harvest(target_id)
        
        return harvested_creds
    
    def _parse_credentials_from_output(
        self,
        stdout: str,
        parsed_data: Dict[str, Any],
        target_id: str
    ) -> List[Dict[str, Any]]:
        """
        Parse credentials from command output.
        """
        import re
        creds = []
        
        # Use parsed_data if available
        if parsed_data.get("usernames"):
            for username in parsed_data["usernames"][:5]:
                creds.append({
                    "username": username,
                    "type": CredentialType.PASSWORD,
                    "privilege": PrivilegeLevel.USER
                })
        
        if parsed_data.get("hashes"):
            for hash_type, hashes in parsed_data["hashes"].items():
                for hash_value in hashes[:3]:
                    creds.append({
                        "username": "unknown",
                        "type": CredentialType.HASH,
                        "value": hash_value.encode(),
                        "privilege": PrivilegeLevel.USER
                    })
        
        # Try to parse mimikatz-style output
        mimikatz_pattern = r'Username\s*:\s*(\S+)\s*.*?NTLM\s*:\s*([a-fA-F0-9]{32})'
        matches = re.findall(mimikatz_pattern, stdout, re.DOTALL)
        for username, ntlm_hash in matches:
            creds.append({
                "username": username,
                "type": CredentialType.HASH,
                "value": ntlm_hash.encode(),
                "privilege": PrivilegeLevel.ADMIN if "admin" in username.lower() else PrivilegeLevel.USER
            })
        
        return creds
    
    async def _simulate_cred_harvest(self, target_id: str) -> List[Dict[str, Any]]:
        """
        Simulate credential harvesting (fallback).
        """
        import random
        
        harvested_creds = []
        
        for source, cred_type, priv_level in self._cred_sources:
            if random.random() < 0.4:  # 40% chance to find each type
                username = self._generate_fake_username()
                domain = "CORP" if priv_level in (PrivilegeLevel.DOMAIN_ADMIN, PrivilegeLevel.ADMIN) else None
                
                cred_id = await self.add_discovered_credential(
                    target_id=target_id,
                    cred_type=cred_type,
                    username=username,
                    domain=domain,
                    value_encrypted=b"simulated_encrypted_value",
                    source=source,
                    verified=False,
                    privilege_level=priv_level
                )
                
                harvested_creds.append({
                    "cred_id": cred_id,
                    "username": username,
                    "domain": domain,
                    "type": cred_type.value,
                    "source": source,
                    "privilege": priv_level.value
                })
        
        return harvested_creds
    
    def _generate_fake_username(self) -> str:
        """Generate a fake username for simulation."""
        import random
        prefixes = ["admin", "user", "svc", "backup", "web", "db", "app"]
        suffixes = ["01", "02", "srv", "prod", "dev", "test", ""]
        return f"{random.choice(prefixes)}{random.choice(suffixes)}"
    
    async def _check_goal_achievement(self, goal_name: str) -> None:
        """Check and update goal achievement."""
        try:
            goals = await self.blackboard.get_mission_goals(self._current_mission_id)
            
            if goal_name in goals and goals[goal_name] != "achieved":
                await self.blackboard.update_goal_status(
                    self._current_mission_id,
                    goal_name,
                    "achieved"
                )
                
                # Publish goal achieved event
                event = GoalAchievedEvent(
                    mission_id=UUID(self._current_mission_id),
                    goal=goal_name
                )
                await self.publish_event(event)
                
                self.logger.info(f"🎯 Goal achieved: {goal_name}")
        except Exception as e:
            self.logger.error(f"Error checking goal achievement: {e}")
    
    # ═══════════════════════════════════════════════════════════
    # Event Handling
    # ═══════════════════════════════════════════════════════════
    
    async def on_event(self, event: Dict[str, Any]) -> None:
        """Handle Pub/Sub events."""
        event_type = event.get("event")
        
        if event_type == "new_vuln":
            # New vulnerability - check if exploitable
            vuln_id = event.get("vuln_id")
            exploit_available = event.get("exploit_available", False)
            severity = event.get("severity")
            
            if exploit_available and severity in ("critical", "high"):
                self.logger.info(f"New exploitable vuln {vuln_id} - creating exploit task")
                # Controller would create the exploit task
        
        elif event_type == "new_cred":
            # New credential - might be useful for lateral movement
            privilege_level = event.get("privilege_level")
            
            if privilege_level in ("admin", "domain_admin"):
                self.logger.info("High-privilege credential found")
        
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
        """Get channels for Attack specialist."""
        return [
            self.blackboard.get_channel(mission_id, "tasks"),
            self.blackboard.get_channel(mission_id, "vulns"),
            self.blackboard.get_channel(mission_id, "creds"),
            self.blackboard.get_channel(mission_id, "sessions"),
            self.blackboard.get_channel(mission_id, "control"),
        ]
