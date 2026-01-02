# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - RX Module Runner
# Translate and execute RX Modules on target systems
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

from .base import BaseExecutor
from .factory import ExecutorFactory, get_executor_factory
from .models import (
    ExecutorType,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    ConnectionConfig,
    RXModuleRequest,
    RXModuleResult,
    ShellType,
    Platform,
)

logger = logging.getLogger("raglox.executors.runner")


class RXModuleRunner:
    """
    RX Module Runner - Translate and execute RX Modules.
    
    This class bridges the gap between RAGLOX's knowledge base
    (RX Modules) and the execution layer (Executors). It:
    
    1. Takes an RX Module and target configuration
    2. Resolves variable substitutions
    3. Checks prerequisites
    4. Executes the main command
    5. Optionally runs cleanup
    6. Returns structured results for analysis
    
    Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    Specialist Layer                          │
    │  (ReconSpecialist, AttackSpecialist, AnalysisSpecialist)    │
    └──────────────────────────┬──────────────────────────────────┘
                               │ RXModuleRequest
                               ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                    RXModuleRunner                            │
    │  1. Load RX Module from Knowledge                           │
    │  2. Resolve Variables                                        │
    │  3. Check Prerequisites                                      │
    │  4. Build Execution Command                                  │
    │  5. Execute via Executor                                     │
    │  6. Parse Results                                            │
    │  7. Run Cleanup (optional)                                   │
    └──────────────────────────┬──────────────────────────────────┘
                               │ ExecutionRequest
                               ▼
    ┌─────────────────────────────────────────────────────────────┐
    │                    ExecutorFactory                           │
    │  • Selects appropriate executor (SSH/WinRM/Local)           │
    │  • Manages connections                                       │
    └─────────────────────────────────────────────────────────────┘
    
    Usage:
        from src.core.knowledge import EmbeddedKnowledge
        from src.executors.runner import RXModuleRunner
        
        knowledge = EmbeddedKnowledge()
        knowledge.load()
        
        runner = RXModuleRunner(knowledge=knowledge)
        
        result = await runner.execute_module(
            RXModuleRequest(
                rx_module_id="rx-t1003-001",
                target_host="192.168.1.100",
                target_platform=Platform.LINUX,
                variables={"username": "test"},
                connection_config=ssh_config,
            )
        )
        
        if result.success:
            print(result.main_result.stdout)
    """
    
    def __init__(
        self,
        knowledge: Optional[Any] = None,  # EmbeddedKnowledge
        factory: Optional[ExecutorFactory] = None,
        default_timeout: int = 300,
        check_prerequisites: bool = True,
        run_cleanup_on_failure: bool = False,
    ):
        """
        Initialize RX Module Runner.
        
        Args:
            knowledge: EmbeddedKnowledge instance (lazy-loaded if None)
            factory: ExecutorFactory instance (uses global if None)
            default_timeout: Default execution timeout
            check_prerequisites: Check prerequisites before execution
            run_cleanup_on_failure: Run cleanup even if execution fails
        """
        self._knowledge = knowledge
        self._factory = factory
        self.default_timeout = default_timeout
        self.check_prerequisites = check_prerequisites
        self.run_cleanup_on_failure = run_cleanup_on_failure
        
        self.logger = logging.getLogger("raglox.executors.runner")
        
        # Statistics
        self._stats = {
            "executions": 0,
            "successes": 0,
            "failures": 0,
            "timeouts": 0,
            "prereq_failures": 0,
        }
    
    @property
    def knowledge(self) -> Any:
        """Get knowledge base (lazy-load if needed)."""
        if self._knowledge is None:
            from ..core.knowledge import EmbeddedKnowledge
            self._knowledge = EmbeddedKnowledge()
            if not self._knowledge._rx_modules:
                self._knowledge.load()
        return self._knowledge
    
    @property
    def factory(self) -> ExecutorFactory:
        """Get executor factory."""
        if self._factory is None:
            self._factory = get_executor_factory()
        return self._factory
    
    # ═══════════════════════════════════════════════════════════
    # Main Execution Interface
    # ═══════════════════════════════════════════════════════════
    
    async def execute_module(
        self,
        request: RXModuleRequest,
    ) -> RXModuleResult:
        """
        Execute an RX Module.
        
        This is the main entry point for module execution.
        
        Args:
            request: RX Module execution request
            
        Returns:
            RX Module execution result
        """
        started_at = datetime.utcnow()
        self._stats["executions"] += 1
        
        # Initialize result
        result = RXModuleResult(
            request_id=request.id,
            rx_module_id=request.rx_module_id,
            success=False,
            status=ExecutionStatus.FAILED,
            started_at=started_at,
        )
        
        try:
            # 1. Load RX Module from knowledge base
            rx_module = self._get_rx_module(request.rx_module_id)
            if rx_module is None:
                result.status = ExecutionStatus.NOT_FOUND
                result.error_context = {
                    "error_type": "module_not_found",
                    "error_message": f"RX Module not found: {request.rx_module_id}",
                }
                return result
            
            # 2. Validate platform compatibility
            if not self._is_platform_compatible(rx_module, request.target_platform):
                result.status = ExecutionStatus.FAILED
                result.error_context = {
                    "error_type": "platform_incompatible",
                    "error_message": f"Module not compatible with {request.target_platform.value}",
                    "supported_platforms": rx_module.execution.platforms,
                }
                return result
            
            # 3. Get executor
            executor = await self.factory.get_executor(
                target_host=request.target_host,
                target_platform=request.target_platform,
                connection_config=request.connection_config,
            )
            
            try:
                # 4. Check prerequisites (if enabled)
                if request.check_prerequisites and self.check_prerequisites:
                    prereq_results = await self._check_prerequisites(
                        executor, rx_module, request
                    )
                    result.prerequisite_results = prereq_results
                    
                    if not all(r.success for r in prereq_results):
                        result.prerequisites_passed = False
                        result.status = ExecutionStatus.FAILED
                        result.error_context = {
                            "error_type": "prerequisite_failed",
                            "error_message": "One or more prerequisites failed",
                        }
                        self._stats["prereq_failures"] += 1
                        return result
                
                # 5. Build and execute main command
                command = self._build_command(rx_module, request.variables)
                shell = self._get_shell_type(rx_module, request.target_platform)
                
                main_request = ExecutionRequest(
                    command=command,
                    shell=shell,
                    timeout=request.timeout or self.default_timeout,
                    elevated=rx_module.execution.elevation_required,
                    task_id=request.task_id,
                    mission_id=request.mission_id,
                    rx_module_id=request.rx_module_id,
                )
                
                main_result = await executor.execute(main_request)
                result.main_result = main_result
                
                # 6. Parse output
                result.parsed_data = self._parse_output(
                    rx_module, main_result.stdout, main_result.stderr
                )
                
                # 7. Run cleanup (if requested and applicable)
                if request.run_cleanup or (self.run_cleanup_on_failure and not main_result.success):
                    if rx_module.execution.cleanup_command:
                        cleanup_result = await self._run_cleanup(
                            executor, rx_module, request
                        )
                        result.cleanup_result = cleanup_result
                
                # 8. Determine final status
                if main_result.success:
                    result.success = True
                    result.status = ExecutionStatus.SUCCESS
                    self._stats["successes"] += 1
                else:
                    result.status = main_result.status
                    result.error_context = self._build_error_context(
                        rx_module, main_result
                    )
                    self._stats["failures"] += 1
                
            finally:
                # Release executor back to pool
                await self.factory.release_executor(executor)
            
        except asyncio.TimeoutError:
            result.status = ExecutionStatus.TIMEOUT
            result.error_context = {
                "error_type": "timeout",
                "error_message": f"Execution timed out after {request.timeout}s",
            }
            self._stats["timeouts"] += 1
            
        except ConnectionError as e:
            result.status = ExecutionStatus.CONNECTION_ERROR
            result.error_context = {
                "error_type": "connection",
                "error_message": str(e),
            }
            
        except Exception as e:
            result.status = ExecutionStatus.FAILED
            result.error_context = {
                "error_type": "unexpected",
                "error_message": str(e),
                "error_class": type(e).__name__,
            }
            self.logger.exception(f"Unexpected error executing {request.rx_module_id}")
        
        # Finalize result
        result.completed_at = datetime.utcnow()
        result.total_duration_ms = int(
            (result.completed_at - started_at).total_seconds() * 1000
        )
        
        return result
    
    async def execute_modules_parallel(
        self,
        requests: List[RXModuleRequest],
        max_concurrent: int = 5,
    ) -> List[RXModuleResult]:
        """
        Execute multiple RX Modules in parallel.
        
        Args:
            requests: List of module requests
            max_concurrent: Maximum concurrent executions
            
        Returns:
            List of results (same order as requests)
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_with_semaphore(req: RXModuleRequest) -> RXModuleResult:
            async with semaphore:
                return await self.execute_module(req)
        
        tasks = [execute_with_semaphore(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to failed results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(RXModuleResult(
                    request_id=requests[i].id,
                    rx_module_id=requests[i].rx_module_id,
                    success=False,
                    status=ExecutionStatus.FAILED,
                    error_context={
                        "error_type": "exception",
                        "error_message": str(result),
                    },
                ))
            else:
                final_results.append(result)
        
        return final_results
    
    # ═══════════════════════════════════════════════════════════
    # RX Module Handling
    # ═══════════════════════════════════════════════════════════
    
    def _get_rx_module(self, rx_module_id: str) -> Optional[Any]:
        """
        Get RX Module from knowledge base.
        
        Args:
            rx_module_id: Module ID (e.g., rx-t1003-001)
            
        Returns:
            RXModule or None if not found
        """
        return self.knowledge.get_rx_module(rx_module_id)
    
    def _is_platform_compatible(
        self,
        rx_module: Any,
        target_platform: Platform,
    ) -> bool:
        """
        Check if module is compatible with target platform.
        
        Args:
            rx_module: RX Module
            target_platform: Target platform
            
        Returns:
            True if compatible
        """
        platforms = [p.lower() for p in rx_module.execution.platforms]
        target = target_platform.value.lower()
        
        # Direct match
        if target in platforms:
            return True
        
        # Handle variations
        platform_aliases = {
            "linux": ["linux", "unix"],
            "windows": ["windows"],
            "macos": ["macos", "darwin", "osx"],
        }
        
        for platform in platforms:
            if target in platform_aliases.get(platform, []):
                return True
        
        return False
    
    # ═══════════════════════════════════════════════════════════
    # Command Building
    # ═══════════════════════════════════════════════════════════
    
    def _build_command(
        self,
        rx_module: Any,
        variables: Dict[str, str],
    ) -> str:
        """
        Build the execution command with variable substitution.
        
        Args:
            rx_module: RX Module
            variables: Variable values to substitute
            
        Returns:
            Command string with variables substituted
        """
        command = rx_module.execution.command
        
        # Build variable map with defaults
        var_map = {}
        for var in rx_module.variables:
            # Use provided value or default
            value = variables.get(var.name, var.default_value or "")
            var_map[var.name] = value
        
        # Substitute variables
        # Handle formats: #{var_name}, ${var_name}, $var_name
        for var_name, value in var_map.items():
            # Pattern: #{var_name}
            pattern1 = "#{" + var_name + "}"
            command = command.replace(pattern1, str(value))
            
            # Pattern: ${var_name}
            pattern2 = "${" + var_name + "}"
            command = command.replace(pattern2, str(value))
            
            # Pattern: $var_name (simple)
            pattern3 = "$" + var_name
            command = command.replace(pattern3, str(value))
            
            # Also handle regex-based interpolation for edge cases
            command = re.sub(
                r'#\{' + re.escape(var_name) + r'\}',
                str(value),
                command
            )
        
        return command
    
    def _get_shell_type(
        self,
        rx_module: Any,
        target_platform: Platform,
    ) -> ShellType:
        """
        Determine shell type based on module and platform.
        
        Args:
            rx_module: RX Module
            target_platform: Target platform
            
        Returns:
            Appropriate ShellType
        """
        executor_type = rx_module.execution.executor_type.lower()
        
        # Map executor types to shells
        executor_shell_map = {
            "powershell": ShellType.POWERSHELL,
            "command_prompt": ShellType.CMD,
            "cmd": ShellType.CMD,
            "bash": ShellType.BASH,
            "sh": ShellType.SH,
        }
        
        if executor_type in executor_shell_map:
            return executor_shell_map[executor_type]
        
        # Default based on platform
        if target_platform == Platform.WINDOWS:
            return ShellType.POWERSHELL
        else:
            return ShellType.BASH
    
    # ═══════════════════════════════════════════════════════════
    # Prerequisites
    # ═══════════════════════════════════════════════════════════
    
    async def _check_prerequisites(
        self,
        executor: BaseExecutor,
        rx_module: Any,
        request: RXModuleRequest,
    ) -> List[ExecutionResult]:
        """
        Check module prerequisites.
        
        Args:
            executor: Executor to use
            rx_module: RX Module
            request: Original request
            
        Returns:
            List of prerequisite check results
        """
        results = []
        
        for prereq in rx_module.prerequisites:
            if not prereq.check_command:
                continue
            
            # Substitute variables in check command
            check_cmd = self._build_command(
                rx_module,
                {**{v.name: v.default_value or "" for v in rx_module.variables},
                 **request.variables}
            )
            
            prereq_request = ExecutionRequest(
                command=prereq.check_command,
                timeout=60,  # Prerequisites should be quick
            )
            
            result = await executor.execute(prereq_request)
            results.append(result)
            
            # If failed and install command exists, try to install
            if not result.success and prereq.install_command:
                self.logger.info(f"Prerequisite failed, attempting install...")
                install_request = ExecutionRequest(
                    command=prereq.install_command,
                    timeout=120,
                    elevated=True,  # Installs usually need elevation
                )
                install_result = await executor.execute(install_request)
                
                if install_result.success:
                    # Re-check prerequisite
                    recheck_result = await executor.execute(prereq_request)
                    results[-1] = recheck_result  # Replace with re-check result
        
        return results
    
    # ═══════════════════════════════════════════════════════════
    # Cleanup
    # ═══════════════════════════════════════════════════════════
    
    async def _run_cleanup(
        self,
        executor: BaseExecutor,
        rx_module: Any,
        request: RXModuleRequest,
    ) -> ExecutionResult:
        """
        Run cleanup command.
        
        Args:
            executor: Executor to use
            rx_module: RX Module
            request: Original request
            
        Returns:
            Cleanup execution result
        """
        cleanup_cmd = rx_module.execution.cleanup_command
        
        # Substitute variables
        cleanup_cmd = self._build_command(rx_module, request.variables)
        
        cleanup_request = ExecutionRequest(
            command=cleanup_cmd,
            timeout=60,
            task_id=request.task_id,
            mission_id=request.mission_id,
        )
        
        return await executor.execute(cleanup_request)
    
    # ═══════════════════════════════════════════════════════════
    # Output Parsing
    # ═══════════════════════════════════════════════════════════
    
    def _parse_output(
        self,
        rx_module: Any,
        stdout: str,
        stderr: str,
    ) -> Dict[str, Any]:
        """
        Parse command output for structured data.
        
        Different modules may have different output formats.
        This method extracts useful information.
        
        Args:
            rx_module: RX Module
            stdout: Standard output
            stderr: Standard error
            
        Returns:
            Parsed data dictionary
        """
        parsed = {
            "stdout_lines": stdout.strip().split('\n') if stdout else [],
            "stderr_lines": stderr.strip().split('\n') if stderr else [],
        }
        
        # Try to extract common patterns
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        parsed["ip_addresses"] = list(set(re.findall(ip_pattern, stdout)))
        
        # Hostnames
        hostname_pattern = r'\b[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\b'
        parsed["hostnames"] = list(set(re.findall(hostname_pattern, stdout)))[:10]
        
        # Usernames (common formats)
        username_patterns = [
            r'(?:user|username|User|Username):\s*(\S+)',
            r'([A-Za-z0-9]+)\\([A-Za-z0-9]+)',  # DOMAIN\user
        ]
        usernames = []
        for pattern in username_patterns:
            matches = re.findall(pattern, stdout)
            usernames.extend(matches if isinstance(matches[0] if matches else '', str) 
                           else [m[-1] for m in matches])
        parsed["usernames"] = list(set(usernames))[:20]
        
        # Ports
        port_pattern = r'\b(?:port|PORT)\s*[:\s]\s*(\d{1,5})\b'
        parsed["ports"] = list(set(int(p) for p in re.findall(port_pattern, stdout) if int(p) < 65536))
        
        # Hashes (NTLM, MD5, SHA1, etc.)
        hash_patterns = {
            "ntlm": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b',
        }
        parsed["hashes"] = {}
        for hash_type, pattern in hash_patterns.items():
            matches = re.findall(pattern, stdout)
            if matches:
                parsed["hashes"][hash_type] = list(set(matches))[:10]
        
        return parsed
    
    # ═══════════════════════════════════════════════════════════
    # Error Context
    # ═══════════════════════════════════════════════════════════
    
    def _build_error_context(
        self,
        rx_module: Any,
        result: ExecutionResult,
    ) -> Dict[str, Any]:
        """
        Build error context for failed executions.
        
        This context is used by the Reflexion pattern for analysis.
        
        Args:
            rx_module: RX Module
            result: Failed execution result
            
        Returns:
            Error context dictionary
        """
        error_type = "unknown"
        error_message = result.error_message or ""
        
        # Classify error
        stderr_lower = result.stderr.lower() if result.stderr else ""
        
        # Defense detection
        defense_indicators = [
            ("av", "antivirus"),
            ("defender", "windows_defender"),
            ("edr", "edr_detection"),
            ("blocked", "blocked_by_policy"),
            ("quarantine", "quarantined"),
            ("access denied", "access_denied"),
            ("permission", "permission_denied"),
        ]
        
        detected_defenses = []
        for indicator, defense_type in defense_indicators:
            if indicator in stderr_lower:
                detected_defenses.append(defense_type)
                error_type = "defense"
        
        # Network errors
        network_indicators = ["connection", "timeout", "network", "unreachable"]
        if any(ind in stderr_lower for ind in network_indicators):
            error_type = "network"
        
        # Command errors
        if result.exit_code in [127, 1]:
            if "not found" in stderr_lower or "not recognized" in stderr_lower:
                error_type = "command_not_found"
        
        context = {
            "error_type": error_type,
            "error_message": error_message or stderr_lower[:500],
            "error_code": result.exit_code,
            "module_used": rx_module.rx_module_id,
            "technique_id": rx_module.technique_id,
            "detected_defenses": detected_defenses,
            "retry_recommended": error_type in ["network", "timeout"],
            "alternative_techniques": [],  # To be filled by analysis
        }
        
        return context
    
    # ═══════════════════════════════════════════════════════════
    # Statistics and Utilities
    # ═══════════════════════════════════════════════════════════
    
    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics."""
        total = self._stats["executions"]
        return {
            **self._stats,
            "success_rate": self._stats["successes"] / total if total > 0 else 0,
        }
    
    def reset_stats(self) -> None:
        """Reset execution statistics."""
        self._stats = {
            "executions": 0,
            "successes": 0,
            "failures": 0,
            "timeouts": 0,
            "prereq_failures": 0,
        }
    
    async def test_module(
        self,
        rx_module_id: str,
        target_platform: Platform = Platform.LINUX,
    ) -> Dict[str, Any]:
        """
        Test if a module is available and properly configured.
        
        Args:
            rx_module_id: Module ID to test
            target_platform: Target platform
            
        Returns:
            Test results dictionary
        """
        result = {
            "module_id": rx_module_id,
            "found": False,
            "platform_compatible": False,
            "has_command": False,
            "has_cleanup": False,
            "variables": [],
            "prerequisites": [],
        }
        
        rx_module = self._get_rx_module(rx_module_id)
        if rx_module is None:
            return result
        
        result["found"] = True
        result["platform_compatible"] = self._is_platform_compatible(
            rx_module, target_platform
        )
        result["has_command"] = bool(rx_module.execution.command)
        result["has_cleanup"] = bool(rx_module.execution.cleanup_command)
        result["variables"] = [
            {"name": v.name, "required": v.default_value is None}
            for v in rx_module.variables
        ]
        result["prerequisites"] = [
            {"description": p.description, "has_check": bool(p.check_command)}
            for p in rx_module.prerequisites
        ]
        
        return result


# ═══════════════════════════════════════════════════════════════
# Global Runner Instance
# ═══════════════════════════════════════════════════════════════

_global_runner: Optional[RXModuleRunner] = None


def get_rx_module_runner() -> RXModuleRunner:
    """
    Get the global RX Module Runner instance.
    
    Returns:
        Global RXModuleRunner instance
    """
    global _global_runner
    
    if _global_runner is None:
        _global_runner = RXModuleRunner()
    
    return _global_runner


async def execute_rx_module(
    rx_module_id: str,
    target_host: str,
    target_platform: Platform,
    variables: Optional[Dict[str, str]] = None,
    connection_config: Optional[ConnectionConfig] = None,
) -> RXModuleResult:
    """
    Convenience function to execute an RX Module.
    
    Uses the global runner instance.
    
    Args:
        rx_module_id: Module ID
        target_host: Target host
        target_platform: Target platform
        variables: Variable substitutions
        connection_config: Connection configuration
        
    Returns:
        Module execution result
    """
    runner = get_rx_module_runner()
    
    request = RXModuleRequest(
        rx_module_id=rx_module_id,
        target_host=target_host,
        target_platform=target_platform,
        variables=variables or {},
        connection_config=connection_config,
    )
    
    return await runner.execute_module(request)
