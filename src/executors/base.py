# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Base Executor
# Abstract base class for all command executors
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Type, TypeVar
from uuid import UUID

from .models import (
    ExecutorType,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    ConnectionConfig,
    ShellType,
    Platform,
)

logger = logging.getLogger("raglox.executors.base")

# Type variable for config types
ConfigT = TypeVar('ConfigT', bound=ConnectionConfig)


class BaseExecutor(ABC):
    """
    Abstract base class for all command executors.
    
    This class defines the interface that all executors must implement.
    It provides common functionality like:
    - Connection management
    - Error handling and classification
    - Output sanitization
    - Retry logic
    - Logging
    
    Subclasses must implement:
    - _connect(): Establish connection to target
    - _disconnect(): Close connection
    - _execute_command(): Execute a single command
    - _is_connected(): Check connection status
    
    Usage:
        async with SSHExecutor(config) as executor:
            result = await executor.execute(request)
    """
    
    # Class attributes
    executor_type: ExecutorType = ExecutorType.LOCAL
    supported_platforms: List[Platform] = [Platform.LINUX, Platform.WINDOWS, Platform.MACOS]
    supported_shells: List[ShellType] = [ShellType.BASH, ShellType.SH, ShellType.POWERSHELL]
    
    def __init__(self, config: ConfigT):
        """
        Initialize the executor.
        
        Args:
            config: Connection configuration
        """
        self.config = config
        self.logger = logging.getLogger(f"raglox.executors.{self.executor_type.value}")
        self._connected = False
        self._connection: Any = None
        self._lock = asyncio.Lock()
    
    # ═══════════════════════════════════════════════════════════
    # Context Manager Protocol
    # ═══════════════════════════════════════════════════════════
    
    async def __aenter__(self) -> 'BaseExecutor':
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management
    # ═══════════════════════════════════════════════════════════
    
    async def connect(self) -> bool:
        """
        Connect to the target.
        
        Returns:
            True if connected successfully, False otherwise
        """
        async with self._lock:
            if self._connected:
                return True
            
            try:
                self.logger.info(f"Connecting to {self.config.host}...")
                await self._connect()
                self._connected = True
                self.logger.info(f"Connected to {self.config.host}")
                return True
                
            except Exception as e:
                self.logger.error(f"Connection failed: {e}")
                self._connected = False
                raise
    
    async def disconnect(self) -> None:
        """Disconnect from the target."""
        async with self._lock:
            if not self._connected:
                return
            
            try:
                self.logger.info(f"Disconnecting from {self.config.host}...")
                await self._disconnect()
                self._connected = False
                self.logger.info(f"Disconnected from {self.config.host}")
                
            except Exception as e:
                self.logger.warning(f"Error during disconnect: {e}")
                self._connected = False
    
    @property
    def is_connected(self) -> bool:
        """Check if currently connected."""
        return self._connected and self._is_connected()
    
    # ═══════════════════════════════════════════════════════════
    # Abstract Methods (must be implemented by subclasses)
    # ═══════════════════════════════════════════════════════════
    
    @abstractmethod
    async def _connect(self) -> None:
        """
        Establish connection to the target.
        
        Raises:
            ConnectionError: If connection fails
        """
        pass
    
    @abstractmethod
    async def _disconnect(self) -> None:
        """Close the connection."""
        pass
    
    @abstractmethod
    async def _execute_command(
        self,
        command: str,
        timeout: int = 300,
        working_directory: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        shell: Optional[ShellType] = None,
    ) -> tuple[int, str, str]:
        """
        Execute a command on the target.
        
        Args:
            command: Command to execute
            timeout: Execution timeout in seconds
            working_directory: Working directory for command
            environment: Environment variables
            shell: Shell to use
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
            
        Raises:
            TimeoutError: If command times out
            ConnectionError: If connection is lost
        """
        pass
    
    @abstractmethod
    def _is_connected(self) -> bool:
        """
        Check if the connection is still active.
        
        Returns:
            True if connected, False otherwise
        """
        pass
    
    # ═══════════════════════════════════════════════════════════
    # Main Execution Interface
    # ═══════════════════════════════════════════════════════════
    
    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """
        Execute a command request.
        
        This is the main entry point for command execution.
        It handles:
        - Connection management
        - Error handling and classification
        - Retry logic
        - Output capture and sanitization
        - Cleanup execution
        
        Args:
            request: Execution request
            
        Returns:
            Execution result
        """
        started_at = datetime.utcnow()
        
        # Ensure we're connected
        if not self.is_connected:
            try:
                await self.connect()
            except Exception as e:
                return self._create_error_result(
                    request=request,
                    status=ExecutionStatus.CONNECTION_ERROR,
                    error_type="connection_failed",
                    error_message=str(e),
                    started_at=started_at,
                )
        
        # Execute with retry logic
        result = await self._execute_with_retry(request, started_at)
        
        # Execute cleanup if requested and command succeeded
        if request.cleanup_command and result.success:
            cleanup_result = await self._execute_cleanup(request)
            result.cleanup_executed = True
            result.cleanup_success = cleanup_result.success
            result.cleanup_output = cleanup_result.stdout
        
        return result
    
    async def _execute_with_retry(
        self,
        request: ExecutionRequest,
        started_at: datetime
    ) -> ExecutionResult:
        """
        Execute command with retry logic.
        
        Args:
            request: Execution request
            started_at: When execution started
            
        Returns:
            Execution result
        """
        last_error: Optional[Exception] = None
        
        for attempt in range(self.config.retry_count + 1):
            if attempt > 0:
                self.logger.info(
                    f"Retry attempt {attempt}/{self.config.retry_count} "
                    f"for {request.command[:50]}..."
                )
                await asyncio.sleep(self.config.retry_delay)
            
            try:
                # Execute the command
                exit_code, stdout, stderr = await self._execute_command(
                    command=request.command,
                    timeout=request.timeout,
                    working_directory=request.working_directory,
                    environment=request.environment,
                    shell=request.shell,
                )
                
                completed_at = datetime.utcnow()
                duration_ms = int((completed_at - started_at).total_seconds() * 1000)
                
                # Determine status
                status = ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED
                
                # Sanitize output
                stdout = self._sanitize_output(stdout)
                stderr = self._sanitize_output(stderr)
                
                # Combine output if requested
                output = ""
                if request.combine_stderr:
                    output = f"{stdout}\n{stderr}".strip()
                
                return ExecutionResult(
                    request_id=request.id,
                    status=status,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    output=output,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    executor_type=self.executor_type,
                    host=self.config.host,
                )
                
            except asyncio.TimeoutError:
                last_error = TimeoutError(f"Command timed out after {request.timeout}s")
                
            except ConnectionError as e:
                last_error = e
                # Try to reconnect
                self._connected = False
                try:
                    await self.connect()
                except Exception:
                    pass
                    
            except Exception as e:
                last_error = e
        
        # All retries failed
        return self._create_error_result(
            request=request,
            status=self._classify_error(last_error),
            error_type=type(last_error).__name__,
            error_message=str(last_error),
            started_at=started_at,
        )
    
    async def _execute_cleanup(self, request: ExecutionRequest) -> ExecutionResult:
        """
        Execute cleanup command.
        
        Args:
            request: Original request (with cleanup_command)
            
        Returns:
            Cleanup execution result
        """
        cleanup_request = ExecutionRequest(
            command=request.cleanup_command,
            shell=request.shell,
            working_directory=request.working_directory,
            environment=request.environment,
            timeout=min(60, request.timeout),  # Cleanup should be quick
            task_id=request.task_id,
            mission_id=request.mission_id,
        )
        
        try:
            exit_code, stdout, stderr = await self._execute_command(
                command=cleanup_request.command,
                timeout=cleanup_request.timeout,
                working_directory=cleanup_request.working_directory,
                environment=cleanup_request.environment,
                shell=cleanup_request.shell,
            )
            
            return ExecutionResult(
                request_id=cleanup_request.id,
                status=ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.FAILED,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                executor_type=self.executor_type,
                host=self.config.host,
            )
            
        except Exception as e:
            return ExecutionResult(
                request_id=cleanup_request.id,
                status=ExecutionStatus.FAILED,
                error_message=str(e),
                executor_type=self.executor_type,
                host=self.config.host,
            )
    
    # ═══════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════
    
    def _create_error_result(
        self,
        request: ExecutionRequest,
        status: ExecutionStatus,
        error_type: str,
        error_message: str,
        started_at: datetime,
    ) -> ExecutionResult:
        """Create an error result."""
        completed_at = datetime.utcnow()
        
        return ExecutionResult(
            request_id=request.id,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=int((completed_at - started_at).total_seconds() * 1000),
            error_type=error_type,
            error_message=error_message,
            executor_type=self.executor_type,
            host=self.config.host,
        )
    
    def _classify_error(self, error: Optional[Exception]) -> ExecutionStatus:
        """
        Classify an error into an ExecutionStatus.
        
        Args:
            error: The exception to classify
            
        Returns:
            Appropriate ExecutionStatus
        """
        if error is None:
            return ExecutionStatus.FAILED
        
        error_str = str(error).lower()
        error_type = type(error).__name__.lower()
        
        # Timeout errors
        if "timeout" in error_type or "timeout" in error_str:
            return ExecutionStatus.TIMEOUT
        
        # Connection errors
        if any(kw in error_str for kw in ["connection", "refused", "unreachable", "network"]):
            return ExecutionStatus.CONNECTION_ERROR
        
        # Authentication errors
        if any(kw in error_str for kw in ["auth", "password", "credential", "login", "denied"]):
            return ExecutionStatus.AUTH_ERROR
        
        # Permission errors
        if any(kw in error_str for kw in ["permission", "access denied", "forbidden"]):
            return ExecutionStatus.PERMISSION_DENIED
        
        # Not found errors
        if any(kw in error_str for kw in ["not found", "no such file", "command not found"]):
            return ExecutionStatus.NOT_FOUND
        
        return ExecutionStatus.FAILED
    
    def _sanitize_output(self, output: str) -> str:
        """
        Sanitize command output.
        
        - Remove ANSI escape codes
        - Limit length
        - Handle encoding issues
        
        Args:
            output: Raw output string
            
        Returns:
            Sanitized output
        """
        if not output:
            return ""
        
        # Remove ANSI escape codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)
        
        # Limit length (max 1MB)
        max_length = 1024 * 1024
        if len(output) > max_length:
            output = output[:max_length] + f"\n... [output truncated, {len(output) - max_length} bytes omitted]"
        
        return output.strip()
    
    def _build_command_with_shell(
        self,
        command: str,
        shell: ShellType,
        working_directory: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Build a command string with shell wrapper.
        
        Args:
            command: The command to execute
            shell: Shell type
            working_directory: Working directory
            environment: Environment variables
            
        Returns:
            Shell-wrapped command string
        """
        parts = []
        
        # Add environment variables
        if environment:
            if shell in [ShellType.BASH, ShellType.SH, ShellType.ZSH]:
                for key, value in environment.items():
                    parts.append(f'export {key}="{value}"')
            elif shell == ShellType.POWERSHELL:
                for key, value in environment.items():
                    parts.append(f'$env:{key}="{value}"')
            elif shell == ShellType.CMD:
                for key, value in environment.items():
                    parts.append(f'set {key}={value}')
        
        # Add working directory change
        if working_directory:
            if shell in [ShellType.BASH, ShellType.SH, ShellType.ZSH]:
                parts.append(f'cd "{working_directory}"')
            elif shell == ShellType.POWERSHELL:
                parts.append(f'Set-Location "{working_directory}"')
            elif shell == ShellType.CMD:
                parts.append(f'cd /d "{working_directory}"')
        
        # Add the main command
        parts.append(command)
        
        # Join with appropriate separator
        if shell in [ShellType.BASH, ShellType.SH, ShellType.ZSH]:
            return " && ".join(parts)
        elif shell == ShellType.POWERSHELL:
            return "; ".join(parts)
        elif shell == ShellType.CMD:
            return " & ".join(parts)
        
        return command
    
    # ═══════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════
    
    async def test_connection(self) -> bool:
        """
        Test the connection with a simple command.
        
        Returns:
            True if connection works, False otherwise
        """
        try:
            request = ExecutionRequest(
                command="echo test" if self.executor_type != ExecutorType.WINRM else "Write-Output test",
                timeout=10,
            )
            result = await self.execute(request)
            return result.success
            
        except Exception:
            return False
    
    async def get_platform(self) -> Platform:
        """
        Detect the target platform.
        
        Returns:
            Detected platform
        """
        try:
            # Try uname for Unix-like systems
            request = ExecutionRequest(command="uname -s", timeout=10)
            result = await self.execute(request)
            
            if result.success:
                output = result.stdout.lower().strip()
                if "linux" in output:
                    return Platform.LINUX
                elif "darwin" in output:
                    return Platform.MACOS
            
            # Try Windows check
            request = ExecutionRequest(
                command="echo %OS%",
                timeout=10,
                shell=ShellType.CMD,
            )
            result = await self.execute(request)
            
            if result.success and "windows" in result.stdout.lower():
                return Platform.WINDOWS
            
            return Platform.UNKNOWN
            
        except Exception:
            return Platform.UNKNOWN
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(host={self.config.host}, connected={self._connected})>"
