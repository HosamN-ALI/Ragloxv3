"""
RAGLOX v3.0 - SSH Command Executor
Executes commands on remote SSH connections with advanced features.

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from enum import Enum

import asyncssh


logger = logging.getLogger("raglox.infrastructure.ssh.command_executor")


class CommandStatus(str, Enum):
    """Command execution status"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    KILLED = "killed"


class CommandResult:
    """Result of command execution"""
    
    def __init__(
        self,
        command: str,
        status: CommandStatus,
        exit_code: int,
        stdout: str,
        stderr: str,
        execution_time: float,
        started_at: datetime,
        ended_at: datetime
    ):
        self.command = command
        self.status = status
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.execution_time = execution_time
        self.started_at = started_at
        self.ended_at = ended_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "command": self.command,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_time": self.execution_time,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat()
        }
    
    @property
    def success(self) -> bool:
        """Check if command succeeded"""
        return self.status == CommandStatus.SUCCESS and self.exit_code == 0


class SSHCommandExecutor:
    """
    SSH Command Executor with advanced features:
    - Async command execution
    - Timeout handling
    - Output streaming
    - Environment variables
    - Working directory support
    - Command chaining
    """
    
    def __init__(
        self,
        connection: asyncssh.SSHClientConnection,
        default_timeout: int = 300,
        default_encoding: str = "utf-8"
    ):
        """
        Initialize SSH Command Executor
        
        Args:
            connection: Active SSH connection
            default_timeout: Default command timeout in seconds
            default_encoding: Default output encoding
        """
        self.connection = connection
        self.default_timeout = default_timeout
        self.default_encoding = default_encoding
        self._command_history: List[CommandResult] = []
    
    async def execute(
        self,
        command: str,
        timeout: Optional[int] = None,
        check: bool = True,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        encoding: Optional[str] = None
    ) -> CommandResult:
        """
        Execute a single command
        
        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            check: Raise exception on non-zero exit code
            env: Environment variables
            cwd: Working directory
            encoding: Output encoding
        
        Returns:
            CommandResult with execution details
        
        Raises:
            asyncssh.ProcessError: If command fails and check=True
            asyncio.TimeoutError: If command times out
        """
        timeout = timeout or self.default_timeout
        encoding = encoding or self.default_encoding
        
        # Prepare command with working directory
        if cwd:
            command = f"cd {cwd} && {command}"
        
        started_at = datetime.utcnow()
        
        try:
            logger.debug(f"Executing command: {command[:100]}...")
            
            # Execute with timeout
            result = await asyncio.wait_for(
                self.connection.run(
                    command,
                    check=False,
                    env=env,
                    encoding=encoding
                ),
                timeout=timeout
            )
            
            ended_at = datetime.utcnow()
            execution_time = (ended_at - started_at).total_seconds()
            
            status = CommandStatus.SUCCESS if result.exit_status == 0 else CommandStatus.FAILED
            
            cmd_result = CommandResult(
                command=command,
                status=status,
                exit_code=result.exit_status,
                stdout=result.stdout,
                stderr=result.stderr,
                execution_time=execution_time,
                started_at=started_at,
                ended_at=ended_at
            )
            
            # Store in history
            self._command_history.append(cmd_result)
            
            logger.info(
                f"Command executed: status={status}, "
                f"exit_code={result.exit_status}, "
                f"duration={execution_time:.2f}s"
            )
            
            # Check exit code if requested
            if check and result.exit_status != 0:
                raise asyncssh.ProcessError(
                    command=command,
                    subsystem=None,
                    exit_status=result.exit_status,
                    exit_signal=None,
                    returncode=result.exit_status,
                    env=env,
                    stdout=result.stdout,
                    stderr=result.stderr
                )
            
            return cmd_result
            
        except asyncio.TimeoutError:
            ended_at = datetime.utcnow()
            execution_time = (ended_at - started_at).total_seconds()
            
            logger.error(f"Command timed out after {timeout}s: {command[:100]}")
            
            cmd_result = CommandResult(
                command=command,
                status=CommandStatus.TIMEOUT,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                execution_time=execution_time,
                started_at=started_at,
                ended_at=ended_at
            )
            
            self._command_history.append(cmd_result)
            raise
        
        except Exception as e:
            ended_at = datetime.utcnow()
            execution_time = (ended_at - started_at).total_seconds()
            
            logger.error(f"Command execution failed: {str(e)}")
            
            cmd_result = CommandResult(
                command=command,
                status=CommandStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                started_at=started_at,
                ended_at=ended_at
            )
            
            self._command_history.append(cmd_result)
            raise
    
    async def execute_script(
        self,
        script_content: str,
        interpreter: str = "/bin/bash",
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None
    ) -> CommandResult:
        """
        Execute a script from content
        
        Args:
            script_content: Script content to execute
            interpreter: Script interpreter
            timeout: Execution timeout
            env: Environment variables
        
        Returns:
            CommandResult
        """
        # Create temporary script file
        temp_script = f"/tmp/raglox_script_{datetime.utcnow().timestamp()}.sh"
        
        try:
            # Write script content
            await self.execute(
                f"cat > {temp_script} << 'RAGLOX_EOF'\n{script_content}\nRAGLOX_EOF",
                timeout=30
            )
            
            # Make executable
            await self.execute(f"chmod +x {temp_script}", timeout=10)
            
            # Execute script
            result = await self.execute(
                f"{interpreter} {temp_script}",
                timeout=timeout,
                env=env
            )
            
            return result
            
        finally:
            # Cleanup
            try:
                await self.execute(f"rm -f {temp_script}", timeout=10, check=False)
            except Exception:
                pass
    
    async def execute_chain(
        self,
        commands: List[str],
        stop_on_error: bool = True,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None
    ) -> List[CommandResult]:
        """
        Execute a chain of commands
        
        Args:
            commands: List of commands to execute
            stop_on_error: Stop execution on first error
            timeout: Timeout per command
            env: Environment variables
        
        Returns:
            List of CommandResult
        """
        results = []
        
        for command in commands:
            try:
                result = await self.execute(
                    command,
                    timeout=timeout,
                    check=stop_on_error,
                    env=env
                )
                results.append(result)
                
                # Stop on error if requested
                if stop_on_error and not result.success:
                    logger.warning(f"Command chain stopped due to error: {command}")
                    break
                    
            except Exception as e:
                logger.error(f"Command chain execution failed: {str(e)}")
                if stop_on_error:
                    raise
        
        return results
    
    async def test_sudo(self, password: Optional[str] = None) -> bool:
        """
        Test sudo access
        
        Args:
            password: Sudo password if required
        
        Returns:
            True if sudo access available
        """
        try:
            if password:
                # Test with password
                result = await self.execute(
                    f"echo '{password}' | sudo -S whoami",
                    timeout=10,
                    check=False
                )
            else:
                # Test without password
                result = await self.execute(
                    "sudo -n whoami",
                    timeout=10,
                    check=False
                )
            
            return result.success and "root" in result.stdout
            
        except Exception:
            return False
    
    async def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information
        
        Returns:
            Dictionary with system details
        """
        info = {}
        
        try:
            # OS info
            uname = await self.execute("uname -a", timeout=10)
            info["os"] = uname.stdout.strip()
            
            # Hostname
            hostname = await self.execute("hostname", timeout=10)
            info["hostname"] = hostname.stdout.strip()
            
            # Kernel
            kernel = await self.execute("uname -r", timeout=10)
            info["kernel"] = kernel.stdout.strip()
            
            # Architecture
            arch = await self.execute("uname -m", timeout=10)
            info["architecture"] = arch.stdout.strip()
            
            # CPU info
            try:
                cpu = await self.execute("nproc", timeout=10)
                info["cpu_cores"] = int(cpu.stdout.strip())
            except Exception:
                info["cpu_cores"] = 0
            
            # Memory info
            try:
                mem = await self.execute(
                    "free -m | grep Mem | awk '{print $2}'",
                    timeout=10
                )
                info["memory_mb"] = int(mem.stdout.strip())
            except Exception:
                info["memory_mb"] = 0
            
            # Disk info
            try:
                disk = await self.execute(
                    "df -h / | tail -1 | awk '{print $2, $3, $5}'",
                    timeout=10
                )
                parts = disk.stdout.strip().split()
                info["disk"] = {
                    "total": parts[0] if len(parts) > 0 else "0",
                    "used": parts[1] if len(parts) > 1 else "0",
                    "usage_percent": parts[2] if len(parts) > 2 else "0%"
                }
            except Exception:
                info["disk"] = {}
            
            # Current user
            user = await self.execute("whoami", timeout=10)
            info["current_user"] = user.stdout.strip()
            
            # Shell
            shell = await self.execute("echo $SHELL", timeout=10)
            info["shell"] = shell.stdout.strip()
            
        except Exception as e:
            logger.error(f"Failed to get system info: {str(e)}")
        
        return info
    
    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get command execution history
        
        Args:
            limit: Maximum number of entries
        
        Returns:
            List of command results as dictionaries
        """
        return [cmd.to_dict() for cmd in self._command_history[-limit:]]
    
    def clear_history(self):
        """Clear command history"""
        self._command_history.clear()
        logger.info("Command history cleared")
