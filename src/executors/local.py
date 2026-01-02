# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Local Executor
# Execute commands on the local system
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
import os
import platform
import shlex
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseExecutor
from .models import (
    ExecutorType,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    LocalConfig,
    ShellType,
    Platform,
)

logger = logging.getLogger("raglox.executors.local")


class LocalExecutor(BaseExecutor):
    """
    Local Executor - Execute commands on the local system.
    
    This executor runs commands directly on the machine where RAGLOX
    is running. Useful for:
    - Testing and development
    - Local reconnaissance
    - Executing post-exploitation tools locally
    - Running container-based attacks
    
    Supports:
    - Bash, sh, zsh shells (Unix/Linux/macOS)
    - PowerShell and CMD (Windows)
    - Sudo elevation (Unix)
    - Environment variable injection
    - Working directory specification
    
    Usage:
        config = LocalConfig(shell=ShellType.BASH)
        async with LocalExecutor(config) as executor:
            result = await executor.execute(
                ExecutionRequest(command="whoami")
            )
            print(result.stdout)
    """
    
    executor_type = ExecutorType.LOCAL
    supported_platforms = [Platform.LINUX, Platform.WINDOWS, Platform.MACOS]
    supported_shells = [
        ShellType.BASH,
        ShellType.SH,
        ShellType.ZSH,
        ShellType.POWERSHELL,
        ShellType.CMD,
        ShellType.PYTHON,
    ]
    
    def __init__(self, config: Optional[LocalConfig] = None):
        """
        Initialize local executor.
        
        Args:
            config: Local execution configuration
        """
        if config is None:
            config = LocalConfig()
        
        super().__init__(config)
        self.config: LocalConfig = config
        
        # Detect platform
        self._platform = self._detect_platform()
        
        # Set default shell based on platform
        if self.config.shell is None:
            if self._platform == Platform.WINDOWS:
                self.config.shell = ShellType.POWERSHELL
            else:
                self.config.shell = ShellType.BASH
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management (trivial for local)
    # ═══════════════════════════════════════════════════════════
    
    async def _connect(self) -> None:
        """Connect (no-op for local executor)."""
        # Local execution doesn't need a connection
        self.logger.debug("Local executor ready")
    
    async def _disconnect(self) -> None:
        """Disconnect (no-op for local executor)."""
        self.logger.debug("Local executor disconnected")
    
    def _is_connected(self) -> bool:
        """Always connected for local executor."""
        return True
    
    # ═══════════════════════════════════════════════════════════
    # Command Execution
    # ═══════════════════════════════════════════════════════════
    
    async def _execute_command(
        self,
        command: str,
        timeout: int = 300,
        working_directory: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
        shell: Optional[ShellType] = None,
    ) -> Tuple[int, str, str]:
        """
        Execute a command locally.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            working_directory: Working directory
            environment: Additional environment variables
            shell: Shell to use
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        shell = shell or self.config.shell
        working_directory = working_directory or self.config.working_directory
        
        # Build environment
        env = os.environ.copy()
        if self.config.environment:
            env.update(self.config.environment)
        if environment:
            env.update(environment)
        
        # Build command with shell wrapper
        full_command = self._build_shell_command(command, shell)
        
        # Add sudo if needed
        if self.config.sudo and shell not in [ShellType.CMD, ShellType.POWERSHELL]:
            full_command = self._add_sudo(full_command, shell)
        
        self.logger.debug(f"Executing: {full_command[:100]}...")
        
        try:
            # Create subprocess
            process = await asyncio.create_subprocess_shell(
                full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_directory,
                env=env,
            )
            
            # Wait for completion with timeout
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill the process on timeout
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
                raise
            
            # Decode output
            stdout = self._decode_output(stdout_bytes)
            stderr = self._decode_output(stderr_bytes)
            
            return process.returncode or 0, stdout, stderr
            
        except asyncio.TimeoutError:
            raise TimeoutError(f"Command timed out after {timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"Command execution failed: {e}")
    
    def _build_shell_command(self, command: str, shell: ShellType) -> str:
        """
        Build the shell command string.
        
        Args:
            command: Raw command
            shell: Shell type
            
        Returns:
            Shell-wrapped command
        """
        if shell == ShellType.BASH:
            return f"bash -c {shlex.quote(command)}"
        elif shell == ShellType.SH:
            return f"sh -c {shlex.quote(command)}"
        elif shell == ShellType.ZSH:
            return f"zsh -c {shlex.quote(command)}"
        elif shell == ShellType.POWERSHELL:
            # Escape for PowerShell
            escaped = command.replace('"', '`"')
            return f'powershell -NoProfile -NonInteractive -Command "{escaped}"'
        elif shell == ShellType.CMD:
            return f'cmd /c "{command}"'
        elif shell == ShellType.PYTHON:
            escaped = command.replace('"', '\\"')
            return f'python -c "{escaped}"'
        else:
            return command
    
    def _add_sudo(self, command: str, shell: ShellType) -> str:
        """
        Add sudo to command if needed.
        
        Args:
            command: The command
            shell: Shell type
            
        Returns:
            Command with sudo
        """
        if self.config.sudo_password:
            password = self.config.sudo_password.get_secret_value()
            # Use echo to pipe password to sudo
            return f"echo {shlex.quote(password)} | sudo -S {command}"
        else:
            return f"sudo {command}"
    
    def _decode_output(self, output: bytes) -> str:
        """
        Decode output bytes to string.
        
        Args:
            output: Raw bytes
            
        Returns:
            Decoded string
        """
        if not output:
            return ""
        
        # Try common encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
        
        for encoding in encodings:
            try:
                return output.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # Last resort: decode with replacement
        return output.decode('utf-8', errors='replace')
    
    def _detect_platform(self) -> Platform:
        """Detect the local platform."""
        system = platform.system().lower()
        
        if system == 'linux':
            return Platform.LINUX
        elif system == 'darwin':
            return Platform.MACOS
        elif system == 'windows':
            return Platform.WINDOWS
        else:
            return Platform.UNKNOWN
    
    # ═══════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════
    
    async def run_script(
        self,
        script: str,
        interpreter: str = "bash",
        timeout: int = 300,
    ) -> ExecutionResult:
        """
        Run a multi-line script.
        
        Args:
            script: Multi-line script content
            interpreter: Script interpreter (bash, python, etc.)
            timeout: Execution timeout
            
        Returns:
            Execution result
        """
        # For bash scripts
        if interpreter == "bash":
            command = f"bash -s <<'RAGLOX_SCRIPT'\n{script}\nRAGLOX_SCRIPT"
        elif interpreter == "python":
            # Escape the script for Python
            escaped_script = script.replace("'", "'\"'\"'")
            command = f"python -c '{escaped_script}'"
        elif interpreter == "powershell":
            escaped_script = script.replace("'", "''")
            command = f"powershell -Command '{escaped_script}'"
        else:
            command = script
        
        request = ExecutionRequest(
            command=command,
            timeout=timeout,
        )
        
        return await self.execute(request)
    
    async def file_exists(self, path: str) -> bool:
        """
        Check if a file exists locally.
        
        Args:
            path: File path
            
        Returns:
            True if exists, False otherwise
        """
        if self._platform == Platform.WINDOWS:
            command = f'Test-Path "{path}"'
            shell = ShellType.POWERSHELL
        else:
            command = f'test -e "{path}" && echo "true" || echo "false"'
            shell = ShellType.BASH
        
        request = ExecutionRequest(command=command, shell=shell, timeout=10)
        result = await self.execute(request)
        
        return result.success and "true" in result.stdout.lower()
    
    async def read_file(self, path: str) -> Optional[str]:
        """
        Read a file's contents.
        
        Args:
            path: File path
            
        Returns:
            File contents or None if failed
        """
        if self._platform == Platform.WINDOWS:
            command = f'Get-Content "{path}" -Raw'
            shell = ShellType.POWERSHELL
        else:
            command = f'cat "{path}"'
            shell = ShellType.BASH
        
        request = ExecutionRequest(command=command, shell=shell, timeout=30)
        result = await self.execute(request)
        
        return result.stdout if result.success else None
    
    async def write_file(self, path: str, content: str) -> bool:
        """
        Write content to a file.
        
        Args:
            path: File path
            content: Content to write
            
        Returns:
            True if successful
        """
        if self._platform == Platform.WINDOWS:
            # Escape for PowerShell
            escaped = content.replace("'", "''")
            command = f"Set-Content -Path '{path}' -Value '{escaped}'"
            shell = ShellType.POWERSHELL
        else:
            # Use heredoc for bash
            command = f"cat > '{path}' <<'RAGLOX_EOF'\n{content}\nRAGLOX_EOF"
            shell = ShellType.BASH
        
        request = ExecutionRequest(command=command, shell=shell, timeout=30)
        result = await self.execute(request)
        
        return result.success
    
    async def get_system_info(self) -> Dict[str, str]:
        """
        Get local system information.
        
        Returns:
            Dictionary with system info
        """
        info = {
            "platform": self._platform.value,
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
        }
        
        # Get additional info based on platform
        if self._platform in [Platform.LINUX, Platform.MACOS]:
            result = await self.execute(ExecutionRequest(command="id", timeout=10))
            if result.success:
                info["user_info"] = result.stdout.strip()
            
            result = await self.execute(ExecutionRequest(command="uname -a", timeout=10))
            if result.success:
                info["kernel"] = result.stdout.strip()
        
        elif self._platform == Platform.WINDOWS:
            result = await self.execute(ExecutionRequest(
                command="whoami /all",
                shell=ShellType.CMD,
                timeout=10
            ))
            if result.success:
                info["user_info"] = result.stdout.strip()[:500]
        
        return info
    
    async def get_network_interfaces(self) -> List[Dict[str, str]]:
        """
        Get network interfaces.
        
        Returns:
            List of interface dictionaries
        """
        interfaces = []
        
        if self._platform in [Platform.LINUX, Platform.MACOS]:
            result = await self.execute(ExecutionRequest(
                command="ip addr show 2>/dev/null || ifconfig",
                timeout=10
            ))
        elif self._platform == Platform.WINDOWS:
            result = await self.execute(ExecutionRequest(
                command="ipconfig /all",
                shell=ShellType.CMD,
                timeout=10
            ))
        else:
            return interfaces
        
        if result.success:
            # Parse output (basic parsing)
            interfaces.append({
                "raw": result.stdout[:2000]  # Truncate for safety
            })
        
        return interfaces


# ═══════════════════════════════════════════════════════════════
# Convenience Function
# ═══════════════════════════════════════════════════════════════

async def run_local(
    command: str,
    shell: ShellType = ShellType.BASH,
    timeout: int = 300,
    sudo: bool = False,
) -> ExecutionResult:
    """
    Convenience function to run a local command.
    
    Args:
        command: Command to execute
        shell: Shell type
        timeout: Timeout in seconds
        sudo: Use sudo
        
    Returns:
        Execution result
    """
    config = LocalConfig(shell=shell, sudo=sudo)
    async with LocalExecutor(config) as executor:
        return await executor.execute(
            ExecutionRequest(command=command, timeout=timeout)
        )
