# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - SSH Executor
# Execute commands via SSH on remote Linux/Unix systems
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
import os
import shlex
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseExecutor
from .models import (
    ExecutorType,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    SSHConfig,
    ShellType,
    Platform,
)

logger = logging.getLogger("raglox.executors.ssh")

# Try to import asyncssh (optional dependency)
try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False
    logger.warning("asyncssh not installed. SSH executor will not be available.")


class SSHExecutor(BaseExecutor):
    """
    SSH Executor - Execute commands via SSH.
    
    This executor connects to remote Linux/Unix systems via SSH and
    executes commands. Useful for:
    - Remote reconnaissance
    - Post-exploitation on compromised hosts
    - Lateral movement execution
    - Remote tool execution
    
    Supports:
    - Password authentication
    - Private key authentication
    - Agent forwarding
    - Sudo elevation
    - Multiple concurrent sessions
    - Connection pooling
    
    Requirements:
    - asyncssh library: pip install asyncssh
    
    Usage:
        config = SSHConfig(
            host="192.168.1.100",
            username="root",
            password=SecretStr("password"),
        )
        async with SSHExecutor(config) as executor:
            result = await executor.execute(
                ExecutionRequest(command="id")
            )
            print(result.stdout)
    """
    
    executor_type = ExecutorType.SSH
    supported_platforms = [Platform.LINUX, Platform.MACOS]
    supported_shells = [ShellType.BASH, ShellType.SH, ShellType.ZSH]
    
    def __init__(self, config: SSHConfig):
        """
        Initialize SSH executor.
        
        Args:
            config: SSH connection configuration
            
        Raises:
            ImportError: If asyncssh is not installed
        """
        if not ASYNCSSH_AVAILABLE:
            raise ImportError(
                "asyncssh is required for SSH executor. "
                "Install with: pip install asyncssh"
            )
        
        super().__init__(config)
        self.config: SSHConfig = config
        self._conn: Optional['asyncssh.SSHClientConnection'] = None
        self._sftp: Optional['asyncssh.SFTPClient'] = None
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management
    # ═══════════════════════════════════════════════════════════
    
    async def _connect(self) -> None:
        """Establish SSH connection."""
        connect_options = {
            'host': self.config.host,
            'port': self.config.port,
            'username': self.config.username,
            'known_hosts': None if not self.config.host_key_checking else self.config.known_hosts_file,
            'compression_algs': ['zlib@openssh.com', 'zlib', 'none'] if self.config.compression else None,
            'keepalive_interval': self.config.keepalive_interval,
        }
        
        # Authentication options
        if self.config.password:
            connect_options['password'] = self.config.password.get_secret_value()
        
        if self.config.private_key:
            key_path = Path(self.config.private_key).expanduser()
            if key_path.exists():
                passphrase = None
                if self.config.private_key_passphrase:
                    passphrase = self.config.private_key_passphrase.get_secret_value()
                connect_options['client_keys'] = [str(key_path)]
                if passphrase:
                    connect_options['passphrase'] = passphrase
        
        try:
            self._conn = await asyncio.wait_for(
                asyncssh.connect(**connect_options),
                timeout=self.config.timeout
            )
            self.logger.info(f"SSH connection established to {self.config.host}")
            
        except asyncio.TimeoutError:
            raise ConnectionError(f"SSH connection timed out after {self.config.timeout}s")
        except asyncssh.DisconnectError as e:
            raise ConnectionError(f"SSH disconnected: {e}")
        except asyncssh.PermissionDenied:
            raise ConnectionError("SSH authentication failed: Permission denied")
        except Exception as e:
            raise ConnectionError(f"SSH connection failed: {e}")
    
    async def _disconnect(self) -> None:
        """Close SSH connection."""
        if self._sftp:
            self._sftp.exit()
            self._sftp = None
        
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None
    
    def _is_connected(self) -> bool:
        """Check if SSH connection is active."""
        return self._conn is not None and not self._conn.is_closed()
    
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
        Execute a command via SSH.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            working_directory: Remote working directory
            environment: Environment variables
            shell: Shell to use
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self._is_connected():
            raise ConnectionError("SSH not connected")
        
        shell = shell or self.config.shell
        
        # Build the full command
        full_command = self._build_remote_command(
            command=command,
            shell=shell,
            working_directory=working_directory,
            environment=environment,
        )
        
        # Add sudo if needed
        if self.config.sudo:
            full_command = self._add_sudo(full_command)
        
        self.logger.debug(f"SSH executing: {full_command[:100]}...")
        
        try:
            # Execute command
            result = await asyncio.wait_for(
                self._conn.run(
                    full_command,
                    check=False,
                    encoding=None,  # Get raw bytes
                ),
                timeout=timeout
            )
            
            # Decode output
            stdout = self._decode_output(result.stdout or b"")
            stderr = self._decode_output(result.stderr or b"")
            
            return result.exit_status or 0, stdout, stderr
            
        except asyncio.TimeoutError:
            raise TimeoutError(f"SSH command timed out after {timeout}s")
        except asyncssh.ProcessError as e:
            return e.exit_status or 1, str(e.stdout or ""), str(e.stderr or str(e))
        except asyncssh.ChannelOpenError as e:
            raise ConnectionError(f"SSH channel error: {e}")
        except Exception as e:
            raise RuntimeError(f"SSH execution failed: {e}")
    
    def _build_remote_command(
        self,
        command: str,
        shell: ShellType,
        working_directory: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Build the remote command string.
        
        Args:
            command: Raw command
            shell: Shell type
            working_directory: Working directory
            environment: Environment variables
            
        Returns:
            Full command string for remote execution
        """
        parts = []
        
        # Add environment variables
        if environment:
            for key, value in environment.items():
                parts.append(f'export {key}={shlex.quote(value)}')
        
        # Add working directory change
        if working_directory:
            parts.append(f'cd {shlex.quote(working_directory)}')
        
        # Add the main command
        parts.append(command)
        
        # Join with && 
        full_command = " && ".join(parts)
        
        # Wrap in shell
        if shell == ShellType.BASH:
            return f"bash -c {shlex.quote(full_command)}"
        elif shell == ShellType.SH:
            return f"sh -c {shlex.quote(full_command)}"
        elif shell == ShellType.ZSH:
            return f"zsh -c {shlex.quote(full_command)}"
        
        return full_command
    
    def _add_sudo(self, command: str) -> str:
        """Add sudo to command."""
        password = self.config.sudo_password or self.config.password
        
        if password:
            pwd = password.get_secret_value()
            return f"echo {shlex.quote(pwd)} | sudo -S {command}"
        else:
            return f"sudo {command}"
    
    def _decode_output(self, output: bytes) -> str:
        """Decode SSH output."""
        if not output:
            return ""
        
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                return output.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        return output.decode('utf-8', errors='replace')
    
    # ═══════════════════════════════════════════════════════════
    # SFTP Operations
    # ═══════════════════════════════════════════════════════════
    
    async def _get_sftp(self) -> 'asyncssh.SFTPClient':
        """Get or create SFTP client."""
        if not self._is_connected():
            raise ConnectionError("SSH not connected")
        
        if self._sftp is None:
            self._sftp = await self._conn.start_sftp_client()
        
        return self._sftp
    
    async def upload_file(
        self,
        local_path: str,
        remote_path: str,
    ) -> bool:
        """
        Upload a file to the remote host.
        
        Args:
            local_path: Local file path
            remote_path: Remote destination path
            
        Returns:
            True if successful
        """
        try:
            sftp = await self._get_sftp()
            await sftp.put(local_path, remote_path)
            self.logger.info(f"Uploaded {local_path} to {remote_path}")
            return True
        except Exception as e:
            self.logger.error(f"Upload failed: {e}")
            return False
    
    async def download_file(
        self,
        remote_path: str,
        local_path: str,
    ) -> bool:
        """
        Download a file from the remote host.
        
        Args:
            remote_path: Remote file path
            local_path: Local destination path
            
        Returns:
            True if successful
        """
        try:
            sftp = await self._get_sftp()
            await sftp.get(remote_path, local_path)
            self.logger.info(f"Downloaded {remote_path} to {local_path}")
            return True
        except Exception as e:
            self.logger.error(f"Download failed: {e}")
            return False
    
    async def file_exists(self, path: str) -> bool:
        """
        Check if a file exists on remote host.
        
        Args:
            path: Remote path
            
        Returns:
            True if exists
        """
        try:
            sftp = await self._get_sftp()
            await sftp.stat(path)
            return True
        except asyncssh.SFTPNoSuchFile:
            return False
        except Exception as e:
            self.logger.error(f"file_exists failed: {e}")
            return False
    
    async def read_file(self, path: str) -> Optional[str]:
        """
        Read a file from remote host.
        
        Args:
            path: Remote file path
            
        Returns:
            File contents or None
        """
        result = await self.execute(
            ExecutionRequest(command=f"cat {shlex.quote(path)}", timeout=30)
        )
        return result.stdout if result.success else None
    
    async def write_file(self, path: str, content: str) -> bool:
        """
        Write content to a file on remote host.
        
        Args:
            path: Remote file path
            content: Content to write
            
        Returns:
            True if successful
        """
        # Use heredoc for safe content transfer
        command = f"cat > {shlex.quote(path)} <<'RAGLOX_EOF'\n{content}\nRAGLOX_EOF"
        result = await self.execute(
            ExecutionRequest(command=command, timeout=30)
        )
        return result.success
    
    # ═══════════════════════════════════════════════════════════
    # Port Forwarding
    # ═══════════════════════════════════════════════════════════
    
    async def forward_local_port(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
    ) -> bool:
        """
        Set up local port forwarding.
        
        Traffic to local_port will be forwarded to remote_host:remote_port
        through the SSH connection.
        
        Args:
            local_port: Local port to listen on
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to
            
        Returns:
            True if successful
        """
        if not self._is_connected():
            return False
        
        try:
            await self._conn.forward_local_port(
                '', local_port,
                remote_host, remote_port
            )
            self.logger.info(
                f"Local port forward: localhost:{local_port} -> "
                f"{remote_host}:{remote_port}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Port forward failed: {e}")
            return False
    
    # ═══════════════════════════════════════════════════════════
    # Utility Methods
    # ═══════════════════════════════════════════════════════════
    
    async def get_system_info(self) -> Dict[str, str]:
        """
        Get remote system information.
        
        Returns:
            Dictionary with system info
        """
        info = {}
        
        # Get hostname
        result = await self.execute(
            ExecutionRequest(command="hostname", timeout=10)
        )
        if result.success:
            info['hostname'] = result.stdout.strip()
        
        # Get OS info
        result = await self.execute(
            ExecutionRequest(command="uname -a", timeout=10)
        )
        if result.success:
            info['kernel'] = result.stdout.strip()
        
        # Get distribution info
        result = await self.execute(
            ExecutionRequest(
                command="cat /etc/os-release 2>/dev/null || cat /etc/*release 2>/dev/null",
                timeout=10
            )
        )
        if result.success:
            info['distribution'] = result.stdout.strip()[:500]
        
        # Get current user
        result = await self.execute(
            ExecutionRequest(command="id", timeout=10)
        )
        if result.success:
            info['user_info'] = result.stdout.strip()
        
        return info
    
    async def get_network_info(self) -> Dict[str, str]:
        """
        Get remote network information.
        
        Returns:
            Dictionary with network info
        """
        info = {}
        
        # Get IP addresses
        result = await self.execute(
            ExecutionRequest(
                command="ip addr show 2>/dev/null || ifconfig",
                timeout=10
            )
        )
        if result.success:
            info['interfaces'] = result.stdout.strip()[:2000]
        
        # Get routing table
        result = await self.execute(
            ExecutionRequest(
                command="ip route 2>/dev/null || netstat -rn",
                timeout=10
            )
        )
        if result.success:
            info['routes'] = result.stdout.strip()[:1000]
        
        # Get listening ports
        result = await self.execute(
            ExecutionRequest(
                command="ss -tlnp 2>/dev/null || netstat -tlnp",
                timeout=10
            )
        )
        if result.success:
            info['listening_ports'] = result.stdout.strip()[:2000]
        
        return info
    
    async def check_tool_available(self, tool: str) -> bool:
        """
        Check if a tool is available on the remote system.
        
        Args:
            tool: Tool name (e.g., 'nmap', 'python')
            
        Returns:
            True if available
        """
        result = await self.execute(
            ExecutionRequest(command=f"which {tool}", timeout=10)
        )
        return result.success and result.exit_code == 0


# ═══════════════════════════════════════════════════════════════
# Stub for when asyncssh is not available
# ═══════════════════════════════════════════════════════════════

class SSHExecutorStub(BaseExecutor):
    """Stub implementation when asyncssh is not available."""
    
    executor_type = ExecutorType.SSH
    
    def __init__(self, config: SSHConfig):
        raise ImportError(
            "asyncssh is required for SSH executor. "
            "Install with: pip install asyncssh"
        )
    
    async def _connect(self) -> None:
        pass
    
    async def _disconnect(self) -> None:
        pass
    
    def _is_connected(self) -> bool:
        return False
    
    async def _execute_command(self, *args, **kwargs) -> Tuple[int, str, str]:
        return 1, "", "SSH not available"


# Use the appropriate implementation
if not ASYNCSSH_AVAILABLE:
    SSHExecutor = SSHExecutorStub
