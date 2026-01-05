# ═══════════════════════════════════════════════════════════════
# SSH Connection Manager
# Manages SSH connections with support for keys and passwords
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from enum import Enum
import paramiko
from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key
from paramiko.ssh_exception import (
    SSHException, 
    AuthenticationException,
    NoValidConnectionsError
)

logger = logging.getLogger("raglox.infrastructure.ssh")


class SSHAuthType(Enum):
    """SSH authentication type"""
    PASSWORD = "password"
    KEY = "key"
    KEY_WITH_PASSPHRASE = "key_with_passphrase"


@dataclass
class SSHCredentials:
    """SSH connection credentials"""
    host: str
    port: int = 22
    username: str = "root"
    
    # Password authentication
    password: Optional[str] = None
    
    # Key-based authentication
    private_key_path: Optional[str] = None
    private_key_content: Optional[str] = None
    key_passphrase: Optional[str] = None
    
    # Connection settings
    timeout: int = 30
    banner_timeout: int = 60
    auth_timeout: int = 30
    
    # Advanced settings
    look_for_keys: bool = False
    allow_agent: bool = False
    compress: bool = False
    
    def get_auth_type(self) -> SSHAuthType:
        """Determine authentication type"""
        if self.private_key_path or self.private_key_content:
            if self.key_passphrase:
                return SSHAuthType.KEY_WITH_PASSPHRASE
            return SSHAuthType.KEY
        return SSHAuthType.PASSWORD


@dataclass
class SSHConnectionInfo:
    """SSH connection information"""
    connection_id: str
    host: str
    port: int
    username: str
    auth_type: SSHAuthType
    connected_at: datetime
    last_activity: datetime
    command_count: int = 0
    is_alive: bool = True


class SSHConnection:
    """
    Wrapper for SSH connection with automatic reconnection.
    
    Features:
    - Automatic reconnection on connection loss
    - Keep-alive mechanism
    - Connection pooling support
    - Activity tracking
    """
    
    def __init__(
        self,
        connection_id: str,
        credentials: SSHCredentials,
        auto_reconnect: bool = True
    ):
        self.connection_id = connection_id
        self.credentials = credentials
        self.auto_reconnect = auto_reconnect
        
        self._client: Optional[SSHClient] = None
        self._transport: Optional[paramiko.Transport] = None
        self._connected = False
        self._lock = asyncio.Lock()
        
        # Connection info
        self.info = SSHConnectionInfo(
            connection_id=connection_id,
            host=credentials.host,
            port=credentials.port,
            username=credentials.username,
            auth_type=credentials.get_auth_type(),
            connected_at=datetime.utcnow(),
            last_activity=datetime.utcnow()
        )
        
        logger.info(
            f"SSH connection initialized: {connection_id} "
            f"({credentials.username}@{credentials.host}:{credentials.port})"
        )
    
    async def connect(self) -> bool:
        """
        Establish SSH connection.
        
        Returns:
            True if connected successfully
        """
        async with self._lock:
            if self._connected and self.is_alive():
                return True
            
            try:
                # Create SSH client
                self._client = SSHClient()
                self._client.set_missing_host_key_policy(AutoAddPolicy())
                
                # Prepare connection parameters
                connect_kwargs = {
                    'hostname': self.credentials.host,
                    'port': self.credentials.port,
                    'username': self.credentials.username,
                    'timeout': self.credentials.timeout,
                    'banner_timeout': self.credentials.banner_timeout,
                    'auth_timeout': self.credentials.auth_timeout,
                    'look_for_keys': self.credentials.look_for_keys,
                    'allow_agent': self.credentials.allow_agent,
                    'compress': self.credentials.compress,
                }
                
                # Add authentication
                auth_type = self.credentials.get_auth_type()
                
                if auth_type == SSHAuthType.PASSWORD:
                    connect_kwargs['password'] = self.credentials.password
                    logger.info(f"Connecting with password authentication to {self.credentials.host}")
                
                elif auth_type in (SSHAuthType.KEY, SSHAuthType.KEY_WITH_PASSPHRASE):
                    # Load private key
                    if self.credentials.private_key_path:
                        connect_kwargs['key_filename'] = self.credentials.private_key_path
                    elif self.credentials.private_key_content:
                        # Parse key from string
                        pkey = self._parse_private_key(
                            self.credentials.private_key_content,
                            self.credentials.key_passphrase
                        )
                        connect_kwargs['pkey'] = pkey
                    
                    if self.credentials.key_passphrase:
                        connect_kwargs['passphrase'] = self.credentials.key_passphrase
                    
                    logger.info(f"Connecting with key authentication to {self.credentials.host}")
                
                # Connect (blocking operation, run in executor)
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._client.connect(**connect_kwargs)
                )
                
                self._transport = self._client.get_transport()
                self._connected = True
                
                # Setup keep-alive
                if self._transport:
                    self._transport.set_keepalive(30)
                
                self.info.connected_at = datetime.utcnow()
                self.info.last_activity = datetime.utcnow()
                self.info.is_alive = True
                
                logger.info(f"SSH connection established: {self.connection_id}")
                return True
                
            except AuthenticationException as e:
                logger.error(f"SSH authentication failed for {self.connection_id}: {e}")
                raise
            except NoValidConnectionsError as e:
                logger.error(f"SSH connection failed for {self.connection_id}: {e}")
                raise
            except Exception as e:
                logger.error(f"SSH connection error for {self.connection_id}: {e}", exc_info=True)
                raise
    
    def _parse_private_key(self, key_content: str, passphrase: Optional[str] = None):
        """Parse private key from string"""
        from io import StringIO
        
        key_file = StringIO(key_content)
        
        # Try different key types
        key_types = [RSAKey, Ed25519Key, paramiko.DSSKey, paramiko.ECDSAKey]
        
        for key_type in key_types:
            try:
                key_file.seek(0)
                return key_type.from_private_key(key_file, password=passphrase)
            except Exception:
                continue
        
        raise ValueError("Unable to parse private key - unsupported format")
    
    def is_alive(self) -> bool:
        """Check if connection is alive"""
        if not self._connected or not self._transport:
            return False
        
        try:
            return self._transport.is_active()
        except Exception:
            return False
    
    async def ensure_connected(self):
        """Ensure connection is active, reconnect if necessary"""
        if not self.is_alive():
            if self.auto_reconnect:
                logger.warning(f"Connection {self.connection_id} lost, reconnecting...")
                await self.connect()
            else:
                raise ConnectionError(f"SSH connection {self.connection_id} is not active")
    
    async def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        get_pty: bool = False
    ) -> Dict[str, any]:
        """
        Execute command on remote server.
        
        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            get_pty: Request a pseudo-terminal
            
        Returns:
            Dict with stdout, stderr, exit_code
        """
        await self.ensure_connected()
        
        try:
            # Execute command (blocking, run in executor)
            stdin, stdout, stderr = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._client.exec_command(
                    command,
                    timeout=timeout or self.credentials.timeout,
                    get_pty=get_pty
                )
            )
            
            # Read output (blocking)
            stdout_data = await asyncio.get_event_loop().run_in_executor(
                None,
                stdout.read
            )
            stderr_data = await asyncio.get_event_loop().run_in_executor(
                None,
                stderr.read
            )
            exit_code = stdout.channel.recv_exit_status()
            
            # Update activity
            self.info.last_activity = datetime.utcnow()
            self.info.command_count += 1
            
            return {
                'stdout': stdout_data.decode('utf-8', errors='replace'),
                'stderr': stderr_data.decode('utf-8', errors='replace'),
                'exit_code': exit_code,
                'success': exit_code == 0
            }
            
        except Exception as e:
            logger.error(f"Command execution failed on {self.connection_id}: {e}")
            raise
    
    async def disconnect(self):
        """Close SSH connection"""
        async with self._lock:
            if self._client:
                try:
                    self._client.close()
                    logger.info(f"SSH connection closed: {self.connection_id}")
                except Exception as e:
                    logger.error(f"Error closing connection {self.connection_id}: {e}")
            
            self._connected = False
            self.info.is_alive = False
    
    def __del__(self):
        """Cleanup on deletion"""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass


class SSHConnectionManager:
    """
    Manages multiple SSH connections with pooling support.
    
    Features:
    - Connection pooling
    - Automatic cleanup of dead connections
    - Connection reuse
    - Health monitoring
    """
    
    def __init__(self, max_connections: int = 50):
        self.max_connections = max_connections
        self._connections: Dict[str, SSHConnection] = {}
        self._connection_lock = asyncio.Lock()
        
        # Statistics
        self._stats = {
            'total_connections_created': 0,
            'active_connections': 0,
            'failed_connections': 0,
            'total_commands_executed': 0
        }
        
        logger.info(f"SSH Connection Manager initialized (max: {max_connections})")
    
    async def create_connection(
        self,
        connection_id: str,
        credentials: SSHCredentials,
        auto_reconnect: bool = True,
        connect_now: bool = True
    ) -> SSHConnection:
        """
        Create a new SSH connection.
        
        Args:
            connection_id: Unique identifier for connection
            credentials: SSH credentials
            auto_reconnect: Enable automatic reconnection
            connect_now: Connect immediately
            
        Returns:
            SSHConnection instance
        """
        async with self._connection_lock:
            # Check if connection already exists
            if connection_id in self._connections:
                logger.warning(f"Connection {connection_id} already exists")
                return self._connections[connection_id]
            
            # Check connection limit
            if len(self._connections) >= self.max_connections:
                # Cleanup dead connections
                await self._cleanup_dead_connections()
                
                if len(self._connections) >= self.max_connections:
                    raise RuntimeError(
                        f"Maximum connections ({self.max_connections}) reached"
                    )
            
            # Create connection
            connection = SSHConnection(
                connection_id=connection_id,
                credentials=credentials,
                auto_reconnect=auto_reconnect
            )
            
            # Connect if requested
            if connect_now:
                try:
                    await connection.connect()
                    self._stats['total_connections_created'] += 1
                    self._stats['active_connections'] += 1
                except Exception as e:
                    self._stats['failed_connections'] += 1
                    raise
            
            self._connections[connection_id] = connection
            
            logger.info(
                f"SSH connection created: {connection_id} "
                f"(total: {len(self._connections)})"
            )
            
            return connection
    
    async def get_connection(self, connection_id: str) -> Optional[SSHConnection]:
        """Get existing connection"""
        return self._connections.get(connection_id)
    
    async def remove_connection(self, connection_id: str):
        """Remove and close connection"""
        async with self._connection_lock:
            connection = self._connections.pop(connection_id, None)
            if connection:
                await connection.disconnect()
                self._stats['active_connections'] -= 1
                logger.info(f"SSH connection removed: {connection_id}")
    
    async def _cleanup_dead_connections(self):
        """Remove dead connections"""
        dead_ids = [
            conn_id for conn_id, conn in self._connections.items()
            if not conn.is_alive()
        ]
        
        for conn_id in dead_ids:
            await self.remove_connection(conn_id)
        
        if dead_ids:
            logger.info(f"Cleaned up {len(dead_ids)} dead connections")
    
    async def get_all_connections(self) -> List[SSHConnection]:
        """Get all active connections"""
        return list(self._connections.values())
    
    async def health_check(self) -> Dict[str, any]:
        """Get manager health status"""
        alive_count = sum(1 for conn in self._connections.values() if conn.is_alive())
        
        return {
            'total_connections': len(self._connections),
            'alive_connections': alive_count,
            'dead_connections': len(self._connections) - alive_count,
            'max_connections': self.max_connections,
            'utilization': len(self._connections) / self.max_connections,
            'statistics': self._stats
        }
    
    async def shutdown(self):
        """Close all connections"""
        logger.info("Shutting down SSH Connection Manager...")
        
        for connection_id in list(self._connections.keys()):
            await self.remove_connection(connection_id)
        
        logger.info("SSH Connection Manager shutdown complete")


# Singleton instance
_manager: Optional[SSHConnectionManager] = None


def get_ssh_manager(max_connections: int = 50) -> SSHConnectionManager:
    """Get or create SSH manager singleton"""
    global _manager
    if _manager is None:
        _manager = SSHConnectionManager(max_connections=max_connections)
    return _manager
