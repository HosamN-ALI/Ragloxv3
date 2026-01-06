"""
SSH Infrastructure Module
=========================

Provides SSH connection management for remote agent execution.

Features:
- SSH key-based authentication
- Password-based authentication
- Command execution
- File transfer (SFTP)
- Connection pooling
- Automatic reconnection

Author: RAGLOX Team
Version: 1.0.0
"""

from .connection_manager import (
    SSHConnectionManager,
    SSHConnection,
    SSHCredentials,
    SSHConnectionInfo,
    get_ssh_manager
)
from .key_manager import SSHKeyManager
from .command_executor import SSHCommandExecutor
from .file_transfer import SSHFileTransfer

# Alias for backward compatibility
SSHConnectionConfig = SSHCredentials

__all__ = [
    'SSHConnectionManager',
    'SSHConnection',
    'SSHCredentials',
    'SSHConnectionConfig',  # Alias for SSHCredentials
    'SSHConnectionInfo',
    'SSHKeyManager',
    'SSHCommandExecutor',
    'SSHFileTransfer',
    'get_ssh_manager',
]
