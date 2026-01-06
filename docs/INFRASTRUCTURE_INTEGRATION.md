# RAGLOX Infrastructure Integration Guide

## Overview

This document describes the infrastructure components for SSH connections, Cloud VM provisioning (OneProvider), and environment management.

## Components

### 1. SSH Infrastructure (`src/infrastructure/ssh/`)

#### Features
- **SSH Connection Manager**: Pool-based SSH connection management
- **Key-based & Password Authentication**: Support for both authentication methods
- **Command Executor**: Async command execution on remote hosts
- **File Transfer**: SFTP-based file operations
- **Key Manager**: SSH key generation and management
- **Auto-reconnect**: Automatic reconnection on connection loss
- **Keepalive**: Connection health monitoring

#### Usage

```python
from src.infrastructure.ssh import (
    SSHConnectionManager,
    SSHCredentials,
    get_ssh_manager
)

# Get SSH manager singleton
ssh_manager = get_ssh_manager(max_connections=50)

# Create credentials
credentials = SSHCredentials(
    host="192.168.1.100",
    port=22,
    username="root",
    password="secret",
    # OR use key-based auth:
    # private_key_path="/path/to/key",
    # key_passphrase="optional_passphrase"
)

# Create connection
conn = await ssh_manager.create_connection(
    connection_id="conn-001",
    credentials=credentials,
    auto_reconnect=True
)

# Execute commands
result = await conn.execute_command("whoami", timeout=30)
print(result['stdout'])
```

### 2. OneProvider Cloud Integration (`src/infrastructure/cloud_provider/`)

#### Features
- **VM Management**: Create, destroy, start, stop, reboot VMs
- **Resource Monitoring**: CPU, memory, bandwidth tracking
- **Billing Tracker**: Cost tracking per project/user
- **Installation Progress**: VM provisioning status

#### Configuration

```env
# OneProvider Settings
ONEPROVIDER_ENABLED=true
ONEPROVIDER_API_KEY=your_api_key
ONEPROVIDER_CLIENT_KEY=your_client_key
ONEPROVIDER_PROJECT_UUID=your_project_uuid
ONEPROVIDER_DEFAULT_PLAN=8GB-2CORE
ONEPROVIDER_DEFAULT_OS=ubuntu-22.04
ONEPROVIDER_DEFAULT_LOCATION=us-east
```

#### Usage

```python
from src.infrastructure.cloud_provider import (
    OneProviderClient,
    VMManager,
    VMConfiguration
)

# Initialize client
client = OneProviderClient(
    api_key="your_api_key",
    client_key="your_client_key"
)

# Initialize VM Manager
vm_manager = VMManager(
    client=client,
    default_project_uuid="project-uuid"
)

# Create VM
config = VMConfiguration(
    hostname="raglox-agent-01",
    plan_id="8GB-2CORE",
    os_id="ubuntu-22.04",
    location_id="us-east"
)

vm = await vm_manager.create_vm(config, wait_for_ready=True)
print(f"VM Created: {vm.vm_id}, IP: {vm.ipv4}")

# Destroy VM
await vm_manager.destroy_vm(vm.vm_id)
```

### 3. Environment Manager (`src/infrastructure/orchestrator/`)

#### Features
- **Remote SSH Environments**: Connect to user-provided servers
- **Sandbox Environments**: Auto-provision VMs via OneProvider
- **Multi-tenant Isolation**: User/tenant-based environment isolation
- **Environment Lifecycle**: Create, connect, reconnect, destroy
- **Health Monitoring**: Environment health checks

#### Environment Types

1. **REMOTE_SSH**: User provides SSH connection details
2. **SANDBOX**: RAGLOX provisions a VM automatically

#### Usage

```python
from src.infrastructure.orchestrator import (
    EnvironmentManager,
    EnvironmentType,
    EnvironmentConfig
)
from src.infrastructure.ssh import SSHCredentials

# Initialize manager
env_manager = EnvironmentManager(
    vm_manager=vm_manager,  # Optional, for sandbox support
    max_environments_per_user=10
)

# Create Remote SSH Environment
config = EnvironmentConfig(
    environment_type=EnvironmentType.REMOTE_SSH,
    name="My Remote Server",
    user_id="user-123",
    tenant_id="tenant-456",
    ssh_config=SSHCredentials(
        host="192.168.1.100",
        username="root",
        password="secret"
    )
)
env = await env_manager.create_environment(config)

# Create Sandbox Environment (auto-provisions VM)
sandbox_config = EnvironmentConfig(
    environment_type=EnvironmentType.SANDBOX,
    name="Test Sandbox",
    user_id="user-123",
    tenant_id="tenant-456"
)
sandbox = await env_manager.create_environment(sandbox_config)

# Execute commands
result = await agent_executor.execute_command(
    env,
    "uname -a",
    task_id="task-001"
)

# Destroy environment
await env_manager.destroy_environment(env.environment_id)
```

## API Endpoints

### Infrastructure Routes (`/api/v1/infrastructure/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/environments` | Create new environment |
| GET | `/environments/{id}` | Get environment details |
| GET | `/users/{user_id}/environments` | List user environments |
| DELETE | `/environments/{id}` | Destroy environment |
| POST | `/environments/{id}/reconnect` | Reconnect disconnected environment |
| POST | `/environments/{id}/execute/command` | Execute command |
| POST | `/environments/{id}/execute/script` | Execute script |
| GET | `/environments/{id}/system-info` | Get system information |
| GET | `/environments/{id}/health` | Health check |
| GET | `/statistics` | Infrastructure statistics |

## Configuration Reference

### SSH Settings

```env
SSH_ENABLED=true
SSH_MAX_CONNECTIONS=50
SSH_DEFAULT_TIMEOUT=30
SSH_KEEPALIVE_INTERVAL=30
SSH_KEY_DIRECTORY=data/ssh_keys
SSH_KNOWN_HOSTS_FILE=data/known_hosts
SSH_AUTO_ADD_HOST_KEYS=true
```

### OneProvider Settings

```env
ONEPROVIDER_ENABLED=false
ONEPROVIDER_API_KEY=
ONEPROVIDER_CLIENT_KEY=
ONEPROVIDER_PROJECT_UUID=
ONEPROVIDER_DEFAULT_PLAN=8GB-2CORE
ONEPROVIDER_DEFAULT_OS=ubuntu-22.04
ONEPROVIDER_DEFAULT_LOCATION=us-east
ONEPROVIDER_VM_TIMEOUT=600
ONEPROVIDER_MAX_VMS=10
```

### Agent Environment Settings

```env
AGENT_MAX_ENVIRONMENTS_PER_USER=10
AGENT_ENVIRONMENT_TIMEOUT=7200
AGENT_INSTALL_SCRIPT_URL=
```

## Security Considerations

1. **SSH Key Storage**: Keys are stored in `SSH_KEY_DIRECTORY` with restricted permissions
2. **API Key Protection**: OneProvider keys are stored as environment variables
3. **Connection Limits**: Per-user environment limits prevent resource exhaustion
4. **Auto-cleanup**: Stale environments are automatically cleaned up
5. **Audit Logging**: All environment operations are logged

## Integration with Exploitation Framework

The SSH infrastructure integrates with the exploitation framework:

1. **Post-Exploitation**: SSH connections can be established from C2 sessions
2. **Pivoting**: SSH tunnels can be used for network pivoting
3. **Credential Harvesting**: Harvested SSH keys can be used for lateral movement

## Troubleshooting

### Common Issues

1. **SSH Connection Timeout**
   - Check firewall rules
   - Verify SSH service is running on target
   - Increase `SSH_DEFAULT_TIMEOUT`

2. **VM Provisioning Fails**
   - Verify OneProvider API credentials
   - Check project UUID is correct
   - Ensure billing is current

3. **Environment Not Connecting**
   - Check SSH credentials
   - Verify VM IP is accessible
   - Check for host key issues

## Author

RAGLOX Team - v3.0.0
