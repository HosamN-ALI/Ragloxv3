# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Execution Layer
# The "hands" of RAGLOX - enables actual command execution
# ═══════════════════════════════════════════════════════════════
#
# This module provides the execution layer that connects RAGLOX's
# "brain" (specialists) to the "real world" (target systems).
#
# Components:
# - BaseExecutor: Abstract base class for all executors
# - LocalExecutor: Execute commands locally (for testing)
# - SSHExecutor: Execute commands via SSH (Linux/Unix)
# - WinRMExecutor: Execute commands via WinRM (Windows)
# - ExecutorFactory: Create appropriate executor for target
# - RXModuleRunner: Translate and execute RX Modules
#
# Architecture:
# ┌─────────────────────────────────────────────────────────────┐
# │                    Specialist Layer                          │
# │  (ReconSpecialist, AttackSpecialist, AnalysisSpecialist)    │
# └──────────────────────────┬──────────────────────────────────┘
#                            │
#                            ▼
# ┌─────────────────────────────────────────────────────────────┐
# │                    RXModuleRunner                            │
# │  • Translates RX Modules to executable commands             │
# │  • Substitutes variables                                     │
# │  • Handles prerequisites                                     │
# └──────────────────────────┬──────────────────────────────────┘
#                            │
#                            ▼
# ┌─────────────────────────────────────────────────────────────┐
# │                    ExecutorFactory                           │
# │  • Selects appropriate executor for target                  │
# │  • Manages connection pool                                  │
# └──────────────────────────┬──────────────────────────────────┘
#                            │
#            ┌───────────────┼───────────────┐
#            ▼               ▼               ▼
# ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
# │ LocalExecutor  │ │  SSHExecutor   │ │ WinRMExecutor  │
# │ (Bash/PS)      │ │  (Linux/Unix)  │ │  (Windows)     │
# └────────────────┘ └────────────────┘ └────────────────┘
#
# Usage Example:
# --------------
#   from src.executors import (
#       LocalExecutor, ExecutionRequest, RXModuleRunner,
#       ExecutorFactory, Platform
#   )
#   
#   # Simple local execution
#   async with LocalExecutor() as executor:
#       result = await executor.execute(ExecutionRequest(command="whoami"))
#       print(result.stdout)
#   
#   # Using factory for automatic executor selection
#   factory = ExecutorFactory()
#   result = await factory.execute_on_target(
#       target_host="192.168.1.100",
#       target_platform=Platform.LINUX,
#       command="id",
#       connection_config=ssh_config,
#   )
#   
#   # Execute RX Module
#   runner = RXModuleRunner()
#   result = await runner.execute_module(RXModuleRequest(
#       rx_module_id="rx-t1003-001",
#       target_host="192.168.1.100",
#       target_platform=Platform.LINUX,
#   ))
#
# ═══════════════════════════════════════════════════════════════

from .models import (
    # Enums
    ExecutorType,
    ExecutionStatus,
    ShellType,
    Platform,
    # Connection Configs
    BaseConnectionConfig,
    SSHConfig,
    WinRMConfig,
    LocalConfig,
    ConnectionConfig,
    # Execution Models
    ExecutionRequest,
    ExecutionResult,
    # RX Module Models
    RXModuleRequest,
    RXModuleResult,
    # Connection Info
    ConnectionInfo,
)

from .base import BaseExecutor
from .local import LocalExecutor, run_local
from .ssh import SSHExecutor
from .winrm import WinRMExecutor
from .factory import (
    ExecutorFactory,
    get_executor_factory,
    execute_command,
)
from .runner import (
    RXModuleRunner,
    get_rx_module_runner,
    execute_rx_module,
)

__all__ = [
    # ═══════════════════════════════════════════════════════════
    # Enums
    # ═══════════════════════════════════════════════════════════
    "ExecutorType",
    "ExecutionStatus",
    "ShellType",
    "Platform",
    
    # ═══════════════════════════════════════════════════════════
    # Connection Configuration Models
    # ═══════════════════════════════════════════════════════════
    "BaseConnectionConfig",
    "SSHConfig",
    "WinRMConfig",
    "LocalConfig",
    "ConnectionConfig",
    "ConnectionInfo",
    
    # ═══════════════════════════════════════════════════════════
    # Execution Models
    # ═══════════════════════════════════════════════════════════
    "ExecutionRequest",
    "ExecutionResult",
    "RXModuleRequest",
    "RXModuleResult",
    
    # ═══════════════════════════════════════════════════════════
    # Executors
    # ═══════════════════════════════════════════════════════════
    "BaseExecutor",
    "LocalExecutor",
    "SSHExecutor",
    "WinRMExecutor",
    
    # ═══════════════════════════════════════════════════════════
    # Factory
    # ═══════════════════════════════════════════════════════════
    "ExecutorFactory",
    "get_executor_factory",
    
    # ═══════════════════════════════════════════════════════════
    # Runner
    # ═══════════════════════════════════════════════════════════
    "RXModuleRunner",
    "get_rx_module_runner",
    
    # ═══════════════════════════════════════════════════════════
    # Convenience Functions
    # ═══════════════════════════════════════════════════════════
    "run_local",
    "execute_command",
    "execute_rx_module",
]

__version__ = "3.0.0"
__author__ = "RAGLOX Team"
__description__ = "Execution Layer for RAGLOX Red Team Automation Platform"
