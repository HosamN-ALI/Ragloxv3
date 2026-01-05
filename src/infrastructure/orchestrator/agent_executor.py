"""
RAGLOX v3.0 - Agent Executor
Executes agent tasks in remote environments.

Author: RAGLOX Team
Version: 3.0.0
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

from .environment_manager import AgentEnvironment
from ..ssh.command_executor import SSHCommandExecutor, CommandResult, CommandStatus


logger = logging.getLogger("raglox.infrastructure.orchestrator.agent_executor")


class TaskType(str, Enum):
    """Agent task type"""
    COMMAND = "command"
    SCRIPT = "script"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    SYSTEM_INFO = "system_info"


@dataclass
class ExecutionResult:
    """Task execution result"""
    task_id: str
    task_type: TaskType
    environment_id: str
    status: str  # success, failed, timeout
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    started_at: datetime
    ended_at: datetime
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "environment_id": self.environment_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_time": self.execution_time,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "error": self.error
        }


class AgentExecutor:
    """
    Agent Executor
    
    Executes tasks in agent environments:
    - Command execution
    - Script execution
    - File operations
    - System information gathering
    """
    
    def __init__(self):
        """Initialize Agent Executor"""
        self._execution_history: Dict[str, List[ExecutionResult]] = {}
    
    async def execute_command(
        self,
        environment: AgentEnvironment,
        command: str,
        task_id: str,
        timeout: int = 300,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """
        Execute a command in environment
        
        Args:
            environment: Agent environment
            command: Command to execute
            task_id: Task identifier
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables
        
        Returns:
            ExecutionResult
        """
        if not environment.ssh_manager or not environment.connection_id:
            return self._error_result(
                task_id,
                TaskType.COMMAND,
                environment.environment_id,
                "No SSH connection available"
            )
        
        try:
            # Get SSH connection
            connection = await environment.ssh_manager.get_connection(
                environment.connection_id
            )
            
            if not connection:
                return self._error_result(
                    task_id,
                    TaskType.COMMAND,
                    environment.environment_id,
                    "SSH connection not found"
                )
            
            # Create command executor
            executor = SSHCommandExecutor(connection)
            
            # Execute command
            cmd_result = await executor.execute(
                command,
                timeout=timeout,
                cwd=cwd,
                env=env,
                check=False
            )
            
            # Convert to ExecutionResult
            result = ExecutionResult(
                task_id=task_id,
                task_type=TaskType.COMMAND,
                environment_id=environment.environment_id,
                status=cmd_result.status,
                exit_code=cmd_result.exit_code,
                stdout=cmd_result.stdout,
                stderr=cmd_result.stderr,
                execution_time=cmd_result.execution_time,
                started_at=cmd_result.started_at,
                ended_at=cmd_result.ended_at
            )
            
            # Store in history
            self._store_result(environment.environment_id, result)
            
            # Update last activity
            environment.last_activity = datetime.utcnow()
            
            return result
            
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            return self._error_result(
                task_id,
                TaskType.COMMAND,
                environment.environment_id,
                str(e)
            )
    
    async def execute_script(
        self,
        environment: AgentEnvironment,
        script_content: str,
        task_id: str,
        interpreter: str = "/bin/bash",
        timeout: int = 600,
        env: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """
        Execute a script in environment
        
        Args:
            environment: Agent environment
            script_content: Script content
            task_id: Task identifier
            interpreter: Script interpreter
            timeout: Timeout in seconds
            env: Environment variables
        
        Returns:
            ExecutionResult
        """
        if not environment.ssh_manager or not environment.connection_id:
            return self._error_result(
                task_id,
                TaskType.SCRIPT,
                environment.environment_id,
                "No SSH connection available"
            )
        
        try:
            connection = await environment.ssh_manager.get_connection(
                environment.connection_id
            )
            
            if not connection:
                return self._error_result(
                    task_id,
                    TaskType.SCRIPT,
                    environment.environment_id,
                    "SSH connection not found"
                )
            
            executor = SSHCommandExecutor(connection)
            
            # Execute script
            cmd_result = await executor.execute_script(
                script_content,
                interpreter=interpreter,
                timeout=timeout,
                env=env
            )
            
            result = ExecutionResult(
                task_id=task_id,
                task_type=TaskType.SCRIPT,
                environment_id=environment.environment_id,
                status=cmd_result.status,
                exit_code=cmd_result.exit_code,
                stdout=cmd_result.stdout,
                stderr=cmd_result.stderr,
                execution_time=cmd_result.execution_time,
                started_at=cmd_result.started_at,
                ended_at=cmd_result.ended_at
            )
            
            self._store_result(environment.environment_id, result)
            environment.last_activity = datetime.utcnow()
            
            return result
            
        except Exception as e:
            logger.error(f"Script execution failed: {str(e)}")
            return self._error_result(
                task_id,
                TaskType.SCRIPT,
                environment.environment_id,
                str(e)
            )
    
    async def upload_file(
        self,
        environment: AgentEnvironment,
        local_path: str,
        remote_path: str,
        task_id: str
    ) -> ExecutionResult:
        """
        Upload file to environment
        
        Args:
            environment: Agent environment
            local_path: Local file path
            remote_path: Remote destination path
            task_id: Task identifier
        
        Returns:
            ExecutionResult
        """
        started_at = datetime.utcnow()
        
        if not environment.ssh_manager or not environment.connection_id:
            return self._error_result(
                task_id,
                TaskType.FILE_UPLOAD,
                environment.environment_id,
                "No SSH connection available"
            )
        
        try:
            # Upload file
            success = await environment.ssh_manager.upload_file(
                environment.connection_id,
                local_path,
                remote_path
            )
            
            ended_at = datetime.utcnow()
            execution_time = (ended_at - started_at).total_seconds()
            
            result = ExecutionResult(
                task_id=task_id,
                task_type=TaskType.FILE_UPLOAD,
                environment_id=environment.environment_id,
                status="success" if success else "failed",
                exit_code=0 if success else 1,
                stdout=f"Uploaded {local_path} -> {remote_path}" if success else "",
                stderr="" if success else "Upload failed",
                execution_time=execution_time,
                started_at=started_at,
                ended_at=ended_at
            )
            
            self._store_result(environment.environment_id, result)
            environment.last_activity = datetime.utcnow()
            
            return result
            
        except Exception as e:
            logger.error(f"File upload failed: {str(e)}")
            return self._error_result(
                task_id,
                TaskType.FILE_UPLOAD,
                environment.environment_id,
                str(e)
            )
    
    async def download_file(
        self,
        environment: AgentEnvironment,
        remote_path: str,
        local_path: str,
        task_id: str
    ) -> ExecutionResult:
        """
        Download file from environment
        
        Args:
            environment: Agent environment
            remote_path: Remote file path
            local_path: Local destination path
            task_id: Task identifier
        
        Returns:
            ExecutionResult
        """
        started_at = datetime.utcnow()
        
        if not environment.ssh_manager or not environment.connection_id:
            return self._error_result(
                task_id,
                TaskType.FILE_DOWNLOAD,
                environment.environment_id,
                "No SSH connection available"
            )
        
        try:
            # Download file
            success = await environment.ssh_manager.download_file(
                environment.connection_id,
                remote_path,
                local_path
            )
            
            ended_at = datetime.utcnow()
            execution_time = (ended_at - started_at).total_seconds()
            
            result = ExecutionResult(
                task_id=task_id,
                task_type=TaskType.FILE_DOWNLOAD,
                environment_id=environment.environment_id,
                status="success" if success else "failed",
                exit_code=0 if success else 1,
                stdout=f"Downloaded {remote_path} -> {local_path}" if success else "",
                stderr="" if success else "Download failed",
                execution_time=execution_time,
                started_at=started_at,
                ended_at=ended_at
            )
            
            self._store_result(environment.environment_id, result)
            environment.last_activity = datetime.utcnow()
            
            return result
            
        except Exception as e:
            logger.error(f"File download failed: {str(e)}")
            return self._error_result(
                task_id,
                TaskType.FILE_DOWNLOAD,
                environment.environment_id,
                str(e)
            )
    
    async def get_system_info(
        self,
        environment: AgentEnvironment,
        task_id: str
    ) -> ExecutionResult:
        """
        Get system information from environment
        
        Args:
            environment: Agent environment
            task_id: Task identifier
        
        Returns:
            ExecutionResult with system info in stdout
        """
        started_at = datetime.utcnow()
        
        if not environment.ssh_manager or not environment.connection_id:
            return self._error_result(
                task_id,
                TaskType.SYSTEM_INFO,
                environment.environment_id,
                "No SSH connection available"
            )
        
        try:
            connection = await environment.ssh_manager.get_connection(
                environment.connection_id
            )
            
            if not connection:
                return self._error_result(
                    task_id,
                    TaskType.SYSTEM_INFO,
                    environment.environment_id,
                    "SSH connection not found"
                )
            
            executor = SSHCommandExecutor(connection)
            
            # Get system info
            system_info = await executor.get_system_info()
            
            ended_at = datetime.utcnow()
            execution_time = (ended_at - started_at).total_seconds()
            
            import json
            stdout = json.dumps(system_info, indent=2)
            
            result = ExecutionResult(
                task_id=task_id,
                task_type=TaskType.SYSTEM_INFO,
                environment_id=environment.environment_id,
                status="success",
                exit_code=0,
                stdout=stdout,
                stderr="",
                execution_time=execution_time,
                started_at=started_at,
                ended_at=ended_at
            )
            
            self._store_result(environment.environment_id, result)
            environment.last_activity = datetime.utcnow()
            
            return result
            
        except Exception as e:
            logger.error(f"System info gathering failed: {str(e)}")
            return self._error_result(
                task_id,
                TaskType.SYSTEM_INFO,
                environment.environment_id,
                str(e)
            )
    
    def _error_result(
        self,
        task_id: str,
        task_type: TaskType,
        environment_id: str,
        error: str
    ) -> ExecutionResult:
        """Create error result"""
        now = datetime.utcnow()
        return ExecutionResult(
            task_id=task_id,
            task_type=task_type,
            environment_id=environment_id,
            status="failed",
            exit_code=-1,
            stdout="",
            stderr=error,
            execution_time=0.0,
            started_at=now,
            ended_at=now,
            error=error
        )
    
    def _store_result(self, environment_id: str, result: ExecutionResult):
        """Store execution result in history"""
        if environment_id not in self._execution_history:
            self._execution_history[environment_id] = []
        
        self._execution_history[environment_id].append(result)
        
        # Keep last 1000 results per environment
        if len(self._execution_history[environment_id]) > 1000:
            self._execution_history[environment_id] = \
                self._execution_history[environment_id][-1000:]
    
    def get_execution_history(
        self,
        environment_id: str,
        limit: int = 100
    ) -> List[ExecutionResult]:
        """Get execution history for environment"""
        history = self._execution_history.get(environment_id, [])
        return history[-limit:]
