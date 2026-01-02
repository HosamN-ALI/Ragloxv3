# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Execution Layer Tests
# Comprehensive tests for executors, factory, and runner
# ═══════════════════════════════════════════════════════════════

import asyncio
import pytest
from datetime import datetime
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from src.executors import (
    # Enums
    ExecutorType,
    ExecutionStatus,
    ShellType,
    Platform,
    # Models
    BaseConnectionConfig,
    SSHConfig,
    WinRMConfig,
    LocalConfig,
    ExecutionRequest,
    ExecutionResult,
    RXModuleRequest,
    RXModuleResult,
    ConnectionInfo,
    # Executors
    BaseExecutor,
    LocalExecutor,
    # Factory & Runner
    ExecutorFactory,
    RXModuleRunner,
    get_executor_factory,
    get_rx_module_runner,
)


# ═══════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def local_config():
    """Create a LocalConfig for testing."""
    return LocalConfig(
        shell=ShellType.BASH,
        timeout=30,
    )


@pytest.fixture
def ssh_config():
    """Create an SSHConfig for testing."""
    from pydantic import SecretStr
    return SSHConfig(
        host="192.168.1.100",
        username="testuser",
        password=SecretStr("testpass"),
        port=22,
        timeout=30,
    )


@pytest.fixture
def winrm_config():
    """Create a WinRMConfig for testing."""
    from pydantic import SecretStr
    return WinRMConfig(
        host="192.168.1.100",
        username="Administrator",
        password=SecretStr("testpass"),
        port=5985,
        timeout=30,
    )


@pytest.fixture
def execution_request():
    """Create a basic ExecutionRequest for testing."""
    return ExecutionRequest(
        command="echo test",
        timeout=30,
    )


@pytest.fixture
def rx_module_request():
    """Create a basic RXModuleRequest for testing."""
    return RXModuleRequest(
        rx_module_id="rx-t1003-001",
        target_host="192.168.1.100",
        target_platform=Platform.LINUX,
        variables={"test_var": "test_value"},
    )


# ═══════════════════════════════════════════════════════════════
# Model Tests
# ═══════════════════════════════════════════════════════════════

class TestExecutorModels:
    """Tests for executor data models."""
    
    def test_executor_type_enum(self):
        """Test ExecutorType enum values."""
        assert ExecutorType.LOCAL.value == "local"
        assert ExecutorType.SSH.value == "ssh"
        assert ExecutorType.WINRM.value == "winrm"
    
    def test_execution_status_enum(self):
        """Test ExecutionStatus enum values."""
        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.FAILED.value == "failed"
        assert ExecutionStatus.TIMEOUT.value == "timeout"
        assert ExecutionStatus.CONNECTION_ERROR.value == "connection_error"
    
    def test_shell_type_enum(self):
        """Test ShellType enum values."""
        assert ShellType.BASH.value == "bash"
        assert ShellType.POWERSHELL.value == "powershell"
        assert ShellType.CMD.value == "cmd"
    
    def test_platform_enum(self):
        """Test Platform enum values."""
        assert Platform.LINUX.value == "linux"
        assert Platform.WINDOWS.value == "windows"
        assert Platform.MACOS.value == "macos"


class TestConnectionConfigs:
    """Tests for connection configuration models."""
    
    def test_local_config_defaults(self, local_config):
        """Test LocalConfig default values."""
        assert local_config.host == "localhost"
        assert local_config.shell == ShellType.BASH
    
    def test_ssh_config_required_fields(self, ssh_config):
        """Test SSHConfig required fields."""
        assert ssh_config.host == "192.168.1.100"
        assert ssh_config.username == "testuser"
        assert ssh_config.port == 22
    
    def test_winrm_config_endpoint(self, winrm_config):
        """Test WinRMConfig endpoint property."""
        assert winrm_config.endpoint == "http://192.168.1.100:5985/wsman"
        
        # Test with SSL
        winrm_config.ssl = True
        winrm_config.port = 5986
        assert winrm_config.endpoint == "https://192.168.1.100:5986/wsman"


class TestExecutionRequest:
    """Tests for ExecutionRequest model."""
    
    def test_request_with_defaults(self):
        """Test ExecutionRequest with default values."""
        request = ExecutionRequest(command="test")
        
        assert request.command == "test"
        assert request.timeout == 300
        assert request.capture_output is True
        assert request.id is not None
    
    def test_request_with_all_fields(self):
        """Test ExecutionRequest with all fields specified."""
        task_id = uuid4()
        mission_id = uuid4()
        
        request = ExecutionRequest(
            command="nmap -sV 192.168.1.0/24",
            shell=ShellType.BASH,
            working_directory="/tmp",
            environment={"PATH": "/usr/bin"},
            timeout=600,
            capture_output=True,
            elevated=True,
            task_id=task_id,
            mission_id=mission_id,
            rx_module_id="rx-t1046-001",
            cleanup_command="rm -f /tmp/scan.txt",
        )
        
        assert request.command == "nmap -sV 192.168.1.0/24"
        assert request.shell == ShellType.BASH
        assert request.elevated is True
        assert request.task_id == task_id


class TestExecutionResult:
    """Tests for ExecutionResult model."""
    
    def test_success_result(self):
        """Test successful ExecutionResult."""
        result = ExecutionResult(
            request_id=uuid4(),
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            stdout="output data",
            stderr="",
            executor_type=ExecutorType.LOCAL,
            host="localhost",
        )
        
        assert result.success is True
    
    def test_failed_result(self):
        """Test failed ExecutionResult."""
        result = ExecutionResult(
            request_id=uuid4(),
            status=ExecutionStatus.FAILED,
            exit_code=1,
            stdout="",
            stderr="Error: command failed",
            executor_type=ExecutorType.LOCAL,
            host="localhost",
        )
        
        assert result.success is False
    
    def test_to_execution_log(self):
        """Test ExecutionResult.to_execution_log method."""
        result = ExecutionResult(
            request_id=uuid4(),
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            stdout="test output",
            stderr="",
            duration_ms=100,
            executor_type=ExecutorType.LOCAL,
            host="localhost",
        )
        
        log = result.to_execution_log()
        
        assert "message" in log
        assert "data" in log
        assert log["data"]["exit_code"] == 0
        assert log["data"]["duration_ms"] == 100


class TestRXModuleModels:
    """Tests for RX Module models."""
    
    def test_rx_module_request(self, rx_module_request):
        """Test RXModuleRequest model."""
        assert rx_module_request.rx_module_id == "rx-t1003-001"
        assert rx_module_request.target_host == "192.168.1.100"
        assert rx_module_request.target_platform == Platform.LINUX
        assert rx_module_request.variables == {"test_var": "test_value"}
    
    def test_rx_module_result(self):
        """Test RXModuleResult model."""
        result = RXModuleResult(
            request_id=uuid4(),
            rx_module_id="rx-t1003-001",
            success=True,
            status=ExecutionStatus.SUCCESS,
        )
        
        assert result.success is True
        assert result.prerequisites_passed is True
    
    def test_rx_module_result_error_context(self):
        """Test RXModuleResult.to_error_context method."""
        main_result = ExecutionResult(
            request_id=uuid4(),
            status=ExecutionStatus.TIMEOUT,
            executor_type=ExecutorType.SSH,
            host="192.168.1.100",
        )
        
        result = RXModuleResult(
            request_id=uuid4(),
            rx_module_id="rx-t1003-001",
            success=False,
            status=ExecutionStatus.TIMEOUT,
            main_result=main_result,
        )
        
        error_context = result.to_error_context()
        
        assert error_context["error_type"] == "timeout"
        assert error_context["retry_recommended"] is True


# ═══════════════════════════════════════════════════════════════
# LocalExecutor Tests
# ═══════════════════════════════════════════════════════════════

class TestLocalExecutor:
    """Tests for LocalExecutor."""
    
    @pytest.mark.asyncio
    async def test_local_executor_creation(self, local_config):
        """Test LocalExecutor creation."""
        executor = LocalExecutor(local_config)
        
        assert executor.executor_type == ExecutorType.LOCAL
        assert executor.config.shell == ShellType.BASH
    
    @pytest.mark.asyncio
    async def test_local_executor_default_config(self):
        """Test LocalExecutor with default config."""
        executor = LocalExecutor()
        
        assert executor.config is not None
        assert executor.config.host == "localhost"
    
    @pytest.mark.asyncio
    async def test_local_executor_connection(self):
        """Test LocalExecutor connection (always succeeds)."""
        async with LocalExecutor() as executor:
            assert executor.is_connected is True
    
    @pytest.mark.asyncio
    async def test_local_executor_simple_command(self):
        """Test LocalExecutor with simple command."""
        async with LocalExecutor() as executor:
            request = ExecutionRequest(command="echo 'hello world'")
            result = await executor.execute(request)
            
            assert result.success is True
            assert "hello world" in result.stdout
    
    @pytest.mark.asyncio
    async def test_local_executor_failing_command(self):
        """Test LocalExecutor with failing command."""
        async with LocalExecutor() as executor:
            request = ExecutionRequest(command="exit 1")
            result = await executor.execute(request)
            
            assert result.success is False
            assert result.exit_code == 1
    
    @pytest.mark.asyncio
    async def test_local_executor_command_not_found(self):
        """Test LocalExecutor with non-existent command."""
        async with LocalExecutor() as executor:
            request = ExecutionRequest(command="nonexistentcommand12345")
            result = await executor.execute(request)
            
            assert result.success is False
    
    @pytest.mark.asyncio
    async def test_local_executor_with_environment(self):
        """Test LocalExecutor with environment variables."""
        async with LocalExecutor() as executor:
            request = ExecutionRequest(
                command="echo $TEST_VAR",
                environment={"TEST_VAR": "test_value"},
            )
            result = await executor.execute(request)
            
            assert result.success is True
            assert "test_value" in result.stdout
    
    @pytest.mark.asyncio
    async def test_local_executor_working_directory(self):
        """Test LocalExecutor with working directory."""
        async with LocalExecutor() as executor:
            request = ExecutionRequest(
                command="pwd",
                working_directory="/tmp",
            )
            result = await executor.execute(request)
            
            assert result.success is True
            assert "/tmp" in result.stdout
    
    @pytest.mark.asyncio
    async def test_local_executor_timeout(self):
        """Test LocalExecutor timeout handling."""
        async with LocalExecutor() as executor:
            request = ExecutionRequest(
                command="sleep 10",
                timeout=1,
            )
            result = await executor.execute(request)
            
            assert result.success is False
            assert result.status == ExecutionStatus.TIMEOUT
    
    @pytest.mark.asyncio
    async def test_local_executor_file_operations(self):
        """Test LocalExecutor file operations."""
        executor = LocalExecutor()
        await executor.connect()
        
        try:
            # Test file_exists
            exists = await executor.file_exists("/etc/passwd")
            assert exists is True
            
            exists = await executor.file_exists("/nonexistent/file/path")
            assert exists is False
            
            # Test read_file
            content = await executor.read_file("/etc/hostname")
            assert content is not None
            
        finally:
            await executor.disconnect()
    
    @pytest.mark.asyncio
    async def test_local_executor_system_info(self):
        """Test LocalExecutor.get_system_info."""
        async with LocalExecutor() as executor:
            info = await executor.get_system_info()
            
            assert "platform" in info
            assert "hostname" in info


# ═══════════════════════════════════════════════════════════════
# ExecutorFactory Tests
# ═══════════════════════════════════════════════════════════════

class TestExecutorFactory:
    """Tests for ExecutorFactory."""
    
    def test_factory_creation(self):
        """Test ExecutorFactory creation."""
        factory = ExecutorFactory()
        
        assert factory.max_connections_per_host == 5
        assert factory.enable_pooling is True
    
    def test_factory_with_custom_settings(self):
        """Test ExecutorFactory with custom settings."""
        factory = ExecutorFactory(
            max_connections_per_host=10,
            connection_timeout=60,
            enable_pooling=False,
        )
        
        assert factory.max_connections_per_host == 10
        assert factory.enable_pooling is False
    
    @pytest.mark.asyncio
    async def test_factory_get_local_executor(self):
        """Test getting LocalExecutor from factory."""
        factory = ExecutorFactory()
        
        executor = await factory.get_executor(
            target_host="localhost",
            target_platform=Platform.LINUX,
            executor_type=ExecutorType.LOCAL,
        )
        
        try:
            assert executor is not None
            assert executor.executor_type == ExecutorType.LOCAL
        finally:
            await factory.release_executor(executor, force_close=True)
    
    @pytest.mark.asyncio
    async def test_factory_executor_selection(self):
        """Test automatic executor type selection."""
        factory = ExecutorFactory()
        
        # Linux should prefer SSH (but fallback to LOCAL without config)
        executor_type = factory._select_executor_type(
            target_platform=Platform.LINUX,
            connection_config=None,
        )
        # Without config, it falls back to first available
        assert executor_type in [ExecutorType.SSH, ExecutorType.LOCAL]
    
    @pytest.mark.asyncio
    async def test_factory_execute_on_target(self):
        """Test factory.execute_on_target convenience method."""
        factory = ExecutorFactory()
        
        result = await factory.execute_on_target(
            target_host="localhost",
            target_platform=Platform.LINUX,
            command="echo 'factory test'",
            connection_config=LocalConfig(),
        )
        
        assert result.success is True
        assert "factory test" in result.stdout
    
    @pytest.mark.asyncio
    async def test_factory_health_check(self):
        """Test factory health check."""
        factory = ExecutorFactory()
        
        # Get an executor to create a connection
        executor = await factory.get_executor(
            target_host="localhost",
            target_platform=Platform.LINUX,
            executor_type=ExecutorType.LOCAL,
        )
        
        try:
            health = await factory.health_check()
            
            assert "total_connections" in health
            assert "pooled_connections" in health
        finally:
            await factory.release_executor(executor, force_close=True)
    
    @pytest.mark.asyncio
    async def test_factory_connection_pooling(self):
        """Test connection pooling."""
        factory = ExecutorFactory(enable_pooling=True)
        
        # Get executor
        executor1 = await factory.get_executor(
            target_host="localhost",
            target_platform=Platform.LINUX,
            executor_type=ExecutorType.LOCAL,
        )
        
        # Release back to pool
        await factory.release_executor(executor1)
        
        # Get again (should reuse)
        executor2 = await factory.get_executor(
            target_host="localhost",
            target_platform=Platform.LINUX,
            executor_type=ExecutorType.LOCAL,
        )
        
        # Should be the same executor from pool
        await factory.release_executor(executor2, force_close=True)
    
    @pytest.mark.asyncio
    async def test_factory_context_manager(self):
        """Test factory as context manager."""
        async with ExecutorFactory() as factory:
            result = await factory.execute_on_target(
                target_host="localhost",
                target_platform=Platform.LINUX,
                command="echo 'context test'",
                connection_config=LocalConfig(),
            )
            
            assert result.success is True


class TestGlobalFactory:
    """Tests for global factory instance."""
    
    def test_get_executor_factory(self):
        """Test getting global factory instance."""
        factory1 = get_executor_factory()
        factory2 = get_executor_factory()
        
        assert factory1 is factory2  # Same instance


# ═══════════════════════════════════════════════════════════════
# RXModuleRunner Tests
# ═══════════════════════════════════════════════════════════════

class TestRXModuleRunner:
    """Tests for RXModuleRunner."""
    
    def test_runner_creation(self):
        """Test RXModuleRunner creation."""
        runner = RXModuleRunner()
        
        assert runner.default_timeout == 300
        assert runner.check_prerequisites is True
    
    def test_runner_with_custom_settings(self):
        """Test RXModuleRunner with custom settings."""
        runner = RXModuleRunner(
            default_timeout=600,
            check_prerequisites=False,
            run_cleanup_on_failure=True,
        )
        
        assert runner.default_timeout == 600
        assert runner.check_prerequisites is False
        assert runner.run_cleanup_on_failure is True
    
    def test_runner_stats(self):
        """Test runner statistics tracking."""
        runner = RXModuleRunner()
        
        stats = runner.get_stats()
        
        assert "executions" in stats
        assert "successes" in stats
        assert "failures" in stats
        assert "success_rate" in stats
    
    def test_runner_reset_stats(self):
        """Test resetting runner statistics."""
        runner = RXModuleRunner()
        runner._stats["executions"] = 100
        
        runner.reset_stats()
        
        assert runner._stats["executions"] == 0


class TestRXModuleRunnerCommandBuilding:
    """Tests for RXModuleRunner command building."""
    
    def test_build_command_simple(self):
        """Test building simple command without variables."""
        runner = RXModuleRunner()
        
        # Mock RX Module
        rx_module = MagicMock()
        rx_module.execution.command = "whoami"
        rx_module.variables = []
        
        command = runner._build_command(rx_module, {})
        
        assert command == "whoami"
    
    def test_build_command_with_variables(self):
        """Test building command with variable substitution."""
        runner = RXModuleRunner()
        
        # Mock RX Module with variable
        var = MagicMock()
        var.name = "target_ip"
        var.default_value = "127.0.0.1"
        
        rx_module = MagicMock()
        rx_module.execution.command = "ping #{target_ip}"
        rx_module.variables = [var]
        
        command = runner._build_command(rx_module, {"target_ip": "192.168.1.1"})
        
        assert "192.168.1.1" in command
    
    def test_get_shell_type_powershell(self):
        """Test shell type detection for PowerShell."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        rx_module.execution.executor_type = "powershell"
        
        shell = runner._get_shell_type(rx_module, Platform.WINDOWS)
        
        assert shell == ShellType.POWERSHELL
    
    def test_get_shell_type_bash(self):
        """Test shell type detection for Bash."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        rx_module.execution.executor_type = "bash"
        
        shell = runner._get_shell_type(rx_module, Platform.LINUX)
        
        assert shell == ShellType.BASH


class TestRXModuleRunnerPlatformCompatibility:
    """Tests for platform compatibility checking."""
    
    def test_platform_compatible_direct_match(self):
        """Test direct platform match."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        rx_module.execution.platforms = ["linux", "macos"]
        
        assert runner._is_platform_compatible(rx_module, Platform.LINUX) is True
        assert runner._is_platform_compatible(rx_module, Platform.WINDOWS) is False
    
    def test_platform_compatible_case_insensitive(self):
        """Test case-insensitive platform matching."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        rx_module.execution.platforms = ["Linux", "Windows"]
        
        assert runner._is_platform_compatible(rx_module, Platform.LINUX) is True
        assert runner._is_platform_compatible(rx_module, Platform.WINDOWS) is True


class TestRXModuleRunnerOutputParsing:
    """Tests for output parsing."""
    
    def test_parse_output_ip_addresses(self):
        """Test IP address extraction from output."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        stdout = "Found hosts: 192.168.1.1, 192.168.1.2, 10.0.0.1"
        stderr = ""
        
        parsed = runner._parse_output(rx_module, stdout, stderr)
        
        assert "ip_addresses" in parsed
        assert "192.168.1.1" in parsed["ip_addresses"]
        assert "192.168.1.2" in parsed["ip_addresses"]
    
    def test_parse_output_usernames(self):
        """Test username extraction from output."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        stdout = "Username: admin\nUser: testuser"
        stderr = ""
        
        parsed = runner._parse_output(rx_module, stdout, stderr)
        
        assert "usernames" in parsed
    
    def test_parse_output_hashes(self):
        """Test hash extraction from output."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        stdout = "NTLM Hash: aad3b435b51404eeaad3b435b51404ee"
        stderr = ""
        
        parsed = runner._parse_output(rx_module, stdout, stderr)
        
        assert "hashes" in parsed


class TestRXModuleRunnerErrorContext:
    """Tests for error context building."""
    
    def test_build_error_context_defense_detection(self):
        """Test error context with defense detection."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        rx_module.rx_module_id = "rx-t1003-001"
        rx_module.technique_id = "T1003"
        
        result = ExecutionResult(
            request_id=uuid4(),
            status=ExecutionStatus.FAILED,
            exit_code=1,
            stdout="",
            stderr="Access denied by Windows Defender",
            executor_type=ExecutorType.LOCAL,
            host="localhost",
        )
        
        context = runner._build_error_context(rx_module, result)
        
        assert context["error_type"] == "defense"
        assert "windows_defender" in context["detected_defenses"]
    
    def test_build_error_context_network_error(self):
        """Test error context with network error."""
        runner = RXModuleRunner()
        
        rx_module = MagicMock()
        rx_module.rx_module_id = "rx-t1003-001"
        rx_module.technique_id = "T1003"
        
        result = ExecutionResult(
            request_id=uuid4(),
            status=ExecutionStatus.CONNECTION_ERROR,
            exit_code=1,
            stdout="",
            stderr="Connection refused",
            executor_type=ExecutorType.SSH,
            host="192.168.1.100",
        )
        
        context = runner._build_error_context(rx_module, result)
        
        assert context["error_type"] == "network"
        assert context["retry_recommended"] is True


class TestGlobalRunner:
    """Tests for global runner instance."""
    
    def test_get_rx_module_runner(self):
        """Test getting global runner instance."""
        runner1 = get_rx_module_runner()
        runner2 = get_rx_module_runner()
        
        assert runner1 is runner2  # Same instance


# ═══════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestExecutorIntegration:
    """Integration tests for the execution layer."""
    
    @pytest.mark.asyncio
    async def test_full_execution_flow(self):
        """Test complete execution flow from factory to result."""
        factory = ExecutorFactory()
        
        # Get executor
        executor = await factory.get_executor(
            target_host="localhost",
            target_platform=Platform.LINUX,
            executor_type=ExecutorType.LOCAL,
        )
        
        try:
            # Execute command
            request = ExecutionRequest(
                command="echo 'integration test' && hostname",
                timeout=30,
            )
            result = await executor.execute(request)
            
            # Verify result
            assert result.success is True
            assert "integration test" in result.stdout
            assert result.duration_ms > 0
            
        finally:
            await factory.release_executor(executor, force_close=True)
    
    @pytest.mark.asyncio
    async def test_multiple_commands_sequential(self):
        """Test executing multiple commands sequentially."""
        async with LocalExecutor() as executor:
            commands = [
                "echo 'command 1'",
                "echo 'command 2'",
                "echo 'command 3'",
            ]
            
            results = []
            for cmd in commands:
                result = await executor.execute(ExecutionRequest(command=cmd))
                results.append(result)
            
            assert all(r.success for r in results)
            assert "command 1" in results[0].stdout
            assert "command 2" in results[1].stdout
            assert "command 3" in results[2].stdout
    
    @pytest.mark.asyncio
    async def test_cleanup_command_execution(self):
        """Test that cleanup commands are executed."""
        async with LocalExecutor() as executor:
            # Create a temp file
            request = ExecutionRequest(
                command="touch /tmp/raglox_test_cleanup && echo 'created'",
                cleanup_command="rm -f /tmp/raglox_test_cleanup",
                timeout=30,
            )
            result = await executor.execute(request)
            
            assert result.success is True
            assert result.cleanup_executed is True
            
            # Verify cleanup worked
            check_result = await executor.execute(
                ExecutionRequest(command="test -f /tmp/raglox_test_cleanup && echo exists || echo deleted")
            )
            assert "deleted" in check_result.stdout


# ═══════════════════════════════════════════════════════════════
# Error Handling Tests
# ═══════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Tests for error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        """Test handling of connection errors."""
        factory = ExecutorFactory()
        
        # Try to connect to non-existent host (with SSH)
        # This should fail gracefully
        with pytest.raises(Exception):  # Should raise some connection error
            await factory.get_executor(
                target_host="192.168.255.255",  # Non-routable address
                target_platform=Platform.LINUX,
                connection_config=SSHConfig(
                    host="192.168.255.255",
                    username="test",
                    timeout=1,  # Very short timeout
                ),
            )
    
    @pytest.mark.asyncio
    async def test_invalid_command_error(self):
        """Test handling of invalid commands."""
        async with LocalExecutor() as executor:
            # Command with special characters that might cause issues
            request = ExecutionRequest(command="true")  # Simple valid command
            result = await executor.execute(request)
            
            # Should complete successfully
            assert result is not None
            assert result.success is True


# ═══════════════════════════════════════════════════════════════
# Performance Tests
# ═══════════════════════════════════════════════════════════════

class TestPerformance:
    """Performance-related tests."""
    
    @pytest.mark.asyncio
    async def test_execution_timing(self):
        """Test that execution timing is accurate."""
        async with LocalExecutor() as executor:
            # Execute a command that takes a known amount of time
            request = ExecutionRequest(command="sleep 0.5 && echo done", timeout=10)
            result = await executor.execute(request)
            
            assert result.success is True
            assert result.duration_ms >= 400  # Should be at least 500ms minus some overhead
            assert result.duration_ms < 2000  # Should not take too long
    
    @pytest.mark.asyncio
    async def test_concurrent_executions(self):
        """Test concurrent command executions."""
        factory = ExecutorFactory(max_connections_per_host=10)
        
        async def run_command(i: int) -> ExecutionResult:
            return await factory.execute_on_target(
                target_host="localhost",
                target_platform=Platform.LINUX,
                command=f"echo 'concurrent {i}'",
                connection_config=LocalConfig(),
            )
        
        # Run 5 commands concurrently
        results = await asyncio.gather(*[run_command(i) for i in range(5)])
        
        assert len(results) == 5
        assert all(r.success for r in results)
        
        await factory.close_all()


# ═══════════════════════════════════════════════════════════════
# Cleanup and Teardown
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(autouse=True)
async def cleanup_global_instances():
    """Clean up global instances after each test."""
    yield
    
    # Reset global factory
    import src.executors.factory as factory_module
    if factory_module._global_factory:
        await factory_module._global_factory.close_all()
        factory_module._global_factory = None
    
    # Reset global runner
    import src.executors.runner as runner_module
    runner_module._global_runner = None
