# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Real SSH Connection Tests
# Tests actual SSH connections without mocks
# ═══════════════════════════════════════════════════════════════════════════════

"""
Real SSH Connection Test Suite

These tests verify actual SSH connectivity and command execution.
No mocks - real connections to real systems.

Requirements:
    - TEST_SSH_HOST environment variable
    - TEST_SSH_USER environment variable
    - TEST_SSH_PASSWORD or TEST_SSH_KEY environment variable
    - RAGLOX_TEST_MODE=real for full execution

Run:
    RAGLOX_TEST_MODE=real TEST_SSH_HOST=192.168.1.100 TEST_SSH_USER=root TEST_SSH_PASSWORD=pass pytest tests/real_integration/test_ssh_connection.py -v
"""

import os
import sys
import time
import pytest
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))

logger = logging.getLogger("raglox.tests.ssh")


# ═══════════════════════════════════════════════════════════════════════════════
# SSH Connection Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestSSHConnection:
    """Test suite for real SSH connection testing."""
    
    @pytest.mark.asyncio
    async def test_ssh_connection_basic(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-001: Basic SSH Connection
        Verify that we can establish an SSH connection to the target host.
        """
        start = time.time()
        test_name = "SSH Basic Connection"
        
        try:
            # Connection is established by fixture, just verify state
            assert ssh_executor._is_connected(), "SSH connection should be active"
            
            # Test basic command
            from executors.models import ExecutionRequest
            result = await ssh_executor.execute(
                ExecutionRequest(command="echo 'RAGLOX_TEST_CONNECTION'", timeout=30)
            )
            
            assert result.success, f"Command failed: {result.stderr}"
            assert "RAGLOX_TEST_CONNECTION" in result.stdout
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout,
                metadata={"host": test_config.ssh_host}
            ))
            
            logger.info(f"✅ {test_name}: Connection verified in {duration:.0f}ms")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"SSH connection failed: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_system_info(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-002: Get System Information
        Retrieve and verify system information from remote host.
        """
        start = time.time()
        test_name = "SSH System Info"
        
        try:
            info = await ssh_executor.get_system_info()
            
            assert 'hostname' in info, "Missing hostname"
            assert 'kernel' in info, "Missing kernel info"
            assert 'user_info' in info, "Missing user info"
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=str(info),
                metadata=info
            ))
            
            logger.info(f"✅ {test_name}:")
            logger.info(f"   Hostname: {info.get('hostname', 'N/A')}")
            logger.info(f"   Kernel: {info.get('kernel', 'N/A')[:80]}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Failed to get system info: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_network_info(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-003: Get Network Information
        Retrieve network configuration from remote host.
        """
        start = time.time()
        test_name = "SSH Network Info"
        
        try:
            info = await ssh_executor.get_network_info()
            
            assert 'interfaces' in info or 'routes' in info, "Missing network info"
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=str(info)[:500],
                metadata={"has_interfaces": 'interfaces' in info, "has_routes": 'routes' in info}
            ))
            
            logger.info(f"✅ {test_name}: Network info retrieved in {duration:.0f}ms")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Failed to get network info: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_command_execution_with_env(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-004: Command Execution with Environment Variables
        Test command execution with custom environment variables.
        """
        start = time.time()
        test_name = "SSH Command with Environment"
        
        try:
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="echo $RAGLOX_TEST_VAR",
                    timeout=30,
                    environment={"RAGLOX_TEST_VAR": "TEST_VALUE_123"}
                )
            )
            
            assert result.success, f"Command failed: {result.stderr}"
            assert "TEST_VALUE_123" in result.stdout, f"Environment variable not passed: {result.stdout}"
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout,
                metadata={"env_set": True}
            ))
            
            logger.info(f"✅ {test_name}: Environment variables work correctly")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Environment variable test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_working_directory(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-005: Command Execution with Working Directory
        Test command execution in specific working directory.
        """
        start = time.time()
        test_name = "SSH Working Directory"
        
        try:
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="pwd",
                    timeout=30,
                    working_directory="/tmp"
                )
            )
            
            assert result.success, f"Command failed: {result.stderr}"
            assert "/tmp" in result.stdout, f"Working directory not set: {result.stdout}"
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout,
                metadata={"working_dir": "/tmp"}
            ))
            
            logger.info(f"✅ {test_name}: Working directory change works")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Working directory test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_file_operations(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-006: SFTP File Operations
        Test file read/write operations via SFTP.
        """
        start = time.time()
        test_name = "SSH File Operations"
        test_file = f"/tmp/raglox_test_{int(time.time())}.txt"
        test_content = f"RAGLOX_TEST_CONTENT_{datetime.now().isoformat()}"
        
        try:
            # Write file
            write_success = await ssh_executor.write_file(test_file, test_content)
            assert write_success, "Failed to write file"
            
            # Check file exists
            exists = await ssh_executor.file_exists(test_file)
            assert exists, "File should exist after write"
            
            # Read file
            content = await ssh_executor.read_file(test_file)
            assert content is not None, "Failed to read file"
            assert test_content in content, f"Content mismatch: expected '{test_content}', got '{content}'"
            
            # Cleanup
            from executors.models import ExecutionRequest
            await ssh_executor.execute(
                ExecutionRequest(command=f"rm -f {test_file}", timeout=10)
            )
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=f"Created and verified: {test_file}",
                metadata={"file": test_file, "content_verified": True}
            ))
            
            logger.info(f"✅ {test_name}: File operations work correctly")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            # Cleanup attempt
            try:
                from executors.models import ExecutionRequest
                await ssh_executor.execute(
                    ExecutionRequest(command=f"rm -f {test_file}", timeout=10)
                )
            except:
                pass
            pytest.fail(f"File operations test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_concurrent_commands(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-007: Concurrent Command Execution
        Test multiple simultaneous commands.
        """
        start = time.time()
        test_name = "SSH Concurrent Commands"
        
        try:
            from executors.models import ExecutionRequest
            
            # Create multiple tasks
            commands = [
                "echo 'CMD1' && sleep 0.1",
                "echo 'CMD2' && sleep 0.1",
                "echo 'CMD3' && sleep 0.1",
                "echo 'CMD4' && sleep 0.1",
                "echo 'CMD5' && sleep 0.1",
            ]
            
            tasks = [
                ssh_executor.execute(ExecutionRequest(command=cmd, timeout=30))
                for cmd in commands
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Check all succeeded
            successful = 0
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.warning(f"Command {i+1} failed: {result}")
                elif result.success:
                    successful += 1
            
            assert successful >= 4, f"Too many failures: {successful}/5 succeeded"
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=f"{successful}/5 commands succeeded",
                metadata={"successful": successful, "total": 5}
            ))
            
            logger.info(f"✅ {test_name}: {successful}/5 concurrent commands succeeded in {duration:.0f}ms")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Concurrent commands test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_tool_availability_check(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-008: Check Tool Availability
        Verify ability to check tool availability on remote system.
        """
        start = time.time()
        test_name = "SSH Tool Availability Check"
        
        try:
            # Test common tools
            tools_to_check = ['bash', 'python3', 'curl', 'wget', 'nmap', 'netcat']
            availability = {}
            
            for tool in tools_to_check:
                available = await ssh_executor.check_tool_available(tool)
                availability[tool] = available
                if available:
                    test_config.available_tools.append(tool)
            
            # At least bash should be available
            assert availability.get('bash', False), "bash should be available"
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=str(availability),
                metadata=availability
            ))
            
            available_list = [t for t, a in availability.items() if a]
            logger.info(f"✅ {test_name}: Available tools: {available_list}")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Tool availability check failed: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_error_handling(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-009: Error Handling
        Test that errors are properly captured and reported.
        """
        start = time.time()
        test_name = "SSH Error Handling"
        
        try:
            from executors.models import ExecutionRequest
            
            # Test command that should fail
            result = await ssh_executor.execute(
                ExecutionRequest(command="exit 42", timeout=30)
            )
            
            # Should capture the non-zero exit code
            assert result.exit_code == 42, f"Expected exit code 42, got {result.exit_code}"
            assert not result.success, "Command with exit 42 should not be marked as success"
            
            # Test non-existent command
            result2 = await ssh_executor.execute(
                ExecutionRequest(command="this_command_does_not_exist_raglox_test", timeout=10)
            )
            
            assert not result2.success, "Non-existent command should fail"
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output="Error handling works correctly",
                metadata={"exit_code_captured": True, "nonexistent_handled": True}
            ))
            
            logger.info(f"✅ {test_name}: Error handling verified")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Error handling test failed: {e}")
    
    @pytest.mark.asyncio
    async def test_ssh_command_timeout(self, ssh_executor, test_config, result_collector):
        """
        TEST-SSH-010: Command Timeout Handling
        Test that command timeouts are properly enforced.
        """
        start = time.time()
        test_name = "SSH Command Timeout"
        
        try:
            from executors.models import ExecutionRequest
            
            # This should timeout
            result = await ssh_executor.execute(
                ExecutionRequest(
                    command="sleep 10",
                    timeout=2  # 2 second timeout
                )
            )
            
            # Either it timed out or was killed
            duration = (time.time() - start) * 1000
            
            # Should complete in ~2 seconds, not 10
            assert duration < 5000, f"Timeout not enforced: took {duration}ms"
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output="Timeout enforced correctly",
                metadata={"timeout_set": 2, "actual_duration_ms": duration}
            ))
            
            logger.info(f"✅ {test_name}: Timeout enforced in {duration:.0f}ms")
            
        except asyncio.TimeoutError:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output="TimeoutError raised as expected",
                metadata={"timeout_raised": True}
            ))
            logger.info(f"✅ {test_name}: TimeoutError raised as expected")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            # If it's a timeout-related error, that's acceptable
            if 'timeout' in str(e).lower():
                result_collector.add(TestExecutionResult(
                    test_name=test_name,
                    passed=True,
                    duration_ms=duration,
                    output=f"Timeout error: {e}",
                    metadata={"timeout_error": str(e)}
                ))
                logger.info(f"✅ {test_name}: Timeout handled: {e}")
            else:
                result_collector.add(TestExecutionResult(
                    test_name=test_name,
                    passed=False,
                    duration_ms=duration,
                    output="",
                    error=str(e)
                ))
                pytest.fail(f"Timeout test failed unexpectedly: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Connection Pool Tests (Advanced)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSSHConnectionPool:
    """Test SSH connection pool functionality."""
    
    @pytest.mark.asyncio
    async def test_reconnection_after_disconnect(self, test_config, result_collector):
        """
        TEST-SSH-011: Reconnection After Disconnect
        Test that we can reconnect after disconnecting.
        """
        if not test_config.has_valid_ssh:
            pytest.skip("SSH not configured")
        
        start = time.time()
        test_name = "SSH Reconnection"
        
        try:
            from executors.ssh import SSHExecutor
            from executors.models import SSHConfig, ExecutionRequest
            from pydantic import SecretStr
            
            config = SSHConfig(
                host=test_config.ssh_host,
                port=test_config.ssh_port,
                username=test_config.ssh_user,
                password=SecretStr(test_config.ssh_password) if test_config.ssh_password else None,
                private_key=test_config.ssh_key_path,
                timeout=30,
            )
            
            executor = SSHExecutor(config)
            
            # First connection
            await executor.connect()
            assert executor._is_connected(), "First connection failed"
            
            result1 = await executor.execute(ExecutionRequest(command="echo 'FIRST'", timeout=10))
            assert result1.success
            
            # Disconnect
            await executor.disconnect()
            assert not executor._is_connected(), "Should be disconnected"
            
            # Reconnect
            await executor.connect()
            assert executor._is_connected(), "Reconnection failed"
            
            result2 = await executor.execute(ExecutionRequest(command="echo 'SECOND'", timeout=10))
            assert result2.success
            
            await executor.disconnect()
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output="Reconnection successful",
                metadata={"reconnected": True}
            ))
            
            logger.info(f"✅ {test_name}: Reconnection works correctly")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            pytest.fail(f"Reconnection test failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# Import TestExecutionResult from conftest
# ═══════════════════════════════════════════════════════════════════════════════

try:
    from .conftest import TestExecutionResult
except ImportError:
    from conftest import TestExecutionResult


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

async def run_ssh_tests_standalone():
    """Run SSH tests without pytest for quick verification."""
    from conftest import RealTestConfig, TestResultCollector, TestExecutionResult
    
    config = RealTestConfig.from_env()
    collector = TestResultCollector()
    
    if not config.has_valid_ssh:
        print("❌ SSH not configured. Set environment variables:")
        print("   TEST_SSH_HOST=<host>")
        print("   TEST_SSH_USER=<user>")
        print("   TEST_SSH_PASSWORD=<password> or TEST_SSH_KEY=<path>")
        print("   RAGLOX_TEST_MODE=real")
        return False
    
    print(f"🔌 Connecting to {config.ssh_host}:{config.ssh_port} as {config.ssh_user}...")
    
    try:
        from executors.ssh import SSHExecutor
        from executors.models import SSHConfig, ExecutionRequest
        from pydantic import SecretStr
        
        ssh_config = SSHConfig(
            host=config.ssh_host,
            port=config.ssh_port,
            username=config.ssh_user,
            password=SecretStr(config.ssh_password) if config.ssh_password else None,
            private_key=config.ssh_key_path,
            timeout=30,
        )
        
        executor = SSHExecutor(ssh_config)
        await executor.connect()
        
        # Run basic test
        print("🧪 Running basic connection test...")
        result = await executor.execute(ExecutionRequest(command="echo 'RAGLOX_OK'", timeout=10))
        
        if result.success and "RAGLOX_OK" in result.stdout:
            print("✅ SSH Connection: SUCCESS")
            collector.add(TestExecutionResult("SSH Basic", True, 0, result.stdout))
        else:
            print(f"❌ SSH Connection: FAILED - {result.stderr}")
            collector.add(TestExecutionResult("SSH Basic", False, 0, "", result.stderr))
        
        # Run system info test
        print("🧪 Getting system info...")
        info = await executor.get_system_info()
        print(f"   Hostname: {info.get('hostname', 'N/A')}")
        print(f"   Kernel: {info.get('kernel', 'N/A')[:60]}")
        collector.add(TestExecutionResult("System Info", True, 0, str(info)))
        
        # Run tool availability test
        print("🧪 Checking tool availability...")
        tools = ['nmap', 'curl', 'wget', 'python3']
        for tool in tools:
            available = await executor.check_tool_available(tool)
            print(f"   {tool}: {'✅' if available else '❌'}")
        
        await executor.disconnect()
        
        print("\n" + "="*50)
        print(f"Results: {collector.passed}/{collector.total} passed")
        return collector.failed == 0
        
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


if __name__ == "__main__":
    import asyncio
    success = asyncio.run(run_ssh_tests_standalone())
    sys.exit(0 if success else 1)
