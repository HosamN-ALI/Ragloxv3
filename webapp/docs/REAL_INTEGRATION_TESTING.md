# RAGLOX v3.0 - Real Integration Testing Guide

## 🎯 Overview

This guide covers the **Real Integration Testing Framework** for RAGLOX v3.0. Unlike traditional tests that use mocks, this framework tests against **real infrastructure** - actual SSH connections, real security tools, and real multi-stage penetration testing scenarios.

> ⚠️ **WARNING**: These tests interact with real systems. Only run against systems you own or have explicit authorization to test.

## 📦 Test Suite Structure

```
tests/real_integration/
├── __init__.py                    # Package initialization
├── conftest.py                    # Pytest configuration & fixtures
├── test_ssh_connection.py         # SSH connection tests
├── test_tool_execution.py         # Security tool execution tests
├── test_multistage_scenarios.py   # Multi-phase pentest scenarios
└── test_environment_validation.py # Environment validation
```

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Required environment variables
export TEST_SSH_HOST="192.168.1.100"      # Target SSH host
export TEST_SSH_USER="root"               # SSH username
export TEST_SSH_PASSWORD="password"       # SSH password (or use key)
export TEST_SSH_KEY="/path/to/key"        # SSH private key (alternative)
export RAGLOX_TEST_MODE="real"            # Enable real tests

# Optional variables
export TEST_SSH_PORT="22"                 # SSH port (default: 22)
export TEST_TARGET_NETWORK="192.168.1.0/24"  # Target network
export TEST_VULNERABLE_HOST="192.168.1.50"   # Vulnerable test host
export TEST_TIMEOUT="300"                 # Test timeout in seconds
```

### 2. Validate Environment

```bash
# Run environment validation first
cd /root/RAGLOX_V3/webapp
python -m pytest webapp/tests/real_integration/test_environment_validation.py -v

# Or use standalone check
python webapp/tests/real_integration/test_environment_validation.py
```

### 3. Run Tests

```bash
# Run all real integration tests
python -m pytest webapp/tests/real_integration/ -v

# Run specific test suite
python -m pytest webapp/tests/real_integration/test_ssh_connection.py -v
python -m pytest webapp/tests/real_integration/test_tool_execution.py -v
python -m pytest webapp/tests/real_integration/test_multistage_scenarios.py -v
```

## 📋 Test Modes

### Dry Run Mode (Default)
```bash
export RAGLOX_TEST_MODE="dry_run"
```
- No actual connections or tool execution
- Tests configuration and dependencies only
- Safe for initial setup verification

### Safe Mode
```bash
export RAGLOX_TEST_MODE="safe"
```
- Connects to target systems
- Executes read-only operations
- No modifications to target systems

### Real Mode
```bash
export RAGLOX_TEST_MODE="real"
```
- Full test execution
- All operations enabled
- Requires explicit confirmation for dangerous actions

## 🧪 Test Categories

### 1. SSH Connection Tests (`test_ssh_connection.py`)

| Test ID | Name | Description |
|---------|------|-------------|
| TEST-SSH-001 | Basic Connection | Verify SSH connection establishment |
| TEST-SSH-002 | System Info | Retrieve system information |
| TEST-SSH-003 | Network Info | Get network configuration |
| TEST-SSH-004 | Env Variables | Test command with environment |
| TEST-SSH-005 | Working Directory | Test directory change |
| TEST-SSH-006 | File Operations | SFTP read/write |
| TEST-SSH-007 | Concurrent Commands | Parallel execution |
| TEST-SSH-008 | Tool Availability | Check installed tools |
| TEST-SSH-009 | Error Handling | Verify error capture |
| TEST-SSH-010 | Timeout Handling | Test timeout enforcement |
| TEST-SSH-011 | Reconnection | Test disconnect/reconnect |

### 2. Tool Execution Tests (`test_tool_execution.py`)

| Test ID | Name | Description |
|---------|------|-------------|
| TEST-TOOL-001 | Ping Connectivity | Basic ping test |
| TEST-TOOL-002 | Nmap Localhost | Port scan localhost |
| TEST-TOOL-003 | Nmap Service | Service version detection |
| TEST-TOOL-004 | Netcat Port | Port check with nc |
| TEST-TOOL-005 | cURL Basic | HTTP request |
| TEST-TOOL-006 | cURL Headers | Header retrieval |
| TEST-TOOL-007 | wget Download | File download |
| TEST-TOOL-008 | WHOIS Lookup | Domain lookup |
| TEST-TOOL-009 | dig DNS | DNS resolution |
| TEST-TOOL-010 | host DNS | Alternative DNS lookup |
| TEST-TOOL-011 | Python Exec | Python script execution |
| TEST-TOOL-012 | Bash Exec | Bash script execution |
| TEST-TOOL-013 | AWK Processing | Text processing |
| TEST-TOOL-014 | ss Connections | Network connections |
| TEST-TOOL-015 | Process List | Process enumeration |
| TEST-TOOL-016 | User Enum | User enumeration |
| TEST-TOOL-017 | SUID Binaries | Privilege escalation recon |

### 3. Multi-Stage Scenarios (`test_multistage_scenarios.py`)

#### Scenario 01: Basic Network Reconnaissance
- Phase 1: Host Discovery (ping)
- Phase 2: Port Scanning (nmap/bash)
- Phase 3: Service Detection
- Phase 4: OS Fingerprinting

#### Scenario 02: Web Application Assessment
- Phase 1: Web Service Discovery
- Phase 2: Technology Detection (headers)
- Phase 3: HTTP Methods Check
- Phase 4: Common Vulnerability Checks

#### Scenario 03: Post-Exploitation Enumeration
- Phase 1: System & User Enumeration
- Phase 2: Network Discovery
- Phase 3: Sensitive File Discovery
- Phase 4: SUID/SGID Binary Discovery
- Phase 5: Sudo Privileges Check

#### Scenario 04: Full Attack Chain Simulation
- Phase 1: External Reconnaissance
- Phase 2: Initial Access Verification
- Phase 3: Rapid Enumeration
- Phase 4: Data Discovery
- Phase 5: Persistence Methods Analysis
- Phase 6: Cleanup (Simulated)

### 4. Environment Validation (`test_environment_validation.py`)

| Test ID | Name | Description |
|---------|------|-------------|
| ENV-001 | Env Variables | Check required vars |
| ENV-002 | Test Mode | Verify mode config |
| ENV-003 | SSH Credentials | Check credentials |
| ENV-004 | Core Dependencies | Python dependencies |
| ENV-005 | SSH Library | asyncssh availability |
| ENV-006 | Executor Imports | RAGLOX module imports |
| ENV-007 | Python Version | Version compatibility |
| ENV-008 | Platform Info | System information |
| ENV-009 | Local Tools | Local tool availability |
| ENV-010 | Target Reachable | Network connectivity |
| ENV-011 | Internet | Internet access |
| ENV-012 | Knowledge Base | KB files exist |
| ENV-013 | Core Modules | RAGLOX imports |
| ENV-014 | Environment Report | Summary report |

## 📊 Test Output

### Example Test Run
```
$ RAGLOX_TEST_MODE=real pytest webapp/tests/real_integration/ -v

============== test session starts ==============
collected 45 items

test_environment_validation.py::TestEnvironmentConfiguration::test_env_variables_present PASSED
test_environment_validation.py::TestEnvironmentConfiguration::test_test_mode_configuration PASSED
test_ssh_connection.py::TestSSHConnection::test_ssh_connection_basic PASSED
test_ssh_connection.py::TestSSHConnection::test_ssh_system_info PASSED
...
test_multistage_scenarios.py::TestScenario04FullAttackChain::test_scenario_04_attack_chain PASSED

============== RAGLOX MULTI-STAGE SCENARIO TEST REPORT ==============
Total Tests: 45
Passed: 43
Failed: 2
Pass Rate: 95.6%
=====================================================================
```

### Result Collection

All test results are collected in `TestResultCollector` with:
- Test name
- Pass/fail status
- Duration (ms)
- Output captured
- Error details (if any)
- Metadata (findings, artifacts)

## 🛡️ Safety Features

### Pre-Test Safety Check
```python
def verify_test_safety(config: RealTestConfig):
    # Warns if targeting production-like hostnames
    # Warns if using wide network ranges (/8, /16)
    # Requires RAGLOX_CONFIRM_DANGEROUS=yes for risky operations
```

### Target Restrictions
- Default tests run against localhost
- External targets require explicit configuration
- Production indicators trigger warnings

### Confirmation Requirements
```bash
# For potentially dangerous operations
export RAGLOX_CONFIRM_DANGEROUS=yes
```

## 🔧 Extending Tests

### Adding New SSH Tests
```python
class TestMySSHFeature:
    @pytest.mark.asyncio
    async def test_my_feature(self, ssh_executor, test_config, result_collector):
        start = time.time()
        test_name = "My SSH Feature"
        
        try:
            from executors.models import ExecutionRequest
            
            result = await ssh_executor.execute(
                ExecutionRequest(command="my_command", timeout=30)
            )
            
            # Verify and collect results
            assert result.success
            
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,
                duration_ms=duration,
                output=result.stdout
            ))
            
        except Exception as e:
            # Handle failures
            pytest.fail(f"Test failed: {e}")
```

### Adding New Scenarios
```python
class TestMyScenario:
    @pytest.mark.asyncio
    async def test_my_scenario(self, ssh_executor, test_config, result_collector):
        scenario = ScenarioResult(
            name="My Custom Scenario",
            target="target_host"
        )
        
        # Phase 1
        phase1_start = time.time()
        findings = []
        # ... execute phase logic ...
        scenario.add_phase(PhaseResult(
            phase=ScenarioPhase.RECONNAISSANCE,
            success=True,
            duration_ms=(time.time() - phase1_start) * 1000,
            findings=findings
        ))
        
        # Generate report
        summary = scenario.generate_summary()
```

## 🔍 Troubleshooting

### Common Issues

1. **SSH Connection Failed**
   ```
   Error: SSH authentication failed: Permission denied
   ```
   - Verify TEST_SSH_USER and TEST_SSH_PASSWORD
   - Check SSH key permissions (chmod 600)
   - Ensure SSH service is running on target

2. **Tool Not Found**
   ```
   SKIPPED: nmap not installed on target system
   ```
   - Install required tools on target
   - Or configure a fully-equipped test VM

3. **Timeout Errors**
   ```
   asyncio.TimeoutError: SSH command timed out
   ```
   - Increase TEST_TIMEOUT value
   - Check network latency
   - Verify command isn't blocking

4. **Import Errors**
   ```
   ImportError: No module named 'asyncssh'
   ```
   - Install dependencies: `pip install asyncssh aiohttp redis pydantic`

### Debug Mode

```bash
# Enable verbose logging
export RAGLOX_DEBUG=1
pytest webapp/tests/real_integration/ -v -s --log-cli-level=DEBUG
```

## 📝 Best Practices

1. **Always validate environment first**
   ```bash
   pytest test_environment_validation.py -v
   ```

2. **Start with dry_run mode**
   ```bash
   export RAGLOX_TEST_MODE=dry_run
   ```

3. **Use isolated test networks**
   - Set up VMs or containers for testing
   - Never test against production systems

4. **Review findings before proceeding**
   - Each scenario generates detailed findings
   - Review before moving to more aggressive tests

5. **Clean up after tests**
   - Remove any created files
   - Close all connections
   - Document any system changes

## 📚 Related Documentation

- [AGENT_WORKFLOW_ANALYSIS.md](AGENT_WORKFLOW_ANALYSIS.md) - Workflow architecture
- [REL_01_02_IMPLEMENTATION.md](REL_01_02_IMPLEMENTATION.md) - Reliability features
- [SEC_01_EXCEPTION_AUDIT.md](SEC_01_EXCEPTION_AUDIT.md) - Security exception handling

---

**RAGLOX v3.0** - Advanced AI-Powered Red Team Operations Platform
