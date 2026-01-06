# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Real Integration Tests Configuration
# Pytest fixtures and configuration for real-world testing
# ═══════════════════════════════════════════════════════════════════════════════

import os
import pytest
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("raglox.tests.real")


# ═══════════════════════════════════════════════════════════════════════════════
# Test Environment Configuration
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RealTestConfig:
    """Configuration for real integration tests."""
    
    # SSH Configuration
    ssh_host: str
    ssh_port: int = 22
    ssh_user: str = "root"
    ssh_password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    
    # Target Configuration
    target_network: str = "192.168.1.0/24"
    vulnerable_host: Optional[str] = None
    
    # Test Control
    test_mode: str = "dry_run"  # 'dry_run', 'safe', 'real'
    timeout_seconds: int = 300
    max_parallel_tasks: int = 5
    
    # Tool Availability
    available_tools: List[str] = None
    
    def __post_init__(self):
        self.available_tools = self.available_tools or []
    
    @classmethod
    def from_env(cls) -> 'RealTestConfig':
        """Load configuration from environment variables."""
        return cls(
            ssh_host=os.getenv('TEST_SSH_HOST', ''),
            ssh_port=int(os.getenv('TEST_SSH_PORT', '22')),
            ssh_user=os.getenv('TEST_SSH_USER', 'root'),
            ssh_password=os.getenv('TEST_SSH_PASSWORD'),
            ssh_key_path=os.getenv('TEST_SSH_KEY'),
            target_network=os.getenv('TEST_TARGET_NETWORK', '192.168.1.0/24'),
            vulnerable_host=os.getenv('TEST_VULNERABLE_HOST'),
            test_mode=os.getenv('RAGLOX_TEST_MODE', 'dry_run'),
            timeout_seconds=int(os.getenv('TEST_TIMEOUT', '300')),
            max_parallel_tasks=int(os.getenv('TEST_MAX_PARALLEL', '5')),
        )
    
    @property
    def is_real_mode(self) -> bool:
        """Check if running in real test mode."""
        return self.test_mode == 'real'
    
    @property
    def is_safe_mode(self) -> bool:
        """Check if running in safe test mode."""
        return self.test_mode == 'safe'
    
    @property
    def has_valid_ssh(self) -> bool:
        """Check if SSH configuration is valid."""
        return bool(self.ssh_host) and (bool(self.ssh_password) or bool(self.ssh_key_path))


# ═══════════════════════════════════════════════════════════════════════════════
# Pytest Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_config() -> RealTestConfig:
    """Load test configuration from environment."""
    config = RealTestConfig.from_env()
    logger.info(f"Test Mode: {config.test_mode}")
    logger.info(f"SSH Host: {config.ssh_host or 'NOT CONFIGURED'}")
    logger.info(f"Target Network: {config.target_network}")
    return config


@pytest.fixture(scope="session")
def require_real_mode(test_config: RealTestConfig):
    """Skip test if not in real mode."""
    if not test_config.is_real_mode:
        pytest.skip("Skipping: RAGLOX_TEST_MODE != 'real'")


@pytest.fixture(scope="session")
def require_ssh(test_config: RealTestConfig):
    """Skip test if SSH not configured."""
    if not test_config.has_valid_ssh:
        pytest.skip("Skipping: SSH not configured (set TEST_SSH_HOST, TEST_SSH_USER, TEST_SSH_PASSWORD/TEST_SSH_KEY)")


@pytest.fixture(scope="session")
def require_vulnerable_host(test_config: RealTestConfig):
    """Skip test if no vulnerable host configured."""
    if not test_config.vulnerable_host:
        pytest.skip("Skipping: No vulnerable host configured (set TEST_VULNERABLE_HOST)")


@pytest.fixture(scope="session")
async def ssh_executor(test_config: RealTestConfig):
    """Create SSH executor for tests."""
    if not test_config.has_valid_ssh:
        pytest.skip("SSH not configured")
    
    # Import here to avoid issues if dependencies missing
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))
        
        from executors.ssh import SSHExecutor
        from executors.models import SSHConfig
        from pydantic import SecretStr
        
        config = SSHConfig(
            host=test_config.ssh_host,
            port=test_config.ssh_port,
            username=test_config.ssh_user,
            password=SecretStr(test_config.ssh_password) if test_config.ssh_password else None,
            private_key=test_config.ssh_key_path,
            timeout=test_config.timeout_seconds,
        )
        
        executor = SSHExecutor(config)
        await executor.connect()
        
        yield executor
        
        await executor.disconnect()
        
    except ImportError as e:
        pytest.skip(f"Missing dependency: {e}")


@pytest.fixture(scope="session")
async def tool_manager(test_config: RealTestConfig):
    """Create tool manager for tests."""
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))
        
        from infrastructure.tools.tool_manager import ToolManager
        
        manager = ToolManager()
        await manager.initialize()
        
        yield manager
        
    except ImportError as e:
        pytest.skip(f"Missing dependency: {e}")


@pytest.fixture
def safe_only(test_config: RealTestConfig):
    """Mark test as safe (non-destructive)."""
    pass  # This fixture is used as marker


@pytest.fixture
def requires_tools(test_config: RealTestConfig):
    """Verify required tools are available."""
    def _checker(tools: List[str]):
        missing = [t for t in tools if t not in test_config.available_tools]
        if missing:
            pytest.skip(f"Missing tools: {missing}")
    return _checker


# ═══════════════════════════════════════════════════════════════════════════════
# Test Result Tracking
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TestExecutionResult:
    """Track test execution results."""
    test_name: str
    passed: bool
    duration_ms: float
    output: str
    error: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        self.metadata = self.metadata or {}


class TestResultCollector:
    """Collect test results for reporting."""
    
    def __init__(self):
        self.results: List[TestExecutionResult] = []
    
    def add(self, result: TestExecutionResult):
        self.results.append(result)
    
    @property
    def passed(self) -> int:
        return len([r for r in self.results if r.passed])
    
    @property
    def failed(self) -> int:
        return len([r for r in self.results if not r.passed])
    
    @property
    def total(self) -> int:
        return len(self.results)
    
    def generate_report(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total": self.total,
                "passed": self.passed,
                "failed": self.failed,
                "pass_rate": f"{(self.passed / self.total * 100):.1f}%" if self.total > 0 else "N/A"
            },
            "results": [
                {
                    "name": r.test_name,
                    "passed": r.passed,
                    "duration_ms": r.duration_ms,
                    "error": r.error,
                    "metadata": r.metadata
                }
                for r in self.results
            ]
        }


@pytest.fixture(scope="session")
def result_collector() -> TestResultCollector:
    """Create test result collector."""
    return TestResultCollector()


# ═══════════════════════════════════════════════════════════════════════════════
# Safety Checks
# ═══════════════════════════════════════════════════════════════════════════════

def verify_test_safety(config: RealTestConfig):
    """Verify test environment safety before real execution."""
    warnings = []
    
    # Check for production indicators
    if config.ssh_host:
        # Warn if targeting common production names
        prod_indicators = ['prod', 'production', 'live', 'main', 'primary']
        for indicator in prod_indicators:
            if indicator in config.ssh_host.lower():
                warnings.append(f"Target host '{config.ssh_host}' contains production indicator '{indicator}'")
    
    # Check network ranges
    if config.target_network:
        # Warn if targeting wide ranges
        if '/8' in config.target_network or '/16' in config.target_network:
            warnings.append(f"Wide network range specified: {config.target_network}")
    
    if warnings:
        logger.warning("⚠️ SAFETY WARNINGS:")
        for w in warnings:
            logger.warning(f"  - {w}")
        
        if config.is_real_mode:
            confirm = os.getenv('RAGLOX_CONFIRM_DANGEROUS', 'no')
            if confirm.lower() != 'yes':
                raise RuntimeError(
                    "Safety check failed. Set RAGLOX_CONFIRM_DANGEROUS=yes to proceed."
                )
    
    return True


@pytest.fixture(scope="session", autouse=True)
def safety_check(test_config: RealTestConfig):
    """Run safety check before tests."""
    if test_config.is_real_mode:
        verify_test_safety(test_config)
    logger.info("✅ Safety check passed")
