# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Environment Validation Tests
# Validate test environment setup and prerequisites
# ═══════════════════════════════════════════════════════════════════════════════

"""
Environment Validation Test Suite

These tests validate that the test environment is properly configured
before running real integration tests.

Run first to ensure environment is ready:
    pytest tests/real_integration/test_environment_validation.py -v
"""

import os
import sys
import time
import pytest
import asyncio
import logging
import platform
from pathlib import Path
from typing import Dict, List, Any

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))

try:
    from .conftest import TestExecutionResult, RealTestConfig
except ImportError:
    from conftest import TestExecutionResult, RealTestConfig

logger = logging.getLogger("raglox.tests.environment")


# ═══════════════════════════════════════════════════════════════════════════════
# Environment Configuration Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnvironmentConfiguration:
    """Validate environment configuration."""
    
    def test_env_variables_present(self, test_config: RealTestConfig, result_collector):
        """
        ENV-001: Check Required Environment Variables
        Verify that necessary environment variables are set.
        """
        start = time.time()
        test_name = "Environment Variables Check"
        
        try:
            required_vars = {
                "TEST_SSH_HOST": test_config.ssh_host,
                "TEST_SSH_USER": test_config.ssh_user,
            }
            
            optional_vars = {
                "TEST_SSH_PORT": test_config.ssh_port,
                "TEST_SSH_PASSWORD": "***" if test_config.ssh_password else None,
                "TEST_SSH_KEY": test_config.ssh_key_path,
                "TEST_TARGET_NETWORK": test_config.target_network,
                "RAGLOX_TEST_MODE": test_config.test_mode,
            }
            
            missing = []
            present = []
            
            for var, value in required_vars.items():
                if value:
                    present.append(var)
                else:
                    missing.append(var)
            
            duration = (time.time() - start) * 1000
            
            # Report status
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=len(missing) == 0 or test_config.test_mode == 'dry_run',
                duration_ms=duration,
                output=f"Present: {present}, Missing: {missing}",
                metadata={
                    "present": present,
                    "missing": missing,
                    "optional": {k: v is not None for k, v in optional_vars.items()}
                }
            ))
            
            if missing and test_config.test_mode != 'dry_run':
                logger.warning(f"⚠️ Missing required variables: {missing}")
            else:
                logger.info(f"✅ {test_name}: All required variables present")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
    
    def test_test_mode_configuration(self, test_config: RealTestConfig, result_collector):
        """
        ENV-002: Verify Test Mode Configuration
        Ensure test mode is properly configured.
        """
        start = time.time()
        test_name = "Test Mode Configuration"
        
        valid_modes = ['dry_run', 'safe', 'real']
        is_valid = test_config.test_mode in valid_modes
        
        duration = (time.time() - start) * 1000
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=is_valid,
            duration_ms=duration,
            output=f"Mode: {test_config.test_mode}",
            metadata={
                "current_mode": test_config.test_mode,
                "valid_modes": valid_modes,
                "is_real_mode": test_config.is_real_mode,
                "is_safe_mode": test_config.is_safe_mode
            }
        ))
        
        logger.info(f"✅ {test_name}: Mode = {test_config.test_mode}")
    
    def test_ssh_credentials_available(self, test_config: RealTestConfig, result_collector):
        """
        ENV-003: Verify SSH Credentials
        Check that SSH credentials are configured.
        """
        start = time.time()
        test_name = "SSH Credentials Check"
        
        has_password = bool(test_config.ssh_password)
        has_key = bool(test_config.ssh_key_path)
        has_credentials = has_password or has_key
        
        # If key specified, verify file exists
        key_exists = False
        if has_key:
            key_path = Path(test_config.ssh_key_path).expanduser()
            key_exists = key_path.exists()
        
        duration = (time.time() - start) * 1000
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=has_credentials or test_config.test_mode == 'dry_run',
            duration_ms=duration,
            output=f"Password: {'SET' if has_password else 'NOT SET'}, Key: {'SET' if has_key else 'NOT SET'}",
            metadata={
                "has_password": has_password,
                "has_key": has_key,
                "key_exists": key_exists if has_key else None
            }
        ))
        
        if has_credentials:
            logger.info(f"✅ {test_name}: Credentials configured")
        else:
            logger.warning(f"⚠️ {test_name}: No credentials configured")


# ═══════════════════════════════════════════════════════════════════════════════
# Python Dependencies Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPythonDependencies:
    """Validate Python dependencies."""
    
    def test_core_dependencies(self, result_collector):
        """
        ENV-004: Check Core Python Dependencies
        Verify core dependencies are installed.
        """
        start = time.time()
        test_name = "Core Dependencies"
        
        dependencies = {}
        
        # Check each dependency
        try:
            import asyncio
            dependencies['asyncio'] = True
        except ImportError:
            dependencies['asyncio'] = False
        
        try:
            import aiohttp
            dependencies['aiohttp'] = True
        except ImportError:
            dependencies['aiohttp'] = False
        
        try:
            import redis
            dependencies['redis'] = True
        except ImportError:
            dependencies['redis'] = False
        
        try:
            import pydantic
            dependencies['pydantic'] = True
        except ImportError:
            dependencies['pydantic'] = False
        
        try:
            import pytest
            dependencies['pytest'] = True
        except ImportError:
            dependencies['pytest'] = False
        
        duration = (time.time() - start) * 1000
        
        all_present = all(dependencies.values())
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=all_present,
            duration_ms=duration,
            output=str(dependencies),
            metadata=dependencies
        ))
        
        if all_present:
            logger.info(f"✅ {test_name}: All core dependencies present")
        else:
            missing = [k for k, v in dependencies.items() if not v]
            logger.warning(f"⚠️ {test_name}: Missing: {missing}")
    
    def test_ssh_library(self, result_collector):
        """
        ENV-005: Check SSH Library (asyncssh)
        Verify asyncssh is installed for SSH functionality.
        """
        start = time.time()
        test_name = "SSH Library (asyncssh)"
        
        try:
            import asyncssh
            installed = True
            version = getattr(asyncssh, '__version__', 'unknown')
        except ImportError:
            installed = False
            version = None
        
        duration = (time.time() - start) * 1000
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=installed,
            duration_ms=duration,
            output=f"asyncssh {'v' + version if version else 'not installed'}",
            metadata={"installed": installed, "version": version}
        ))
        
        if installed:
            logger.info(f"✅ {test_name}: asyncssh v{version}")
        else:
            logger.warning(f"⚠️ {test_name}: asyncssh not installed (pip install asyncssh)")
    
    def test_executor_imports(self, result_collector):
        """
        ENV-006: Check RAGLOX Executor Imports
        Verify RAGLOX executor modules can be imported.
        """
        start = time.time()
        test_name = "Executor Module Imports"
        
        imports = {}
        
        try:
            from executors.base import BaseExecutor
            imports['BaseExecutor'] = True
        except ImportError as e:
            imports['BaseExecutor'] = str(e)
        
        try:
            from executors.ssh import SSHExecutor
            imports['SSHExecutor'] = True
        except ImportError as e:
            imports['SSHExecutor'] = str(e)
        
        try:
            from executors.models import ExecutionRequest, SSHConfig
            imports['ExecutorModels'] = True
        except ImportError as e:
            imports['ExecutorModels'] = str(e)
        
        try:
            from executors.factory import ExecutorFactory
            imports['ExecutorFactory'] = True
        except ImportError as e:
            imports['ExecutorFactory'] = str(e)
        
        duration = (time.time() - start) * 1000
        
        all_success = all(v == True for v in imports.values())
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=all_success,
            duration_ms=duration,
            output=str(imports),
            metadata=imports
        ))
        
        if all_success:
            logger.info(f"✅ {test_name}: All executor modules imported")
        else:
            failed = {k: v for k, v in imports.items() if v != True}
            logger.warning(f"⚠️ {test_name}: Import failures: {failed}")


# ═══════════════════════════════════════════════════════════════════════════════
# Local System Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestLocalSystem:
    """Validate local system environment."""
    
    def test_python_version(self, result_collector):
        """
        ENV-007: Check Python Version
        Verify Python version is compatible.
        """
        start = time.time()
        test_name = "Python Version"
        
        version_info = sys.version_info
        version_str = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
        
        # Require Python 3.9+
        is_compatible = version_info.major >= 3 and version_info.minor >= 9
        
        duration = (time.time() - start) * 1000
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=is_compatible,
            duration_ms=duration,
            output=f"Python {version_str}",
            metadata={
                "version": version_str,
                "major": version_info.major,
                "minor": version_info.minor,
                "compatible": is_compatible,
                "minimum_required": "3.9"
            }
        ))
        
        if is_compatible:
            logger.info(f"✅ {test_name}: Python {version_str}")
        else:
            logger.warning(f"⚠️ {test_name}: Python {version_str} (3.9+ required)")
    
    def test_platform_info(self, result_collector):
        """
        ENV-008: Collect Platform Information
        Gather system platform information.
        """
        start = time.time()
        test_name = "Platform Information"
        
        info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_impl": platform.python_implementation(),
        }
        
        duration = (time.time() - start) * 1000
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=True,
            duration_ms=duration,
            output=f"{info['system']} {info['release']}",
            metadata=info
        ))
        
        logger.info(f"✅ {test_name}: {info['system']} {info['release']}")
    
    def test_local_tools_available(self, result_collector):
        """
        ENV-009: Check Local Tools
        Verify common tools are available locally.
        """
        import shutil
        
        start = time.time()
        test_name = "Local Tools"
        
        tools = {}
        
        # Check common tools
        tool_list = ['ssh', 'scp', 'curl', 'wget', 'git', 'python3']
        
        for tool in tool_list:
            path = shutil.which(tool)
            tools[tool] = path is not None
        
        duration = (time.time() - start) * 1000
        
        available = [t for t, a in tools.items() if a]
        missing = [t for t, a in tools.items() if not a]
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=True,  # Info only
            duration_ms=duration,
            output=f"Available: {len(available)}/{len(tool_list)}",
            metadata={"available": available, "missing": missing}
        ))
        
        logger.info(f"✅ {test_name}: {len(available)}/{len(tool_list)} tools available")


# ═══════════════════════════════════════════════════════════════════════════════
# Network Connectivity Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestNetworkConnectivity:
    """Validate network connectivity."""
    
    @pytest.mark.asyncio
    async def test_target_reachable(self, test_config: RealTestConfig, result_collector):
        """
        ENV-010: Check Target Reachability
        Verify target host is reachable.
        """
        start = time.time()
        test_name = "Target Reachability"
        
        if not test_config.ssh_host:
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=True,  # Skip if no host
                duration_ms=0,
                output="No target host configured",
                metadata={"skipped": True}
            ))
            logger.info(f"⏭️ {test_name}: Skipped (no host)")
            return
        
        try:
            import socket
            
            # Try to connect to SSH port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((test_config.ssh_host, test_config.ssh_port))
            sock.close()
            
            reachable = result == 0
            
            duration = (time.time() - start) * 1000
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=reachable,
                duration_ms=duration,
                output=f"{test_config.ssh_host}:{test_config.ssh_port} {'reachable' if reachable else 'unreachable'}",
                metadata={
                    "host": test_config.ssh_host,
                    "port": test_config.ssh_port,
                    "reachable": reachable
                }
            ))
            
            if reachable:
                logger.info(f"✅ {test_name}: {test_config.ssh_host}:{test_config.ssh_port} reachable")
            else:
                logger.warning(f"⚠️ {test_name}: {test_config.ssh_host}:{test_config.ssh_port} unreachable")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))
            logger.warning(f"⚠️ {test_name}: Connection check failed: {e}")
    
    @pytest.mark.asyncio
    async def test_internet_connectivity(self, result_collector):
        """
        ENV-011: Check Internet Connectivity
        Verify internet access is available.
        """
        start = time.time()
        test_name = "Internet Connectivity"
        
        try:
            import socket
            
            # Try to resolve a known domain
            socket.setdefaulttimeout(10)
            socket.gethostbyname('google.com')
            
            # Try to connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex(('google.com', 443))
            sock.close()
            
            has_internet = result == 0
            
            duration = (time.time() - start) * 1000
            
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=has_internet,
                duration_ms=duration,
                output="Internet access: " + ("available" if has_internet else "unavailable"),
                metadata={"has_internet": has_internet}
            ))
            
            if has_internet:
                logger.info(f"✅ {test_name}: Internet available")
            else:
                logger.warning(f"⚠️ {test_name}: No internet access")
            
        except Exception as e:
            duration = (time.time() - start) * 1000
            result_collector.add(TestExecutionResult(
                test_name=test_name,
                passed=False,
                duration_ms=duration,
                output="",
                error=str(e)
            ))


# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX Components Tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRAGLOXComponents:
    """Validate RAGLOX components."""
    
    def test_knowledge_base_accessible(self, result_collector):
        """
        ENV-012: Check Knowledge Base Files
        Verify RAGLOX knowledge base files exist.
        """
        start = time.time()
        test_name = "Knowledge Base Files"
        
        base_path = Path(__file__).parent.parent.parent.parent.parent / "data"
        
        kb_files = {
            "raglox_indexes_v2.json": base_path / "raglox_indexes_v2.json",
            "raglox_nuclei_templates.json": base_path / "raglox_nuclei_templates.json",
            "raglox_executable_modules.json": base_path / "raglox_executable_modules.json",
            "raglox_threat_library.json": base_path / "raglox_threat_library.json",
        }
        
        status = {}
        for name, path in kb_files.items():
            exists = path.exists()
            size = path.stat().st_size if exists else 0
            status[name] = {
                "exists": exists,
                "size_mb": round(size / 1024 / 1024, 2) if size else 0
            }
        
        duration = (time.time() - start) * 1000
        
        all_exist = all(s["exists"] for s in status.values())
        total_size = sum(s["size_mb"] for s in status.values())
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=all_exist,
            duration_ms=duration,
            output=f"Knowledge base: {total_size:.1f} MB",
            metadata=status
        ))
        
        if all_exist:
            logger.info(f"✅ {test_name}: {total_size:.1f} MB total")
        else:
            missing = [k for k, v in status.items() if not v["exists"]]
            logger.warning(f"⚠️ {test_name}: Missing files: {missing}")
    
    def test_core_modules_importable(self, result_collector):
        """
        ENV-013: Check Core Module Imports
        Verify RAGLOX core modules can be imported.
        """
        start = time.time()
        test_name = "Core Module Imports"
        
        imports = {}
        
        modules_to_check = [
            ("core.blackboard", "Blackboard"),
            ("core.mission_controller", "MissionController"),
            ("core.specialists.base", "BaseSpecialist"),
            ("intelligence.adaptive_learning", "AdaptiveLearningLayer"),
            ("knowledge.embedded", "EmbeddedKnowledge"),
        ]
        
        for module_path, class_name in modules_to_check:
            try:
                module = __import__(f"{module_path}", fromlist=[class_name])
                getattr(module, class_name)
                imports[module_path] = True
            except (ImportError, AttributeError) as e:
                imports[module_path] = str(e)[:100]
        
        duration = (time.time() - start) * 1000
        
        success_count = sum(1 for v in imports.values() if v == True)
        
        result_collector.add(TestExecutionResult(
            test_name=test_name,
            passed=success_count >= len(modules_to_check) * 0.5,  # At least 50% should work
            duration_ms=duration,
            output=f"{success_count}/{len(modules_to_check)} modules importable",
            metadata=imports
        ))
        
        logger.info(f"{'✅' if success_count == len(modules_to_check) else '⚠️'} {test_name}: {success_count}/{len(modules_to_check)}")


# ═══════════════════════════════════════════════════════════════════════════════
# Environment Report Generator
# ═══════════════════════════════════════════════════════════════════════════════

class TestEnvironmentReport:
    """Generate comprehensive environment report."""
    
    def test_generate_environment_report(self, test_config: RealTestConfig, result_collector):
        """
        ENV-014: Generate Environment Report
        Create comprehensive environment status report.
        """
        report = result_collector.generate_report()
        
        print("\n" + "="*70)
        print("RAGLOX v3.0 - ENVIRONMENT VALIDATION REPORT")
        print("="*70)
        print(f"\n📊 Summary:")
        print(f"   Total Checks: {report['summary']['total']}")
        print(f"   Passed: {report['summary']['passed']}")
        print(f"   Failed: {report['summary']['failed']}")
        print(f"   Pass Rate: {report['summary']['pass_rate']}")
        
        print(f"\n🔧 Test Configuration:")
        print(f"   Test Mode: {test_config.test_mode}")
        print(f"   SSH Host: {test_config.ssh_host or 'NOT SET'}")
        print(f"   SSH User: {test_config.ssh_user}")
        print(f"   Has Credentials: {test_config.has_valid_ssh}")
        print(f"   Target Network: {test_config.target_network}")
        
        print(f"\n📋 Check Results:")
        for result in report['results']:
            status = "✅" if result['passed'] else "❌"
            print(f"   {status} {result['name']}")
            if result.get('error'):
                print(f"      Error: {result['error'][:60]}")
        
        print("\n" + "="*70)
        
        # Overall readiness
        critical_checks = ['Environment Variables Check', 'SSH Credentials Check', 'Target Reachability']
        critical_passed = sum(1 for r in report['results'] if r['name'] in critical_checks and r['passed'])
        
        if test_config.test_mode == 'dry_run':
            print("🔔 Status: DRY RUN MODE - No real tests will be executed")
        elif critical_passed == len(critical_checks):
            print("✅ Status: READY FOR REAL INTEGRATION TESTING")
        else:
            print("⚠️ Status: ENVIRONMENT NOT FULLY CONFIGURED")
            print("   Fix the failed checks above before running real tests.")
        
        print("="*70 + "\n")


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone Runner
# ═══════════════════════════════════════════════════════════════════════════════

def run_environment_check():
    """Run environment validation without pytest."""
    from .conftest import RealTestConfig, TestResultCollector
    
    config = RealTestConfig.from_env()
    
    print("\n" + "="*60)
    print("RAGLOX v3.0 - Environment Validation")
    print("="*60)
    
    print(f"\n🔧 Configuration:")
    print(f"   Test Mode: {config.test_mode}")
    print(f"   SSH Host: {config.ssh_host or 'NOT SET'}")
    print(f"   SSH Port: {config.ssh_port}")
    print(f"   SSH User: {config.ssh_user}")
    print(f"   Has Password: {bool(config.ssh_password)}")
    print(f"   Has Key: {bool(config.ssh_key_path)}")
    
    print(f"\n📦 Python Environment:")
    print(f"   Python: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    print(f"   Platform: {platform.system()} {platform.release()}")
    
    print(f"\n📚 Dependencies:")
    deps = ['asyncssh', 'aiohttp', 'redis', 'pydantic', 'pytest']
    for dep in deps:
        try:
            __import__(dep)
            print(f"   ✅ {dep}")
        except ImportError:
            print(f"   ❌ {dep}")
    
    print("\n" + "="*60)
    
    if config.has_valid_ssh and config.test_mode == 'real':
        print("✅ Environment ready for real integration tests")
        return True
    elif config.test_mode == 'dry_run':
        print("🔔 Dry run mode - real tests skipped")
        return True
    else:
        print("⚠️ Configure environment variables for real tests:")
        print("   export TEST_SSH_HOST=<host>")
        print("   export TEST_SSH_USER=<user>")
        print("   export TEST_SSH_PASSWORD=<password>")
        print("   export RAGLOX_TEST_MODE=real")
        return False


if __name__ == "__main__":
    success = run_environment_check()
    sys.exit(0 if success else 1)
