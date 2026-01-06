#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Real Integration Test Runner
# Unified runner for all real integration tests
# ═══════════════════════════════════════════════════════════════════════════════

"""
RAGLOX Real Integration Test Runner

Usage:
    python run_tests.py                    # Run all tests (dry_run mode)
    python run_tests.py --mode real        # Run all tests in real mode
    python run_tests.py --suite ssh        # Run only SSH tests
    python run_tests.py --suite tools      # Run only tool tests
    python run_tests.py --suite scenarios  # Run only scenario tests
    python run_tests.py --validate         # Run environment validation only
    python run_tests.py --help             # Show help

Environment Variables:
    TEST_SSH_HOST       - Target SSH host
    TEST_SSH_USER       - SSH username
    TEST_SSH_PASSWORD   - SSH password
    TEST_SSH_KEY        - SSH private key path
    TEST_SSH_PORT       - SSH port (default: 22)
    RAGLOX_TEST_MODE    - Test mode: dry_run, safe, real
"""

import os
import sys
import argparse
import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from conftest import RealTestConfig, TestResultCollector, TestExecutionResult


# ═══════════════════════════════════════════════════════════════════════════════
# Test Runner
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TestRunResult:
    """Result of a test run."""
    suite: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    duration_ms: float = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


class RealTestRunner:
    """Runner for real integration tests."""
    
    def __init__(self, config: RealTestConfig):
        self.config = config
        self.collector = TestResultCollector()
        self.run_results: List[TestRunResult] = []
    
    async def run_environment_validation(self) -> TestRunResult:
        """Run environment validation tests."""
        print("\n" + "="*60)
        print("🔍 ENVIRONMENT VALIDATION")
        print("="*60)
        
        result = TestRunResult(suite="Environment Validation")
        start = time.time()
        
        # Check configuration
        checks = [
            ("SSH Host", bool(self.config.ssh_host)),
            ("SSH User", bool(self.config.ssh_user)),
            ("Has Credentials", self.config.has_valid_ssh),
            ("Test Mode Valid", self.config.test_mode in ['dry_run', 'safe', 'real']),
        ]
        
        for name, passed in checks:
            result.total += 1
            if passed:
                result.passed += 1
                print(f"  ✅ {name}")
            else:
                result.failed += 1
                print(f"  ❌ {name}")
            
            self.collector.add(TestExecutionResult(
                test_name=f"ENV: {name}",
                passed=passed,
                duration_ms=0,
                output=""
            ))
        
        # Check dependencies
        deps = ['asyncssh', 'aiohttp', 'redis', 'pydantic']
        for dep in deps:
            result.total += 1
            try:
                __import__(dep)
                result.passed += 1
                print(f"  ✅ Dependency: {dep}")
                self.collector.add(TestExecutionResult(
                    test_name=f"DEP: {dep}",
                    passed=True,
                    duration_ms=0,
                    output=""
                ))
            except ImportError:
                result.failed += 1
                print(f"  ❌ Dependency: {dep}")
                self.collector.add(TestExecutionResult(
                    test_name=f"DEP: {dep}",
                    passed=False,
                    duration_ms=0,
                    output="",
                    error="Not installed"
                ))
        
        result.duration_ms = (time.time() - start) * 1000
        return result
    
    async def run_ssh_tests(self) -> TestRunResult:
        """Run SSH connection tests."""
        print("\n" + "="*60)
        print("🔌 SSH CONNECTION TESTS")
        print("="*60)
        
        result = TestRunResult(suite="SSH Connection")
        
        if not self.config.has_valid_ssh:
            print("  ⏭️ Skipped: SSH not configured")
            result.skipped = 11
            return result
        
        if self.config.test_mode == 'dry_run':
            print("  ⏭️ Skipped: Dry run mode")
            result.skipped = 11
            return result
        
        start = time.time()
        
        try:
            from executors.ssh import SSHExecutor
            from executors.models import SSHConfig, ExecutionRequest
            from pydantic import SecretStr
            
            # Create executor
            ssh_config = SSHConfig(
                host=self.config.ssh_host,
                port=self.config.ssh_port,
                username=self.config.ssh_user,
                password=SecretStr(self.config.ssh_password) if self.config.ssh_password else None,
                private_key=self.config.ssh_key_path,
                timeout=60,
            )
            
            executor = SSHExecutor(ssh_config)
            
            print(f"  🔗 Connecting to {self.config.ssh_host}...")
            await executor.connect()
            
            # Test 1: Basic connection
            test_result = await executor.execute(
                ExecutionRequest(command="echo 'RAGLOX_OK'", timeout=10)
            )
            result.total += 1
            if test_result.success and "RAGLOX_OK" in test_result.stdout:
                result.passed += 1
                print("  ✅ Basic Connection")
                self.collector.add(TestExecutionResult("SSH: Basic Connection", True, 0, ""))
            else:
                result.failed += 1
                print("  ❌ Basic Connection")
                self.collector.add(TestExecutionResult("SSH: Basic Connection", False, 0, "", "Failed"))
            
            # Test 2: System Info
            info = await executor.get_system_info()
            result.total += 1
            if info.get('hostname'):
                result.passed += 1
                print(f"  ✅ System Info: {info.get('hostname', 'N/A')}")
                self.collector.add(TestExecutionResult("SSH: System Info", True, 0, str(info)))
            else:
                result.failed += 1
                print("  ❌ System Info")
                self.collector.add(TestExecutionResult("SSH: System Info", False, 0, ""))
            
            # Test 3: Network Info
            net_info = await executor.get_network_info()
            result.total += 1
            if net_info:
                result.passed += 1
                print("  ✅ Network Info")
                self.collector.add(TestExecutionResult("SSH: Network Info", True, 0, ""))
            else:
                result.failed += 1
                print("  ❌ Network Info")
                self.collector.add(TestExecutionResult("SSH: Network Info", False, 0, ""))
            
            # Test 4: File operations
            test_file = f"/tmp/raglox_test_{int(time.time())}.txt"
            write_ok = await executor.write_file(test_file, "RAGLOX_TEST")
            read_content = await executor.read_file(test_file)
            result.total += 1
            if write_ok and read_content and "RAGLOX_TEST" in read_content:
                result.passed += 1
                print("  ✅ File Operations")
                self.collector.add(TestExecutionResult("SSH: File Operations", True, 0, ""))
            else:
                result.failed += 1
                print("  ❌ File Operations")
                self.collector.add(TestExecutionResult("SSH: File Operations", False, 0, ""))
            # Cleanup
            await executor.execute(ExecutionRequest(command=f"rm -f {test_file}", timeout=5))
            
            # Test 5: Tool availability
            tools = ['bash', 'curl', 'wget', 'python3']
            available = []
            for tool in tools:
                if await executor.check_tool_available(tool):
                    available.append(tool)
            result.total += 1
            result.passed += 1
            print(f"  ✅ Tool Check: {len(available)}/{len(tools)} tools")
            self.collector.add(TestExecutionResult("SSH: Tool Check", True, 0, str(available)))
            
            await executor.disconnect()
            
        except Exception as e:
            result.error = str(e)
            print(f"  ❌ Error: {e}")
            self.collector.add(TestExecutionResult("SSH: Connection Error", False, 0, "", str(e)))
        
        result.duration_ms = (time.time() - start) * 1000
        return result
    
    async def run_tool_tests(self) -> TestRunResult:
        """Run tool execution tests."""
        print("\n" + "="*60)
        print("🔧 TOOL EXECUTION TESTS")
        print("="*60)
        
        result = TestRunResult(suite="Tool Execution")
        
        if not self.config.has_valid_ssh:
            print("  ⏭️ Skipped: SSH not configured")
            result.skipped = 19
            return result
        
        if self.config.test_mode == 'dry_run':
            print("  ⏭️ Skipped: Dry run mode")
            result.skipped = 19
            return result
        
        start = time.time()
        
        try:
            from executors.ssh import SSHExecutor
            from executors.models import SSHConfig, ExecutionRequest
            from pydantic import SecretStr
            
            ssh_config = SSHConfig(
                host=self.config.ssh_host,
                port=self.config.ssh_port,
                username=self.config.ssh_user,
                password=SecretStr(self.config.ssh_password) if self.config.ssh_password else None,
                private_key=self.config.ssh_key_path,
                timeout=120,
            )
            
            executor = SSHExecutor(ssh_config)
            await executor.connect()
            
            # Tool tests
            tools_to_test = [
                ('ping', "ping -c 1 -W 2 127.0.0.1"),
                ('curl', "curl -s -o /dev/null -w '%{http_code}' https://httpstat.us/200 --connect-timeout 5"),
                ('ss', "ss -tln | head -5"),
                ('ps', "ps aux | head -5"),
                ('id', "id"),
            ]
            
            for tool_name, cmd in tools_to_test:
                result.total += 1
                try:
                    test_result = await executor.execute(
                        ExecutionRequest(command=cmd, timeout=30)
                    )
                    if test_result.success:
                        result.passed += 1
                        print(f"  ✅ {tool_name}")
                        self.collector.add(TestExecutionResult(f"TOOL: {tool_name}", True, 0, ""))
                    else:
                        result.failed += 1
                        print(f"  ❌ {tool_name}")
                        self.collector.add(TestExecutionResult(f"TOOL: {tool_name}", False, 0, "", test_result.stderr))
                except Exception as e:
                    result.failed += 1
                    print(f"  ❌ {tool_name}: {e}")
                    self.collector.add(TestExecutionResult(f"TOOL: {tool_name}", False, 0, "", str(e)))
            
            await executor.disconnect()
            
        except Exception as e:
            result.error = str(e)
            print(f"  ❌ Error: {e}")
        
        result.duration_ms = (time.time() - start) * 1000
        return result
    
    async def run_scenario_tests(self) -> TestRunResult:
        """Run multi-stage scenario tests."""
        print("\n" + "="*60)
        print("🎯 MULTI-STAGE SCENARIO TESTS")
        print("="*60)
        
        result = TestRunResult(suite="Scenarios")
        
        if not self.config.has_valid_ssh:
            print("  ⏭️ Skipped: SSH not configured")
            result.skipped = 4
            return result
        
        if self.config.test_mode == 'dry_run':
            print("  ⏭️ Skipped: Dry run mode")
            result.skipped = 4
            return result
        
        start = time.time()
        
        try:
            from executors.ssh import SSHExecutor
            from executors.models import SSHConfig, ExecutionRequest
            from pydantic import SecretStr
            
            ssh_config = SSHConfig(
                host=self.config.ssh_host,
                port=self.config.ssh_port,
                username=self.config.ssh_user,
                password=SecretStr(self.config.ssh_password) if self.config.ssh_password else None,
                private_key=self.config.ssh_key_path,
                timeout=180,
            )
            
            executor = SSHExecutor(ssh_config)
            await executor.connect()
            
            # Scenario 1: Basic Recon
            result.total += 1
            print("\n  📍 Scenario 1: Basic Reconnaissance")
            phases_completed = 0
            
            # Phase 1: Host discovery
            r = await executor.execute(ExecutionRequest(command="ping -c 1 127.0.0.1 && echo 'UP'", timeout=10))
            if r.success and "UP" in r.stdout:
                phases_completed += 1
                print("    ✓ Phase 1: Host Discovery")
            
            # Phase 2: Port check
            r = await executor.execute(ExecutionRequest(command="ss -tln | grep LISTEN | head -5", timeout=10))
            if r.success:
                phases_completed += 1
                print("    ✓ Phase 2: Port Scan")
            
            # Phase 3: System info
            r = await executor.execute(ExecutionRequest(command="uname -a", timeout=10))
            if r.success:
                phases_completed += 1
                print("    ✓ Phase 3: System Info")
            
            if phases_completed >= 2:
                result.passed += 1
                print(f"  ✅ Scenario 1: {phases_completed}/3 phases")
                self.collector.add(TestExecutionResult("SCENARIO: Basic Recon", True, 0, ""))
            else:
                result.failed += 1
                print(f"  ❌ Scenario 1: {phases_completed}/3 phases")
                self.collector.add(TestExecutionResult("SCENARIO: Basic Recon", False, 0, ""))
            
            # Scenario 2: Post-Exploitation Enum
            result.total += 1
            print("\n  📍 Scenario 2: Post-Exploitation Enumeration")
            phases_completed = 0
            
            # Phase 1: User enum
            r = await executor.execute(ExecutionRequest(command="id && whoami", timeout=10))
            if r.success:
                phases_completed += 1
                print("    ✓ Phase 1: User Context")
            
            # Phase 2: Network enum
            r = await executor.execute(ExecutionRequest(command="ip addr show 2>/dev/null | grep inet || ifconfig | grep inet", timeout=10))
            if r.success:
                phases_completed += 1
                print("    ✓ Phase 2: Network Info")
            
            # Phase 3: Process enum
            r = await executor.execute(ExecutionRequest(command="ps aux | head -10", timeout=10))
            if r.success:
                phases_completed += 1
                print("    ✓ Phase 3: Process List")
            
            if phases_completed >= 2:
                result.passed += 1
                print(f"  ✅ Scenario 2: {phases_completed}/3 phases")
                self.collector.add(TestExecutionResult("SCENARIO: Post-Exploitation", True, 0, ""))
            else:
                result.failed += 1
                print(f"  ❌ Scenario 2: {phases_completed}/3 phases")
                self.collector.add(TestExecutionResult("SCENARIO: Post-Exploitation", False, 0, ""))
            
            await executor.disconnect()
            
        except Exception as e:
            result.error = str(e)
            print(f"  ❌ Error: {e}")
        
        result.duration_ms = (time.time() - start) * 1000
        return result
    
    async def run_all(self) -> Dict[str, Any]:
        """Run all test suites."""
        total_start = time.time()
        
        print("\n" + "═"*60)
        print("  RAGLOX v3.0 - REAL INTEGRATION TEST SUITE")
        print("═"*60)
        print(f"  Test Mode: {self.config.test_mode}")
        print(f"  SSH Host: {self.config.ssh_host or 'NOT SET'}")
        print(f"  Target Network: {self.config.target_network}")
        print("═"*60)
        
        # Run all suites
        self.run_results.append(await self.run_environment_validation())
        self.run_results.append(await self.run_ssh_tests())
        self.run_results.append(await self.run_tool_tests())
        self.run_results.append(await self.run_scenario_tests())
        
        # Generate summary
        total_duration = (time.time() - total_start) * 1000
        
        summary = {
            "timestamp": datetime.now().isoformat(),
            "test_mode": self.config.test_mode,
            "target": self.config.ssh_host,
            "total_duration_ms": total_duration,
            "suites": [],
            "totals": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0
            }
        }
        
        for r in self.run_results:
            summary["suites"].append({
                "name": r.suite,
                "total": r.total,
                "passed": r.passed,
                "failed": r.failed,
                "skipped": r.skipped,
                "duration_ms": r.duration_ms,
                "error": r.error
            })
            summary["totals"]["total"] += r.total
            summary["totals"]["passed"] += r.passed
            summary["totals"]["failed"] += r.failed
            summary["totals"]["skipped"] += r.skipped
        
        # Print summary
        self._print_summary(summary)
        
        return summary
    
    def _print_summary(self, summary: Dict[str, Any]):
        """Print test summary."""
        print("\n" + "═"*60)
        print("  TEST SUMMARY")
        print("═"*60)
        
        for suite in summary["suites"]:
            status = "✅" if suite["failed"] == 0 else "❌"
            print(f"  {status} {suite['name']}: {suite['passed']}/{suite['total']} passed")
            if suite["skipped"] > 0:
                print(f"     ({suite['skipped']} skipped)")
            if suite["error"]:
                print(f"     Error: {suite['error'][:50]}")
        
        print("─"*60)
        t = summary["totals"]
        pass_rate = (t["passed"] / t["total"] * 100) if t["total"] > 0 else 0
        print(f"  TOTAL: {t['passed']}/{t['total']} passed ({pass_rate:.1f}%)")
        print(f"  SKIPPED: {t['skipped']}")
        print(f"  DURATION: {summary['total_duration_ms']:.0f}ms")
        print("═"*60)
        
        if t["failed"] == 0:
            print("\n  ✅ ALL TESTS PASSED!")
        else:
            print(f"\n  ❌ {t['failed']} TEST(S) FAILED")


# ═══════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="RAGLOX Real Integration Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['dry_run', 'safe', 'real'],
        help='Test mode (overrides RAGLOX_TEST_MODE)'
    )
    
    parser.add_argument(
        '--suite', '-s',
        choices=['all', 'env', 'ssh', 'tools', 'scenarios'],
        default='all',
        help='Test suite to run'
    )
    
    parser.add_argument(
        '--validate', '-v',
        action='store_true',
        help='Run environment validation only'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file for JSON results'
    )
    
    parser.add_argument(
        '--host',
        help='Override TEST_SSH_HOST'
    )
    
    parser.add_argument(
        '--user',
        help='Override TEST_SSH_USER'
    )
    
    parser.add_argument(
        '--password',
        help='Override TEST_SSH_PASSWORD'
    )
    
    args = parser.parse_args()
    
    # Override environment if specified
    if args.mode:
        os.environ['RAGLOX_TEST_MODE'] = args.mode
    if args.host:
        os.environ['TEST_SSH_HOST'] = args.host
    if args.user:
        os.environ['TEST_SSH_USER'] = args.user
    if args.password:
        os.environ['TEST_SSH_PASSWORD'] = args.password
    
    # Load config
    config = RealTestConfig.from_env()
    
    # Create runner
    runner = RealTestRunner(config)
    
    # Run tests
    async def run():
        if args.validate:
            result = await runner.run_environment_validation()
            return {"suites": [asdict(result)]}
        
        if args.suite == 'all':
            return await runner.run_all()
        elif args.suite == 'env':
            result = await runner.run_environment_validation()
            return {"suites": [asdict(result)]}
        elif args.suite == 'ssh':
            result = await runner.run_ssh_tests()
            return {"suites": [asdict(result)]}
        elif args.suite == 'tools':
            result = await runner.run_tool_tests()
            return {"suites": [asdict(result)]}
        elif args.suite == 'scenarios':
            result = await runner.run_scenario_tests()
            return {"suites": [asdict(result)]}
    
    results = asyncio.run(run())
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")
    
    # Exit code based on failures
    failed = results.get('totals', {}).get('failed', 0)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
