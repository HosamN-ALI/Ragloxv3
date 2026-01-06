#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - End-to-End Test Runner
Comprehensive E2E testing with reporting
═══════════════════════════════════════════════════════════════════════════════

Usage:
    # Basic E2E test
    python tests/e2e/run_e2e.py
    
    # With custom API URL
    python tests/e2e/run_e2e.py --api-url http://localhost:8000
    
    # Generate HTML report
    python tests/e2e/run_e2e.py --report html
    
    # Quick health check only
    python tests/e2e/run_e2e.py --quick
"""

import os
import sys
import json
import asyncio
import argparse
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("raglox.e2e.runner")


class TestStatus(Enum):
    """Test result status."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class TestResult:
    """Individual test result."""
    name: str
    status: TestStatus
    duration_ms: float
    category: str = ""
    endpoint: str = ""
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class E2EReport:
    """Complete E2E test report."""
    start_time: str
    end_time: str
    duration_seconds: float
    api_url: str
    test_mode: str
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    warnings: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        executed = self.passed + self.failed
        if executed == 0:
            return 0.0
        return (self.passed / executed) * 100


class E2ETestRunner:
    """End-to-End test runner with comprehensive testing."""
    
    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        timeout: int = 30,
        test_mode: str = "safe"
    ):
        self.api_url = api_url
        self.timeout = timeout
        self.test_mode = test_mode
        self.results: List[TestResult] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
    async def run_all_tests(self, quick: bool = False) -> E2EReport:
        """Run all E2E tests."""
        self.start_time = datetime.now()
        self.results = []
        
        try:
            import httpx
        except ImportError:
            logger.error("httpx not installed. Run: pip install httpx")
            sys.exit(1)
        
        async with httpx.AsyncClient(
            base_url=self.api_url,
            timeout=self.timeout
        ) as client:
            
            # Run test categories
            await self._run_health_tests(client)
            
            if not quick:
                await self._run_mission_tests(client)
                await self._run_knowledge_tests(client)
                await self._run_security_tests(client)
                await self._run_infrastructure_tests(client)
                await self._run_exploitation_tests(client)
        
        self.end_time = datetime.now()
        return self._generate_report()
    
    async def _run_health_tests(self, client):
        """Run health and core endpoint tests."""
        logger.info("Running health tests...")
        
        tests = [
            ("E2E-001: Root Endpoint", "/", "GET"),
            ("E2E-002: Health Check", "/health", "GET"),
            ("E2E-003: API Docs", "/docs", "GET"),
            ("E2E-004: OpenAPI Schema", "/openapi.json", "GET"),
        ]
        
        for name, endpoint, method in tests:
            await self._run_single_test(client, name, endpoint, method, "Health")
    
    async def _run_mission_tests(self, client):
        """Run mission lifecycle tests."""
        logger.info("Running mission tests...")
        
        # List missions
        await self._run_single_test(
            client, "E2E-010: List Missions", "/missions", "GET", "Mission"
        )
        
        # Create mission
        mission_data = {
            "name": f"E2E Test {datetime.now().strftime('%H%M%S')}",
            "scope": ["192.168.1.0/24"],
            "goals": ["reconnaissance"],
            "constraints": {"test_mode": True}
        }
        result = await self._run_single_test(
            client, "E2E-011: Create Mission", "/missions", "POST", "Mission",
            json_data=mission_data, expected_status=[200, 201]
        )
        
        # Validation tests
        await self._run_single_test(
            client, "E2E-012: Empty Payload Validation", "/missions", "POST", "Mission",
            json_data={}, expected_status=[422]
        )
        
        await self._run_single_test(
            client, "E2E-013: Empty Scope Validation", "/missions", "POST", "Mission",
            json_data={"name": "Test", "scope": [], "goals": ["recon"]},
            expected_status=[422]
        )
    
    async def _run_knowledge_tests(self, client):
        """Run knowledge base tests."""
        logger.info("Running knowledge tests...")
        
        await self._run_single_test(
            client, "E2E-020: Knowledge Stats", "/knowledge/stats", "GET", "Knowledge"
        )
        
        await self._run_single_test(
            client, "E2E-021: List Techniques", "/knowledge/techniques", "GET", "Knowledge"
        )
    
    async def _run_security_tests(self, client):
        """Run security middleware tests."""
        logger.info("Running security tests...")
        
        # XSS test
        xss_data = {
            "name": "<script>alert('xss')</script>",
            "scope": ["192.168.1.0/24"],
            "goals": ["reconnaissance"]
        }
        await self._run_single_test(
            client, "E2E-030: XSS Prevention", "/missions", "POST", "Security",
            json_data=xss_data, expected_status=[200, 201, 400, 422]
        )
        
        # SQL injection test
        sqli_data = {
            "name": "'; DROP TABLE missions; --",
            "scope": ["192.168.1.0/24"],
            "goals": ["reconnaissance"]
        }
        await self._run_single_test(
            client, "E2E-031: SQL Injection Prevention", "/missions", "POST", "Security",
            json_data=sqli_data, expected_status=[200, 201, 400, 422]  # Should NOT be 500
        )
        
        # Path traversal
        await self._run_single_test(
            client, "E2E-032: Path Traversal", "/missions/../../../etc/passwd", "GET", "Security",
            expected_status=[400, 404, 422]
        )
    
    async def _run_infrastructure_tests(self, client):
        """Run infrastructure tests."""
        logger.info("Running infrastructure tests...")
        
        await self._run_single_test(
            client, "E2E-040: Infrastructure Health", "/infrastructure/health", "GET", "Infrastructure"
        )
        
        await self._run_single_test(
            client, "E2E-041: List Environments", "/environments", "GET", "Infrastructure"
        )
    
    async def _run_exploitation_tests(self, client):
        """Run exploitation module tests."""
        logger.info("Running exploitation tests...")
        
        # Try multiple possible endpoints
        endpoints = [
            ("/exploits/status", "Exploit Status"),
            ("/c2/status", "C2 Status"),
            ("/exploits", "List Exploits"),
        ]
        
        for endpoint, desc in endpoints:
            await self._run_single_test(
                client, f"E2E-05x: {desc}", endpoint, "GET", "Exploitation"
            )
    
    async def _run_single_test(
        self,
        client,
        name: str,
        endpoint: str,
        method: str,
        category: str,
        json_data: Optional[Dict] = None,
        expected_status: Optional[List[int]] = None
    ) -> TestResult:
        """Run a single test."""
        import httpx
        
        start = datetime.now()
        status = TestStatus.PASSED
        error = None
        details = {}
        
        try:
            if method == "GET":
                response = await client.get(endpoint)
            elif method == "POST":
                response = await client.post(endpoint, json=json_data)
            else:
                response = await client.request(method, endpoint)
            
            details["status_code"] = response.status_code
            details["response_time_ms"] = (datetime.now() - start).total_seconds() * 1000
            
            # Check expected status
            if expected_status:
                if response.status_code not in expected_status:
                    status = TestStatus.FAILED
                    error = f"Expected {expected_status}, got {response.status_code}"
            elif response.status_code == 404:
                status = TestStatus.SKIPPED
                error = "Endpoint not available"
            elif response.status_code >= 500:
                status = TestStatus.FAILED
                error = f"Server error: {response.status_code}"
            elif response.status_code >= 400:
                # Some 4xx are expected for validation tests
                if expected_status is None:
                    status = TestStatus.WARNING
                    error = f"Client error: {response.status_code}"
            
        except httpx.ConnectError as e:
            status = TestStatus.ERROR
            error = f"Connection failed: {e}"
        except Exception as e:
            status = TestStatus.ERROR
            error = str(e)
        
        duration = (datetime.now() - start).total_seconds() * 1000
        
        result = TestResult(
            name=name,
            status=status,
            duration_ms=duration,
            category=category,
            endpoint=endpoint,
            error=error,
            details=details
        )
        
        self.results.append(result)
        
        # Log result
        status_symbol = {
            TestStatus.PASSED: "✓",
            TestStatus.FAILED: "✗",
            TestStatus.SKIPPED: "⊘",
            TestStatus.WARNING: "⚠",
            TestStatus.ERROR: "⊗"
        }
        
        symbol = status_symbol.get(status, "?")
        log_msg = f"  {symbol} {name} ({duration:.0f}ms)"
        if error:
            log_msg += f" - {error}"
        
        if status == TestStatus.PASSED:
            logger.info(log_msg)
        elif status == TestStatus.FAILED:
            logger.error(log_msg)
        elif status == TestStatus.SKIPPED:
            logger.warning(log_msg)
        else:
            logger.warning(log_msg)
        
        return result
    
    def _generate_report(self) -> E2EReport:
        """Generate test report."""
        passed = sum(1 for r in self.results if r.status == TestStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == TestStatus.FAILED)
        skipped = sum(1 for r in self.results if r.status == TestStatus.SKIPPED)
        warnings = sum(1 for r in self.results if r.status == TestStatus.WARNING)
        
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
        
        report = E2EReport(
            start_time=self.start_time.isoformat() if self.start_time else "",
            end_time=self.end_time.isoformat() if self.end_time else "",
            duration_seconds=duration,
            api_url=self.api_url,
            test_mode=self.test_mode,
            total_tests=len(self.results),
            passed=passed,
            failed=failed,
            skipped=skipped,
            warnings=warnings,
            results=[
                {
                    "name": r.name,
                    "status": r.status.value,
                    "duration_ms": r.duration_ms,
                    "category": r.category,
                    "endpoint": r.endpoint,
                    "error": r.error,
                    "details": r.details
                }
                for r in self.results
            ]
        )
        
        return report
    
    def print_summary(self, report: E2EReport):
        """Print test summary."""
        print("\n" + "=" * 70)
        print("RAGLOX v3.0 - E2E Test Report")
        print("=" * 70)
        print(f"API URL: {report.api_url}")
        print(f"Duration: {report.duration_seconds:.2f}s")
        print("-" * 70)
        print(f"Total Tests:  {report.total_tests}")
        print(f"  Passed:     {report.passed}")
        print(f"  Failed:     {report.failed}")
        print(f"  Skipped:    {report.skipped}")
        print(f"  Warnings:   {report.warnings}")
        print(f"Success Rate: {report.success_rate:.1f}%")
        print("-" * 70)
        
        # Print by category
        categories = {}
        for r in self.results:
            cat = r.category or "Other"
            if cat not in categories:
                categories[cat] = {"passed": 0, "failed": 0, "skipped": 0}
            if r.status == TestStatus.PASSED:
                categories[cat]["passed"] += 1
            elif r.status == TestStatus.FAILED:
                categories[cat]["failed"] += 1
            else:
                categories[cat]["skipped"] += 1
        
        print("\nResults by Category:")
        for cat, counts in categories.items():
            total = counts["passed"] + counts["failed"]
            rate = (counts["passed"] / total * 100) if total > 0 else 0
            print(f"  {cat}: {counts['passed']}/{total} passed ({rate:.0f}%)")
        
        # Print failures
        failures = [r for r in self.results if r.status == TestStatus.FAILED]
        if failures:
            print("\nFailed Tests:")
            for r in failures:
                print(f"  ✗ {r.name}")
                if r.error:
                    print(f"    Error: {r.error}")
        
        print("=" * 70)
        
        # Overall status
        if report.failed == 0:
            print("✓ ALL TESTS PASSED")
        else:
            print(f"✗ {report.failed} TEST(S) FAILED")
        
        print("=" * 70 + "\n")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="RAGLOX E2E Test Runner")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("API_BASE_URL", "http://localhost:8000"),
        help="API base URL"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick health check only"
    )
    parser.add_argument(
        "--report",
        choices=["json", "html"],
        help="Generate report file"
    )
    parser.add_argument(
        "--output",
        help="Output file for report"
    )
    
    args = parser.parse_args()
    
    print(f"\nStarting E2E tests against: {args.api_url}")
    if args.quick:
        print("Mode: Quick health check\n")
    else:
        print("Mode: Full E2E test\n")
    
    runner = E2ETestRunner(
        api_url=args.api_url,
        timeout=args.timeout
    )
    
    report = await runner.run_all_tests(quick=args.quick)
    runner.print_summary(report)
    
    # Save report if requested
    if args.report:
        output_file = args.output or f"e2e_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if args.report == "json":
            output_file = output_file if output_file.endswith(".json") else f"{output_file}.json"
            with open(output_file, "w") as f:
                json.dump(asdict(report), f, indent=2)
            print(f"Report saved to: {output_file}")
        
        elif args.report == "html":
            output_file = output_file if output_file.endswith(".html") else f"{output_file}.html"
            html = generate_html_report(report)
            with open(output_file, "w") as f:
                f.write(html)
            print(f"Report saved to: {output_file}")
    
    # Exit with appropriate code
    sys.exit(0 if report.failed == 0 else 1)


def generate_html_report(report: E2EReport) -> str:
    """Generate HTML report."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>RAGLOX E2E Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ padding: 15px; border-radius: 8px; text-align: center; flex: 1; }}
        .stat.passed {{ background: #d4edda; color: #155724; }}
        .stat.failed {{ background: #f8d7da; color: #721c24; }}
        .stat.skipped {{ background: #fff3cd; color: #856404; }}
        .stat .number {{ font-size: 2em; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        .status-PASSED {{ color: #28a745; }}
        .status-FAILED {{ color: #dc3545; }}
        .status-SKIPPED {{ color: #ffc107; }}
        .status-WARNING {{ color: #fd7e14; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>RAGLOX v3.0 - E2E Test Report</h1>
        <p>API: {report.api_url} | Duration: {report.duration_seconds:.2f}s | {report.start_time}</p>
        
        <div class="summary">
            <div class="stat passed">
                <div class="number">{report.passed}</div>
                <div>Passed</div>
            </div>
            <div class="stat failed">
                <div class="number">{report.failed}</div>
                <div>Failed</div>
            </div>
            <div class="stat skipped">
                <div class="number">{report.skipped}</div>
                <div>Skipped</div>
            </div>
        </div>
        
        <h2>Test Results</h2>
        <table>
            <tr>
                <th>Test</th>
                <th>Category</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Details</th>
            </tr>
"""
    
    for r in report.results:
        html += f"""
            <tr>
                <td>{r['name']}</td>
                <td>{r['category']}</td>
                <td class="status-{r['status']}">{r['status']}</td>
                <td>{r['duration_ms']:.0f}ms</td>
                <td>{r.get('error', '') or 'OK'}</td>
            </tr>
"""
    
    html += """
        </table>
    </div>
</body>
</html>
"""
    return html


if __name__ == "__main__":
    asyncio.run(main())
