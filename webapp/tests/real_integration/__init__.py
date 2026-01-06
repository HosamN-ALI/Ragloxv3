# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Real Integration Tests Package
# Real-world testing without mocks - actual SSH/VM environments
# ═══════════════════════════════════════════════════════════════════════════════

"""
Real Integration Test Suite for RAGLOX v3.0

This package contains tests that run against actual infrastructure:
- Real SSH connections
- Real tool execution
- Real multi-stage penetration testing scenarios
- Real vulnerability scanning

NO MOCKS - NO FAKES - REAL EXECUTION

Environment Variables:
    TEST_SSH_HOST: Target SSH host (required)
    TEST_SSH_PORT: SSH port (default: 22)
    TEST_SSH_USER: SSH username (required)
    TEST_SSH_PASSWORD: SSH password (optional)
    TEST_SSH_KEY: Path to SSH private key (optional)
    TEST_TARGET_NETWORK: Target network CIDR (default: 192.168.1.0/24)
    TEST_VULNERABLE_HOST: Known vulnerable host for exploit tests
    RAGLOX_TEST_MODE: Set to 'real' for real tests (safety check)
"""

__version__ = "3.0.0"
__author__ = "RAGLOX Team"
