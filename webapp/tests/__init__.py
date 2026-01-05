# RAGLOX v3.0 - Red Team Integration Tests
"""
This package contains comprehensive offensive security testing suites:

1. offensive_integration_tests.py - Core MITRE ATT&CK integration tests
2. redteam_scenarios_tests.py - Realistic Red Team engagement scenarios
3. advanced_attack_scenarios_tests.py - Cloud, macOS, and advanced attacks

Run all tests:
    pytest webapp/tests/ -v

Run specific suite:
    pytest webapp/tests/redteam_scenarios_tests.py -v

Run with coverage report:
    pytest webapp/tests/ -v --cov=src --cov-report=html
"""
