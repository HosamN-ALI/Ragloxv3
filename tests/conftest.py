# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Pytest Configuration
# Shared fixtures and configuration for tests
# ═══════════════════════════════════════════════════════════════

import pytest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Configure pytest-asyncio
pytest_plugins = ['pytest_asyncio']


def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()
