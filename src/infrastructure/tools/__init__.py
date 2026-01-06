# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Tools Infrastructure
# Automated penetration testing tool management
# ═══════════════════════════════════════════════════════════════

"""
Tools Infrastructure Module

Provides automated installation and management of penetration testing tools
on execution environments (SSH, VM).

Features:
- Tool registry with 25+ common pentest tools
- Automatic dependency resolution
- Platform-aware installation
- Installation verification
- Goal-based tool recommendations

Author: RAGLOX Team
Version: 3.0.0
"""

from .tool_manager import (
    ToolManager,
    ToolManifest,
    ToolInstallResult,
    ToolStatus,
    ToolCategory,
    TOOL_REGISTRY,
    get_tool_manager,
)

__version__ = "3.0.0"
__author__ = "RAGLOX Team"

__all__ = [
    "ToolManager",
    "ToolManifest",
    "ToolInstallResult",
    "ToolStatus",
    "ToolCategory",
    "TOOL_REGISTRY",
    "get_tool_manager",
]
