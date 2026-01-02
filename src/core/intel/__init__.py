# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Intel/CTI Module
# Breach Data and Threat Intelligence Integration
# ═══════════════════════════════════════════════════════════════

"""
Intel Module - Breach Data and Threat Intelligence Integration.

This module provides integration with leaked/breached data sources
for credential intelligence gathering.

Components:
- BreachDataProvider: Abstract interface for breach data sources
- MockBreachProvider: Test provider with simulated data
- FileSearchProvider: Provider that searches local files
- ElasticsearchBreachProvider: Provider for Elasticsearch Data Lake
- IntelCredential: Credential with source metadata and reliability

Architecture:
┌────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ IntelSpecialist│────▶│ BreachDataProvider│────▶│ Data Sources    │
│                │     │ (Interface)       │     │ - Mock          │
│                │     └──────────────────┘     │ - File Search   │
│                │              │               │ - Elasticsearch │
│                │              │               │ - External APIs │
└────────────────┘              │               └─────────────────┘
                                ▼
                    ┌──────────────────────┐
                    │ IntelCredential      │
                    │ - username/password  │
                    │ - source metadata    │
                    │ - reliability_score  │
                    └──────────────────────┘

Data Flow:
1. IntelSpecialist receives NewTargetEvent
2. Queries BreachDataProvider with domain/IP
3. Returns IntelCredentials with source metadata
4. Credentials stored in Blackboard with reliability_score
5. AttackSpecialist prioritizes high-reliability credentials

Elasticsearch Integration:
- Connects to Data Lake with leaked credentials
- Smart field extraction for unstructured data
- Handles various naming conventions
- Automatic retry on connection failures
"""

from .base import (
    BreachDataProvider,
    IntelCredential,
    IntelSearchResult,
    BreachSource,
)
from .mock_provider import MockBreachProvider
from .file_provider import FileSearchProvider

# Elasticsearch provider is optional (requires elasticsearch package)
try:
    from .elasticsearch_provider import ElasticsearchBreachProvider, ELASTICSEARCH_AVAILABLE
except ImportError:
    ElasticsearchBreachProvider = None  # type: ignore
    ELASTICSEARCH_AVAILABLE = False

__all__ = [
    # Base types
    "BreachDataProvider",
    "IntelCredential",
    "IntelSearchResult",
    "BreachSource",
    # Providers
    "MockBreachProvider",
    "FileSearchProvider",
    "ElasticsearchBreachProvider",
    "ELASTICSEARCH_AVAILABLE",
]

__version__ = "3.0.0"
