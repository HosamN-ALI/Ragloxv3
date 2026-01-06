# ===================================================================
# RAGLOX v3.0 - Database Layer
# PostgreSQL + asyncpg Implementation for SaaS Architecture
# ===================================================================
"""
Database Access Layer (DAL) for RAGLOX SaaS platform.

This module provides:
- Async PostgreSQL connection pooling
- Repository pattern for data access
- Multi-tenant data isolation
- Transaction support

Usage:
    from src.core.database import init_db_pool, get_db_pool, UserRepository
    
    # Initialize pool at startup
    pool = await init_db_pool(settings.database_url)
    
    # Use repositories
    user_repo = UserRepository(pool)
    user = await user_repo.get_by_id(user_id)
"""

from .connection import (
    DatabasePool,
    get_db_pool,
    init_db_pool,
    close_db_pool,
)
from .base_repository import BaseRepository
from .user_repository import UserRepository
from .organization_repository import OrganizationRepository
from .mission_repository import MissionRepository

__all__ = [
    # Connection
    "DatabasePool",
    "get_db_pool",
    "init_db_pool",
    "close_db_pool",
    # Repositories
    "BaseRepository",
    "UserRepository",
    "OrganizationRepository",
    "MissionRepository",
]
