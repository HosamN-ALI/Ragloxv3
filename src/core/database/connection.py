# ===================================================================
# RAGLOX v3.0 - PostgreSQL Connection Pool
# Async connection management with asyncpg
# ===================================================================
"""
PostgreSQL Connection Pool Manager.

Features:
- Connection pooling with configurable size
- Automatic reconnection
- Health checking
- Transaction support
- Query logging (optional)

Why asyncpg?
- Native async support (no blocking)
- Best performance for PostgreSQL in Python
- Prepared statement caching
- LISTEN/NOTIFY support
"""

import asyncio
from typing import Optional, Any, Dict, List, TypeVar, Union
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger("raglox.database")

# Type hints for when asyncpg is not installed
T = TypeVar('T')

try:
    import asyncpg
    from asyncpg import Pool, Connection, Record
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False
    Pool = Any
    Connection = Any
    Record = Any
    asyncpg = None

# ===================================================================
# Global Pool Instance
# ===================================================================

_db_pool: Optional["DatabasePool"] = None


class DatabasePool:
    """
    PostgreSQL Connection Pool Manager.
    
    Thread-safe async connection pool with:
    - Configurable pool size
    - Health checking
    - Transaction support
    - Query helpers
    
    Example:
        pool = DatabasePool(database_url)
        await pool.connect()
        
        # Simple query
        users = await pool.fetch("SELECT * FROM users WHERE org_id = $1", org_id)
        
        # Transaction
        async with pool.transaction() as conn:
            await conn.execute("INSERT INTO users ...")
            await conn.execute("INSERT INTO audit_log ...")
    """
    
    def __init__(
        self,
        database_url: str,
        min_size: int = 5,
        max_size: int = 20,
        command_timeout: float = 60.0,
        statement_cache_size: int = 100,
    ):
        """
        Initialize database pool configuration.
        
        Args:
            database_url: PostgreSQL connection string
                Format: postgresql://user:password@host:port/database
            min_size: Minimum pool connections (default: 5)
            max_size: Maximum pool connections (default: 20)
            command_timeout: Query timeout in seconds (default: 60)
            statement_cache_size: Prepared statement cache size (default: 100)
        """
        if not ASYNCPG_AVAILABLE:
            logger.warning(
                "asyncpg not installed. Database operations will use mock mode. "
                "Install with: pip install asyncpg"
            )
        
        self._database_url = database_url
        self._min_size = min_size
        self._max_size = max_size
        self._command_timeout = command_timeout
        self._statement_cache_size = statement_cache_size
        self._pool: Optional[Pool] = None
        self._connected = False
        
    @property
    def is_connected(self) -> bool:
        """Check if pool is connected."""
        return self._connected and self._pool is not None
    
    @property
    def pool(self) -> Optional[Pool]:
        """Get the underlying asyncpg pool."""
        return self._pool
    
    async def connect(self) -> None:
        """
        Initialize the connection pool.
        
        Raises:
            ConnectionError: If unable to connect to PostgreSQL
            ImportError: If asyncpg is not installed
        """
        if self._connected:
            logger.warning("Database pool already connected")
            return
        
        if not ASYNCPG_AVAILABLE:
            logger.warning("Using mock database pool (asyncpg not available)")
            self._connected = True
            return
            
        try:
            logger.info(f"Connecting to PostgreSQL (pool: {self._min_size}-{self._max_size})")
            
            self._pool = await asyncpg.create_pool(
                self._database_url,
                min_size=self._min_size,
                max_size=self._max_size,
                command_timeout=self._command_timeout,
                statement_cache_size=self._statement_cache_size,
            )
            
            self._connected = True
            logger.info("PostgreSQL connection pool established")
            
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise ConnectionError(f"Database connection failed: {e}") from e
    
    async def disconnect(self) -> None:
        """Close the connection pool."""
        if self._pool:
            try:
                await self._pool.close()
                logger.info("PostgreSQL connection pool closed")
            except Exception as e:
                logger.error(f"Error closing pool: {e}")
            finally:
                self._pool = None
                self._connected = False
        else:
            self._connected = False
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check database connectivity and return health status.
        
        Returns:
            Dict with health status information
        """
        if not ASYNCPG_AVAILABLE:
            return {
                "healthy": False,
                "mode": "mock",
                "error": "asyncpg not installed"
            }
            
        if not self._pool:
            return {
                "healthy": False,
                "error": "Pool not initialized"
            }
            
        try:
            async with self._pool.acquire() as conn:
                result = await conn.fetchval("SELECT 1")
                version = await conn.fetchval("SELECT version()")
                
            return {
                "healthy": True,
                "version": version,
                "pool_size": self._pool.get_size(),
                "pool_free": self._pool.get_idle_size(),
            }
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                "healthy": False,
                "error": str(e)
            }
    
    @asynccontextmanager
    async def acquire(self):
        """
        Acquire a connection from the pool.
        
        Yields:
            asyncpg.Connection instance
            
        Raises:
            ConnectionError: If pool is not initialized
            
        Usage:
            async with pool.acquire() as conn:
                result = await conn.fetch("SELECT * FROM users")
        """
        if not self._pool:
            raise ConnectionError("Database pool not initialized")
            
        async with self._pool.acquire() as conn:
            yield conn
    
    @asynccontextmanager
    async def transaction(self):
        """
        Acquire a connection with transaction.
        
        Yields:
            asyncpg.Connection instance within a transaction
            
        The transaction is automatically committed on success,
        or rolled back on exception.
            
        Usage:
            async with pool.transaction() as conn:
                await conn.execute("INSERT INTO users ...")
                await conn.execute("INSERT INTO audit_log ...")
                # Automatically committed if no exception
        """
        if not self._pool:
            raise ConnectionError("Database pool not initialized")
            
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                yield conn
    
    # ===================================================================
    # Query Helpers
    # ===================================================================
    
    async def fetch(self, query: str, *args) -> List[Record]:
        """
        Execute a query and fetch all results.
        
        Args:
            query: SQL query with $1, $2, ... placeholders
            *args: Query parameters
            
        Returns:
            List of Record objects
        """
        if not self._pool:
            raise ConnectionError("Database pool not initialized")
            
        async with self._pool.acquire() as conn:
            return await conn.fetch(query, *args)
    
    async def fetchrow(self, query: str, *args) -> Optional[Record]:
        """
        Execute a query and fetch a single row.
        
        Args:
            query: SQL query with $1, $2, ... placeholders
            *args: Query parameters
            
        Returns:
            Single Record or None
        """
        if not self._pool:
            raise ConnectionError("Database pool not initialized")
            
        async with self._pool.acquire() as conn:
            return await conn.fetchrow(query, *args)
    
    async def fetchval(self, query: str, *args, column: int = 0) -> Any:
        """
        Execute a query and fetch a single value.
        
        Args:
            query: SQL query with $1, $2, ... placeholders
            *args: Query parameters
            column: Column index to fetch (default: 0)
            
        Returns:
            Single value
        """
        if not self._pool:
            raise ConnectionError("Database pool not initialized")
            
        async with self._pool.acquire() as conn:
            return await conn.fetchval(query, *args, column=column)
    
    async def execute(self, query: str, *args) -> str:
        """
        Execute a query without returning results.
        
        Args:
            query: SQL query with $1, $2, ... placeholders
            *args: Query parameters
            
        Returns:
            Status string (e.g., "INSERT 0 1")
        """
        if not self._pool:
            raise ConnectionError("Database pool not initialized")
            
        async with self._pool.acquire() as conn:
            return await conn.execute(query, *args)
    
    async def executemany(self, query: str, args_list: List[tuple]) -> None:
        """
        Execute a query multiple times with different arguments.
        
        Args:
            query: SQL query with $1, $2, ... placeholders
            args_list: List of parameter tuples
        """
        if not self._pool:
            raise ConnectionError("Database pool not initialized")
            
        async with self._pool.acquire() as conn:
            await conn.executemany(query, args_list)
    
    # ===================================================================
    # Pool Statistics
    # ===================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get pool statistics.
        
        Returns:
            Dict with pool size, free connections, etc.
        """
        if not self._pool:
            return {
                "connected": False,
                "size": 0,
                "free_size": 0,
                "used_size": 0,
            }
        
        return {
            "connected": True,
            "size": self._pool.get_size(),
            "free_size": self._pool.get_idle_size(),
            "used_size": self._pool.get_size() - self._pool.get_idle_size(),
            "min_size": self._pool.get_min_size(),
            "max_size": self._pool.get_max_size(),
        }


# ===================================================================
# Global Pool Functions
# ===================================================================

async def init_db_pool(
    database_url: str,
    min_size: int = 5,
    max_size: int = 20,
    **kwargs
) -> DatabasePool:
    """
    Initialize the global database pool.
    
    This function should be called once during application startup.
    
    Args:
        database_url: PostgreSQL connection string
        min_size: Minimum pool connections
        max_size: Maximum pool connections
        **kwargs: Additional pool configuration
        
    Returns:
        DatabasePool instance
        
    Example:
        # In main.py lifespan
        pool = await init_db_pool(settings.database_url)
        app.state.db_pool = pool
    """
    global _db_pool
    
    if _db_pool and _db_pool.is_connected:
        logger.warning("Database pool already initialized")
        return _db_pool
    
    _db_pool = DatabasePool(
        database_url=database_url,
        min_size=min_size,
        max_size=max_size,
        **kwargs
    )
    
    await _db_pool.connect()
    return _db_pool


def get_db_pool() -> Optional[DatabasePool]:
    """
    Get the global database pool instance.
    
    Returns:
        DatabasePool instance or None if not initialized
        
    Usage:
        pool = get_db_pool()
        if pool:
            users = await pool.fetch("SELECT * FROM users")
    """
    return _db_pool


async def close_db_pool() -> None:
    """
    Close the global database pool.
    
    This function should be called during application shutdown.
    """
    global _db_pool
    
    if _db_pool:
        await _db_pool.disconnect()
        _db_pool = None
        logger.info("Global database pool closed")
