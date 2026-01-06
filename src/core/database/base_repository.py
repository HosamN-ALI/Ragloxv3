# ===================================================================
# RAGLOX v3.0 - Base Repository
# Abstract base class for all repositories
# ===================================================================
"""
Repository Pattern Implementation.

The Repository pattern provides:
- Abstraction over data access
- Centralized query logic
- Easy testing with mock repositories
- Consistent error handling

All repositories inherit from BaseRepository and implement
entity-specific methods while using shared CRUD operations.
"""

from abc import ABC, abstractmethod
from typing import Optional, Any, Dict, List, TypeVar, Generic, Type
from uuid import UUID
from datetime import datetime
import logging

from .connection import DatabasePool

logger = logging.getLogger("raglox.database")

# Generic type for entities
T = TypeVar('T')


class BaseRepository(ABC, Generic[T]):
    """
    Abstract base repository with common CRUD operations.
    
    All repositories inherit from this class and implement
    entity-specific methods.
    
    Features:
    - Multi-tenant data isolation via organization_id
    - Automatic audit logging
    - Soft delete support (optional)
    - Pagination helpers
    
    Example:
        class UserRepository(BaseRepository[User]):
            table_name = "users"
            
            async def get_by_email(self, org_id: UUID, email: str) -> Optional[User]:
                row = await self.pool.fetchrow(
                    f"SELECT * FROM {self.table_name} WHERE organization_id = $1 AND email = $2",
                    org_id, email
                )
                return self._record_to_entity(row) if row else None
    """
    
    # Subclasses must define these
    table_name: str = ""
    
    def __init__(self, pool: DatabasePool):
        """
        Initialize repository with database pool.
        
        Args:
            pool: DatabasePool instance for queries
        """
        self.pool = pool
        
        if not self.table_name:
            raise ValueError(f"{self.__class__.__name__} must define table_name")
    
    # ===================================================================
    # Abstract Methods (must be implemented by subclasses)
    # ===================================================================
    
    @abstractmethod
    def _record_to_entity(self, record: Any) -> Optional[T]:
        """
        Convert database record to entity object.
        
        Args:
            record: asyncpg Record object
            
        Returns:
            Entity instance or None
        """
        pass
    
    @abstractmethod
    def _entity_to_dict(self, entity: T) -> Dict[str, Any]:
        """
        Convert entity to dictionary for database operations.
        
        Args:
            entity: Entity instance
            
        Returns:
            Dictionary of column values
        """
        pass
    
    # ===================================================================
    # Common CRUD Operations
    # ===================================================================
    
    async def get_by_id(
        self,
        id: UUID,
        organization_id: Optional[UUID] = None
    ) -> Optional[T]:
        """
        Get entity by ID with optional organization isolation.
        
        Args:
            id: Entity UUID
            organization_id: Organization UUID for multi-tenant isolation
            
        Returns:
            Entity instance or None
        """
        if organization_id:
            query = f"""
                SELECT * FROM {self.table_name}
                WHERE id = $1 AND organization_id = $2
            """
            row = await self.pool.fetchrow(query, id, organization_id)
        else:
            query = f"SELECT * FROM {self.table_name} WHERE id = $1"
            row = await self.pool.fetchrow(query, id)
        
        return self._record_to_entity(row) if row else None
    
    async def get_all(
        self,
        organization_id: UUID,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "created_at",
        order_dir: str = "DESC"
    ) -> List[T]:
        """
        Get all entities for an organization with pagination.
        
        Args:
            organization_id: Organization UUID for isolation
            limit: Maximum results (default: 100)
            offset: Skip N results (default: 0)
            order_by: Column to order by (default: created_at)
            order_dir: ASC or DESC (default: DESC)
            
        Returns:
            List of entity instances
        """
        # Sanitize order_by to prevent SQL injection
        allowed_columns = ["created_at", "updated_at", "name", "email", "status"]
        if order_by not in allowed_columns:
            order_by = "created_at"
        if order_dir.upper() not in ["ASC", "DESC"]:
            order_dir = "DESC"
        
        query = f"""
            SELECT * FROM {self.table_name}
            WHERE organization_id = $1
            ORDER BY {order_by} {order_dir}
            LIMIT $2 OFFSET $3
        """
        
        rows = await self.pool.fetch(query, organization_id, limit, offset)
        return [self._record_to_entity(row) for row in rows if row]
    
    async def count(
        self,
        organization_id: UUID,
        filters: Optional[Dict[str, Any]] = None
    ) -> int:
        """
        Count entities for an organization.
        
        Args:
            organization_id: Organization UUID
            filters: Optional filter conditions
            
        Returns:
            Total count
        """
        query = f"SELECT COUNT(*) FROM {self.table_name} WHERE organization_id = $1"
        return await self.pool.fetchval(query, organization_id)
    
    async def exists(
        self,
        id: UUID,
        organization_id: Optional[UUID] = None
    ) -> bool:
        """
        Check if entity exists.
        
        Args:
            id: Entity UUID
            organization_id: Optional organization UUID
            
        Returns:
            True if exists
        """
        if organization_id:
            query = f"""
                SELECT EXISTS(
                    SELECT 1 FROM {self.table_name}
                    WHERE id = $1 AND organization_id = $2
                )
            """
            return await self.pool.fetchval(query, id, organization_id)
        else:
            query = f"SELECT EXISTS(SELECT 1 FROM {self.table_name} WHERE id = $1)"
            return await self.pool.fetchval(query, id)
    
    async def create(self, entity: T) -> T:
        """
        Create a new entity.
        
        Args:
            entity: Entity instance to create
            
        Returns:
            Created entity with ID
        """
        import json
        data = self._entity_to_dict(entity)
        
        # Convert dict/list values to JSON strings for JSONB columns
        processed_data = {}
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                processed_data[key] = json.dumps(value)
            else:
                processed_data[key] = value
        
        # Build INSERT query
        columns = list(processed_data.keys())
        placeholders = [f"${i+1}" for i in range(len(columns))]
        
        query = f"""
            INSERT INTO {self.table_name} ({', '.join(columns)})
            VALUES ({', '.join(placeholders)})
            RETURNING *
        """
        
        row = await self.pool.fetchrow(query, *processed_data.values())
        return self._record_to_entity(row)
    
    async def update(
        self,
        id: UUID,
        updates: Dict[str, Any],
        organization_id: Optional[UUID] = None
    ) -> Optional[T]:
        """
        Update an entity.
        
        Args:
            id: Entity UUID
            updates: Dictionary of fields to update
            organization_id: Optional organization UUID for isolation
            
        Returns:
            Updated entity or None if not found
        """
        import json
        
        if not updates:
            return await self.get_by_id(id, organization_id)
        
        # Add updated_at timestamp
        updates["updated_at"] = datetime.utcnow()
        
        # Convert dict/list values to JSON strings for JSONB columns
        processed_updates = {}
        for key, value in updates.items():
            if isinstance(value, (dict, list)):
                processed_updates[key] = json.dumps(value)
            else:
                processed_updates[key] = value
        
        # Build UPDATE query
        set_clauses = [f"{key} = ${i+1}" for i, key in enumerate(processed_updates.keys())]
        param_index = len(processed_updates) + 1
        
        if organization_id:
            query = f"""
                UPDATE {self.table_name}
                SET {', '.join(set_clauses)}
                WHERE id = ${param_index} AND organization_id = ${param_index + 1}
                RETURNING *
            """
            row = await self.pool.fetchrow(query, *processed_updates.values(), id, organization_id)
        else:
            query = f"""
                UPDATE {self.table_name}
                SET {', '.join(set_clauses)}
                WHERE id = ${param_index}
                RETURNING *
            """
            row = await self.pool.fetchrow(query, *processed_updates.values(), id)
        
        return self._record_to_entity(row) if row else None
    
    async def delete(
        self,
        id: UUID,
        organization_id: Optional[UUID] = None,
        soft: bool = False
    ) -> bool:
        """
        Delete an entity.
        
        Args:
            id: Entity UUID
            organization_id: Optional organization UUID for isolation
            soft: If True, set is_active=False instead of DELETE
            
        Returns:
            True if deleted, False if not found
        """
        if soft:
            result = await self.update(id, {"is_active": False}, organization_id)
            return result is not None
        
        if organization_id:
            query = f"""
                DELETE FROM {self.table_name}
                WHERE id = $1 AND organization_id = $2
            """
            result = await self.pool.execute(query, id, organization_id)
        else:
            query = f"DELETE FROM {self.table_name} WHERE id = $1"
            result = await self.pool.execute(query, id)
        
        # result is like "DELETE 1" or "DELETE 0"
        return result.split()[-1] != "0"
    
    # ===================================================================
    # Batch Operations
    # ===================================================================
    
    async def bulk_create(self, entities: List[T]) -> List[T]:
        """
        Create multiple entities in a transaction.
        
        Args:
            entities: List of entities to create
            
        Returns:
            List of created entities with IDs
        """
        if not entities:
            return []
        
        created = []
        async with self.pool.transaction() as conn:
            for entity in entities:
                data = self._entity_to_dict(entity)
                columns = list(data.keys())
                placeholders = [f"${i+1}" for i in range(len(columns))]
                
                query = f"""
                    INSERT INTO {self.table_name} ({', '.join(columns)})
                    VALUES ({', '.join(placeholders)})
                    RETURNING *
                """
                
                row = await conn.fetchrow(query, *data.values())
                created.append(self._record_to_entity(row))
        
        return created
    
    async def bulk_delete(
        self,
        ids: List[UUID],
        organization_id: UUID
    ) -> int:
        """
        Delete multiple entities.
        
        Args:
            ids: List of entity UUIDs
            organization_id: Organization UUID for isolation
            
        Returns:
            Number of deleted entities
        """
        if not ids:
            return 0
        
        query = f"""
            DELETE FROM {self.table_name}
            WHERE id = ANY($1) AND organization_id = $2
        """
        result = await self.pool.execute(query, ids, organization_id)
        return int(result.split()[-1])
    
    # ===================================================================
    # Search & Filter Helpers
    # ===================================================================
    
    async def search(
        self,
        organization_id: UUID,
        search_term: str,
        search_columns: List[str],
        limit: int = 50
    ) -> List[T]:
        """
        Full-text search across specified columns.
        
        Args:
            organization_id: Organization UUID
            search_term: Search string
            search_columns: Columns to search in
            limit: Maximum results
            
        Returns:
            List of matching entities
        """
        # Build search condition using ILIKE for simplicity
        # For production, consider using pg_trgm or full-text search
        conditions = " OR ".join([f"{col} ILIKE $2" for col in search_columns])
        
        query = f"""
            SELECT * FROM {self.table_name}
            WHERE organization_id = $1 AND ({conditions})
            LIMIT $3
        """
        
        search_pattern = f"%{search_term}%"
        rows = await self.pool.fetch(query, organization_id, search_pattern, limit)
        return [self._record_to_entity(row) for row in rows if row]
    
    # ===================================================================
    # Pagination Helper
    # ===================================================================
    
    async def paginate(
        self,
        organization_id: UUID,
        page: int = 1,
        per_page: int = 20,
        order_by: str = "created_at",
        order_dir: str = "DESC",
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Get paginated results with metadata.
        
        Args:
            organization_id: Organization UUID
            page: Page number (1-indexed)
            per_page: Items per page
            order_by: Column to order by
            order_dir: ASC or DESC
            filters: Optional filter conditions
            
        Returns:
            Dict with items, total, page, per_page, pages
        """
        # Ensure valid page
        page = max(1, page)
        per_page = min(100, max(1, per_page))
        offset = (page - 1) * per_page
        
        # Get total count
        total = await self.count(organization_id, filters)
        
        # Get items
        items = await self.get_all(
            organization_id=organization_id,
            limit=per_page,
            offset=offset,
            order_by=order_by,
            order_dir=order_dir
        )
        
        # Calculate pages
        pages = (total + per_page - 1) // per_page if total > 0 else 1
        
        return {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
            "has_next": page < pages,
            "has_prev": page > 1,
        }
