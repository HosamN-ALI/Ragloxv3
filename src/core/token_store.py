# ===================================================================
# RAGLOX v3.0 - Token Store
# Redis-backed JWT token management for authentication
# ===================================================================
"""
Token Store for managing JWT tokens in Redis.

Features:
- Token storage and validation
- Token revocation (logout)
- User session management
- Token expiration handling
- Multi-device support

Architecture:
- Tokens stored in Redis with TTL matching JWT expiration
- Each token mapped to user_id for validation
- User can have multiple active tokens (multi-device)
- Revocation is instant (no token refresh needed)
"""

from typing import Optional, Set
from datetime import timedelta
import logging

logger = logging.getLogger("raglox.token_store")

# Redis key prefixes
TOKEN_PREFIX = "token:"           # token:{token_hash} -> user_id
USER_TOKENS_PREFIX = "user_tokens:"  # user_tokens:{user_id} -> set of token_hashes


class TokenStore:
    """
    Redis-backed token store for JWT management.
    
    This replaces the in-memory token storage in UserStore.
    
    Example:
        store = TokenStore(redis_client)
        
        # Store token after login
        await store.store_token(token, user_id, expires_seconds=86400)
        
        # Validate token on each request
        user_id = await store.validate_token(token)
        
        # Revoke on logout
        await store.revoke_token(token)
    """
    
    def __init__(self, redis_client):
        """
        Initialize token store with Redis client.
        
        Args:
            redis_client: aioredis/redis-py client instance
        """
        self._redis = redis_client
        self._default_ttl = 86400  # 24 hours
    
    @property
    def redis(self):
        """Get Redis client."""
        return self._redis
    
    def _token_key(self, token: str) -> str:
        """Generate Redis key for token."""
        # Use hash of token for key (token itself may be too long)
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:32]
        return f"{TOKEN_PREFIX}{token_hash}"
    
    def _user_tokens_key(self, user_id: str) -> str:
        """Generate Redis key for user's token set."""
        return f"{USER_TOKENS_PREFIX}{user_id}"
    
    async def store_token(
        self,
        token: str,
        user_id: str,
        expires_seconds: int = None
    ) -> bool:
        """
        Store token in Redis.
        
        Args:
            token: JWT token string
            user_id: User ID (UUID string)
            expires_seconds: Token TTL in seconds
            
        Returns:
            True if stored successfully
        """
        if not self._redis:
            logger.warning("Redis not available - token not stored")
            return False
        
        try:
            ttl = expires_seconds or self._default_ttl
            token_key = self._token_key(token)
            user_tokens_key = self._user_tokens_key(user_id)
            
            # Store token -> user_id mapping with TTL
            await self._redis.setex(token_key, ttl, user_id)
            
            # Add to user's token set
            await self._redis.sadd(user_tokens_key, token_key)
            
            # Set TTL on user's token set (cleanup)
            await self._redis.expire(user_tokens_key, ttl + 3600)  # Extra hour for cleanup
            
            logger.debug(f"Token stored for user {user_id[:8]}...")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            return False
    
    async def validate_token(self, token: str) -> Optional[str]:
        """
        Validate token and return user_id.
        
        Args:
            token: JWT token string
            
        Returns:
            user_id if token is valid, None otherwise
        """
        if not self._redis:
            logger.warning("Redis not available - token validation failed")
            return None
        
        try:
            token_key = self._token_key(token)
            user_id = await self._redis.get(token_key)
            
            if user_id:
                # Decode bytes to string if needed
                if isinstance(user_id, bytes):
                    user_id = user_id.decode('utf-8')
                return user_id
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to validate token: {e}")
            return None
    
    async def revoke_token(self, token: str) -> bool:
        """
        Revoke a specific token (logout from one device).
        
        Args:
            token: JWT token string
            
        Returns:
            True if revoked successfully
        """
        if not self._redis:
            logger.warning("Redis not available - token not revoked")
            return False
        
        try:
            token_key = self._token_key(token)
            
            # Get user_id before deleting
            user_id = await self._redis.get(token_key)
            
            # Delete token
            await self._redis.delete(token_key)
            
            # Remove from user's token set
            if user_id:
                if isinstance(user_id, bytes):
                    user_id = user_id.decode('utf-8')
                user_tokens_key = self._user_tokens_key(user_id)
                await self._redis.srem(user_tokens_key, token_key)
            
            logger.debug(f"Token revoked")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False
    
    async def revoke_all_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user (logout from all devices).
        
        Args:
            user_id: User ID
            
        Returns:
            Number of tokens revoked
        """
        if not self._redis:
            logger.warning("Redis not available - tokens not revoked")
            return 0
        
        try:
            user_tokens_key = self._user_tokens_key(user_id)
            
            # Get all token keys for user
            token_keys = await self._redis.smembers(user_tokens_key)
            
            if not token_keys:
                return 0
            
            # Delete all tokens
            count = 0
            for token_key in token_keys:
                if isinstance(token_key, bytes):
                    token_key = token_key.decode('utf-8')
                await self._redis.delete(token_key)
                count += 1
            
            # Delete user's token set
            await self._redis.delete(user_tokens_key)
            
            logger.info(f"Revoked {count} tokens for user {user_id[:8]}...")
            return count
            
        except Exception as e:
            logger.error(f"Failed to revoke all tokens: {e}")
            return 0
    
    async def get_user_token_count(self, user_id: str) -> int:
        """
        Get number of active tokens for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of active tokens
        """
        if not self._redis:
            return 0
        
        try:
            user_tokens_key = self._user_tokens_key(user_id)
            return await self._redis.scard(user_tokens_key) or 0
        except Exception as e:
            logger.error(f"Failed to get token count: {e}")
            return 0
    
    async def cleanup_expired_tokens(self, user_id: str) -> int:
        """
        Remove references to expired tokens from user's set.
        
        This is called periodically or on login to clean up.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of expired references removed
        """
        if not self._redis:
            return 0
        
        try:
            user_tokens_key = self._user_tokens_key(user_id)
            token_keys = await self._redis.smembers(user_tokens_key)
            
            if not token_keys:
                return 0
            
            removed = 0
            for token_key in token_keys:
                if isinstance(token_key, bytes):
                    token_key = token_key.decode('utf-8')
                
                # Check if token still exists
                exists = await self._redis.exists(token_key)
                if not exists:
                    await self._redis.srem(user_tokens_key, token_key)
                    removed += 1
            
            return removed
            
        except Exception as e:
            logger.error(f"Failed to cleanup tokens: {e}")
            return 0


# ===================================================================
# Sync wrapper for non-async contexts
# ===================================================================

class SyncTokenStore:
    """
    Synchronous wrapper for TokenStore.
    
    For use in non-async contexts (e.g., JWT token creation).
    Internally runs async methods in event loop.
    """
    
    def __init__(self, redis_client):
        """Initialize with sync redis client."""
        self._redis = redis_client
        self._default_ttl = 86400
    
    def _token_key(self, token: str) -> str:
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:32]
        return f"{TOKEN_PREFIX}{token_hash}"
    
    def _user_tokens_key(self, user_id: str) -> str:
        return f"{USER_TOKENS_PREFIX}{user_id}"
    
    def store_token(self, token: str, user_id: str, expires_seconds: int = None) -> bool:
        """Store token synchronously."""
        if not self._redis:
            return False
        
        try:
            ttl = expires_seconds or self._default_ttl
            token_key = self._token_key(token)
            user_tokens_key = self._user_tokens_key(user_id)
            
            self._redis.setex(token_key, ttl, user_id)
            self._redis.sadd(user_tokens_key, token_key)
            self._redis.expire(user_tokens_key, ttl + 3600)
            
            return True
        except Exception as e:
            logger.error(f"Failed to store token (sync): {e}")
            return False
    
    def validate_token(self, token: str) -> Optional[str]:
        """Validate token synchronously."""
        if not self._redis:
            return None
        
        try:
            token_key = self._token_key(token)
            user_id = self._redis.get(token_key)
            
            if user_id:
                if isinstance(user_id, bytes):
                    user_id = user_id.decode('utf-8')
                return user_id
            return None
        except Exception as e:
            logger.error(f"Failed to validate token (sync): {e}")
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke token synchronously."""
        if not self._redis:
            return False
        
        try:
            token_key = self._token_key(token)
            user_id = self._redis.get(token_key)
            
            self._redis.delete(token_key)
            
            if user_id:
                if isinstance(user_id, bytes):
                    user_id = user_id.decode('utf-8')
                user_tokens_key = self._user_tokens_key(user_id)
                self._redis.srem(user_tokens_key, token_key)
            
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token (sync): {e}")
            return False
    
    def revoke_all_user_tokens(self, user_id: str) -> int:
        """Revoke all user tokens synchronously."""
        if not self._redis:
            return 0
        
        try:
            user_tokens_key = self._user_tokens_key(user_id)
            token_keys = self._redis.smembers(user_tokens_key)
            
            if not token_keys:
                return 0
            
            count = 0
            for token_key in token_keys:
                if isinstance(token_key, bytes):
                    token_key = token_key.decode('utf-8')
                self._redis.delete(token_key)
                count += 1
            
            self._redis.delete(user_tokens_key)
            return count
        except Exception as e:
            logger.error(f"Failed to revoke all tokens (sync): {e}")
            return 0


# ===================================================================
# Global token store instance
# ===================================================================

_token_store: Optional[TokenStore] = None
_sync_token_store: Optional[SyncTokenStore] = None


def init_token_store(redis_client) -> TokenStore:
    """Initialize global token store."""
    global _token_store
    _token_store = TokenStore(redis_client)
    logger.info("Token store initialized")
    return _token_store


def init_sync_token_store(redis_client) -> SyncTokenStore:
    """Initialize global sync token store."""
    global _sync_token_store
    _sync_token_store = SyncTokenStore(redis_client)
    logger.info("Sync token store initialized")
    return _sync_token_store


def get_token_store() -> Optional[TokenStore]:
    """Get global token store."""
    return _token_store


def get_sync_token_store() -> Optional[SyncTokenStore]:
    """Get global sync token store."""
    return _sync_token_store
