# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Rate Limiter
# API rate limiting with Redis backend support
# ═══════════════════════════════════════════════════════════════

"""
Enterprise-grade rate limiting for RAGLOX API.

Features:
- Token bucket algorithm
- Redis backend for distributed deployments
- In-memory fallback for single-node
- Per-endpoint and per-user limits
- Configurable time windows
"""

from typing import Optional, Dict, Any, Callable, Union
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import asyncio
import time
import logging

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Rate limit exceeded exception."""
    
    def __init__(self, message: str, retry_after: int):
        self.message = message
        self.retry_after = retry_after
        super().__init__(message)


class TokenBucket:
    """Token bucket rate limiter."""
    
    def __init__(
        self,
        rate: int,
        period: int = 60,
        burst: Optional[int] = None
    ):
        """
        Initialize token bucket.
        
        Args:
            rate: Number of requests allowed per period
            period: Time period in seconds
            burst: Maximum burst size (defaults to rate)
        """
        self.rate = rate
        self.period = period
        self.burst = burst or rate
        self.tokens = float(self.burst)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if rate limited
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(
                self.burst,
                self.tokens + (elapsed * self.rate / self.period)
            )
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def time_until_available(self, tokens: int = 1) -> float:
        """Get seconds until tokens will be available."""
        if self.tokens >= tokens:
            return 0
        
        needed = tokens - self.tokens
        return needed * self.period / self.rate


class RateLimiter:
    """
    Rate limiter with support for multiple strategies.
    
    Example:
        limiter = RateLimiter(default_rate=100, default_period=60)
        
        @limiter.limit("10/minute")
        async def create_mission(request):
            ...
    """
    
    def __init__(
        self,
        default_rate: int = 100,
        default_period: int = 60,
        redis_client: Optional[Any] = None,
        key_prefix: str = "raglox:ratelimit:"
    ):
        """
        Initialize rate limiter.
        
        Args:
            default_rate: Default requests per period
            default_period: Default period in seconds
            redis_client: Optional Redis client for distributed limiting
            key_prefix: Prefix for Redis keys
        """
        self.default_rate = default_rate
        self.default_period = default_period
        self.redis = redis_client
        self.key_prefix = key_prefix
        
        # In-memory buckets for fallback
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()
    
    def parse_limit(self, limit_str: str) -> tuple:
        """
        Parse limit string like "10/minute" or "100/hour".
        
        Args:
            limit_str: Limit specification
            
        Returns:
            Tuple of (rate, period_seconds)
        """
        periods = {
            "second": 1,
            "minute": 60,
            "hour": 3600,
            "day": 86400,
        }
        
        parts = limit_str.lower().split("/")
        if len(parts) != 2:
            raise ValueError(f"Invalid limit format: {limit_str}")
        
        rate = int(parts[0])
        period_name = parts[1].rstrip("s")  # Remove trailing 's'
        
        if period_name not in periods:
            raise ValueError(f"Unknown period: {period_name}")
        
        return rate, periods[period_name]
    
    async def _get_bucket(self, key: str, rate: int, period: int) -> TokenBucket:
        """Get or create token bucket for key."""
        async with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(rate, period)
            return self._buckets[key]
    
    async def is_allowed(
        self,
        key: str,
        rate: Optional[int] = None,
        period: Optional[int] = None
    ) -> tuple:
        """
        Check if request is allowed.
        
        Args:
            key: Unique identifier (e.g., IP address, user ID)
            rate: Requests per period (uses default if None)
            period: Period in seconds (uses default if None)
            
        Returns:
            Tuple of (allowed: bool, retry_after: int)
        """
        rate = rate or self.default_rate
        period = period or self.default_period
        
        full_key = f"{self.key_prefix}{key}"
        
        # Try Redis first if available
        if self.redis:
            try:
                return await self._check_redis(full_key, rate, period)
            except Exception as e:
                logger.warning(f"Redis rate limit check failed, using in-memory: {e}")
        
        # Fall back to in-memory
        bucket = await self._get_bucket(full_key, rate, period)
        if await bucket.consume():
            return True, 0
        
        retry_after = int(bucket.time_until_available())
        return False, retry_after
    
    async def _check_redis(self, key: str, rate: int, period: int) -> tuple:
        """Check rate limit using Redis."""
        now = time.time()
        window_start = now - period
        
        # Use Redis sorted set for sliding window
        pipe = self.redis.pipeline()
        
        # Remove old entries
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count current window
        pipe.zcard(key)
        
        # Add new entry
        pipe.zadd(key, {str(now): now})
        
        # Set expiry
        pipe.expire(key, period + 1)
        
        results = await pipe.execute()
        current_count = results[1]
        
        if current_count < rate:
            return True, 0
        
        # Calculate retry after
        oldest = await self.redis.zrange(key, 0, 0, withscores=True)
        if oldest:
            retry_after = int(oldest[0][1] + period - now) + 1
        else:
            retry_after = period
        
        return False, retry_after
    
    def limit(
        self,
        limit_spec: str,
        key_func: Optional[Callable] = None,
        error_message: str = "Rate limit exceeded"
    ):
        """
        Decorator to apply rate limiting.
        
        Args:
            limit_spec: Limit specification (e.g., "10/minute")
            key_func: Function to extract key from request
            error_message: Custom error message
            
        Example:
            @limiter.limit("10/minute")
            async def create_mission(request):
                ...
        """
        rate, period = self.parse_limit(limit_spec)
        
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract key
                if key_func:
                    key = key_func(*args, **kwargs)
                else:
                    # Try to get from request object
                    request = kwargs.get("request") or (args[0] if args else None)
                    if hasattr(request, "client") and request.client:
                        key = request.client.host
                    else:
                        key = "default"
                
                # Check rate limit
                allowed, retry_after = await self.is_allowed(key, rate, period)
                
                if not allowed:
                    logger.warning(
                        f"Rate limit exceeded for {key}: {rate}/{period}s"
                    )
                    raise RateLimitExceeded(
                        f"{error_message}. Try again in {retry_after} seconds.",
                        retry_after
                    )
                
                return await func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    async def cleanup(self) -> None:
        """Clean up expired buckets."""
        async with self._lock:
            now = time.monotonic()
            expired = []
            
            for key, bucket in self._buckets.items():
                # Remove buckets not used for 2x period
                if now - bucket.last_update > bucket.period * 2:
                    expired.append(key)
            
            for key in expired:
                del self._buckets[key]
            
            if expired:
                logger.debug(f"Cleaned up {len(expired)} expired rate limit buckets")


# Pre-configured rate limits for common endpoints
RATE_LIMITS = {
    "missions_create": "10/minute",
    "missions_start": "5/minute",
    "exploit_execute": "5/minute",
    "chat_send": "30/minute",
    "status_check": "60/minute",
    "websocket_connect": "10/minute",
    "default": "100/minute",
}


def rate_limit(
    limit_spec: Optional[str] = None,
    endpoint_name: Optional[str] = None
):
    """
    Convenience decorator using global rate limiter.
    
    Args:
        limit_spec: Limit specification (e.g., "10/minute")
        endpoint_name: Name to look up in RATE_LIMITS
        
    Example:
        @rate_limit("10/minute")
        async def create_mission(request):
            ...
        
        @rate_limit(endpoint_name="missions_create")
        async def create_mission(request):
            ...
    """
    if limit_spec is None:
        if endpoint_name and endpoint_name in RATE_LIMITS:
            limit_spec = RATE_LIMITS[endpoint_name]
        else:
            limit_spec = RATE_LIMITS["default"]
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get or create global limiter
            limiter = getattr(wrapper, "_limiter", None)
            if limiter is None:
                wrapper._limiter = RateLimiter()
                limiter = wrapper._limiter
            
            # Apply rate limit
            rate, period = limiter.parse_limit(limit_spec)
            
            # Extract key from request
            request = kwargs.get("request") or (args[0] if args else None)
            if hasattr(request, "client") and request.client:
                key = f"{request.client.host}:{func.__name__}"
            else:
                key = f"default:{func.__name__}"
            
            allowed, retry_after = await limiter.is_allowed(key, rate, period)
            
            if not allowed:
                raise RateLimitExceeded(
                    f"Rate limit exceeded for {func.__name__}",
                    retry_after
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator
