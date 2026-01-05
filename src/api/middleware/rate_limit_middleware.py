# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Rate Limit Middleware (SEC-04)
# FastAPI middleware for API rate limiting
# ═══════════════════════════════════════════════════════════════

"""
SEC-04: Rate Limiting Middleware

This middleware provides:
- Per-endpoint rate limiting
- Per-IP rate limiting
- Configurable limits per route
- Redis-backed distributed limiting (optional)
- Retry-After headers in 429 responses

Integration with FastAPI:
```python
from src.api.middleware import create_rate_limit_middleware

app = FastAPI()
app.add_middleware(create_rate_limit_middleware(redis_client=redis))
```
"""

from typing import Optional, Dict, Any, Callable, List, Tuple
from datetime import datetime, timedelta
import asyncio
import time
import logging
import re

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Rate Limit Configuration
# ═══════════════════════════════════════════════════════════════

# Default rate limits per endpoint pattern
DEFAULT_RATE_LIMITS: Dict[str, Tuple[int, int]] = {
    # Mission endpoints
    r"^/api/v1/missions$": (10, 60),  # 10 per minute (POST create)
    r"^/api/v1/missions/[^/]+/start$": (5, 60),  # 5 per minute
    r"^/api/v1/missions/[^/]+/stop$": (5, 60),  # 5 per minute
    r"^/api/v1/missions/[^/]+/pause$": (5, 60),  # 5 per minute
    r"^/api/v1/missions/[^/]+/resume$": (5, 60),  # 5 per minute
    
    # HITL endpoints
    r"^/api/v1/missions/[^/]+/approve/": (20, 60),  # 20 per minute
    r"^/api/v1/missions/[^/]+/reject/": (20, 60),  # 20 per minute
    r"^/api/v1/missions/[^/]+/chat$": (30, 60),  # 30 per minute
    
    # Exploitation endpoints
    r"^/api/v1/exploitation/execute": (5, 60),  # 5 per minute
    r"^/api/v1/exploitation/c2/": (30, 60),  # 30 per minute
    
    # Knowledge endpoints (read-heavy)
    r"^/api/v1/knowledge/": (100, 60),  # 100 per minute
    r"^/api/v1/knowledge/search": (50, 60),  # 50 per minute
    
    # Infrastructure endpoints
    r"^/api/v1/infrastructure/": (20, 60),  # 20 per minute
    
    # Security endpoints
    r"^/api/v1/security/validate/": (100, 60),  # 100 per minute
    r"^/api/v1/security/rate-limits/": (60, 60),  # 60 per minute
    
    # Stats endpoints
    r"^/api/v1/stats/": (60, 60),  # 60 per minute
    
    # Health check
    r"^/health$": (120, 60),  # 120 per minute
    
    # WebSocket
    r"^/ws": (10, 60),  # 10 connections per minute
    
    # Default
    r".*": (100, 60),  # 100 per minute for all others
}

# Whitelist paths (no rate limiting)
WHITELIST_PATHS = [
    "/docs",
    "/redoc",
    "/openapi.json",
    "/",
]


class TokenBucket:
    """Simple token bucket implementation."""
    
    def __init__(self, rate: int, period: int):
        self.rate = rate
        self.period = period
        self.tokens = float(rate)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> Tuple[bool, float]:
        """
        Try to consume tokens.
        
        Returns:
            Tuple of (allowed, retry_after_seconds)
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            
            # Replenish tokens
            self.tokens = min(
                self.rate,
                self.tokens + (elapsed * self.rate / self.period)
            )
            self.last_update = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0
            
            # Calculate retry after
            needed = tokens - self.tokens
            retry_after = needed * self.period / self.rate
            return False, retry_after


class RateLimitStore:
    """
    In-memory rate limit store.
    
    Can be extended to use Redis for distributed deployments.
    """
    
    def __init__(self, redis_client: Optional[Any] = None):
        self.redis = redis_client
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()
    
    async def check(
        self,
        key: str,
        rate: int,
        period: int
    ) -> Tuple[bool, float, int]:
        """
        Check rate limit.
        
        Returns:
            Tuple of (allowed, retry_after, remaining)
        """
        if self.redis:
            return await self._check_redis(key, rate, period)
        return await self._check_memory(key, rate, period)
    
    async def _check_memory(
        self,
        key: str,
        rate: int,
        period: int
    ) -> Tuple[bool, float, int]:
        """Check using in-memory store."""
        async with self._lock:
            if key not in self._buckets:
                self._buckets[key] = TokenBucket(rate, period)
            
            bucket = self._buckets[key]
            allowed, retry_after = await bucket.consume()
            remaining = int(bucket.tokens)
            
            return allowed, retry_after, remaining
    
    async def _check_redis(
        self,
        key: str,
        rate: int,
        period: int
    ) -> Tuple[bool, float, int]:
        """Check using Redis (sliding window)."""
        now = time.time()
        window_start = now - period
        
        try:
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
                remaining = rate - current_count - 1
                return True, 0.0, max(0, remaining)
            
            # Calculate retry after
            oldest = await self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                retry_after = oldest[0][1] + period - now + 1
            else:
                retry_after = period
            
            return False, retry_after, 0
            
        except Exception as e:
            logger.warning(f"Redis rate limit check failed: {e}, falling back to memory")
            return await self._check_memory(key, rate, period)
    
    async def cleanup(self) -> int:
        """
        Cleanup expired buckets.
        
        Returns:
            Number of buckets cleaned up
        """
        async with self._lock:
            now = time.monotonic()
            expired = []
            
            for key, bucket in self._buckets.items():
                # Remove buckets not used for 2x period
                if now - bucket.last_update > bucket.period * 2:
                    expired.append(key)
            
            for key in expired:
                del self._buckets[key]
            
            return len(expired)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware for FastAPI.
    
    SEC-04 Implementation:
    - Per-endpoint rate limits
    - Per-IP tracking
    - Configurable limits
    - 429 responses with Retry-After header
    """
    
    def __init__(
        self,
        app: ASGIApp,
        rate_limits: Optional[Dict[str, Tuple[int, int]]] = None,
        redis_client: Optional[Any] = None,
        key_func: Optional[Callable[[Request], str]] = None,
        whitelist: Optional[List[str]] = None,
        enabled: bool = True,
    ):
        """
        Initialize rate limit middleware.
        
        Args:
            app: ASGI application
            rate_limits: Dict mapping path patterns to (rate, period) tuples
            redis_client: Optional Redis client for distributed limiting
            key_func: Function to extract rate limit key from request
            whitelist: List of paths to exclude from rate limiting
            enabled: Whether rate limiting is enabled
        """
        super().__init__(app)
        self.rate_limits = rate_limits or DEFAULT_RATE_LIMITS
        self.store = RateLimitStore(redis_client)
        self.key_func = key_func or self._default_key_func
        self.whitelist = whitelist or WHITELIST_PATHS
        self.enabled = enabled
        
        # Compile patterns
        self._patterns = [
            (re.compile(pattern), limits)
            for pattern, limits in self.rate_limits.items()
        ]
        
        # Statistics
        self.stats = {
            "total_requests": 0,
            "rate_limited": 0,
            "by_endpoint": {},
        }
    
    def _default_key_func(self, request: Request) -> str:
        """Default key function using client IP."""
        # Try to get real IP from headers (behind proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fall back to client host
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _get_rate_limit(self, path: str, method: str) -> Tuple[int, int]:
        """
        Get rate limit for a path.
        
        Returns:
            Tuple of (rate, period)
        """
        # Check whitelist
        for whitelisted in self.whitelist:
            if path.startswith(whitelisted):
                return 0, 0  # No limit
        
        # Find matching pattern
        for pattern, limits in self._patterns:
            if pattern.match(path):
                return limits
        
        # Default
        return 100, 60
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process request with rate limiting."""
        if not self.enabled:
            return await call_next(request)
        
        path = request.url.path
        method = request.method
        
        # Get rate limit for this path
        rate, period = self._get_rate_limit(path, method)
        
        # No limit for whitelisted paths
        if rate == 0:
            return await call_next(request)
        
        # Get client key
        client_key = self.key_func(request)
        
        # Create unique key for this client + endpoint
        limit_key = f"ratelimit:{client_key}:{method}:{path}"
        
        # Check rate limit
        allowed, retry_after, remaining = await self.store.check(
            limit_key, rate, period
        )
        
        # Update statistics
        self.stats["total_requests"] += 1
        endpoint_key = f"{method}:{path}"
        if endpoint_key not in self.stats["by_endpoint"]:
            self.stats["by_endpoint"][endpoint_key] = {"total": 0, "limited": 0}
        self.stats["by_endpoint"][endpoint_key]["total"] += 1
        
        if not allowed:
            self.stats["rate_limited"] += 1
            self.stats["by_endpoint"][endpoint_key]["limited"] += 1
            
            logger.warning(
                f"Rate limit exceeded: {client_key} on {method} {path} "
                f"(retry after {retry_after:.1f}s)"
            )
            
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "detail": f"Too many requests. Please retry after {int(retry_after)} seconds.",
                    "retry_after": int(retry_after),
                    "limit": rate,
                    "period": period,
                },
                headers={
                    "Retry-After": str(int(retry_after)),
                    "X-RateLimit-Limit": str(rate),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time() + retry_after)),
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(rate)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time() + period))
        
        return response
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        return {
            **self.stats,
            "active_buckets": len(self.store._buckets),
            "rate_limit_percentage": (
                self.stats["rate_limited"] / self.stats["total_requests"] * 100
                if self.stats["total_requests"] > 0 else 0
            ),
        }


def create_rate_limit_middleware(
    rate_limits: Optional[Dict[str, Tuple[int, int]]] = None,
    redis_client: Optional[Any] = None,
    enabled: bool = True,
) -> type:
    """
    Create a rate limit middleware class with configuration.
    
    Usage:
    ```python
    app.add_middleware(
        create_rate_limit_middleware(
            redis_client=redis,
            enabled=True
        )
    )
    ```
    """
    class ConfiguredRateLimitMiddleware(RateLimitMiddleware):
        def __init__(self, app: ASGIApp):
            super().__init__(
                app,
                rate_limits=rate_limits,
                redis_client=redis_client,
                enabled=enabled,
            )
    
    return ConfiguredRateLimitMiddleware


# ═══════════════════════════════════════════════════════════════
# Decorator for route-level rate limiting
# ═══════════════════════════════════════════════════════════════

def rate_limit_endpoint(
    rate: int,
    period: int = 60,
    key_func: Optional[Callable[[Request], str]] = None,
):
    """
    Decorator for per-endpoint rate limiting.
    
    Usage:
    ```python
    @router.post("/missions")
    @rate_limit_endpoint(rate=10, period=60)
    async def create_mission(request: Request):
        ...
    ```
    """
    _store = RateLimitStore()
    
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            # Find request in args/kwargs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if request is None:
                request = kwargs.get("request")
            
            if request is None:
                # No request found, just call the function
                return await func(*args, **kwargs)
            
            # Get client key
            if key_func:
                client_key = key_func(request)
            else:
                client_key = request.client.host if request.client else "unknown"
            
            # Create unique key
            limit_key = f"ratelimit:endpoint:{func.__name__}:{client_key}"
            
            # Check rate limit
            allowed, retry_after, _ = await _store.check(limit_key, rate, period)
            
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail={
                        "error": "Rate limit exceeded",
                        "retry_after": int(retry_after),
                        "limit": rate,
                        "period": period,
                    },
                    headers={"Retry-After": str(int(retry_after))},
                )
            
            return await func(*args, **kwargs)
        
        # Preserve function metadata
        wrapper.__name__ = func.__name__
        wrapper.__doc__ = func.__doc__
        
        return wrapper
    
    return decorator
