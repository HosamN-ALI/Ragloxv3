# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Circuit Breaker
# Resilience pattern for external service calls
# ═══════════════════════════════════════════════════════════════

"""
Circuit Breaker pattern implementation for RAGLOX.

Features:
- Automatic failure detection
- Service protection during outages
- Gradual recovery (half-open state)
- Configurable thresholds and timeouts
- State change notifications
"""

from typing import Optional, Callable, Any, Dict, Type, Union
from functools import wraps
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import time
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitStats:
    """Circuit breaker statistics."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    state_changes: int = 0
    
    def reset(self) -> None:
        """Reset statistics."""
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.rejected_calls = 0
        self.consecutive_failures = 0
        self.consecutive_successes = 0


class CircuitBreakerOpenError(Exception):
    """Raised when circuit is open and rejecting requests."""
    
    def __init__(self, service_name: str, retry_after: float):
        self.service_name = service_name
        self.retry_after = retry_after
        super().__init__(
            f"Circuit breaker open for '{service_name}'. "
            f"Retry after {retry_after:.1f}s"
        )


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5        # Failures before opening
    success_threshold: int = 3        # Successes before closing from half-open
    timeout: float = 30.0             # Seconds before trying half-open
    expected_exceptions: tuple = field(default_factory=lambda: (Exception,))
    excluded_exceptions: tuple = field(default_factory=tuple)
    
    def __post_init__(self):
        """Validate configuration."""
        if self.failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if self.success_threshold < 1:
            raise ValueError("success_threshold must be at least 1")
        if self.timeout < 0:
            raise ValueError("timeout must be non-negative")


class CircuitBreaker:
    """
    Circuit Breaker for protecting external service calls.
    
    Example:
        breaker = CircuitBreaker("metasploit", failure_threshold=3)
        
        @breaker
        async def call_metasploit():
            ...
        
        # Or manual usage
        async with breaker:
            result = await call_service()
    """
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout: float = 30.0,
        expected_exceptions: tuple = (Exception,),
        excluded_exceptions: tuple = (),
        on_state_change: Optional[Callable[[str, CircuitState, CircuitState], None]] = None
    ):
        """
        Initialize circuit breaker.
        
        Args:
            name: Service name for logging
            failure_threshold: Failures before opening circuit
            success_threshold: Successes before closing from half-open
            timeout: Seconds before trying half-open
            expected_exceptions: Exceptions that count as failures
            excluded_exceptions: Exceptions that don't count as failures
            on_state_change: Callback for state changes
        """
        self.name = name
        self.config = CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout,
            expected_exceptions=expected_exceptions,
            excluded_exceptions=excluded_exceptions
        )
        
        self._state = CircuitState.CLOSED
        self._stats = CircuitStats()
        self._opened_at: Optional[float] = None
        self._lock = asyncio.Lock()
        self._on_state_change = on_state_change
    
    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED
    
    @property
    def is_open(self) -> bool:
        """Check if circuit is open (rejecting requests)."""
        return self._state == CircuitState.OPEN
    
    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing)."""
        return self._state == CircuitState.HALF_OPEN
    
    @property
    def stats(self) -> CircuitStats:
        """Get circuit statistics."""
        return self._stats
    
    def _should_try_reset(self) -> bool:
        """Check if enough time has passed to try half-open."""
        if self._opened_at is None:
            return True
        elapsed = time.monotonic() - self._opened_at
        return elapsed >= self.config.timeout
    
    def _change_state(self, new_state: CircuitState) -> None:
        """Change circuit state with logging and callback."""
        if new_state == self._state:
            return
        
        old_state = self._state
        self._state = new_state
        self._stats.state_changes += 1
        
        if new_state == CircuitState.OPEN:
            self._opened_at = time.monotonic()
        elif new_state == CircuitState.CLOSED:
            self._stats.consecutive_failures = 0
        
        logger.warning(
            f"Circuit breaker '{self.name}' state changed: "
            f"{old_state.value} -> {new_state.value}"
        )
        
        if self._on_state_change:
            try:
                self._on_state_change(self.name, old_state, new_state)
            except Exception as e:
                logger.error(f"State change callback failed: {e}")
    
    def _record_success(self) -> None:
        """Record successful call."""
        self._stats.total_calls += 1
        self._stats.successful_calls += 1
        self._stats.consecutive_successes += 1
        self._stats.consecutive_failures = 0
        self._stats.last_success_time = datetime.utcnow()
        
        if self._state == CircuitState.HALF_OPEN:
            if self._stats.consecutive_successes >= self.config.success_threshold:
                self._change_state(CircuitState.CLOSED)
    
    def _record_failure(self) -> None:
        """Record failed call."""
        self._stats.total_calls += 1
        self._stats.failed_calls += 1
        self._stats.consecutive_failures += 1
        self._stats.consecutive_successes = 0
        self._stats.last_failure_time = datetime.utcnow()
        
        if self._state == CircuitState.HALF_OPEN:
            self._change_state(CircuitState.OPEN)
        elif self._state == CircuitState.CLOSED:
            if self._stats.consecutive_failures >= self.config.failure_threshold:
                self._change_state(CircuitState.OPEN)
    
    def _is_expected_exception(self, exc: Exception) -> bool:
        """Check if exception should count as failure."""
        if isinstance(exc, self.config.excluded_exceptions):
            return False
        return isinstance(exc, self.config.expected_exceptions)
    
    async def _can_execute(self) -> bool:
        """Check if request can be executed."""
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return True
            
            if self._state == CircuitState.OPEN:
                if self._should_try_reset():
                    self._change_state(CircuitState.HALF_OPEN)
                    return True
                return False
            
            # Half-open: allow limited requests
            return True
    
    def _get_retry_after(self) -> float:
        """Get seconds until circuit might close."""
        if self._opened_at is None:
            return 0
        elapsed = time.monotonic() - self._opened_at
        return max(0, self.config.timeout - elapsed)
    
    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection.
        
        Args:
            func: Async function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerOpenError: If circuit is open
        """
        if not await self._can_execute():
            self._stats.rejected_calls += 1
            retry_after = self._get_retry_after()
            logger.warning(
                f"Circuit breaker '{self.name}' is OPEN, "
                f"rejecting request (retry in {retry_after:.1f}s)"
            )
            raise CircuitBreakerOpenError(self.name, retry_after)
        
        try:
            result = await func(*args, **kwargs)
            self._record_success()
            return result
            
        except Exception as exc:
            if self._is_expected_exception(exc):
                self._record_failure()
                logger.warning(
                    f"Circuit breaker '{self.name}' recorded failure: "
                    f"{type(exc).__name__}: {exc}"
                )
            raise
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator to protect async function with circuit breaker."""
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await self.execute(func, *args, **kwargs)
        
        # Attach circuit breaker info to wrapper
        wrapper.circuit_breaker = self
        return wrapper
    
    async def __aenter__(self) -> "CircuitBreaker":
        """Async context manager entry."""
        if not await self._can_execute():
            retry_after = self._get_retry_after()
            raise CircuitBreakerOpenError(self.name, retry_after)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Async context manager exit."""
        if exc_type is None:
            self._record_success()
        elif exc_val and self._is_expected_exception(exc_val):
            self._record_failure()
        return False  # Don't suppress exceptions
    
    def reset(self) -> None:
        """Manually reset circuit to closed state."""
        self._change_state(CircuitState.CLOSED)
        self._stats.reset()
        self._opened_at = None
        logger.info(f"Circuit breaker '{self.name}' manually reset")
    
    def force_open(self) -> None:
        """Manually open circuit."""
        self._change_state(CircuitState.OPEN)
        logger.info(f"Circuit breaker '{self.name}' manually opened")
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status for monitoring."""
        return {
            "name": self.name,
            "state": self._state.value,
            "stats": {
                "total_calls": self._stats.total_calls,
                "successful_calls": self._stats.successful_calls,
                "failed_calls": self._stats.failed_calls,
                "rejected_calls": self._stats.rejected_calls,
                "consecutive_failures": self._stats.consecutive_failures,
                "state_changes": self._stats.state_changes,
            },
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "success_threshold": self.config.success_threshold,
                "timeout": self.config.timeout,
            },
            "last_failure": (
                self._stats.last_failure_time.isoformat()
                if self._stats.last_failure_time else None
            ),
            "last_success": (
                self._stats.last_success_time.isoformat()
                if self._stats.last_success_time else None
            ),
        }


# ═══════════════════════════════════════════════════════════════
# Pre-configured Circuit Breakers
# ═══════════════════════════════════════════════════════════════

# Registry of circuit breakers
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    name: str,
    failure_threshold: int = 5,
    timeout: float = 30.0,
    **kwargs
) -> CircuitBreaker:
    """
    Get or create circuit breaker by name.
    
    Args:
        name: Service name
        failure_threshold: Failures before opening
        timeout: Seconds before trying half-open
        **kwargs: Additional configuration
        
    Returns:
        CircuitBreaker instance
    """
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(
            name=name,
            failure_threshold=failure_threshold,
            timeout=timeout,
            **kwargs
        )
    return _circuit_breakers[name]


# Pre-configured breakers for common services
def get_metasploit_breaker() -> CircuitBreaker:
    """Get circuit breaker for Metasploit RPC."""
    return get_circuit_breaker(
        "metasploit",
        failure_threshold=3,
        timeout=60.0,
        expected_exceptions=(ConnectionError, TimeoutError, OSError)
    )


def get_elasticsearch_breaker() -> CircuitBreaker:
    """Get circuit breaker for Elasticsearch."""
    return get_circuit_breaker(
        "elasticsearch",
        failure_threshold=5,
        timeout=30.0,
        expected_exceptions=(ConnectionError, TimeoutError)
    )


def get_llm_breaker() -> CircuitBreaker:
    """Get circuit breaker for LLM providers."""
    return get_circuit_breaker(
        "llm",
        failure_threshold=3,
        timeout=120.0,  # LLM services may need longer recovery
        expected_exceptions=(ConnectionError, TimeoutError)
    )


def get_redis_breaker() -> CircuitBreaker:
    """Get circuit breaker for Redis."""
    return get_circuit_breaker(
        "redis",
        failure_threshold=3,
        timeout=15.0,  # Redis should recover quickly
        expected_exceptions=(ConnectionError, TimeoutError, OSError)
    )


def get_all_circuit_breakers() -> Dict[str, Dict[str, Any]]:
    """Get health status of all circuit breakers."""
    return {
        name: breaker.get_health_status()
        for name, breaker in _circuit_breakers.items()
    }
