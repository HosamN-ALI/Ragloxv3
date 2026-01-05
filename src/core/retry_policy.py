"""
═══════════════════════════════════════════════════════════════════════════════
RAGLOX v3.0 - Centralized Retry Policy System
═══════════════════════════════════════════════════════════════════════════════

GAP-C01 FIX: Enterprise-Grade Retry Policy Framework

This module provides a unified, configurable retry mechanism for all RAGLOX operations.
Eliminates inconsistent retry logic across different components by centralizing:

1. Retry strategies per error category
2. Exponential backoff with jitter
3. Circuit breaker pattern integration
4. Contextual retry decisions
5. Observable retry metrics

Key Features:
- Strategy-based retry policies (exponential, linear, fixed)
- Error categorization and context-aware decisions
- Circuit breaker to prevent cascading failures
- Retry budget tracking (prevent infinite retries)
- Detailed retry metrics and observability
- Thread-safe and async-compatible

Architecture:
┌──────────────────┐
│  Retry Policy    │←─── Configuration
│    Manager       │
└────────┬─────────┘
         │
    ┌────┴─────┐
    │  Policy  │
    │  Store   │
    └────┬─────┘
         │
    ┌────┴──────┐
    │  Metrics  │
    │  Tracker  │
    └───────────┘

Usage:
    # Initialize retry manager
    retry_manager = RetryPolicyManager()
    
    # Execute with retry policy
    result = await retry_manager.execute_with_retry(
        func=my_async_function,
        args=(arg1, arg2),
        kwargs={'key': 'value'},
        policy_name='network_operation',
        context={'target': '192.168.1.1'}
    )
    
    # Custom policy
    custom_policy = RetryPolicy(
        max_attempts=5,
        base_delay=2.0,
        strategy=RetryStrategy.EXPONENTIAL,
        max_delay=120.0,
        jitter=True
    )

Author: RAGLOX Core Team
License: Proprietary
"""

import asyncio
import time
import random
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TypeVar, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

T = TypeVar('T')


# ═══════════════════════════════════════════════════════════
# Error Categories & Classifications
# ═══════════════════════════════════════════════════════════

class ErrorCategory(str, Enum):
    """Error categories for retry decision-making."""
    NETWORK = "network"                  # Connection issues, timeouts
    DEFENSE = "defense"                  # Firewall, IDS/IPS, WAF blocks
    AUTHENTICATION = "authentication"    # Auth failures, permission denied
    VULNERABILITY = "vulnerability"       # Target patched, exploit failed
    TECHNICAL = "technical"              # Code errors, crashes
    RATE_LIMIT = "rate_limit"           # Rate limiting, throttling
    RESOURCE = "resource"                # Resource exhaustion, memory
    UNKNOWN = "unknown"                  # Unclassified errors


class RetryStrategy(str, Enum):
    """Retry delay calculation strategies."""
    EXPONENTIAL = "exponential"    # Exponential backoff (2^n * base_delay)
    LINEAR = "linear"              # Linear increase (n * base_delay)
    FIXED = "fixed"                # Fixed delay (base_delay)
    FIBONACCI = "fibonacci"        # Fibonacci sequence delay
    RANDOM = "random"              # Random delay within bounds


# ═══════════════════════════════════════════════════════════
# Retry Policy Configuration
# ═══════════════════════════════════════════════════════════

@dataclass
class RetryPolicy:
    """
    Retry policy configuration for a specific operation type.
    
    Attributes:
        max_attempts: Maximum retry attempts (0 = no retry)
        base_delay: Base delay in seconds
        strategy: Delay calculation strategy
        max_delay: Maximum delay cap in seconds
        jitter: Add randomness to delays (prevent thundering herd)
        timeout: Per-attempt timeout in seconds
        circuit_breaker_threshold: Failures before circuit opens
        circuit_breaker_reset: Time to reset circuit breaker (seconds)
        retryable_errors: List of error contexts that trigger retry
        non_retryable_errors: List of error contexts that skip retry
    """
    max_attempts: int = 3
    base_delay: float = 1.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    max_delay: float = 60.0
    jitter: bool = True
    timeout: Optional[float] = None
    circuit_breaker_threshold: int = 5
    circuit_breaker_reset: float = 300.0
    retryable_errors: List[str] = field(default_factory=list)
    non_retryable_errors: List[str] = field(default_factory=list)
    
    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate retry delay for given attempt number.
        
        Args:
            attempt: Current attempt number (1-indexed)
            
        Returns:
            Delay in seconds
        """
        if self.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.base_delay * (2 ** (attempt - 1))
        elif self.strategy == RetryStrategy.LINEAR:
            delay = self.base_delay * attempt
        elif self.strategy == RetryStrategy.FIXED:
            delay = self.base_delay
        elif self.strategy == RetryStrategy.FIBONACCI:
            fib = self._fibonacci(attempt)
            delay = self.base_delay * fib
        elif self.strategy == RetryStrategy.RANDOM:
            delay = random.uniform(self.base_delay, self.max_delay)
        else:
            delay = self.base_delay
        
        # Apply max delay cap
        delay = min(delay, self.max_delay)
        
        # Apply jitter to prevent thundering herd
        if self.jitter:
            jitter_amount = random.uniform(0, delay * 0.1)  # ±10% jitter
            delay = delay + jitter_amount
        
        return delay
    
    @staticmethod
    def _fibonacci(n: int) -> int:
        """Calculate nth Fibonacci number."""
        if n <= 1:
            return n
        a, b = 0, 1
        for _ in range(n - 1):
            a, b = b, a + b
        return b
    
    def is_retryable(self, error_context: str) -> bool:
        """
        Determine if error is retryable based on context.
        
        Args:
            error_context: Error context string
            
        Returns:
            True if error should be retried
        """
        # Check non-retryable errors first (explicit deny)
        for non_retryable in self.non_retryable_errors:
            if non_retryable.lower() in error_context.lower():
                return False
        
        # Check retryable errors (explicit allow)
        if self.retryable_errors:
            for retryable in self.retryable_errors:
                if retryable.lower() in error_context.lower():
                    return True
            # If retryable list exists but no match, don't retry
            return False
        
        # Default: retry if no explicit lists
        return True


# ═══════════════════════════════════════════════════════════
# Circuit Breaker Implementation
# ═══════════════════════════════════════════════════════════

class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"            # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreaker:
    """
    Circuit breaker to prevent cascading failures.
    
    States:
    - CLOSED: Normal operation, requests allowed
    - OPEN: Too many failures, requests rejected
    - HALF_OPEN: Testing recovery, limited requests
    """
    threshold: int
    reset_timeout: float
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    success_count_in_half_open: int = 0
    
    def record_success(self) -> None:
        """Record successful request."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count_in_half_open += 1
            # After 3 successes in half-open, close circuit
            if self.success_count_in_half_open >= 3:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count_in_half_open = 0
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0
    
    def record_failure(self) -> None:
        """Record failed request."""
        self.last_failure_time = datetime.now()
        self.failure_count += 1
        
        if self.state == CircuitState.HALF_OPEN:
            # Failure in half-open -> reopen circuit
            self.state = CircuitState.OPEN
            self.success_count_in_half_open = 0
        elif self.state == CircuitState.CLOSED:
            # Check if threshold exceeded
            if self.failure_count >= self.threshold:
                self.state = CircuitState.OPEN
    
    def can_attempt(self) -> bool:
        """Check if request can be attempted."""
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Check if reset timeout elapsed
            if self.last_failure_time:
                elapsed = (datetime.now() - self.last_failure_time).total_seconds()
                if elapsed >= self.reset_timeout:
                    # Transition to half-open
                    self.state = CircuitState.HALF_OPEN
                    self.success_count_in_half_open = 0
                    return True
            return False
        
        if self.state == CircuitState.HALF_OPEN:
            # Allow limited requests in half-open
            return True
        
        return False


# ═══════════════════════════════════════════════════════════
# Retry Metrics & Observability
# ═══════════════════════════════════════════════════════════

@dataclass
class RetryMetrics:
    """Metrics for retry operations."""
    policy_name: str
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    retries_triggered: int = 0
    circuit_breaker_opens: int = 0
    total_delay_seconds: float = 0.0
    last_attempt_time: Optional[datetime] = None
    
    def record_attempt(self, success: bool, delay: float = 0.0) -> None:
        """Record an attempt result."""
        self.total_attempts += 1
        self.last_attempt_time = datetime.now()
        
        if success:
            self.successful_attempts += 1
        else:
            self.failed_attempts += 1
            self.retries_triggered += 1
            self.total_delay_seconds += delay
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "policy_name": self.policy_name,
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts,
            "failed_attempts": self.failed_attempts,
            "retries_triggered": self.retries_triggered,
            "circuit_breaker_opens": self.circuit_breaker_opens,
            "total_delay_seconds": round(self.total_delay_seconds, 2),
            "success_rate": round(
                self.successful_attempts / self.total_attempts * 100, 2
            ) if self.total_attempts > 0 else 0.0,
            "last_attempt_time": self.last_attempt_time.isoformat() if self.last_attempt_time else None
        }


# ═══════════════════════════════════════════════════════════
# Retry Policy Manager
# ═══════════════════════════════════════════════════════════

class RetryPolicyManager:
    """
    Centralized retry policy manager for all RAGLOX operations.
    
    Provides:
    - Unified retry logic across all components
    - Configurable policies per operation type
    - Circuit breaker integration
    - Retry metrics and observability
    """
    
    def __init__(self):
        """Initialize retry policy manager with default policies."""
        self._policies: Dict[str, RetryPolicy] = {}
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._metrics: Dict[str, RetryMetrics] = {}
        
        # Load default policies
        self._load_default_policies()
    
    def _load_default_policies(self) -> None:
        """Load default retry policies for common operations."""
        
        # Network operations (connection failures, timeouts)
        self._policies["network_operation"] = RetryPolicy(
            max_attempts=3,
            base_delay=2.0,
            strategy=RetryStrategy.EXPONENTIAL,
            max_delay=30.0,
            jitter=True,
            timeout=60.0,
            circuit_breaker_threshold=5,
            circuit_breaker_reset=300.0,
            retryable_errors=[
                "connection_refused",
                "connection_timeout",
                "connection_reset",
                "network_unreachable",
                "timeout"
            ],
            non_retryable_errors=["connection_closed_permanently"]
        )
        
        # Defense evasion (firewall, IDS/IPS, WAF blocks)
        self._policies["defense_operation"] = RetryPolicy(
            max_attempts=1,  # Limited retries for defense mechanisms
            base_delay=60.0,
            strategy=RetryStrategy.FIXED,
            max_delay=300.0,
            jitter=True,
            timeout=120.0,
            circuit_breaker_threshold=3,
            circuit_breaker_reset=600.0,
            retryable_errors=["rate_limited", "temporarily_blocked"],
            non_retryable_errors=[
                "firewall_blocked",
                "waf_blocked",
                "ids_detected",
                "av_detected",
                "edr_blocked"
            ]
        )
        
        # Authentication operations
        self._policies["authentication_operation"] = RetryPolicy(
            max_attempts=2,
            base_delay=5.0,
            strategy=RetryStrategy.LINEAR,
            max_delay=30.0,
            jitter=False,
            timeout=30.0,
            circuit_breaker_threshold=5,
            circuit_breaker_reset=300.0,
            retryable_errors=["auth_timeout", "auth_rate_limit"],
            non_retryable_errors=[
                "auth_failed",
                "invalid_credentials",
                "access_denied",
                "permission_denied"
            ]
        )
        
        # Vulnerability exploitation
        self._policies["vulnerability_operation"] = RetryPolicy(
            max_attempts=0,  # No retry for failed exploits
            base_delay=0.0,
            strategy=RetryStrategy.FIXED,
            max_delay=0.0,
            jitter=False,
            timeout=300.0,
            circuit_breaker_threshold=10,
            circuit_breaker_reset=900.0,
            non_retryable_errors=[
                "target_patched",
                "exploit_failed",
                "vulnerability_not_present"
            ]
        )
        
        # LLM API calls
        self._policies["llm_api"] = RetryPolicy(
            max_attempts=5,
            base_delay=1.0,
            strategy=RetryStrategy.EXPONENTIAL,
            max_delay=120.0,
            jitter=True,
            timeout=60.0,
            circuit_breaker_threshold=10,
            circuit_breaker_reset=180.0,
            retryable_errors=[
                "rate_limit",
                "timeout",
                "service_unavailable",
                "connection_error",
                "502",
                "503",
                "504"
            ],
            non_retryable_errors=[
                "invalid_api_key",
                "invalid_request",
                "400",
                "401",
                "403"
            ]
        )
        
        # Database operations
        self._policies["database_operation"] = RetryPolicy(
            max_attempts=3,
            base_delay=1.0,
            strategy=RetryStrategy.EXPONENTIAL,
            max_delay=10.0,
            jitter=True,
            timeout=30.0,
            circuit_breaker_threshold=5,
            circuit_breaker_reset=60.0,
            retryable_errors=[
                "connection_timeout",
                "deadlock",
                "lock_timeout",
                "connection_pool_exhausted"
            ]
        )
        
        # Default policy (conservative)
        self._policies["default"] = RetryPolicy(
            max_attempts=2,
            base_delay=5.0,
            strategy=RetryStrategy.EXPONENTIAL,
            max_delay=30.0,
            jitter=True,
            timeout=60.0,
            circuit_breaker_threshold=5,
            circuit_breaker_reset=300.0
        )
    
    def register_policy(self, name: str, policy: RetryPolicy) -> None:
        """
        Register a custom retry policy.
        
        Args:
            name: Policy name
            policy: RetryPolicy configuration
        """
        self._policies[name] = policy
        self._metrics[name] = RetryMetrics(policy_name=name)
    
    def get_policy(self, name: str) -> RetryPolicy:
        """Get retry policy by name (defaults to 'default' if not found)."""
        return self._policies.get(name, self._policies["default"])
    
    def _get_circuit_breaker(self, policy_name: str, policy: RetryPolicy) -> CircuitBreaker:
        """Get or create circuit breaker for policy."""
        if policy_name not in self._circuit_breakers:
            self._circuit_breakers[policy_name] = CircuitBreaker(
                threshold=policy.circuit_breaker_threshold,
                reset_timeout=policy.circuit_breaker_reset
            )
        return self._circuit_breakers[policy_name]
    
    def _get_metrics(self, policy_name: str) -> RetryMetrics:
        """Get or create metrics for policy."""
        if policy_name not in self._metrics:
            self._metrics[policy_name] = RetryMetrics(policy_name=policy_name)
        return self._metrics[policy_name]
    
    async def execute_with_retry(
        self,
        func: Callable[..., Awaitable[T]],
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        policy_name: str = "default",
        context: Optional[Dict[str, Any]] = None
    ) -> T:
        """
        Execute async function with retry policy.
        
        Args:
            func: Async function to execute
            args: Positional arguments for func
            kwargs: Keyword arguments for func
            policy_name: Name of retry policy to use
            context: Additional context for retry decisions
            
        Returns:
            Result from func
            
        Raises:
            Exception: Last exception if all retries exhausted
        """
        kwargs = kwargs or {}
        context = context or {}
        
        policy = self.get_policy(policy_name)
        circuit_breaker = self._get_circuit_breaker(policy_name, policy)
        metrics = self._get_metrics(policy_name)
        
        last_exception = None
        attempt = 0
        
        while attempt < policy.max_attempts + 1:  # +1 for initial attempt
            attempt += 1
            
            # Check circuit breaker
            if not circuit_breaker.can_attempt():
                raise Exception(
                    f"Circuit breaker open for {policy_name} "
                    f"(state: {circuit_breaker.state}, "
                    f"failures: {circuit_breaker.failure_count})"
                )
            
            try:
                # Execute with timeout if specified
                if policy.timeout:
                    result = await asyncio.wait_for(
                        func(*args, **kwargs),
                        timeout=policy.timeout
                    )
                else:
                    result = await func(*args, **kwargs)
                
                # Success
                circuit_breaker.record_success()
                metrics.record_attempt(success=True)
                return result
                
            except Exception as e:
                last_exception = e
                error_context = str(e)
                
                # Record failure
                circuit_breaker.record_failure()
                
                # Check if error is retryable
                if not policy.is_retryable(error_context):
                    metrics.record_attempt(success=False)
                    raise
                
                # Check if we have retries left
                if attempt >= policy.max_attempts + 1:
                    metrics.record_attempt(success=False)
                    raise
                
                # Calculate delay and wait
                delay = policy.calculate_delay(attempt)
                metrics.record_attempt(success=False, delay=delay)
                
                # Log retry attempt (could integrate with logger here)
                await asyncio.sleep(delay)
        
        # Should never reach here, but just in case
        if last_exception:
            raise last_exception
        raise Exception("Retry logic error: exhausted attempts without exception")
    
    def execute_with_retry_sync(
        self,
        func: Callable[..., T],
        args: tuple = (),
        kwargs: Optional[Dict[str, Any]] = None,
        policy_name: str = "default",
        context: Optional[Dict[str, Any]] = None
    ) -> T:
        """
        Execute sync function with retry policy.
        
        Args:
            func: Sync function to execute
            args: Positional arguments for func
            kwargs: Keyword arguments for func
            policy_name: Name of retry policy to use
            context: Additional context for retry decisions
            
        Returns:
            Result from func
            
        Raises:
            Exception: Last exception if all retries exhausted
        """
        kwargs = kwargs or {}
        context = context or {}
        
        policy = self.get_policy(policy_name)
        circuit_breaker = self._get_circuit_breaker(policy_name, policy)
        metrics = self._get_metrics(policy_name)
        
        last_exception = None
        attempt = 0
        
        while attempt < policy.max_attempts + 1:
            attempt += 1
            
            # Check circuit breaker
            if not circuit_breaker.can_attempt():
                raise Exception(
                    f"Circuit breaker open for {policy_name} "
                    f"(state: {circuit_breaker.state})"
                )
            
            try:
                result = func(*args, **kwargs)
                
                # Success
                circuit_breaker.record_success()
                metrics.record_attempt(success=True)
                return result
                
            except Exception as e:
                last_exception = e
                error_context = str(e)
                
                # Record failure
                circuit_breaker.record_failure()
                
                # Check if error is retryable
                if not policy.is_retryable(error_context):
                    metrics.record_attempt(success=False)
                    raise
                
                # Check if we have retries left
                if attempt >= policy.max_attempts + 1:
                    metrics.record_attempt(success=False)
                    raise
                
                # Calculate delay and wait
                delay = policy.calculate_delay(attempt)
                metrics.record_attempt(success=False, delay=delay)
                
                time.sleep(delay)
        
        if last_exception:
            raise last_exception
        raise Exception("Retry logic error: exhausted attempts without exception")
    
    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all registered policies."""
        return {
            name: metrics.to_dict()
            for name, metrics in self._metrics.items()
        }
    
    def get_circuit_breaker_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers."""
        return {
            name: {
                "state": cb.state.value,
                "failure_count": cb.failure_count,
                "last_failure_time": cb.last_failure_time.isoformat() if cb.last_failure_time else None
            }
            for name, cb in self._circuit_breakers.items()
        }


# ═══════════════════════════════════════════════════════════
# Global Singleton Instance
# ═══════════════════════════════════════════════════════════

_global_retry_manager: Optional[RetryPolicyManager] = None


def get_retry_manager() -> RetryPolicyManager:
    """Get global retry manager singleton."""
    global _global_retry_manager
    if _global_retry_manager is None:
        _global_retry_manager = RetryPolicyManager()
    return _global_retry_manager


# ═══════════════════════════════════════════════════════════
# Decorator for Easy Integration
# ═══════════════════════════════════════════════════════════

def with_retry(policy_name: str = "default", context: Optional[Dict[str, Any]] = None):
    """
    Decorator to add retry logic to async functions.
    
    Usage:
        @with_retry(policy_name="network_operation")
        async def fetch_data(url: str) -> Dict:
            ...
    """
    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(*args, **kwargs) -> T:
            manager = get_retry_manager()
            return await manager.execute_with_retry(
                func=func,
                args=args,
                kwargs=kwargs,
                policy_name=policy_name,
                context=context or {}
            )
        return wrapper
    return decorator
