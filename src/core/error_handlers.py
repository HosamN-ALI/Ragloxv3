# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - SEC-01 Error Handlers
# Centralized error handling utilities for exception replacement
# ═══════════════════════════════════════════════════════════════
"""
SEC-01 Implementation: Exception Handling Enhancement

This module provides centralized error handling utilities to replace
generic `except Exception` blocks with specific, secure error handling.

Security Benefits:
- Prevents information leakage through generic error messages
- Categorizes errors for proper response codes
- Sanitizes sensitive data from error messages
- Provides consistent error handling across the application
- Enables proper logging without exposing internals

Usage:
    from src.core.error_handlers import (
        handle_api_error,
        handle_specialist_error,
        safe_execute,
        categorize_exception
    )
"""

import asyncio
import logging
import traceback
from functools import wraps
from typing import Any, Callable, Dict, Optional, Type, Union, Tuple, List
from pydantic import ValidationError

from .exceptions import (
    RAGLOXException,
    # Connection exceptions
    ConnectionException,
    RedisConnectionError,
    DatabaseConnectionError,
    BlackboardNotConnectedError,
    # Mission exceptions
    MissionException,
    MissionNotFoundError,
    MissionAlreadyExistsError,
    InvalidMissionStateError,
    MissionLimitExceededError,
    # Target exceptions
    TargetException,
    TargetNotFoundError,
    InvalidTargetError,
    TargetOutOfScopeError,
    # Task exceptions
    TaskException,
    TaskNotFoundError,
    TaskExecutionError,
    TaskTimeoutError,
    NoTasksAvailableError,
    # Specialist exceptions
    SpecialistException,
    SpecialistNotRunningError,
    UnsupportedTaskTypeError,
    # Validation exceptions
    ValidationException,
    InvalidIPAddressError,
    InvalidCIDRError,
    InvalidUUIDError,
    MissingRequiredFieldError,
    # Security exceptions
    SecurityException,
    AuthenticationError,
    AuthorizationError,
    RateLimitExceededError,
    # API exceptions
    APIException,
    BadRequestError,
    NotFoundError,
    ConflictError,
    InternalServerError,
    # Network exceptions
    NetworkException,
    ConnectionTimeoutError,
    ServiceUnavailableError,
    ExternalAPIError,
    # Exploitation exceptions
    ExploitationException,
    ExploitNotFoundError,
    ExploitExecutionError,
    SessionCreationError,
    PayloadGenerationError,
    # Configuration exceptions
    ConfigurationException,
    MissingConfigurationError,
    InvalidConfigurationError,
    # File operation exceptions
    FileOperationException,
    FileReadError,
    FileWriteError,
    # LLM exceptions
    LLMException,
    LLMRateLimitError,
    LLMResponseError,
    # Data parsing exceptions
    DataParsingException,
    JSONParsingError,
    SchemaValidationError,
    # Utilities
    sanitize_error_message,
    wrap_exception,
)

logger = logging.getLogger("raglox.error_handlers")


# ═══════════════════════════════════════════════════════════════
# Exception Category Mapping
# ═══════════════════════════════════════════════════════════════

class ErrorCategory:
    """Error categories for consistent handling."""
    CONNECTION = "connection"
    VALIDATION = "validation"
    NOT_FOUND = "not_found"
    PERMISSION = "permission"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    SERVICE_UNAVAILABLE = "service_unavailable"
    EXPLOITATION = "exploitation"
    CONFIGURATION = "configuration"
    LLM = "llm"
    FILE_IO = "file_io"
    PARSING = "parsing"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


# HTTP Status Code Mapping
CATEGORY_TO_STATUS_CODE = {
    ErrorCategory.CONNECTION: 503,
    ErrorCategory.VALIDATION: 400,
    ErrorCategory.NOT_FOUND: 404,
    ErrorCategory.PERMISSION: 403,
    ErrorCategory.TIMEOUT: 504,
    ErrorCategory.RATE_LIMIT: 429,
    ErrorCategory.SERVICE_UNAVAILABLE: 503,
    ErrorCategory.EXPLOITATION: 500,
    ErrorCategory.CONFIGURATION: 500,
    ErrorCategory.LLM: 502,
    ErrorCategory.FILE_IO: 500,
    ErrorCategory.PARSING: 400,
    ErrorCategory.INTERNAL: 500,
    ErrorCategory.UNKNOWN: 500,
}


def categorize_exception(e: Exception) -> Tuple[str, int]:
    """
    Categorize an exception for proper handling.
    
    Args:
        e: The exception to categorize
        
    Returns:
        Tuple of (category, http_status_code)
    """
    # RAGLOX-specific exceptions
    if isinstance(e, (MissionNotFoundError, TargetNotFoundError, TaskNotFoundError, 
                      ExploitNotFoundError, NotFoundError)):
        return ErrorCategory.NOT_FOUND, 404
    
    if isinstance(e, (InvalidMissionStateError, InvalidTargetError, ValidationException,
                      InvalidIPAddressError, InvalidCIDRError, InvalidUUIDError,
                      MissingRequiredFieldError, BadRequestError)):
        return ErrorCategory.VALIDATION, 400
    
    if isinstance(e, (RedisConnectionError, DatabaseConnectionError, 
                      BlackboardNotConnectedError, ConnectionException)):
        return ErrorCategory.CONNECTION, 503
    
    if isinstance(e, (AuthenticationError, AuthorizationError)):
        return ErrorCategory.PERMISSION, 403
    
    if isinstance(e, RateLimitExceededError):
        return ErrorCategory.RATE_LIMIT, 429
    
    if isinstance(e, (ConnectionTimeoutError, TaskTimeoutError)):
        return ErrorCategory.TIMEOUT, 504
    
    if isinstance(e, ServiceUnavailableError):
        return ErrorCategory.SERVICE_UNAVAILABLE, 503
    
    if isinstance(e, (ExploitationException, ExploitExecutionError, 
                      SessionCreationError, PayloadGenerationError)):
        return ErrorCategory.EXPLOITATION, 500
    
    if isinstance(e, (ConfigurationException, MissingConfigurationError, 
                      InvalidConfigurationError)):
        return ErrorCategory.CONFIGURATION, 500
    
    if isinstance(e, (LLMException, LLMRateLimitError, LLMResponseError)):
        return ErrorCategory.LLM, 502
    
    if isinstance(e, (FileOperationException, FileReadError, FileWriteError)):
        return ErrorCategory.FILE_IO, 500
    
    if isinstance(e, (DataParsingException, JSONParsingError, SchemaValidationError)):
        return ErrorCategory.PARSING, 400
    
    # Standard Python exceptions
    if isinstance(e, ValidationError):  # Pydantic
        return ErrorCategory.VALIDATION, 400
    
    if isinstance(e, asyncio.TimeoutError):
        return ErrorCategory.TIMEOUT, 504
    
    if isinstance(e, (ConnectionError, OSError)) and "connection" in str(e).lower():
        return ErrorCategory.CONNECTION, 503
    
    if isinstance(e, PermissionError):
        return ErrorCategory.PERMISSION, 403
    
    if isinstance(e, FileNotFoundError):
        return ErrorCategory.NOT_FOUND, 404
    
    if isinstance(e, ValueError):
        return ErrorCategory.VALIDATION, 400
    
    if isinstance(e, KeyError):
        return ErrorCategory.NOT_FOUND, 404
    
    if isinstance(e, (json_import_error(), TypeError)):
        return ErrorCategory.PARSING, 400
    
    # Default
    return ErrorCategory.INTERNAL, 500


def json_import_error():
    """Lazy import of JSONDecodeError."""
    import json
    return json.JSONDecodeError


# ═══════════════════════════════════════════════════════════════
# API Error Handling
# ═══════════════════════════════════════════════════════════════

def handle_api_error(
    e: Exception,
    operation: str,
    logger_instance: Optional[logging.Logger] = None,
    include_traceback: bool = False
) -> Dict[str, Any]:
    """
    Handle an exception and return a safe API response.
    
    This function should be used in API endpoints to convert exceptions
    to safe, consistent error responses.
    
    Args:
        e: The exception to handle
        operation: Description of the operation that failed
        logger_instance: Logger to use (defaults to module logger)
        include_traceback: Whether to include traceback in logs (not response)
        
    Returns:
        Dictionary suitable for API error response
    """
    log = logger_instance or logger
    category, status_code = categorize_exception(e)
    
    # Sanitize the error message
    safe_message = sanitize_error_message(e)
    
    # Log based on severity
    if status_code >= 500:
        if include_traceback:
            log.error(
                f"[{category.upper()}] {operation} failed: {safe_message}",
                exc_info=True
            )
        else:
            log.error(f"[{category.upper()}] {operation} failed: {safe_message}")
    elif status_code >= 400:
        log.warning(f"[{category.upper()}] {operation}: {safe_message}")
    else:
        log.info(f"[{category.upper()}] {operation}: {safe_message}")
    
    # Build response
    response = {
        "error": True,
        "error_category": category,
        "status_code": status_code,
        "message": _get_safe_user_message(e, category, operation),
    }
    
    # Add error code if available
    if isinstance(e, RAGLOXException):
        response["error_code"] = e.error_code
        # Include safe details (no sensitive data)
        if e.details:
            response["details"] = _sanitize_details(e.details)
    
    # Add retry info for rate limits
    if isinstance(e, RateLimitExceededError) and e.retry_after:
        response["retry_after_seconds"] = e.retry_after
    
    return response


def _get_safe_user_message(
    e: Exception,
    category: str,
    operation: str
) -> str:
    """Get a safe, user-friendly error message."""
    
    # Use specific messages for known categories
    category_messages = {
        ErrorCategory.CONNECTION: f"Service temporarily unavailable during {operation}",
        ErrorCategory.VALIDATION: f"Invalid input for {operation}",
        ErrorCategory.NOT_FOUND: f"Resource not found during {operation}",
        ErrorCategory.PERMISSION: f"Permission denied for {operation}",
        ErrorCategory.TIMEOUT: f"Operation timed out: {operation}",
        ErrorCategory.RATE_LIMIT: "Rate limit exceeded. Please try again later",
        ErrorCategory.SERVICE_UNAVAILABLE: f"Service unavailable for {operation}",
        ErrorCategory.EXPLOITATION: f"Operation failed: {operation}",
        ErrorCategory.CONFIGURATION: f"Configuration error during {operation}",
        ErrorCategory.LLM: f"AI service error during {operation}",
        ErrorCategory.FILE_IO: f"File operation failed during {operation}",
        ErrorCategory.PARSING: f"Invalid data format for {operation}",
        ErrorCategory.INTERNAL: f"Internal error during {operation}",
        ErrorCategory.UNKNOWN: f"Unexpected error during {operation}",
    }
    
    # For RAGLOX exceptions, use the sanitized message if it's safe
    if isinstance(e, RAGLOXException):
        return sanitize_error_message(e)
    
    # For standard exceptions, use category-based message
    return category_messages.get(category, f"Error during {operation}")


def _sanitize_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """Remove sensitive data from error details."""
    sensitive_keys = {
        "password", "secret", "api_key", "token", "credential",
        "private_key", "ssh_key", "auth", "authorization"
    }
    
    sanitized = {}
    for key, value in details.items():
        key_lower = key.lower()
        if any(s in key_lower for s in sensitive_keys):
            sanitized[key] = "***"
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_details(value)
        elif isinstance(value, str) and len(value) > 100:
            # Truncate long strings
            sanitized[key] = value[:100] + "..."
        else:
            sanitized[key] = value
    
    return sanitized


# ═══════════════════════════════════════════════════════════════
# Specialist Error Handling
# ═══════════════════════════════════════════════════════════════

def handle_specialist_error(
    e: Exception,
    specialist_type: str,
    task_id: Optional[str] = None,
    operation: str = "task execution",
    logger_instance: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Handle an exception in a specialist context.
    
    This provides additional context for specialist operations
    and returns data suitable for Blackboard logging.
    
    Args:
        e: The exception to handle
        specialist_type: Type of specialist (e.g., "attack", "recon")
        task_id: Task ID if applicable
        operation: Description of the operation
        logger_instance: Logger to use
        
    Returns:
        Dictionary with error context for Blackboard
    """
    log = logger_instance or logger
    category, _ = categorize_exception(e)
    safe_message = sanitize_error_message(e)
    
    # Log with specialist context
    log.error(
        f"[{specialist_type.upper()}] {operation} failed "
        f"(task={task_id or 'N/A'}): {safe_message}"
    )
    
    # Build error context for Reflexion analysis
    error_context = {
        "category": category,
        "specialist_type": specialist_type,
        "task_id": task_id,
        "operation": operation,
        "error_type": type(e).__name__,
        "safe_message": safe_message,
    }
    
    # Add exception-specific context
    if isinstance(e, RAGLOXException):
        error_context["error_code"] = e.error_code
        if e.details:
            error_context["details"] = _sanitize_details(e.details)
    
    # Add retry hints
    error_context["retryable"] = category in {
        ErrorCategory.CONNECTION,
        ErrorCategory.TIMEOUT,
        ErrorCategory.SERVICE_UNAVAILABLE,
        ErrorCategory.LLM,
    }
    
    return error_context


# ═══════════════════════════════════════════════════════════════
# Safe Execution Decorators
# ═══════════════════════════════════════════════════════════════

def safe_execute(
    operation: str,
    default_return: Any = None,
    reraise_types: Optional[Tuple[Type[Exception], ...]] = None,
    logger_instance: Optional[logging.Logger] = None
):
    """
    Decorator for safe execution with error handling.
    
    Wraps a function to catch and handle exceptions, logging them
    appropriately and optionally returning a default value.
    
    Args:
        operation: Description of the operation
        default_return: Value to return on error
        reraise_types: Exception types to re-raise (not catch)
        logger_instance: Logger to use
        
    Example:
        @safe_execute("credential harvesting", default_return=[])
        async def harvest_credentials(target_id: str):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                if reraise_types and isinstance(e, reraise_types):
                    raise
                
                log = logger_instance or logger
                safe_message = sanitize_error_message(e)
                category, _ = categorize_exception(e)
                
                log.error(
                    f"[{category.upper()}] {operation} failed: {safe_message}"
                )
                
                return default_return
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if reraise_types and isinstance(e, reraise_types):
                    raise
                
                log = logger_instance or logger
                safe_message = sanitize_error_message(e)
                category, _ = categorize_exception(e)
                
                log.error(
                    f"[{category.upper()}] {operation} failed: {safe_message}"
                )
                
                return default_return
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


def safe_execute_with_result(
    operation: str,
    logger_instance: Optional[logging.Logger] = None
):
    """
    Decorator that returns (success, result/error) tuple.
    
    This variant allows the caller to check success status
    while still having access to error details.
    
    Args:
        operation: Description of the operation
        logger_instance: Logger to use
        
    Example:
        @safe_execute_with_result("exploit execution")
        async def execute_exploit(target_id: str):
            ...
            
        success, result = await execute_exploit("target-123")
        if not success:
            error_context = result
    """
    def decorator(func: Callable):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                result = await func(*args, **kwargs)
                return True, result
            except Exception as e:
                log = logger_instance or logger
                error_context = handle_specialist_error(
                    e=e,
                    specialist_type="general",
                    operation=operation,
                    logger_instance=log
                )
                return False, error_context
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                result = func(*args, **kwargs)
                return True, result
            except Exception as e:
                log = logger_instance or logger
                error_context = handle_specialist_error(
                    e=e,
                    specialist_type="general",
                    operation=operation,
                    logger_instance=log
                )
                return False, error_context
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    return decorator


# ═══════════════════════════════════════════════════════════════
# Exception Type Guards (for replacing except Exception)
# ═══════════════════════════════════════════════════════════════

# Network/Connection errors
NETWORK_ERRORS = (
    ConnectionError,
    OSError,
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionException,
    RedisConnectionError,
    DatabaseConnectionError,
    BlackboardNotConnectedError,
    ConnectionTimeoutError,
    ServiceUnavailableError,
)

# Validation errors
VALIDATION_ERRORS = (
    ValueError,
    TypeError,
    ValidationError,
    ValidationException,
    InvalidIPAddressError,
    InvalidCIDRError,
    InvalidUUIDError,
    MissingRequiredFieldError,
    InvalidTargetError,
    InvalidMissionStateError,
    BadRequestError,
)

# Not found errors
NOT_FOUND_ERRORS = (
    KeyError,
    FileNotFoundError,
    MissionNotFoundError,
    TargetNotFoundError,
    TaskNotFoundError,
    ExploitNotFoundError,
    NotFoundError,
)

# Permission/Auth errors
PERMISSION_ERRORS = (
    PermissionError,
    AuthenticationError,
    AuthorizationError,
)

# Exploitation errors
EXPLOITATION_ERRORS = (
    ExploitationException,
    ExploitNotFoundError,
    ExploitExecutionError,
    SessionCreationError,
    PayloadGenerationError,
)

# All known RAGLOX errors (for catch-all that's still specific)
ALL_RAGLOX_ERRORS = (
    RAGLOXException,
)

# Recoverable errors (can be retried)
RECOVERABLE_ERRORS = (
    ConnectionError,
    OSError,
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionException,
    ConnectionTimeoutError,
    ServiceUnavailableError,
    LLMRateLimitError,
    RateLimitExceededError,
)


# ═══════════════════════════════════════════════════════════════
# FastAPI HTTPException Helper
# ═══════════════════════════════════════════════════════════════

def create_http_exception(
    e: Exception,
    operation: str,
    logger_instance: Optional[logging.Logger] = None
):
    """
    Create a FastAPI HTTPException from any exception.
    
    This is the recommended way to convert exceptions in API routes.
    
    Args:
        e: The exception to convert
        operation: Description of the operation
        logger_instance: Logger to use
        
    Returns:
        HTTPException with appropriate status code and detail
    """
    from fastapi import HTTPException, status
    
    log = logger_instance or logger
    category, status_code = categorize_exception(e)
    safe_message = sanitize_error_message(e)
    
    # Log the error
    log.error(f"[{category.upper()}] {operation}: {safe_message}")
    
    # Get user-friendly message
    user_message = _get_safe_user_message(e, category, operation)
    
    return HTTPException(
        status_code=status_code,
        detail=user_message
    )


# ═══════════════════════════════════════════════════════════════
# Context Manager for Safe Blocks
# ═══════════════════════════════════════════════════════════════

class safe_block:
    """
    Context manager for safe code blocks with error handling.
    
    Usage:
        async with safe_block("credential lookup", logger=self.logger) as ctx:
            result = await lookup_credentials()
            ctx.result = result
        
        if ctx.success:
            use(ctx.result)
        else:
            handle_error(ctx.error_context)
    """
    
    def __init__(
        self,
        operation: str,
        logger: Optional[logging.Logger] = None,
        reraise_types: Optional[Tuple[Type[Exception], ...]] = None
    ):
        self.operation = operation
        self.logger = logger or logging.getLogger("raglox.safe_block")
        self.reraise_types = reraise_types
        self.success = False
        self.result = None
        self.error_context = None
        self.exception = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_val is None:
            self.success = True
            return True
        
        if self.reraise_types and isinstance(exc_val, self.reraise_types):
            return False  # Re-raise
        
        self.exception = exc_val
        self.error_context = handle_specialist_error(
            e=exc_val,
            specialist_type="general",
            operation=self.operation,
            logger_instance=self.logger
        )
        
        return True  # Suppress exception
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is None:
            self.success = True
            return True
        
        if self.reraise_types and isinstance(exc_val, self.reraise_types):
            return False
        
        self.exception = exc_val
        self.error_context = handle_specialist_error(
            e=exc_val,
            specialist_type="general",
            operation=self.operation,
            logger_instance=self.logger
        )
        
        return True


# ═══════════════════════════════════════════════════════════════
# Export all
# ═══════════════════════════════════════════════════════════════

__all__ = [
    # Category
    "ErrorCategory",
    "CATEGORY_TO_STATUS_CODE",
    "categorize_exception",
    
    # Handlers
    "handle_api_error",
    "handle_specialist_error",
    
    # Decorators
    "safe_execute",
    "safe_execute_with_result",
    
    # Exception groups
    "NETWORK_ERRORS",
    "VALIDATION_ERRORS", 
    "NOT_FOUND_ERRORS",
    "PERMISSION_ERRORS",
    "EXPLOITATION_ERRORS",
    "ALL_RAGLOX_ERRORS",
    "RECOVERABLE_ERRORS",
    
    # Helpers
    "create_http_exception",
    "safe_block",
]
