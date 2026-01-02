# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Structured Logging
# Advanced logging with JSON output and context tracking
# ═══════════════════════════════════════════════════════════════

import json
import logging
import sys
import traceback
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, Optional, TypeVar, Union
from uuid import uuid4

from .config import get_settings


# ═══════════════════════════════════════════════════════════════
# Context Variables for Request Tracking
# ═══════════════════════════════════════════════════════════════

# These context variables allow logging to include request-specific information
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
mission_id_var: ContextVar[Optional[str]] = ContextVar('mission_id', default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar('user_id', default=None)
specialist_id_var: ContextVar[Optional[str]] = ContextVar('specialist_id', default=None)


def get_context() -> Dict[str, Optional[str]]:
    """Get current logging context."""
    return {
        'request_id': request_id_var.get(),
        'mission_id': mission_id_var.get(),
        'user_id': user_id_var.get(),
        'specialist_id': specialist_id_var.get(),
    }


@contextmanager
def logging_context(
    request_id: Optional[str] = None,
    mission_id: Optional[str] = None,
    user_id: Optional[str] = None,
    specialist_id: Optional[str] = None
):
    """
    Context manager for setting logging context.
    
    Usage:
        with logging_context(mission_id="abc123"):
            logger.info("Processing mission")  # Includes mission_id
    """
    tokens = []
    
    if request_id is not None:
        tokens.append(request_id_var.set(request_id))
    if mission_id is not None:
        tokens.append(mission_id_var.set(mission_id))
    if user_id is not None:
        tokens.append(user_id_var.set(user_id))
    if specialist_id is not None:
        tokens.append(specialist_id_var.set(specialist_id))
    
    try:
        yield
    finally:
        # Reset context variables
        for token in tokens:
            token.var.reset(token)


# ═══════════════════════════════════════════════════════════════
# JSON Formatter
# ═══════════════════════════════════════════════════════════════

class JSONFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging.
    
    Produces machine-readable JSON logs with consistent structure.
    """
    
    def __init__(self, include_traceback: bool = True):
        super().__init__()
        self.include_traceback = include_traceback
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Base log entry
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add context from context variables
        context = get_context()
        for key, value in context.items():
            if value is not None:
                log_entry[key] = value
        
        # Add extra fields from record
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        
        # Add exception info if present
        if record.exc_info:
            if self.include_traceback:
                log_entry['exception'] = {
                    'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                    'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                    'traceback': traceback.format_exception(*record.exc_info)
                }
            else:
                log_entry['exception'] = {
                    'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                    'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                }
        
        # Add stack info if present
        if record.stack_info:
            log_entry['stack_info'] = record.stack_info
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """
    Colored console formatter for development.
    
    Produces human-readable logs with color coding.
    """
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        color = self.COLORS.get(record.levelname, self.RESET)
        
        # Format timestamp
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        # Format base message
        message = f"{color}[{timestamp}] [{record.levelname:8}] {record.name}: {record.getMessage()}{self.RESET}"
        
        # Add context info
        context = get_context()
        context_parts = [f"{k}={v}" for k, v in context.items() if v]
        if context_parts:
            message += f" | {' '.join(context_parts)}"
        
        # Add extra fields
        if hasattr(record, 'extra_fields') and record.extra_fields:
            extras = ' '.join(f"{k}={v}" for k, v in record.extra_fields.items())
            message += f" | {extras}"
        
        # Add exception info
        if record.exc_info:
            message += f"\n{self.COLORS['ERROR']}{self.formatException(record.exc_info)}{self.RESET}"
        
        return message


# ═══════════════════════════════════════════════════════════════
# Custom Logger
# ═══════════════════════════════════════════════════════════════

class RAGLOXLogger(logging.Logger):
    """
    Enhanced logger with structured logging support.
    
    Extends standard Logger with extra field support.
    """
    
    def _log(
        self,
        level: int,
        msg: object,
        args,
        exc_info=None,
        extra=None,
        stack_info: bool = False,
        stacklevel: int = 1,
        **kwargs
    ) -> None:
        """Override _log to support extra fields."""
        extra = extra or {}
        
        # Extract extra_fields from kwargs
        extra_fields = kwargs.pop('extra_fields', {})
        
        # Merge any remaining kwargs into extra_fields
        extra_fields.update(kwargs)
        
        if extra_fields:
            extra['extra_fields'] = extra_fields
        
        super()._log(
            level, msg, args, exc_info=exc_info, extra=extra,
            stack_info=stack_info, stacklevel=stacklevel + 1
        )
    
    def debug(self, msg: object, *args, **kwargs) -> None:
        """Log debug message with optional extra fields."""
        if self.isEnabledFor(logging.DEBUG):
            self._log(logging.DEBUG, msg, args, **kwargs)
    
    def info(self, msg: object, *args, **kwargs) -> None:
        """Log info message with optional extra fields."""
        if self.isEnabledFor(logging.INFO):
            self._log(logging.INFO, msg, args, **kwargs)
    
    def warning(self, msg: object, *args, **kwargs) -> None:
        """Log warning message with optional extra fields."""
        if self.isEnabledFor(logging.WARNING):
            self._log(logging.WARNING, msg, args, **kwargs)
    
    def error(self, msg: object, *args, **kwargs) -> None:
        """Log error message with optional extra fields."""
        if self.isEnabledFor(logging.ERROR):
            self._log(logging.ERROR, msg, args, **kwargs)
    
    def critical(self, msg: object, *args, **kwargs) -> None:
        """Log critical message with optional extra fields."""
        if self.isEnabledFor(logging.CRITICAL):
            self._log(logging.CRITICAL, msg, args, **kwargs)
    
    def exception(self, msg: object, *args, exc_info=True, **kwargs) -> None:
        """Log exception with traceback and optional extra fields."""
        self.error(msg, *args, exc_info=exc_info, **kwargs)


# ═══════════════════════════════════════════════════════════════
# Logger Factory
# ═══════════════════════════════════════════════════════════════

# Set our custom logger class as default
logging.setLoggerClass(RAGLOXLogger)

_configured = False


def configure_logging(
    log_level: Optional[str] = None,
    log_format: Optional[str] = None,
    log_file: Optional[str] = None
) -> None:
    """
    Configure logging for the application.
    
    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Output format ('json' or 'console')
        log_file: Optional file path for logging
    """
    global _configured
    
    if _configured:
        return
    
    settings = get_settings()
    
    level = getattr(logging, log_level or settings.log_level)
    format_type = log_format or settings.log_format
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    if format_type == 'json':
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ConsoleFormatter())
    
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)
    
    # Configure specific loggers
    _configure_library_loggers(level)
    
    _configured = True


def _configure_library_loggers(level: int) -> None:
    """Configure third-party library loggers."""
    # Reduce noise from verbose libraries
    logging.getLogger('uvicorn').setLevel(max(level, logging.INFO))
    logging.getLogger('uvicorn.access').setLevel(max(level, logging.WARNING))
    logging.getLogger('asyncio').setLevel(max(level, logging.WARNING))
    logging.getLogger('redis').setLevel(max(level, logging.WARNING))
    logging.getLogger('httpx').setLevel(max(level, logging.WARNING))


def get_logger(name: str) -> RAGLOXLogger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        RAGLOXLogger instance
    """
    configure_logging()
    return logging.getLogger(name)


# ═══════════════════════════════════════════════════════════════
# Decorators
# ═══════════════════════════════════════════════════════════════

T = TypeVar('T')


def log_function_call(
    logger: Optional[logging.Logger] = None,
    level: int = logging.DEBUG,
    include_args: bool = True,
    include_result: bool = True,
    include_timing: bool = True
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator to log function calls.
    
    Args:
        logger: Logger to use (default: creates one based on function module)
        level: Log level for messages
        include_args: Whether to log function arguments
        include_result: Whether to log function result
        include_timing: Whether to log execution time
        
    Usage:
        @log_function_call()
        def my_function(arg1, arg2):
            return result
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        nonlocal logger
        if logger is None:
            logger = get_logger(func.__module__)
        
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            func_name = func.__qualname__
            start_time = datetime.utcnow()
            
            # Log call
            extra = {'function': func_name}
            if include_args:
                extra['args'] = str(args)[:500]
                extra['kwargs'] = str(kwargs)[:500]
            
            logger.log(level, f"Calling {func_name}", extra_fields=extra)
            
            try:
                result = func(*args, **kwargs)
                
                # Log success
                extra = {'function': func_name, 'status': 'success'}
                if include_result and result is not None:
                    extra['result'] = str(result)[:500]
                if include_timing:
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
                    extra['elapsed_seconds'] = elapsed
                
                logger.log(level, f"Completed {func_name}", extra_fields=extra)
                
                return result
                
            except Exception as e:
                # Log failure
                extra = {
                    'function': func_name,
                    'status': 'error',
                    'error_type': type(e).__name__,
                    'error_message': str(e)
                }
                if include_timing:
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
                    extra['elapsed_seconds'] = elapsed
                
                logger.error(f"Error in {func_name}", exc_info=True, extra_fields=extra)
                raise
        
        return wrapper
    
    return decorator


def log_async_function_call(
    logger: Optional[logging.Logger] = None,
    level: int = logging.DEBUG,
    include_args: bool = True,
    include_result: bool = True,
    include_timing: bool = True
) -> Callable:
    """
    Decorator to log async function calls.
    
    Same as log_function_call but for async functions.
    """
    def decorator(func: Callable) -> Callable:
        nonlocal logger
        if logger is None:
            logger = get_logger(func.__module__)
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            func_name = func.__qualname__
            start_time = datetime.utcnow()
            
            # Log call
            extra = {'function': func_name}
            if include_args:
                extra['args'] = str(args)[:500]
                extra['kwargs'] = str(kwargs)[:500]
            
            logger.log(level, f"Calling {func_name}", extra_fields=extra)
            
            try:
                result = await func(*args, **kwargs)
                
                # Log success
                extra = {'function': func_name, 'status': 'success'}
                if include_result and result is not None:
                    extra['result'] = str(result)[:500]
                if include_timing:
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
                    extra['elapsed_seconds'] = elapsed
                
                logger.log(level, f"Completed {func_name}", extra_fields=extra)
                
                return result
                
            except Exception as e:
                # Log failure
                extra = {
                    'function': func_name,
                    'status': 'error',
                    'error_type': type(e).__name__,
                    'error_message': str(e)
                }
                if include_timing:
                    elapsed = (datetime.utcnow() - start_time).total_seconds()
                    extra['elapsed_seconds'] = elapsed
                
                logger.error(f"Error in {func_name}", exc_info=True, extra_fields=extra)
                raise
        
        return wrapper
    
    return decorator


# ═══════════════════════════════════════════════════════════════
# Audit Logging
# ═══════════════════════════════════════════════════════════════

class AuditLogger:
    """
    Specialized logger for security audit events.
    
    Records security-relevant events with additional context.
    """
    
    def __init__(self):
        self.logger = get_logger('raglox.audit')
    
    def log_authentication(
        self,
        user_id: Optional[str],
        success: bool,
        method: str = "password",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authentication attempt."""
        self.logger.info(
            f"Authentication {'succeeded' if success else 'failed'}",
            extra_fields={
                'audit_type': 'authentication',
                'user_id': user_id,
                'success': success,
                'method': method,
                'ip_address': ip_address,
                'user_agent': user_agent,
                **(details or {})
            }
        )
    
    def log_authorization(
        self,
        user_id: str,
        resource: str,
        action: str,
        granted: bool,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authorization check."""
        self.logger.info(
            f"Authorization {'granted' if granted else 'denied'}: {action} on {resource}",
            extra_fields={
                'audit_type': 'authorization',
                'user_id': user_id,
                'resource': resource,
                'action': action,
                'granted': granted,
                **(details or {})
            }
        )
    
    def log_mission_action(
        self,
        mission_id: str,
        action: str,
        user_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log mission-related action."""
        self.logger.info(
            f"Mission action: {action}",
            extra_fields={
                'audit_type': 'mission_action',
                'mission_id': mission_id,
                'action': action,
                'user_id': user_id,
                **(details or {})
            }
        )
    
    def log_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log data access event."""
        self.logger.info(
            f"Data access: {action} {resource_type}/{resource_id}",
            extra_fields={
                'audit_type': 'data_access',
                'user_id': user_id,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'action': action,
                **(details or {})
            }
        )
    
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log security event."""
        log_method = getattr(self.logger, severity.lower(), self.logger.warning)
        log_method(
            f"Security event: {message}",
            extra_fields={
                'audit_type': 'security_event',
                'event_type': event_type,
                'severity': severity,
                **(details or {})
            }
        )


# Singleton audit logger
audit_logger = AuditLogger()


# ═══════════════════════════════════════════════════════════════
# Performance Logging
# ═══════════════════════════════════════════════════════════════

class PerformanceLogger:
    """
    Logger for performance metrics.
    
    Records timing and resource usage information.
    """
    
    def __init__(self):
        self.logger = get_logger('raglox.performance')
    
    @contextmanager
    def measure(
        self,
        operation: str,
        threshold_seconds: Optional[float] = None,
        extra: Optional[Dict[str, Any]] = None
    ):
        """
        Context manager to measure operation timing.
        
        Args:
            operation: Name of the operation
            threshold_seconds: Log warning if exceeded
            extra: Additional context
            
        Usage:
            with performance_logger.measure("database_query"):
                result = db.query(...)
        """
        start = datetime.utcnow()
        
        try:
            yield
        finally:
            elapsed = (datetime.utcnow() - start).total_seconds()
            
            extra_fields = {
                'operation': operation,
                'elapsed_seconds': elapsed,
                **(extra or {})
            }
            
            if threshold_seconds and elapsed > threshold_seconds:
                self.logger.warning(
                    f"Slow operation: {operation} took {elapsed:.3f}s",
                    extra_fields=extra_fields
                )
            else:
                self.logger.debug(
                    f"Operation: {operation} completed in {elapsed:.3f}s",
                    extra_fields=extra_fields
                )
    
    def log_metric(
        self,
        metric_name: str,
        value: Union[int, float],
        unit: str = "",
        tags: Optional[Dict[str, str]] = None
    ) -> None:
        """Log a performance metric."""
        self.logger.info(
            f"Metric: {metric_name}={value}{unit}",
            extra_fields={
                'metric_type': 'gauge',
                'metric_name': metric_name,
                'metric_value': value,
                'metric_unit': unit,
                'tags': tags or {}
            }
        )


# Singleton performance logger
performance_logger = PerformanceLogger()
