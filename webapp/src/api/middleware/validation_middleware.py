# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Validation Middleware (SEC-03)
# FastAPI middleware for input validation
# ═══════════════════════════════════════════════════════════════

"""
SEC-03: Input Validation Middleware

This middleware provides:
- Automatic input validation for all requests
- XSS protection
- SQL injection detection
- Command injection detection
- Path traversal detection
- Content-Type validation
- Request size limiting

Integration with FastAPI:
```python
from src.api.middleware import create_validation_middleware

app = FastAPI()
app.add_middleware(create_validation_middleware())
```
"""

from typing import Optional, Dict, Any, Callable, List, Set
import re
import json
import logging
from datetime import datetime

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════
# Validation Patterns
# ═══════════════════════════════════════════════════════════════

# Command injection patterns
CMD_INJECTION_PATTERNS = [
    re.compile(r'[;|&`$()]'),  # Shell metacharacters
    re.compile(r'\$\{.*\}'),  # Variable expansion
    re.compile(r'\$\(.*\)'),  # Command substitution
    re.compile(r'`.*`'),  # Backtick execution
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r'\.\.[/\\]'),  # Parent directory
    re.compile(r'[/\\]\.\.[/\\]'),  # Mid-path traversal
    re.compile(r'^[/\\]etc[/\\]'),  # Unix system files
    re.compile(r'^[/\\]proc[/\\]'),  # Unix proc
    re.compile(r'^[A-Za-z]:[/\\]'),  # Windows paths
]

# SQL injection patterns (basic detection)
SQL_INJECTION_PATTERNS = [
    re.compile(r"'.*OR.*'", re.IGNORECASE),
    re.compile(r"'.*AND.*'", re.IGNORECASE),
    re.compile(r"'.*UNION.*SELECT", re.IGNORECASE),
    re.compile(r"'.*DROP\s+TABLE", re.IGNORECASE),
    re.compile(r"'.*DELETE\s+FROM", re.IGNORECASE),
    re.compile(r"'.*INSERT\s+INTO", re.IGNORECASE),
    re.compile(r"'.*UPDATE.*SET", re.IGNORECASE),
    re.compile(r"--.*$"),  # SQL comments
    re.compile(r"/\*.*\*/"),  # Block comments
]

# XSS patterns
XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),  # Event handlers
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"<object[^>]*>", re.IGNORECASE),
    re.compile(r"<embed[^>]*>", re.IGNORECASE),
    re.compile(r"<svg[^>]*onload", re.IGNORECASE),
    re.compile(r"expression\s*\(", re.IGNORECASE),  # CSS expression
]

# Dangerous content types
BLOCKED_CONTENT_TYPES = [
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
]

# Allowed content types for POST/PUT/PATCH
ALLOWED_CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
]


class ValidationResult:
    """Result of validation check."""
    
    def __init__(
        self,
        valid: bool,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.valid = valid
        self.error_type = error_type
        self.error_message = error_message
        self.details = details or {}


class InputValidator:
    """
    Input validation engine.
    
    Checks for various injection and attack patterns.
    """
    
    def __init__(
        self,
        check_xss: bool = True,
        check_sql: bool = True,
        check_command: bool = True,
        check_path: bool = True,
        max_body_size: int = 10 * 1024 * 1024,  # 10MB
        max_param_length: int = 10000,
    ):
        self.check_xss = check_xss
        self.check_sql = check_sql
        self.check_command = check_command
        self.check_path = check_path
        self.max_body_size = max_body_size
        self.max_param_length = max_param_length
        
        # Statistics
        self.stats = {
            "total_validated": 0,
            "blocked": 0,
            "by_type": {
                "xss": 0,
                "sql_injection": 0,
                "command_injection": 0,
                "path_traversal": 0,
                "size_exceeded": 0,
                "invalid_content_type": 0,
            },
            "recent_blocks": [],
        }
    
    def validate_string(self, value: str, field_name: str = "input") -> ValidationResult:
        """
        Validate a string for injection patterns.
        
        Args:
            value: String to validate
            field_name: Name of the field for error messages
            
        Returns:
            ValidationResult
        """
        if not value:
            return ValidationResult(valid=True)
        
        # Check length
        if len(value) > self.max_param_length:
            return ValidationResult(
                valid=False,
                error_type="size_exceeded",
                error_message=f"{field_name} exceeds maximum length of {self.max_param_length}",
                details={"length": len(value), "max_length": self.max_param_length},
            )
        
        # Check XSS
        if self.check_xss:
            for pattern in XSS_PATTERNS:
                if pattern.search(value):
                    return ValidationResult(
                        valid=False,
                        error_type="xss",
                        error_message=f"Potential XSS detected in {field_name}",
                        details={"pattern": pattern.pattern},
                    )
        
        # Check SQL injection
        if self.check_sql:
            for pattern in SQL_INJECTION_PATTERNS:
                if pattern.search(value):
                    return ValidationResult(
                        valid=False,
                        error_type="sql_injection",
                        error_message=f"Potential SQL injection detected in {field_name}",
                        details={"pattern": pattern.pattern},
                    )
        
        # Check command injection
        if self.check_command:
            for pattern in CMD_INJECTION_PATTERNS:
                if pattern.search(value):
                    return ValidationResult(
                        valid=False,
                        error_type="command_injection",
                        error_message=f"Potential command injection detected in {field_name}",
                        details={"pattern": pattern.pattern},
                    )
        
        # Check path traversal
        if self.check_path:
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(value):
                    return ValidationResult(
                        valid=False,
                        error_type="path_traversal",
                        error_message=f"Potential path traversal detected in {field_name}",
                        details={"pattern": pattern.pattern},
                    )
        
        return ValidationResult(valid=True)
    
    def validate_dict(self, data: Dict[str, Any], prefix: str = "") -> ValidationResult:
        """
        Recursively validate a dictionary.
        
        Args:
            data: Dictionary to validate
            prefix: Key prefix for nested values
            
        Returns:
            ValidationResult
        """
        for key, value in data.items():
            field_name = f"{prefix}.{key}" if prefix else key
            
            # Validate key
            key_result = self.validate_string(key, f"key:{field_name}")
            if not key_result.valid:
                return key_result
            
            # Validate value
            if isinstance(value, str):
                result = self.validate_string(value, field_name)
                if not result.valid:
                    return result
            elif isinstance(value, dict):
                result = self.validate_dict(value, field_name)
                if not result.valid:
                    return result
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        result = self.validate_string(item, f"{field_name}[{i}]")
                        if not result.valid:
                            return result
                    elif isinstance(item, dict):
                        result = self.validate_dict(item, f"{field_name}[{i}]")
                        if not result.valid:
                            return result
        
        return ValidationResult(valid=True)
    
    def validate_content_type(
        self,
        content_type: Optional[str],
        method: str,
    ) -> ValidationResult:
        """
        Validate content type for request.
        
        Args:
            content_type: Content-Type header value
            method: HTTP method
            
        Returns:
            ValidationResult
        """
        if method not in ("POST", "PUT", "PATCH"):
            return ValidationResult(valid=True)
        
        if not content_type:
            return ValidationResult(
                valid=False,
                error_type="invalid_content_type",
                error_message="Content-Type header is required for this request",
            )
        
        # Extract base content type (without charset, etc.)
        base_type = content_type.split(";")[0].strip().lower()
        
        # Check if blocked
        for blocked in BLOCKED_CONTENT_TYPES:
            if base_type == blocked:
                return ValidationResult(
                    valid=False,
                    error_type="invalid_content_type",
                    error_message=f"Content type '{base_type}' is not allowed",
                )
        
        # Check if allowed
        allowed = any(
            base_type.startswith(allowed_type.split(";")[0])
            for allowed_type in ALLOWED_CONTENT_TYPES
        )
        
        if not allowed:
            return ValidationResult(
                valid=False,
                error_type="invalid_content_type",
                error_message=f"Content type '{base_type}' is not supported",
                details={"allowed_types": ALLOWED_CONTENT_TYPES},
            )
        
        return ValidationResult(valid=True)
    
    def record_block(self, error_type: str, request_info: Dict[str, Any]):
        """Record a blocked request."""
        self.stats["blocked"] += 1
        self.stats["by_type"][error_type] = self.stats["by_type"].get(error_type, 0) + 1
        
        # Keep last 100 blocks
        self.stats["recent_blocks"].append({
            "type": error_type,
            "timestamp": datetime.utcnow().isoformat(),
            "request": request_info,
        })
        if len(self.stats["recent_blocks"]) > 100:
            self.stats["recent_blocks"] = self.stats["recent_blocks"][-100:]


class ValidationMiddleware(BaseHTTPMiddleware):
    """
    Input validation middleware for FastAPI.
    
    SEC-03 Implementation:
    - XSS protection
    - SQL injection detection
    - Command injection detection
    - Path traversal detection
    - Content-Type validation
    - Request size limiting
    """
    
    def __init__(
        self,
        app: ASGIApp,
        check_xss: bool = True,
        check_sql: bool = True,
        check_command: bool = True,
        check_path: bool = True,
        max_body_size: int = 10 * 1024 * 1024,
        max_param_length: int = 10000,
        whitelist_paths: Optional[List[str]] = None,
        enabled: bool = True,
    ):
        """
        Initialize validation middleware.
        
        Args:
            app: ASGI application
            check_xss: Enable XSS detection
            check_sql: Enable SQL injection detection
            check_command: Enable command injection detection
            check_path: Enable path traversal detection
            max_body_size: Maximum request body size in bytes
            max_param_length: Maximum parameter length
            whitelist_paths: Paths to skip validation
            enabled: Whether validation is enabled
        """
        super().__init__(app)
        self.validator = InputValidator(
            check_xss=check_xss,
            check_sql=check_sql,
            check_command=check_command,
            check_path=check_path,
            max_body_size=max_body_size,
            max_param_length=max_param_length,
        )
        self.whitelist_paths = whitelist_paths or [
            "/docs",
            "/redoc",
            "/openapi.json",
            "/health",
        ]
        self.enabled = enabled
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request with validation."""
        if not self.enabled:
            return await call_next(request)
        
        path = request.url.path
        
        # Skip whitelisted paths
        for whitelisted in self.whitelist_paths:
            if path.startswith(whitelisted):
                return await call_next(request)
        
        self.validator.stats["total_validated"] += 1
        
        # Get request info for logging
        request_info = {
            "method": request.method,
            "path": path,
            "client": request.client.host if request.client else "unknown",
        }
        
        # Validate content type
        content_type = request.headers.get("content-type")
        ct_result = self.validator.validate_content_type(content_type, request.method)
        if not ct_result.valid:
            self.validator.record_block("invalid_content_type", request_info)
            return self._error_response(ct_result)
        
        # Validate query parameters
        for key, value in request.query_params.items():
            result = self.validator.validate_string(value, f"query:{key}")
            if not result.valid:
                self.validator.record_block(result.error_type, {
                    **request_info,
                    "param": key,
                })
                return self._error_response(result)
        
        # Validate path parameters (from URL)
        result = self.validator.validate_string(path, "path")
        if not result.valid:
            self.validator.record_block(result.error_type, request_info)
            return self._error_response(result)
        
        # Validate request body for JSON requests
        if request.method in ("POST", "PUT", "PATCH"):
            if content_type and "application/json" in content_type:
                try:
                    # Check body size first
                    content_length = request.headers.get("content-length")
                    if content_length:
                        if int(content_length) > self.validator.max_body_size:
                            self.validator.record_block("size_exceeded", request_info)
                            return self._error_response(ValidationResult(
                                valid=False,
                                error_type="size_exceeded",
                                error_message=f"Request body exceeds maximum size of {self.validator.max_body_size} bytes",
                            ))
                    
                    # Parse and validate body
                    body = await request.body()
                    if body:
                        try:
                            data = json.loads(body)
                            if isinstance(data, dict):
                                result = self.validator.validate_dict(data)
                                if not result.valid:
                                    self.validator.record_block(result.error_type, request_info)
                                    return self._error_response(result)
                        except json.JSONDecodeError:
                            pass  # Let FastAPI handle JSON errors
                        
                except Exception as e:
                    logger.warning(f"Error validating request body: {e}")
        
        return await call_next(request)
    
    def _error_response(self, result: ValidationResult) -> Response:
        """Create error response for validation failure."""
        return JSONResponse(
            status_code=400,
            content={
                "error": "Validation failed",
                "type": result.error_type,
                "message": result.error_message,
                "details": result.details,
            },
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return self.validator.stats


def create_validation_middleware(
    check_xss: bool = True,
    check_sql: bool = True,
    check_command: bool = True,
    check_path: bool = True,
    max_body_size: int = 10 * 1024 * 1024,
    enabled: bool = True,
) -> type:
    """
    Create a validation middleware class with configuration.
    
    Usage:
    ```python
    app.add_middleware(
        create_validation_middleware(
            check_xss=True,
            check_sql=True,
            enabled=True
        )
    )
    ```
    """
    class ConfiguredValidationMiddleware(ValidationMiddleware):
        def __init__(self, app: ASGIApp):
            super().__init__(
                app,
                check_xss=check_xss,
                check_sql=check_sql,
                check_command=check_command,
                check_path=check_path,
                max_body_size=max_body_size,
                enabled=enabled,
            )
    
    return ConfiguredValidationMiddleware
