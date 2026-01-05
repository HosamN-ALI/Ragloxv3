# 🔧 SEC-01: Exception Handling Implementation Guide

**Task ID:** SEC-01  
**Priority:** 🔴 Critical  
**Estimated Effort:** 3 days  
**Document Version:** 1.0.0

---

## 📋 Overview

This guide provides step-by-step instructions for replacing generic `except Exception:` clauses with specific exception handling throughout the RAGLOX codebase.

### Why This Matters
- **Security:** Generic exceptions may leak sensitive information
- **Debugging:** Specific exceptions provide better error context
- **Reliability:** Proper handling prevents cascading failures
- **Observability:** Better logging and monitoring

---

## 🎯 Scope

### Files to Update (20 files, ~45 locations)

| Priority | File | Lines | Estimated Time |
|----------|------|-------|----------------|
| Critical | `src/core/blackboard.py` | 96 | 30 min |
| Critical | `src/specialists/attack.py` | 978 | 45 min |
| Critical | `src/specialists/recon.py` | 710 | 45 min |
| Critical | `src/api/websocket.py` | 74, 89 | 30 min |
| High | `src/core/transaction_manager.py` | 74 | 30 min |
| High | `src/executors/base.py` | 311, 541, 576 | 1 hour |
| High | `src/executors/winrm.py` | 614, 635, 658 | 1 hour |
| High | `src/executors/local.py` | 172 | 30 min |
| Medium | `src/core/llm/blackbox_provider.py` | 339, 361 | 30 min |
| Medium | `src/core/llm/local_provider.py` | 186, 206, 312, 326, 424, 459 | 1 hour |
| Medium | `src/core/scanners/nuclei.py` | 508 | 30 min |
| Medium | `src/core/intelligence_coordinator.py` | 495 | 30 min |
| Medium | `src/core/strategic_scorer.py` | 1043, 1058 | 30 min |
| Medium | `src/core/intel/file_provider.py` | 184, 383 | 30 min |
| Medium | `src/infrastructure/**/*.py` | Multiple | 2 hours |

---

## 📚 Exception Mapping Reference

### Network Operations
```python
# ❌ Before
except Exception as e:
    logger.error(f"Network error: {e}")

# ✅ After
except socket.timeout as e:
    logger.error(f"Connection timeout: {e}")
    raise NetworkTimeoutError(f"Connection timed out") from e
except ConnectionRefusedError as e:
    logger.error(f"Connection refused: {e}")
    raise ServiceUnavailableError(f"Service unavailable") from e
except socket.error as e:
    logger.error(f"Socket error: {e}")
    raise NetworkError(f"Network communication failed") from e
```

### Redis Operations
```python
# ❌ Before
except Exception as e:
    logger.error(f"Redis error: {e}")

# ✅ After
except redis.ConnectionError as e:
    logger.error(f"Redis connection failed: {e}")
    raise BlackboardConnectionError("Failed to connect to Blackboard") from e
except redis.TimeoutError as e:
    logger.error(f"Redis timeout: {e}")
    raise BlackboardTimeoutError("Blackboard operation timed out") from e
except redis.RedisError as e:
    logger.error(f"Redis error: {e}")
    raise BlackboardError(f"Blackboard operation failed") from e
```

### File Operations
```python
# ❌ Before
except Exception as e:
    logger.error(f"File error: {e}")

# ✅ After
except FileNotFoundError as e:
    logger.warning(f"File not found: {e.filename}")
    raise ConfigurationError(f"Required file not found: {e.filename}") from e
except PermissionError as e:
    logger.error(f"Permission denied: {e.filename}")
    raise SecurityError(f"Access denied to file: {e.filename}") from e
except IOError as e:
    logger.error(f"I/O error: {e}")
    raise StorageError(f"File operation failed") from e
```

### JSON Operations
```python
# ❌ Before
except Exception as e:
    logger.error(f"JSON error: {e}")

# ✅ After
except json.JSONDecodeError as e:
    logger.error(f"JSON decode error at line {e.lineno}: {e.msg}")
    raise DataValidationError(f"Invalid JSON format") from e
except TypeError as e:
    logger.error(f"JSON serialization error: {e}")
    raise DataValidationError(f"Data cannot be serialized to JSON") from e
```

### HTTP Client Operations
```python
# ❌ Before
except Exception as e:
    logger.error(f"HTTP error: {e}")

# ✅ After
except httpx.ConnectError as e:
    logger.error(f"HTTP connection failed: {e}")
    raise ExternalServiceError(f"Failed to connect to service") from e
except httpx.TimeoutException as e:
    logger.error(f"HTTP timeout: {e}")
    raise ExternalServiceTimeoutError(f"Service request timed out") from e
except httpx.HTTPStatusError as e:
    logger.error(f"HTTP {e.response.status_code}: {e}")
    raise ExternalServiceError(f"Service returned error: {e.response.status_code}") from e
```

### Metasploit Operations
```python
# ❌ Before
except Exception as e:
    logger.error(f"Metasploit error: {e}")

# ✅ After
except MetasploitConnectionError as e:
    logger.error(f"Metasploit connection failed: {e}")
    raise ExploitationServiceError("Metasploit service unavailable") from e
except MetasploitAuthenticationError as e:
    logger.error(f"Metasploit authentication failed: {e}")
    raise ExploitationConfigError("Invalid Metasploit credentials") from e
except MetasploitTimeoutError as e:
    logger.error(f"Metasploit timeout: {e}")
    raise ExploitationTimeoutError("Metasploit operation timed out") from e
except MetasploitRPCError as e:
    logger.error(f"Metasploit RPC error: {e}")
    raise ExploitationError(f"Metasploit operation failed") from e
```

---

## 🛠️ Implementation Steps

### Step 1: Create Custom Exceptions Module

Create or update `src/core/exceptions.py`:

```python
"""
RAGLOX v3.0 - Custom Exceptions
Enterprise-grade exception hierarchy for consistent error handling.
"""

from typing import Optional, Dict, Any


class RAGLOXBaseException(Exception):
    """Base exception for all RAGLOX errors."""
    
    def __init__(
        self,
        message: str,
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details
        }


# ════════════════════════════════════════════════════════════════
# Network Exceptions
# ════════════════════════════════════════════════════════════════

class NetworkError(RAGLOXBaseException):
    """Base exception for network-related errors."""
    pass


class NetworkTimeoutError(NetworkError):
    """Network operation timed out."""
    pass


class ServiceUnavailableError(NetworkError):
    """External service is unavailable."""
    pass


# ════════════════════════════════════════════════════════════════
# Blackboard (Redis) Exceptions
# ════════════════════════════════════════════════════════════════

class BlackboardError(RAGLOXBaseException):
    """Base exception for Blackboard operations."""
    pass


class BlackboardConnectionError(BlackboardError):
    """Failed to connect to Blackboard."""
    pass


class BlackboardTimeoutError(BlackboardError):
    """Blackboard operation timed out."""
    pass


# ════════════════════════════════════════════════════════════════
# Exploitation Exceptions
# ════════════════════════════════════════════════════════════════

class ExploitationError(RAGLOXBaseException):
    """Base exception for exploitation operations."""
    pass


class ExploitationServiceError(ExploitationError):
    """Exploitation service unavailable."""
    pass


class ExploitationTimeoutError(ExploitationError):
    """Exploitation operation timed out."""
    pass


class ExploitationConfigError(ExploitationError):
    """Invalid exploitation configuration."""
    pass


# ════════════════════════════════════════════════════════════════
# Data Validation Exceptions
# ════════════════════════════════════════════════════════════════

class DataValidationError(RAGLOXBaseException):
    """Data validation failed."""
    pass


class ConfigurationError(RAGLOXBaseException):
    """Configuration error."""
    pass


# ════════════════════════════════════════════════════════════════
# Security Exceptions
# ════════════════════════════════════════════════════════════════

class SecurityError(RAGLOXBaseException):
    """Security-related error."""
    pass


class AuthenticationError(SecurityError):
    """Authentication failed."""
    pass


class AuthorizationError(SecurityError):
    """Authorization failed."""
    pass


# ════════════════════════════════════════════════════════════════
# External Service Exceptions
# ════════════════════════════════════════════════════════════════

class ExternalServiceError(RAGLOXBaseException):
    """External service error."""
    pass


class ExternalServiceTimeoutError(ExternalServiceError):
    """External service timed out."""
    pass


class LLMServiceError(ExternalServiceError):
    """LLM service error."""
    pass


# ════════════════════════════════════════════════════════════════
# Storage Exceptions
# ════════════════════════════════════════════════════════════════

class StorageError(RAGLOXBaseException):
    """Storage operation failed."""
    pass
```

### Step 2: Update Error Sanitization Utility

Create `src/core/utils/error_sanitizer.py`:

```python
"""
Error sanitization utilities.
Prevents sensitive information leakage in error messages.
"""

import re
from typing import Any


# Patterns to sanitize
SENSITIVE_PATTERNS = [
    (r'password[=:]\s*\S+', 'password=***'),
    (r'secret[=:]\s*\S+', 'secret=***'),
    (r'api[_-]?key[=:]\s*\S+', 'api_key=***'),
    (r'token[=:]\s*\S+', 'token=***'),
    (r'bearer\s+\S+', 'Bearer ***'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***'),
    (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '***.***.***.***'),
]


def sanitize_error(error: Any) -> str:
    """
    Sanitize error message to remove sensitive information.
    
    Args:
        error: Error object or string
        
    Returns:
        Sanitized error string
    """
    error_str = str(error)
    
    for pattern, replacement in SENSITIVE_PATTERNS:
        error_str = re.sub(pattern, replacement, error_str, flags=re.IGNORECASE)
    
    return error_str


def sanitize_for_logging(data: dict) -> dict:
    """
    Sanitize dictionary for logging.
    
    Args:
        data: Dictionary to sanitize
        
    Returns:
        Sanitized dictionary
    """
    sensitive_keys = {'password', 'secret', 'api_key', 'token', 'credential'}
    
    result = {}
    for key, value in data.items():
        if any(s in key.lower() for s in sensitive_keys):
            result[key] = '***'
        elif isinstance(value, dict):
            result[key] = sanitize_for_logging(value)
        else:
            result[key] = value
    
    return result
```

### Step 3: Update Individual Files

#### Example: `src/core/blackboard.py`

```python
# ❌ Before (line 96)
async def health_check(self) -> bool:
    if not self._redis:
        return False
    try:
        await self._redis.ping()
        return True
    except Exception:
        return False

# ✅ After
async def health_check(self) -> bool:
    """Check if Redis connection is healthy."""
    if not self._redis:
        return False
    try:
        await self._redis.ping()
        return True
    except redis.ConnectionError as e:
        self.logger.warning(f"Redis connection check failed: {e}")
        return False
    except redis.TimeoutError as e:
        self.logger.warning(f"Redis health check timed out: {e}")
        return False
    except redis.RedisError as e:
        self.logger.error(f"Redis health check error: {sanitize_error(e)}")
        return False
```

#### Example: `src/api/websocket.py`

```python
# ❌ Before (lines 74, 89)
try:
    await websocket.send_json(message)
except Exception as e:
    logger.error(f"WebSocket error: {e}")

# ✅ After
try:
    await websocket.send_json(message)
except WebSocketDisconnect:
    logger.info(f"WebSocket disconnected: {client_id}")
    await self._cleanup_client(client_id)
except ConnectionResetError as e:
    logger.warning(f"WebSocket connection reset: {client_id}")
    await self._cleanup_client(client_id)
except Exception as e:
    logger.error(f"WebSocket error for {client_id}: {sanitize_error(e)}")
    await self._cleanup_client(client_id)
    raise
```

---

## ✅ Verification Checklist

For each updated file:

- [ ] All `except Exception:` replaced with specific exceptions
- [ ] Custom exceptions imported from `src/core/exceptions.py`
- [ ] Error messages sanitized using `sanitize_error()`
- [ ] Logging includes context (correlation ID, operation type)
- [ ] Re-raising with `from e` to preserve stack trace
- [ ] Unit tests added for error scenarios
- [ ] No sensitive data in error messages

---

## 🧪 Testing Requirements

### Unit Tests

```python
# tests/core/test_exceptions.py
import pytest
from src.core.exceptions import *


class TestExceptionHierarchy:
    def test_base_exception(self):
        exc = RAGLOXBaseException("test", code="TEST_ERROR")
        assert exc.message == "test"
        assert exc.code == "TEST_ERROR"
    
    def test_exception_to_dict(self):
        exc = NetworkTimeoutError("Connection timed out")
        result = exc.to_dict()
        assert result["error"] == "NetworkTimeoutError"
        assert "timed out" in result["message"]
    
    def test_exception_inheritance(self):
        exc = BlackboardConnectionError("Failed")
        assert isinstance(exc, BlackboardError)
        assert isinstance(exc, RAGLOXBaseException)


class TestErrorSanitization:
    def test_sanitize_password(self):
        from src.core.utils.error_sanitizer import sanitize_error
        error = "Connection failed: password=secret123"
        result = sanitize_error(error)
        assert "secret123" not in result
        assert "password=***" in result
```

### Integration Tests

```python
# tests/integration/test_error_handling.py
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_api_error_response_sanitized(client: AsyncClient):
    """Verify API error responses don't leak sensitive info."""
    response = await client.post(
        "/api/v1/missions",
        json={"invalid": "data"}
    )
    assert response.status_code == 422
    body = response.json()
    assert "password" not in str(body).lower()
    assert "secret" not in str(body).lower()
```

---

## 📊 Progress Tracking

| File | Status | Reviewer | Notes |
|------|--------|----------|-------|
| `src/core/blackboard.py` | ⬜ | - | |
| `src/specialists/attack.py` | ⬜ | - | |
| `src/specialists/recon.py` | ⬜ | - | |
| `src/api/websocket.py` | ⬜ | - | |
| `src/core/transaction_manager.py` | ⬜ | - | |
| `src/executors/base.py` | ⬜ | - | |
| `src/executors/winrm.py` | ⬜ | - | |
| `src/executors/local.py` | ⬜ | - | |
| ... | ... | ... | ... |

---

## 📝 Code Review Checklist

- [ ] All changes follow the exception mapping guide
- [ ] No `except Exception:` without a comment explaining why
- [ ] Error messages are user-friendly and actionable
- [ ] Sensitive data is sanitized
- [ ] Logging is at appropriate levels
- [ ] Tests cover error scenarios
- [ ] Documentation updated if needed

---

**Document End**
