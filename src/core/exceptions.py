# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Custom Exceptions
# Centralized exception handling for the entire application
# ═══════════════════════════════════════════════════════════════

from typing import Any, Dict, Optional


class RAGLOXException(Exception):
    """
    Base exception for all RAGLOX errors.
    
    All custom exceptions inherit from this class to enable
    unified error handling throughout the application.
    
    Attributes:
        message: Human-readable error message
        error_code: Machine-readable error code
        details: Additional error details
        original_error: Original exception if wrapping another error
    """
    
    def __init__(
        self,
        message: str,
        error_code: str = "RAGLOX_ERROR",
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.original_error = original_error
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "error": True,
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
        }
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(code={self.error_code}, message='{self.message}')"


# ═══════════════════════════════════════════════════════════════
# Connection Exceptions
# ═══════════════════════════════════════════════════════════════

class ConnectionException(RAGLOXException):
    """Base exception for connection-related errors."""
    
    def __init__(
        self,
        message: str,
        service: str = "unknown",
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.service = service
        super().__init__(
            message=message,
            error_code=f"CONNECTION_ERROR_{service.upper()}",
            details={"service": service, **(details or {})},
            original_error=original_error
        )


class RedisConnectionError(ConnectionException):
    """Redis connection failure."""
    
    def __init__(
        self,
        message: str = "Failed to connect to Redis",
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=message,
            service="redis",
            details=details,
            original_error=original_error
        )


class DatabaseConnectionError(ConnectionException):
    """PostgreSQL connection failure."""
    
    def __init__(
        self,
        message: str = "Failed to connect to database",
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=message,
            service="postgresql",
            details=details,
            original_error=original_error
        )


class BlackboardNotConnectedError(ConnectionException):
    """Blackboard is not connected."""
    
    def __init__(
        self,
        message: str = "Blackboard is not connected. Call connect() first.",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            service="blackboard",
            details=details
        )


# ═══════════════════════════════════════════════════════════════
# Mission Exceptions
# ═══════════════════════════════════════════════════════════════

class MissionException(RAGLOXException):
    """Base exception for mission-related errors."""
    
    def __init__(
        self,
        message: str,
        mission_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.mission_id = mission_id
        super().__init__(
            message=message,
            error_code="MISSION_ERROR",
            details={"mission_id": mission_id, **(details or {})},
            original_error=original_error
        )


class MissionNotFoundError(MissionException):
    """Mission was not found."""
    
    def __init__(
        self,
        mission_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Mission not found: {mission_id}",
            mission_id=mission_id,
            details=details
        )
        self.error_code = "MISSION_NOT_FOUND"


class MissionAlreadyExistsError(MissionException):
    """Mission already exists."""
    
    def __init__(
        self,
        mission_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Mission already exists: {mission_id}",
            mission_id=mission_id,
            details=details
        )
        self.error_code = "MISSION_ALREADY_EXISTS"


class InvalidMissionStateError(MissionException):
    """Mission is in an invalid state for the requested operation."""
    
    def __init__(
        self,
        mission_id: str,
        current_state: str,
        required_states: list,
        operation: str = "unknown",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Cannot {operation} mission {mission_id}: "
                    f"current state is '{current_state}', "
                    f"required states: {required_states}",
            mission_id=mission_id,
            details={
                "current_state": current_state,
                "required_states": required_states,
                "operation": operation,
                **(details or {})
            }
        )
        self.error_code = "INVALID_MISSION_STATE"
        self.current_state = current_state
        self.required_states = required_states
        self.operation = operation


class MissionLimitExceededError(MissionException):
    """Maximum concurrent missions limit exceeded."""
    
    def __init__(
        self,
        current_count: int,
        max_limit: int,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Maximum concurrent missions limit exceeded: "
                    f"{current_count}/{max_limit}",
            details={
                "current_count": current_count,
                "max_limit": max_limit,
                **(details or {})
            }
        )
        self.error_code = "MISSION_LIMIT_EXCEEDED"
        self.current_count = current_count
        self.max_limit = max_limit


# ═══════════════════════════════════════════════════════════════
# Target Exceptions
# ═══════════════════════════════════════════════════════════════

class TargetException(RAGLOXException):
    """Base exception for target-related errors."""
    
    def __init__(
        self,
        message: str,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.target_id = target_id
        super().__init__(
            message=message,
            error_code="TARGET_ERROR",
            details={"target_id": target_id, **(details or {})},
            original_error=original_error
        )


class TargetNotFoundError(TargetException):
    """Target was not found."""
    
    def __init__(
        self,
        target_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Target not found: {target_id}",
            target_id=target_id,
            details=details
        )
        self.error_code = "TARGET_NOT_FOUND"


class InvalidTargetError(TargetException):
    """Target data is invalid."""
    
    def __init__(
        self,
        message: str,
        target_id: Optional[str] = None,
        validation_errors: Optional[list] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            target_id=target_id,
            details={
                "validation_errors": validation_errors or [],
                **(details or {})
            }
        )
        self.error_code = "INVALID_TARGET"
        self.validation_errors = validation_errors or []


class TargetOutOfScopeError(TargetException):
    """Target is outside the mission scope."""
    
    def __init__(
        self,
        target_ip: str,
        mission_scope: list,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Target {target_ip} is outside mission scope",
            details={
                "target_ip": target_ip,
                "mission_scope": mission_scope,
                **(details or {})
            }
        )
        self.error_code = "TARGET_OUT_OF_SCOPE"
        self.target_ip = target_ip
        self.mission_scope = mission_scope


# ═══════════════════════════════════════════════════════════════
# Task Exceptions
# ═══════════════════════════════════════════════════════════════

class TaskException(RAGLOXException):
    """Base exception for task-related errors."""
    
    def __init__(
        self,
        message: str,
        task_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.task_id = task_id
        super().__init__(
            message=message,
            error_code="TASK_ERROR",
            details={"task_id": task_id, **(details or {})},
            original_error=original_error
        )


class TaskNotFoundError(TaskException):
    """Task was not found."""
    
    def __init__(
        self,
        task_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Task not found: {task_id}",
            task_id=task_id,
            details=details
        )
        self.error_code = "TASK_NOT_FOUND"


class TaskExecutionError(TaskException):
    """Task execution failed."""
    
    def __init__(
        self,
        task_id: str,
        message: str = "Task execution failed",
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"{message}: {task_id}",
            task_id=task_id,
            details=details,
            original_error=original_error
        )
        self.error_code = "TASK_EXECUTION_ERROR"


class TaskTimeoutError(TaskException):
    """Task execution timed out."""
    
    def __init__(
        self,
        task_id: str,
        timeout_seconds: int,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Task {task_id} timed out after {timeout_seconds}s",
            task_id=task_id,
            details={
                "timeout_seconds": timeout_seconds,
                **(details or {})
            }
        )
        self.error_code = "TASK_TIMEOUT"
        self.timeout_seconds = timeout_seconds


class NoTasksAvailableError(TaskException):
    """No tasks available for the specialist."""
    
    def __init__(
        self,
        specialist_type: str,
        mission_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"No tasks available for {specialist_type} in mission {mission_id}",
            details={
                "specialist_type": specialist_type,
                "mission_id": mission_id,
                **(details or {})
            }
        )
        self.error_code = "NO_TASKS_AVAILABLE"
        self.specialist_type = specialist_type
        self.mission_id = mission_id


# ═══════════════════════════════════════════════════════════════
# Specialist Exceptions
# ═══════════════════════════════════════════════════════════════

class SpecialistException(RAGLOXException):
    """Base exception for specialist-related errors."""
    
    def __init__(
        self,
        message: str,
        specialist_id: Optional[str] = None,
        specialist_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.specialist_id = specialist_id
        self.specialist_type = specialist_type
        super().__init__(
            message=message,
            error_code="SPECIALIST_ERROR",
            details={
                "specialist_id": specialist_id,
                "specialist_type": specialist_type,
                **(details or {})
            },
            original_error=original_error
        )


class SpecialistNotRunningError(SpecialistException):
    """Specialist is not running."""
    
    def __init__(
        self,
        specialist_id: str,
        specialist_type: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Specialist {specialist_id} ({specialist_type}) is not running",
            specialist_id=specialist_id,
            specialist_type=specialist_type,
            details=details
        )
        self.error_code = "SPECIALIST_NOT_RUNNING"


class UnsupportedTaskTypeError(SpecialistException):
    """Specialist does not support the task type."""
    
    def __init__(
        self,
        specialist_type: str,
        task_type: str,
        supported_types: list,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Specialist {specialist_type} does not support task type {task_type}",
            specialist_type=specialist_type,
            details={
                "task_type": task_type,
                "supported_types": supported_types,
                **(details or {})
            }
        )
        self.error_code = "UNSUPPORTED_TASK_TYPE"
        self.task_type = task_type
        self.supported_types = supported_types


# ═══════════════════════════════════════════════════════════════
# Validation Exceptions
# ═══════════════════════════════════════════════════════════════

class ValidationException(RAGLOXException):
    """Base exception for validation errors."""
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Any = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.field = field
        self.value = value
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            details={
                "field": field,
                "value": str(value) if value is not None else None,
                **(details or {})
            }
        )


class InvalidIPAddressError(ValidationException):
    """Invalid IP address format."""
    
    def __init__(
        self,
        ip: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Invalid IP address: {ip}",
            field="ip",
            value=ip,
            details=details
        )
        self.error_code = "INVALID_IP_ADDRESS"


class InvalidCIDRError(ValidationException):
    """Invalid CIDR notation."""
    
    def __init__(
        self,
        cidr: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Invalid CIDR notation: {cidr}",
            field="cidr",
            value=cidr,
            details=details
        )
        self.error_code = "INVALID_CIDR"


class InvalidUUIDError(ValidationException):
    """Invalid UUID format."""
    
    def __init__(
        self,
        uuid_str: str,
        field: str = "id",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Invalid UUID: {uuid_str}",
            field=field,
            value=uuid_str,
            details=details
        )
        self.error_code = "INVALID_UUID"


class MissingRequiredFieldError(ValidationException):
    """Required field is missing."""
    
    def __init__(
        self,
        field: str,
        entity: str = "entity",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Missing required field '{field}' for {entity}",
            field=field,
            details={"entity": entity, **(details or {})}
        )
        self.error_code = "MISSING_REQUIRED_FIELD"
        self.entity = entity


# ═══════════════════════════════════════════════════════════════
# Security Exceptions
# ═══════════════════════════════════════════════════════════════

class SecurityException(RAGLOXException):
    """Base exception for security-related errors."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=message,
            error_code="SECURITY_ERROR",
            details=details,
            original_error=original_error
        )


class AuthenticationError(SecurityException):
    """Authentication failed."""
    
    def __init__(
        self,
        message: str = "Authentication failed",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            details=details
        )
        self.error_code = "AUTHENTICATION_ERROR"


class AuthorizationError(SecurityException):
    """Authorization failed - insufficient permissions."""
    
    def __init__(
        self,
        message: str = "Insufficient permissions",
        required_permission: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            details={
                "required_permission": required_permission,
                **(details or {})
            }
        )
        self.error_code = "AUTHORIZATION_ERROR"
        self.required_permission = required_permission


class RateLimitExceededError(SecurityException):
    """Rate limit exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            details={
                "retry_after_seconds": retry_after,
                **(details or {})
            }
        )
        self.error_code = "RATE_LIMIT_EXCEEDED"
        self.retry_after = retry_after


# ═══════════════════════════════════════════════════════════════
# API Exceptions
# ═══════════════════════════════════════════════════════════════

class APIException(RAGLOXException):
    """Base exception for API-related errors."""
    
    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.status_code = status_code
        super().__init__(
            message=message,
            error_code="API_ERROR",
            details={"status_code": status_code, **(details or {})},
            original_error=original_error
        )


class BadRequestError(APIException):
    """Bad request - invalid input."""
    
    def __init__(
        self,
        message: str = "Bad request",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            status_code=400,
            details=details
        )
        self.error_code = "BAD_REQUEST"


class NotFoundError(APIException):
    """Resource not found."""
    
    def __init__(
        self,
        resource: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"{resource} not found: {resource_id}",
            status_code=404,
            details={
                "resource": resource,
                "resource_id": resource_id,
                **(details or {})
            }
        )
        self.error_code = "NOT_FOUND"
        self.resource = resource
        self.resource_id = resource_id


class ConflictError(APIException):
    """Resource conflict."""
    
    def __init__(
        self,
        message: str = "Resource conflict",
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=message,
            status_code=409,
            details=details
        )
        self.error_code = "CONFLICT"


class InternalServerError(APIException):
    """Internal server error."""
    
    def __init__(
        self,
        message: str = "Internal server error",
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=message,
            status_code=500,
            details=details,
            original_error=original_error
        )
        self.error_code = "INTERNAL_SERVER_ERROR"


# ═══════════════════════════════════════════════════════════════
# Network & External Service Exceptions
# ═══════════════════════════════════════════════════════════════

class NetworkException(RAGLOXException):
    """Base exception for network-related errors."""
    
    def __init__(
        self,
        message: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.host = host
        self.port = port
        super().__init__(
            message=message,
            error_code="NETWORK_ERROR",
            details={
                "host": host,
                "port": port,
                **(details or {})
            },
            original_error=original_error
        )


class ConnectionTimeoutError(NetworkException):
    """Connection timed out."""
    
    def __init__(
        self,
        host: str,
        port: int,
        timeout_seconds: float,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Connection to {host}:{port} timed out after {timeout_seconds}s",
            host=host,
            port=port,
            details={"timeout_seconds": timeout_seconds, **(details or {})},
            original_error=original_error
        )
        self.error_code = "CONNECTION_TIMEOUT"
        self.timeout_seconds = timeout_seconds


class ServiceUnavailableError(NetworkException):
    """External service is unavailable."""
    
    def __init__(
        self,
        service_name: str,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=message or f"Service '{service_name}' is unavailable",
            details={"service_name": service_name, **(details or {})},
            original_error=original_error
        )
        self.error_code = "SERVICE_UNAVAILABLE"
        self.service_name = service_name


class ExternalAPIError(NetworkException):
    """Error from external API."""
    
    def __init__(
        self,
        api_name: str,
        status_code: Optional[int] = None,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=message or f"External API '{api_name}' returned an error",
            details={
                "api_name": api_name,
                "status_code": status_code,
                **(details or {})
            },
            original_error=original_error
        )
        self.error_code = "EXTERNAL_API_ERROR"
        self.api_name = api_name
        self.status_code = status_code


# ═══════════════════════════════════════════════════════════════
# Exploitation Exceptions
# ═══════════════════════════════════════════════════════════════

class ExploitationException(RAGLOXException):
    """Base exception for exploitation-related errors."""
    
    def __init__(
        self,
        message: str,
        exploit_id: Optional[str] = None,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.exploit_id = exploit_id
        self.target_id = target_id
        super().__init__(
            message=message,
            error_code="EXPLOITATION_ERROR",
            details={
                "exploit_id": exploit_id,
                "target_id": target_id,
                **(details or {})
            },
            original_error=original_error
        )


class ExploitNotFoundError(ExploitationException):
    """Exploit not found in repository."""
    
    def __init__(
        self,
        exploit_id: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Exploit not found: {exploit_id}",
            exploit_id=exploit_id,
            details=details
        )
        self.error_code = "EXPLOIT_NOT_FOUND"


class ExploitExecutionError(ExploitationException):
    """Exploit execution failed."""
    
    def __init__(
        self,
        exploit_id: str,
        target_id: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Exploit {exploit_id} failed on target {target_id}: {reason}",
            exploit_id=exploit_id,
            target_id=target_id,
            details={"reason": reason, **(details or {})},
            original_error=original_error
        )
        self.error_code = "EXPLOIT_EXECUTION_ERROR"
        self.reason = reason


class SessionCreationError(ExploitationException):
    """Failed to create C2 session."""
    
    def __init__(
        self,
        target_id: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Failed to create session for target {target_id}: {reason}",
            target_id=target_id,
            details={"reason": reason, **(details or {})},
            original_error=original_error
        )
        self.error_code = "SESSION_CREATION_ERROR"
        self.reason = reason


class PayloadGenerationError(ExploitationException):
    """Failed to generate payload."""
    
    def __init__(
        self,
        payload_type: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Failed to generate {payload_type} payload: {reason}",
            details={"payload_type": payload_type, "reason": reason, **(details or {})},
            original_error=original_error
        )
        self.error_code = "PAYLOAD_GENERATION_ERROR"
        self.payload_type = payload_type
        self.reason = reason


# ═══════════════════════════════════════════════════════════════
# Configuration Exceptions
# ═══════════════════════════════════════════════════════════════

class ConfigurationException(RAGLOXException):
    """Base exception for configuration errors."""
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.config_key = config_key
        super().__init__(
            message=message,
            error_code="CONFIGURATION_ERROR",
            details={"config_key": config_key, **(details or {})}
        )


class MissingConfigurationError(ConfigurationException):
    """Required configuration is missing."""
    
    def __init__(
        self,
        config_key: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Missing required configuration: {config_key}",
            config_key=config_key,
            details=details
        )
        self.error_code = "MISSING_CONFIGURATION"


class InvalidConfigurationError(ConfigurationException):
    """Configuration value is invalid."""
    
    def __init__(
        self,
        config_key: str,
        value: Any,
        expected: str,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Invalid configuration for '{config_key}': expected {expected}, got {type(value).__name__}",
            config_key=config_key,
            details={"value": str(value), "expected": expected, **(details or {})}
        )
        self.error_code = "INVALID_CONFIGURATION"
        self.value = value
        self.expected = expected


# ═══════════════════════════════════════════════════════════════
# File Operation Exceptions
# ═══════════════════════════════════════════════════════════════

class FileOperationException(RAGLOXException):
    """Base exception for file operation errors."""
    
    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        operation: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.file_path = file_path
        self.operation = operation
        super().__init__(
            message=message,
            error_code="FILE_OPERATION_ERROR",
            details={
                "file_path": file_path,
                "operation": operation,
                **(details or {})
            },
            original_error=original_error
        )


class FileReadError(FileOperationException):
    """Failed to read file."""
    
    def __init__(
        self,
        file_path: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Failed to read file '{file_path}': {reason}",
            file_path=file_path,
            operation="read",
            details={"reason": reason, **(details or {})},
            original_error=original_error
        )
        self.error_code = "FILE_READ_ERROR"
        self.reason = reason


class FileWriteError(FileOperationException):
    """Failed to write file."""
    
    def __init__(
        self,
        file_path: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Failed to write file '{file_path}': {reason}",
            file_path=file_path,
            operation="write",
            details={"reason": reason, **(details or {})},
            original_error=original_error
        )
        self.error_code = "FILE_WRITE_ERROR"
        self.reason = reason


# ═══════════════════════════════════════════════════════════════
# LLM Exceptions
# ═══════════════════════════════════════════════════════════════

class LLMException(RAGLOXException):
    """Base exception for LLM-related errors."""
    
    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.provider = provider
        self.model = model
        super().__init__(
            message=message,
            error_code="LLM_ERROR",
            details={
                "provider": provider,
                "model": model,
                **(details or {})
            },
            original_error=original_error
        )


class LLMRateLimitError(LLMException):
    """LLM rate limit exceeded."""
    
    def __init__(
        self,
        provider: str,
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"LLM rate limit exceeded for provider '{provider}'",
            provider=provider,
            details={"retry_after_seconds": retry_after, **(details or {})},
            original_error=original_error
        )
        self.error_code = "LLM_RATE_LIMIT"
        self.retry_after = retry_after


class LLMResponseError(LLMException):
    """Invalid or unexpected LLM response."""
    
    def __init__(
        self,
        provider: str,
        model: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Invalid response from LLM '{provider}/{model}': {reason}",
            provider=provider,
            model=model,
            details={"reason": reason, **(details or {})},
            original_error=original_error
        )
        self.error_code = "LLM_RESPONSE_ERROR"
        self.reason = reason


# ═══════════════════════════════════════════════════════════════
# Data Parsing Exceptions
# ═══════════════════════════════════════════════════════════════

class DataParsingException(RAGLOXException):
    """Base exception for data parsing errors."""
    
    def __init__(
        self,
        message: str,
        data_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        self.data_type = data_type
        super().__init__(
            message=message,
            error_code="DATA_PARSING_ERROR",
            details={"data_type": data_type, **(details or {})},
            original_error=original_error
        )


class JSONParsingError(DataParsingException):
    """Failed to parse JSON data."""
    
    def __init__(
        self,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            message=f"Failed to parse JSON: {reason}",
            data_type="json",
            details={"reason": reason, **(details or {})},
            original_error=original_error
        )
        self.error_code = "JSON_PARSING_ERROR"
        self.reason = reason


class SchemaValidationError(DataParsingException):
    """Data schema validation failed."""
    
    def __init__(
        self,
        schema_name: str,
        validation_errors: list,
        details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            message=f"Schema validation failed for '{schema_name}'",
            data_type="schema",
            details={
                "schema_name": schema_name,
                "validation_errors": validation_errors,
                **(details or {})
            }
        )
        self.error_code = "SCHEMA_VALIDATION_ERROR"
        self.schema_name = schema_name
        self.validation_errors = validation_errors


# ═══════════════════════════════════════════════════════════════
# Utility Functions
# ═══════════════════════════════════════════════════════════════

def wrap_exception(
    original: Exception,
    message: Optional[str] = None
) -> RAGLOXException:
    """
    Wrap a standard exception in a RAGLOX exception.
    
    Args:
        original: The original exception
        message: Optional custom message
        
    Returns:
        A RAGLOXException wrapping the original
    """
    return RAGLOXException(
        message=message or str(original),
        error_code="WRAPPED_ERROR",
        details={"original_type": type(original).__name__},
        original_error=original
    )


def sanitize_error_message(error: Exception) -> str:
    """
    Sanitize error message to remove sensitive information.
    
    Args:
        error: The exception to sanitize
        
    Returns:
        Sanitized error message
    """
    import re
    
    message = str(error)
    
    # Patterns to mask
    patterns = [
        (r'password["\']?\s*[:=]\s*["\']?[^\s"\']+', 'password=***'),
        (r'secret["\']?\s*[:=]\s*["\']?[^\s"\']+', 'secret=***'),
        (r'api_key["\']?\s*[:=]\s*["\']?[^\s"\']+', 'api_key=***'),
        (r'token["\']?\s*[:=]\s*["\']?[^\s"\']+', 'token=***'),
        (r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'Bearer ***'),
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '***@***.***'),
    ]
    
    for pattern, replacement in patterns:
        message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)
    
    return message


def get_exception_for_status_code(status_code: int, message: str = "") -> APIException:
    """
    Get appropriate API exception for HTTP status code.
    
    Args:
        status_code: HTTP status code
        message: Error message
        
    Returns:
        Appropriate APIException subclass
    """
    exceptions = {
        400: BadRequestError,
        401: AuthenticationError,
        403: AuthorizationError,
        404: lambda m: NotFoundError("resource", "unknown"),
        409: ConflictError,
        429: lambda m: RateLimitExceededError(m),
        500: InternalServerError,
        503: lambda m: ServiceUnavailableError("unknown", m),
    }
    
    exception_class = exceptions.get(status_code, InternalServerError)
    if callable(exception_class):
        return exception_class(message)
    return exception_class(message)
