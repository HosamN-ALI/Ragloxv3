# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Exception Tests
# Comprehensive tests for custom exceptions
# ═══════════════════════════════════════════════════════════════

import pytest

from src.core.exceptions import (
    # Base
    RAGLOXException,
    wrap_exception,
    
    # Connection
    ConnectionException,
    RedisConnectionError,
    DatabaseConnectionError,
    BlackboardNotConnectedError,
    
    # Mission
    MissionException,
    MissionNotFoundError,
    MissionAlreadyExistsError,
    InvalidMissionStateError,
    MissionLimitExceededError,
    
    # Target
    TargetException,
    TargetNotFoundError,
    InvalidTargetError,
    TargetOutOfScopeError,
    
    # Task
    TaskException,
    TaskNotFoundError,
    TaskExecutionError,
    TaskTimeoutError,
    NoTasksAvailableError,
    
    # Specialist
    SpecialistException,
    SpecialistNotRunningError,
    UnsupportedTaskTypeError,
    
    # Validation
    ValidationException,
    InvalidIPAddressError,
    InvalidCIDRError,
    InvalidUUIDError,
    MissingRequiredFieldError,
    
    # Security
    SecurityException,
    AuthenticationError,
    AuthorizationError,
    RateLimitExceededError,
    
    # API
    APIException,
    BadRequestError,
    NotFoundError,
    ConflictError,
    InternalServerError,
)


# ═══════════════════════════════════════════════════════════════
# Base Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestRAGLOXException:
    """Tests for base RAGLOX exception."""
    
    def test_basic_creation(self):
        """Test basic exception creation."""
        exc = RAGLOXException("Test error")
        assert exc.message == "Test error"
        assert exc.error_code == "RAGLOX_ERROR"
        assert exc.details == {}
        assert exc.original_error is None
    
    def test_with_error_code(self):
        """Test exception with custom error code."""
        exc = RAGLOXException("Test error", error_code="CUSTOM_CODE")
        assert exc.error_code == "CUSTOM_CODE"
    
    def test_with_details(self):
        """Test exception with details."""
        details = {"field": "value", "count": 5}
        exc = RAGLOXException("Test error", details=details)
        assert exc.details == details
    
    def test_with_original_error(self):
        """Test exception wrapping another exception."""
        original = ValueError("Original error")
        exc = RAGLOXException("Wrapped error", original_error=original)
        assert exc.original_error is original
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        exc = RAGLOXException(
            "Test error",
            error_code="TEST_CODE",
            details={"key": "value"}
        )
        d = exc.to_dict()
        
        assert d["error"] is True
        assert d["error_code"] == "TEST_CODE"
        assert d["message"] == "Test error"
        assert d["details"] == {"key": "value"}
    
    def test_repr(self):
        """Test string representation."""
        exc = RAGLOXException("Test error", error_code="TEST_CODE")
        assert "RAGLOXException" in repr(exc)
        assert "TEST_CODE" in repr(exc)
    
    def test_str(self):
        """Test string conversion."""
        exc = RAGLOXException("Test error message")
        assert str(exc) == "Test error message"


class TestWrapException:
    """Tests for wrap_exception utility."""
    
    def test_wrap_standard_exception(self):
        """Test wrapping a standard exception."""
        original = ValueError("Invalid value")
        wrapped = wrap_exception(original)
        
        assert isinstance(wrapped, RAGLOXException)
        assert wrapped.original_error is original
        assert "Invalid value" in wrapped.message
        assert wrapped.error_code == "WRAPPED_ERROR"
    
    def test_wrap_with_custom_message(self):
        """Test wrapping with custom message."""
        original = ValueError("Invalid value")
        wrapped = wrap_exception(original, "Custom message")
        
        assert wrapped.message == "Custom message"


# ═══════════════════════════════════════════════════════════════
# Connection Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestConnectionExceptions:
    """Tests for connection-related exceptions."""
    
    def test_redis_connection_error(self):
        """Test Redis connection error."""
        exc = RedisConnectionError()
        assert "Redis" in exc.message
        assert "CONNECTION_ERROR_REDIS" in exc.error_code
        assert exc.service == "redis"
    
    def test_redis_connection_error_custom_message(self):
        """Test Redis connection error with custom message."""
        exc = RedisConnectionError("Custom Redis error")
        assert exc.message == "Custom Redis error"
    
    def test_database_connection_error(self):
        """Test database connection error."""
        exc = DatabaseConnectionError()
        assert "database" in exc.message.lower()
        assert "CONNECTION_ERROR_POSTGRESQL" in exc.error_code
    
    def test_blackboard_not_connected(self):
        """Test blackboard not connected error."""
        exc = BlackboardNotConnectedError()
        assert "not connected" in exc.message.lower()
        assert "connect()" in exc.message


# ═══════════════════════════════════════════════════════════════
# Mission Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestMissionExceptions:
    """Tests for mission-related exceptions."""
    
    def test_mission_not_found(self):
        """Test mission not found error."""
        exc = MissionNotFoundError("abc123")
        assert exc.mission_id == "abc123"
        assert "abc123" in exc.message
        assert exc.error_code == "MISSION_NOT_FOUND"
    
    def test_mission_already_exists(self):
        """Test mission already exists error."""
        exc = MissionAlreadyExistsError("abc123")
        assert exc.mission_id == "abc123"
        assert exc.error_code == "MISSION_ALREADY_EXISTS"
    
    def test_invalid_mission_state(self):
        """Test invalid mission state error."""
        exc = InvalidMissionStateError(
            mission_id="abc123",
            current_state="completed",
            required_states=["created", "paused"],
            operation="start"
        )
        assert exc.current_state == "completed"
        assert exc.required_states == ["created", "paused"]
        assert exc.operation == "start"
        assert "start" in exc.message
        assert "completed" in exc.message
    
    def test_mission_limit_exceeded(self):
        """Test mission limit exceeded error."""
        exc = MissionLimitExceededError(current_count=5, max_limit=5)
        assert exc.current_count == 5
        assert exc.max_limit == 5
        assert "5/5" in exc.message


# ═══════════════════════════════════════════════════════════════
# Target Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestTargetExceptions:
    """Tests for target-related exceptions."""
    
    def test_target_not_found(self):
        """Test target not found error."""
        exc = TargetNotFoundError("target123")
        assert exc.target_id == "target123"
        assert exc.error_code == "TARGET_NOT_FOUND"
    
    def test_invalid_target(self):
        """Test invalid target error."""
        exc = InvalidTargetError(
            message="Invalid IP address",
            target_id="target123",
            validation_errors=["invalid_ip", "missing_hostname"]
        )
        assert exc.validation_errors == ["invalid_ip", "missing_hostname"]
    
    def test_target_out_of_scope(self):
        """Test target out of scope error."""
        exc = TargetOutOfScopeError(
            target_ip="10.0.0.1",
            mission_scope=["192.168.1.0/24", "192.168.2.0/24"]
        )
        assert exc.target_ip == "10.0.0.1"
        assert exc.mission_scope == ["192.168.1.0/24", "192.168.2.0/24"]


# ═══════════════════════════════════════════════════════════════
# Task Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestTaskExceptions:
    """Tests for task-related exceptions."""
    
    def test_task_not_found(self):
        """Test task not found error."""
        exc = TaskNotFoundError("task123")
        assert exc.task_id == "task123"
        assert exc.error_code == "TASK_NOT_FOUND"
    
    def test_task_execution_error(self):
        """Test task execution error."""
        exc = TaskExecutionError("task123", "Module failed to load")
        assert exc.task_id == "task123"
        assert "task123" in exc.message
    
    def test_task_timeout(self):
        """Test task timeout error."""
        exc = TaskTimeoutError("task123", timeout_seconds=60)
        assert exc.timeout_seconds == 60
        assert "60" in exc.message
    
    def test_no_tasks_available(self):
        """Test no tasks available error."""
        exc = NoTasksAvailableError(specialist_type="recon", mission_id="mission123")
        assert exc.specialist_type == "recon"
        assert exc.mission_id == "mission123"


# ═══════════════════════════════════════════════════════════════
# Specialist Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestSpecialistExceptions:
    """Tests for specialist-related exceptions."""
    
    def test_specialist_not_running(self):
        """Test specialist not running error."""
        exc = SpecialistNotRunningError(
            specialist_id="recon-abc123",
            specialist_type="recon"
        )
        assert exc.specialist_id == "recon-abc123"
        assert exc.specialist_type == "recon"
    
    def test_unsupported_task_type(self):
        """Test unsupported task type error."""
        exc = UnsupportedTaskTypeError(
            specialist_type="recon",
            task_type="exploit",
            supported_types=["network_scan", "port_scan"]
        )
        assert exc.task_type == "exploit"
        assert exc.supported_types == ["network_scan", "port_scan"]


# ═══════════════════════════════════════════════════════════════
# Validation Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestValidationExceptions:
    """Tests for validation-related exceptions."""
    
    def test_invalid_ip_address(self):
        """Test invalid IP address error."""
        exc = InvalidIPAddressError("not.an.ip")
        assert exc.field == "ip"
        assert "not.an.ip" in exc.message
    
    def test_invalid_cidr(self):
        """Test invalid CIDR error."""
        exc = InvalidCIDRError("192.168.1.0/99")
        assert exc.field == "cidr"
        assert "192.168.1.0/99" in exc.message
    
    def test_invalid_uuid(self):
        """Test invalid UUID error."""
        exc = InvalidUUIDError("not-a-uuid", field="mission_id")
        assert exc.field == "mission_id"
        assert "not-a-uuid" in exc.message
    
    def test_missing_required_field(self):
        """Test missing required field error."""
        exc = MissingRequiredFieldError(field="name", entity="mission")
        assert exc.field == "name"
        assert exc.entity == "mission"
        assert "name" in exc.message


# ═══════════════════════════════════════════════════════════════
# Security Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestSecurityExceptions:
    """Tests for security-related exceptions."""
    
    def test_authentication_error(self):
        """Test authentication error."""
        exc = AuthenticationError()
        assert exc.error_code == "AUTHENTICATION_ERROR"
    
    def test_authorization_error(self):
        """Test authorization error."""
        exc = AuthorizationError(
            message="Cannot access resource",
            required_permission="admin"
        )
        assert exc.required_permission == "admin"
    
    def test_rate_limit_exceeded(self):
        """Test rate limit exceeded error."""
        exc = RateLimitExceededError(retry_after=60)
        assert exc.retry_after == 60
        assert exc.details.get("retry_after_seconds") == 60


# ═══════════════════════════════════════════════════════════════
# API Exception Tests
# ═══════════════════════════════════════════════════════════════

class TestAPIExceptions:
    """Tests for API-related exceptions."""
    
    def test_bad_request(self):
        """Test bad request error."""
        exc = BadRequestError("Invalid input format")
        assert exc.status_code == 400
        assert exc.error_code == "BAD_REQUEST"
    
    def test_not_found(self):
        """Test not found error."""
        exc = NotFoundError(resource="Mission", resource_id="abc123")
        assert exc.status_code == 404
        assert exc.resource == "Mission"
        assert exc.resource_id == "abc123"
    
    def test_conflict(self):
        """Test conflict error."""
        exc = ConflictError("Resource already exists")
        assert exc.status_code == 409
    
    def test_internal_server_error(self):
        """Test internal server error."""
        original = RuntimeError("Database connection failed")
        exc = InternalServerError(
            message="An unexpected error occurred",
            original_error=original
        )
        assert exc.status_code == 500
        assert exc.original_error is original


# ═══════════════════════════════════════════════════════════════
# Exception Inheritance Tests
# ═══════════════════════════════════════════════════════════════

class TestExceptionInheritance:
    """Tests for exception inheritance chain."""
    
    def test_all_inherit_from_base(self):
        """Test that all exceptions inherit from RAGLOXException."""
        exceptions = [
            RedisConnectionError(),
            MissionNotFoundError("id"),
            TargetNotFoundError("id"),
            TaskNotFoundError("id"),
            SpecialistNotRunningError("id", "type"),
            InvalidIPAddressError("ip"),
            AuthenticationError(),
            BadRequestError(),
        ]
        
        for exc in exceptions:
            assert isinstance(exc, RAGLOXException)
            assert isinstance(exc, Exception)
    
    def test_can_catch_by_category(self):
        """Test catching exceptions by category."""
        # Connection errors
        with pytest.raises(ConnectionException):
            raise RedisConnectionError()
        
        # Mission errors
        with pytest.raises(MissionException):
            raise MissionNotFoundError("id")
        
        # Validation errors
        with pytest.raises(ValidationException):
            raise InvalidIPAddressError("ip")
        
        # API errors
        with pytest.raises(APIException):
            raise NotFoundError("resource", "id")
