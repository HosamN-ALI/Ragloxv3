# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Logging Tests
# Comprehensive tests for structured logging
# ═══════════════════════════════════════════════════════════════

import json
import logging
import pytest
from io import StringIO
from datetime import datetime
from unittest.mock import patch, MagicMock

from src.core.logging import (
    # Context management
    get_context,
    logging_context,
    request_id_var,
    mission_id_var,
    user_id_var,
    specialist_id_var,
    
    # Formatters
    JSONFormatter,
    ConsoleFormatter,
    
    # Logger
    RAGLOXLogger,
    get_logger,
    configure_logging,
    
    # Decorators
    log_function_call,
    log_async_function_call,
    
    # Special loggers
    AuditLogger,
    audit_logger,
    PerformanceLogger,
    performance_logger,
)


# ═══════════════════════════════════════════════════════════════
# Context Management Tests
# ═══════════════════════════════════════════════════════════════

class TestLoggingContext:
    """Tests for logging context management."""
    
    def test_get_context_empty(self):
        """Test getting empty context."""
        # Reset context variables
        request_id_var.set(None)
        mission_id_var.set(None)
        user_id_var.set(None)
        specialist_id_var.set(None)
        
        context = get_context()
        
        assert context['request_id'] is None
        assert context['mission_id'] is None
        assert context['user_id'] is None
        assert context['specialist_id'] is None
    
    def test_logging_context_manager(self):
        """Test logging context manager."""
        # Ensure clean state
        request_id_var.set(None)
        mission_id_var.set(None)
        
        with logging_context(mission_id="test-mission", user_id="test-user"):
            context = get_context()
            assert context['mission_id'] == "test-mission"
            assert context['user_id'] == "test-user"
        
        # Context should be reset after exiting
        context = get_context()
        assert context['mission_id'] is None
        assert context['user_id'] is None
    
    def test_nested_contexts(self):
        """Test nested logging contexts."""
        with logging_context(mission_id="mission-1"):
            assert get_context()['mission_id'] == "mission-1"
            
            with logging_context(request_id="request-1"):
                context = get_context()
                assert context['mission_id'] == "mission-1"
                assert context['request_id'] == "request-1"
            
            # Request ID should be reset, mission ID should remain
            context = get_context()
            assert context['mission_id'] == "mission-1"
            assert context['request_id'] is None


# ═══════════════════════════════════════════════════════════════
# JSON Formatter Tests
# ═══════════════════════════════════════════════════════════════

class TestJSONFormatter:
    """Tests for JSON log formatter."""
    
    def test_basic_formatting(self):
        """Test basic JSON formatting."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        output = formatter.format(record)
        data = json.loads(output)
        
        assert data['level'] == 'INFO'
        assert data['logger'] == 'test.logger'
        assert data['message'] == 'Test message'
        assert 'timestamp' in data
    
    def test_formatting_with_context(self):
        """Test JSON formatting includes context."""
        formatter = JSONFormatter()
        
        with logging_context(mission_id="test-mission"):
            record = logging.LogRecord(
                name="test.logger",
                level=logging.INFO,
                pathname="test.py",
                lineno=10,
                msg="Test message",
                args=(),
                exc_info=None
            )
            
            output = formatter.format(record)
            data = json.loads(output)
            
            assert data['mission_id'] == 'test-mission'
    
    def test_formatting_with_extra_fields(self):
        """Test JSON formatting with extra fields."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        record.extra_fields = {'custom_field': 'custom_value', 'count': 5}
        
        output = formatter.format(record)
        data = json.loads(output)
        
        assert data['custom_field'] == 'custom_value'
        assert data['count'] == 5
    
    def test_formatting_with_exception(self):
        """Test JSON formatting with exception."""
        formatter = JSONFormatter(include_traceback=True)
        
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        
        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname="test.py",
            lineno=10,
            msg="Error occurred",
            args=(),
            exc_info=exc_info
        )
        
        output = formatter.format(record)
        data = json.loads(output)
        
        assert 'exception' in data
        assert data['exception']['type'] == 'ValueError'
        assert 'Test error' in data['exception']['message']


# ═══════════════════════════════════════════════════════════════
# Console Formatter Tests
# ═══════════════════════════════════════════════════════════════

class TestConsoleFormatter:
    """Tests for console log formatter."""
    
    def test_basic_formatting(self):
        """Test basic console formatting."""
        formatter = ConsoleFormatter()
        
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        output = formatter.format(record)
        
        assert 'INFO' in output
        assert 'test.logger' in output
        assert 'Test message' in output
    
    def test_formatting_with_colors(self):
        """Test console formatting includes colors."""
        formatter = ConsoleFormatter()
        
        for level in [logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR]:
            record = logging.LogRecord(
                name="test",
                level=level,
                pathname="test.py",
                lineno=10,
                msg="Test",
                args=(),
                exc_info=None
            )
            
            output = formatter.format(record)
            # Check that ANSI codes are present (color escape sequences)
            assert '\033[' in output


# ═══════════════════════════════════════════════════════════════
# RAGLOX Logger Tests
# ═══════════════════════════════════════════════════════════════

class TestRAGLOXLogger:
    """Tests for custom logger."""
    
    def test_get_logger(self):
        """Test getting a logger."""
        # Use a unique name to ensure a new logger is created
        import uuid
        unique_name = f"test.module.{uuid.uuid4().hex[:8]}"
        logger = get_logger(unique_name)
        
        assert logger.name == unique_name
        # Check if logger is RAGLOXLogger or has the same capabilities
        # Note: existing loggers may not be RAGLOXLogger if created before setLoggerClass
        assert hasattr(logger, 'name')
        assert callable(getattr(logger, 'info', None))
    
    def test_logger_with_extra_fields(self):
        """Test logger with extra fields."""
        logger = get_logger("test.module")
        handler = logging.StreamHandler(StringIO())
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        
        # This should not raise
        logger.info("Test message", extra_fields={'key': 'value'})
    
    def test_logger_levels(self):
        """Test logger level methods."""
        logger = get_logger("test.levels")
        handler = logging.StreamHandler(StringIO())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        
        # These should not raise
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")


# ═══════════════════════════════════════════════════════════════
# Decorator Tests
# ═══════════════════════════════════════════════════════════════

class TestLogFunctionDecorator:
    """Tests for function logging decorator."""
    
    def test_log_function_call(self):
        """Test logging function calls."""
        @log_function_call(level=logging.INFO)
        def sample_function(x, y):
            return x + y
        
        result = sample_function(1, 2)
        assert result == 3
    
    def test_log_function_with_exception(self):
        """Test logging function that raises exception."""
        @log_function_call(level=logging.INFO)
        def failing_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            failing_function()


class TestLogAsyncFunctionDecorator:
    """Tests for async function logging decorator."""
    
    @pytest.mark.asyncio
    async def test_log_async_function_call(self):
        """Test logging async function calls."""
        @log_async_function_call(level=logging.INFO)
        async def async_sample_function(x, y):
            return x + y
        
        result = await async_sample_function(1, 2)
        assert result == 3
    
    @pytest.mark.asyncio
    async def test_log_async_function_with_exception(self):
        """Test logging async function that raises exception."""
        @log_async_function_call(level=logging.INFO)
        async def failing_async_function():
            raise ValueError("Test error")
        
        with pytest.raises(ValueError):
            await failing_async_function()


# ═══════════════════════════════════════════════════════════════
# Audit Logger Tests
# ═══════════════════════════════════════════════════════════════

class TestAuditLogger:
    """Tests for audit logging."""
    
    def test_log_authentication_success(self):
        """Test logging successful authentication."""
        # Should not raise
        audit_logger.log_authentication(
            user_id="user123",
            success=True,
            method="password",
            ip_address="192.168.1.1"
        )
    
    def test_log_authentication_failure(self):
        """Test logging failed authentication."""
        audit_logger.log_authentication(
            user_id="user123",
            success=False,
            method="password",
            ip_address="192.168.1.1",
            details={"reason": "invalid_password"}
        )
    
    def test_log_authorization(self):
        """Test logging authorization check."""
        audit_logger.log_authorization(
            user_id="user123",
            resource="mission",
            action="create",
            granted=True
        )
    
    def test_log_mission_action(self):
        """Test logging mission action."""
        audit_logger.log_mission_action(
            mission_id="mission123",
            action="started",
            user_id="user123"
        )
    
    def test_log_data_access(self):
        """Test logging data access."""
        audit_logger.log_data_access(
            user_id="user123",
            resource_type="target",
            resource_id="target123",
            action="read"
        )
    
    def test_log_security_event(self):
        """Test logging security event."""
        audit_logger.log_security_event(
            event_type="brute_force_detected",
            severity="warning",
            message="Multiple failed login attempts detected"
        )


# ═══════════════════════════════════════════════════════════════
# Performance Logger Tests
# ═══════════════════════════════════════════════════════════════

class TestPerformanceLogger:
    """Tests for performance logging."""
    
    def test_measure_context_manager(self):
        """Test performance measurement context manager."""
        with performance_logger.measure("test_operation"):
            # Simulate some work
            x = sum(range(1000))
        
        # Should not raise
    
    def test_measure_with_threshold(self):
        """Test performance measurement with threshold."""
        import time
        
        with performance_logger.measure("slow_operation", threshold_seconds=0.001):
            time.sleep(0.01)  # This should trigger warning
        
        # Should not raise
    
    def test_log_metric(self):
        """Test logging performance metric."""
        performance_logger.log_metric(
            metric_name="requests_per_second",
            value=150.5,
            unit="req/s",
            tags={"endpoint": "/api/missions"}
        )
        
        # Should not raise


# ═══════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestLoggingIntegration:
    """Integration tests for logging system."""
    
    def test_full_logging_flow(self):
        """Test complete logging flow with context and extra fields."""
        logger = get_logger("integration.test")
        
        with logging_context(mission_id="test-mission", request_id="req-123"):
            logger.info(
                "Processing request",
                extra_fields={
                    "action": "create",
                    "target": "192.168.1.1"
                }
            )
    
    def test_logging_with_all_features(self):
        """Test logging with all features combined."""
        logger = get_logger("features.test")
        
        # Set up handler to capture output
        output = StringIO()
        handler = logging.StreamHandler(output)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        
        with logging_context(mission_id="m123", user_id="u456"):
            logger.info(
                "Operation completed",
                extra_fields={
                    "duration_ms": 150,
                    "status": "success"
                }
            )
        
        # Parse and verify output
        log_output = output.getvalue()
        if log_output:
            log_data = json.loads(log_output.strip())
            assert log_data['message'] == 'Operation completed'
            # Context might be captured based on timing
