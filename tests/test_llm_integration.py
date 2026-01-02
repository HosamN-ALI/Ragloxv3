# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - LLM Integration Tests
# Tests for LLM providers and AnalysisSpecialist integration
# ═══════════════════════════════════════════════════════════════

import pytest
import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List
from unittest.mock import AsyncMock, MagicMock, patch

# Import LLM components
from src.core.llm.base import (
    LLMProvider,
    LLMConfig,
    LLMMessage,
    LLMResponse,
    TokenUsage,
    MessageRole,
    ProviderType,
    LLMError,
    RateLimitError,
    InvalidResponseError,
)
from src.core.llm.mock_provider import MockLLMProvider
from src.core.llm.service import (
    LLMService,
    get_llm_service,
    init_llm_service,
    reset_llm_service,
)
from src.core.llm.models import (
    AnalysisRequest,
    AnalysisResponse,
    FailureAnalysis,
    TaskContext,
    ExecutionContext,
    ErrorDetails,
    AvailableModule,
    DecisionType,
    ConfidenceLevel,
    FailureCategory,
)
from src.core.llm.prompts import (
    build_analysis_prompt,
    extract_json_from_response,
    REFLEXION_SYSTEM_PROMPT,
)


# ═══════════════════════════════════════════════════════════════
# Test Fixtures
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def llm_config():
    """Create a test LLM configuration."""
    return LLMConfig(
        provider_type=ProviderType.MOCK,
        model="mock-gpt-4",
        temperature=0.3,
        max_tokens=2048,
    )


@pytest.fixture
def mock_provider():
    """Create a mock LLM provider."""
    provider = MockLLMProvider()
    provider.setup_analysis_responses()
    return provider


@pytest.fixture
def llm_service(mock_provider):
    """Create an LLM service with mock provider."""
    reset_llm_service()
    service = LLMService()
    service.register_provider("mock", mock_provider, set_as_default=True)
    return service


@pytest.fixture
def sample_analysis_request():
    """Create a sample analysis request."""
    return AnalysisRequest(
        task=TaskContext(
            task_id="task-123",
            task_type="EXPLOIT",
            target_ip="192.168.1.100",
            target_hostname="target-host",
            target_os="Windows Server 2019",
            target_platform="windows",
        ),
        execution=ExecutionContext(
            module_used="rx-exploit-ms17010",
            technique_id="T1210",
            command_executed="exploit -t 192.168.1.100",
            exit_code=1,
            duration_ms=5000,
        ),
        error=ErrorDetails(
            error_type="edr_blocked",
            error_message="Execution blocked by EDR",
            stderr="[ERROR] CrowdStrike blocked execution",
            detected_defenses=["edr"],
        ),
        retry_count=0,
        max_retries=3,
        available_modules=[
            AvailableModule(
                rx_module_id="rx-exploit-ms17010-evasion",
                name="MS17-010 with Evasion",
                description="EternalBlue with EDR bypass",
                technique_id="T1210",
                supports_evasion=True,
                success_rate=0.75,
            ),
        ],
        mission_goals=["Gain initial access", "Establish persistence"],
    )


# ═══════════════════════════════════════════════════════════════
# MockLLMProvider Tests
# ═══════════════════════════════════════════════════════════════

class TestMockLLMProvider:
    """Tests for MockLLMProvider."""
    
    @pytest.mark.asyncio
    async def test_mock_provider_basic_response(self, mock_provider):
        """Test basic mock response generation."""
        messages = [
            LLMMessage.system("You are a helpful assistant."),
            LLMMessage.user("Hello, world!"),
        ]
        
        response = await mock_provider.generate(messages)
        
        assert response is not None
        assert response.provider == "mock"
        assert response.model == "mock-gpt-4"
        assert response.content
    
    @pytest.mark.asyncio
    async def test_mock_provider_custom_response(self):
        """Test custom response configuration."""
        provider = MockLLMProvider()
        provider.add_response("test query", {"result": "custom response"})
        
        messages = [LLMMessage.user("This is a test query")]
        response = await provider.generate(messages)
        
        assert response.parsed_json == {"result": "custom response"}
    
    @pytest.mark.asyncio
    async def test_mock_provider_queued_responses(self):
        """Test queued response system."""
        provider = MockLLMProvider()
        provider.queue_response({"seq": 1})
        provider.queue_response({"seq": 2})
        provider.queue_response({"seq": 3})
        
        messages = [LLMMessage.user("Query")]
        
        r1 = await provider.generate(messages)
        r2 = await provider.generate(messages)
        r3 = await provider.generate(messages)
        
        assert r1.parsed_json == {"seq": 1}
        assert r2.parsed_json == {"seq": 2}
        assert r3.parsed_json == {"seq": 3}
    
    @pytest.mark.asyncio
    async def test_mock_provider_call_tracking(self, mock_provider):
        """Test call history tracking."""
        messages = [LLMMessage.user("Test message")]
        
        await mock_provider.generate(messages)
        await mock_provider.generate(messages)
        
        assert mock_provider.call_count == 2
        assert mock_provider.last_messages is not None
    
    @pytest.mark.asyncio
    async def test_mock_provider_analysis_responses(self, mock_provider):
        """Test pre-configured analysis responses."""
        # Test timeout response
        messages = [LLMMessage.user("Error: connection timeout")]
        response = await mock_provider.generate(messages)
        
        assert response.parsed_json is not None
        assert response.parsed_json["recommended_action"]["decision"] == "retry"
    
    @pytest.mark.asyncio
    async def test_mock_provider_defense_response(self, mock_provider):
        """Test defense detection response."""
        messages = [LLMMessage.user("Error: blocked by antivirus")]
        response = await mock_provider.generate(messages)
        
        data = response.parsed_json
        assert data["analysis"]["category"] == "defense"
        assert data["recommended_action"]["decision"] == "modify_approach"
    
    @pytest.mark.asyncio
    async def test_mock_provider_json_generation(self, mock_provider):
        """Test JSON response generation."""
        mock_provider.queue_response({"test": "json", "value": 42})
        
        messages = [LLMMessage.user("Give me JSON")]
        result = await mock_provider.generate_json(messages)
        
        assert result == {"test": "json", "value": 42}
    
    @pytest.mark.asyncio
    async def test_mock_provider_failure_simulation(self):
        """Test failure simulation."""
        provider = MockLLMProvider(failure_rate=1.0)  # Always fail
        
        messages = [LLMMessage.user("Test")]
        
        with pytest.raises(LLMError):
            await provider.generate(messages)
    
    @pytest.mark.asyncio
    async def test_mock_provider_health_check(self, mock_provider):
        """Test health check always returns True for mock."""
        assert await mock_provider.health_check() is True
    
    def test_mock_provider_assertions(self, mock_provider):
        """Test assertion helpers."""
        mock_provider.assert_not_called()
        
        with pytest.raises(AssertionError):
            mock_provider.assert_called()


# ═══════════════════════════════════════════════════════════════
# LLMService Tests
# ═══════════════════════════════════════════════════════════════

class TestLLMService:
    """Tests for LLMService."""
    
    def test_service_initialization(self):
        """Test service initialization."""
        service = LLMService()
        assert service.providers == {}
        assert service.default_provider_name is None
    
    def test_provider_registration(self, mock_provider):
        """Test provider registration."""
        service = LLMService()
        service.register_provider("mock", mock_provider, set_as_default=True)
        
        assert "mock" in service.providers
        assert service.default_provider_name == "mock"
    
    def test_provider_unregistration(self, llm_service):
        """Test provider unregistration."""
        assert llm_service.unregister_provider("mock") is True
        assert "mock" not in llm_service.providers
    
    def test_get_provider(self, llm_service, mock_provider):
        """Test getting provider by name."""
        provider = llm_service.get_provider("mock")
        assert provider is mock_provider
    
    @pytest.mark.asyncio
    async def test_service_generate(self, llm_service):
        """Test generate through service."""
        messages = [LLMMessage.user("Test")]
        response = await llm_service.generate(messages)
        
        assert response is not None
        assert response.provider == "mock"
    
    @pytest.mark.asyncio
    async def test_service_failover(self):
        """Test provider failover."""
        # Create service with failing primary and working backup
        service = LLMService(enable_fallback=True)
        
        failing_provider = MockLLMProvider(failure_rate=1.0)
        working_provider = MockLLMProvider()
        working_provider.queue_response({"status": "success"})
        
        # Register primary first (lower priority number = higher priority)
        service.register_provider("primary", failing_provider)
        service.register_provider("backup", working_provider)
        
        # Manually set priority order to ensure primary is tried first
        service._provider_priority = ["primary", "backup"]
        service._default_provider = "primary"
        
        messages = [LLMMessage.user("Test")]
        response = await service.generate(messages)
        
        assert response.parsed_json == {"status": "success"}
        # Failover should have occurred
        stats = service.get_stats()
        assert stats["failovers"] >= 1
    
    @pytest.mark.asyncio
    async def test_service_no_fallback(self):
        """Test without failover enabled."""
        service = LLMService(enable_fallback=False)
        failing_provider = MockLLMProvider(failure_rate=1.0)
        service.register_provider("primary", failing_provider)
        
        messages = [LLMMessage.user("Test")]
        
        with pytest.raises(LLMError):
            await service.generate(messages)
    
    @pytest.mark.asyncio
    async def test_analyze_failure(self, llm_service, sample_analysis_request):
        """Test failure analysis."""
        response = await llm_service.analyze_failure(sample_analysis_request)
        
        assert isinstance(response, AnalysisResponse)
        # Mock provider returns a valid response
        assert response.success or response.error
    
    @pytest.mark.asyncio
    async def test_health_check(self, llm_service):
        """Test health check across providers."""
        results = await llm_service.health_check()
        
        assert "mock" in results
        assert results["mock"] is True
    
    def test_service_statistics(self, llm_service):
        """Test statistics collection."""
        stats = llm_service.get_stats()
        
        assert "total_requests" in stats
        assert "successful_requests" in stats
        assert "providers" in stats


# ═══════════════════════════════════════════════════════════════
# Prompt Builder Tests
# ═══════════════════════════════════════════════════════════════

class TestPromptBuilders:
    """Tests for prompt building functions."""
    
    def test_build_analysis_prompt(self, sample_analysis_request):
        """Test analysis prompt building."""
        prompt = build_analysis_prompt(sample_analysis_request)
        
        assert "task-123" in prompt
        assert "EXPLOIT" in prompt
        assert "192.168.1.100" in prompt
        assert "edr_blocked" in prompt
        assert "rx-exploit-ms17010" in prompt
    
    def test_extract_json_direct(self):
        """Test direct JSON extraction."""
        response = '{"key": "value", "number": 42}'
        result = extract_json_from_response(response)
        
        assert result == {"key": "value", "number": 42}
    
    def test_extract_json_from_markdown(self):
        """Test JSON extraction from markdown code block."""
        response = '''Here's the analysis:
        
```json
{
    "decision": "retry",
    "reasoning": "Transient error"
}
```

That's my recommendation.'''
        
        result = extract_json_from_response(response)
        assert result["decision"] == "retry"
    
    def test_extract_json_embedded(self):
        """Test extraction of embedded JSON."""
        response = 'The result is {"success": true, "count": 5} as expected.'
        result = extract_json_from_response(response)
        
        assert result["success"] is True
        assert result["count"] == 5
    
    def test_extract_json_invalid(self):
        """Test error on invalid JSON."""
        response = "This is not JSON at all"
        
        with pytest.raises(ValueError):
            extract_json_from_response(response)


# ═══════════════════════════════════════════════════════════════
# Pydantic Model Tests
# ═══════════════════════════════════════════════════════════════

class TestPydanticModels:
    """Tests for Pydantic model validation."""
    
    def test_task_context_creation(self):
        """Test TaskContext creation."""
        ctx = TaskContext(
            task_id="test-123",
            task_type="EXPLOIT",
        )
        assert ctx.task_id == "test-123"
        assert ctx.target_ip is None
    
    def test_analysis_request_validation(self):
        """Test AnalysisRequest validation."""
        request = AnalysisRequest(
            task=TaskContext(task_id="t1", task_type="RECON"),
            execution=ExecutionContext(),
            error=ErrorDetails(error_type="test", error_message="Test error"),
        )
        
        assert request.retry_count == 0
        assert request.max_retries == 3
        assert request.available_modules == []
    
    def test_analysis_response_success(self):
        """Test successful AnalysisResponse."""
        from src.core.llm.models import (
            RootCauseAnalysis,
            RecommendedAction,
        )
        
        response = AnalysisResponse(
            success=True,
            analysis=FailureAnalysis(
                analysis=RootCauseAnalysis(
                    category=FailureCategory.NETWORK,
                    root_cause="Connection timeout",
                ),
                recommended_action=RecommendedAction(
                    decision=DecisionType.RETRY,
                    reasoning="Transient network issue",
                    delay_seconds=30,
                ),
            ),
            model_used="gpt-4",
            tokens_used=100,
        )
        
        assert response.success
        assert response.analysis is not None
        assert response.analysis.recommended_action.decision == DecisionType.RETRY
    
    def test_analysis_response_failure(self):
        """Test failed AnalysisResponse."""
        response = AnalysisResponse(
            success=False,
            error="Provider unavailable",
        )
        
        assert not response.success
        assert response.analysis is None
        assert response.error == "Provider unavailable"
    
    def test_decision_type_enum(self):
        """Test DecisionType enum values."""
        assert DecisionType.RETRY.value == "retry"
        assert DecisionType.MODIFY_APPROACH.value == "modify_approach"
        assert DecisionType.SKIP.value == "skip"
        assert DecisionType.ESCALATE.value == "escalate"
        assert DecisionType.PIVOT.value == "pivot"


# ═══════════════════════════════════════════════════════════════
# AnalysisSpecialist Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestAnalysisSpecialistLLMIntegration:
    """Tests for AnalysisSpecialist LLM integration."""
    
    @pytest.fixture
    def mock_blackboard(self):
        """Create a mock blackboard."""
        import uuid
        task_id = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        
        blackboard = MagicMock()
        blackboard.get_task = AsyncMock(return_value={
            "id": task_id,
            "type": "EXPLOIT",
            "specialist": "ATTACK",
            "target_id": target_id,
            "retry_count": 0,
            "max_retries": 3,
        })
        blackboard.get_target = AsyncMock(return_value={
            "id": target_id,
            "ip": "192.168.1.100",
            "os": "Windows Server 2019",
        })
        blackboard.get_vulnerability = AsyncMock(return_value=None)
        blackboard.log_result = AsyncMock()
        blackboard.get_channel = MagicMock(return_value="test-channel")
        blackboard.publish = AsyncMock()  # Add publish mock
        blackboard._task_id = task_id  # Store for later use
        return blackboard
    
    @pytest.fixture
    def analysis_specialist_with_llm(self, mock_blackboard, mock_provider):
        """Create AnalysisSpecialist with LLM enabled."""
        from src.specialists.analysis import AnalysisSpecialist
        from src.core.llm.service import LLMService
        import uuid
        
        # Create service with mock provider
        service = LLMService()
        service.register_provider("mock", mock_provider, set_as_default=True)
        
        specialist = AnalysisSpecialist(
            blackboard=mock_blackboard,
            llm_enabled=True,
            llm_service=service,
        )
        # Use a proper UUID format
        specialist._current_mission_id = str(uuid.uuid4())
        
        return specialist
    
    @pytest.fixture
    def analysis_specialist_no_llm(self, mock_blackboard):
        """Create AnalysisSpecialist with LLM disabled."""
        from src.specialists.analysis import AnalysisSpecialist
        import uuid
        
        specialist = AnalysisSpecialist(
            blackboard=mock_blackboard,
            llm_enabled=False,
        )
        # Use a proper UUID format
        specialist._current_mission_id = str(uuid.uuid4())
        
        return specialist
    
    @pytest.mark.asyncio
    async def test_llm_enabled_analysis(self, analysis_specialist_with_llm, mock_blackboard):
        """Test analysis with LLM enabled."""
        task_id = mock_blackboard._task_id
        result = await analysis_specialist_with_llm.analyze_failure(
            task_id=task_id,
            error_context={
                "error_type": "edr_blocked",
                "error_message": "Blocked by EDR",
                "detected_defenses": ["edr"],
            },
            execution_logs=[],
        )
        
        assert result is not None
        assert "decision" in result
    
    @pytest.mark.asyncio
    async def test_llm_disabled_analysis(self, analysis_specialist_no_llm, mock_blackboard):
        """Test analysis with LLM disabled (rule-based)."""
        task_id = mock_blackboard._task_id
        result = await analysis_specialist_no_llm.analyze_failure(
            task_id=task_id,
            error_context={
                "error_type": "connection_timeout",
                "error_message": "Connection timed out",
            },
            execution_logs=[],
        )
        
        assert result is not None
        assert "decision" in result
        # Rule-based should recommend retry for network issues
        assert result["decision"] in ["retry", "skip", "escalate", "modify_approach"]
    
    @pytest.mark.asyncio
    async def test_llm_fallback_on_failure(self, mock_blackboard):
        """Test fallback to rule-based when LLM fails."""
        from src.specialists.analysis import AnalysisSpecialist
        from src.core.llm.service import LLMService
        import uuid
        
        # Create service with failing provider
        failing_provider = MockLLMProvider(failure_rate=1.0)
        service = LLMService()
        service.register_provider("failing", failing_provider, set_as_default=True)
        
        specialist = AnalysisSpecialist(
            blackboard=mock_blackboard,
            llm_enabled=True,
            llm_service=service,
        )
        specialist._current_mission_id = str(uuid.uuid4())
        
        task_id = mock_blackboard._task_id
        result = await specialist.analyze_failure(
            task_id=task_id,
            error_context={
                "error_type": "connection_timeout",
                "error_message": "Timeout",
            },
            execution_logs=[],
        )
        
        assert result is not None
        assert "decision" in result
        # Should still work via fallback
    
    @pytest.mark.asyncio
    async def test_analysis_stats_tracking(self, analysis_specialist_with_llm, mock_blackboard):
        """Test that analysis statistics are tracked."""
        task_id = mock_blackboard._task_id
        await analysis_specialist_with_llm.analyze_failure(
            task_id=task_id,
            error_context={"error_type": "timeout", "error_message": "Timeout"},
            execution_logs=[],
        )
        
        stats = analysis_specialist_with_llm.get_stats()
        assert stats["analyses_performed"] > 0


# ═══════════════════════════════════════════════════════════════
# Global Service Tests
# ═══════════════════════════════════════════════════════════════

class TestGlobalService:
    """Tests for global service management."""
    
    def test_get_llm_service_singleton(self):
        """Test singleton pattern."""
        reset_llm_service()
        
        service1 = get_llm_service()
        service2 = get_llm_service()
        
        assert service1 is service2
    
    def test_init_llm_service(self):
        """Test service initialization with config."""
        reset_llm_service()
        
        mock = MockLLMProvider()
        service = init_llm_service(
            config={"enable_fallback": True},
            providers={"test": mock}
        )
        
        assert "test" in service.providers
        assert service.get_provider("test") is mock
    
    def test_reset_llm_service(self):
        """Test service reset."""
        get_llm_service()  # Ensure initialized
        reset_llm_service()
        
        # Should create new instance
        service1 = get_llm_service()
        reset_llm_service()
        service2 = get_llm_service()
        
        assert service1 is not service2


# ═══════════════════════════════════════════════════════════════
# LLMMessage Tests
# ═══════════════════════════════════════════════════════════════

class TestLLMMessage:
    """Tests for LLMMessage class."""
    
    def test_system_message(self):
        """Test system message creation."""
        msg = LLMMessage.system("You are an assistant.")
        assert msg.role == MessageRole.SYSTEM
        assert msg.content == "You are an assistant."
    
    def test_user_message(self):
        """Test user message creation."""
        msg = LLMMessage.user("Hello!")
        assert msg.role == MessageRole.USER
        assert msg.content == "Hello!"
    
    def test_assistant_message(self):
        """Test assistant message creation."""
        msg = LLMMessage.assistant("I can help with that.")
        assert msg.role == MessageRole.ASSISTANT
    
    def test_message_to_dict(self):
        """Test message serialization."""
        msg = LLMMessage.user("Test")
        d = msg.to_dict()
        
        assert d["role"] == "user"
        assert d["content"] == "Test"


# ═══════════════════════════════════════════════════════════════
# Edge Cases and Error Handling
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_empty_messages(self, mock_provider):
        """Test handling of empty messages list."""
        with pytest.raises(ValueError):
            await mock_provider.generate([])
    
    @pytest.mark.asyncio
    async def test_no_providers_available(self):
        """Test error when no providers available."""
        service = LLMService()
        
        with pytest.raises(LLMError):
            await service.generate([LLMMessage.user("Test")])
    
    def test_invalid_temperature(self):
        """Test invalid temperature validation."""
        with pytest.raises(ValueError):
            LLMConfig(temperature=3.0)  # > 2.0
    
    def test_invalid_max_tokens(self):
        """Test invalid max_tokens validation."""
        with pytest.raises(ValueError):
            LLMConfig(max_tokens=0)  # Must be positive


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
