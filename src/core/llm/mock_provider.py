# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Mock LLM Provider
# Mock provider for testing without real LLM calls
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
import random
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union

from .base import (
    LLMProvider,
    LLMConfig,
    LLMMessage,
    LLMResponse,
    TokenUsage,
    LLMError,
    InvalidResponseError,
)
from .models import (
    DecisionType,
    ConfidenceLevel,
    FailureCategory,
)


class MockLLMProvider(LLMProvider):
    """
    Mock LLM provider for testing.
    
    Provides deterministic or configurable responses for testing
    without making actual API calls.
    
    Features:
    - Configurable response delays
    - Pre-defined response patterns
    - Custom response handlers
    - Error simulation
    - Response recording for assertions
    
    Example usage:
        # Basic usage
        provider = MockLLMProvider()
        response = await provider.generate([...])
        
        # With custom responses
        provider = MockLLMProvider()
        provider.add_response("What is...", {"answer": "42"})
        
        # With failure simulation
        provider = MockLLMProvider(failure_rate=0.2)
    """
    
    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        delay_ms: float = 50,
        failure_rate: float = 0.0,
        simulate_tokens: bool = True,
    ):
        """
        Initialize Mock LLM provider.
        
        Args:
            config: Optional LLM configuration
            delay_ms: Simulated response delay in milliseconds
            failure_rate: Probability of simulated failure (0-1)
            simulate_tokens: Whether to simulate token counting
        """
        if config is None:
            config = LLMConfig(model="mock-gpt-4")
        
        super().__init__(config)
        
        self.delay_ms = delay_ms
        self.failure_rate = failure_rate
        self.simulate_tokens = simulate_tokens
        
        # Response storage
        self._responses: Dict[str, Any] = {}
        self._default_response: Optional[Union[str, Dict, Callable]] = None
        self._response_queue: List[Any] = []
        
        # Recording for assertions
        self._call_history: List[Dict[str, Any]] = []
        self._recorded_messages: List[List[LLMMessage]] = []
    
    @property
    def provider_name(self) -> str:
        return "mock"
    
    @property
    def available_models(self) -> List[str]:
        return ["mock-gpt-4", "mock-gpt-3.5", "mock-llama"]
    
    @property
    def call_count(self) -> int:
        """Get number of generate calls made."""
        return len(self._call_history)
    
    @property
    def last_messages(self) -> Optional[List[LLMMessage]]:
        """Get messages from last call."""
        if self._recorded_messages:
            return self._recorded_messages[-1]
        return None
    
    # ═══════════════════════════════════════════════════════════
    # Response Configuration
    # ═══════════════════════════════════════════════════════════
    
    def add_response(
        self,
        pattern: str,
        response: Union[str, Dict[str, Any], Callable]
    ) -> "MockLLMProvider":
        """
        Add a response pattern.
        
        Args:
            pattern: Substring to match in message content
            response: Response to return (string, dict, or callable)
            
        Returns:
            self for chaining
        """
        self._responses[pattern.lower()] = response
        return self
    
    def set_default_response(
        self,
        response: Union[str, Dict[str, Any], Callable]
    ) -> "MockLLMProvider":
        """
        Set the default response when no patterns match.
        
        Args:
            response: Default response
            
        Returns:
            self for chaining
        """
        self._default_response = response
        return self
    
    def queue_response(
        self,
        response: Union[str, Dict[str, Any]]
    ) -> "MockLLMProvider":
        """
        Queue a response for the next call (FIFO).
        
        Args:
            response: Response to queue
            
        Returns:
            self for chaining
        """
        self._response_queue.append(response)
        return self
    
    def queue_responses(
        self,
        responses: List[Union[str, Dict[str, Any]]]
    ) -> "MockLLMProvider":
        """
        Queue multiple responses.
        
        Args:
            responses: List of responses to queue
            
        Returns:
            self for chaining
        """
        self._response_queue.extend(responses)
        return self
    
    def clear_responses(self) -> "MockLLMProvider":
        """Clear all configured responses."""
        self._responses.clear()
        self._default_response = None
        self._response_queue.clear()
        return self
    
    def reset(self) -> "MockLLMProvider":
        """Reset all state including history."""
        self.clear_responses()
        self._call_history.clear()
        self._recorded_messages.clear()
        return self
    
    # ═══════════════════════════════════════════════════════════
    # Pre-defined Analysis Responses
    # ═══════════════════════════════════════════════════════════
    
    def setup_analysis_responses(self) -> "MockLLMProvider":
        """
        Setup pre-defined responses for failure analysis.
        
        Returns:
            self for chaining
        """
        # Retry response
        self.add_response("timeout", self._build_retry_response())
        self.add_response("connection refused", self._build_retry_response(delay=30))
        
        # Defense detection responses
        self.add_response("access denied", self._build_defense_response("firewall"))
        self.add_response("blocked", self._build_defense_response("edr"))
        self.add_response("antivirus", self._build_defense_response("antivirus"))
        
        # Authentication responses
        self.add_response("authentication failed", self._build_auth_response())
        self.add_response("invalid credentials", self._build_auth_response())
        
        # Technical responses
        self.add_response("not found", self._build_technical_response())
        self.add_response("module error", self._build_technical_response())
        
        # Escalation responses
        self.add_response("unknown error", self._build_escalate_response())
        
        # Set default to retry
        self.set_default_response(self._build_retry_response())
        
        return self
    
    def _build_retry_response(self, delay: int = 10) -> Dict[str, Any]:
        """Build a retry decision response."""
        return {
            "analysis": {
                "category": FailureCategory.NETWORK.value,
                "root_cause": "Temporary network issue or timeout",
                "contributing_factors": ["Network latency", "Server overload"],
                "detected_defenses": [],
                "confidence": ConfidenceLevel.MEDIUM.value
            },
            "recommended_action": {
                "decision": DecisionType.RETRY.value,
                "reasoning": "Transient error that may succeed on retry",
                "delay_seconds": delay,
                "alternative_module": None,
                "modified_parameters": {},
                "new_attack_vector": None,
                "new_technique_id": None,
                "escalation_reason": None,
                "human_guidance_needed": []
            },
            "additional_recommendations": ["Monitor network stability"],
            "lessons_learned": ["Network issues may require patience"],
            "should_update_knowledge": False,
            "knowledge_update": None
        }
    
    def _build_defense_response(self, defense_type: str) -> Dict[str, Any]:
        """Build a defense detection response."""
        return {
            "analysis": {
                "category": FailureCategory.DEFENSE.value,
                "root_cause": f"Detected {defense_type} blocking the attack",
                "contributing_factors": [f"{defense_type.upper()} detection"],
                "detected_defenses": [defense_type],
                "confidence": ConfidenceLevel.HIGH.value
            },
            "recommended_action": {
                "decision": DecisionType.MODIFY_APPROACH.value,
                "reasoning": f"Need to evade {defense_type}",
                "delay_seconds": 60,
                "alternative_module": {
                    "rx_module_id": f"rx-evasion-{defense_type}",
                    "reason": f"Module designed to evade {defense_type}",
                    "expected_success_rate": 0.7,
                    "required_parameters": {},
                    "evasion_techniques": ["obfuscation", "timing"]
                },
                "modified_parameters": {"use_evasion": True},
                "new_attack_vector": None,
                "new_technique_id": None,
                "escalation_reason": None,
                "human_guidance_needed": []
            },
            "additional_recommendations": [
                f"Consider {defense_type} bypass techniques",
                "Use living-off-the-land binaries"
            ],
            "lessons_learned": [f"Target has {defense_type} protection"],
            "should_update_knowledge": True,
            "knowledge_update": f"Target protected by {defense_type}"
        }
    
    def _build_auth_response(self) -> Dict[str, Any]:
        """Build an authentication failure response."""
        return {
            "analysis": {
                "category": FailureCategory.AUTHENTICATION.value,
                "root_cause": "Invalid or expired credentials",
                "contributing_factors": ["Wrong credentials", "Account lockout possible"],
                "detected_defenses": [],
                "confidence": ConfidenceLevel.HIGH.value
            },
            "recommended_action": {
                "decision": DecisionType.MODIFY_APPROACH.value,
                "reasoning": "Try different credentials or credential harvesting",
                "delay_seconds": 30,
                "alternative_module": {
                    "rx_module_id": "rx-cred-spray",
                    "reason": "Try credential spraying with other accounts",
                    "expected_success_rate": 0.5,
                    "required_parameters": {},
                    "evasion_techniques": []
                },
                "modified_parameters": {"use_alternative_creds": True},
                "new_attack_vector": None,
                "new_technique_id": None,
                "escalation_reason": None,
                "human_guidance_needed": []
            },
            "additional_recommendations": [
                "Harvest more credentials",
                "Check for default credentials"
            ],
            "lessons_learned": ["Need valid credentials for this target"],
            "should_update_knowledge": False,
            "knowledge_update": None
        }
    
    def _build_technical_response(self) -> Dict[str, Any]:
        """Build a technical failure response."""
        return {
            "analysis": {
                "category": FailureCategory.TECHNICAL.value,
                "root_cause": "Module or configuration error",
                "contributing_factors": ["Invalid parameters", "Module incompatibility"],
                "detected_defenses": [],
                "confidence": ConfidenceLevel.MEDIUM.value
            },
            "recommended_action": {
                "decision": DecisionType.MODIFY_APPROACH.value,
                "reasoning": "Try alternative module with correct configuration",
                "delay_seconds": 5,
                "alternative_module": {
                    "rx_module_id": "rx-alternative-exploit",
                    "reason": "Different implementation that may work",
                    "expected_success_rate": 0.6,
                    "required_parameters": {},
                    "evasion_techniques": []
                },
                "modified_parameters": {},
                "new_attack_vector": None,
                "new_technique_id": None,
                "escalation_reason": None,
                "human_guidance_needed": []
            },
            "additional_recommendations": ["Check module documentation"],
            "lessons_learned": ["Module may have compatibility issues"],
            "should_update_knowledge": False,
            "knowledge_update": None
        }
    
    def _build_escalate_response(self) -> Dict[str, Any]:
        """Build an escalation response."""
        return {
            "analysis": {
                "category": FailureCategory.UNKNOWN.value,
                "root_cause": "Unable to determine root cause",
                "contributing_factors": ["Insufficient information"],
                "detected_defenses": [],
                "confidence": ConfidenceLevel.LOW.value
            },
            "recommended_action": {
                "decision": DecisionType.ESCALATE.value,
                "reasoning": "Cannot automatically resolve this issue",
                "delay_seconds": 0,
                "alternative_module": None,
                "modified_parameters": {},
                "new_attack_vector": None,
                "new_technique_id": None,
                "escalation_reason": "Unknown error requiring human analysis",
                "human_guidance_needed": [
                    "Review error logs manually",
                    "Check target accessibility",
                    "Verify mission parameters"
                ]
            },
            "additional_recommendations": ["Collect more information"],
            "lessons_learned": ["Some failures require human intervention"],
            "should_update_knowledge": False,
            "knowledge_update": None
        }
    
    # ═══════════════════════════════════════════════════════════
    # LLMProvider Implementation
    # ═══════════════════════════════════════════════════════════
    
    async def generate(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a mock response.
        
        Args:
            messages: List of conversation messages
            **kwargs: Additional parameters (ignored)
            
        Returns:
            Mock LLM response
        """
        self._validate_messages(messages)
        
        # Record call
        self._call_history.append({
            "messages": messages,
            "kwargs": kwargs,
            "timestamp": datetime.utcnow()
        })
        self._recorded_messages.append(messages)
        
        # Simulate delay
        if self.delay_ms > 0:
            await asyncio.sleep(self.delay_ms / 1000)
        
        # Simulate failure
        if self.failure_rate > 0 and random.random() < self.failure_rate:
            raise LLMError("Simulated failure", provider=self.provider_name)
        
        # Get response content
        start_time = time.time()
        content = self._get_response_content(messages)
        latency_ms = (time.time() - start_time) * 1000 + self.delay_ms
        
        # Parse JSON if possible
        parsed_json = None
        if isinstance(content, dict):
            parsed_json = content
            content = json.dumps(content)
        elif content.strip().startswith("{"):
            try:
                parsed_json = json.loads(content)
            except json.JSONDecodeError:
                pass
        
        # Calculate mock token usage
        usage = None
        if self.simulate_tokens:
            prompt_text = " ".join(m.content for m in messages)
            usage = TokenUsage(
                prompt_tokens=len(prompt_text.split()) * 2,
                completion_tokens=len(content.split()) * 2 if isinstance(content, str) else 100,
                total_tokens=0
            )
            usage.total_tokens = usage.prompt_tokens + usage.completion_tokens
        
        response = LLMResponse(
            content=content if isinstance(content, str) else json.dumps(content),
            model=self.config.model,
            provider=self.provider_name,
            finish_reason="stop",
            usage=usage,
            latency_ms=latency_ms,
            parsed_json=parsed_json,
        )
        
        self._update_stats(response)
        return response
    
    async def generate_json(
        self,
        messages: List[LLMMessage],
        schema: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a mock JSON response.
        
        Args:
            messages: List of conversation messages
            schema: Optional JSON schema for validation
            **kwargs: Additional parameters
            
        Returns:
            Parsed JSON response
        """
        response = await self.generate(messages, **kwargs)
        
        if response.parsed_json:
            return response.parsed_json
        
        try:
            return json.loads(response.content)
        except json.JSONDecodeError as e:
            raise InvalidResponseError(
                f"Mock response is not valid JSON: {e}",
                raw_response=response.content,
                provider=self.provider_name
            )
    
    async def health_check(self) -> bool:
        """Mock health check always returns True."""
        return True
    
    # ═══════════════════════════════════════════════════════════
    # Private Methods
    # ═══════════════════════════════════════════════════════════
    
    def _get_response_content(self, messages: List[LLMMessage]) -> Union[str, Dict]:
        """Get response content based on configuration."""
        # Check queue first
        if self._response_queue:
            return self._response_queue.pop(0)
        
        # Get last user message content for pattern matching
        user_content = ""
        for msg in reversed(messages):
            if msg.role.value == "user":
                user_content = msg.content.lower()
                break
        
        # Check patterns
        for pattern, response in self._responses.items():
            if pattern in user_content:
                if callable(response):
                    return response(messages)
                return response
        
        # Return default
        if self._default_response:
            if callable(self._default_response):
                return self._default_response(messages)
            return self._default_response
        
        # Fallback response
        return {
            "response": "Mock response",
            "messages_received": len(messages)
        }
    
    # ═══════════════════════════════════════════════════════════
    # Assertion Helpers
    # ═══════════════════════════════════════════════════════════
    
    def assert_called(self, times: Optional[int] = None) -> None:
        """Assert that generate was called (optionally a specific number of times)."""
        if times is not None:
            assert self.call_count == times, f"Expected {times} calls, got {self.call_count}"
        else:
            assert self.call_count > 0, "Expected at least one call"
    
    def assert_not_called(self) -> None:
        """Assert that generate was not called."""
        assert self.call_count == 0, f"Expected no calls, got {self.call_count}"
    
    def assert_message_contains(self, text: str, call_index: int = -1) -> None:
        """Assert that a call's messages contain specific text."""
        messages = self._recorded_messages[call_index]
        all_content = " ".join(m.content for m in messages)
        assert text.lower() in all_content.lower(), \
            f"Expected '{text}' in messages, but not found"
    
    def get_call_messages(self, call_index: int = -1) -> List[LLMMessage]:
        """Get messages from a specific call."""
        return self._recorded_messages[call_index]
