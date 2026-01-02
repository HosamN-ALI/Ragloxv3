# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - LLM Base Classes
# Abstract base classes and data models for LLM integration
# ═══════════════════════════════════════════════════════════════

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import logging


# ═══════════════════════════════════════════════════════════════
# Exceptions
# ═══════════════════════════════════════════════════════════════

class LLMError(Exception):
    """Base exception for LLM-related errors."""
    
    def __init__(self, message: str, provider: Optional[str] = None, details: Optional[Dict] = None):
        super().__init__(message)
        self.message = message
        self.provider = provider
        self.details = details or {}


class RateLimitError(LLMError):
    """Rate limit exceeded error."""
    
    def __init__(
        self, 
        message: str = "Rate limit exceeded",
        provider: Optional[str] = None,
        retry_after: Optional[int] = None
    ):
        super().__init__(message, provider, {"retry_after": retry_after})
        self.retry_after = retry_after


class ModelNotAvailableError(LLMError):
    """Model not available error."""
    
    def __init__(self, model: str, provider: Optional[str] = None):
        super().__init__(f"Model '{model}' not available", provider, {"model": model})
        self.model = model


class InvalidResponseError(LLMError):
    """Invalid response from LLM."""
    
    def __init__(self, message: str, raw_response: Optional[str] = None, provider: Optional[str] = None):
        super().__init__(message, provider, {"raw_response": raw_response})
        self.raw_response = raw_response


class AuthenticationError(LLMError):
    """Authentication/API key error."""
    pass


class ContextLengthError(LLMError):
    """Context length exceeded error."""
    
    def __init__(self, tokens_used: int, max_tokens: int, provider: Optional[str] = None):
        super().__init__(
            f"Context length exceeded: {tokens_used} > {max_tokens}",
            provider,
            {"tokens_used": tokens_used, "max_tokens": max_tokens}
        )
        self.tokens_used = tokens_used
        self.max_tokens = max_tokens


# ═══════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════

class MessageRole(str, Enum):
    """LLM message role."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    FUNCTION = "function"
    TOOL = "tool"


class ProviderType(str, Enum):
    """LLM provider type."""
    OPENAI = "openai"
    LOCAL = "local"
    ANTHROPIC = "anthropic"
    MOCK = "mock"


# ═══════════════════════════════════════════════════════════════
# Data Classes
# ═══════════════════════════════════════════════════════════════

@dataclass
class LLMConfig:
    """Configuration for LLM provider."""
    
    provider_type: ProviderType = ProviderType.OPENAI
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    model: str = "gpt-4o-mini"
    
    # Generation parameters
    temperature: float = 0.7
    max_tokens: int = 2048
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    
    # Retry configuration
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_multiplier: float = 2.0
    
    # Rate limiting
    requests_per_minute: int = 60
    tokens_per_minute: int = 90000
    
    # Timeouts
    timeout: float = 60.0
    connect_timeout: float = 10.0
    
    # Response format
    response_format: Optional[Dict[str, str]] = None  # {"type": "json_object"}
    
    def __post_init__(self):
        """Validate configuration."""
        if self.temperature < 0 or self.temperature > 2:
            raise ValueError("Temperature must be between 0 and 2")
        if self.max_tokens < 1:
            raise ValueError("max_tokens must be positive")


@dataclass
class LLMMessage:
    """A message in an LLM conversation."""
    
    role: MessageRole
    content: str
    name: Optional[str] = None
    function_call: Optional[Dict[str, Any]] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API call."""
        result = {
            "role": self.role.value,
            "content": self.content
        }
        if self.name:
            result["name"] = self.name
        if self.function_call:
            result["function_call"] = self.function_call
        if self.tool_calls:
            result["tool_calls"] = self.tool_calls
        return result
    
    @classmethod
    def system(cls, content: str) -> "LLMMessage":
        """Create a system message."""
        return cls(role=MessageRole.SYSTEM, content=content)
    
    @classmethod
    def user(cls, content: str) -> "LLMMessage":
        """Create a user message."""
        return cls(role=MessageRole.USER, content=content)
    
    @classmethod
    def assistant(cls, content: str) -> "LLMMessage":
        """Create an assistant message."""
        return cls(role=MessageRole.ASSISTANT, content=content)


@dataclass
class TokenUsage:
    """Token usage information."""
    
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class LLMResponse:
    """Response from LLM provider."""
    
    content: str
    model: str
    provider: str
    
    # Metadata
    finish_reason: Optional[str] = None
    usage: Optional[TokenUsage] = None
    
    # Timing
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Raw response for debugging
    raw_response: Optional[Dict[str, Any]] = None
    
    # Parsed JSON if response_format was json_object
    parsed_json: Optional[Dict[str, Any]] = None
    
    @property
    def is_complete(self) -> bool:
        """Check if response completed normally."""
        return self.finish_reason in ("stop", "end_turn", None)
    
    @property
    def was_truncated(self) -> bool:
        """Check if response was truncated due to length."""
        return self.finish_reason == "length"


# ═══════════════════════════════════════════════════════════════
# Abstract Base Class
# ═══════════════════════════════════════════════════════════════

class LLMProvider(ABC):
    """
    Abstract base class for LLM providers.
    
    All LLM providers must implement this interface.
    """
    
    def __init__(self, config: LLMConfig):
        """
        Initialize the provider.
        
        Args:
            config: LLM configuration
        """
        self.config = config
        self.logger = logging.getLogger(f"raglox.llm.{self.__class__.__name__}")
        
        # Statistics
        self._request_count = 0
        self._total_tokens = 0
        self._error_count = 0
        self._last_request_time: Optional[datetime] = None
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get the provider name."""
        pass
    
    @property
    @abstractmethod
    def available_models(self) -> List[str]:
        """Get list of available models."""
        pass
    
    @abstractmethod
    async def generate(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response from the LLM.
        
        Args:
            messages: List of conversation messages
            **kwargs: Additional generation parameters
            
        Returns:
            LLM response
            
        Raises:
            LLMError: If generation fails
        """
        pass
    
    @abstractmethod
    async def generate_json(
        self,
        messages: List[LLMMessage],
        schema: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a JSON response from the LLM.
        
        Args:
            messages: List of conversation messages
            schema: Optional JSON schema for validation
            **kwargs: Additional generation parameters
            
        Returns:
            Parsed JSON response
            
        Raises:
            LLMError: If generation or parsing fails
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if the provider is healthy and available.
        
        Returns:
            True if healthy, False otherwise
        """
        pass
    
    async def close(self) -> None:
        """Close any open connections."""
        pass
    
    # ═══════════════════════════════════════════════════════════
    # Helper Methods
    # ═══════════════════════════════════════════════════════════
    
    def _validate_messages(self, messages: List[LLMMessage]) -> None:
        """Validate message list."""
        if not messages:
            raise ValueError("Messages list cannot be empty")
        
        for msg in messages:
            if not msg.content and not msg.function_call and not msg.tool_calls:
                raise ValueError("Message must have content, function_call, or tool_calls")
    
    def _update_stats(self, response: LLMResponse) -> None:
        """Update provider statistics."""
        self._request_count += 1
        self._last_request_time = datetime.utcnow()
        
        if response.usage:
            self._total_tokens += response.usage.total_tokens
    
    def get_stats(self) -> Dict[str, Any]:
        """Get provider statistics."""
        return {
            "provider": self.provider_name,
            "model": self.config.model,
            "request_count": self._request_count,
            "total_tokens": self._total_tokens,
            "error_count": self._error_count,
            "last_request": self._last_request_time.isoformat() if self._last_request_time else None
        }
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self.config.model})"
