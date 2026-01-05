# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - BlackboxAI Provider
# LLM provider for BlackboxAI API (OpenAI-compatible)
# ═══════════════════════════════════════════════════════════════

import asyncio
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from .base import (
    LLMProvider,
    LLMConfig,
    LLMMessage,
    LLMResponse,
    TokenUsage,
    LLMError,
    RateLimitError,
    ModelNotAvailableError,
    InvalidResponseError,
    AuthenticationError,
    ContextLengthError,
)
from .prompts import extract_json_from_response


class BlackboxAIProvider(LLMProvider):
    """
    BlackboxAI API provider.
    
    BlackboxAI provides an OpenAI-compatible API for various models.
    
    Supports:
    - GPT-4 via BlackboxAI
    - GPT-3.5-Turbo via BlackboxAI
    - JSON mode for structured output
    - Automatic retry with exponential backoff
    - Rate limiting and cost tracking
    
    Example:
        config = LLMConfig(
            api_key="sk-your-blackbox-key",
            api_base="https://api.blackbox.ai",
            model="gpt-4",
        )
        provider = BlackboxAIProvider(config)
    """
    
    DEFAULT_BASE_URL = "https://api.blackbox.ai"
    
    AVAILABLE_MODELS = [
        "gpt-4",
        "gpt-3.5-turbo",
        "gpt-4o",
        "gpt-4o-mini",
        "blackboxai/openai/gpt-4",
        "blackboxai/openai/gpt-3.5-turbo",
        "blackboxai/openai/gpt-4-turbo",
        "blackboxai/openai/gpt-4o",
        "blackboxai/openai/gpt-4o-mini",
        "blackboxai/deepseek/deepseek-chat:free",
        "blackboxai/deepseek/deepseek-chat",
        "blackboxai/qwen/qwen-2.5-72b-instruct",
        "blackboxai/meta-llama/llama-3.3-70b-instruct",
        "blackbox/deepseek/deepseek-chat",
    ]
    
    # Cost per 1K tokens (approximate)
    MODEL_COSTS = {
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "gpt-4o": {"input": 0.005, "output": 0.015},
        "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
        "blackboxai/openai/gpt-4": {"input": 0.03, "output": 0.06},
        "blackboxai/openai/gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "blackboxai/openai/gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        "blackboxai/openai/gpt-4o": {"input": 0.005, "output": 0.015},
        "blackboxai/openai/gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
        "blackboxai/deepseek/deepseek-chat:free": {"input": 0.0002, "output": 0.0004},
        "blackboxai/deepseek/deepseek-chat": {"input": 0.0002, "output": 0.0004},
        "blackbox/deepseek/deepseek-chat": {"input": 0.0002, "output": 0.0004},
    }
    
    def __init__(self, config: LLMConfig):
        """
        Initialize BlackboxAI provider.
        
        Args:
            config: LLM configuration with API key
        """
        super().__init__(config)
        
        if not config.api_key:
            raise ValueError("BlackboxAI API key is required")
        
        self.base_url = config.api_base or self.DEFAULT_BASE_URL
        self._client: Optional[httpx.AsyncClient] = None
        
        # Cost tracking
        self._total_cost = 0.0
        self._session_tokens = 0
        
        # Rate limiting state
        self._request_times: List[float] = []
        self._token_counts: List[tuple[float, int]] = []
    
    @property
    def provider_name(self) -> str:
        return "blackbox"
    
    @property
    def available_models(self) -> List[str]:
        return self.AVAILABLE_MODELS.copy()
    
    @property
    def total_cost(self) -> float:
        """Get total cost incurred in this session."""
        return self._total_cost
    
    @property
    def session_tokens(self) -> int:
        """Get total tokens used in this session."""
        return self._session_tokens
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(
                    connect=self.config.connect_timeout,
                    read=self.config.timeout,
                    write=self.config.timeout,
                    pool=self.config.timeout,
                ),
            )
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
    
    async def generate(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response from BlackboxAI.
        
        Args:
            messages: List of conversation messages
            **kwargs: Additional parameters (temperature, max_tokens, etc.)
            
        Returns:
            LLM response
        """
        self._validate_messages(messages)
        await self._check_rate_limit()
        
        # Build request
        request_data = self._build_request(messages, **kwargs)
        
        # Make request with retries
        start_time = time.time()
        response_data = await self._make_request(request_data)
        latency_ms = (time.time() - start_time) * 1000
        
        # Parse response
        response = self._parse_response(response_data, latency_ms)
        
        # Update stats and cost
        self._update_stats(response)
        self._record_request(response.usage)
        self._update_cost(response.usage)
        
        return response
    
    async def generate_json(
        self,
        messages: List[LLMMessage],
        schema: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a JSON response from BlackboxAI.
        
        Args:
            messages: List of conversation messages
            schema: Optional JSON schema for validation
            **kwargs: Additional parameters
            
        Returns:
            Parsed JSON response
        """
        # Add JSON instruction to the last message if not present
        if messages:
            last_msg = messages[-1]
            if "json" not in last_msg.content.lower():
                last_msg.content += "\n\nRespond with valid JSON only."
        
        # Generate response
        response = await self.generate(messages, **kwargs)
        
        # Parse JSON from response
        try:
            if response.parsed_json:
                return response.parsed_json
            
            result = extract_json_from_response(response.content)
            
            # Validate against schema if provided
            if schema:
                self._validate_json_schema(result, schema)
            
            return result
            
        except (json.JSONDecodeError, ValueError) as e:
            raise InvalidResponseError(
                f"Failed to parse JSON response: {e}",
                raw_response=response.content,
                provider=self.provider_name
            )
    
    async def health_check(self) -> bool:
        """Check if BlackboxAI API is accessible."""
        try:
            # Simple test request with minimal tokens to avoid context length issues
            messages = [LLMMessage.user("OK")]
            response = await self.generate(messages, max_tokens=5, model="gpt-4o-mini")
            return bool(response.content)
        except Exception as e:
            self.logger.warning(f"Health check failed: {e}")
            return False
    
    # ═══════════════════════════════════════════════════════════
    # Private Methods
    # ═══════════════════════════════════════════════════════════
    
    def _build_request(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> Dict[str, Any]:
        """Build the API request body."""
        model = kwargs.get("model", self.config.model)
        
        # Ensure we're using a valid model format
        if "blackbox/deepseek" in model or "blackboxai/deepseek" in model:
            # These are already correctly formatted
            pass
        elif model in ["deepseek-chat", "deepseek"]:
            model = "blackbox/deepseek/deepseek-chat"
        
        # Map simple model names to BlackboxAI format if needed
        if "blackbox" not in model:
            if model == "gpt-4":
                model = "blackboxai/openai/gpt-4-turbo"
            elif model == "gpt-3.5-turbo":
                model = "blackboxai/openai/gpt-3.5-turbo"
            elif model == "gpt-4o":
                model = "blackboxai/openai/gpt-4o"
            elif model == "gpt-4o-mini":
                model = "blackboxai/openai/gpt-4o-mini"
        else:
            # Allow blackbox/deepseek format
            pass
        
        request = {
            "model": model,
            "messages": [msg.to_dict() for msg in messages],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": False,
        }
        
        # Add optional parameters
        if kwargs.get("top_p") is not None:
            request["top_p"] = kwargs["top_p"]
        
        return request
    
    async def _make_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Make API request with retry logic."""
        last_error = None
        delay = self.config.retry_delay
        
        for attempt in range(self.config.max_retries + 1):
            try:
                client = await self._get_client()
                response = await client.post(
                    "/v1/chat/completions",
                    json=request_data,
                )
                
                # Handle response codes
                if response.status_code == 200:
                    return response.json()
                
                elif response.status_code == 429:
                    # Rate limited
                    retry_after = int(response.headers.get("Retry-After", delay))
                    if attempt < self.config.max_retries:
                        self.logger.warning(f"Rate limited, retrying in {retry_after}s")
                        await asyncio.sleep(retry_after)
                        delay *= self.config.retry_multiplier
                        continue
                    raise RateLimitError(
                        "Rate limit exceeded",
                        provider=self.provider_name,
                        retry_after=retry_after
                    )
                
                elif response.status_code == 401:
                    raise AuthenticationError(
                        "Invalid API key",
                        provider=self.provider_name
                    )
                
                elif response.status_code == 404:
                    raise ModelNotAvailableError(
                        request_data.get("model", "unknown"),
                        provider=self.provider_name
                    )
                
                elif response.status_code == 400:
                    error_data = {}
                    try:
                        error_data = response.json().get("error", {})
                    except Exception:
                        error_data = {"message": response.text}
                    
                    error_message = error_data.get("message", str(error_data))
                    
                    if "context_length" in error_message.lower() or "token" in error_message.lower():
                        raise ContextLengthError(
                            tokens_used=0,
                            max_tokens=0,
                            provider=self.provider_name
                        )
                    
                    raise LLMError(
                        f"Bad request: {error_message}",
                        provider=self.provider_name,
                        details=error_data
                    )
                
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except Exception:
                        pass
                    raise LLMError(
                        f"API error: {response.status_code}",
                        provider=self.provider_name,
                        details=error_data
                    )
                    
            except httpx.TimeoutException as e:
                last_error = e
                if attempt < self.config.max_retries:
                    self.logger.warning(f"Timeout, retrying in {delay}s")
                    await asyncio.sleep(delay)
                    delay *= self.config.retry_multiplier
                    continue
                    
            except httpx.RequestError as e:
                last_error = e
                if attempt < self.config.max_retries:
                    self.logger.warning(f"Request error: {e}, retrying in {delay}s")
                    await asyncio.sleep(delay)
                    delay *= self.config.retry_multiplier
                    continue
            
            except (RateLimitError, AuthenticationError, ModelNotAvailableError, ContextLengthError):
                raise
            
            except Exception as e:
                last_error = e
                self._error_count += 1
                if attempt < self.config.max_retries:
                    self.logger.warning(f"Error: {e}, retrying in {delay}s")
                    await asyncio.sleep(delay)
                    delay *= self.config.retry_multiplier
                    continue
        
        raise LLMError(
            f"Request failed after {self.config.max_retries + 1} attempts: {last_error}",
            provider=self.provider_name
        )
    
    def _parse_response(
        self,
        response_data: Dict[str, Any],
        latency_ms: float
    ) -> LLMResponse:
        """Parse API response into LLMResponse."""
        choice = response_data.get("choices", [{}])[0]
        message = choice.get("message", {})
        
        # Parse usage
        usage_data = response_data.get("usage", {})
        usage = TokenUsage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0),
        )
        
        # Get content
        content = message.get("content", "")
        
        # Try to parse as JSON if content looks like JSON
        parsed_json = None
        if content and content.strip().startswith("{"):
            try:
                parsed_json = json.loads(content)
            except json.JSONDecodeError:
                pass
        
        return LLMResponse(
            content=content,
            model=response_data.get("model", self.config.model),
            provider=self.provider_name,
            finish_reason=choice.get("finish_reason"),
            usage=usage,
            latency_ms=latency_ms,
            raw_response=response_data,
            parsed_json=parsed_json,
        )
    
    async def _check_rate_limit(self) -> None:
        """Check and enforce rate limits."""
        now = time.time()
        
        # Clean old request times (older than 1 minute)
        self._request_times = [t for t in self._request_times if now - t < 60]
        self._token_counts = [(t, c) for t, c in self._token_counts if now - t < 60]
        
        # Check requests per minute
        if len(self._request_times) >= self.config.requests_per_minute:
            oldest = self._request_times[0]
            wait_time = 60 - (now - oldest)
            if wait_time > 0:
                self.logger.info(f"Rate limiting: waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
        
        # Check tokens per minute
        total_tokens = sum(c for _, c in self._token_counts)
        if total_tokens >= self.config.tokens_per_minute:
            oldest = self._token_counts[0][0]
            wait_time = 60 - (now - oldest)
            if wait_time > 0:
                self.logger.info(f"Token rate limiting: waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
    
    def _record_request(self, usage: Optional[TokenUsage]) -> None:
        """Record request for rate limiting."""
        now = time.time()
        self._request_times.append(now)
        
        if usage:
            self._token_counts.append((now, usage.total_tokens))
            self._session_tokens += usage.total_tokens
    
    def _update_cost(self, usage: Optional[TokenUsage]) -> None:
        """Update cost tracking."""
        if not usage:
            return
        
        model = self.config.model
        costs = self.MODEL_COSTS.get(model, self.MODEL_COSTS.get("gpt-4"))
        
        if costs:
            input_cost = (usage.prompt_tokens / 1000) * costs["input"]
            output_cost = (usage.completion_tokens / 1000) * costs["output"]
            self._total_cost += input_cost + output_cost
    
    def _validate_json_schema(
        self,
        data: Dict[str, Any],
        schema: Dict[str, Any]
    ) -> None:
        """Validate JSON data against schema."""
        required = schema.get("required", [])
        for field in required:
            if field not in data:
                raise InvalidResponseError(
                    f"Missing required field: {field}",
                    provider=self.provider_name
                )
    
    def get_cost_stats(self) -> Dict[str, Any]:
        """Get cost and usage statistics."""
        return {
            "provider": self.provider_name,
            "model": self.config.model,
            "total_cost_usd": round(self._total_cost, 6),
            "session_tokens": self._session_tokens,
            "request_count": self._request_count,
            "error_count": self._error_count,
        }
