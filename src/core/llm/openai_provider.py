# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - OpenAI Provider
# LLM provider for OpenAI API (GPT-4, GPT-3.5)
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


class OpenAIProvider(LLMProvider):
    """
    OpenAI API provider for GPT models.
    
    Supports:
    - GPT-4, GPT-4-Turbo, GPT-4o
    - GPT-3.5-Turbo
    - JSON mode for structured output
    - Automatic retry with exponential backoff
    - Rate limiting
    """
    
    DEFAULT_BASE_URL = "https://api.openai.com/v1"
    
    AVAILABLE_MODELS = [
        "gpt-4o",
        "gpt-4o-mini",
        "gpt-4-turbo",
        "gpt-4-turbo-preview",
        "gpt-4",
        "gpt-4-0613",
        "gpt-3.5-turbo",
        "gpt-3.5-turbo-0125",
        "gpt-3.5-turbo-16k",
    ]
    
    def __init__(self, config: LLMConfig):
        """
        Initialize OpenAI provider.
        
        Args:
            config: LLM configuration with API key
        """
        super().__init__(config)
        
        if not config.api_key:
            raise ValueError("OpenAI API key is required")
        
        self.base_url = config.api_base or self.DEFAULT_BASE_URL
        self._client: Optional[httpx.AsyncClient] = None
        
        # Rate limiting state
        self._request_times: List[float] = []
        self._token_counts: List[tuple[float, int]] = []
    
    @property
    def provider_name(self) -> str:
        return "openai"
    
    @property
    def available_models(self) -> List[str]:
        return self.AVAILABLE_MODELS.copy()
    
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
        Generate a response from OpenAI.
        
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
        
        # Update stats
        self._update_stats(response)
        self._record_request(response.usage)
        
        return response
    
    async def generate_json(
        self,
        messages: List[LLMMessage],
        schema: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a JSON response from OpenAI.
        
        Uses JSON mode for guaranteed valid JSON output.
        
        Args:
            messages: List of conversation messages
            schema: Optional JSON schema for validation
            **kwargs: Additional parameters
            
        Returns:
            Parsed JSON response
        """
        # Enable JSON mode
        kwargs["response_format"] = {"type": "json_object"}
        
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
        """Check if OpenAI API is accessible."""
        try:
            client = await self._get_client()
            response = await client.get("/models")
            return response.status_code == 200
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
        request = {
            "model": kwargs.get("model", self.config.model),
            "messages": [msg.to_dict() for msg in messages],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "top_p": kwargs.get("top_p", self.config.top_p),
            "frequency_penalty": kwargs.get("frequency_penalty", self.config.frequency_penalty),
            "presence_penalty": kwargs.get("presence_penalty", self.config.presence_penalty),
        }
        
        # Add response format if specified
        if kwargs.get("response_format"):
            request["response_format"] = kwargs["response_format"]
        
        # Add functions/tools if specified
        if kwargs.get("functions"):
            request["functions"] = kwargs["functions"]
        if kwargs.get("tools"):
            request["tools"] = kwargs["tools"]
        
        return request
    
    async def _make_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Make API request with retry logic."""
        last_error = None
        delay = self.config.retry_delay
        
        for attempt in range(self.config.max_retries + 1):
            try:
                client = await self._get_client()
                response = await client.post(
                    "/chat/completions",
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
                    error_data = response.json().get("error", {})
                    error_type = error_data.get("type", "")
                    
                    if "context_length" in error_type.lower() or "context_length" in error_data.get("message", "").lower():
                        raise ContextLengthError(
                            tokens_used=0,  # Would need to count
                            max_tokens=0,
                            provider=self.provider_name
                        )
                    
                    raise LLMError(
                        f"Bad request: {error_data.get('message', 'Unknown error')}",
                        provider=self.provider_name,
                        details=error_data
                    )
                
                else:
                    error_data = response.json() if response.content else {}
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
    
    def _validate_json_schema(
        self,
        data: Dict[str, Any],
        schema: Dict[str, Any]
    ) -> None:
        """Validate JSON data against schema."""
        # Basic schema validation
        # For full validation, use jsonschema library
        required = schema.get("required", [])
        for field in required:
            if field not in data:
                raise InvalidResponseError(
                    f"Missing required field: {field}",
                    provider=self.provider_name
                )
