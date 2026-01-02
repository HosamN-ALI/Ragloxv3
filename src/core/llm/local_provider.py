# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Local LLM Provider
# LLM provider for local/self-hosted models (Ollama, vLLM, LocalAI)
# All use OpenAI-compatible API format
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


class LocalLLMProvider(LLMProvider):
    """
    Local LLM provider for self-hosted models.
    
    Supports any OpenAI-compatible API:
    - Ollama (http://localhost:11434/v1)
    - vLLM (http://localhost:8000/v1)
    - LocalAI (http://localhost:8080/v1)
    - text-generation-webui (with openai extension)
    - LM Studio
    - Any other OpenAI-compatible endpoint
    
    Example usage:
        config = LLMConfig(
            provider_type=ProviderType.LOCAL,
            api_base="http://localhost:11434/v1",  # Ollama
            model="llama3.2:latest",
        )
        provider = LocalLLMProvider(config)
    """
    
    # Common default endpoints
    DEFAULT_ENDPOINTS = {
        "ollama": "http://localhost:11434/v1",
        "vllm": "http://localhost:8000/v1",
        "localai": "http://localhost:8080/v1",
        "lmstudio": "http://localhost:1234/v1",
        "textgen": "http://localhost:5000/v1",
    }
    
    # Common models for each platform
    COMMON_MODELS = {
        "ollama": [
            "llama3.2:latest",
            "llama3.1:8b",
            "llama3.1:70b",
            "mistral:latest",
            "mixtral:latest",
            "codellama:latest",
            "qwen2.5:latest",
            "deepseek-r1:latest",
        ],
        "vllm": [
            "meta-llama/Llama-3.1-8B-Instruct",
            "meta-llama/Llama-3.1-70B-Instruct",
            "mistralai/Mistral-7B-Instruct-v0.3",
            "Qwen/Qwen2.5-7B-Instruct",
        ],
        "generic": [
            "local-model",
        ],
    }
    
    def __init__(self, config: LLMConfig):
        """
        Initialize Local LLM provider.
        
        Args:
            config: LLM configuration with api_base URL
        """
        super().__init__(config)
        
        # Set default base URL if not provided
        if not config.api_base:
            config.api_base = self.DEFAULT_ENDPOINTS["ollama"]
            self.logger.info(f"No api_base provided, defaulting to Ollama: {config.api_base}")
        
        self.base_url = config.api_base.rstrip('/')
        self._client: Optional[httpx.AsyncClient] = None
        self._available_models_cache: Optional[List[str]] = None
        self._cache_time: Optional[float] = None
        self._cache_ttl = 300  # 5 minutes cache
        
        # Detect platform from URL
        self.platform = self._detect_platform()
        self.logger.info(f"LocalLLMProvider initialized with platform: {self.platform}")
    
    @property
    def provider_name(self) -> str:
        return f"local-{self.platform}"
    
    @property
    def available_models(self) -> List[str]:
        """Get list of common models for this platform."""
        return self.COMMON_MODELS.get(self.platform, self.COMMON_MODELS["generic"]).copy()
    
    def _detect_platform(self) -> str:
        """Detect the LLM platform from the base URL."""
        url_lower = self.base_url.lower()
        
        if "11434" in url_lower:
            return "ollama"
        elif "8000" in url_lower:
            return "vllm"
        elif "8080" in url_lower:
            return "localai"
        elif "1234" in url_lower:
            return "lmstudio"
        elif "5000" in url_lower or "5001" in url_lower:
            return "textgen"
        else:
            return "generic"
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            headers = {"Content-Type": "application/json"}
            
            # Add authorization header if API key provided
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"
            
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
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
    
    async def list_models(self) -> List[str]:
        """
        List available models from the server.
        
        Returns:
            List of model names
        """
        # Check cache
        now = time.time()
        if self._available_models_cache and self._cache_time:
            if now - self._cache_time < self._cache_ttl:
                return self._available_models_cache
        
        try:
            client = await self._get_client()
            
            # Try OpenAI-compatible endpoint first
            try:
                response = await client.get("/models")
                if response.status_code == 200:
                    data = response.json()
                    models = [m.get("id", m.get("name", "")) for m in data.get("data", [])]
                    self._available_models_cache = models
                    self._cache_time = now
                    return models
            except Exception:
                pass
            
            # Try Ollama-specific endpoint
            if self.platform == "ollama":
                try:
                    # Ollama uses /api/tags outside of /v1
                    ollama_client = httpx.AsyncClient(
                        base_url=self.base_url.replace("/v1", ""),
                        timeout=self.config.timeout
                    )
                    response = await ollama_client.get("/api/tags")
                    await ollama_client.aclose()
                    
                    if response.status_code == 200:
                        data = response.json()
                        models = [m.get("name", "") for m in data.get("models", [])]
                        self._available_models_cache = models
                        self._cache_time = now
                        return models
                except Exception:
                    pass
            
            # Return common models as fallback
            return self.available_models
            
        except Exception as e:
            self.logger.warning(f"Failed to list models: {e}")
            return self.available_models
    
    async def generate(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response from local LLM.
        
        Args:
            messages: List of conversation messages
            **kwargs: Additional parameters (temperature, max_tokens, etc.)
            
        Returns:
            LLM response
        """
        self._validate_messages(messages)
        
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
        
        return response
    
    async def generate_json(
        self,
        messages: List[LLMMessage],
        schema: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a JSON response from local LLM.
        
        Note: Not all local models support JSON mode. We'll add
        instructions to the prompt to encourage JSON output.
        
        Args:
            messages: List of conversation messages
            schema: Optional JSON schema for validation
            **kwargs: Additional parameters
            
        Returns:
            Parsed JSON response
        """
        # Try to enable JSON mode if supported
        if self.platform in ["vllm", "localai", "lmstudio"]:
            kwargs["response_format"] = {"type": "json_object"}
        
        # For Ollama and others, add JSON instruction to last message
        elif messages:
            last_msg = messages[-1]
            if not last_msg.content.strip().endswith("Respond with valid JSON only."):
                last_msg.content += "\n\nRespond with valid JSON only."
        
        # Generate response
        response = await self.generate(messages, **kwargs)
        
        # Parse JSON from response
        try:
            if response.parsed_json:
                result = response.parsed_json
            else:
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
        """Check if local LLM server is accessible."""
        try:
            client = await self._get_client()
            
            # Try models endpoint
            try:
                response = await client.get("/models")
                if response.status_code == 200:
                    return True
            except Exception:
                pass
            
            # Try Ollama-specific health check
            if self.platform == "ollama":
                try:
                    ollama_client = httpx.AsyncClient(
                        base_url=self.base_url.replace("/v1", ""),
                        timeout=5.0
                    )
                    response = await ollama_client.get("/")
                    await ollama_client.aclose()
                    if response.status_code == 200:
                        return True
                except Exception:
                    pass
            
            return False
            
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
            "stream": False,  # We don't support streaming yet
        }
        
        # Add optional parameters
        if kwargs.get("top_p") is not None or self.config.top_p != 1.0:
            request["top_p"] = kwargs.get("top_p", self.config.top_p)
        
        if kwargs.get("frequency_penalty") or self.config.frequency_penalty:
            request["frequency_penalty"] = kwargs.get(
                "frequency_penalty", self.config.frequency_penalty
            )
        
        if kwargs.get("presence_penalty") or self.config.presence_penalty:
            request["presence_penalty"] = kwargs.get(
                "presence_penalty", self.config.presence_penalty
            )
        
        # Add response format if specified (for compatible servers)
        if kwargs.get("response_format"):
            request["response_format"] = kwargs["response_format"]
        
        # Add stop sequences if specified
        if kwargs.get("stop"):
            request["stop"] = kwargs["stop"]
        
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
                    # Rate limited (some local servers implement this)
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
                    
                    error_message = error_data.get("message", "Unknown error")
                    
                    # Check for context length error
                    if any(x in error_message.lower() for x in ["context", "length", "token"]):
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
                
                elif response.status_code == 503:
                    # Service unavailable - model might be loading
                    if attempt < self.config.max_retries:
                        self.logger.warning(f"Service unavailable, retrying in {delay}s")
                        await asyncio.sleep(delay)
                        delay *= self.config.retry_multiplier
                        continue
                    raise LLMError(
                        "Service unavailable (model may be loading)",
                        provider=self.provider_name
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
                    
            except httpx.ConnectError as e:
                last_error = e
                if attempt < self.config.max_retries:
                    self.logger.warning(
                        f"Connection failed to {self.base_url}, retrying in {delay}s"
                    )
                    await asyncio.sleep(delay)
                    delay *= self.config.retry_multiplier
                    continue
                    
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
        
        # Parse usage (may not be present in all local models)
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


# ═══════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════

def create_ollama_provider(
    model: str = "llama3.2:latest",
    base_url: str = "http://localhost:11434/v1",
    **kwargs
) -> LocalLLMProvider:
    """
    Create an Ollama provider with sensible defaults.
    
    Args:
        model: Model name (e.g., "llama3.2:latest", "mistral:latest")
        base_url: Ollama server URL
        **kwargs: Additional LLMConfig parameters
        
    Returns:
        Configured LocalLLMProvider
    """
    config = LLMConfig(
        api_base=base_url,
        model=model,
        **kwargs
    )
    return LocalLLMProvider(config)


def create_vllm_provider(
    model: str = "meta-llama/Llama-3.1-8B-Instruct",
    base_url: str = "http://localhost:8000/v1",
    api_key: Optional[str] = None,
    **kwargs
) -> LocalLLMProvider:
    """
    Create a vLLM provider with sensible defaults.
    
    Args:
        model: Model name (HuggingFace model ID)
        base_url: vLLM server URL
        api_key: Optional API key if vLLM is configured with auth
        **kwargs: Additional LLMConfig parameters
        
    Returns:
        Configured LocalLLMProvider
    """
    config = LLMConfig(
        api_base=base_url,
        model=model,
        api_key=api_key,
        **kwargs
    )
    return LocalLLMProvider(config)
