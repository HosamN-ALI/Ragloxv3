# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - LLM Service
# Central service for managing LLM providers and analysis
# ═══════════════════════════════════════════════════════════════

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Type, Union

from pydantic import ValidationError

from .base import (
    LLMProvider,
    LLMConfig,
    LLMMessage,
    LLMResponse,
    ProviderType,
    LLMError,
    InvalidResponseError,
)
from .models import (
    AnalysisRequest,
    AnalysisResponse,
    FailureAnalysis,
    ModuleSelectionResponse,
    DecisionType,
    ConfidenceLevel,
    FailureCategory,
    RecommendedAction,
    RootCauseAnalysis,
)
from .prompts import (
    REFLEXION_SYSTEM_PROMPT,
    build_analysis_prompt,
    build_module_selection_prompt,
    extract_json_from_response,
)


# Global service instance
_llm_service: Optional["LLMService"] = None


class LLMService:
    """
    Central service for LLM operations.
    
    Manages multiple providers, handles failover, and provides
    high-level analysis functions.
    
    Features:
    - Multi-provider support with automatic failover
    - Response caching (optional)
    - Structured output validation with Pydantic
    - Rate limiting across providers
    - Statistics and monitoring
    
    Example usage:
        # Initialize service
        service = LLMService()
        service.register_provider("openai", OpenAIProvider(config))
        
        # Analyze failure
        analysis = await service.analyze_failure(request)
        
        # Or use singleton
        service = get_llm_service()
    """
    
    def __init__(
        self,
        default_provider: Optional[str] = None,
        enable_fallback: bool = True,
        enable_caching: bool = False,
        cache_ttl_seconds: int = 300,
    ):
        """
        Initialize LLM service.
        
        Args:
            default_provider: Name of the default provider to use
            enable_fallback: Enable automatic failover to backup providers
            enable_caching: Enable response caching
            cache_ttl_seconds: Cache TTL in seconds
        """
        self.logger = logging.getLogger("raglox.llm.service")
        
        self._providers: Dict[str, LLMProvider] = {}
        self._provider_priority: List[str] = []
        self._default_provider = default_provider
        self._enable_fallback = enable_fallback
        
        # Caching
        self._enable_caching = enable_caching
        self._cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, tuple[datetime, Any]] = {}
        
        # Statistics
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "cache_hits": 0,
            "failovers": 0,
            "total_tokens": 0,
            "total_latency_ms": 0.0,
        }
    
    # ═══════════════════════════════════════════════════════════
    # Provider Management
    # ═══════════════════════════════════════════════════════════
    
    def register_provider(
        self,
        name: str,
        provider: LLMProvider,
        priority: int = 100,
        set_as_default: bool = False,
    ) -> "LLMService":
        """
        Register an LLM provider.
        
        Args:
            name: Unique name for the provider
            provider: LLMProvider instance
            priority: Priority for failover (lower = higher priority)
            set_as_default: Set this provider as the default
            
        Returns:
            self for chaining
        """
        self._providers[name] = provider
        
        # Insert in priority order
        if name not in self._provider_priority:
            # Find insertion point
            insert_idx = len(self._provider_priority)
            for i, existing in enumerate(self._provider_priority):
                if priority < 100:  # Default priority
                    insert_idx = i
                    break
            self._provider_priority.insert(insert_idx, name)
        
        if set_as_default or self._default_provider is None:
            self._default_provider = name
        
        self.logger.info(f"Registered provider: {name} ({provider.provider_name})")
        return self
    
    def unregister_provider(self, name: str) -> bool:
        """
        Unregister a provider.
        
        Args:
            name: Provider name
            
        Returns:
            True if removed, False if not found
        """
        if name in self._providers:
            del self._providers[name]
            self._provider_priority.remove(name)
            
            if self._default_provider == name:
                self._default_provider = self._provider_priority[0] if self._provider_priority else None
            
            return True
        return False
    
    def get_provider(self, name: Optional[str] = None) -> Optional[LLMProvider]:
        """
        Get a provider by name.
        
        Args:
            name: Provider name (or None for default)
            
        Returns:
            LLMProvider or None
        """
        name = name or self._default_provider
        return self._providers.get(name) if name else None
    
    @property
    def providers(self) -> Dict[str, LLMProvider]:
        """Get all registered providers."""
        return self._providers.copy()
    
    @property
    def default_provider_name(self) -> Optional[str]:
        """Get the default provider name."""
        return self._default_provider
    
    # ═══════════════════════════════════════════════════════════
    # Core Operations
    # ═══════════════════════════════════════════════════════════
    
    async def generate(
        self,
        messages: List[LLMMessage],
        provider_name: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Generate a response using an LLM provider.
        
        Args:
            messages: List of conversation messages
            provider_name: Specific provider to use (or default)
            **kwargs: Additional generation parameters
            
        Returns:
            LLM response
            
        Raises:
            LLMError: If all providers fail
        """
        self._stats["total_requests"] += 1
        
        # Determine providers to try
        providers_to_try = self._get_providers_to_try(provider_name)
        
        if not providers_to_try:
            raise LLMError("No providers available")
        
        last_error = None
        
        for name in providers_to_try:
            provider = self._providers[name]
            
            try:
                response = await provider.generate(messages, **kwargs)
                
                self._stats["successful_requests"] += 1
                if response.usage:
                    self._stats["total_tokens"] += response.usage.total_tokens
                self._stats["total_latency_ms"] += response.latency_ms
                
                return response
                
            except LLMError as e:
                last_error = e
                self.logger.warning(f"Provider {name} failed: {e}")
                
                if self._enable_fallback and len(providers_to_try) > 1:
                    self._stats["failovers"] += 1
                    continue
                raise
            
            except Exception as e:
                last_error = LLMError(str(e), provider=name)
                self.logger.error(f"Unexpected error from {name}: {e}")
                
                if self._enable_fallback and len(providers_to_try) > 1:
                    self._stats["failovers"] += 1
                    continue
                raise last_error
        
        self._stats["failed_requests"] += 1
        raise last_error or LLMError("All providers failed")
    
    async def generate_json(
        self,
        messages: List[LLMMessage],
        schema: Optional[Dict[str, Any]] = None,
        provider_name: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a JSON response.
        
        Args:
            messages: List of conversation messages
            schema: Optional JSON schema for validation
            provider_name: Specific provider to use
            **kwargs: Additional generation parameters
            
        Returns:
            Parsed JSON response
        """
        providers_to_try = self._get_providers_to_try(provider_name)
        
        if not providers_to_try:
            raise LLMError("No providers available")
        
        last_error = None
        
        for name in providers_to_try:
            provider = self._providers[name]
            
            try:
                result = await provider.generate_json(messages, schema, **kwargs)
                self._stats["successful_requests"] += 1
                return result
                
            except (LLMError, InvalidResponseError) as e:
                last_error = e
                self.logger.warning(f"Provider {name} JSON generation failed: {e}")
                
                if self._enable_fallback:
                    self._stats["failovers"] += 1
                    continue
                raise
        
        self._stats["failed_requests"] += 1
        raise last_error or LLMError("All providers failed for JSON generation")
    
    # ═══════════════════════════════════════════════════════════
    # Failure Analysis (Reflexion Pattern)
    # ═══════════════════════════════════════════════════════════
    
    async def analyze_failure(
        self,
        request: AnalysisRequest,
        provider_name: Optional[str] = None,
    ) -> AnalysisResponse:
        """
        Analyze a task failure and provide recommendations.
        
        This is the core Reflexion pattern implementation.
        
        Args:
            request: Analysis request with task context
            provider_name: Specific provider to use
            
        Returns:
            Structured analysis response
        """
        start_time = datetime.utcnow()
        
        try:
            # Build messages
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(build_analysis_prompt(request)),
            ]
            
            # Generate response
            response = await self.generate(
                messages,
                provider_name=provider_name,
                temperature=0.3,  # Lower temperature for more consistent analysis
                max_tokens=2048,
            )
            
            # Parse JSON response
            try:
                json_data = extract_json_from_response(response.content)
            except ValueError as e:
                self.logger.error(f"Failed to parse LLM response: {e}")
                return self._create_fallback_response(
                    error=f"Invalid JSON response: {e}",
                    model=response.model,
                    latency_ms=response.latency_ms,
                )
            
            # Validate with Pydantic
            try:
                analysis = FailureAnalysis.model_validate(json_data)
            except ValidationError as e:
                self.logger.error(f"Response validation failed: {e}")
                return self._create_fallback_response(
                    error=f"Validation error: {e}",
                    model=response.model,
                    latency_ms=response.latency_ms,
                )
            
            return AnalysisResponse(
                success=True,
                analysis=analysis,
                model_used=response.model,
                tokens_used=response.usage.total_tokens if response.usage else 0,
                latency_ms=response.latency_ms,
            )
            
        except LLMError as e:
            self.logger.error(f"LLM error during analysis: {e}")
            return self._create_fallback_response(error=str(e))
        
        except Exception as e:
            self.logger.error(f"Unexpected error during analysis: {e}")
            return self._create_fallback_response(error=f"Unexpected error: {e}")
    
    async def select_module(
        self,
        task_type: str,
        target_ip: Optional[str],
        target_os: Optional[str],
        technique_id: Optional[str],
        goal: str,
        detected_defenses: List[str],
        available_modules: List[Dict[str, Any]],
        provider_name: Optional[str] = None,
    ) -> Optional[ModuleSelectionResponse]:
        """
        Select the best module for a task using LLM.
        
        Args:
            task_type: Type of task
            target_ip: Target IP address
            target_os: Target operating system
            technique_id: MITRE technique ID
            goal: Goal of the task
            detected_defenses: List of detected defenses
            available_modules: List of available modules
            provider_name: Specific provider to use
            
        Returns:
            Module selection response or None on failure
        """
        from .models import AvailableModule
        
        try:
            # Convert to AvailableModule objects
            modules = [
                AvailableModule(
                    rx_module_id=m.get("rx_module_id", m.get("id", "")),
                    name=m.get("name", ""),
                    description=m.get("description"),
                    technique_id=m.get("technique_id"),
                    supports_evasion=m.get("supports_evasion", False),
                    success_rate=m.get("success_rate"),
                )
                for m in available_modules
            ]
            
            # Build prompt
            prompt = build_module_selection_prompt(
                task_type=task_type,
                target_ip=target_ip,
                target_os=target_os,
                technique_id=technique_id,
                goal=goal,
                detected_defenses=detected_defenses,
                modules=modules,
            )
            
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(prompt),
            ]
            
            response = await self.generate(
                messages,
                provider_name=provider_name,
                temperature=0.2,
            )
            
            json_data = extract_json_from_response(response.content)
            return ModuleSelectionResponse.model_validate(json_data)
            
        except Exception as e:
            self.logger.error(f"Module selection failed: {e}")
            return None
    
    # ═══════════════════════════════════════════════════════════
    # Health & Statistics
    # ═══════════════════════════════════════════════════════════
    
    async def health_check(self) -> Dict[str, bool]:
        """
        Check health of all providers.
        
        Returns:
            Dict mapping provider name to health status
        """
        results = {}
        
        for name, provider in self._providers.items():
            try:
                results[name] = await provider.health_check()
            except Exception as e:
                self.logger.warning(f"Health check failed for {name}: {e}")
                results[name] = False
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics."""
        stats = self._stats.copy()
        
        # Add provider stats
        stats["providers"] = {}
        for name, provider in self._providers.items():
            stats["providers"][name] = provider.get_stats()
        
        # Calculate averages
        if stats["successful_requests"] > 0:
            stats["avg_latency_ms"] = stats["total_latency_ms"] / stats["successful_requests"]
            stats["avg_tokens"] = stats["total_tokens"] / stats["successful_requests"]
        else:
            stats["avg_latency_ms"] = 0
            stats["avg_tokens"] = 0
        
        return stats
    
    async def close(self) -> None:
        """Close all providers."""
        for provider in self._providers.values():
            try:
                await provider.close()
            except Exception as e:
                self.logger.warning(f"Error closing provider: {e}")
    
    # ═══════════════════════════════════════════════════════════
    # Private Methods
    # ═══════════════════════════════════════════════════════════
    
    def _get_providers_to_try(self, provider_name: Optional[str]) -> List[str]:
        """Get list of providers to try in order."""
        if provider_name:
            if provider_name in self._providers:
                return [provider_name]
            return []
        
        if self._enable_fallback:
            return self._provider_priority.copy()
        
        if self._default_provider:
            return [self._default_provider]
        
        return []
    
    def _create_fallback_response(
        self,
        error: str,
        model: str = "unknown",
        latency_ms: float = 0.0,
    ) -> AnalysisResponse:
        """Create a fallback response when LLM fails."""
        return AnalysisResponse(
            success=False,
            analysis=None,
            error=error,
            model_used=model,
            latency_ms=latency_ms,
        )


# ═══════════════════════════════════════════════════════════════
# Service Factory Functions
# ═══════════════════════════════════════════════════════════════

def get_llm_service() -> LLMService:
    """
    Get the global LLM service instance.
    
    Returns:
        Global LLMService instance
    """
    global _llm_service
    
    if _llm_service is None:
        _llm_service = LLMService()
    
    return _llm_service


def init_llm_service(
    config: Optional[Dict[str, Any]] = None,
    providers: Optional[Dict[str, LLMProvider]] = None,
) -> LLMService:
    """
    Initialize the global LLM service.
    
    Args:
        config: Optional configuration dict
        providers: Optional dict of providers to register
        
    Returns:
        Initialized LLMService
    """
    global _llm_service
    
    service = LLMService(
        enable_fallback=config.get("enable_fallback", True) if config else True,
        enable_caching=config.get("enable_caching", False) if config else False,
        cache_ttl_seconds=config.get("cache_ttl_seconds", 300) if config else 300,
    )
    
    if providers:
        for name, provider in providers.items():
            service.register_provider(name, provider)
    
    _llm_service = service
    return service


def reset_llm_service() -> None:
    """Reset the global LLM service instance."""
    global _llm_service
    _llm_service = None


async def create_default_service(
    openai_api_key: Optional[str] = None,
    local_api_base: Optional[str] = None,
    local_model: Optional[str] = None,
    use_mock: bool = False,
) -> LLMService:
    """
    Create a service with common providers configured.
    
    Args:
        openai_api_key: OpenAI API key (enables OpenAI provider)
        local_api_base: Local LLM API base URL (enables local provider)
        local_model: Local model name
        use_mock: Use mock provider (for testing)
        
    Returns:
        Configured LLMService
    """
    service = LLMService()
    
    if use_mock:
        from .mock_provider import MockLLMProvider
        mock = MockLLMProvider()
        mock.setup_analysis_responses()
        service.register_provider("mock", mock, priority=10, set_as_default=True)
        return service
    
    if openai_api_key:
        from .openai_provider import OpenAIProvider
        config = LLMConfig(
            provider_type=ProviderType.OPENAI,
            api_key=openai_api_key,
            model="gpt-4o-mini",
        )
        service.register_provider("openai", OpenAIProvider(config), priority=10)
    
    if local_api_base:
        from .local_provider import LocalLLMProvider
        config = LLMConfig(
            provider_type=ProviderType.LOCAL,
            api_base=local_api_base,
            model=local_model or "llama3.2:latest",
        )
        service.register_provider("local", LocalLLMProvider(config), priority=20)
    
    return service
