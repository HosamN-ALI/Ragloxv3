# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - LLM Integration Layer
# Integration with Large Language Models for Reflexion Pattern
# ═══════════════════════════════════════════════════════════════
#
# This module provides LLM integration for intelligent analysis:
# - Abstract LLMProvider interface for multiple backends
# - OpenAI API integration (GPT-4, GPT-3.5)
# - Local LLM support (Ollama, vLLM, LocalAI)
# - Structured output with Pydantic validation
# - Rate limiting and retry logic
#
# Architecture:
# ┌─────────────────────────────────────────────────────────────┐
# │                  AnalysisSpecialist                          │
# │              (Reflexion Pattern)                             │
# └──────────────────────────┬──────────────────────────────────┘
#                            │
#                            ▼
# ┌─────────────────────────────────────────────────────────────┐
# │                    LLMService                                │
# │    (Manages providers, caching, rate limiting)              │
# └──────────────────────────┬──────────────────────────────────┘
#                            │
#            ┌───────────────┼───────────────┐
#            ▼               ▼               ▼
# ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
# │ OpenAIProvider │ │ LocalLLMProvider│ │ MockProvider  │
# │  (GPT-4)       │ │ (Ollama/vLLM)  │ │  (Testing)    │
# └────────────────┘ └────────────────┘ └────────────────┘
#
# ═══════════════════════════════════════════════════════════════

from .base import (
    LLMProvider,
    LLMMessage,
    LLMResponse,
    LLMConfig,
    LLMError,
    RateLimitError,
    ModelNotAvailableError,
    InvalidResponseError,
)

from .openai_provider import OpenAIProvider
from .blackbox_provider import BlackboxAIProvider
from .local_provider import LocalLLMProvider
from .mock_provider import MockLLMProvider

from .service import (
    LLMService,
    get_llm_service,
)

from .models import (
    AnalysisRequest,
    AnalysisResponse,
    FailureAnalysis,
    RecommendedAction,
    AlternativeModule,
    DecisionType,
)

from .prompts import (
    REFLEXION_SYSTEM_PROMPT,
    FAILURE_ANALYSIS_PROMPT,
    MODULE_SELECTION_PROMPT,
    build_analysis_prompt,
    build_module_selection_prompt,
)

__all__ = [
    # Base classes
    "LLMProvider",
    "LLMMessage",
    "LLMResponse",
    "LLMConfig",
    
    # Errors
    "LLMError",
    "RateLimitError",
    "ModelNotAvailableError",
    "InvalidResponseError",
    
    # Providers
    "OpenAIProvider",
    "BlackboxAIProvider",
    "LocalLLMProvider",
    "MockLLMProvider",
    
    # Service
    "LLMService",
    "get_llm_service",
    
    # Models
    "AnalysisRequest",
    "AnalysisResponse",
    "FailureAnalysis",
    "RecommendedAction",
    "AlternativeModule",
    "DecisionType",
    
    # Prompts
    "REFLEXION_SYSTEM_PROMPT",
    "FAILURE_ANALYSIS_PROMPT",
    "MODULE_SELECTION_PROMPT",
    "build_analysis_prompt",
    "build_module_selection_prompt",
]

__version__ = "3.0.0"
