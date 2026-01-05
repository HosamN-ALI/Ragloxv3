#!/usr/bin/env python3
"""
Test LLM Service for RAGLOX v3.0
Tests the Blackbox AI provider functionality
"""

import asyncio
import logging
import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.config import get_settings
from core.llm import LLMService, BlackboxAIProvider, LLMConfig
from core.llm.base import ProviderType, LLMMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_llm_service():
    """Test LLM service with Blackbox AI provider"""
    
    print("🧪 Testing LLM Service (Blackbox AI)...")
    
    # Get settings
    settings = get_settings()
    
    print(f"📄 LLM Provider: {settings.llm_provider}")
    print(f"🎯 LLM Model: {settings.llm_model}")
    print(f"🔑 API Key configured: {'Yes' if settings.effective_llm_api_key else 'No'}")
    
    # Test direct provider initialization
    try:
        config = LLMConfig(
            provider_type=ProviderType.OPENAI,
            api_key=settings.effective_llm_api_key,
            api_base=settings.llm_api_base or "https://api.blackbox.ai",
            model=settings.llm_model or "blackboxai/openai/gpt-4o-mini",
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
            timeout=settings.llm_timeout,
        )
        
        print("\n🤖 Initializing Blackbox AI provider...")
        provider = BlackboxAIProvider(config)
        
        # Test provider health check
        print("\n🏥 Testing provider health check...")
        health_status = await provider.health_check()
        print(f"✅ Provider health: {'Healthy' if health_status else 'Unhealthy'}")
        
        if health_status:
            # Test simple message
            print("\n💬 Testing simple message generation...")
            messages = [LLMMessage.user("Hello, this is a test. Please respond with 'Test successful!'")]
            
            response = await provider.generate(messages, max_tokens=20)
            print(f"📤 Response received: {response.content.strip()}")
            print(f"⏱️  Latency: {response.latency_ms:.2f}ms")
            print(f"📊 Tokens used: {response.usage.total_tokens}")
            print(f"🏁 Finish reason: {response.finish_reason}")
            
            # Test analysis functionality
            print("\n🧠 Testing analysis functionality...")
            from core.llm.models import AnalysisRequest
            
            request = AnalysisRequest(
                task_type="recon",
                task_description="Test task for LLM analysis",
                success=False,
                error="Connection timeout to target host",
                context_data={"target_ip": "192.168.1.1", "port": 80}
            )
            
            from core.llm.service import get_llm_service
            from core.llm.prompts import REFLEXION_SYSTEM_PROMPT, build_analysis_prompt
            
            service = get_llm_service()
            service.register_provider("test-blackbox", provider, set_as_default=True)
            
            messages = [
                LLMMessage.system(REFLEXION_SYSTEM_PROMPT),
                LLMMessage.user(build_analysis_prompt(request))
            ]
            
            response = await service.generate(messages)
            
            try:
                from core.llm.prompts import extract_json_from_response
                json_result = extract_json_from_response(response.content)
                print(f"🎯 Successfully generated analysis JSON: {json_result.get('decision', 'unknown')}")
                
                # Validate with Pydantic
                from core.llm.models import FailureAnalysis
                analysis = FailureAnalysis.model_validate(json_result)
                print(f"✅ Analysis validation passed: {analysis.decision}")
                
            except Exception as e:
                print(f"⚠️  JSON extraction failed: {e}")
                print(f"Raw response: {response.content[:200]}...")
        
        # Test service-wide functionality
        print("\n🌐 Testing global LLM service...")
        service = get_llm_service()
        
        # Register additional providers
        service.register_provider("blackbox-main", provider, set_as_default=True)
        
        print(f"📊 Registered providers: {list(service.providers.keys())}")
        print(f"🔧 Default provider: {service.default_provider_name}")
        print(f"📈 Service stats: {service.get_stats()}")
        
        print("\n✅ LLM Service tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ LLM Service test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    print("🚀 Starting LLM Service test for RAGLOX v3.0")
    print("=" * 50)
    
    try:
        success = asyncio.run(test_llm_service())
        if success:
            print("\n🏆 All LLM tests passed!")
            sys.exit(0)
        else:
            print("\n💥 LLM tests failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚡ Test interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n🔥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)