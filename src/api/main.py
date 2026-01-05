# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - FastAPI Application
# Main API entry point
# ═══════════════════════════════════════════════════════════════

import logging
import signal
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from ..core.config import get_settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("raglox")
from ..core.blackboard import Blackboard
from ..core.knowledge import EmbeddedKnowledge, init_knowledge
from ..controller.mission import MissionController
from .routes import router
from .websocket import websocket_router
from .knowledge_routes import router as knowledge_router
from .exploitation_routes import router as exploitation_router

# ═══════════════════════════════════════════════════════════════
# INTEGRATION: Shutdown Manager
# ═══════════════════════════════════════════════════════════════
from ..core.shutdown_manager import ShutdownManager, get_shutdown_manager


# Global instances
blackboard: Blackboard = None
controller: MissionController = None
knowledge: EmbeddedKnowledge = None
shutdown_manager: ShutdownManager = None


def init_llm_service(settings) -> None:
    """Initialize LLM service with configured provider."""
    try:
        from ..core.llm import (
            LLMService, 
            get_llm_service, 
            BlackboxAIProvider,
            OpenAIProvider,
            MockLLMProvider,
            LLMConfig
        )
        from ..core.llm.base import ProviderType
        
        service = get_llm_service()
        
        # Get API key from settings
        api_key = settings.effective_llm_api_key
        provider_name = settings.llm_provider.lower()
        
        if not api_key:
            logger.warning("No LLM API key configured - using mock provider")
            provider_name = "mock"
        
        # Configure based on provider
        if provider_name == "blackbox":
            config = LLMConfig(
                provider_type=ProviderType.OPENAI,  # BlackBox uses OpenAI-compatible API
                api_key=api_key,
                api_base="https://api.blackbox.ai",  # Base URL only, provider adds /v1/chat/completions
                model=settings.llm_model or "blackboxai/openai/gpt-4o-mini",
                temperature=settings.llm_temperature,
                max_tokens=settings.llm_max_tokens,
                timeout=settings.llm_timeout,
            )
            provider = BlackboxAIProvider(config)
            service.register_provider("blackbox", provider)
            logger.info("🤖 LLM Service initialized with BlackBox AI provider")
            
        elif provider_name == "openai":
            config = LLMConfig(
                provider_type=ProviderType.OPENAI,
                api_key=api_key,
                api_base=settings.llm_api_base,
                model=settings.llm_model or "gpt-4",
                temperature=settings.llm_temperature,
                max_tokens=settings.llm_max_tokens,
                timeout=settings.llm_timeout,
            )
            provider = OpenAIProvider(config)
            service.register_provider("openai", provider)
            logger.info("🤖 LLM Service initialized with OpenAI provider")
            
        else:
            # Use mock provider for testing
            config = LLMConfig(provider_type=ProviderType.MOCK)
            provider = MockLLMProvider(config)
            service.register_provider("mock", provider)
            logger.info("🤖 LLM Service initialized with Mock provider")
            
    except Exception as e:
        logger.error(f"Failed to initialize LLM service: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager."""
    global blackboard, controller, knowledge, shutdown_manager
    
    settings = get_settings()
    
    # ═══════════════════════════════════════════════════════════════
    # INTEGRATION: Initialize Shutdown Manager
    # ═══════════════════════════════════════════════════════════════
    shutdown_manager = get_shutdown_manager()
    logger.info("🛡️ Shutdown Manager initialized")
    
    # ═══════════════════════════════════════════════════════════════
    # INTEGRATION: Initialize Metasploit & Exploitation Framework
    # ═══════════════════════════════════════════════════════════════
    metasploit_adapter = None
    if settings.use_real_exploits:
        try:
            from ..exploitation.adapters.metasploit_adapter import get_metasploit_adapter
            logger.info("🎯 Real Exploitation ENABLED - Initializing Metasploit RPC...")
            logger.info(f"   MSF RPC: {settings.msf_rpc_host}:{settings.msf_rpc_port}")
            
            metasploit_adapter = get_metasploit_adapter(
                host=settings.msf_rpc_host,
                port=settings.msf_rpc_port,
                username=settings.msf_rpc_user,
                password=settings.msf_rpc_pass,
                ssl=settings.msf_rpc_ssl
            )
            
            # Test connection
            if metasploit_adapter.connect():
                logger.info("✅ Metasploit RPC Connected Successfully")
                version = metasploit_adapter.get_version()
                exploits = metasploit_adapter.list_exploits()
                logger.info(f"   Metasploit Version: {version}")
                logger.info(f"   Available Modules: {len(exploits) if exploits else 0}")
                
                # Register for graceful shutdown
                shutdown_manager.register(
                    name="metasploit_adapter",
                    shutdown_func=metasploit_adapter.disconnect,
                    priority=40,
                    timeout=10.0
                )
            else:
                logger.error("❌ Failed to connect to Metasploit RPC")
                logger.warning("   Falling back to SIMULATION mode")
                metasploit_adapter = None
        except Exception as e:
            logger.error(f"❌ Metasploit initialization failed: {e}")
            logger.warning("   Falling back to SIMULATION mode")
            metasploit_adapter = None
    else:
        logger.info("🔵 Real Exploitation DISABLED (USE_REAL_EXPLOITS=false)")
        logger.info("   System running in SIMULATION mode")
    
    # Store MetasploitAdapter in app state for global access
    app.state.metasploit_adapter = metasploit_adapter
    app.state.use_real_exploits = settings.use_real_exploits and metasploit_adapter is not None
    
    # ═══════════════════════════════════════════════════════════════
    # INTEGRATION: Initialize C2 Session Manager
    # ═══════════════════════════════════════════════════════════════
    c2_manager = None
    if settings.use_real_exploits:
        try:
            from ..exploitation.c2.session_manager import C2SessionManager
            logger.info("🌐 Initializing C2 Session Manager...")
            
            c2_manager = C2SessionManager(
                encryption_enabled=settings.c2_encryption_enabled,
                data_dir=settings.c2_data_dir
            )
            
            logger.info(f"✅ C2 Session Manager Initialized")
            logger.info(f"   Encryption: {'Enabled (AES-256-GCM)' if settings.c2_encryption_enabled else 'Disabled'}")
            logger.info(f"   Data Directory: {settings.c2_data_dir}")
            
            # Register for graceful shutdown
            shutdown_manager.register(
                name="c2_session_manager",
                shutdown_func=c2_manager.cleanup_all_sessions,
                priority=35,
                timeout=15.0
            )
        except Exception as e:
            logger.error(f"❌ C2 Session Manager initialization failed: {e}")
            c2_manager = None
    
    # Store C2SessionManager in app state
    app.state.c2_manager = c2_manager
    
    # Initialize Knowledge Base (in-memory, fast)
    knowledge = init_knowledge(data_path=settings.knowledge_data_path)
    app.state.knowledge = knowledge
    
    if knowledge.is_loaded():
        stats = knowledge.get_statistics()
        print(f"📚 Knowledge base loaded: {stats['total_rx_modules']} modules, {stats['total_techniques']} techniques")
    else:
        print("⚠️ Knowledge base not loaded - check data path")
    
    # Initialize LLM Service
    if settings.llm_enabled:
        init_llm_service(settings)
    else:
        logger.info("LLM service disabled in settings")
    
    # Initialize Blackboard
    blackboard = Blackboard(settings=settings)
    await blackboard.connect()
    
    # Initialize Controller
    controller = MissionController(blackboard=blackboard, settings=settings)
    
    # ═══════════════════════════════════════════════════════════════
    # INTEGRATION: Register components with Shutdown Manager
    # ═══════════════════════════════════════════════════════════════
    # Note: MissionController already registers itself in __init__
    
    # Register Blackboard for graceful disconnection
    shutdown_manager.register_component(
        name="blackboard",
        component=blackboard,
        priority=50,  # After controller
        shutdown_timeout=30.0,
        shutdown_method="disconnect"
    )
    
    # Store in app state
    app.state.blackboard = blackboard
    app.state.controller = controller
    app.state.shutdown_manager = shutdown_manager
    
    # ═══════════════════════════════════════════════════════════════
    # INTEGRATION: Setup signal handlers for graceful shutdown
    # ═══════════════════════════════════════════════════════════════
    def signal_handler(signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        shutdown_manager.shutdown(signum, frame)
    
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    print("🚀 RAGLOX v3.0 API started")
    print("🛡️ Graceful shutdown enabled (SIGTERM/SIGINT)")
    
    yield
    
    # ═══════════════════════════════════════════════════════════════
    # INTEGRATION: Graceful Shutdown
    # ═══════════════════════════════════════════════════════════════
    print("🛑 Shutting down RAGLOX...")
    
    # Use ShutdownManager for coordinated shutdown
    if shutdown_manager:
        logger.info("Initiating graceful shutdown via ShutdownManager...")
        await shutdown_manager.shutdown_async()
    else:
        # Fallback to manual shutdown
        logger.warning("ShutdownManager not available, using fallback shutdown")
        await controller.shutdown()
        await blackboard.disconnect()
    
    print("✓ RAGLOX shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="RAGLOX",
        description="Red Team Automation Platform with Blackboard Architecture",
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    
    # CORS middleware
    # Note: allow_origins=["*"] cannot be used with allow_credentials=True
    # For development, we allow all origins without credentials
    # For production, specify exact origins with credentials
    cors_origins = settings.cors_origins_list
    
    # If wildcard, credentials must be False (per CORS spec)
    allow_creds = False if "*" in cors_origins else True
    
    # Debug: Print CORS configuration
    print(f"🔧 CORS Configuration: origins={cors_origins}, credentials={allow_creds}")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=allow_creds,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=3600,  # Cache preflight response for 1 hour
    )
    
    # Include routers
    app.include_router(router, prefix="/api/v1")
    app.include_router(knowledge_router, prefix="/api/v1")
    app.include_router(exploitation_router, prefix="/api/v1")
    app.include_router(websocket_router)
    
    return app


# Create app instance
app = create_app()


# ═══════════════════════════════════════════════════════════════
# Global Exception Handler (ensures CORS headers are included)
# ═══════════════════════════════════════════════════════════════

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Global exception handler that ensures CORS headers are included
    in error responses. Without this, 500 errors would not include
    CORS headers and be blocked by browsers.
    """
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Get CORS settings
    settings = get_settings()
    cors_origins = settings.cors_origins_list
    
    # Determine origin header to return
    origin = request.headers.get("origin", "*")
    if "*" not in cors_origins:
        # If we have specific origins, only return it if it's allowed
        if origin not in cors_origins:
            origin = cors_origins[0] if cors_origins else "*"
    
    response = JSONResponse(
        status_code=500,
        content={
            "detail": f"Internal server error: {str(exc)}",
            "type": type(exc).__name__
        }
    )
    
    # Add CORS headers manually
    response.headers["Access-Control-Allow-Origin"] = "*" if "*" in cors_origins else origin
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "*"
    
    return response


@app.get("/", tags=["Root"])
async def root():
    """Root endpoint."""
    return {
        "name": "RAGLOX",
        "version": "3.0.0",
        "architecture": "Blackboard",
        "status": "operational"
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    blackboard_healthy = False
    knowledge_loaded = False
    
    if hasattr(app.state, 'blackboard') and app.state.blackboard:
        blackboard_healthy = await app.state.blackboard.health_check()
    
    if hasattr(app.state, 'knowledge') and app.state.knowledge:
        knowledge_loaded = app.state.knowledge.is_loaded()
    
    all_healthy = blackboard_healthy and knowledge_loaded
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "components": {
            "api": "healthy",
            "blackboard": "healthy" if blackboard_healthy else "unhealthy",
            "knowledge": "loaded" if knowledge_loaded else "not_loaded"
        }
    }
