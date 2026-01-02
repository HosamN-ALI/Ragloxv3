# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - FastAPI Application
# Main API entry point
# ═══════════════════════════════════════════════════════════════

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ..core.config import get_settings
from ..core.blackboard import Blackboard
from ..core.knowledge import EmbeddedKnowledge, init_knowledge
from ..controller.mission import MissionController
from .routes import router
from .websocket import websocket_router
from .knowledge_routes import router as knowledge_router


# Global instances
blackboard: Blackboard = None
controller: MissionController = None
knowledge: EmbeddedKnowledge = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager."""
    global blackboard, controller, knowledge
    
    settings = get_settings()
    
    # Initialize Knowledge Base (in-memory, fast)
    knowledge = init_knowledge(data_path=settings.knowledge_data_path)
    app.state.knowledge = knowledge
    
    if knowledge.is_loaded():
        stats = knowledge.get_statistics()
        print(f"📚 Knowledge base loaded: {stats['total_rx_modules']} modules, {stats['total_techniques']} techniques")
    else:
        print("⚠️ Knowledge base not loaded - check data path")
    
    # Initialize Blackboard
    blackboard = Blackboard(settings=settings)
    await blackboard.connect()
    
    # Initialize Controller
    controller = MissionController(blackboard=blackboard, settings=settings)
    
    # Store in app state
    app.state.blackboard = blackboard
    app.state.controller = controller
    
    print("🚀 RAGLOX v3.0 API started")
    
    yield
    
    # Cleanup
    print("🛑 Shutting down RAGLOX...")
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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(router, prefix="/api/v1")
    app.include_router(knowledge_router, prefix="/api/v1")
    app.include_router(websocket_router)
    
    return app


# Create app instance
app = create_app()


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
