#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Application Entry Point
# Run the FastAPI server
# ═══════════════════════════════════════════════════════════════

import uvicorn
from src.core.config import get_settings


def main():
    """Run the RAGLOX API server."""
    settings = get_settings()
    
    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║         RAGLOX v3.0 - Red Team Automation Platform            ║
║              Blackboard Architecture MVP                       ║
╚═══════════════════════════════════════════════════════════════╝
    
Starting server on {settings.api_host}:{settings.api_port}
Debug mode: {settings.debug}
    """)
    
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level="debug" if settings.debug else "info"
    )


if __name__ == "__main__":
    main()
