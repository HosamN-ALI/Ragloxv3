#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Startup Script
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════════════════"
echo "  ██████╗  █████╗  ██████╗ ██╗      ██████╗ ██╗  ██╗    ██╗   ██╗██████╗   "
echo "  ██╔══██╗██╔══██╗██╔════╝ ██║     ██╔═══██╗╚██╗██╔╝    ██║   ██║╚════██╗  "
echo "  ██████╔╝███████║██║  ███╗██║     ██║   ██║ ╚███╔╝     ██║   ██║ █████╔╝  "
echo "  ██╔══██╗██╔══██║██║   ██║██║     ██║   ██║ ██╔██╗     ╚██╗ ██╔╝ ╚═══██╗  "
echo "  ██║  ██║██║  ██║╚██████╔╝███████╗╚██████╔╝██╔╝ ██╗     ╚████╔╝ ██████╔╝  "
echo "  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝      ╚═══╝  ╚═════╝   "
echo "═══════════════════════════════════════════════════════════════════════════"
echo -e "  Enterprise AI-Powered Penetration Testing Platform${NC}"
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  No .env file found. Creating from .env.example...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${YELLOW}   Please edit .env with your configuration before starting.${NC}"
        exit 1
    else
        echo -e "${RED}❌ No .env.example found. Cannot proceed.${NC}"
        exit 1
    fi
fi

# Source environment
source .env 2>/dev/null || true

# Parse arguments
PROFILE=""
DETACH=""
BUILD=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            PROFILE="--profile dev"
            shift
            ;;
        --testing)
            PROFILE="--profile testing"
            shift
            ;;
        --full)
            PROFILE="--profile dev --profile testing --profile intel"
            shift
            ;;
        --production)
            PROFILE="--profile production"
            shift
            ;;
        -d|--detach)
            DETACH="-d"
            shift
            ;;
        --build)
            BUILD="--build"
            shift
            ;;
        --down)
            echo -e "${YELLOW}🛑 Stopping RAGLOX services...${NC}"
            docker-compose down
            echo -e "${GREEN}✅ Services stopped${NC}"
            exit 0
            ;;
        --logs)
            docker-compose logs -f
            exit 0
            ;;
        --status)
            echo -e "${BLUE}📊 Service Status:${NC}"
            docker-compose ps
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dev         Run with development tools (Redis Commander, Adminer)"
            echo "  --testing     Run with vulnerable targets for testing"
            echo "  --full        Run all services including intel stack"
            echo "  --production  Run with Nginx reverse proxy"
            echo "  -d, --detach  Run in background"
            echo "  --build       Rebuild containers"
            echo "  --down        Stop all services"
            echo "  --logs        Follow logs"
            echo "  --status      Show service status"
            echo "  -h, --help    Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validation
echo -e "${BLUE}🔍 Validating configuration...${NC}"

# Check required env vars
REQUIRED_VARS=("POSTGRES_PASSWORD" "MINIO_SECRET_KEY")
MISSING_VARS=()

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        MISSING_VARS+=("$var")
    fi
done

if [ ${#MISSING_VARS[@]} -gt 0 ]; then
    echo -e "${RED}❌ Missing required environment variables:${NC}"
    for var in "${MISSING_VARS[@]}"; do
        echo -e "   - $var"
    done
    echo -e "${YELLOW}   Please edit .env file and set these values.${NC}"
    exit 1
fi

# Generate JWT_SECRET if not set
if [ -z "$JWT_SECRET" ] || [ "$JWT_SECRET" = "CHANGE_ME_TO_A_SECURE_RANDOM_STRING_AT_LEAST_64_CHARS" ]; then
    echo -e "${YELLOW}⚠️  Generating secure JWT_SECRET...${NC}"
    NEW_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))" 2>/dev/null || openssl rand -base64 64 | tr -d '\n')
    sed -i "s/JWT_SECRET=.*/JWT_SECRET=$NEW_SECRET/" .env
    export JWT_SECRET="$NEW_SECRET"
fi

echo -e "${GREEN}✅ Configuration validated${NC}"

# Create necessary directories
echo -e "${BLUE}📁 Creating directories...${NC}"
mkdir -p config/nginx/ssl

# Generate self-signed SSL certificate if not exists
if [ ! -f "config/nginx/ssl/cert.pem" ]; then
    echo -e "${YELLOW}🔐 Generating self-signed SSL certificate...${NC}"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout config/nginx/ssl/key.pem \
        -out config/nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=RAGLOX/CN=localhost" 2>/dev/null || true
    echo -e "${GREEN}✅ SSL certificate generated${NC}"
fi

# Start services
echo -e "${BLUE}🚀 Starting RAGLOX services...${NC}"
echo ""

docker-compose $PROFILE up $BUILD $DETACH

if [ -n "$DETACH" ]; then
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✅ RAGLOX services started successfully!${NC}"
    echo ""
    echo -e "   ${BLUE}API:${NC}         http://localhost:${API_PORT:-8000}"
    echo -e "   ${BLUE}API Docs:${NC}    http://localhost:${API_PORT:-8000}/docs"
    echo -e "   ${BLUE}Health:${NC}      http://localhost:${API_PORT:-8000}/health"
    
    if [[ "$PROFILE" == *"dev"* ]]; then
        echo ""
        echo -e "   ${YELLOW}Dev Tools:${NC}"
        echo -e "   ${BLUE}Redis UI:${NC}    http://localhost:8081"
        echo -e "   ${BLUE}DB Admin:${NC}    http://localhost:8082"
        echo -e "   ${BLUE}MinIO:${NC}       http://localhost:${MINIO_CONSOLE_PORT:-9001}"
    fi
    
    if [[ "$PROFILE" == *"testing"* ]]; then
        echo ""
        echo -e "   ${YELLOW}Test Targets:${NC}"
        echo -e "   ${BLUE}Target 1:${NC}    ssh root@localhost -p 2222 (password: toor)"
        echo -e "   ${BLUE}Target 1 Web:${NC} http://localhost:8088"
    fi
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "   Use '${YELLOW}$0 --logs${NC}' to view logs"
    echo -e "   Use '${YELLOW}$0 --down${NC}' to stop services"
    echo -e "   Use '${YELLOW}$0 --status${NC}' to view status"
fi
