#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Environment Setup Script
# Initializes environment configuration for development or production
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  RAGLOX v3.0 - Environment Setup${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Function to generate secure random string
generate_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe($1))"
}

# Function to generate encryption key
generate_encryption_key() {
    python3 -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
}

# Check environment argument
ENV_TYPE="${1:-development}"

case "$ENV_TYPE" in
    dev|development)
        ENV_TYPE="development"
        SOURCE_FILE="${PROJECT_DIR}/.env.development"
        ;;
    prod|production)
        ENV_TYPE="production"
        SOURCE_FILE="${PROJECT_DIR}/.env.production"
        ;;
    example)
        SOURCE_FILE="${PROJECT_DIR}/.env.example"
        ;;
    *)
        echo -e "${RED}Invalid environment type: $ENV_TYPE${NC}"
        echo "Usage: $0 [development|production|example]"
        exit 1
        ;;
esac

TARGET_FILE="${PROJECT_DIR}/.env"

echo -e "${YELLOW}Environment type: ${ENV_TYPE}${NC}"
echo -e "${YELLOW}Source file: ${SOURCE_FILE}${NC}"
echo -e "${YELLOW}Target file: ${TARGET_FILE}${NC}"
echo ""

# Check if source file exists
if [ ! -f "$SOURCE_FILE" ]; then
    echo -e "${RED}Error: Source file not found: ${SOURCE_FILE}${NC}"
    exit 1
fi

# Check if .env already exists
if [ -f "$TARGET_FILE" ]; then
    echo -e "${YELLOW}Warning: .env file already exists!${NC}"
    read -p "Do you want to overwrite it? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Aborted.${NC}"
        exit 0
    fi
    # Backup existing file
    BACKUP_FILE="${TARGET_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$TARGET_FILE" "$BACKUP_FILE"
    echo -e "${GREEN}Existing .env backed up to: ${BACKUP_FILE}${NC}"
fi

# Copy source to target
cp "$SOURCE_FILE" "$TARGET_FILE"
echo -e "${GREEN}Copied ${SOURCE_FILE} to ${TARGET_FILE}${NC}"

# For production, generate secure secrets
if [ "$ENV_TYPE" = "production" ]; then
    echo ""
    echo -e "${YELLOW}Generating secure secrets for production...${NC}"
    
    # Generate JWT secret
    JWT_SECRET=$(generate_secret 64)
    sed -i "s|JWT_SECRET=CHANGE_ME.*|JWT_SECRET=${JWT_SECRET}|g" "$TARGET_FILE"
    echo -e "${GREEN}  ✓ Generated JWT_SECRET${NC}"
    
    # Generate encryption key
    ENCRYPTION_KEY=$(generate_encryption_key)
    sed -i "s|ENCRYPTION_KEY=CHANGE_ME.*|ENCRYPTION_KEY=${ENCRYPTION_KEY}|g" "$TARGET_FILE"
    echo -e "${GREEN}  ✓ Generated ENCRYPTION_KEY${NC}"
    
    # Generate Redis password
    REDIS_PWD=$(generate_secret 32)
    sed -i "s|REDIS_PASSWORD=YOUR_REDIS_PASSWORD|REDIS_PASSWORD=${REDIS_PWD}|g" "$TARGET_FILE"
    echo -e "${GREEN}  ✓ Generated REDIS_PASSWORD${NC}"
    
    # Generate MinIO secret
    MINIO_SECRET=$(generate_secret 32)
    sed -i "s|MINIO_SECRET_KEY=YOUR_MINIO_SECRET_KEY|MINIO_SECRET_KEY=${MINIO_SECRET}|g" "$TARGET_FILE"
    echo -e "${GREEN}  ✓ Generated MINIO_SECRET_KEY${NC}"
    
    # Generate PostgreSQL password
    PG_PWD=$(generate_secret 32)
    sed -i "s|YOUR_SECURE_PASSWORD|${PG_PWD}|g" "$TARGET_FILE"
    echo -e "${GREEN}  ✓ Generated PostgreSQL password${NC}"
    
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  IMPORTANT: Manual configuration required!${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${RED}You must configure the following in ${TARGET_FILE}:${NC}"
    echo ""
    echo "  1. LLM Provider API Key:"
    echo "     OPENAI_API_KEY=sk-your-actual-key"
    echo "     or"
    echo "     LLM_API_KEY=your-api-key"
    echo ""
    echo "  2. CORS Origins (for production):"
    echo "     CORS_ORIGINS=https://your-frontend.com"
    echo ""
    echo "  3. Optional: Metasploit configuration"
    echo "  4. Optional: OneProvider cloud integration"
    echo "  5. Optional: Elasticsearch for intel module"
    echo ""
fi

# Validate configuration
echo ""
echo -e "${BLUE}Validating configuration...${NC}"

# Check Python availability
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}  ✗ Python 3 not found${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ Python 3 available${NC}"

# Try to load and validate settings
cd "$PROJECT_DIR/.."
if python3 -c "
import sys
sys.path.insert(0, 'src')
sys.path.insert(0, 'webapp')
from core.config import Settings
try:
    settings = Settings(_env_file='webapp/.env')
    print('Settings loaded successfully')
    print(f'  - App: {settings.app_name} v{settings.app_version}')
    print(f'  - Environment: {\"production\" if not settings.dev_mode else \"development\"}\')
    print(f'  - API: {settings.api_host}:{settings.api_port}')
    print(f'  - LLM Provider: {settings.llm_provider}')
    print(f'  - Redis Mode: {settings.redis_mode}')
except Exception as e:
    print(f'Error: {e}')
    sys.exit(1)
" 2>/dev/null; then
    echo -e "${GREEN}  ✓ Configuration validated${NC}"
else
    echo -e "${YELLOW}  ⚠ Configuration validation skipped (dependencies may not be installed)${NC}"
fi

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Environment setup complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Next steps:"
if [ "$ENV_TYPE" = "development" ]; then
    echo "  1. Start Docker containers: docker-compose up -d"
    echo "  2. Run the API: python -m uvicorn src.api.main:app --reload"
    echo "  3. Access API at: http://localhost:8000"
    echo "  4. Access docs at: http://localhost:8000/docs"
else
    echo "  1. Review and configure .env file"
    echo "  2. Set your LLM API key"
    echo "  3. Start with: docker-compose -f docker-compose.yml up -d"
    echo "  4. Or use: ./scripts/start.sh"
fi
echo ""
