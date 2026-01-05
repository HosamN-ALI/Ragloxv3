#!/bin/bash

# Production Deployment Script for RAGLOX Frontend
# This script handles the complete production deployment process

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PRODUCTION_NODE_ENV="production"
PRODUCTION_API_URL="https://api.raglox.com/api/v1"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required tools are available
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    command -v node >/dev/null 2>&1 || { log_error "Node.js is not installed"; exit 1; }
    command -v pnpm >/dev/null 2>&1 || { log_error "pnpm is not installed"; exit 1; }
    
    log_success "Prerequisites check passed"
}

# Run security audit
security_audit() {
    log_info "Running security audit..."
    
    # Check for known vulnerabilities
    pnpm audit --audit-level moderate || {
        log_warning "Security vulnerabilities found. Please review before deployment."
        read -p "Continue with deployment? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Deployment cancelled by user"
            exit 1
        fi
    }
    
    log_success "Security audit completed"
}

# Run comprehensive tests
run_tests() {
    log_info "Running comprehensive test suite..."
    
    # Unit tests
    pnpm test --run
    
    # Build test (ensure production build works)
    pnpm build
    
    # Test build output
    if [ ! -d "dist/public" ] || [ ! -d "dist/server" ]; then
        log_error "Build output missing. Deployment failed."
        exit 1
    fi
    
    log_success "All tests passed"
}

# Optimize build
optimize_build() {
    log_info "Optimizing build for production..."
    
    # Enable production environment
    export NODE_ENV=$PRODUCTION_NODE_ENV
    export VITE_API_BASE_URL=$PRODUCTION_API_URL
    export VITE_CSP_ENABLED=true
    export VITE_XSS_PROTECTION=true
    export VITE_SECURITY_HEADERS=true
    
    # Clean previous build
    rm -rf dist/
    
    # Build with production optimizations
    pnpm build
    
    # Generate build report
    if [ -d "dist/public/assets" ]; then
        log_info "Build completed. Asset sizes:"
        du -h dist/public/assets/* || true
    fi
    
    log_success "Build optimization completed"
}

# Generate security headers
generate_security_headers() {
    log_info "Generating security headers..."
    
    cat > dist/_headers << 'EOF'
# Security headers for production
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  X-XSS-Protection: 1; mode=block
  Referrer-Policy: strict-origin-when-cross-origin
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' ws: localhost:8000; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# API routes
/api/*
  Cache-Control: no-cache, no-store, must-revalidate
  Pragma: no-cache
  Expires: 0
  Access-Control-Allow-Origin: *
  Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
  Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With

# Static assets
/assets/*
  Cache-Control: public, max-age=31536000, immutable

# HTML pages
/*.html
  Cache-Control: no-cache, no-store, must-revalidate
EOF
    
    log_success "Security headers generated"
}

# Generate robots.txt
generate_robots_txt() {
    log_info "Generating robots.txt..."
    
    cat > dist/robots.txt << 'EOF'
User-agent: *
Disallow: /api/
Disallow: /admin/
Disallow: /private/
Allow: /

Sitemap: https://raglox.com/sitemap.xml
EOF

    log_success "robots.txt generated"
}

# Cleanup
cleanup() {
    log_info "Cleaning up deployment artifacts..."
    
    # Remove sensitive files
    rm -f dist/.env.production
    rm -f dist/*.map  # Remove source maps
    rm -f dist/README.md
    rm -f dist/LICEN*

    log_success "Cleanup completed"
}

# Main deployment function
deploy() {
    log_info "Starting RAGLOX Frontend Production Deployment"
    echo
    
    # Create backup of current dist if it exists
    if [ -d "dist" ]; then
        log_info "Backing up current build..."
        rm -rf dist.backup || true
        mv dist dist.backup.$(date +%Y%m%d_%H%M%S) || true
    fi
    
    check_prerequisites
    cleanup
    run_tests
    security_audit
    optimize_build
    generate_security_headers
    generate_robots_txt
    
    log_success "RAGLOX Frontend Production Deployment Completed Successfully!"
    echo
    log_info "Build artifacts are located in the 'dist/' directory"
    log_info "Deploy these files to your production web server"
}

# Error handling
trap 'log_error "Deployment failed! Check the logs above for details."' ERR

# Run deployment
deploy