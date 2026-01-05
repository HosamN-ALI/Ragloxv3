#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# RAGLOX v3.0 - Vulnerable Target Container Builder & Runner
# ═══════════════════════════════════════════════════════════════════════════════

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="raglox-vuln-target"
CONTAINER_NAME="raglox-target"
TARGET_PORT_HTTP=8888
TARGET_PORT_SSH=2222
TARGET_PORT_MYSQL=3307
TARGET_PORT_REDIS=6380

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  RAGLOX v3.0 - Vulnerable Target Container${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}⚠️  WARNING: This container is intentionally VULNERABLE!${NC}"
echo -e "${YELLOW}⚠️  DO NOT deploy in production environments!${NC}"
echo ""

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  build     - Build the vulnerable container image"
    echo "  start     - Start the vulnerable container"
    echo "  stop      - Stop the vulnerable container"
    echo "  restart   - Restart the vulnerable container"
    echo "  status    - Check container status"
    echo "  logs      - View container logs"
    echo "  shell     - Get a shell inside the container"
    echo "  cleanup   - Remove container and image"
    echo "  help      - Show this help message"
    echo ""
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        exit 1
    fi
}

build_image() {
    echo -e "${GREEN}[*] Building vulnerable container image...${NC}"
    cd "$SCRIPT_DIR"
    docker build -t "$IMAGE_NAME" .
    echo -e "${GREEN}[✓] Image built successfully: $IMAGE_NAME${NC}"
}

start_container() {
    echo -e "${GREEN}[*] Starting vulnerable container...${NC}"
    
    # Stop if already running
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p "$TARGET_PORT_HTTP:80" \
        -p "$TARGET_PORT_SSH:22" \
        -p "$TARGET_PORT_MYSQL:3306" \
        -p "$TARGET_PORT_REDIS:6379" \
        --hostname vulnerable-target \
        "$IMAGE_NAME"
    
    # Wait for services
    echo -e "${YELLOW}[*] Waiting for services to start...${NC}"
    sleep 5
    
    # Check health
    if docker ps | grep -q "$CONTAINER_NAME"; then
        echo -e "${GREEN}[✓] Container started successfully!${NC}"
        echo ""
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}Target Information:${NC}"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "  HTTP:  http://localhost:${TARGET_PORT_HTTP}"
        echo -e "  SSH:   ssh root@localhost -p ${TARGET_PORT_SSH} (password: toor)"
        echo -e "  MySQL: localhost:${TARGET_PORT_MYSQL} (root/toor)"
        echo -e "  Redis: localhost:${TARGET_PORT_REDIS} (no auth)"
        echo ""
        echo -e "${YELLOW}Vulnerable Endpoints:${NC}"
        echo -e "  SQL Injection:     http://localhost:${TARGET_PORT_HTTP}/login.php"
        echo -e "  Command Injection: http://localhost:${TARGET_PORT_HTTP}/ping.php"
        echo -e "  LFI:              http://localhost:${TARGET_PORT_HTTP}/include.php"
        echo -e "  File Upload RCE:  http://localhost:${TARGET_PORT_HTTP}/upload.php"
        echo -e "  SSRF:             http://localhost:${TARGET_PORT_HTTP}/fetch.php"
        echo -e "  XSS:              http://localhost:${TARGET_PORT_HTTP}/search.php"
        echo -e "  XXE:              http://localhost:${TARGET_PORT_HTTP}/xml.php"
        echo -e "  API SQLi:         http://localhost:${TARGET_PORT_HTTP}/api/users.php"
        echo ""
        echo -e "${YELLOW}Known Credentials:${NC}"
        echo -e "  Web Admin:  admin:admin123"
        echo -e "  SSH Root:   root:toor"
        echo -e "  victim:     victim:victim123"
        echo -e "  developer:  developer:dev2024"
        echo -e "  backup:     backup:backup"
        echo ""
        echo -e "${YELLOW}System Vulns:${NC}"
        echo -e "  SUID Binary: /usr/local/bin/vuln_suid"
        echo -e "  Sudo Escape: victim (find), developer (vim), backup (tar)"
        echo -e "  Writable:    /tmp/backup.sh (cron root)"
        echo ""
    else
        echo -e "${RED}[✗] Container failed to start${NC}"
        docker logs "$CONTAINER_NAME"
        exit 1
    fi
}

stop_container() {
    echo -e "${YELLOW}[*] Stopping vulnerable container...${NC}"
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    echo -e "${GREEN}[✓] Container stopped${NC}"
}

restart_container() {
    stop_container
    sleep 2
    start_container
}

check_status() {
    echo -e "${BLUE}Container Status:${NC}"
    if docker ps | grep -q "$CONTAINER_NAME"; then
        echo -e "${GREEN}[✓] Running${NC}"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep "$CONTAINER_NAME"
    else
        echo -e "${RED}[✗] Not running${NC}"
    fi
}

view_logs() {
    docker logs -f "$CONTAINER_NAME"
}

get_shell() {
    docker exec -it "$CONTAINER_NAME" /bin/bash
}

cleanup() {
    echo -e "${YELLOW}[*] Cleaning up...${NC}"
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    docker rmi "$IMAGE_NAME" 2>/dev/null || true
    echo -e "${GREEN}[✓] Cleanup complete${NC}"
}

# Get container IP for internal use
get_container_ip() {
    docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME" 2>/dev/null || echo "127.0.0.1"
}

# Main
check_docker

case "${1:-help}" in
    build)
        build_image
        ;;
    start)
        if ! docker images | grep -q "$IMAGE_NAME"; then
            build_image
        fi
        start_container
        ;;
    stop)
        stop_container
        ;;
    restart)
        restart_container
        ;;
    status)
        check_status
        ;;
    logs)
        view_logs
        ;;
    shell)
        get_shell
        ;;
    cleanup)
        cleanup
        ;;
    ip)
        get_container_ip
        ;;
    help|*)
        usage
        ;;
esac
