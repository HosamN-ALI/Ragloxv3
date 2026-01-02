# RAGLOX v3.0 - E2E Demo Guide

## Overview

This guide explains how to run the End-to-End (E2E) demonstration of RAGLOX v3.0, which showcases the complete attack workflow from reconnaissance to exploitation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         RAGLOX Controller                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │ReconSpecialist│  │AttackSpecialist│  │AnalysisSpec │                  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────┘                  │
│         │                  │                                             │
│         └────────┬─────────┘                                             │
│                  ▼                                                       │
│         ┌────────────────┐                                               │
│         │ RXModuleRunner │                                               │
│         └────────┬───────┘                                               │
│                  │                                                       │
│         ┌────────┼────────┐                                              │
│         ▼        ▼        ▼                                              │
│  ┌──────────┐ ┌─────────┐ ┌───────────┐                                 │
│  │LocalExec │ │SSHExec  │ │WinRMExec  │                                 │
│  └──────────┘ └────┬────┘ └───────────┘                                 │
└────────────────────┼────────────────────────────────────────────────────┘
                     │ SSH (port 22)
                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      Docker Network (172.28.0.0/24)                      │
│                                                                          │
│  ┌──────────────────────┐     ┌──────────────────────┐                  │
│  │  vulnerable-target   │     │ vulnerable-target-2  │                  │
│  │   172.28.0.100       │     │   172.28.0.101       │                  │
│  │   SSH: 22            │     │   SSH: 22            │                  │
│  │   HTTP: 80           │     │   HTTP: 80           │                  │
│  │                      │     │                      │                  │
│  │  Users:              │     │  Users:              │                  │
│  │  - testuser:password123    │  - testuser:password123  │              │
│  │  - admin:admin123    │     │  - admin:admin123    │                  │
│  │  - root:toor         │     │  - backup:backup     │                  │
│  └──────────────────────┘     └──────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### 1. Docker & Docker Compose
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install docker.io docker-compose-plugin

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### 2. Python Virtual Environment
```bash
cd /root/RAGLOX_V3/webapp
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### Option 1: Standalone Mode (No Docker Required)

This mode uses mock blackboard and simulated execution:

```bash
cd /root/RAGLOX_V3/webapp
source venv/bin/activate
python run_demo.py --mock
```

### Option 2: Full Docker Mode

This mode starts real vulnerable targets:

```bash
# 1. Start infrastructure
cd infrastructure
docker-compose --profile demo up -d

# 2. Wait for containers to be ready
docker-compose ps

# 3. Run the demo
cd ..
source venv/bin/activate
python run_demo.py --redis
```

## Demo Flow

The demo runs through these phases:

### Phase 1: Reconnaissance 🔍
- Discovers hosts in the Docker network (172.28.0.0/24)
- Scans for open ports (22/SSH, 80/HTTP)
- Identifies vulnerabilities (weak SSH credentials)

### Phase 2: SSH Execution Test 🔐
- Attempts SSH connections using known weak credentials
- Executes system commands on successful connection
- Harvests sensitive files (database credentials, SSH keys)

### Phase 3: Attack Simulation ⚔️
- Simulates credential harvesting
- Records discovered credentials in Blackboard
- Prepares for lateral movement

### Phase 4: Summary 📊
- Displays mission statistics
- Shows discovered targets, vulnerabilities, credentials

## Vulnerable Target Details

### Container: vulnerable-target (172.28.0.100)

| Service | Port | Description |
|---------|------|-------------|
| SSH | 22 | OpenSSH with password auth |
| HTTP | 80 | Nginx with exposed info |

### Credentials

| Username | Password | Privilege |
|----------|----------|-----------|
| testuser | password123 | Standard user |
| admin | admin123 | sudo access |
| backup | backup | Service account |
| root | toor | Root access |

### Interesting Files

- `/home/testuser/.db_creds` - Database credentials
- `/home/testuser/.bash_history` - Command history with secrets
- `/home/admin/.ssh/id_rsa_backup` - SSH private key
- `/var/www/html/backup/config.bak` - Backup configuration

### HTTP Endpoints

- `http://172.28.0.100/` - Main page with info
- `http://172.28.0.100/admin` - Admin login panel
- `http://172.28.0.100/backup` - Exposed backup directory
- `http://172.28.0.100/server-status` - Nginx status
- `http://172.28.0.100/info` - JSON configuration

## Troubleshooting

### SSH Connection Timeout

If SSH connections timeout, ensure:
1. Docker containers are running: `docker-compose ps`
2. Network is correct: `docker network inspect raglox-network`
3. SSH service is up: `docker exec raglox-vulnerable-target pgrep sshd`

### Redis Connection Error

If using `--redis` flag:
1. Ensure Redis is running: `docker-compose ps redis`
2. Check Redis health: `docker exec raglox-redis redis-cli ping`

### Container Not Starting

Check logs:
```bash
docker-compose logs vulnerable-target
```

## Customization

### Adding More Targets

Edit `infrastructure/docker-compose.yml` to add more vulnerable targets:

```yaml
vulnerable-target-3:
  build:
    context: ./vulnerable-target
    dockerfile: Dockerfile
  container_name: raglox-vulnerable-target-3
  profiles:
    - demo
  networks:
    raglox-network:
      ipv4_address: 172.28.0.102
```

### Modifying Credentials

Edit `infrastructure/vulnerable-target/Dockerfile` to change users/passwords.

### Adding More Vulnerabilities

You can add more vulnerable services by modifying the Dockerfile:
- Install vulnerable versions of software
- Misconfigure services
- Add SUID binaries for privilege escalation

## Security Warning

⚠️ **IMPORTANT**: These containers are INTENTIONALLY VULNERABLE!

- Never expose to the internet
- Only use on isolated networks
- Destroy containers after testing
- Do not use in production environments

## Cleanup

```bash
# Stop and remove containers
cd infrastructure
docker-compose --profile demo down

# Remove images
docker rmi raglox-vulnerable-target

# Remove network
docker network rm raglox-network
```

## Expected Output

A successful demo shows:

```
╔═══════════════════════════════════════════════════════════════════╗
║                      MISSION RESULTS                               ║
╠═══════════════════════════════════════════════════════════════════╣
║  🎯 Targets Discovered:      2                                     ║
║  🔌 Open Ports Found:        4                                     ║
║  ⚠️  Vulnerabilities:         2                                     ║
║  🔑 Credentials Harvested:   4                                     ║
║  💻 Sessions Established:    1+                                    ║
║  ✅ Goals Achieved:          1+                                    ║
╚═══════════════════════════════════════════════════════════════════╝
```
