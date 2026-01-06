# RAGLOX v3.0 - Production Setup Guide

## 📋 Overview

This guide covers the complete setup of RAGLOX v3.0 for production deployment.

## 🚀 Quick Start

### 1. Clone and Setup Environment

```bash
# Clone the repository
git clone https://github.com/HosamN-ALI/Ragloxv3.git
cd Ragloxv3/webapp/webapp

# Setup environment (generates secure secrets)
chmod +x scripts/setup-env.sh
./scripts/setup-env.sh production

# Review and configure .env file
nano .env
```

### 2. Configure Required Services

Edit `.env` and configure:

```env
# LLM Provider (Required)
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-api-key-here

# Database credentials (auto-generated, review if needed)
DATABASE_URL=postgresql://raglox:password@postgres:5432/raglox

# CORS (restrict in production)
CORS_ORIGINS=https://your-frontend.com
```

### 3. Start Services

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f raglox-api
```

### 4. Verify Deployment

```bash
# Health check
curl http://localhost:8000/health

# Run E2E tests
python tests/e2e/run_e2e.py --quick
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        RAGLOX v3.0                                │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Nginx     │  │   FastAPI   │  │  WebSocket  │              │
│  │   Proxy     │──│    API      │──│   Handler   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                          │                                        │
│         ┌────────────────┼────────────────┐                      │
│         ▼                ▼                ▼                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   Redis     │  │ PostgreSQL  │  │   MinIO     │              │
│  │  (Cluster)  │  │ (Primary)   │  │  (Storage)  │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                    Core Components                           │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐            │ │
│  │  │ Mission    │  │ Knowledge  │  │ Workflow   │            │ │
│  │  │ Controller │  │   Base     │  │ Orchestr.  │            │ │
│  │  └────────────┘  └────────────┘  └────────────┘            │ │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐            │ │
│  │  │    LLM     │  │   Intel    │  │ Exploit    │            │ │
│  │  │  Service   │  │  Manager   │  │  Engine    │            │ │
│  │  └────────────┘  └────────────┘  └────────────┘            │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📦 Services

### Docker Compose Services

| Service | Port | Description |
|---------|------|-------------|
| `raglox-api` | 8000 | FastAPI backend |
| `raglox-nginx` | 80, 443 | Reverse proxy |
| `raglox-redis` | 6379 | Session & cache |
| `raglox-postgres` | 5432 | Database |
| `raglox-minio` | 9000, 9001 | Object storage |

### Optional Services

| Service | Port | Description |
|---------|------|-------------|
| `elasticsearch` | 9200 | Intel data lake |
| `kibana` | 5601 | Intel visualization |
| `redis-commander` | 8081 | Redis admin |
| `adminer` | 8082 | Database admin |

---

## ⚙️ Configuration

### Environment Variables

#### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `LLM_PROVIDER` | LLM provider | `openai`, `blackbox`, `mock` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-...` |
| `JWT_SECRET` | JWT signing key | Auto-generated |
| `DATABASE_URL` | PostgreSQL URL | `postgresql://user:pass@host/db` |

#### Redis Configuration

```env
# Standalone (default)
REDIS_MODE=standalone
REDIS_URL=redis://localhost:6379/0

# Sentinel (HA)
REDIS_MODE=sentinel
REDIS_SENTINEL_HOSTS=sentinel1:26379,sentinel2:26379,sentinel3:26379
REDIS_SENTINEL_MASTER=mymaster

# Cluster
REDIS_MODE=cluster
REDIS_CLUSTER_NODES=redis1:6379,redis2:6379,redis3:6379
```

#### LLM Providers

```env
# OpenAI (Recommended)
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key
LLM_MODEL=gpt-4

# Azure OpenAI
LLM_PROVIDER=openai
OPENAI_API_KEY=your-azure-key
LLM_API_BASE=https://your-resource.openai.azure.com/
LLM_MODEL=your-deployment-name

# BlackBox AI (Free)
LLM_PROVIDER=blackbox
LLM_API_BASE=https://api.blackbox.ai
LLM_MODEL=blackboxai/openai/gpt-4o-mini

# Mock (Testing)
LLM_PROVIDER=mock
```

---

## 🔒 Security Checklist

### Before Deployment

- [ ] Generate secure `JWT_SECRET` (64+ chars)
- [ ] Generate secure `ENCRYPTION_KEY` (32 bytes base64)
- [ ] Set secure database password
- [ ] Set secure Redis password
- [ ] Configure CORS origins (no `*` in production)
- [ ] Enable rate limiting
- [ ] Enable input validation
- [ ] Set `DEBUG=false`
- [ ] Set `DEV_MODE=false`

### Security Features (Enabled by Default)

| Feature | Setting | Description |
|---------|---------|-------------|
| XSS Prevention | `SECURITY_CHECK_XSS=true` | SEC-03 |
| SQL Injection Prevention | `SECURITY_CHECK_SQL=true` | SEC-03 |
| Command Injection Prevention | `SECURITY_CHECK_COMMAND=true` | SEC-03 |
| Path Traversal Prevention | `SECURITY_CHECK_PATH=true` | SEC-03 |
| Rate Limiting | `RATE_LIMITING_ENABLED=true` | SEC-04 |
| JWT Validation | Automatic | SEC-05 |

---

## 🧪 Testing

### Run Tests

```bash
# Unit tests
pytest tests/ -v

# API tests
pytest tests/test_api.py -v

# Security tests
pytest tests/test_sec_03_04.py -v

# Reliability tests
pytest tests/test_rel_01_02.py -v

# E2E tests (quick)
python tests/e2e/run_e2e.py --quick

# E2E tests (full)
python tests/e2e/run_e2e.py --report html
```

### Test with Real SSH

```bash
# Set environment
export TEST_SSH_HOST=192.168.1.100
export TEST_SSH_USER=root
export TEST_SSH_PASSWORD=password
export RAGLOX_TEST_MODE=real

# Run real integration tests
python webapp/tests/real_integration/run_tests.py --mode real
```

---

## 📊 Monitoring

### Health Endpoints

```bash
# API health
curl http://localhost:8000/health

# Infrastructure health
curl http://localhost:8000/infrastructure/health

# Security health
curl http://localhost:8000/security/health
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f raglox-api

# Filter errors
docker-compose logs -f raglox-api | grep ERROR
```

### Metrics

```bash
# Statistics endpoint
curl http://localhost:8000/stats

# Rate limit stats
curl http://localhost:8000/rate-limit/stats
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. API won't start

```bash
# Check logs
docker-compose logs raglox-api

# Verify environment
docker-compose exec raglox-api env | grep -E "^(LLM|REDIS|DATABASE)"
```

#### 2. Redis connection failed

```bash
# Test Redis
docker-compose exec redis redis-cli ping

# Check Redis logs
docker-compose logs redis
```

#### 3. LLM not working

```bash
# Check API key
echo $OPENAI_API_KEY

# Test LLM endpoint
curl http://localhost:8000/health | jq '.llm_status'
```

#### 4. Database migration issues

```bash
# Check PostgreSQL
docker-compose exec postgres psql -U raglox -c "SELECT 1"

# View tables
docker-compose exec postgres psql -U raglox -c "\dt"
```

---

## 🚀 Scaling

### Horizontal Scaling

```yaml
# docker-compose.override.yml
version: '3.8'
services:
  raglox-api:
    deploy:
      replicas: 3
```

### Redis Sentinel

```yaml
# docker-compose.sentinel.yml
services:
  redis-sentinel-1:
    image: redis:7-alpine
    command: redis-sentinel /etc/redis/sentinel.conf
    volumes:
      - ./config/redis/sentinel.conf:/etc/redis/sentinel.conf
```

---

## 📚 Additional Resources

- [API Documentation](/docs): Auto-generated OpenAPI docs
- [Architecture Guide](./ARCHITECTURE.md): System design details
- [Security Guide](./SECURITY.md): Security implementation
- [Testing Guide](./REAL_INTEGRATION_TESTING.md): Testing strategies

---

## 📞 Support

- GitHub Issues: [Report bugs](https://github.com/HosamN-ALI/Ragloxv3/issues)
- Documentation: `/docs` endpoint when API is running

---

*RAGLOX v3.0 - Autonomous Red Team Agent*
