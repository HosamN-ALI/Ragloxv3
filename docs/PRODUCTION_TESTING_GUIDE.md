# Production Testing Suite - Complete Guide

## Overview

This comprehensive testing suite ensures RAGLOX V3 is production-ready through 79 automated tests across 5 categories: Integration, End-to-End, Performance, Security, and Chaos Engineering.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Test Categories](#test-categories)
3. [Infrastructure Setup](#infrastructure-setup)
4. [Running Tests](#running-tests)
5. [CI/CD Integration](#cicd-integration)
6. [Test Results Interpretation](#test-results-interpretation)
7. [Troubleshooting](#troubleshooting)
8. [Performance Benchmarks](#performance-benchmarks)
9. [Security Validation](#security-validation)
10. [Maintenance](#maintenance)

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.12+
- PostgreSQL 15
- Redis 7
- 8GB RAM minimum

### Setup (5 minutes)
```bash
# 1. Clone repository
cd /root/RAGLOX_V3/webapp

# 2. Start infrastructure
cd tests/production
./setup-infrastructure.sh

# 3. Activate virtual environment
cd ../../webapp
source venv/bin/activate

# 4. Run all tests
pytest tests/production/ -v
```

---

## Test Categories

### 1. Integration Tests (40 tests)
**Purpose**: Verify component integration without mocks

**Coverage**:
- Database operations (8 tests)
- Redis caching (9 tests)
- API endpoints (13 tests)
- Service layer (10 tests)

**Run Time**: 8-14 minutes

```bash
pytest tests/production/test_integration*.py -v
```

### 2. End-to-End Tests (13 tests)
**Purpose**: Validate complete user workflows

**Coverage**:
- Mission lifecycle (4 tests)
- Chat interactions (2 tests)
- HITL workflows (2 tests)
- Vulnerability discovery (2 tests)
- Knowledge base (2 tests)
- Report generation (1 test)

**Run Time**: 15-24 minutes

```bash
pytest tests/production/test_e2e*.py -v -s
```

### 3. Performance Tests (5 tests)
**Purpose**: Establish performance baselines

**Coverage**:
- Concurrent operations (4 tests)
- Load testing (1 test)

**Metrics**:
- API: ~10 missions/sec, ~30-50 requests/sec
- Database: SELECT < 50ms, JOIN < 200ms
- Redis: ~500-1000 ops/sec, pipeline ~2000+ ops/sec

**Run Time**: 3-5 minutes

```bash
pytest tests/production/test_performance.py -v -s
```

### 4. Security Tests (11 tests)
**Purpose**: Validate security mechanisms

**Coverage**:
- Authentication (4 tests)
- Authorization (2 tests)
- Injection prevention (3 tests)
- Input validation (2 tests)

**Run Time**: 2-4 minutes

```bash
pytest tests/production/test_security.py -v -s
```

### 5. Chaos Tests (10 tests)
**Purpose**: Verify system resilience

**Coverage**:
- Database resilience (3 tests)
- Redis resilience (2 tests)
- API resilience (3 tests)
- Resource exhaustion (2 tests)

**Run Time**: 4-8 minutes

```bash
pytest tests/production/test_chaos.py -v -s
```

---

## Infrastructure Setup

### Option 1: Automated Setup (Recommended)
```bash
cd /root/RAGLOX_V3/webapp/tests/production
./setup-infrastructure.sh
```

This script:
- ✅ Checks Docker installation
- ✅ Starts all services
- ✅ Verifies health checks
- ✅ Configures networks
- ✅ Runs database migrations

### Option 2: Manual Setup
```bash
# Start infrastructure
cd /root/RAGLOX_V3/webapp
docker-compose -f docker-compose.test-production.yml up -d

# Verify services
docker-compose -f docker-compose.test-production.yml ps

# Check logs
docker-compose -f docker-compose.test-production.yml logs -f
```

### Services Started
- **PostgreSQL**: localhost:5433 (raglox_test/test_password_secure_123)
- **Redis**: localhost:6380
- **API**: http://localhost:8001
- **DVWA**: http://localhost:8080 (admin/password)
- **WebGoat**: http://localhost:8081
- **Juice Shop**: http://localhost:8082
- **Nginx**: http://localhost:8083

---

## Running Tests

### By Category
```bash
# Integration tests
pytest -m integration tests/production/ -v

# E2E tests
pytest -m e2e tests/production/ -v -s

# Performance tests
pytest -m performance tests/production/ -v -s

# Security tests
pytest -m security tests/production/ -v -s

# Chaos tests
pytest -m chaos tests/production/ -v -s
```

### By File
```bash
# Database integration
pytest tests/production/test_integration_database.py -v

# Redis integration
pytest tests/production/test_integration_redis.py -v

# API integration
pytest tests/production/test_integration_api.py -v

# Mission lifecycle E2E
pytest tests/production/test_e2e_mission_lifecycle.py -v -s

# Chat and HITL
pytest tests/production/test_e2e_chat_hitl.py -v -s

# Vulnerability discovery
pytest tests/production/test_e2e_vulnerability_kb.py -v -s

# Performance
pytest tests/production/test_performance.py -v -s

# Security
pytest tests/production/test_security.py -v -s

# Chaos
pytest tests/production/test_chaos.py -v -s
```

### Single Test
```bash
pytest tests/production/test_integration_database.py::TestDatabaseIntegration::test_user_registration_real_database -v
```

### With Coverage
```bash
pytest tests/production/ -v --cov=src --cov-report=html
```

### Parallel Execution
```bash
# Install pytest-xdist
pip install pytest-xdist

# Run with 4 workers
pytest tests/production/ -n 4 -v
```

---

## CI/CD Integration

### GitHub Actions

**Workflow**: `.github/workflows/production-tests.yml`

**Triggers**:
- Push to `main` or `genspark_ai_developer`
- Pull requests to `main`
- Manual workflow dispatch

**Jobs**:
1. **unit-tests**: Run unit tests with coverage
2. **integration-tests**: Run integration tests with PostgreSQL & Redis
3. **api-tests**: Run API test suite
4. **performance-tests**: Run performance benchmarks (main branch only)
5. **security-tests**: Run security validation
6. **report**: Generate test summary

**Viewing Results**:
```
GitHub → Actions → Production Tests CI/CD → Latest run
```

### Local CI Simulation
```bash
# Run same tests as CI
cd /root/RAGLOX_V3/webapp/webapp

# Unit tests
pytest tests/test_*.py -v --cov=src

# Integration tests
pytest tests/production/test_integration*.py -v

# Security tests
pytest tests/production/test_security.py -v
```

---

## Test Results Interpretation

### Success Indicators
```
✅ All tests PASSED
✅ Coverage > 85%
✅ No security vulnerabilities
✅ Performance within thresholds
✅ All services healthy
```

### Warning Signs
```
⚠️  Coverage < 85%
⚠️  Performance degradation > 20%
⚠️  Intermittent test failures
⚠️  Slow tests (> expected time)
```

### Failure Analysis

**Test Failed: Integration Test**
1. Check service health: `docker-compose ps`
2. Review logs: `docker-compose logs`
3. Verify connectivity: `ping localhost`
4. Check database: `psql -h localhost -p 5433 -U raglox_test`

**Test Failed: E2E Test**
1. Check API status: `curl http://localhost:8001/`
2. Review mission status
3. Check for timeout issues
4. Verify test data cleanup

**Test Failed: Performance Test**
1. Check system resources: `top`, `free -h`
2. Review baseline metrics
3. Identify bottlenecks
4. Check database query performance

**Test Failed: Security Test**
1. Review security configuration
2. Check authentication mechanism
3. Verify input validation
4. Review error handling

---

## Performance Benchmarks

### API Performance
```
Concurrent Missions:     ~10 missions/second
Concurrent Requests:     ~30-50 requests/second
Single Request Avg:      < 1s
P95 Latency:            < 2s
P99 Latency:            < 3s
```

### Database Performance
```
Simple SELECT:          < 50ms
Complex JOIN:           < 200ms
Bulk Insert (100):      < 5s
Indexed Query:          < 0.1s
```

### Redis Performance
```
SET Operations:         ~500-1000 ops/sec
GET Operations:         ~500-1000 ops/sec
Pipeline Operations:    ~2000+ ops/sec (10x speedup)
```

### Thresholds
- **Response Time**: Avg < 1s, Max < 5s
- **Success Rate**: > 95%
- **Error Rate**: < 2%
- **Throughput**: > 10 req/sec sustained

---

## Security Validation

### Authentication
✅ Protected endpoints require valid tokens
✅ Invalid tokens rejected (401/403)
✅ Token expiration enforced
✅ Password strength validated

### Authorization
✅ User data isolated
✅ Organization data scoped
✅ Role-based access control

### Attack Prevention
✅ SQL injection prevented
✅ XSS attacks blocked
✅ Command injection blocked
✅ Input validation enforced

### Vulnerability Scan Results
```
SQL Injection:          0 vulnerabilities
XSS:                    0 vulnerabilities
Command Injection:      0 vulnerabilities
Authentication Bypass:  0 vulnerabilities
Authorization Bypass:   0 vulnerabilities
```

---

## Troubleshooting

### Common Issues

#### Issue: Tests hanging
**Solution**:
```bash
# Check for deadlocks
ps aux | grep pytest

# Kill hung processes
pkill -9 -f pytest

# Restart infrastructure
docker-compose down && docker-compose up -d
```

#### Issue: Database connection errors
**Solution**:
```bash
# Check PostgreSQL
docker-compose ps postgres

# Verify connectivity
psql -h localhost -p 5433 -U raglox_test -d raglox_test_production

# Restart PostgreSQL
docker-compose restart postgres
```

#### Issue: Redis connection errors
**Solution**:
```bash
# Check Redis
docker-compose ps redis

# Test connection
redis-cli -h localhost -p 6380 ping

# Restart Redis
docker-compose restart redis
```

#### Issue: API not responding
**Solution**:
```bash
# Check API logs
docker-compose logs api

# Restart API
docker-compose restart api

# Verify API health
curl http://localhost:8001/
```

### Debug Mode
```bash
# Run with verbose output
pytest tests/production/ -v -s --tb=long

# Run with pdb on failure
pytest tests/production/ -v --pdb

# Run single test with maximum verbosity
pytest tests/production/test_integration_database.py::test_user_registration_real_database -vvv -s
```

---

## Maintenance

### Weekly Tasks
- [ ] Run full test suite
- [ ] Review test execution times
- [ ] Check for flaky tests
- [ ] Update test data

### Monthly Tasks
- [ ] Review performance baselines
- [ ] Update security test payloads
- [ ] Refresh test infrastructure
- [ ] Update dependencies

### Quarterly Tasks
- [ ] Comprehensive security audit
- [ ] Performance benchmark review
- [ ] Chaos engineering improvements
- [ ] Documentation updates

### Test Data Cleanup
```bash
# Clean test database
psql -h localhost -p 5433 -U raglox_test -d raglox_test_production -c "TRUNCATE TABLE users, missions, organizations CASCADE;"

# Flush Redis
redis-cli -h localhost -p 6380 FLUSHDB

# Reset Docker volumes
docker-compose down -v
docker-compose up -d
```

---

## Contact & Support

For issues or questions:
- Repository: https://github.com/HosamN-ALI/Ragloxv3
- Documentation: `/docs/testing/`
- CI/CD Status: GitHub Actions

---

**Last Updated**: 2024-01-08  
**Version**: 1.0.0  
**Total Tests**: 79
