# RAGLOX V3 - Development Instructions Guide
## دليل التعليمات الشامل للتطوير

**Document ID**: RAGLOX-INST-2026-001  
**Version**: 1.0.0  
**Created**: 2026-01-08  
**Last Updated**: 2026-01-08  
**Status**: ACTIVE

---

## 📚 Table of Contents

1. [Introduction](#introduction)
2. [Core Development Principles](#core-development-principles)
3. [70/30 Rule - Understanding vs Implementation](#7030-rule---understanding-vs-implementation)
4. [Environment Setup](#environment-setup)
5. [Git Workflow & Branch Strategy](#git-workflow--branch-strategy)
6. [Code Development Guidelines](#code-development-guidelines)
7. [Testing Strategy](#testing-strategy)
8. [Security Best Practices](#security-best-practices)
9. [CI/CD Integration](#cicd-integration)
10. [Documentation Standards](#documentation-standards)
11. [Troubleshooting & Debugging](#troubleshooting--debugging)
12. [Appendix](#appendix)

---

## Introduction

### Project Overview

**RAGLOX V3** is an Enterprise Red Team Automation Platform built using:
- **Architecture**: Hybrid Blackboard + Redis Pub/Sub
- **Language**: Python 3.11+
- **Core Stack**: FastAPI, PostgreSQL, Redis, Docker
- **Modules**: 1,761 RX Modules
- **Technologies**: 201 Covered
- **Platforms**: Windows, Linux, macOS, Cloud

### Project Statistics

| Component | Count | Status |
|-----------|-------|--------|
| Production Tests | 79 | ✅ 100% Pass |
| Integration Tests | 40 | ✅ Complete |
| E2E Tests | 13 | ✅ Complete |
| Performance Tests | 5 | ✅ Complete |
| Security Tests | 11 | ✅ Complete |
| Chaos Tests | 10 | ✅ Complete |
| Code Coverage | ~85% | ✅ Target Met |
| Lines of Code | ~11,600 | 📈 Growing |

### Repository Information

- **Repository**: https://github.com/HosamN-ALI/Ragloxv3.git
- **Main Branch**: `main` (Production)
- **AI Development Branch**: `genspark_ai_developer` (Testing & Validation)
- **Development Branch**: `development` (Active Development)
- **Feature Branches**: `feature/*`, `bugfix/*`, `hotfix/*`

---

## Core Development Principles

### 1. Code Quality First

**Standards**:
- ✅ Clean, readable, maintainable code
- ✅ Comprehensive error handling
- ✅ Strong type hints (mypy validated)
- ✅ PEP 8 compliance (black formatted)
- ✅ No magic numbers or hardcoded values
- ✅ DRY (Don't Repeat Yourself)
- ✅ SOLID principles

**Example**:
```python
# ❌ BAD: Generic exception, no types
def process(data):
    try:
        result = do_something(data)
    except Exception as e:
        print(f"Error: {e}")
        return None

# ✅ GOOD: Specific exceptions, typed, logged
from typing import Optional
from src.core.exceptions import DataProcessingError, ValidationError

def process_data(data: dict[str, Any]) -> Optional[ProcessResult]:
    """
    Process mission data and return results.
    
    Args:
        data: Mission configuration dictionary
        
    Returns:
        ProcessResult object or None if processing fails
        
    Raises:
        ValidationError: If data validation fails
        DataProcessingError: If processing encounters errors
    """
    try:
        # Validate input
        validated_data = MissionSchema(**data)
        
        # Process
        result = execute_processing(validated_data)
        
        logger.info(
            "data_processed_successfully",
            data_id=validated_data.id,
            duration_ms=result.duration
        )
        return result
        
    except ValidationError as e:
        logger.error(
            "validation_failed",
            error=str(e),
            data_keys=list(data.keys())
        )
        raise
    except (ConnectionError, TimeoutError) as e:
        logger.warning(
            "processing_network_error",
            error_type=type(e).__name__,
            retry_attempted=True
        )
        raise DataProcessingError("Network error during processing") from e
    except Exception as e:
        logger.exception(
            "unexpected_processing_error",
            error_type=type(e).__name__
        )
        raise DataProcessingError(f"Unexpected error: {type(e).__name__}") from e
```

### 2. Test-Driven Development (TDD)

**Process**:
1. Write test first (Red)
2. Write minimal code to pass (Green)
3. Refactor (Clean)
4. Repeat

**Test Hierarchy**:
```
Unit Tests (Fast, Isolated)
    ↓
Integration Tests (Real Components, No Mocks)
    ↓
E2E Tests (Complete User Workflows)
    ↓
Performance Tests (Benchmarks & Baselines)
    ↓
Security Tests (Vulnerability Validation)
    ↓
Chaos Tests (Resilience & Recovery)
```

### 3. Security by Design

**Mandatory Practices**:
- ✅ Input validation on all endpoints
- ✅ Output encoding/sanitization
- ✅ SQL injection prevention (ORM only)
- ✅ XSS prevention (template escaping)
- ✅ CSRF protection (tokens)
- ✅ Rate limiting on all public endpoints
- ✅ Authentication required by default
- ✅ Authorization checks on all operations
- ✅ Secrets in environment variables ONLY
- ✅ Credentials encrypted at rest

### 4. Performance First

**Targets**:
- API Response: P95 < 2s, P99 < 5s
- Database Query: Simple < 50ms, Complex < 200ms
- Redis Operations: > 500 ops/sec
- Concurrent Requests: > 30 req/sec sustained

**Optimization Checklist**:
- [ ] Database queries use indexes
- [ ] N+1 queries eliminated
- [ ] Caching implemented where appropriate
- [ ] Connection pooling configured
- [ ] Async operations used for I/O
- [ ] Bulk operations instead of loops
- [ ] Load testing completed

---

## 70/30 Rule - Understanding vs Implementation

### The Golden Rule

> **70% of development time should be spent on Understanding & Analysis**  
> **30% of development time should be spent on Implementation & Execution**

This rule is MANDATORY for all development work and must be applied to:
- ✅ New feature development
- ✅ Bug fixes and debugging
- ✅ Code refactoring
- ✅ Architecture decisions
- ✅ Testing strategy
- ✅ Documentation updates
- ✅ Security implementations

### Why This Rule Exists

**Problems Solved**:
1. ❌ Premature implementation before full understanding
2. ❌ Incomplete solutions due to missed requirements
3. ❌ Technical debt from rushed code
4. ❌ Security vulnerabilities from inadequate design
5. ❌ Performance issues from poor architecture

### How to Apply the 70/30 Rule

#### Phase 1: Understanding (70% Time)

**Step 1: Context Gathering (20% of 70%)**
```bash
# Read project documentation
cd /root/RAGLOX_V3/webapp/webapp
cat README.md
cat docs/PRODUCTION_TESTING_GUIDE.md
cat docs/DEPLOYMENT_CHECKLIST.md
cat docs/OPERATIONS_GUIDE.md

# Examine architecture
ls -la src/
tree -L 2 src/

# Review existing code
grep -r "class Mission" src/
grep -r "def process_mission" src/
```

**Questions to Answer**:
- What problem are we solving?
- Why is this problem important?
- Who is affected by this problem?
- What are the constraints?
- What are the dependencies?
- What are the risks?

**Step 2: Requirements Analysis (30% of 70%)**

**Create a Requirements Document**:
```markdown
# Feature: Mission Auto-Retry

## Problem Statement
Missions fail transiently due to network issues, but require manual restart.

## User Story
As a penetration tester, I want missions to automatically retry on transient 
failures so that I don't have to manually monitor and restart them.

## Requirements
1. Detect transient vs permanent failures
2. Retry up to 3 times with exponential backoff
3. Log all retry attempts
4. Notify user after final failure
5. Preserve mission state between retries

## Non-Requirements
- Will NOT retry on authentication failures
- Will NOT retry on validation errors
- Will NOT retry after user-initiated stop

## Success Criteria
- [ ] 90% of transient failures recovered automatically
- [ ] No data loss during retry
- [ ] Performance impact < 5%
```

**Step 3: Design & Architecture (30% of 70%)**

**Design Document Template**:
```markdown
# Design: Mission Auto-Retry System

## Architecture Overview
```
┌─────────────┐
│   Mission   │
│ Controller  │
└──────┬──────┘
       │
       ↓
┌─────────────┐      ┌──────────────┐
│   Retry     │─────→│  Backoff     │
│   Manager   │      │  Calculator  │
└──────┬──────┘      └──────────────┘
       │
       ↓
┌─────────────┐
│   State     │
│   Store     │
└─────────────┘
```

## Component Specification

### RetryManager
- **Purpose**: Coordinate retry logic
- **Location**: `src/controller/retry_manager.py`
- **Dependencies**: `BackoffCalculator`, `StateStore`
- **Interface**:
  ```python
  class RetryManager:
      async def should_retry(self, error: Exception) -> bool
      async def execute_with_retry(self, func: Callable) -> Any
      async def get_retry_count(self, mission_id: str) -> int
  ```

### BackoffCalculator
- **Purpose**: Calculate retry delays
- **Algorithm**: Exponential with jitter
- **Formula**: delay = base * (2 ^ attempt) + random(0, 1)

## Data Flow
1. Mission execution fails
2. RetryManager checks if error is retryable
3. BackoffCalculator determines wait time
4. StateStore persists retry count
5. Wait for backoff period
6. Mission execution retried

## Error Handling
- NetworkError → Retry
- TimeoutError → Retry
- ValidationError → No Retry
- AuthenticationError → No Retry

## Testing Strategy
- Unit: RetryManager logic
- Integration: End-to-end retry flow
- Performance: Overhead measurement
- Chaos: Simulate various failure modes
```

**Step 4: Risk Assessment (20% of 70%)**

**Risk Matrix**:
| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Infinite retry loop | Medium | Critical | Hard limit of 3 retries |
| State corruption | Low | Critical | Atomic state updates |
| Performance degradation | Medium | Medium | Monitor retry overhead |
| Race conditions | Low | High | Use distributed locks |

#### Phase 2: Implementation (30% Time)

**Step 1: Setup (10% of 30%)**
```bash
# Create feature branch
cd /root/RAGLOX_V3/webapp/webapp
git checkout development
git pull origin development
git checkout -b feature/mission-auto-retry

# Create test file first (TDD)
touch tests/unit/test_retry_manager.py
```

**Step 2: Test-First Development (40% of 30%)**
```python
# tests/unit/test_retry_manager.py
import pytest
from src.controller.retry_manager import RetryManager
from src.core.exceptions import NetworkError, ValidationError

@pytest.mark.asyncio
class TestRetryManager:
    async def test_should_retry_on_network_error(self):
        """Network errors should trigger retry"""
        manager = RetryManager(max_retries=3)
        assert await manager.should_retry(NetworkError("Connection lost"))
    
    async def test_should_not_retry_on_validation_error(self):
        """Validation errors should NOT trigger retry"""
        manager = RetryManager(max_retries=3)
        assert not await manager.should_retry(ValidationError("Invalid input"))
    
    async def test_execute_with_retry_succeeds_eventually(self):
        """Should succeed after transient failures"""
        manager = RetryManager(max_retries=3)
        
        call_count = 0
        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise NetworkError("Temporary failure")
            return "success"
        
        result = await manager.execute_with_retry(flaky_function)
        
        assert result == "success"
        assert call_count == 3
    
    async def test_max_retries_respected(self):
        """Should not exceed max retry limit"""
        manager = RetryManager(max_retries=3)
        
        async def always_fails():
            raise NetworkError("Persistent failure")
        
        with pytest.raises(NetworkError):
            await manager.execute_with_retry(always_fails)
        
        assert await manager.get_retry_count("mission-1") == 3
```

**Step 3: Implementation (40% of 30%)**
```python
# src/controller/retry_manager.py
from typing import Callable, Any
import asyncio
import random
from src.core.exceptions import NetworkError, TimeoutError as RagloxTimeout
from src.core.logging import get_logger

logger = get_logger(__name__)

class RetryManager:
    """Manages automatic retries for mission operations"""
    
    RETRYABLE_EXCEPTIONS = (NetworkError, RagloxTimeout, ConnectionError)
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self._retry_counts: dict[str, int] = {}
    
    async def should_retry(self, error: Exception) -> bool:
        """Determine if error is retryable"""
        return isinstance(error, self.RETRYABLE_EXCEPTIONS)
    
    async def execute_with_retry(
        self,
        func: Callable,
        mission_id: str = None,
        *args,
        **kwargs
    ) -> Any:
        """Execute function with automatic retry logic"""
        
        attempt = 0
        last_error = None
        
        while attempt <= self.max_retries:
            try:
                result = await func(*args, **kwargs)
                
                # Success - reset retry count
                if mission_id:
                    self._retry_counts[mission_id] = 0
                
                logger.info(
                    "execution_succeeded",
                    mission_id=mission_id,
                    attempts=attempt + 1
                )
                
                return result
                
            except Exception as e:
                last_error = e
                
                if not await self.should_retry(e):
                    logger.error(
                        "non_retryable_error",
                        mission_id=mission_id,
                        error_type=type(e).__name__
                    )
                    raise
                
                attempt += 1
                
                if attempt > self.max_retries:
                    logger.error(
                        "max_retries_exceeded",
                        mission_id=mission_id,
                        total_attempts=attempt
                    )
                    break
                
                # Calculate backoff with jitter
                delay = self.base_delay * (2 ** attempt) + random.uniform(0, 1)
                
                logger.warning(
                    "retrying_after_error",
                    mission_id=mission_id,
                    attempt=attempt,
                    max_retries=self.max_retries,
                    delay_seconds=delay,
                    error=str(e)
                )
                
                # Track retry count
                if mission_id:
                    self._retry_counts[mission_id] = attempt
                
                await asyncio.sleep(delay)
        
        # All retries exhausted
        raise last_error
    
    async def get_retry_count(self, mission_id: str) -> int:
        """Get current retry count for mission"""
        return self._retry_counts.get(mission_id, 0)
```

**Step 4: Verification (10% of 30%)**
```bash
# Run tests
pytest tests/unit/test_retry_manager.py -v

# Check coverage
pytest tests/unit/test_retry_manager.py --cov=src.controller.retry_manager --cov-report=term-missing

# Lint
black src/controller/retry_manager.py
flake8 src/controller/retry_manager.py
mypy src/controller/retry_manager.py

# Integration test
pytest tests/integration/test_mission_retry.py -v
```

### Measuring Compliance

**Time Tracking Template**:
```markdown
## Task: Implement Mission Auto-Retry

### Understanding Phase (70%)
- [x] Context gathering: 2 hours
- [x] Requirements analysis: 3 hours
- [x] Design & architecture: 3 hours
- [x] Risk assessment: 2 hours
**Total**: 10 hours

### Implementation Phase (30%)
- [x] Setup: 0.5 hours
- [x] Test development: 2 hours
- [x] Implementation: 2 hours
- [x] Verification: 0.5 hours
**Total**: 5 hours

**Ratio**: 10:5 = 66.7%:33.3% ✅ (Close to 70:30)
```

---

## Environment Setup

### Prerequisites Checklist

- [ ] Docker & Docker Compose installed
- [ ] Python 3.11+ installed
- [ ] PostgreSQL 15+ client tools
- [ ] Redis 7+ client tools
- [ ] Git configured
- [ ] SSH keys for GitHub configured
- [ ] Minimum 8GB RAM available
- [ ] Minimum 20GB disk space

### Initial Setup

```bash
# 1. Clone repository
git clone https://github.com/HosamN-ALI/Ragloxv3.git
cd Ragloxv3/webapp/webapp

# 2. Verify working directory
pwd
# Expected: /root/RAGLOX_V3/webapp/webapp (or similar)

# 3. Create virtual environment
python3.11 -m venv venv

# 4. Activate virtual environment
source venv/bin/activate

# 5. Upgrade pip
pip install --upgrade pip setuptools wheel

# 6. Install dependencies
pip install -r requirements.txt

# 7. Install development dependencies
pip install -e ".[dev]"  # If setup.py exists

# 8. Copy environment template
cp .env.example .env

# 9. Edit environment variables
nano .env  # or vim, code, etc.

# 10. Start infrastructure
docker-compose up -d

# 11. Verify services
docker-compose ps

# 12. Run database migrations
python manage.py migrate  # If using Django
# OR
alembic upgrade head  # If using Alembic

# 13. Create superuser (if applicable)
python manage.py createsuperuser

# 14. Run tests to verify setup
pytest tests/ -v

# 15. Start development server
python -m uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Environment Variables

**Critical Variables** (.env file):
```bash
# PostgreSQL
POSTGRES_USER=raglox
POSTGRES_PASSWORD=your_secure_password_here
POSTGRES_DB=raglox
DATABASE_URL=postgresql://raglox:your_secure_password_here@localhost:5432/raglox

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=

# JWT
JWT_SECRET=your_jwt_secret_key_here_min_32_chars
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# API
API_HOST=0.0.0.0
API_PORT=8000
API_DEBUG=false
API_RELOAD=false

# Security
ENCRYPTION_KEY=your_base64_encoded_32_byte_key_here
CORS_ORIGINS=http://localhost:3000,http://localhost:8080

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Cloud Provider (Firecracker)
CLOUD_PROVIDER=firecracker
FIRECRACKER_ENABLED=true
FIRECRACKER_API_URL=http://208.115.230.194:8080
FIRECRACKER_DEFAULT_VCPU=2
FIRECRACKER_DEFAULT_MEM_MIB=2048
FIRECRACKER_DEFAULT_DISK_MB=10240
FIRECRACKER_VM_TIMEOUT=30
FIRECRACKER_MAX_VMS_PER_USER=5
FIRECRACKER_SSH_PASSWORD=raglox123
```

**⚠️ Security Note**: NEVER commit `.env` files to Git!

### Verification Commands

```bash
# Check Python version
python --version

# Check virtual environment
which python
# Should show path within venv

# Check installed packages
pip list

# Check database connection
psql -h localhost -U raglox -d raglox -c "SELECT 1"

# Check Redis connection
redis-cli ping
# Should return: PONG

# Check Docker services
docker-compose ps

# Check API health
curl http://localhost:8000/health
```

---

## Git Workflow & Branch Strategy

### Branch Structure

```
main (Production)
  ├── genspark_ai_developer (AI Development & Full Testing)
  │   ├── development (Active Development)
  │   │   ├── feature/user-auth
  │   │   ├── feature/mission-retry
  │   │   ├── bugfix/api-validation
  │   │   └── hotfix/security-patch
```

### Branch Purposes

| Branch | Purpose | Protected | Requires PR | Tests Required |
|--------|---------|-----------|-------------|----------------|
| `main` | Production | ✅ | ✅ | ALL 79 tests |
| `genspark_ai_developer` | AI Testing | ✅ | ✅ | ALL 79 tests |
| `development` | Integration | ⚠️ | ✅ | Unit + Integration |
| `feature/*` | New features | ❌ | ✅ | Unit tests |
| `bugfix/*` | Bug fixes | ❌ | ✅ | Related tests |
| `hotfix/*` | Urgent fixes | ❌ | ⚠️ | Smoke tests |

### Development Workflow

#### Starting New Work

```bash
# 1. Switch to development branch
git checkout development

# 2. Pull latest changes
git pull origin development

# 3. Create feature branch
git checkout -b feature/mission-auto-retry

# 4. Verify branch
git branch
git status
```

#### During Development

```bash
# Make changes
# Edit files...

# Check status
git status

# Review changes
git diff

# Stage changes
git add src/controller/retry_manager.py
git add tests/unit/test_retry_manager.py

# Commit with conventional commit format
git commit -m "feat(controller): add mission auto-retry system

- Implement RetryManager with exponential backoff
- Add retry logic for transient failures
- Include comprehensive unit tests
- Update documentation

Closes #123"

# Push to remote
git push origin feature/mission-auto-retry
```

#### Commit Message Format

**Conventional Commits**:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Formatting, missing semi colons, etc.
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding missing tests
- `chore`: Maintain, dependencies, etc.
- `perf`: Performance improvement
- `ci`: CI/CD changes

**Examples**:
```bash
# Feature
git commit -m "feat(api): add rate limiting middleware

- Implement token bucket algorithm
- Add Redis backend for distributed rate limiting
- Configure per-endpoint limits

Closes #456"

# Bug fix
git commit -m "fix(db): resolve connection pool exhaustion

- Increase pool size from 10 to 50
- Add connection timeout configuration
- Improve error handling for pool exhaustion

Fixes #789"

# Documentation
git commit -m "docs(readme): update installation instructions

- Add prerequisites section
- Include Docker setup steps
- Add troubleshooting guide"

# Refactor
git commit -m "refactor(controller): simplify mission state machine

- Extract state transition logic to separate class
- Reduce complexity from O(n²) to O(n)
- Maintain backward compatibility"
```

#### Creating Pull Requests

```bash
# 1. Ensure all commits are pushed
git push origin feature/mission-auto-retry

# 2. Fetch latest development
git fetch origin development

# 3. Rebase on development (if needed)
git rebase origin/development

# 4. Resolve conflicts (if any)
# Edit conflicted files
git add <resolved-files>
git rebase --continue

# 5. Force push (after rebase)
git push -f origin feature/mission-auto-retry

# 6. Create PR via GitHub UI
# Navigate to: https://github.com/HosamN-ALI/Ragloxv3/pull/new/feature/mission-auto-retry
```

**PR Template**:
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added/updated
- [ ] All tests passing

## Related Issues
Closes #123
Relates to #456

## Screenshots (if applicable)
```

#### Merging Strategy

**Feature → Development**:
```bash
# Squash merge for clean history
# Via GitHub UI: Use "Squash and merge" button
```

**Development → Genspark AI Developer**:
```bash
# Regular merge to preserve history
# Via GitHub UI: Use "Create a merge commit" button
```

**Genspark AI Developer → Main**:
```bash
# Regular merge with full validation
# Requires: All 79 tests passing, Code review approval
# Via GitHub UI: Use "Create a merge commit" button
```

### Conflict Resolution

```bash
# If conflicts occur during merge/rebase

# 1. Identify conflicted files
git status

# 2. Open conflicted file
# Look for conflict markers:
<<<<<<< HEAD
current changes
=======
incoming changes
>>>>>>> feature/mission-auto-retry

# 3. Resolve conflicts manually
# Keep current, incoming, or both based on context
# Remove conflict markers

# 4. Stage resolved files
git add <resolved-file>

# 5. Continue rebase/merge
git rebase --continue
# OR
git merge --continue

# 6. Verify resolution
git diff HEAD~1

# 7. Run tests
pytest tests/ -v

# 8. Push
git push origin <branch-name>
```

**Conflict Resolution Priority**:
1. **Prefer Remote (main/development) code** unless local changes are critical
2. **Discuss with team** if unsure
3. **Test thoroughly** after resolution
4. **Document decision** in commit message

---

## Code Development Guidelines

### Project Structure

```
webapp/webapp/
├── src/                          # Source code
│   ├── api/                      # FastAPI routes
│   │   ├── main.py              # Application entry point
│   │   ├── routes.py            # Route definitions
│   │   ├── auth_routes.py       # Authentication endpoints
│   │   ├── websocket.py         # WebSocket handlers
│   │   └── middleware/          # Middleware components
│   ├── controller/               # Mission control logic
│   │   ├── mission.py           # Mission controller
│   │   ├── scheduler.py         # Task scheduler
│   │   └── goal_tracker.py      # Goal tracking
│   ├── core/                     # Core components
│   │   ├── blackboard.py        # Blackboard implementation
│   │   ├── config.py            # Configuration
│   │   ├── database/            # Database models & utils
│   │   ├── exceptions.py        # Custom exceptions
│   │   ├── logging.py           # Logging setup
│   │   └── validators.py        # Input validation
│   ├── specialists/              # Specialist agents
│   │   ├── base.py              # Base specialist class
│   │   ├── recon.py             # Reconnaissance specialist
│   │   ├── attack.py            # Attack specialist
│   │   └── analysis.py          # Analysis specialist
│   ├── executors/                # Task executors
│   │   ├── base.py              # Base executor
│   │   ├── ssh.py               # SSH executor
│   │   └── winrm.py             # WinRM executor
│   ├── exploitation/             # Exploitation modules
│   ├── intelligence/             # Intelligence gathering
│   ├── infrastructure/           # Infrastructure management
│   │   └── cloud_provider/      # Cloud providers
│   │       ├── firecracker_client.py  # Firecracker integration
│   │       └── vm_manager.py    # VM management
│   └── utils/                    # Utility functions
├── tests/                        # Test suites
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   ├── production/              # Production test suite
│   │   ├── base.py              # Test base classes
│   │   ├── config.py            # Test configuration
│   │   ├── test_integration_*.py     # Integration tests
│   │   ├── test_e2e_*.py            # E2E tests
│   │   ├── test_performance.py      # Performance tests
│   │   ├── test_security.py         # Security tests
│   │   └── test_chaos.py            # Chaos tests
│   └── smoke/                   # Smoke tests
├── docs/                         # Documentation
│   ├── PRODUCTION_TESTING_GUIDE.md
│   ├── DEPLOYMENT_CHECKLIST.md
│   └── OPERATIONS_GUIDE.md
├── config/                       # Configuration files
├── scripts/                      # Utility scripts
├── docker-compose.yml            # Docker composition
├── Dockerfile                    # Docker image definition
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment template
├── pytest.ini                    # Pytest configuration
└── README.md                     # Project overview
```

### Coding Standards

#### Python Style Guide

**Follow PEP 8** with these additions:
- Line length: 88 characters (Black default)
- Indentation: 4 spaces (no tabs)
- Quotes: Double quotes for strings, single for characters
- Imports: Organized and sorted (isort)

**Formatting Tools**:
```bash
# Format code
black src/ tests/

# Check formatting
black --check src/ tests/

# Sort imports
isort src/ tests/

# Lint
flake8 src/ tests/

# Type check
mypy src/
```

#### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Module | lowercase_with_underscores | `retry_manager.py` |
| Class | CapWords | `RetryManager` |
| Function | lowercase_with_underscores | `execute_with_retry` |
| Method | lowercase_with_underscores | `should_retry` |
| Constant | UPPERCASE_WITH_UNDERSCORES | `MAX_RETRIES` |
| Variable | lowercase_with_underscores | `retry_count` |
| Private | _leading_underscore | `_internal_state` |
| Protected | _single_underscore | `_helper_method` |

#### Type Hints

**Always use type hints**:
```python
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime

# Function types
def process_mission(
    mission_id: str,
    config: Dict[str, Any],
    retry: bool = False
) -> Optional[MissionResult]:
    ...

# Class types
class MissionController:
    def __init__(
        self,
        database: Database,
        redis: Redis,
        max_retries: int = 3
    ) -> None:
        self.database = database
        self.redis = redis
        self.max_retries = max_retries
    
    async def start_mission(
        self,
        mission: Mission,
        callback: Optional[Callable[[MissionResult], None]] = None
    ) -> MissionResult:
        ...
```

#### Documentation

**Docstring Format** (Google Style):
```python
def calculate_backoff(
    attempt: int,
    base_delay: float = 1.0,
    max_delay: float = 60.0
) -> float:
    """
    Calculate exponential backoff delay with jitter.
    
    Uses the formula: delay = min(base * (2 ^ attempt) + random(0, 1), max)
    
    Args:
        attempt: Current retry attempt number (0-indexed)
        base_delay: Base delay in seconds. Defaults to 1.0.
        max_delay: Maximum delay in seconds. Defaults to 60.0.
    
    Returns:
        Calculated delay in seconds, capped at max_delay.
    
    Raises:
        ValueError: If attempt is negative or base_delay is non-positive.
    
    Example:
        >>> calculate_backoff(0)
        1.234  # 1.0 + random jitter
        >>> calculate_backoff(3, base_delay=2.0)
        16.789  # 2.0 * (2^3) + random jitter
    """
    if attempt < 0:
        raise ValueError("Attempt must be non-negative")
    if base_delay <= 0:
        raise ValueError("Base delay must be positive")
    
    delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
    return min(delay, max_delay)
```

#### Error Handling

**Exception Hierarchy**:
```python
# src/core/exceptions.py

class RagloxError(Exception):
    """Base exception for all RAGLOX errors"""
    pass

class ConfigurationError(RagloxError):
    """Configuration-related errors"""
    pass

class DatabaseError(RagloxError):
    """Database operation errors"""
    pass

class NetworkError(RagloxError):
    """Network communication errors"""
    pass

class TimeoutError(RagloxError):
    """Operation timeout errors"""
    pass

class ValidationError(RagloxError):
    """Input validation errors"""
    pass

class AuthenticationError(RagloxError):
    """Authentication failures"""
    pass

class AuthorizationError(RagloxError):
    """Authorization failures"""
    pass

class MissionError(RagloxError):
    """Mission execution errors"""
    pass

class TaskExecutionError(MissionError):
    """Task execution failures"""
    pass

class SpecialistError(MissionError):
    """Specialist agent errors"""
    pass
```

**Error Handling Pattern**:
```python
from src.core.exceptions import (
    NetworkError,
    TimeoutError as RagloxTimeout,
    TaskExecutionError
)
from src.core.logging import get_logger

logger = get_logger(__name__)

async def execute_task(task: Task) -> TaskResult:
    """Execute a single task with comprehensive error handling"""
    
    try:
        # Validate input
        if not task.is_valid():
            raise ValidationError(f"Invalid task configuration: {task.id}")
        
        # Execute
        result = await _perform_execution(task)
        
        # Log success
        logger.info(
            "task_executed_successfully",
            task_id=task.id,
            duration_ms=result.duration,
            result_size_bytes=len(result.data)
        )
        
        return result
        
    except ValidationError as e:
        # Don't retry validation errors
        logger.error(
            "task_validation_failed",
            task_id=task.id,
            error=str(e)
        )
        raise  # Re-raise without wrapping
    
    except (ConnectionError, socket.error) as e:
        # Network errors are retryable
        logger.warning(
            "task_network_error",
            task_id=task.id,
            error_type=type(e).__name__,
            retryable=True
        )
        raise NetworkError(f"Network error during task execution") from e
    
    except asyncio.TimeoutError as e:
        # Timeout errors are retryable
        logger.warning(
            "task_timeout",
            task_id=task.id,
            timeout_seconds=task.timeout,
            retryable=True
        )
        raise RagloxTimeout(f"Task timed out after {task.timeout}s") from e
    
    except Exception as e:
        # Unexpected errors - last resort
        logger.exception(
            "task_unexpected_error",
            task_id=task.id,
            error_type=type(e).__name__,
            error=str(e)
        )
        raise TaskExecutionError(
            f"Unexpected error during task execution: {type(e).__name__}"
        ) from e
```

#### Logging

**Structured Logging**:
```python
from src.core.logging import get_logger

logger = get_logger(__name__)

# Information
logger.info(
    "mission_started",
    mission_id=mission.id,
    user_id=user.id,
    targets_count=len(mission.targets)
)

# Warning
logger.warning(
    "rate_limit_approaching",
    user_id=user.id,
    current_rate=current_rate,
    limit=rate_limit,
    utilization_percent=utilization
)

# Error with context
logger.error(
    "mission_execution_failed",
    mission_id=mission.id,
    error_type=type(e).__name__,
    error_message=str(e),
    traceback=traceback.format_exc()
)

# Critical
logger.critical(
    "database_connection_lost",
    database_url=redacted_url,
    retry_attempts=retry_count,
    last_error=str(last_error)
)

# Debug (verbose)
logger.debug(
    "cache_hit",
    key=cache_key,
    ttl_remaining=ttl,
    data_size_bytes=len(data)
)
```

**Log Levels**:
- `DEBUG`: Detailed information for debugging
- `INFO`: General informational messages
- `WARNING`: Warning messages, but application continues
- `ERROR`: Error messages, operation failed
- `CRITICAL`: Critical errors, application may stop

---

## Testing Strategy

### Test Pyramid

```
        /\
       /  \      E2E Tests (13)
      /    \     [Slow, High Value]
     /------\
    /        \   Integration Tests (40)
   /          \  [Medium Speed, Medium Value]
  /------------\
 /              \ Unit Tests (100+)
/________________\ [Fast, Low Value]
```

### Test Categories

#### 1. Unit Tests

**Purpose**: Test individual functions/classes in isolation

**Location**: `tests/unit/`

**Characteristics**:
- Fast (< 100ms per test)
- No external dependencies
- Use mocks/fakes for dependencies
- High coverage (> 90%)

**Example**:
```python
# tests/unit/test_retry_manager.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from src.controller.retry_manager import RetryManager
from src.core.exceptions import NetworkError, ValidationError

@pytest.mark.asyncio
class TestRetryManager:
    """Unit tests for RetryManager"""
    
    @pytest.fixture
    def manager(self):
        """Create RetryManager instance"""
        return RetryManager(max_retries=3, base_delay=0.1)
    
    async def test_should_retry_returns_true_for_network_error(self, manager):
        """should_retry returns True for NetworkError"""
        result = await manager.should_retry(NetworkError("Connection lost"))
        assert result is True
    
    async def test_should_retry_returns_false_for_validation_error(self, manager):
        """should_retry returns False for ValidationError"""
        result = await manager.should_retry(ValidationError("Invalid input"))
        assert result is False
    
    async def test_execute_with_retry_succeeds_on_first_attempt(self, manager):
        """execute_with_retry succeeds without retry when no error"""
        mock_func = AsyncMock(return_value="success")
        
        result = await manager.execute_with_retry(mock_func, mission_id="test-1")
        
        assert result == "success"
        assert mock_func.call_count == 1
    
    async def test_execute_with_retry_retries_on_transient_failure(self, manager):
        """execute_with_retry retries on transient NetworkError"""
        mock_func = AsyncMock(
            side_effect=[
                NetworkError("Temporary failure"),
                NetworkError("Temporary failure"),
                "success"
            ]
        )
        
        result = await manager.execute_with_retry(mock_func, mission_id="test-2")
        
        assert result == "success"
        assert mock_func.call_count == 3
    
    async def test_execute_with_retry_fails_after_max_retries(self, manager):
        """execute_with_retry raises error after max retries exceeded"""
        mock_func = AsyncMock(side_effect=NetworkError("Persistent failure"))
        
        with pytest.raises(NetworkError):
            await manager.execute_with_retry(mock_func, mission_id="test-3")
        
        # max_retries=3 means 4 total attempts (initial + 3 retries)
        assert mock_func.call_count == 4
```

**Running Unit Tests**:
```bash
# All unit tests
pytest tests/unit/ -v

# Specific file
pytest tests/unit/test_retry_manager.py -v

# Specific test
pytest tests/unit/test_retry_manager.py::TestRetryManager::test_should_retry_returns_true_for_network_error -v

# With coverage
pytest tests/unit/ --cov=src --cov-report=term-missing --cov-report=html
```

#### 2. Integration Tests

**Purpose**: Test component interactions with real dependencies

**Location**: `tests/production/test_integration_*.py`

**Characteristics**:
- Medium speed (1-5s per test)
- Real database, Redis, APIs
- No mocks (real infrastructure)
- Tests actual integration

**Example**:
```python
# tests/production/test_integration_database.py
import pytest
from src.core.database import Database
from src.core.models import User, Organization

@pytest.mark.integration
class TestDatabaseIntegration:
    """Integration tests for database operations"""
    
    @pytest.fixture
    async def db(self):
        """Real database connection"""
        db = Database(url=os.getenv("TEST_DATABASE_URL"))
        await db.connect()
        yield db
        await db.disconnect()
    
    async def test_user_registration_real_database(self, db):
        """Test user registration with real database"""
        # Create user
        user = await db.users.create(
            email="test@example.com",
            password="SecurePass123!",
            name="Test User"
        )
        
        assert user.id is not None
        assert user.email == "test@example.com"
        assert user.name == "Test User"
        assert user.password != "SecurePass123!"  # Should be hashed
        
        # Verify persistence
        retrieved = await db.users.get(user.id)
        assert retrieved.email == user.email
        
        # Cleanup
        await db.users.delete(user.id)
    
    async def test_organization_user_relationship(self, db):
        """Test organization-user relationship with real database"""
        # Create organization
        org = await db.organizations.create(name="Test Corp")
        
        # Create user in organization
        user = await db.users.create(
            email="employee@testcorp.com",
            password="SecurePass123!",
            organization_id=org.id
        )
        
        # Verify relationship
        org_users = await db.organizations.get_users(org.id)
        assert len(org_users) == 1
        assert org_users[0].id == user.id
        
        # Cleanup
        await db.users.delete(user.id)
        await db.organizations.delete(org.id)
```

**Running Integration Tests**:
```bash
# All integration tests
pytest -m integration tests/production/ -v

# Specific category
pytest tests/production/test_integration_database.py -v
pytest tests/production/test_integration_redis.py -v
pytest tests/production/test_integration_api.py -v

# With infrastructure setup
cd tests/production
./setup-infrastructure.sh
cd ../../
pytest -m integration tests/production/ -v
```

#### 3. End-to-End Tests

**Purpose**: Test complete user workflows

**Location**: `tests/production/test_e2e_*.py`

**Characteristics**:
- Slow (30s - 5min per test)
- Multiple components involved
- Real user scenarios
- High confidence

**Example**:
```python
# tests/production/test_e2e_mission_lifecycle.py
import pytest
from src.api.client import APIClient
from src.core.models import MissionStatus

@pytest.mark.e2e
class TestMissionLifecycleE2E:
    """End-to-end tests for complete mission lifecycle"""
    
    @pytest.fixture
    async def api_client(self):
        """Authenticated API client"""
        client = APIClient(base_url=os.getenv("TEST_API_URL"))
        
        # Register and login
        await client.register(
            email="tester@example.com",
            password="TestPass123!"
        )
        await client.login(
            email="tester@example.com",
            password="TestPass123!"
        )
        
        yield client
        
        await client.logout()
    
    async def test_complete_mission_workflow(self, api_client):
        """Test complete mission from creation to report generation"""
        
        # 1. Create mission
        mission = await api_client.missions.create(
            name="E2E Test Mission",
            scope=["10.0.0.0/24"],
            goals=["domain_admin"]
        )
        assert mission.status == MissionStatus.PENDING
        
        # 2. Start mission
        await api_client.missions.start(mission.id)
        await asyncio.sleep(5)  # Wait for initialization
        
        mission = await api_client.missions.get(mission.id)
        assert mission.status == MissionStatus.RUNNING
        
        # 3. Wait for target discovery
        for _ in range(30):  # 5 minutes max
            targets = await api_client.missions.get_targets(mission.id)
            if len(targets) > 0:
                break
            await asyncio.sleep(10)
        
        assert len(targets) > 0, "No targets discovered"
        
        # 4. Wait for vulnerabilities
        for _ in range(60):  # 10 minutes max
            vulns = await api_client.missions.get_vulnerabilities(mission.id)
            if len(vulns) > 0:
                break
            await asyncio.sleep(10)
        
        assert len(vulns) > 0, "No vulnerabilities found"
        
        # 5. Stop mission
        await api_client.missions.stop(mission.id)
        
        mission = await api_client.missions.get(mission.id)
        assert mission.status in [MissionStatus.STOPPED, MissionStatus.COMPLETED]
        
        # 6. Generate report
        report = await api_client.missions.generate_report(mission.id)
        assert report is not None
        assert len(report.targets) > 0
        assert len(report.vulnerabilities) > 0
        
        # Cleanup
        await api_client.missions.delete(mission.id)
```

**Running E2E Tests**:
```bash
# All E2E tests (slow)
pytest -m e2e tests/production/ -v -s

# Specific workflow
pytest tests/production/test_e2e_mission_lifecycle.py -v -s

# With timeout extension
pytest -m e2e tests/production/ -v -s --timeout=600
```

#### 4. Performance Tests

**Purpose**: Establish performance baselines and detect regressions

**Location**: `tests/production/test_performance.py`

**Example**:
```python
# tests/production/test_performance.py
import pytest
import time
from concurrent.futures import ThreadPoolExecutor

@pytest.mark.performance
class TestPerformance:
    """Performance and load tests"""
    
    async def test_api_concurrent_requests(self, api_client):
        """Test API handles concurrent requests efficiently"""
        
        async def create_mission():
            start = time.time()
            mission = await api_client.missions.create(
                name="Perf Test",
                scope=["10.0.0.1"]
            )
            duration = time.time() - start
            return duration, mission
        
        # Execute 50 concurrent requests
        start_time = time.time()
        
        tasks = [create_mission() for _ in range(50)]
        results = await asyncio.gather(*tasks)
        
        total_duration = time.time() - start_time
        durations = [r[0] for r in results]
        
        # Assertions
        avg_duration = sum(durations) / len(durations)
        p95_duration = sorted(durations)[int(len(durations) * 0.95)]
        
        assert avg_duration < 1.0, f"Average request too slow: {avg_duration}s"
        assert p95_duration < 2.0, f"P95 too slow: {p95_duration}s"
        assert total_duration < 10.0, f"Total time too slow: {total_duration}s"
        
        throughput = len(tasks) / total_duration
        assert throughput > 5.0, f"Throughput too low: {throughput} req/s"
    
    async def test_database_query_performance(self, db):
        """Test database queries meet performance requirements"""
        
        # Simple SELECT
        start = time.time()
        users = await db.users.list(limit=100)
        duration = time.time() - start
        
        assert duration < 0.05, f"Simple SELECT too slow: {duration}s"
        
        # Complex JOIN
        start = time.time()
        result = await db.execute("""
            SELECT u.*, o.name as org_name, COUNT(m.id) as mission_count
            FROM users u
            LEFT JOIN organizations o ON u.organization_id = o.id
            LEFT JOIN missions m ON m.user_id = u.id
            GROUP BY u.id, o.name
            LIMIT 100
        """)
        duration = time.time() - start
        
        assert duration < 0.2, f"Complex JOIN too slow: {duration}s"
```

**Running Performance Tests**:
```bash
# Performance tests
pytest -m performance tests/production/ -v -s

# Generate performance report
pytest -m performance tests/production/ -v -s --benchmark-only --benchmark-json=benchmark.json
```

#### 5. Security Tests

**Purpose**: Validate security mechanisms and prevent vulnerabilities

**Location**: `tests/production/test_security.py`

**Example**:
```python
# tests/production/test_security.py
import pytest
from src.api.client import APIClient

@pytest.mark.security
class TestSecurity:
    """Security validation tests"""
    
    async def test_sql_injection_prevention(self, api_client):
        """Test API prevents SQL injection attacks"""
        
        # Attempt SQL injection in search
        payload = "test' OR '1'='1"
        
        try:
            results = await api_client.search(query=payload)
            # Should not return all results
            assert len(results) < 1000, "Possible SQL injection vulnerability"
        except ValidationError:
            # Expected - input validation rejected payload
            pass
    
    async def test_xss_prevention(self, api_client):
        """Test API prevents XSS attacks"""
        
        # Attempt XSS in mission name
        xss_payload = "<script>alert('XSS')</script>"
        
        mission = await api_client.missions.create(
            name=xss_payload,
            scope=["10.0.0.1"]
        )
        
        # Retrieve and verify encoding
        retrieved = await api_client.missions.get(mission.id)
        
        # Name should be HTML-encoded
        assert "<script>" not in retrieved.name
        assert "&lt;script&gt;" in retrieved.name or retrieved.name == xss_payload
        
        # Cleanup
        await api_client.missions.delete(mission.id)
    
    async def test_authentication_required(self, unauthenticated_client):
        """Test protected endpoints require authentication"""
        
        with pytest.raises(AuthenticationError):
            await unauthenticated_client.missions.list()
    
    async def test_authorization_enforced(self, api_client, other_user_client):
        """Test users cannot access other users' missions"""
        
        # Create mission as user 1
        mission = await api_client.missions.create(
            name="Private Mission",
            scope=["10.0.0.1"]
        )
        
        # Attempt to access as user 2
        with pytest.raises(AuthorizationError):
            await other_user_client.missions.get(mission.id)
        
        # Cleanup
        await api_client.missions.delete(mission.id)
```

**Running Security Tests**:
```bash
# Security tests
pytest -m security tests/production/ -v -s

# With security scanning
bandit -r src/ -ll
safety check
```

#### 6. Chaos Tests

**Purpose**: Verify system resilience under failure conditions

**Location**: `tests/production/test_chaos.py`

**Example**:
```python
# tests/production/test_chaos.py
import pytest
import docker
import time

@pytest.mark.chaos
class TestChaos:
    """Chaos engineering tests"""
    
    @pytest.fixture
    def docker_client(self):
        """Docker client for chaos injection"""
        return docker.from_env()
    
    async def test_database_connection_loss_recovery(
        self,
        api_client,
        docker_client
    ):
        """Test system recovers from database connection loss"""
        
        # Create mission before chaos
        mission = await api_client.missions.create(
            name="Chaos Test",
            scope=["10.0.0.1"]
        )
        
        # Stop database container
        postgres_container = docker_client.containers.get("raglox_postgres")
        postgres_container.stop()
        
        # Wait for connection pool to detect failure
        time.sleep(5)
        
        # Attempt operation (should fail gracefully)
        with pytest.raises(DatabaseError):
            await api_client.missions.get(mission.id)
        
        # Restart database
        postgres_container.start()
        time.sleep(10)  # Wait for startup
        
        # Verify recovery
        retrieved = await api_client.missions.get(mission.id)
        assert retrieved.id == mission.id
        
        # Cleanup
        await api_client.missions.delete(mission.id)
    
    async def test_redis_failure_graceful_degradation(
        self,
        api_client,
        docker_client
    ):
        """Test system degrades gracefully when Redis fails"""
        
        # Stop Redis container
        redis_container = docker_client.containers.get("raglox_redis")
        redis_container.stop()
        
        # Operations should still work (without caching)
        missions = await api_client.missions.list()
        assert isinstance(missions, list)
        
        # Create mission (should work without cache)
        mission = await api_client.missions.create(
            name="No Cache Test",
            scope=["10.0.0.1"]
        )
        assert mission.id is not None
        
        # Restart Redis
        redis_container.start()
        time.sleep(5)
        
        # Verify cache recovery
        cached_mission = await api_client.missions.get(mission.id)
        assert cached_mission.id == mission.id
        
        # Cleanup
        await api_client.missions.delete(mission.id)
```

**Running Chaos Tests**:
```bash
# Chaos tests (requires Docker access)
pytest -m chaos tests/production/ -v -s

# Specific chaos scenario
pytest tests/production/test_chaos.py::TestChaos::test_database_connection_loss_recovery -v -s
```

### Test Execution

**Full Test Suite**:
```bash
# All tests (slow)
pytest tests/ -v

# Production test suite only (79 tests)
pytest tests/production/ -v

# By marker
pytest -m integration tests/production/ -v
pytest -m e2e tests/production/ -v -s
pytest -m performance tests/production/ -v -s
pytest -m security tests/production/ -v -s
pytest -m chaos tests/production/ -v -s

# Parallel execution
pytest tests/production/ -n 4 -v

# With coverage
pytest tests/production/ --cov=src --cov-report=html --cov-report=term-missing

# Generate reports
pytest tests/production/ -v --html=report.html --self-contained-html
pytest tests/production/ -v --junit-xml=results.xml
```

### Code Coverage

**Target**: ≥ 80% overall, ≥ 90% for critical paths

**Check Coverage**:
```bash
# Generate coverage report
pytest tests/ --cov=src --cov-report=html --cov-report=term-missing

# View HTML report
open htmlcov/index.html

# Check coverage percentage
coverage report

# Fail if below threshold
pytest tests/ --cov=src --cov-fail-under=80
```

---

## Security Best Practices

### Input Validation

**Always validate input using Pydantic**:
```python
from pydantic import BaseModel, validator, Field
from typing import List

class MissionCreateRequest(BaseModel):
    """Mission creation request validation"""
    
    name: str = Field(..., min_length=3, max_length=100)
    scope: List[str] = Field(..., min_items=1, max_items=100)
    goals: List[str] = Field(..., min_items=1, max_items=10)
    
    @validator('name')
    def validate_name(cls, v):
        """Validate mission name"""
        # No special characters except dash and underscore
        if not v.replace('-', '').replace('_', '').replace(' ', '').isalnum():
            raise ValueError("Name contains invalid characters")
        return v
    
    @validator('scope')
    def validate_scope(cls, v):
        """Validate IP addresses/ranges in scope"""
        import ipaddress
        
        for item in v:
            try:
                # Validate CIDR notation
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError(f"Invalid IP/CIDR: {item}")
        
        return v
    
    @validator('goals')
    def validate_goals(cls, v):
        """Validate mission goals"""
        valid_goals = {
            "domain_admin",
            "user_credentials",
            "data_exfiltration",
            "lateral_movement"
        }
        
        for goal in v:
            if goal not in valid_goals:
                raise ValueError(f"Invalid goal: {goal}")
        
        return v
```

### SQL Injection Prevention

**Use ORM only - NO raw SQL**:
```python
# ❌ NEVER DO THIS
query = f"SELECT * FROM users WHERE email = '{email}'"
result = await db.execute(query)

# ✅ USE ORM
from sqlalchemy import select
from src.core.models import User

stmt = select(User).where(User.email == email)
result = await db.execute(stmt)
user = result.scalar_one_or_none()

# ✅ OR use parameterized queries if raw SQL is absolutely necessary
query = "SELECT * FROM users WHERE email = :email"
result = await db.execute(query, {"email": email})
```

### XSS Prevention

**Always escape output**:
```python
from markupsafe import escape
from fastapi.responses import HTMLResponse

@app.get("/mission/{mission_id}")
async def get_mission_page(mission_id: str):
    mission = await get_mission(mission_id)
    
    # Escape user-provided content
    safe_name = escape(mission.name)
    safe_description = escape(mission.description)
    
    html = f"""
    <html>
        <body>
            <h1>{safe_name}</h1>
            <p>{safe_description}</p>
        </body>
    </html>
    """
    
    return HTMLResponse(content=html)
```

### Authentication

**Use JWT tokens**:
```python
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM
    )
    
    return encoded_jwt

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """Get current authenticated user from JWT token"""
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        token = credentials.credentials
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise credentials_exception
        
    except JWTError:
        raise credentials_exception
    
    user = await get_user_by_id(user_id)
    
    if user is None:
        raise credentials_exception
    
    return user
```

### Authorization

**Check permissions**:
```python
from fastapi import Depends, HTTPException, status
from src.core.models import User, Mission

async def check_mission_access(
    mission_id: str,
    current_user: User = Depends(get_current_user)
) -> Mission:
    """Verify user has access to mission"""
    
    mission = await get_mission(mission_id)
    
    if mission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mission not found"
        )
    
    # Check ownership or organization membership
    if mission.user_id != current_user.id:
        if current_user.organization_id != mission.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
    
    return mission

# Usage in endpoint
@app.get("/api/v1/missions/{mission_id}")
async def get_mission(
    mission: Mission = Depends(check_mission_access)
):
    return mission
```

### Rate Limiting

**Implement rate limiting**:
```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, Request

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/v1/missions")
@limiter.limit("10/minute")
async def create_mission(
    request: Request,
    data: MissionCreateRequest,
    current_user: User = Depends(get_current_user)
):
    """Create mission with rate limiting"""
    mission = await create_new_mission(data, current_user)
    return mission
```

### Secrets Management

**Never hardcode secrets**:
```python
# ❌ NEVER
DATABASE_URL = "postgresql://user:password@localhost/db"
API_KEY = "sk_live_abc123xyz"

# ✅ USE environment variables
import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    """Application settings from environment"""
    
    database_url: str
    redis_url: str
    jwt_secret: str
    api_key: str
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()

# Access
db = Database(url=settings.database_url)
```

### Logging Security

**Mask sensitive data in logs**:
```python
import re
from src.core.logging import get_logger

logger = get_logger(__name__)

def mask_credentials(text: str) -> str:
    """Mask sensitive information in text"""
    # Mask passwords
    text = re.sub(
        r'password["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
        r'password=***REDACTED***',
        text,
        flags=re.IGNORECASE
    )
    
    # Mask API keys
    text = re.sub(
        r'(api[_-]?key|token)["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)',
        r'\1=***REDACTED***',
        text,
        flags=re.IGNORECASE
    )
    
    return text

# Use when logging
data = {"username": "user@example.com", "password": "secret123"}
logger.info("user_login_attempt", data=mask_credentials(str(data)))
```

---

## CI/CD Integration

### GitHub Actions Workflow

**Location**: `.github/workflows/production-tests.yml`

**Workflow Structure**:
```yaml
name: Production Tests CI/CD

on:
  push:
    branches: [main, genspark_ai_developer, development]
  pull_request:
    branches: [main, genspark_ai_developer]
  schedule:
    - cron: '0 0 * * *'  # Daily
  workflow_dispatch:

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest tests/unit/ -v --cov=src --cov-report=xml
      - uses: codecov/codecov-action@v3
  
  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test_password
      redis:
        image: redis:7
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: pytest -m integration tests/production/ -v
  
  e2e-tests:
    runs-on: ubuntu-latest
    needs: [unit-tests, integration-tests]
    steps:
      - uses: actions/checkout@v3
      - run: docker-compose up -d
      - run: pytest -m e2e tests/production/ -v -s
  
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: bandit -r src/ -ll
      - run: safety check
      - run: pytest -m security tests/production/ -v
```

### Local CI Simulation

**Using `act`**:
```bash
# Install act
brew install act  # macOS
# OR
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run workflow locally
act

# Run specific job
act -j unit-tests

# Run with secrets
act -s JWT_SECRET=test_secret -s DATABASE_URL=postgresql://localhost/test
```

### Pre-Commit Hooks

**Setup**:
```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml << 'EOF'
repos:
  - repo: https://github.com/psf/black
    rev: 23.1.0
    hooks:
      - id: black
        language_version: python3.11
  
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
  
  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8
        args: ['--max-line-length=88', '--extend-ignore=E203']
  
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.0.1
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
  
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.4
    hooks:
      - id: bandit
        args: ['-ll', '-r', 'src/']
  
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
      - id: check-json
      - id: check-toml
      - id: debug-statements
      - id: name-tests-test
        args: ['--django']
EOF

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

---

## Documentation Standards

### Code Documentation

**Every module should have a docstring**:
```python
"""
Mission retry management module.

This module provides automatic retry logic for mission operations that fail
due to transient errors such as network issues or timeouts. It implements
exponential backoff with jitter to avoid thundering herd problems.

Classes:
    RetryManager: Coordinates retry logic with configurable policies
    BackoffCalculator: Calculates retry delays using exponential backoff

Functions:
    create_retry_manager: Factory function for RetryManager instances

Example:
    >>> manager = create_retry_manager(max_retries=3)
    >>> result = await manager.execute_with_retry(risky_operation)

Author: RAGLOX Team
Version: 1.0.0
License: MIT
"""
```

### README Files

**Every major component should have a README**:
```markdown
# Component Name

Brief description of what this component does.

## Purpose

Detailed explanation of the component's purpose and role in the system.

## Usage

### Basic Example
```python
from src.component import ComponentClass

component = ComponentClass(config)
result = component.do_something()
```

### Advanced Example
```python
# More complex usage
```

## API Reference

### `ComponentClass`

#### Methods

##### `do_something(param1, param2)`

Description of what this method does.

**Parameters:**
- `param1` (str): Description
- `param2` (int): Description

**Returns:**
- `Result`: Description

**Raises:**
- `ValueError`: When...
- `ConnectionError`: When...

## Configuration

Required environment variables:
- `COMPONENT_URL`: URL of the component service
- `COMPONENT_TIMEOUT`: Timeout in seconds

## Testing

```bash
pytest tests/test_component.py -v
```

## Contributing

See main CONTRIBUTING.md for guidelines.

## License

MIT License - see LICENSE file.
```

### API Documentation

**Use OpenAPI/Swagger annotations**:
```python
from fastapi import FastAPI, Path, Query
from pydantic import BaseModel, Field

app = FastAPI(
    title="RAGLOX API",
    description="Red Team Automation Platform API",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

class MissionResponse(BaseModel):
    """Mission response model"""
    
    id: str = Field(..., description="Unique mission identifier")
    name: str = Field(..., description="Mission name")
    status: str = Field(..., description="Current mission status")
    
    class Config:
        schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Penetration Test - Q1 2026",
                "status": "running"
            }
        }

@app.get(
    "/api/v1/missions/{mission_id}",
    response_model=MissionResponse,
    summary="Get mission details",
    description="Retrieve detailed information about a specific mission",
    response_description="Mission details",
    tags=["missions"]
)
async def get_mission(
    mission_id: str = Path(..., description="Mission UUID"),
    include_targets: bool = Query(False, description="Include target list"),
    current_user: User = Depends(get_current_user)
):
    """
    Get mission details by ID.
    
    **Parameters:**
    - `mission_id`: UUID of the mission to retrieve
    - `include_targets`: Whether to include full target list
    
    **Returns:**
    Mission object with all details
    
    **Raises:**
    - 404: Mission not found
    - 403: Access denied
    """
    mission = await get_mission_by_id(mission_id, current_user)
    return mission
```

### Changelog

**Maintain CHANGELOG.md**:
```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Mission auto-retry system with exponential backoff

### Changed
- Updated authentication to use JWT instead of sessions

### Fixed
- Fixed race condition in mission state machine

## [3.0.0] - 2026-01-08

### Added
- Complete production test suite (79 tests)
- Firecracker VM integration
- HITL approval workflow
- Knowledge base search
- Chat functionality

### Changed
- Migrated to FastAPI from Flask
- Switched to PostgreSQL from SQLite
- Implemented Blackboard architecture

### Deprecated
- Legacy API v0.9 endpoints (will be removed in v4.0.0)

### Removed
- OneProvider cloud integration (replaced by Firecracker)

### Fixed
- SQL injection vulnerabilities
- XSS in mission names
- Rate limiting bypass

### Security
- Added rate limiting on all public endpoints
- Implemented CSRF protection
- Enhanced input validation
- Encrypted credentials at rest

## [2.5.0] - 2025-12-15
...
```

---

## Troubleshooting & Debugging

### Common Issues

#### 1. Import Errors

**Problem**: `ModuleNotFoundError: No module named 'src'`

**Solution**:
```bash
# Ensure you're in the correct directory
cd /root/RAGLOX_V3/webapp/webapp

# Check PYTHONPATH
echo $PYTHONPATH

# Add current directory to PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Or install in development mode
pip install -e .
```

#### 2. Database Connection Errors

**Problem**: `Connection refused` when connecting to PostgreSQL

**Solution**:
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Restart PostgreSQL
docker-compose restart postgres

# Verify connection
psql -h localhost -p 5432 -U raglox -d raglox

# Check DATABASE_URL in .env
cat .env | grep DATABASE_URL
```

#### 3. Redis Connection Errors

**Problem**: `Connection refused` when connecting to Redis

**Solution**:
```bash
# Check if Redis is running
docker-compose ps redis

# Test connection
redis-cli -h localhost -p 6379 ping

# Restart Redis
docker-compose restart redis

# Flush Redis (caution: deletes all data)
redis-cli -h localhost -p 6379 FLUSHDB
```

#### 4. Test Failures

**Problem**: Tests failing unexpectedly

**Solution**:
```bash
# Run with verbose output
pytest tests/failing_test.py -vvv -s

# Run with debugger
pytest tests/failing_test.py --pdb

# Check test data
pytest tests/failing_test.py -vvv -s --setup-show

# Clean test database
docker-compose down -v
docker-compose up -d
```

#### 5. Performance Issues

**Problem**: Slow API responses

**Solution**:
```bash
# Profile code
python -m cProfile -o profile.stats src/api/main.py

# Analyze profile
python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(20)"

# Check database queries
# Enable query logging in PostgreSQL
docker-compose exec postgres psql -U raglox -c "ALTER DATABASE raglox SET log_statement = 'all';"

# Monitor slow queries
docker-compose logs -f postgres | grep "duration:"

# Check Redis performance
redis-cli --latency

# Monitor API metrics
curl http://localhost:8000/metrics
```

### Debugging Techniques

#### Using Python Debugger (pdb)

```python
import pdb

def problematic_function():
    x = calculate_something()
    
    # Set breakpoint
    pdb.set_trace()
    
    y = process_result(x)
    return y
```

**PDB Commands**:
- `n` (next): Execute current line
- `s` (step): Step into function
- `c` (continue): Continue execution
- `l` (list): Show current code
- `p variable`: Print variable value
- `pp variable`: Pretty-print variable
- `h`: Help
- `q`: Quit

#### Using IPython Debugger (ipdb)

```python
import ipdb

def problematic_function():
    x = calculate_something()
    
    # Set breakpoint with IPython
    ipdb.set_trace()
    
    y = process_result(x)
    return y
```

#### Remote Debugging with VS Code

**.vscode/launch.json**:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: FastAPI",
            "type": "python",
            "request": "launch",
            "module": "uvicorn",
            "args": [
                "src.api.main:app",
                "--reload",
                "--host",
                "0.0.0.0",
                "--port",
                "8000"
            ],
            "jinja": true,
            "justMyCode": false,
            "env": {
                "PYTHONPATH": "${workspaceFolder}"
            }
        },
        {
            "name": "Python: Current File",
            "type": "python",
            "request": "launch",
            "program": "${file}",
            "console": "integratedTerminal",
            "justMyCode": false
        },
        {
            "name": "Python: Pytest",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": [
                "${file}",
                "-v",
                "-s"
            ],
            "console": "integratedTerminal",
            "justMyCode": false
        }
    ]
}
```

### Logging Best Practices

```python
from src.core.logging import get_logger

logger = get_logger(__name__)

# Use appropriate log levels
logger.debug("Detailed debug information")
logger.info("Informational message")
logger.warning("Warning message")
logger.error("Error occurred", exc_info=True)  # Include traceback
logger.critical("Critical error - system may be unstable")

# Include context
logger.info(
    "mission_created",
    mission_id=mission.id,
    user_id=user.id,
    organization_id=user.organization_id,
    target_count=len(mission.targets)
)

# Log performance metrics
import time
start_time = time.time()
result = perform_operation()
duration = time.time() - start_time

logger.info(
    "operation_completed",
    operation="data_processing",
    duration_ms=duration * 1000,
    records_processed=result.count
)
```

---

## Appendix

### A. Quick Reference

#### Essential Commands

```bash
# Git
git checkout development
git pull origin development
git checkout -b feature/my-feature
git add .
git commit -m "feat: add my feature"
git push origin feature/my-feature

# Python
source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn src.api.main:app --reload

# Docker
docker-compose up -d
docker-compose ps
docker-compose logs -f
docker-compose down

# Testing
pytest tests/ -v
pytest -m integration tests/production/ -v
pytest tests/ --cov=src --cov-report=html

# Linting
black src/ tests/
isort src/ tests/
flake8 src/ tests/
mypy src/

# Database
psql -h localhost -U raglox -d raglox
python manage.py migrate
python manage.py makemigrations

# Redis
redis-cli -h localhost -p 6379
redis-cli -h localhost -p 6379 FLUSHDB
```

#### Environment Variables

```bash
# Required
DATABASE_URL=postgresql://user:pass@localhost/db
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=your_secret_min_32_chars

# Optional
LOG_LEVEL=INFO
API_DEBUG=false
CORS_ORIGINS=http://localhost:3000
```

#### Test Markers

```bash
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests
pytest -m e2e          # End-to-end tests
pytest -m performance  # Performance tests
pytest -m security     # Security tests
pytest -m chaos        # Chaos tests
```

### B. Resources

#### Documentation
- [README.md](README.md)
- [Production Testing Guide](docs/PRODUCTION_TESTING_GUIDE.md)
- [Deployment Checklist](docs/DEPLOYMENT_CHECKLIST.md)
- [Operations Guide](docs/OPERATIONS_GUIDE.md)
- [API Documentation](http://localhost:8000/docs)

#### External Resources
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Pytest Documentation](https://docs.pytest.org/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [Redis Documentation](https://redis.io/docs/)
- [Docker Documentation](https://docs.docker.com/)
- [Git Best Practices](https://www.conventionalcommits.org/)

### C. Contact & Support

#### Team
- **Repository**: https://github.com/HosamN-ALI/Ragloxv3
- **Issues**: https://github.com/HosamN-ALI/Ragloxv3/issues
- **Pull Requests**: https://github.com/HosamN-ALI/Ragloxv3/pulls

#### Getting Help
1. Check this documentation
2. Search existing issues on GitHub
3. Review related documentation
4. Ask in team channels
5. Create new issue if needed

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-01-08 | RAGLOX Team | Initial comprehensive guide |

---

**Document End**

---

**Remember the 70/30 Rule**: 70% Understanding, 30% Implementation

**Always**:
- ✅ Understand before implementing
- ✅ Test before committing
- ✅ Document while coding
- ✅ Review before pushing
- ✅ Validate before deploying

**Never**:
- ❌ Rush to code without understanding
- ❌ Skip tests
- ❌ Commit without testing
- ❌ Push without review
- ❌ Deploy without validation
- ❌ Hardcode secrets
- ❌ Ignore security
- ❌ Leave TODOs unresolved
- ❌ Forget to update documentation

**Happy Coding! 🚀**
