# 🌳 Git Branching Strategy - RAGLOX V3

## Overview
This document defines the Git branching strategy for RAGLOX V3 project.

---

## 📊 Branch Structure

```
┌─────────────────────────────────────────────────────────────┐
│                         PRODUCTION                          │
│                        main (stable)                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ PR (after testing)
                           │
┌──────────────────────────┴──────────────────────────────────┐
│                      TESTING & AI                           │
│              genspark_ai_developer (testing)                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           │ PR (after development)
                           │
┌──────────────────────────┴──────────────────────────────────┐
│                    ACTIVE DEVELOPMENT                       │
│                  development (unstable)                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                ┌──────────┼──────────┐
                │          │          │
         ┌──────┴───┐  ┌──┴────┐  ┌──┴──────┐
         │ feature/ │  │bugfix/│  │hotfix/  │
         │ branches │  │branches│  │branches │
         └──────────┘  └───────┘  └─────────┘
```

---

## 🎯 Branch Purposes

### 1. `main` - Production Branch 🟢
- **Purpose**: Production-ready code only
- **Stability**: 🟢 Stable (100%)
- **Deployable**: ✅ Always
- **Protection**: Protected branch, requires PR approval
- **Tests**: All 79 production tests must pass
- **Updates**: Only from `genspark_ai_developer` via PR

**Rules**:
- ❌ No direct commits
- ✅ Only merge via approved PRs
- ✅ All tests must pass
- ✅ Code review required
- ✅ Deployment ready at all times

### 2. `genspark_ai_developer` - AI Development & Testing Branch 🟡
- **Purpose**: AI-driven development, comprehensive testing
- **Stability**: 🟡 Testing (95%)
- **Deployable**: ⚠️ Review Required
- **Protection**: Protected, requires testing
- **Tests**: Full production test suite (79 tests)
- **Updates**: From `development` via PR after testing

**Rules**:
- ✅ Used for AI-driven development
- ✅ Production tests run here
- ✅ Integration testing
- ✅ Performance & security validation
- ⚠️ Merge to `main` after approval

### 3. `development` - Active Development Branch 🟡
- **Purpose**: Ongoing development and integration
- **Stability**: 🟡 Development (80%)
- **Deployable**: ❌ No
- **Protection**: None (free development)
- **Tests**: Unit & integration tests
- **Updates**: From `feature/*` branches

**Rules**:
- ✅ Active development happens here
- ✅ Feature integration point
- ✅ Breaking changes allowed
- ✅ Experimental features welcome
- ⚠️ Run tests before pushing

### 4. `feature/*` - Feature Branches 🔴
- **Purpose**: Individual feature development
- **Stability**: 🔴 Experimental
- **Deployable**: ❌ No
- **Protection**: None
- **Tests**: Related unit tests
- **Lifetime**: Short-lived (days to weeks)

**Naming Convention**:
- `feature/feature-name` - New features
- `bugfix/bug-description` - Bug fixes
- `hotfix/critical-fix` - Urgent fixes
- `refactor/component-name` - Refactoring
- `docs/documentation-update` - Documentation
- `test/test-description` - Testing improvements

---

## 🔄 Workflow

### Normal Feature Development Flow

```
1. Create feature branch from development
   development → feature/my-feature

2. Develop and test locally
   feature/my-feature (commits)

3. Merge to development
   feature/my-feature → development (PR)

4. Test in development
   development (run tests)

5. Promote to AI testing
   development → genspark_ai_developer (PR)

6. Run production tests
   genspark_ai_developer (79 tests)

7. Deploy to production
   genspark_ai_developer → main (PR)
```

### Hotfix Flow (Urgent Production Fix)

```
1. Create hotfix from main
   main → hotfix/critical-fix

2. Fix and test
   hotfix/critical-fix (commits + tests)

3. Merge to main
   hotfix/critical-fix → main (PR)

4. Backport to other branches
   main → genspark_ai_developer
   main → development
```

---

## 📋 Pull Request Process

### PR from `feature/*` to `development`
- **Requirements**:
  - ✅ Code compiles/runs
  - ✅ Unit tests pass
  - ✅ No merge conflicts
  - ✅ Self-review completed
- **Review**: Optional (team discretion)
- **CI/CD**: Basic tests run

### PR from `development` to `genspark_ai_developer`
- **Requirements**:
  - ✅ All unit tests pass
  - ✅ Integration tests pass
  - ✅ No breaking changes (or documented)
  - ✅ Code review completed
- **Review**: Required
- **CI/CD**: Full test suite runs

### PR from `genspark_ai_developer` to `main`
- **Requirements**:
  - ✅ All 79 production tests pass
  - ✅ Performance benchmarks met
  - ✅ Security tests pass
  - ✅ Code review + approval
  - ✅ Documentation updated
- **Review**: Required + Senior approval
- **CI/CD**: Full production test suite
- **Deployment**: Immediate or scheduled

---

## 🧪 Testing Requirements by Branch

| Branch | Unit | Integration | E2E | Performance | Security | Chaos |
|--------|------|-------------|-----|-------------|----------|-------|
| `feature/*` | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ |
| `development` | ✅ | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| `genspark_ai_developer` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `main` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Legend:
- ✅ Required and must pass
- ⚠️ Recommended
- ❌ Not required

---

## 🛡️ Branch Protection Rules

### `main` Branch
- ✅ Require pull request before merging
- ✅ Require 1 approval
- ✅ Require status checks to pass
- ✅ Require branches to be up to date
- ✅ Include administrators
- ❌ Allow force pushes
- ❌ Allow deletions

### `genspark_ai_developer` Branch
- ✅ Require pull request before merging
- ⚠️ Require 1 approval (recommended)
- ✅ Require status checks to pass
- ⚠️ Require branches to be up to date
- ❌ Allow force pushes
- ❌ Allow deletions

### `development` Branch
- ⚠️ Require pull request (recommended)
- ❌ No approval required (team discretion)
- ⚠️ Status checks recommended
- ❌ Allow force pushes (with caution)
- ❌ Allow deletions

---

## 📝 Commit Guidelines

### Commit Message Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Testing
- `chore`: Maintenance
- `perf`: Performance
- `ci`: CI/CD changes

### Examples
```bash
feat(auth): Add OAuth2 authentication
fix(api): Resolve rate limiting issue
docs(readme): Update installation steps
test(e2e): Add mission lifecycle tests
refactor(db): Optimize query performance
```

---

## 🚀 Deployment Strategy

### Development Environment
- **Branch**: `development`
- **Auto-deploy**: On push (optional)
- **URL**: https://dev.raglox.example.com
- **Purpose**: Development testing

### Staging Environment
- **Branch**: `genspark_ai_developer`
- **Auto-deploy**: On PR merge
- **URL**: https://staging.raglox.example.com
- **Purpose**: Pre-production testing

### Production Environment
- **Branch**: `main`
- **Auto-deploy**: Manual trigger after approval
- **URL**: https://raglox.example.com
- **Purpose**: Live production

---

## 📊 Branch Lifecycle

### Feature Branch Lifecycle
```
1. Create: git checkout -b feature/my-feature
2. Develop: (commits)
3. Test: pytest tests/
4. Push: git push origin feature/my-feature
5. PR: feature/my-feature → development
6. Merge: (after review)
7. Delete: git branch -d feature/my-feature
```

**Lifetime**: 1-2 weeks max

### Release Cycle
```
Weekly:  development → genspark_ai_developer (testing)
Bi-weekly: genspark_ai_developer → main (production)
```

---

## 🔧 Maintenance

### Keeping Branches Updated

```bash
# Update development from main
git checkout development
git pull origin main
git push origin development

# Update feature branch from development
git checkout feature/my-feature
git pull origin development
git push origin feature/my-feature
```

### Cleaning Up Old Branches

```bash
# List merged branches
git branch --merged

# Delete local merged branches
git branch -d feature/old-feature

# Delete remote merged branches
git push origin --delete feature/old-feature

# Prune remote tracking branches
git fetch --prune
```

---

## 📚 Best Practices

### Do's ✅
- ✅ Keep branches up to date
- ✅ Use descriptive branch names
- ✅ Write meaningful commit messages
- ✅ Test before pushing
- ✅ Small, focused commits
- ✅ Regular merges to development
- ✅ Delete branches after merge

### Don'ts ❌
- ❌ Commit directly to main
- ❌ Long-lived feature branches
- ❌ Force push to shared branches
- ❌ Merge without testing
- ❌ Commit secrets/credentials
- ❌ Ignore merge conflicts
- ❌ Skip code reviews

---

## 🆘 Emergency Procedures

### Production Incident
1. **Assess severity**
2. **Create hotfix branch** from `main`
3. **Fix and test** thoroughly
4. **Fast-track PR** to `main`
5. **Deploy immediately**
6. **Backport fixes** to other branches
7. **Post-mortem** analysis

### Rollback
1. **Identify last good commit** on `main`
2. **Create revert commit** or **rollback deployment**
3. **Verify system stability**
4. **Create fix** on separate branch
5. **Test thoroughly**
6. **Re-deploy**

---

## 📞 Contact & Support

For branching strategy questions:
- **Documentation**: This file
- **Technical Lead**: [Contact]
- **DevOps Team**: [Contact]
- **GitHub Issues**: For discussions

---

**Last Updated**: 2026-01-08  
**Version**: 1.0  
**Owner**: Development Team

---

**Keep branches clean, tests green, and deployments smooth! 🚀**
