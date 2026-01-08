# 🚀 Development Branch Guide

## Overview
This document explains the Git branching strategy for RAGLOX V3 development and how to use the `development` branch effectively.

---

## 📊 Branching Strategy

### Branch Hierarchy

```
main (production)
├── genspark_ai_developer (AI development & testing)
├── development (active development) ← YOU ARE HERE
└── feature/* (feature branches)
```

### Branch Purposes

| Branch | Purpose | Stability | Deployable |
|--------|---------|-----------|------------|
| `main` | Production code | 🟢 Stable | ✅ Yes |
| `genspark_ai_developer` | AI-driven development & testing | 🟡 Testing | ⚠️ Review Required |
| `development` | Active development & integration | 🟡 Development | ❌ No |
| `feature/*` | Individual features | 🔴 Experimental | ❌ No |

---

## 🎯 Development Branch Usage

### Purpose
The `development` branch is designed for:
- **Component Development**: Building new features and components
- **Integration Testing**: Testing integration between components
- **Experimental Features**: Trying new ideas without affecting production
- **Continuous Development**: Ongoing improvements and enhancements
- **Team Collaboration**: Multiple developers working together

### Characteristics
- ✅ Safe for experimentation
- ✅ Isolated from production
- ✅ Allows breaking changes
- ✅ Regular integration point
- ✅ Pre-production testing ground

---

## 🔄 Workflow

### 1. Starting New Feature Development

```bash
# Ensure you're on development branch
cd /root/RAGLOX_V3/webapp
git checkout development
git pull origin development

# Create a feature branch
git checkout -b feature/your-feature-name

# Work on your feature
# ... make changes ...

# Commit your changes
git add .
git commit -m "feat: Add your feature description"
```

### 2. Integrating Features to Development

```bash
# Update development branch
git checkout development
git pull origin development

# Merge your feature
git merge feature/your-feature-name

# Run tests
source webapp/venv/bin/activate
pytest tests/ -v

# If tests pass, push to remote
git push origin development
```

### 3. Testing in Development

```bash
# Switch to development branch
git checkout development
git pull origin development

# Install dependencies
source webapp/venv/bin/activate
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Run all tests
pytest tests/ -v

# Run development server
python manage.py runserver
```

### 4. Promoting to Production

```bash
# Only after thorough testing in development

# Create PR from development to main
# Via GitHub UI: 
# https://github.com/HosamN-ALI/Ragloxv3/compare/main...development

# After review and approval, merge to main
# Then deploy to production
```

---

## 📋 Best Practices

### Do's ✅
- ✅ Always pull latest changes before starting work
- ✅ Create feature branches for significant changes
- ✅ Write descriptive commit messages
- ✅ Run tests before pushing
- ✅ Keep commits focused and atomic
- ✅ Document new features
- ✅ Update tests for new functionality
- ✅ Rebase feature branches regularly

### Don'ts ❌
- ❌ Don't commit directly to `main`
- ❌ Don't push broken code to `development`
- ❌ Don't merge untested features
- ❌ Don't commit secrets or credentials
- ❌ Don't force push to shared branches
- ❌ Don't ignore test failures
- ❌ Don't leave commented-out code
- ❌ Don't commit large binary files

---

## 🛠️ Common Commands

### Branch Management
```bash
# List all branches
git branch -a

# Switch to development
git checkout development

# Create new feature branch
git checkout -b feature/my-feature

# Delete local branch
git branch -d feature/my-feature

# Delete remote branch
git push origin --delete feature/my-feature
```

### Keeping Development Updated
```bash
# Update from main
git checkout development
git pull origin main
git push origin development

# Update from genspark_ai_developer (if needed)
git checkout development
git pull origin genspark_ai_developer
git push origin development
```

### Resolving Conflicts
```bash
# When conflicts occur during merge
git status  # See conflicted files

# Edit files to resolve conflicts
# Look for <<<<<<< HEAD markers

# After resolving
git add <resolved-files>
git commit -m "merge: Resolve conflicts from <branch>"
```

---

## 🧪 Testing Requirements

### Before Pushing to Development
1. **Unit Tests**: All unit tests must pass
   ```bash
   pytest tests/unit/ -v
   ```

2. **Integration Tests**: Integration tests should pass
   ```bash
   pytest tests/integration/ -v
   ```

3. **Linting**: Code should be properly formatted
   ```bash
   flake8 webapp/
   black webapp/ --check
   ```

4. **Type Checking**: Type hints should be valid (if using)
   ```bash
   mypy webapp/
   ```

### Before Creating PR to Main
All production tests must pass:
```bash
# Run full production test suite
pytest tests/production/ -v

# All 79 tests should pass
# Integration (40) + E2E (13) + Performance (5) + Security (11) + Chaos (10)
```

---

## 📦 Feature Branch Naming Convention

Use descriptive, kebab-case names with prefixes:

### Prefixes
- `feature/` - New features
- `bugfix/` - Bug fixes
- `hotfix/` - Urgent production fixes
- `refactor/` - Code refactoring
- `docs/` - Documentation updates
- `test/` - Test additions/improvements
- `chore/` - Maintenance tasks

### Examples
```bash
feature/user-authentication
feature/mission-dashboard
bugfix/api-rate-limiting
hotfix/security-vulnerability
refactor/database-queries
docs/api-documentation
test/e2e-mission-lifecycle
chore/dependency-updates
```

---

## 📝 Commit Message Convention

Follow conventional commits format:

### Format
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks
- `perf`: Performance improvements
- `ci`: CI/CD changes

### Examples
```bash
git commit -m "feat(auth): Add OAuth2 authentication"
git commit -m "fix(api): Resolve rate limiting bug"
git commit -m "docs(readme): Update installation instructions"
git commit -m "test(e2e): Add mission lifecycle tests"
git commit -m "refactor(db): Optimize query performance"
```

---

## 🔐 Security Considerations

### Sensitive Data
- **Never commit** secrets, API keys, or passwords
- Use `.env` files (already in `.gitignore`)
- Use environment variables for configuration
- Review commits before pushing

### Code Review
- All PRs to `main` require review
- Security-related changes require security review
- Run security tests before merging

---

## 🚀 Deployment Pipeline

```
development → genspark_ai_developer → main → production
     ↓                    ↓              ↓          ↓
  Active Dev          Testing         Staging    Production
```

### Stage Descriptions
1. **development**: Active development and experimentation
2. **genspark_ai_developer**: AI-driven testing and validation
3. **main**: Production-ready code
4. **production**: Deployed to production environment

---

## 📊 Monitoring Development

### GitHub Actions
- CI/CD runs on all branches
- Tests run automatically on push
- Check Actions tab for results

### Test Coverage
- Maintain test coverage > 80%
- Add tests for new features
- Update tests for bug fixes

### Code Quality
- Use pre-commit hooks (if configured)
- Run linters before committing
- Follow project code style

---

## 🆘 Troubleshooting

### Common Issues

#### 1. Merge Conflicts
```bash
# Update your branch first
git checkout development
git pull origin development

# Then merge/rebase your feature branch
git checkout feature/my-feature
git rebase development

# Resolve conflicts and continue
git add <resolved-files>
git rebase --continue
```

#### 2. Accidentally Committed to Wrong Branch
```bash
# Undo last commit (keep changes)
git reset --soft HEAD~1

# Switch to correct branch
git checkout correct-branch

# Commit again
git add .
git commit -m "Your commit message"
```

#### 3. Need to Discard Local Changes
```bash
# Discard all local changes
git reset --hard HEAD

# Discard specific file
git checkout -- path/to/file
```

#### 4. Branch Out of Sync
```bash
# Update local branch with remote
git fetch origin
git reset --hard origin/development
```

---

## 📚 Additional Resources

### Documentation
- [Production Testing Guide](./docs/PRODUCTION_TESTING_GUIDE.md)
- [Deployment Checklist](./docs/DEPLOYMENT_CHECKLIST.md)
- [Operations Guide](./docs/OPERATIONS_GUIDE.md)
- [CI/CD Setup](./docs/CI_CD_SETUP.md)

### Git Resources
- [Git Documentation](https://git-scm.com/doc)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [GitHub Flow](https://guides.github.com/introduction/flow/)

---

## 👥 Team Collaboration

### Communication
- Discuss major changes before implementing
- Document architectural decisions
- Update team on breaking changes
- Review PRs promptly

### Code Reviews
- Be constructive and respectful
- Check for:
  - Code quality
  - Test coverage
  - Documentation
  - Security issues
  - Performance implications

---

## 📞 Support

For questions or issues:
- **Technical**: Check documentation first
- **Git Issues**: See troubleshooting section
- **Feature Discussions**: Create GitHub issue
- **Security Issues**: Report privately

---

## 🎯 Quick Reference

### Most Used Commands
```bash
# Start working
git checkout development
git pull origin development
git checkout -b feature/my-feature

# Make changes and commit
git add .
git commit -m "feat: My feature description"

# Push feature branch
git push -u origin feature/my-feature

# Merge to development
git checkout development
git merge feature/my-feature
pytest tests/ -v  # Run tests
git push origin development

# Create PR to main via GitHub UI
```

---

## 📝 Changelog

| Date | Change | Author |
|------|--------|--------|
| 2026-01-08 | Created development branch | GenSpark AI |
| 2026-01-08 | Added development guide | GenSpark AI |

---

**Branch**: `development`  
**Created**: 2026-01-08  
**Purpose**: Active development and integration  
**Status**: 🟢 Active

---

**Happy Coding! 🚀**
