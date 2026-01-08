# RAGLOX V3 - Database Migration Files
## دليل ترحيل قاعدة البيانات

**Created**: 2026-01-08  
**Database**: PostgreSQL 15+  
**Database Name**: raglox  
**Version**: 3.0.0

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Files Description](#files-description)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Detailed Usage](#detailed-usage)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

---

## Overview

هذا المجلد يحتوي على ملفات SQL اللازمة لترحيل قاعدة بيانات RAGLOX V3 إلى سيرفر جديد. تم تصدير هذه الملفات من قاعدة البيانات الحالية وهي جاهزة للاستيراد.

### Database Statistics

| Metric | Value |
|--------|-------|
| Total Tables | 11 |
| Total Size | ~488 KB |
| Largest Table | audit_log (96 KB) |
| Schema Lines | 983 |
| Data Lines | 111 |

---

## Files Description

### Core Migration Files

#### `00_full_backup.sql` ⭐
**النسخة الاحتياطية الكاملة**
- **Size**: 1,090 lines
- **Contains**: Schema + Data + Indexes + Constraints
- **Use Case**: Full database restoration
- **Recommended**: Yes (safest option)

```bash
# Restore full database
psql -U raglox -d raglox < 00_full_backup.sql
```

#### `01_schema.sql` 🏗️
**مخطط قاعدة البيانات فقط**
- **Size**: 983 lines
- **Contains**: Tables, Indexes, Constraints, Functions
- **Use Case**: Create empty database structure
- **Note**: No data included

```bash
# Restore schema only
psql -U raglox -d raglox < 01_schema.sql
```

#### `02_data.sql` 📊
**البيانات فقط**
- **Size**: 111 lines
- **Contains**: INSERT statements for all tables
- **Use Case**: Restore data into existing schema
- **Note**: Requires schema to exist first

```bash
# Restore data only (schema must exist)
psql -U raglox -d raglox < 02_data.sql
```

### Automation Script

#### `03_restore_script.sh` 🤖
**النص البرمجي للترحيل الآلي**
- **Type**: Bash script
- **Features**:
  - ✅ Prerequisites checking
  - ✅ Automatic safety backup
  - ✅ Three restore modes (full/schema/data)
  - ✅ Verification after restore
  - ✅ Colored output
  - ✅ Error handling

```bash
# Usage
./03_restore_script.sh [full|schema|data]

# Examples
./03_restore_script.sh full     # Full restore (default)
./03_restore_script.sh schema   # Schema only
./03_restore_script.sh data     # Data only
```

### Documentation Files

#### `table_sizes.txt` 📈
**أحجام الجداول**
- Contains table sizes sorted by total size
- Useful for capacity planning

#### `schema_info.txt` 📝
**معلومات المخطط التفصيلية**
- Complete column information for all tables
- Data types, nullability, defaults
- Useful for understanding database structure

#### `README.md` 📚
**هذا الملف**
- Complete migration documentation

---

## Prerequisites

### Software Requirements

- ✅ PostgreSQL 15+ installed
- ✅ PostgreSQL client tools (psql, pg_dump, pg_restore)
- ✅ Bash shell (for automated script)
- ✅ Network access to target server

### Database Requirements

```bash
# Create database
createdb -U postgres raglox

# Create user with password
psql -U postgres <<EOF
CREATE USER raglox WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE raglox TO raglox;
EOF

# Enable required extensions
psql -U postgres -d raglox <<EOF
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
EOF
```

### Environment Variables

```bash
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_USER=raglox
export POSTGRES_PASSWORD=your_secure_password
export POSTGRES_DB=raglox
```

---

## Quick Start

### Option 1: Automated (Recommended) ⭐

```bash
# 1. Set environment variables
export POSTGRES_PASSWORD=your_password

# 2. Run restore script
./03_restore_script.sh full

# 3. Verify
psql -U raglox -d raglox -c "\dt"
```

### Option 2: Manual

```bash
# 1. Create database
createdb -U postgres raglox

# 2. Grant permissions
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE raglox TO raglox;"

# 3. Restore
psql -U raglox -d raglox < 00_full_backup.sql

# 4. Verify
psql -U raglox -d raglox -c "SELECT COUNT(*) FROM users;"
```

### Option 3: Docker Container

```bash
# 1. Copy files to container
docker cp . raglox-postgres:/tmp/migration/

# 2. Execute restore
docker exec -it raglox-postgres bash -c "
  cd /tmp/migration && 
  psql -U raglox -d raglox < 00_full_backup.sql
"

# 3. Verify
docker exec raglox-postgres psql -U raglox -d raglox -c "\dt"
```

---

## Detailed Usage

### Scenario 1: New Server Setup (Fresh Install)

**Goal**: Set up RAGLOX database on a new server

```bash
# Step 1: Install PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib

# Step 2: Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Step 3: Create database and user
sudo -u postgres createdb raglox
sudo -u postgres psql <<EOF
CREATE USER raglox WITH PASSWORD 'SecurePass123!';
GRANT ALL PRIVILEGES ON DATABASE raglox TO raglox;
ALTER DATABASE raglox OWNER TO raglox;
EOF

# Step 4: Enable extensions
sudo -u postgres psql -d raglox <<EOF
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
EOF

# Step 5: Transfer migration files
scp -r database/migrations/ user@new-server:/opt/raglox/

# Step 6: Restore database
cd /opt/raglox/migrations/
export POSTGRES_PASSWORD=SecurePass123!
./03_restore_script.sh full

# Step 7: Verify
psql -U raglox -d raglox -c "
  SELECT 
    schemaname, 
    tablename, 
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size 
  FROM pg_tables 
  WHERE schemaname = 'public';
"
```

### Scenario 2: Migration to Cloud (AWS RDS, Azure, GCP)

**Goal**: Migrate to managed PostgreSQL service

```bash
# Step 1: Get connection details from cloud provider
export POSTGRES_HOST=raglox-db.xxxxxx.us-east-1.rds.amazonaws.com
export POSTGRES_PORT=5432
export POSTGRES_USER=raglox
export POSTGRES_PASSWORD=CloudPassword123!
export POSTGRES_DB=raglox

# Step 2: Test connection
psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER -d postgres -c "SELECT version();"

# Step 3: Create database (if not exists)
psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER -d postgres -c "CREATE DATABASE raglox;"

# Step 4: Enable extensions
psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER -d $POSTGRES_DB <<EOF
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
EOF

# Step 5: Restore using script
./03_restore_script.sh full

# Step 6: Verify and optimize
psql -h $POSTGRES_HOST -p $POSTGRES_PORT -U $POSTGRES_USER -d $POSTGRES_DB <<EOF
ANALYZE;
VACUUM;
REINDEX DATABASE raglox;
EOF
```

### Scenario 3: Schema Update (Preserve Data)

**Goal**: Update schema while keeping existing data

```bash
# Step 1: Backup current data
pg_dump -U raglox -d raglox --data-only --inserts > current_data_backup.sql

# Step 2: Drop and recreate schema
psql -U raglox -d raglox <<EOF
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
GRANT ALL ON SCHEMA public TO raglox;
EOF

# Step 3: Restore new schema
psql -U raglox -d raglox < 01_schema.sql

# Step 4: Restore old data
psql -U raglox -d raglox < current_data_backup.sql

# Step 5: Verify
psql -U raglox -d raglox -c "SELECT COUNT(*) FROM users;"
```

### Scenario 4: Development/Testing Environment

**Goal**: Create test database from production backup

```bash
# Step 1: Create test database
createdb -U postgres raglox_test

# Step 2: Restore with modified database name
export POSTGRES_DB=raglox_test
./03_restore_script.sh full

# Step 3: Anonymize sensitive data
psql -U raglox -d raglox_test <<EOF
-- Anonymize emails
UPDATE users SET email = 'user' || id || '@test.example.com';

-- Clear API keys
UPDATE api_keys SET key_hash = 'test_key_' || id;

-- Clear sensitive credentials
UPDATE credentials SET password = 'test_password_123';
EOF

# Step 4: Verify
psql -U raglox -d raglox_test -c "SELECT email FROM users LIMIT 5;"
```

---

## Troubleshooting

### Issue 1: Connection Refused

**Problem**: Cannot connect to PostgreSQL

```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Check if port is open
sudo netstat -tulpn | grep 5432

# Check pg_hba.conf for access rules
sudo cat /etc/postgresql/15/main/pg_hba.conf

# Allow local connections
echo "host    all    all    0.0.0.0/0    md5" | sudo tee -a /etc/postgresql/15/main/pg_hba.conf
sudo systemctl restart postgresql
```

### Issue 2: Permission Denied

**Problem**: User lacks permissions

```bash
# Grant all privileges
sudo -u postgres psql <<EOF
GRANT ALL PRIVILEGES ON DATABASE raglox TO raglox;
ALTER DATABASE raglox OWNER TO raglox;
GRANT ALL ON SCHEMA public TO raglox;
GRANT ALL ON ALL TABLES IN SCHEMA public TO raglox;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO raglox;
EOF
```

### Issue 3: Extension Not Found

**Problem**: Required extensions missing

```bash
# Install extensions
sudo -u postgres psql -d raglox <<EOF
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
EOF

# Verify
psql -U raglox -d raglox -c "\dx"
```

### Issue 4: Disk Space Full

**Problem**: Insufficient disk space

```bash
# Check disk space
df -h

# Check database size
psql -U raglox -d raglox -c "
  SELECT pg_size_pretty(pg_database_size('raglox'));
"

# Clean up old backups
find /var/lib/postgresql/backups -mtime +30 -delete

# Vacuum database
psql -U raglox -d raglox -c "VACUUM FULL ANALYZE;"
```

### Issue 5: Encoding Mismatch

**Problem**: Character encoding issues

```bash
# Check current encoding
psql -U raglox -d raglox -c "SHOW SERVER_ENCODING;"

# Create database with UTF8
createdb -U postgres -E UTF8 -T template0 raglox

# Restore
psql -U raglox -d raglox < 00_full_backup.sql
```

### Issue 6: Restore Hangs

**Problem**: Restore process stuck

```bash
# Check for locks
psql -U postgres -d raglox -c "
  SELECT 
    pid, 
    usename, 
    application_name, 
    state, 
    query 
  FROM pg_stat_activity 
  WHERE datname = 'raglox';
"

# Kill blocking processes
psql -U postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'raglox' AND pid <> pg_backend_pid();"

# Retry restore
./03_restore_script.sh full
```

---

## Best Practices

### 1. Always Backup First ⚠️

```bash
# Before any migration, create a backup
pg_dump -U raglox -d raglox -F c -f backup_$(date +%Y%m%d_%H%M%S).dump

# Keep multiple backups
cp 00_full_backup.sql 00_full_backup_$(date +%Y%m%d).sql.bak
```

### 2. Verify After Restore ✅

```bash
# Check table count
psql -U raglox -d raglox -c "
  SELECT COUNT(*) as table_count 
  FROM information_schema.tables 
  WHERE table_schema = 'public';
"

# Check row counts
psql -U raglox -d raglox -c "
  SELECT 
    schemaname,
    tablename,
    n_live_tup as row_count
  FROM pg_stat_user_tables
  WHERE schemaname = 'public'
  ORDER BY n_live_tup DESC;
"

# Check for errors
psql -U raglox -d raglox -c "SELECT * FROM pg_stat_database WHERE datname = 'raglox';"
```

### 3. Optimize After Large Restore 🚀

```bash
# Analyze statistics
psql -U raglox -d raglox -c "ANALYZE;"

# Rebuild indexes
psql -U raglox -d raglox -c "REINDEX DATABASE raglox;"

# Vacuum
psql -U raglox -d raglox -c "VACUUM ANALYZE;"

# Update statistics
psql -U raglox -d raglox -c "VACUUM FULL ANALYZE;"
```

### 4. Test in Staging First 🧪

```bash
# Never restore directly to production
# Always test in staging environment first

# 1. Restore to staging
export POSTGRES_DB=raglox_staging
./03_restore_script.sh full

# 2. Run tests
pytest tests/integration/

# 3. Verify application
curl http://staging.raglox.local/health

# 4. If successful, proceed to production
```

### 5. Document Migration 📝

```bash
# Create migration log
cat > migration_log_$(date +%Y%m%d).txt <<EOF
Date: $(date)
Server: $(hostname)
Database: raglox
Migration Files: $(ls -1 *.sql)
Status: Success/Failed
Notes: [Add any notes here]
EOF
```

### 6. Secure Credentials 🔒

```bash
# Never expose passwords in commands
# Use .pgpass file
cat > ~/.pgpass <<EOF
localhost:5432:raglox:raglox:your_password
EOF
chmod 0600 ~/.pgpass

# Or use environment variables
export PGPASSWORD=your_password
```

### 7. Monitor Performance 📊

```bash
# Enable query logging (temporarily)
psql -U raglox -d raglox -c "ALTER DATABASE raglox SET log_statement = 'all';"

# Monitor slow queries
psql -U raglox -d raglox -c "
  SELECT 
    query,
    calls,
    total_time,
    mean_time
  FROM pg_stat_statements
  ORDER BY mean_time DESC
  LIMIT 10;
"

# Disable logging when done
psql -U raglox -d raglox -c "ALTER DATABASE raglox SET log_statement = 'none';"
```

---

## Database Schema Overview

### Tables

| Table | Description | Primary Key | Foreign Keys |
|-------|-------------|-------------|--------------|
| users | User accounts | id (UUID) | - |
| organizations | Organization entities | id (UUID) | - |
| missions | Penetration test missions | id (UUID) | user_id, organization_id |
| targets | Scanned targets | id (UUID) | mission_id |
| vulnerabilities | Discovered vulnerabilities | id (UUID) | mission_id, target_id |
| credentials | Harvested credentials | id (UUID) | mission_id, target_id |
| sessions | Command & control sessions | id (UUID) | mission_id, target_id |
| attack_paths | Attack path graphs | id (UUID) | mission_id |
| reports | Generated reports | id (UUID) | mission_id |
| api_keys | API authentication keys | id (UUID) | user_id |
| settings | Application settings | key (VARCHAR) | - |
| audit_log | Audit trail | id (UUID) | user_id |

### Key Relationships

```
users (1) ←→ (N) missions
missions (1) ←→ (N) targets
targets (1) ←→ (N) vulnerabilities
targets (1) ←→ (N) credentials
targets (1) ←→ (N) sessions
missions (1) ←→ (1) reports
users (1) ←→ (N) api_keys
users (1) ←→ (N) audit_log
```

---

## Support & Contact

For issues or questions:
- **Repository**: https://github.com/HosamN-ALI/Ragloxv3
- **Documentation**: `/docs/`
- **Issues**: https://github.com/HosamN-ALI/Ragloxv3/issues

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial migration files created |

---

**Last Updated**: 2026-01-08  
**Generated By**: RAGLOX V3 Development Team  
**Status**: Production Ready ✅
