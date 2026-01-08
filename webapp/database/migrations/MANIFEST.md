# RAGLOX V3 - Database Migration Files Manifest
## قائمة ملفات الترحيل

**Generated**: 2026-01-08  
**Total Files**: 10  
**Total Size**: ~148 KB  
**Database**: raglox (PostgreSQL 15+)

---

## Files Summary

### 📦 SQL Backup Files

| File | Size | Lines | Description |
|------|------|-------|-------------|
| `00_full_backup.sql` | 30 KB | 1,090 | Complete database backup (schema + data) |
| `01_schema.sql` | 26 KB | 983 | Database schema only (tables, indexes, constraints) |
| `02_data.sql` | 3.6 KB | 111 | Data only (INSERT statements) |

### 🔧 Automation Scripts

| File | Size | Purpose | Executable |
|------|------|---------|------------|
| `03_restore_script.sh` | 10 KB | Automated database restore | ✅ Yes |
| `04_verify_database.sh` | 8.0 KB | Database integrity verification | ✅ Yes |
| `05_backup_script.sh` | 12 KB | Automated backup creation | ✅ Yes |

### 📚 Documentation Files

| File | Size | Content |
|------|------|---------|
| `README.md` | 15 KB | Complete migration guide |
| `MANIFEST.md` | This file | Files manifest |
| `.env.migration.example` | 6.6 KB | Environment variables template |

### 📊 Reference Files

| File | Size | Content |
|------|------|---------|
| `table_sizes.txt` | 507 B | Table sizes and statistics |
| `schema_info.txt` | 14 KB | Detailed schema information |

---

## Database Structure

### Tables (11 Total)

| Table | Estimated Size | Purpose |
|-------|----------------|---------|
| `audit_log` | 96 KB | Audit trail and activity logs |
| `users` | 80 KB | User accounts and authentication |
| `vulnerabilities` | 48 KB | Discovered vulnerabilities |
| `missions` | 40 KB | Penetration test missions |
| `targets` | 40 KB | Scanned target systems |
| `settings` | 32 KB | Application settings |
| `sessions` | 32 KB | C2 sessions |
| `reports` | 32 KB | Generated reports |
| `api_keys` | 32 KB | API authentication keys |
| `credentials` | 32 KB | Harvested credentials |
| `attack_paths` | 24 KB | Attack path graphs |

**Total Database Size**: ~488 KB

---

## Quick Start Guide

### 1. Full Database Restore (Recommended)

```bash
# Set password
export POSTGRES_PASSWORD=your_password

# Run automated restore
./03_restore_script.sh full

# Verify
./04_verify_database.sh
```

### 2. Manual Restore

```bash
# Restore full backup
psql -U raglox -d raglox < 00_full_backup.sql

# Or restore separately
psql -U raglox -d raglox < 01_schema.sql
psql -U raglox -d raglox < 02_data.sql
```

### 3. Create Backup

```bash
# Daily backup
./05_backup_script.sh daily

# Weekly backup
./05_backup_script.sh weekly

# Monthly backup
./05_backup_script.sh monthly
```

---

## Checksum Verification

Use these checksums to verify file integrity after transfer:

```bash
# Generate checksums
sha256sum *.sql *.sh > CHECKSUMS.txt

# Verify checksums
sha256sum -c CHECKSUMS.txt
```

---

## File Permissions

**Recommended permissions** after deployment:

```bash
# SQL files (read-only)
chmod 600 00_full_backup.sql
chmod 600 01_schema.sql
chmod 600 02_data.sql

# Scripts (executable)
chmod 700 03_restore_script.sh
chmod 700 04_verify_database.sh
chmod 700 05_backup_script.sh

# Documentation (read-only)
chmod 644 README.md
chmod 644 MANIFEST.md

# Environment template (read-only)
chmod 600 .env.migration.example
```

---

## Transfer Instructions

### Via SCP

```bash
# Transfer entire directory
scp -r database/migrations/ user@new-server:/opt/raglox/

# Transfer specific files only
scp 00_full_backup.sql 03_restore_script.sh user@new-server:/opt/raglox/
```

### Via SFTP

```bash
sftp user@new-server
put -r database/migrations/
bye
```

### Via Git

```bash
# Add to repository (exclude .env files)
git add database/migrations/
git commit -m "Add database migration files"
git push origin development
```

### Via Cloud Storage

```bash
# Upload to S3
aws s3 cp database/migrations/ s3://raglox-backups/migrations/ --recursive

# Upload to Azure Blob
az storage blob upload-batch -d raglox-migrations -s database/migrations/

# Upload to GCS
gsutil -m cp -r database/migrations/ gs://raglox-backups/
```

---

## Security Checklist

Before transferring or storing:

- [ ] Review all SQL files for sensitive data
- [ ] Remove any passwords from comments
- [ ] Encrypt sensitive backups
- [ ] Use secure transfer methods (SCP/SFTP)
- [ ] Verify checksums after transfer
- [ ] Set appropriate file permissions
- [ ] Store credentials securely (not in files)
- [ ] Enable SSL/TLS for database connections
- [ ] Restrict access to migration files
- [ ] Log all restore operations

---

## Usage Scenarios

### Scenario 1: New Server Setup
```bash
# Copy files, restore database, verify
scp -r migrations/ user@new-server:/opt/raglox/
ssh user@new-server "cd /opt/raglox/migrations && ./03_restore_script.sh full"
ssh user@new-server "cd /opt/raglox/migrations && ./04_verify_database.sh"
```

### Scenario 2: Cloud Migration
```bash
# Configure cloud database, restore
export POSTGRES_HOST=raglox.xyz.rds.amazonaws.com
export POSTGRES_PASSWORD=cloud_password
./03_restore_script.sh full
```

### Scenario 3: Automated Backups
```bash
# Setup cron for automated backups
echo "0 2 * * * /opt/raglox/migrations/05_backup_script.sh daily" | crontab -
```

---

## Troubleshooting

### File Not Found Errors
```bash
# Verify all files present
ls -la *.sql *.sh
```

### Permission Denied
```bash
# Fix permissions
chmod +x *.sh
chmod 600 *.sql
```

### Connection Errors
```bash
# Test connection
psql -U raglox -h localhost -d raglox -c "SELECT 1"
```

### Checksum Mismatch
```bash
# Re-export from source
docker exec raglox-postgres pg_dump -U raglox -d raglox > 00_full_backup.sql
```

---

## Support

For issues or questions:
- **Documentation**: See README.md
- **Repository**: https://github.com/HosamN-ALI/Ragloxv3
- **Issues**: https://github.com/HosamN-ALI/Ragloxv3/issues

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-08 | 1.0.0 | Initial migration files created |

---

**Status**: Production Ready ✅  
**Last Updated**: 2026-01-08  
**Generated By**: RAGLOX V3 Development Team
