# 🛠️ RAGLOX V3 Operations Guide

## Overview
This guide provides day-to-day operational procedures for managing and maintaining RAGLOX V3 in production environments.

---

## 🚀 Service Management

### Starting Services

#### Using Systemd
```bash
# Start all services
sudo systemctl start raglox-api
sudo systemctl start raglox-worker
sudo systemctl start raglox-scheduler
sudo systemctl start raglox-redis
sudo systemctl start raglox-postgresql

# Enable auto-start on boot
sudo systemctl enable raglox-api
sudo systemctl enable raglox-worker
sudo systemctl enable raglox-scheduler
```

#### Using Docker Compose
```bash
cd /root/RAGLOX_V3/webapp
docker-compose up -d

# Start specific service
docker-compose up -d api
docker-compose up -d worker
```

### Stopping Services
```bash
# Systemd
sudo systemctl stop raglox-api
sudo systemctl stop raglox-worker

# Docker
docker-compose down
docker-compose stop api
```

### Restarting Services (Zero Downtime)
```bash
# Graceful restart with systemd
sudo systemctl reload raglox-api

# Docker rolling restart
docker-compose up -d --no-deps --build api
```

### Checking Service Status
```bash
# Systemd
sudo systemctl status raglox-api
sudo systemctl status raglox-worker

# Docker
docker-compose ps
docker-compose logs -f api

# Health checks
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/status
```

---

## 📊 Monitoring

### Key Metrics to Monitor

#### Application Metrics
```bash
# Request rate
curl http://localhost:8000/metrics | grep http_requests_total

# Response time
curl http://localhost:8000/metrics | grep http_request_duration_seconds

# Error rate
curl http://localhost:8000/metrics | grep http_requests_total{status="5xx"}

# Active connections
curl http://localhost:8000/metrics | grep active_connections
```

#### Database Metrics
```sql
-- Active connections
SELECT count(*) FROM pg_stat_activity;

-- Long-running queries
SELECT pid, now() - query_start as duration, query 
FROM pg_stat_activity 
WHERE state = 'active' AND now() - query_start > interval '1 minute';

-- Database size
SELECT pg_size_pretty(pg_database_size('raglox_production'));

-- Cache hit ratio
SELECT 
  sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) as cache_hit_ratio
FROM pg_statio_user_tables;
```

#### Redis Metrics
```bash
# Redis CLI
redis-cli INFO | grep connected_clients
redis-cli INFO | grep used_memory_human
redis-cli INFO | grep keyspace_hits
redis-cli INFO | grep keyspace_misses

# Calculate hit rate
redis-cli INFO stats | grep -E 'keyspace_hits|keyspace_misses'
```

#### System Metrics
```bash
# CPU usage
top -bn1 | grep "Cpu(s)"

# Memory usage
free -h

# Disk usage
df -h

# Network usage
netstat -i
```

### Alert Thresholds

| Metric | Warning | Critical | Action |
|--------|---------|----------|--------|
| CPU Usage | > 70% | > 90% | Scale up |
| Memory Usage | > 75% | > 90% | Investigate/Scale |
| Disk Usage | > 80% | > 95% | Clean up/Expand |
| Error Rate | > 1% | > 5% | Investigate logs |
| Response Time (P95) | > 2s | > 5s | Optimize/Scale |
| DB Connections | > 80% | > 95% | Increase pool |
| Queue Length | > 1000 | > 5000 | Scale workers |

---

## 📝 Log Management

### Log Locations
```bash
# Application logs
/var/log/raglox/api.log
/var/log/raglox/worker.log
/var/log/raglox/scheduler.log

# System logs
/var/log/syslog
/var/log/nginx/access.log
/var/log/nginx/error.log

# Docker logs
docker-compose logs -f api
docker-compose logs -f worker --tail=100
```

### Log Rotation
```bash
# Configure logrotate
cat > /etc/logrotate.d/raglox << EOF
/var/log/raglox/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 raglox raglox
    sharedscripts
    postrotate
        systemctl reload raglox-api
    endscript
}
EOF
```

### Searching Logs
```bash
# Recent errors
tail -f /var/log/raglox/api.log | grep ERROR

# Specific user actions
grep "user_id=12345" /var/log/raglox/api.log

# Performance issues
grep "slow_query" /var/log/raglox/api.log

# Failed authentication
grep "401" /var/log/raglox/api.log
```

---

## 🗄️ Database Operations

### Backup
```bash
# Full database backup
pg_dump -U raglox_user -h localhost raglox_production > backup_$(date +%Y%m%d_%H%M%S).sql

# Compressed backup
pg_dump -U raglox_user -h localhost raglox_production | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Backup specific tables
pg_dump -U raglox_user -h localhost -t missions -t targets raglox_production > tables_backup.sql

# Automated daily backups (cron)
0 2 * * * /usr/local/bin/backup_raglox.sh
```

### Restore
```bash
# Restore from backup
psql -U raglox_user -h localhost raglox_production < backup.sql

# Restore compressed backup
gunzip -c backup.sql.gz | psql -U raglox_user -h localhost raglox_production

# Restore specific tables
psql -U raglox_user -h localhost raglox_production < tables_backup.sql
```

### Maintenance
```bash
# Vacuum (reclaim space)
psql -U raglox_user -h localhost raglox_production -c "VACUUM ANALYZE;"

# Reindex
psql -U raglox_user -h localhost raglox_production -c "REINDEX DATABASE raglox_production;"

# Check database size
psql -U raglox_user -h localhost raglox_production -c "SELECT pg_size_pretty(pg_database_size('raglox_production'));"

# Check table sizes
psql -U raglox_user -h localhost raglox_production -c "
SELECT 
  relname as table_name,
  pg_size_pretty(pg_total_relation_size(relid)) as total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 10;"
```

### Performance Tuning
```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM missions WHERE status = 'running';

-- Find missing indices
SELECT 
  schemaname, tablename, attname, n_distinct, correlation
FROM pg_stats
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY abs(correlation) DESC;

-- Update statistics
ANALYZE missions;
ANALYZE targets;
ANALYZE vulnerabilities;
```

---

## 🔄 Redis Operations

### Monitoring
```bash
# Connect to Redis
redis-cli -h localhost -p 6379

# Monitor commands in real-time
redis-cli MONITOR

# Get info
redis-cli INFO

# Check memory usage
redis-cli INFO memory

# List all keys (use with caution in production)
redis-cli KEYS "*"

# Count keys by pattern
redis-cli --scan --pattern "session:*" | wc -l
```

### Maintenance
```bash
# Flush specific pattern (use with extreme caution)
redis-cli --scan --pattern "temp:*" | xargs redis-cli DEL

# Save snapshot
redis-cli BGSAVE

# Check last save time
redis-cli LASTSAVE

# Get configuration
redis-cli CONFIG GET maxmemory

# Set configuration
redis-cli CONFIG SET maxmemory 2gb
```

### Cache Warming
```bash
# Warm up common queries
python manage.py warm_cache

# Or manually
redis-cli SET "mission:123" "$(curl http://localhost:8000/api/v1/missions/123)"
```

---

## 🔧 Troubleshooting

### High CPU Usage
```bash
# 1. Identify process
top -c

# 2. Check application metrics
curl http://localhost:8000/metrics

# 3. Look for long-running queries
psql -U raglox_user -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"

# 4. Check worker queue
celery -A webapp inspect active

# 5. Temporary fix: restart service
sudo systemctl restart raglox-api
```

### Memory Leaks
```bash
# 1. Check memory usage over time
ps aux | grep raglox-api | awk '{print $4, $11}'

# 2. Enable memory profiling
export PYTHONMALLOC=malloc
python -m memory_profiler manage.py runserver

# 3. Restart service to free memory
sudo systemctl restart raglox-api
```

### Database Connection Exhaustion
```bash
# 1. Check current connections
psql -U raglox_user -c "SELECT count(*) FROM pg_stat_activity;"

# 2. Kill idle connections
psql -U raglox_user -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle' AND state_change < now() - interval '10 minutes';"

# 3. Increase connection pool
# Edit .env or database configuration
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=10

# 4. Restart application
sudo systemctl restart raglox-api
```

### Slow API Responses
```bash
# 1. Enable query logging
# In .env
LOG_LEVEL=DEBUG
SQL_ECHO=true

# 2. Identify slow endpoints
tail -f /var/log/raglox/api.log | grep "response_time"

# 3. Profile specific endpoint
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8000/api/v1/missions

# curl-format.txt:
time_namelookup:  %{time_namelookup}\n
time_connect:  %{time_connect}\n
time_appconnect:  %{time_appconnect}\n
time_pretransfer:  %{time_pretransfer}\n
time_redirect:  %{time_redirect}\n
time_starttransfer:  %{time_starttransfer}\n
time_total:  %{time_total}\n

# 4. Add caching
redis-cli SET "missions:list" "$(curl http://localhost:8000/api/v1/missions)"
```

### Worker Queue Backlog
```bash
# 1. Check queue length
celery -A webapp inspect active_queues

# 2. Inspect tasks
celery -A webapp inspect reserved

# 3. Purge queue (use with caution)
celery -A webapp purge

# 4. Scale workers
# Add more workers
celery -A webapp worker --loglevel=info --concurrency=8

# Or in systemd
sudo systemctl start raglox-worker@2
sudo systemctl start raglox-worker@3
```

---

## 🔐 Security Operations

### SSL Certificate Renewal
```bash
# Let's Encrypt (Certbot)
sudo certbot renew --dry-run
sudo certbot renew

# Manual renewal
sudo systemctl stop nginx
sudo certbot certonly --standalone -d api.yourdomain.com
sudo systemctl start nginx
```

### Secret Rotation
```bash
# 1. Generate new secret
python -c "import secrets; print(secrets.token_urlsafe(32))"

# 2. Update .env
SECRET_KEY=new_secret_key_here

# 3. Update database (JWT secret rotation)
python manage.py rotate_jwt_secret

# 4. Restart services
sudo systemctl restart raglox-api
```

### Access Control
```bash
# Review active sessions
psql -U raglox_user -c "SELECT * FROM user_sessions WHERE is_active = true;"

# Revoke user access
psql -U raglox_user -c "UPDATE users SET is_active = false WHERE id = 12345;"

# Force logout all users
redis-cli FLUSHDB  # Caution: removes all sessions
```

### Audit Logs
```bash
# Review security events
grep "SECURITY" /var/log/raglox/api.log

# Failed login attempts
grep "401\|403" /var/log/raglox/api.log | wc -l

# Suspicious activity
grep "sql_injection\|xss\|csrf" /var/log/raglox/api.log
```

---

## 📦 Deployment Operations

### Zero-Downtime Deployment
```bash
#!/bin/bash
# deploy.sh

set -e

echo "🚀 Starting deployment..."

# 1. Pull latest code
git pull origin main

# 2. Install dependencies
source venv/bin/activate
pip install -r requirements.txt

# 3. Run migrations
python manage.py migrate --check
python manage.py migrate

# 4. Run tests
pytest tests/smoke/ -v

# 5. Build static assets (if applicable)
python manage.py collectstatic --noinput

# 6. Reload services (zero downtime)
sudo systemctl reload raglox-api

# 7. Health check
sleep 5
curl -f http://localhost:8000/health || exit 1

echo "✅ Deployment successful!"
```

### Rollback
```bash
#!/bin/bash
# rollback.sh

set -e

PREVIOUS_TAG=$1

echo "🔄 Rolling back to $PREVIOUS_TAG..."

# 1. Checkout previous version
git checkout $PREVIOUS_TAG

# 2. Install dependencies
source venv/bin/activate
pip install -r requirements.txt

# 3. Rollback migrations (if needed)
# python manage.py migrate app_name migration_number

# 4. Restart services
sudo systemctl restart raglox-api
sudo systemctl restart raglox-worker

# 5. Health check
sleep 5
curl -f http://localhost:8000/health || exit 1

echo "✅ Rollback successful!"
```

---

## 📈 Performance Optimization

### Database Optimization
```sql
-- Add missing indices
CREATE INDEX CONCURRENTLY idx_missions_status ON missions(status);
CREATE INDEX CONCURRENTLY idx_missions_user_id ON missions(user_id);
CREATE INDEX CONCURRENTLY idx_targets_mission_id ON targets(mission_id);

-- Partition large tables
CREATE TABLE missions_2026 PARTITION OF missions
FOR VALUES FROM ('2026-01-01') TO ('2027-01-01');

-- Optimize queries
EXPLAIN ANALYZE SELECT * FROM missions WHERE status = 'running';
```

### Caching Strategy
```python
# Cache mission data (15 minutes)
@cache_memoize(900)
def get_mission_data(mission_id):
    return Mission.query.get(mission_id)

# Cache expensive computations (1 hour)
@cache_memoize(3600)
def calculate_statistics(mission_id):
    return compute_stats(mission_id)
```

### Load Balancing
```nginx
# nginx.conf
upstream raglox_api {
    least_conn;
    server api1.local:8000 weight=3;
    server api2.local:8000 weight=2;
    server api3.local:8000 weight=1;
}

server {
    listen 80;
    server_name api.yourdomain.com;
    
    location / {
        proxy_pass http://raglox_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 🆘 Incident Response

### Severity Levels

| Level | Description | Response Time | Notification |
|-------|-------------|---------------|--------------|
| P0 | Complete outage | Immediate | All hands |
| P1 | Major feature broken | < 15 min | On-call + Lead |
| P2 | Minor feature broken | < 1 hour | On-call |
| P3 | Non-critical issue | < 4 hours | Team |

### Incident Procedure
1. **Detect**: Alert triggered or reported
2. **Acknowledge**: On-call engineer acknowledges
3. **Assess**: Determine severity and impact
4. **Mitigate**: Quick fix or workaround
5. **Resolve**: Permanent fix deployed
6. **Document**: Incident report and postmortem

### Communication Template
```
🔴 INCIDENT: [Title]
Severity: P1
Start Time: 2026-01-08 14:30 UTC
Status: Investigating

Impact: 
- API response time increased by 300%
- 25% of users affected

Actions:
1. [14:30] Incident detected via monitoring
2. [14:32] On-call engineer notified
3. [14:35] Database query identified as root cause
4. [14:40] Query optimized and deployed
5. [14:45] Metrics returning to normal

Next Update: 15:00 UTC
```

---

## 📚 Useful Commands Reference

### Quick Diagnostics
```bash
# One-liner system health check
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')% | MEM: $(free | grep Mem | awk '{print ($3/$2)*100}')% | DISK: $(df -h / | tail -1 | awk '{print $5}') | API: $(curl -o /dev/null -s -w '%{http_code}' http://localhost:8000/health)"

# Check all services status
for service in raglox-api raglox-worker raglox-scheduler; do
    echo "$service: $(systemctl is-active $service)"
done

# Database connection test
psql -U raglox_user -h localhost -c "SELECT 1;" > /dev/null && echo "✅ DB OK" || echo "❌ DB FAIL"

# Redis connection test
redis-cli PING > /dev/null && echo "✅ Redis OK" || echo "❌ Redis FAIL"
```

---

## 📞 Support Contacts

- **On-Call Engineer**: [Phone] [Email]
- **Database Admin**: [Phone] [Email]
- **Security Team**: [Phone] [Email]
- **Incident Commander**: [Phone] [Email]

---

**Last Updated**: 2026-01-08  
**Version**: 1.0  
**Owner**: Platform Engineering Team
