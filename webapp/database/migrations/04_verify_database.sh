#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# RAGLOX V3 - Database Verification Script
# ═══════════════════════════════════════════════════════════════════════════
#
# This script verifies the integrity and consistency of the restored database.
#
# Usage:
#   ./04_verify_database.sh
#
# ═══════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
DB_NAME="${POSTGRES_DB:-raglox}"
DB_USER="${POSTGRES_USER:-raglox}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"

PASS_COUNT=0
FAIL_COUNT=0

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
print_fail() { echo -e "${RED}[✗]${NC} $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Execute SQL query
exec_sql() {
    PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "$1" 2>/dev/null
}

print_header "RAGLOX V3 Database Verification"

# 1. Connection Test
print_info "Testing database connection..."
if exec_sql "SELECT 1" > /dev/null 2>&1; then
    print_success "Database connection successful"
else
    print_fail "Cannot connect to database"
    exit 1
fi

# 2. Table Count
print_info "Verifying table count..."
TABLE_COUNT=$(exec_sql "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")
EXPECTED_TABLES=11

if [ "$TABLE_COUNT" -eq "$EXPECTED_TABLES" ]; then
    print_success "All $EXPECTED_TABLES tables present"
else
    print_fail "Expected $EXPECTED_TABLES tables, found $TABLE_COUNT"
fi

# 3. Required Tables
print_info "Checking required tables..."
REQUIRED_TABLES=(
    "users"
    "missions"
    "targets"
    "vulnerabilities"
    "credentials"
    "sessions"
    "attack_paths"
    "reports"
    "api_keys"
    "settings"
    "audit_log"
)

for table in "${REQUIRED_TABLES[@]}"; do
    if exec_sql "SELECT to_regclass('public.$table')" | grep -q "$table"; then
        print_success "Table '$table' exists"
    else
        print_fail "Table '$table' missing"
    fi
done

# 4. Required Extensions
print_info "Checking PostgreSQL extensions..."
REQUIRED_EXTENSIONS=("uuid-ossp" "pgcrypto")

for ext in "${REQUIRED_EXTENSIONS[@]}"; do
    if exec_sql "SELECT 1 FROM pg_extension WHERE extname = '$ext'" | grep -q 1; then
        print_success "Extension '$ext' installed"
    else
        print_fail "Extension '$ext' missing"
    fi
done

# 5. Primary Keys
print_info "Verifying primary keys..."
for table in "${REQUIRED_TABLES[@]}"; do
    PK_COUNT=$(exec_sql "SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_name = '$table' AND constraint_type = 'PRIMARY KEY';")
    if [ "$PK_COUNT" -ge 1 ]; then
        print_success "Table '$table' has primary key"
    else
        print_fail "Table '$table' missing primary key"
    fi
done

# 6. Foreign Keys
print_info "Checking foreign key constraints..."
FK_COUNT=$(exec_sql "SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_type = 'FOREIGN KEY' AND table_schema = 'public';")
if [ "$FK_COUNT" -gt 0 ]; then
    print_success "Found $FK_COUNT foreign key constraints"
else
    print_fail "No foreign key constraints found"
fi

# 7. Indexes
print_info "Verifying indexes..."
INDEX_COUNT=$(exec_sql "SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public';")
if [ "$INDEX_COUNT" -gt 0 ]; then
    print_success "Found $INDEX_COUNT indexes"
else
    print_fail "No indexes found"
fi

# 8. UUID Generation Function
print_info "Testing UUID generation..."
if exec_sql "SELECT uuid_generate_v4()" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
    print_success "UUID generation working"
else
    print_fail "UUID generation not working"
fi

# 9. Table Permissions
print_info "Checking table permissions..."
PERM_COUNT=$(exec_sql "SELECT COUNT(*) FROM information_schema.role_table_grants WHERE grantee = '$DB_USER' AND table_schema = 'public';")
if [ "$PERM_COUNT" -gt 0 ]; then
    print_success "User has permissions on $PERM_COUNT tables"
else
    print_fail "User has no table permissions"
fi

# 10. Data Integrity
print_info "Checking data integrity..."

# Check for NULL in required fields
USERS_COUNT=$(exec_sql "SELECT COUNT(*) FROM users WHERE email IS NULL OR password_hash IS NULL;")
if [ "$USERS_COUNT" -eq 0 ]; then
    print_success "Users table integrity OK"
else
    print_fail "Found $USERS_COUNT users with NULL required fields"
fi

# Check for orphaned records
ORPHANED_MISSIONS=$(exec_sql "SELECT COUNT(*) FROM missions WHERE user_id NOT IN (SELECT id FROM users);")
if [ "$ORPHANED_MISSIONS" -eq 0 ]; then
    print_success "No orphaned missions"
else
    print_fail "Found $ORPHANED_MISSIONS orphaned missions"
fi

# 11. Database Size
print_info "Checking database size..."
DB_SIZE=$(exec_sql "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));")
print_success "Database size: $DB_SIZE"

# 12. Sequence Status
print_info "Verifying sequences..."
SEQ_COUNT=$(exec_sql "SELECT COUNT(*) FROM information_schema.sequences WHERE sequence_schema = 'public';")
print_success "Found $SEQ_COUNT sequences"

# 13. View Check
print_info "Checking for views..."
VIEW_COUNT=$(exec_sql "SELECT COUNT(*) FROM information_schema.views WHERE table_schema = 'public';")
if [ "$VIEW_COUNT" -gt 0 ]; then
    print_success "Found $VIEW_COUNT views"
else
    print_info "No views found (this is normal)"
fi

# Summary
print_header "Verification Summary"

echo -e "Database:     ${GREEN}$DB_NAME${NC}"
echo -e "Host:         ${GREEN}$DB_HOST:$DB_PORT${NC}"
echo -e "User:         ${GREEN}$DB_USER${NC}"
echo ""
echo -e "Tests Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Tests Failed: ${RED}$FAIL_COUNT${NC}"
echo ""

# Detailed Statistics
print_info "Database Statistics:"
exec_sql "
SELECT 
    schemaname,
    tablename,
    n_live_tup as rows,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY n_live_tup DESC;
"

echo ""

# Final Result
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✅ DATABASE VERIFICATION PASSED    ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔═══════════════════════════════════════╗${NC}"
    echo -e "${RED}║   ❌ DATABASE VERIFICATION FAILED    ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Please review the failed checks above and take corrective action.${NC}"
    exit 1
fi
