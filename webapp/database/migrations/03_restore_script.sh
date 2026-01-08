#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# RAGLOX V3 - Database Restore Script
# ═══════════════════════════════════════════════════════════════════════════
#
# This script restores the RAGLOX database from SQL backup files.
#
# Usage:
#   ./03_restore_script.sh [full|schema|data]
#
# Options:
#   full   - Restore complete database (default)
#   schema - Restore schema only
#   data   - Restore data only
#
# Prerequisites:
#   - PostgreSQL 15+ installed
#   - Database 'raglox' created
#   - User 'raglox' with appropriate permissions
#
# ═══════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DB_NAME="${POSTGRES_DB:-raglox}"
DB_USER="${POSTGRES_USER:-raglox}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Restore mode
RESTORE_MODE="${1:-full}"

# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check if psql is installed
    if ! command -v psql &> /dev/null; then
        print_error "psql command not found. Please install PostgreSQL client."
        exit 1
    fi
    print_success "PostgreSQL client found"
    
    # Check if backup files exist
    case $RESTORE_MODE in
        full)
            if [ ! -f "$SCRIPT_DIR/00_full_backup.sql" ]; then
                print_error "Backup file 00_full_backup.sql not found"
                exit 1
            fi
            print_success "Full backup file found"
            ;;
        schema)
            if [ ! -f "$SCRIPT_DIR/01_schema.sql" ]; then
                print_error "Schema file 01_schema.sql not found"
                exit 1
            fi
            print_success "Schema file found"
            ;;
        data)
            if [ ! -f "$SCRIPT_DIR/02_data.sql" ]; then
                print_error "Data file 02_data.sql not found"
                exit 1
            fi
            print_success "Data file found"
            ;;
        *)
            print_error "Invalid restore mode: $RESTORE_MODE"
            print_info "Valid options: full, schema, data"
            exit 1
            ;;
    esac
    
    # Check database connection
    if ! PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" &> /dev/null; then
        print_error "Cannot connect to database. Please check connection settings."
        print_info "Host: $DB_HOST, Port: $DB_PORT, Database: $DB_NAME, User: $DB_USER"
        exit 1
    fi
    print_success "Database connection successful"
}

backup_current_database() {
    print_header "Creating Safety Backup"
    
    BACKUP_FILE="$SCRIPT_DIR/backup_before_restore_$(date +%Y%m%d_%H%M%S).sql"
    
    print_info "Creating backup: $BACKUP_FILE"
    if PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > "$BACKUP_FILE" 2>&1; then
        print_success "Current database backed up successfully"
        print_info "Backup location: $BACKUP_FILE"
    else
        print_warning "Failed to create safety backup (continuing anyway)"
    fi
}

restore_full() {
    print_header "Restoring Full Database"
    
    print_info "Dropping existing schema..."
    PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<-EOF
        DROP SCHEMA public CASCADE;
        CREATE SCHEMA public;
        GRANT ALL ON SCHEMA public TO $DB_USER;
        GRANT ALL ON SCHEMA public TO public;
EOF
    
    print_info "Restoring from: 00_full_backup.sql"
    if PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/00_full_backup.sql" > /dev/null 2>&1; then
        print_success "Full database restored successfully"
    else
        print_error "Failed to restore database"
        exit 1
    fi
}

restore_schema() {
    print_header "Restoring Schema Only"
    
    print_info "Dropping existing schema..."
    PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<-EOF
        DROP SCHEMA public CASCADE;
        CREATE SCHEMA public;
        GRANT ALL ON SCHEMA public TO $DB_USER;
        GRANT ALL ON SCHEMA public TO public;
EOF
    
    print_info "Restoring from: 01_schema.sql"
    if PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/01_schema.sql" > /dev/null 2>&1; then
        print_success "Schema restored successfully"
    else
        print_error "Failed to restore schema"
        exit 1
    fi
}

restore_data() {
    print_header "Restoring Data Only"
    
    print_info "Truncating existing data..."
    PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<-EOF
        TRUNCATE TABLE 
            active_missions,
            api_keys,
            attack_paths,
            audit_log,
            credentials,
            missions,
            reports,
            sessions,
            settings,
            targets,
            users,
            vulnerabilities
        CASCADE;
EOF
    
    print_info "Restoring from: 02_data.sql"
    if PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" < "$SCRIPT_DIR/02_data.sql" > /dev/null 2>&1; then
        print_success "Data restored successfully"
    else
        print_error "Failed to restore data"
        exit 1
    fi
}

verify_restore() {
    print_header "Verifying Restore"
    
    print_info "Checking tables..."
    TABLE_COUNT=$(PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")
    
    if [ "$TABLE_COUNT" -gt 0 ]; then
        print_success "Found $TABLE_COUNT tables"
        
        print_info "Table details:"
        PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
            SELECT 
                schemaname, 
                tablename, 
                pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size 
            FROM pg_tables 
            WHERE schemaname = 'public' 
            ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
        "
    else
        print_error "No tables found after restore"
        exit 1
    fi
}

print_summary() {
    print_header "Restore Summary"
    
    echo -e "${GREEN}✅ Database restore completed successfully${NC}"
    echo ""
    echo "Mode:     $RESTORE_MODE"
    echo "Database: $DB_NAME"
    echo "Host:     $DB_HOST:$DB_PORT"
    echo "User:     $DB_USER"
    echo ""
    
    if [ "$RESTORE_MODE" = "full" ] || [ "$RESTORE_MODE" = "data" ]; then
        print_info "Checking row counts..."
        PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" <<-EOF
            SELECT 
                schemaname,
                tablename,
                n_live_tup AS row_count
            FROM pg_stat_user_tables
            WHERE schemaname = 'public'
            ORDER BY n_live_tup DESC;
EOF
    fi
    
    echo ""
    print_success "Restore process completed!"
}

# ═══════════════════════════════════════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════════════════════════════════════

main() {
    print_header "RAGLOX V3 Database Restore - Mode: $RESTORE_MODE"
    
    # Check prerequisites
    check_prerequisites
    
    # Create safety backup
    backup_current_database
    
    # Perform restore based on mode
    case $RESTORE_MODE in
        full)
            restore_full
            ;;
        schema)
            restore_schema
            ;;
        data)
            restore_data
            ;;
    esac
    
    # Verify restore
    verify_restore
    
    # Print summary
    print_summary
}

# Run main function
main

exit 0
