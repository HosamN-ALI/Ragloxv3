#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# RAGLOX V3 - Database Backup Script
# ═══════════════════════════════════════════════════════════════════════════
#
# This script creates automated backups of the RAGLOX database.
#
# Usage:
#   ./05_backup_script.sh [daily|weekly|monthly]
#
# Features:
#   - Compressed backups
#   - Automatic rotation
#   - Checksum verification
#   - Email notifications (optional)
#
# Cron Examples:
#   # Daily at 2 AM
#   0 2 * * * /path/to/05_backup_script.sh daily
#   
#   # Weekly on Sunday at 3 AM
#   0 3 * * 0 /path/to/05_backup_script.sh weekly
#   
#   # Monthly on 1st at 4 AM
#   0 4 1 * * /path/to/05_backup_script.sh monthly
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

# Backup configuration
BACKUP_TYPE="${1:-daily}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/raglox}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATE_SHORT=$(date +%Y%m%d)

# Retention policy (days)
DAILY_RETENTION=7
WEEKLY_RETENTION=30
MONTHLY_RETENTION=365

# Email settings (optional)
ENABLE_EMAIL_NOTIFICATION=false
EMAIL_TO=""
EMAIL_SUBJECT="RAGLOX Database Backup - $BACKUP_TYPE"

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Validate backup type
validate_backup_type() {
    case $BACKUP_TYPE in
        daily|weekly|monthly)
            print_info "Backup type: $BACKUP_TYPE"
            ;;
        *)
            print_error "Invalid backup type: $BACKUP_TYPE"
            print_info "Valid types: daily, weekly, monthly"
            exit 1
            ;;
    esac
}

# Create backup directory structure
create_backup_dirs() {
    print_info "Creating backup directory structure..."
    
    mkdir -p "$BACKUP_DIR/$BACKUP_TYPE"
    mkdir -p "$BACKUP_DIR/logs"
    
    if [ -d "$BACKUP_DIR/$BACKUP_TYPE" ]; then
        print_success "Backup directories created"
    else
        print_error "Failed to create backup directories"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check pg_dump
    if ! command -v pg_dump &> /dev/null; then
        print_error "pg_dump not found"
        exit 1
    fi
    
    # Check gzip
    if ! command -v gzip &> /dev/null; then
        print_error "gzip not found"
        exit 1
    fi
    
    # Check database connection
    if ! PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1" &> /dev/null; then
        print_error "Cannot connect to database"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Create backup
create_backup() {
    print_header "Creating $BACKUP_TYPE Backup"
    
    local backup_file="$BACKUP_DIR/$BACKUP_TYPE/raglox_${BACKUP_TYPE}_${TIMESTAMP}.sql"
    local compressed_file="${backup_file}.gz"
    local checksum_file="${compressed_file}.sha256"
    
    print_info "Backing up database: $DB_NAME"
    print_info "Backup file: $backup_file"
    
    # Get database size
    local db_size=$(PGPASSWORD="${POSTGRES_PASSWORD}" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));")
    print_info "Database size: $db_size"
    
    # Create backup
    print_info "Dumping database..."
    if PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > "$backup_file" 2>/dev/null; then
        print_success "Database dump completed"
    else
        print_error "Database dump failed"
        exit 1
    fi
    
    # Compress backup
    print_info "Compressing backup..."
    if gzip "$backup_file"; then
        local compressed_size=$(du -h "$compressed_file" | cut -f1)
        print_success "Backup compressed (size: $compressed_size)"
    else
        print_error "Compression failed"
        exit 1
    fi
    
    # Create checksum
    print_info "Creating checksum..."
    if sha256sum "$compressed_file" > "$checksum_file"; then
        print_success "Checksum created"
    else
        print_warning "Checksum creation failed"
    fi
    
    # Set permissions
    chmod 600 "$compressed_file"
    chmod 600 "$checksum_file"
    
    print_success "Backup created successfully"
    echo "Location: $compressed_file"
}

# Verify backup
verify_backup() {
    print_header "Verifying Backup"
    
    local latest_backup=$(ls -t "$BACKUP_DIR/$BACKUP_TYPE"/raglox_${BACKUP_TYPE}_*.sql.gz 2>/dev/null | head -1)
    
    if [ -z "$latest_backup" ]; then
        print_error "No backup found to verify"
        return 1
    fi
    
    print_info "Verifying: $latest_backup"
    
    # Verify checksum
    local checksum_file="${latest_backup}.sha256"
    if [ -f "$checksum_file" ]; then
        if sha256sum -c "$checksum_file" &>/dev/null; then
            print_success "Checksum verification passed"
        else
            print_error "Checksum verification failed"
            return 1
        fi
    fi
    
    # Test decompression
    print_info "Testing decompression..."
    if gzip -t "$latest_backup" 2>/dev/null; then
        print_success "Decompression test passed"
    else
        print_error "Decompression test failed"
        return 1
    fi
    
    # Test SQL syntax
    print_info "Testing SQL syntax..."
    local temp_test=$(mktemp)
    if gunzip -c "$latest_backup" | head -100 > "$temp_test" 2>/dev/null; then
        if grep -q "PostgreSQL database dump" "$temp_test"; then
            print_success "SQL syntax test passed"
            rm -f "$temp_test"
        else
            print_error "SQL syntax test failed"
            rm -f "$temp_test"
            return 1
        fi
    fi
    
    print_success "Backup verification completed"
}

# Cleanup old backups
cleanup_old_backups() {
    print_header "Cleaning Up Old Backups"
    
    local retention_days
    case $BACKUP_TYPE in
        daily)   retention_days=$DAILY_RETENTION ;;
        weekly)  retention_days=$WEEKLY_RETENTION ;;
        monthly) retention_days=$MONTHLY_RETENTION ;;
    esac
    
    print_info "Retention policy: $retention_days days for $BACKUP_TYPE backups"
    
    # Find and delete old backups
    local old_backups=$(find "$BACKUP_DIR/$BACKUP_TYPE" -name "raglox_${BACKUP_TYPE}_*.sql.gz" -mtime +$retention_days 2>/dev/null)
    
    if [ -n "$old_backups" ]; then
        local count=0
        while IFS= read -r backup; do
            print_info "Deleting old backup: $(basename "$backup")"
            rm -f "$backup"
            rm -f "${backup}.sha256"
            count=$((count + 1))
        done <<< "$old_backups"
        print_success "Deleted $count old backup(s)"
    else
        print_info "No old backups to delete"
    fi
}

# Generate backup report
generate_report() {
    print_header "Backup Report"
    
    print_info "Backup Statistics:"
    
    for type in daily weekly monthly; do
        local dir="$BACKUP_DIR/$type"
        if [ -d "$dir" ]; then
            local count=$(ls -1 "$dir"/raglox_${type}_*.sql.gz 2>/dev/null | wc -l)
            local size=$(du -sh "$dir" 2>/dev/null | cut -f1)
            echo "  $type: $count backups, $size total"
        fi
    done
    
    echo ""
    print_info "Latest Backups:"
    
    for type in daily weekly monthly; do
        local latest=$(ls -t "$BACKUP_DIR/$type"/raglox_${type}_*.sql.gz 2>/dev/null | head -1)
        if [ -n "$latest" ]; then
            local size=$(du -h "$latest" | cut -f1)
            local date=$(stat -c %y "$latest" | cut -d' ' -f1,2 | cut -d'.' -f1)
            echo "  $type: $(basename "$latest") ($size) - $date"
        fi
    done
}

# Send email notification
send_notification() {
    if [ "$ENABLE_EMAIL_NOTIFICATION" = true ] && [ -n "$EMAIL_TO" ]; then
        print_info "Sending email notification..."
        
        local latest_backup=$(ls -t "$BACKUP_DIR/$BACKUP_TYPE"/raglox_${BACKUP_TYPE}_*.sql.gz 2>/dev/null | head -1)
        local backup_size=$(du -h "$latest_backup" 2>/dev/null | cut -f1)
        
        local email_body="
RAGLOX V3 Database Backup Report
================================

Backup Type: $BACKUP_TYPE
Timestamp: $(date)
Database: $DB_NAME
Host: $DB_HOST
Status: Success

Backup Details:
- File: $(basename "$latest_backup")
- Size: $backup_size
- Location: $latest_backup

Verification: Passed
"
        
        if command -v mail &> /dev/null; then
            echo "$email_body" | mail -s "$EMAIL_SUBJECT" "$EMAIL_TO"
            print_success "Email notification sent to $EMAIL_TO"
        else
            print_warning "mail command not found, skipping email notification"
        fi
    fi
}

# Log backup operation
log_backup() {
    local log_file="$BACKUP_DIR/logs/backup_${BACKUP_TYPE}_${DATE_SHORT}.log"
    
    {
        echo "═══════════════════════════════════════════════════════════════"
        echo "Backup Execution Log"
        echo "═══════════════════════════════════════════════════════════════"
        echo "Timestamp: $(date)"
        echo "Type: $BACKUP_TYPE"
        echo "Database: $DB_NAME"
        echo "Host: $DB_HOST:$DB_PORT"
        echo "Status: $1"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
    } >> "$log_file"
}

# Main execution
main() {
    print_header "RAGLOX V3 Database Backup - $BACKUP_TYPE"
    
    # Validate
    validate_backup_type
    
    # Create directories
    create_backup_dirs
    
    # Check prerequisites
    check_prerequisites
    
    # Create backup
    if create_backup; then
        # Verify backup
        verify_backup
        
        # Cleanup old backups
        cleanup_old_backups
        
        # Generate report
        generate_report
        
        # Send notification
        send_notification
        
        # Log success
        log_backup "SUCCESS"
        
        print_header "Backup Completed Successfully"
        exit 0
    else
        log_backup "FAILED"
        print_error "Backup failed"
        exit 1
    fi
}

# Run main function
main
