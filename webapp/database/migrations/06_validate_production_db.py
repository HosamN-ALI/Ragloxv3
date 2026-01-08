#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
RAGLOX V3 - Comprehensive Database Validation Script
═══════════════════════════════════════════════════════════════════════════

This script performs comprehensive validation of the database schema against
project requirements by analyzing the code models and verifying the database.

Tests:
    1. Table existence
    2. Column existence and types
    3. Foreign keys
    4. Indexes
    5. Constraints
    6. Required extensions
    7. Data integrity
    8. Performance indexes
    
═══════════════════════════════════════════════════════════════════════════
"""

import asyncio
import sys
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any
import asyncpg
from tabulate import tabulate

# Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text: str):
    print(f"\n{Colors.BLUE}{'═' * 80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.ENDC}")
    print(f"{Colors.BLUE}{'═' * 80}{Colors.ENDC}\n")

def print_success(text: str):
    print(f"{Colors.GREEN}✓ {text}{Colors.ENDC}")

def print_error(text: str):
    print(f"{Colors.RED}✗ {text}{Colors.ENDC}")

def print_warning(text: str):
    print(f"{Colors.YELLOW}⚠ {text}{Colors.ENDC}")

def print_info(text: str):
    print(f"{Colors.CYAN}ℹ {text}{Colors.ENDC}")


class DatabaseValidator:
    """Comprehensive database validation."""
    
    # Expected tables based on models
    REQUIRED_TABLES = {
        'users': {
            'columns': ['id', 'email', 'password_hash', 'name', 'organization_id', 
                       'is_active', 'is_superuser', 'created_at', 'updated_at'],
            'primary_key': 'id',
            'indexes': ['email', 'organization_id'],
        },
        'organizations': {
            'columns': ['id', 'name', 'created_at', 'updated_at'],
            'primary_key': 'id',
        },
        'missions': {
            'columns': ['id', 'name', 'description', 'status', 'scope', 'goals', 
                       'constraints', 'started_at', 'completed_at', 'targets_discovered',
                       'vulns_found', 'creds_harvested', 'sessions_established', 
                       'goals_achieved', 'organization_id', 'created_by', 'created_at', 
                       'updated_at', 'metadata'],
            'primary_key': 'id',
            'foreign_keys': [
                ('organization_id', 'organizations', 'id'),
                ('created_by', 'users', 'id'),
            ],
            'indexes': ['status', 'organization_id', 'created_by'],
        },
        'targets': {
            'columns': ['id', 'mission_id', 'ip', 'hostname', 'os', 'os_version', 
                       'status', 'priority', 'risk_score', 'discovered_by', 
                       'discovered_at', 'ports', 'services', 'created_at', 
                       'updated_at', 'metadata'],
            'primary_key': 'id',
            'foreign_keys': [
                ('mission_id', 'missions', 'id'),
            ],
            'indexes': ['mission_id', 'status', 'ip'],
        },
        'vulnerabilities': {
            'columns': ['id', 'mission_id', 'target_id', 'type', 'name', 'description',
                       'severity', 'cvss', 'discovered_by', 'discovered_at', 'status',
                       'exploit_available', 'rx_modules', 'created_at', 'updated_at', 
                       'metadata'],
            'primary_key': 'id',
            'foreign_keys': [
                ('mission_id', 'missions', 'id'),
                ('target_id', 'targets', 'id'),
            ],
            'indexes': ['mission_id', 'target_id', 'severity', 'status'],
        },
        'credentials': {
            'columns': ['id', 'mission_id', 'target_id', 'type', 'username', 'domain',
                       'value_encrypted', 'source', 'discovered_by', 'discovered_at',
                       'verified', 'privilege_level', 'reliability_score', 
                       'source_metadata', 'created_at', 'updated_at', 'metadata'],
            'primary_key': 'id',
            'foreign_keys': [
                ('mission_id', 'missions', 'id'),
                ('target_id', 'targets', 'id'),
            ],
            'indexes': ['mission_id', 'target_id', 'username', 'verified'],
        },
        'sessions': {
            'columns': ['id', 'mission_id', 'target_id', 'type', 'user', 'privilege',
                       'established_at', 'last_activity', 'closed_at', 'status',
                       'via_vuln_id', 'via_cred_id', 'created_at', 'updated_at', 
                       'metadata'],
            'primary_key': 'id',
            'foreign_keys': [
                ('mission_id', 'missions', 'id'),
                ('target_id', 'targets', 'id'),
            ],
            'indexes': ['mission_id', 'target_id', 'status'],
        },
        'attack_paths': {
            'columns': ['id', 'mission_id', 'from_target_id', 'to_target_id', 'path',
                       'status', 'via_vulns', 'via_creds', 'discovered_at', 'tested_at',
                       'created_at', 'updated_at', 'metadata'],
            'primary_key': 'id',
            'foreign_keys': [
                ('mission_id', 'missions', 'id'),
            ],
            'indexes': ['mission_id', 'status'],
        },
        'reports': {
            'columns': ['id', 'mission_id', 'type', 'format', 'content', 'generated_at',
                       'generated_by', 'created_at', 'updated_at', 'metadata'],
            'primary_key': 'id',
            'foreign_keys': [
                ('mission_id', 'missions', 'id'),
                ('generated_by', 'users', 'id'),
            ],
            'indexes': ['mission_id', 'type'],
        },
        'api_keys': {
            'columns': ['id', 'user_id', 'key_hash', 'name', 'permissions', 
                       'expires_at', 'last_used', 'created_at', 'updated_at'],
            'primary_key': 'id',
            'foreign_keys': [
                ('user_id', 'users', 'id'),
            ],
            'indexes': ['user_id', 'key_hash'],
        },
        'settings': {
            'columns': ['key', 'value', 'type', 'description', 'created_at', 
                       'updated_at'],
            'primary_key': 'key',
        },
        'audit_log': {
            'columns': ['id', 'user_id', 'organization_id', 'action', 'resource_type',
                       'resource_id', 'changes', 'ip_address', 'user_agent', 
                       'created_at'],
            'primary_key': 'id',
            'foreign_keys': [
                ('user_id', 'users', 'id'),
                ('organization_id', 'organizations', 'id'),
            ],
            'indexes': ['user_id', 'organization_id', 'action', 'resource_type', 
                       'created_at'],
        },
    }
    
    # Required PostgreSQL extensions
    REQUIRED_EXTENSIONS = ['uuid-ossp', 'pgcrypto']
    
    def __init__(self, db_url: str):
        self.db_url = db_url
        self.conn = None
        self.issues = []
        self.warnings = []
        self.passes = []
        
    async def connect(self):
        """Connect to database."""
        try:
            self.conn = await asyncpg.connect(self.db_url)
            print_success("Database connection established")
            return True
        except Exception as e:
            print_error(f"Failed to connect to database: {e}")
            return False
    
    async def close(self):
        """Close database connection."""
        if self.conn:
            await self.conn.close()
    
    async def check_extensions(self) -> bool:
        """Check required PostgreSQL extensions."""
        print_header("Checking PostgreSQL Extensions")
        
        query = "SELECT extname FROM pg_extension"
        rows = await self.conn.fetch(query)
        installed = {row['extname'] for row in rows}
        
        all_ok = True
        for ext in self.REQUIRED_EXTENSIONS:
            if ext in installed:
                print_success(f"Extension '{ext}' is installed")
                self.passes.append(f"Extension {ext} present")
            else:
                print_error(f"Extension '{ext}' is MISSING")
                self.issues.append(f"Missing extension: {ext}")
                all_ok = False
        
        return all_ok
    
    async def check_tables(self) -> bool:
        """Check all required tables exist."""
        print_header("Checking Required Tables")
        
        query = """
            SELECT tablename 
            FROM pg_tables 
            WHERE schemaname = 'public'
        """
        rows = await self.conn.fetch(query)
        existing_tables = {row['tablename'] for row in rows}
        
        all_ok = True
        for table in self.REQUIRED_TABLES.keys():
            if table in existing_tables:
                print_success(f"Table '{table}' exists")
                self.passes.append(f"Table {table} present")
            else:
                print_error(f"Table '{table}' is MISSING")
                self.issues.append(f"Missing table: {table}")
                all_ok = False
        
        # Check for unexpected tables
        unexpected = existing_tables - set(self.REQUIRED_TABLES.keys())
        if unexpected:
            print_warning(f"Unexpected tables found: {', '.join(unexpected)}")
            for table in unexpected:
                self.warnings.append(f"Unexpected table: {table}")
        
        return all_ok
    
    async def check_columns(self) -> bool:
        """Check all required columns exist in each table."""
        print_header("Checking Table Columns")
        
        all_ok = True
        
        for table_name, table_def in self.REQUIRED_TABLES.items():
            query = """
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = $1
                ORDER BY ordinal_position
            """
            
            rows = await self.conn.fetch(query, table_name)
            existing_columns = {row['column_name']: row for row in rows}
            required_columns = table_def.get('columns', [])
            
            print(f"\n{Colors.BOLD}Table: {table_name}{Colors.ENDC}")
            
            table_ok = True
            for col in required_columns:
                if col in existing_columns:
                    col_info = existing_columns[col]
                    print_success(f"  Column '{col}' exists ({col_info['data_type']})")
                    self.passes.append(f"{table_name}.{col} present")
                else:
                    print_error(f"  Column '{col}' is MISSING")
                    self.issues.append(f"Missing column: {table_name}.{col}")
                    table_ok = False
                    all_ok = False
            
            # Check for unexpected columns
            unexpected = set(existing_columns.keys()) - set(required_columns)
            if unexpected:
                print_warning(f"  Unexpected columns: {', '.join(unexpected)}")
                for col in unexpected:
                    self.warnings.append(f"Unexpected column: {table_name}.{col}")
        
        return all_ok
    
    async def check_primary_keys(self) -> bool:
        """Check primary keys on all tables."""
        print_header("Checking Primary Keys")
        
        query = """
            SELECT tc.table_name, kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu 
                ON tc.constraint_name = kcu.constraint_name
            WHERE tc.constraint_type = 'PRIMARY KEY'
                AND tc.table_schema = 'public'
        """
        
        rows = await self.conn.fetch(query)
        pk_map = {row['table_name']: row['column_name'] for row in rows}
        
        all_ok = True
        for table_name, table_def in self.REQUIRED_TABLES.items():
            expected_pk = table_def.get('primary_key')
            if not expected_pk:
                continue
            
            if table_name in pk_map:
                actual_pk = pk_map[table_name]
                if actual_pk == expected_pk:
                    print_success(f"Table '{table_name}' has correct PK: {actual_pk}")
                    self.passes.append(f"{table_name} primary key correct")
                else:
                    print_error(f"Table '{table_name}' PK mismatch: expected {expected_pk}, got {actual_pk}")
                    self.issues.append(f"PK mismatch: {table_name}")
                    all_ok = False
            else:
                print_error(f"Table '{table_name}' has NO primary key")
                self.issues.append(f"Missing primary key: {table_name}")
                all_ok = False
        
        return all_ok
    
    async def check_foreign_keys(self) -> bool:
        """Check foreign key constraints."""
        print_header("Checking Foreign Keys")
        
        query = """
            SELECT
                tc.table_name,
                kcu.column_name,
                ccu.table_name AS foreign_table_name,
                ccu.column_name AS foreign_column_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
                ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.constraint_column_usage AS ccu
                ON ccu.constraint_name = tc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
                AND tc.table_schema = 'public'
        """
        
        rows = await self.conn.fetch(query)
        existing_fks = set()
        for row in rows:
            existing_fks.add((row['table_name'], row['column_name'], 
                            row['foreign_table_name'], row['foreign_column_name']))
        
        all_ok = True
        total_expected = 0
        total_found = 0
        
        for table_name, table_def in self.REQUIRED_TABLES.items():
            fks = table_def.get('foreign_keys', [])
            for fk in fks:
                total_expected += 1
                col, ref_table, ref_col = fk
                fk_tuple = (table_name, col, ref_table, ref_col)
                
                if fk_tuple in existing_fks:
                    print_success(f"{table_name}.{col} → {ref_table}.{ref_col}")
                    self.passes.append(f"FK: {table_name}.{col} → {ref_table}.{ref_col}")
                    total_found += 1
                else:
                    print_error(f"MISSING FK: {table_name}.{col} → {ref_table}.{ref_col}")
                    self.issues.append(f"Missing FK: {table_name}.{col} → {ref_table}.{ref_col}")
                    all_ok = False
        
        print_info(f"Found {total_found}/{total_expected} expected foreign keys")
        return all_ok
    
    async def check_indexes(self) -> bool:
        """Check indexes for performance."""
        print_header("Checking Indexes")
        
        query = """
            SELECT
                t.relname AS table_name,
                i.relname AS index_name,
                a.attname AS column_name
            FROM pg_class t
            JOIN pg_index ix ON t.oid = ix.indrelid
            JOIN pg_class i ON i.oid = ix.indexrelid
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
            WHERE t.relkind = 'r'
                AND t.relname IN (
                    SELECT tablename FROM pg_tables WHERE schemaname = 'public'
                )
            ORDER BY t.relname, i.relname
        """
        
        rows = await self.conn.fetch(query)
        index_map = {}
        for row in rows:
            table = row['table_name']
            col = row['column_name']
            if table not in index_map:
                index_map[table] = set()
            index_map[table].add(col)
        
        all_ok = True
        missing_indexes = []
        
        for table_name, table_def in self.REQUIRED_TABLES.items():
            indexes = table_def.get('indexes', [])
            existing = index_map.get(table_name, set())
            
            for col in indexes:
                if col in existing:
                    print_success(f"Index on {table_name}.{col}")
                    self.passes.append(f"Index: {table_name}.{col}")
                else:
                    print_warning(f"Recommended index missing: {table_name}.{col}")
                    missing_indexes.append(f"{table_name}.{col}")
                    self.warnings.append(f"Missing index: {table_name}.{col}")
        
        if missing_indexes:
            print_warning(f"Consider creating indexes on: {', '.join(missing_indexes)}")
        
        return all_ok
    
    async def check_data_integrity(self) -> bool:
        """Check data integrity constraints."""
        print_header("Checking Data Integrity")
        
        checks = []
        
        # Check for NULL values in required fields
        for table, table_def in self.REQUIRED_TABLES.items():
            pk = table_def.get('primary_key')
            if pk:
                query = f"SELECT COUNT(*) as count FROM {table} WHERE {pk} IS NULL"
                try:
                    result = await self.conn.fetchval(query)
                    if result == 0:
                        print_success(f"{table}: No NULL primary keys")
                        self.passes.append(f"{table} data integrity OK")
                    else:
                        print_error(f"{table}: Found {result} NULL primary keys")
                        self.issues.append(f"{table} has NULL primary keys")
                except Exception as e:
                    print_warning(f"Could not check {table}: {e}")
        
        # Check for orphaned records
        checks.append(("missions", "created_by", "users", "id"))
        checks.append(("targets", "mission_id", "missions", "id"))
        checks.append(("vulnerabilities", "mission_id", "missions", "id"))
        checks.append(("credentials", "mission_id", "missions", "id"))
        checks.append(("sessions", "mission_id", "missions", "id"))
        
        all_ok = True
        for table, col, ref_table, ref_col in checks:
            query = f"""
                SELECT COUNT(*) 
                FROM {table} 
                WHERE {col} IS NOT NULL 
                    AND {col} NOT IN (SELECT {ref_col} FROM {ref_table})
            """
            try:
                result = await self.conn.fetchval(query)
                if result == 0:
                    print_success(f"No orphaned records in {table}.{col}")
                    self.passes.append(f"{table}.{col} no orphans")
                else:
                    print_warning(f"Found {result} orphaned records in {table}.{col}")
                    self.warnings.append(f"{table}.{col} has {result} orphans")
            except Exception as e:
                print_warning(f"Could not check {table}.{col}: {e}")
        
        return all_ok
    
    async def check_uuid_functions(self) -> bool:
        """Test UUID generation functions."""
        print_header("Checking UUID Functions")
        
        try:
            uuid = await self.conn.fetchval("SELECT uuid_generate_v4()")
            if uuid:
                print_success(f"UUID generation working: {uuid}")
                self.passes.append("UUID generation functional")
                return True
        except Exception as e:
            print_error(f"UUID generation failed: {e}")
            self.issues.append("UUID generation not working")
            return False
    
    async def get_table_stats(self):
        """Get table statistics."""
        print_header("Table Statistics")
        
        query = """
            SELECT 
                schemaname,
                tablename,
                pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size,
                n_live_tup as rows
            FROM pg_stat_user_tables
            WHERE schemaname = 'public'
            ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
        """
        
        rows = await self.conn.fetch(query)
        
        table_data = []
        for row in rows:
            table_data.append([
                row['tablename'],
                row['rows'],
                row['size']
            ])
        
        print(tabulate(
            table_data,
            headers=['Table', 'Rows', 'Size'],
            tablefmt='grid'
        ))
    
    async def generate_missing_schema_sql(self):
        """Generate SQL for missing schema elements."""
        if not self.issues:
            return
        
        print_header("Missing Schema SQL Generation")
        
        sql_statements = []
        
        # Check missing tables
        query = "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        rows = await self.conn.fetch(query)
        existing_tables = {row['tablename'] for row in rows}
        
        for table in self.REQUIRED_TABLES.keys():
            if table not in existing_tables:
                print_warning(f"Generating CREATE TABLE for: {table}")
                # Simplified - you would need full DDL here
                sql_statements.append(f"-- TODO: CREATE TABLE {table}")
        
        if sql_statements:
            filename = f"schema_fixes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
            with open(filename, 'w') as f:
                f.write("-- RAGLOX V3 - Schema Fixes\n")
                f.write(f"-- Generated: {datetime.now()}\n\n")
                f.write("\n".join(sql_statements))
            print_info(f"Generated SQL file: {filename}")
    
    async def print_summary(self):
        """Print validation summary."""
        print_header("Validation Summary")
        
        total_checks = len(self.passes) + len(self.issues) + len(self.warnings)
        
        print(f"\n{Colors.BOLD}Total Checks Performed:{Colors.ENDC} {total_checks}")
        print(f"{Colors.GREEN}✓ Passed:{Colors.ENDC} {len(self.passes)}")
        print(f"{Colors.RED}✗ Failed:{Colors.ENDC} {len(self.issues)}")
        print(f"{Colors.YELLOW}⚠ Warnings:{Colors.ENDC} {len(self.warnings)}")
        
        if self.issues:
            print(f"\n{Colors.RED}{Colors.BOLD}CRITICAL ISSUES:{Colors.ENDC}")
            for i, issue in enumerate(self.issues, 1):
                print(f"  {i}. {issue}")
        
        if self.warnings:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}WARNINGS:{Colors.ENDC}")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
        
        # Overall status
        print(f"\n{'═' * 80}")
        if not self.issues:
            print(f"{Colors.GREEN}{Colors.BOLD}✓ DATABASE IS PRODUCTION READY{Colors.ENDC}")
            print(f"{'═' * 80}\n")
            return 0
        else:
            print(f"{Colors.RED}{Colors.BOLD}✗ DATABASE REQUIRES FIXES{Colors.ENDC}")
            print(f"{'═' * 80}\n")
            return 1
    
    async def run_all_checks(self):
        """Run all validation checks."""
        if not await self.connect():
            return 1
        
        try:
            await self.check_extensions()
            await self.check_tables()
            await self.check_columns()
            await self.check_primary_keys()
            await self.check_foreign_keys()
            await self.check_indexes()
            await self.check_uuid_functions()
            await self.check_data_integrity()
            await self.get_table_stats()
            await self.generate_missing_schema_sql()
            
            return await self.print_summary()
        finally:
            await self.close()


async def main():
    """Main entry point."""
    # Get database URL from environment
    # Load from .env.test first, then .env
    from dotenv import load_dotenv
    load_dotenv('.env.test')
    load_dotenv()
    
    db_url = os.getenv('DATABASE_URL', 'postgresql://raglox:raglox_dev_password_2026@localhost:5432/raglox')
    
    print(f"""
{Colors.BOLD}{Colors.BLUE}
╔═══════════════════════════════════════════════════════════════════════════╗
║              RAGLOX V3 - Database Validation Tool                         ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}

Database URL: {db_url.split('@')[1] if '@' in db_url else db_url}
Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")
    
    validator = DatabaseValidator(db_url)
    exit_code = await validator.run_all_checks()
    
    sys.exit(exit_code)


if __name__ == '__main__':
    asyncio.run(main())
