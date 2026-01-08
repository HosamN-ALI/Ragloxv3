#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
RAGLOX V3 - Comprehensive Production Database Testing
═══════════════════════════════════════════════════════════════════════════
Tests all database operations to ensure production readiness
"""

import asyncio
import asyncpg
import os
import sys
from datetime import datetime, timezone
from uuid import uuid4
from dotenv import load_dotenv

# Load environment
load_dotenv('.env.test')
load_dotenv()

db_url = os.getenv('DATABASE_URL', 'postgresql://raglox:raglox_dev_password_2026@localhost:5432/raglox')

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_test(name: str, passed: bool, details: str = ""):
    status = f"{Colors.GREEN}✓ PASS{Colors.ENDC}" if passed else f"{Colors.RED}✗ FAIL{Colors.ENDC}"
    print(f"  {status}  {name}")
    if details:
        print(f"         {details}")

class DatabaseTester:
    def __init__(self, conn):
        self.conn = conn
        self.passed = 0
        self.failed = 0
        self.test_org_id = None
        self.test_user_id = None
        self.test_mission_id = None
        self.test_target_id = None
    
    async def test_organizations(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Organizations Table{Colors.ENDC}")
        
        # Test INSERT
        try:
            self.test_org_id = uuid4()
            await self.conn.execute("""
                INSERT INTO organizations (id, name, created_at, updated_at)
                VALUES ($1, $2, NOW(), NOW())
            """, self.test_org_id, f"Test Org {uuid4().hex[:8]}")
            print_test("INSERT organization", True, f"ID: {self.test_org_id}")
            self.passed += 1
        except Exception as e:
            print_test("INSERT organization", False, str(e))
            self.failed += 1
        
        # Test SELECT
        try:
            org = await self.conn.fetchrow("SELECT * FROM organizations WHERE id = $1", self.test_org_id)
            print_test("SELECT organization", org is not None, f"Name: {org['name'] if org else 'N/A'}")
            self.passed += 1
        except Exception as e:
            print_test("SELECT organization", False, str(e))
            self.failed += 1
    
    async def test_users(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Users Table{Colors.ENDC}")
        
        # Test INSERT
        try:
            self.test_user_id = uuid4()
            await self.conn.execute("""
                INSERT INTO users (id, email, password_hash, name, organization_id, 
                                 is_active, is_superuser, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
            """, self.test_user_id, f"test_{uuid4().hex[:8]}@raglox.com", 
                "hashed_password", "Test User", self.test_org_id, True, False)
            print_test("INSERT user", True, f"ID: {self.test_user_id}")
            self.passed += 1
        except Exception as e:
            print_test("INSERT user", False, str(e))
            self.failed += 1
        
        # Test SELECT with JOIN
        try:
            user = await self.conn.fetchrow("""
                SELECT u.*, o.name as org_name 
                FROM users u 
                LEFT JOIN organizations o ON u.organization_id = o.id
                WHERE u.id = $1
            """, self.test_user_id)
            print_test("SELECT user with JOIN", user is not None, 
                      f"User: {user['name'] if user else 'N/A'}, Org: {user['org_name'] if user else 'N/A'}")
            self.passed += 1
        except Exception as e:
            print_test("SELECT user with JOIN", False, str(e))
            self.failed += 1
    
    async def test_missions(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Missions Table{Colors.ENDC}")
        
        # Test INSERT
        try:
            self.test_mission_id = uuid4()
            await self.conn.execute("""
                INSERT INTO missions (id, name, description, status, scope, goals, 
                                    constraints, organization_id, created_by, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            """, self.test_mission_id, f"Test Mission {uuid4().hex[:8]}", 
                "Testing mission", "created", '{"targets": ["10.0.0.0/24"]}',
                '[{"type": "recon", "description": "Test goal"}]',
                '{"no_dos": true}', self.test_org_id, self.test_user_id)
            print_test("INSERT mission", True, f"ID: {self.test_mission_id}")
            self.passed += 1
        except Exception as e:
            print_test("INSERT mission", False, str(e))
            self.failed += 1
        
        # Test UPDATE
        try:
            await self.conn.execute("""
                UPDATE missions 
                SET status = $1, updated_at = NOW()
                WHERE id = $2
            """, "running", self.test_mission_id)
            status = await self.conn.fetchval(
                "SELECT status FROM missions WHERE id = $1", self.test_mission_id)
            print_test("UPDATE mission", status == "running", f"Status: {status}")
            self.passed += 1
        except Exception as e:
            print_test("UPDATE mission", False, str(e))
            self.failed += 1
    
    async def test_targets(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Targets Table{Colors.ENDC}")
        
        # Test INSERT
        try:
            self.test_target_id = uuid4()
            await self.conn.execute("""
                INSERT INTO targets (id, mission_id, ip, hostname, os, status, 
                                   priority, risk_score, discovered_by, discovered_at, 
                                   ports, services, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, NOW(), NOW())
            """, self.test_target_id, self.test_mission_id, "10.0.0.100", 
                "test-target", "Linux", "active", "medium", 75.0, "nmap",
                '{"22": {"state": "open", "service": "ssh"}}',
                '[{"port": 22, "protocol": "tcp", "name": "ssh"}]')
            print_test("INSERT target", True, f"ID: {self.test_target_id}")
            self.passed += 1
        except Exception as e:
            print_test("INSERT target", False, str(e))
            self.failed += 1
        
        # Test JSONB query
        try:
            ports = await self.conn.fetchval("""
                SELECT ports->'22'->'service' as ssh_service 
                FROM targets WHERE id = $1
            """, self.test_target_id)
            print_test("JSONB query on ports", ports is not None, f"Service: {ports}")
            self.passed += 1
        except Exception as e:
            print_test("JSONB query on ports", False, str(e))
            self.failed += 1
    
    async def test_vulnerabilities(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Vulnerabilities Table{Colors.ENDC}")
        
        # Test INSERT
        try:
            vuln_id = uuid4()
            await self.conn.execute("""
                INSERT INTO vulnerabilities 
                (id, mission_id, target_id, type, name, description, severity, 
                 cvss, discovered_by, discovered_at, status, exploit_available, 
                 rx_modules, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12, NOW(), NOW())
            """, vuln_id, self.test_mission_id, self.test_target_id,
                "CVE-2021-12345", "Test Vulnerability", "A test vulnerability",
                "high", 8.5, "nuclei", "confirmed", True,
                '["exploit/multi/handler"]')
            print_test("INSERT vulnerability", True, f"ID: {vuln_id}")
            self.passed += 1
        except Exception as e:
            print_test("INSERT vulnerability", False, str(e))
            self.failed += 1
    
    async def test_credentials(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Credentials Table{Colors.ENDC}")
        
        # Test INSERT
        try:
            cred_id = uuid4()
            await self.conn.execute("""
                INSERT INTO credentials 
                (id, mission_id, target_id, type, username, domain, value_encrypted, 
                 source, discovered_by, discovered_at, verified, privilege_level, 
                 reliability_score, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), $10, $11, $12, NOW(), NOW())
            """, cred_id, self.test_mission_id, self.test_target_id,
                "password", "admin", "WORKGROUP", b"encrypted_pass",
                "bruteforce", "hydra", True, "admin", 0.95)
            print_test("INSERT credential", True, f"ID: {cred_id}")
            self.passed += 1
        except Exception as e:
            print_test("INSERT credential", False, str(e))
            self.failed += 1
    
    async def test_sessions(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Sessions Table{Colors.ENDC}")
        
        # Test INSERT
        try:
            session_id = uuid4()
            await self.conn.execute("""
                INSERT INTO sessions 
                (id, mission_id, target_id, type, "user", privilege, 
                 established_at, last_activity, status, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), $7, NOW(), NOW())
            """, session_id, self.test_mission_id, self.test_target_id,
                "shell", "admin", "admin", "active")
            print_test("INSERT session", True, f"ID: {session_id}")
            self.passed += 1
        except Exception as e:
            print_test("INSERT session", False, str(e))
            self.failed += 1
    
    async def test_foreign_keys(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Foreign Key Constraints{Colors.ENDC}")
        
        # Test FK constraint (should fail)
        try:
            fake_id = uuid4()
            await self.conn.execute("""
                INSERT INTO targets (id, mission_id, ip) 
                VALUES ($1, $2, '10.0.0.1')
            """, uuid4(), fake_id)
            print_test("FK constraint enforcement", False, "Insert succeeded when it should have failed")
            self.failed += 1
        except asyncpg.ForeignKeyViolationError:
            print_test("FK constraint enforcement", True, "Correctly rejected invalid mission_id")
            self.passed += 1
        except Exception as e:
            print_test("FK constraint enforcement", False, f"Unexpected error: {e}")
            self.failed += 1
    
    async def test_indexes(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Index Performance{Colors.ENDC}")
        
        # Test email index
        try:
            result = await self.conn.fetch("""
                EXPLAIN ANALYZE 
                SELECT * FROM users WHERE email = $1
            """, f"test_{uuid4().hex[:8]}@raglox.com")
            
            # Check if index was used
            plan = "\n".join([r['QUERY PLAN'] for r in result])
            using_index = 'Index Scan' in plan or 'Index Only Scan' in plan
            print_test("Email index usage", using_index, 
                      "Index Scan found" if using_index else "Sequential Scan (no index)")
            if using_index:
                self.passed += 1
            else:
                self.failed += 1
        except Exception as e:
            print_test("Email index usage", False, str(e))
            self.failed += 1
    
    async def test_triggers(self):
        print(f"\n{Colors.BOLD}{Colors.BLUE}Testing Triggers{Colors.ENDC}")
        
        # Test updated_at trigger
        try:
            old_updated = await self.conn.fetchval(
                "SELECT updated_at FROM missions WHERE id = $1", self.test_mission_id)
            
            await asyncio.sleep(0.1)  # Ensure time difference
            
            await self.conn.execute("""
                UPDATE missions SET name = $1 WHERE id = $2
            """, "Updated Mission Name", self.test_mission_id)
            
            new_updated = await self.conn.fetchval(
                "SELECT updated_at FROM missions WHERE id = $1", self.test_mission_id)
            
            trigger_worked = new_updated > old_updated
            print_test("updated_at trigger", trigger_worked, 
                      f"Old: {old_updated}, New: {new_updated}")
            if trigger_worked:
                self.passed += 1
            else:
                self.failed += 1
        except Exception as e:
            print_test("updated_at trigger", False, str(e))
            self.failed += 1
    
    async def cleanup(self):
        """Clean up test data"""
        print(f"\n{Colors.BOLD}{Colors.BLUE}Cleaning Up Test Data{Colors.ENDC}")
        
        try:
            # Delete in correct order (respecting FK constraints)
            await self.conn.execute("DELETE FROM sessions WHERE mission_id = $1", self.test_mission_id)
            await self.conn.execute("DELETE FROM credentials WHERE mission_id = $1", self.test_mission_id)
            await self.conn.execute("DELETE FROM vulnerabilities WHERE mission_id = $1", self.test_mission_id)
            await self.conn.execute("DELETE FROM targets WHERE mission_id = $1", self.test_mission_id)
            await self.conn.execute("DELETE FROM missions WHERE id = $1", self.test_mission_id)
            await self.conn.execute("DELETE FROM users WHERE id = $1", self.test_user_id)
            await self.conn.execute("DELETE FROM organizations WHERE id = $1", self.test_org_id)
            
            print_test("Cleanup test data", True, "All test records removed")
        except Exception as e:
            print_test("Cleanup test data", False, str(e))

async def main():
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'═'*70}")
    print(f"    RAGLOX V3 - Production Database Testing Suite")
    print(f"{'═'*70}{Colors.ENDC}\n")
    print(f"Database: {db_url.split('@')[1] if '@' in db_url else db_url}")
    print(f"Started: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    
    try:
        conn = await asyncpg.connect(db_url)
        tester = DatabaseTester(conn)
        
        # Run all tests
        await tester.test_organizations()
        await tester.test_users()
        await tester.test_missions()
        await tester.test_targets()
        await tester.test_vulnerabilities()
        await tester.test_credentials()
        await tester.test_sessions()
        await tester.test_foreign_keys()
        await tester.test_indexes()
        await tester.test_triggers()
        
        # Cleanup
        await tester.cleanup()
        
        # Summary
        total = tester.passed + tester.failed
        pass_rate = (tester.passed / total * 100) if total > 0 else 0
        
        print(f"\n{Colors.BOLD}{'═'*70}")
        print(f"TEST SUMMARY")
        print(f"{'═'*70}{Colors.ENDC}")
        print(f"  Total Tests:  {total}")
        print(f"  {Colors.GREEN}Passed:       {tester.passed}{Colors.ENDC}")
        print(f"  {Colors.RED}Failed:       {tester.failed}{Colors.ENDC}")
        print(f"  Pass Rate:    {pass_rate:.1f}%")
        print(f"{'═'*70}\n")
        
        await conn.close()
        
        # Exit with appropriate code
        sys.exit(0 if tester.failed == 0 else 1)
        
    except Exception as e:
        print(f"\n{Colors.RED}✗ FATAL ERROR: {e}{Colors.ENDC}\n")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
