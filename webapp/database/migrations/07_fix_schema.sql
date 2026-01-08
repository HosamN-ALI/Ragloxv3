-- ═══════════════════════════════════════════════════════════════════════════
-- RAGLOX V3 - Database Schema Fixes
-- ═══════════════════════════════════════════════════════════════════════════
-- This script adds missing tables, columns, and indexes based on validation report
-- Generated: 2026-01-08
-- ═══════════════════════════════════════════════════════════════════════════

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════
-- 1. CREATE MISSING TABLES
-- ═══════════════════════════════════════════════════════════════════════════

-- Create organizations table (if not exists)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name);

COMMENT ON TABLE organizations IS 'Organizations/tenants for multi-tenancy support';

-- ═══════════════════════════════════════════════════════════════════════════
-- 2. ADD MISSING COLUMNS TO USERS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

-- Add organization_id to users
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS organization_id UUID 
REFERENCES organizations(id) ON DELETE CASCADE;

-- Add name column (migrate from full_name if exists)
ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(255);
UPDATE users SET name = full_name WHERE name IS NULL AND full_name IS NOT NULL;

-- Add is_superuser flag
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_superuser BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- 3. ADD MISSING COLUMNS TO MISSIONS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE missions ADD COLUMN IF NOT EXISTS organization_id UUID 
REFERENCES organizations(id) ON DELETE CASCADE;

ALTER TABLE missions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ 
DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE missions ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_missions_organization ON missions(organization_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- 4. ADD MISSING COLUMNS TO TARGETS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE targets ADD COLUMN IF NOT EXISTS os_version VARCHAR(100);
ALTER TABLE targets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- ═══════════════════════════════════════════════════════════════════════════
-- 5. ADD MISSING COLUMNS TO VULNERABILITIES TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS name VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- Populate name from type if empty
UPDATE vulnerabilities SET name = type WHERE name IS NULL;

CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);

-- ═══════════════════════════════════════════════════════════════════════════
-- 6. ADD MISSING COLUMNS TO CREDENTIALS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS reliability_score NUMERIC(3,2) 
DEFAULT 1.0 CHECK (reliability_score >= 0 AND reliability_score <= 1.0);

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS source_metadata JSONB DEFAULT '{}'::jsonb;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target_id);
CREATE INDEX IF NOT EXISTS idx_creds_username ON credentials(username);
CREATE INDEX IF NOT EXISTS idx_creds_verified ON credentials(verified);

-- ═══════════════════════════════════════════════════════════════════════════
-- 7. ADD MISSING COLUMNS TO SESSIONS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

-- Rename username to user if it exists
DO $$ 
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name='sessions' AND column_name='username') THEN
        ALTER TABLE sessions RENAME COLUMN username TO "user";
    END IF;
END $$;

-- Add user column if it doesn't exist
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS "user" VARCHAR(100);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_activity TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- Set last_activity from established_at if null
UPDATE sessions SET last_activity = established_at WHERE last_activity IS NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

-- ═══════════════════════════════════════════════════════════════════════════
-- 8. ADD MISSING COLUMNS TO ATTACK_PATHS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS path JSONB DEFAULT '[]'::jsonb;
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS via_vulns JSONB DEFAULT '[]'::jsonb;
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS via_creds JSONB DEFAULT '[]'::jsonb;
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS tested_at TIMESTAMPTZ;
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE attack_paths ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_attack_paths_status ON attack_paths(status);

-- ═══════════════════════════════════════════════════════════════════════════
-- 9. ADD MISSING COLUMNS TO REPORTS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE reports ADD COLUMN IF NOT EXISTS content TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- ═══════════════════════════════════════════════════════════════════════════
-- 10. ADD MISSING COLUMNS TO API_KEYS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- ═══════════════════════════════════════════════════════════════════════════
-- 11. ADD MISSING COLUMNS TO SETTINGS TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE settings ADD COLUMN IF NOT EXISTS type VARCHAR(50) DEFAULT 'string';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- ═══════════════════════════════════════════════════════════════════════════
-- 12. ADD MISSING COLUMNS TO AUDIT_LOG TABLE
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS organization_id UUID 
REFERENCES organizations(id) ON DELETE CASCADE;

-- Rename timestamp to created_at if it exists
DO $$ 
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name='audit_log' AND column_name='timestamp') THEN
        ALTER TABLE audit_log RENAME COLUMN timestamp TO created_at;
    END IF;
END $$;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

-- Rename details to changes if it exists
DO $$ 
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns 
               WHERE table_name='audit_log' AND column_name='details') THEN
        ALTER TABLE audit_log RENAME COLUMN details TO changes;
    END IF;
END $$;

ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS changes JSONB DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_audit_organization ON audit_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);

-- ═══════════════════════════════════════════════════════════════════════════
-- 13. CREATE DEFAULT ORGANIZATION
-- ═══════════════════════════════════════════════════════════════════════════

-- Insert default organization if not exists
INSERT INTO organizations (id, name, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default Organization',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
)
ON CONFLICT (id) DO NOTHING;

-- Update existing records to use default organization
UPDATE users SET organization_id = '00000000-0000-0000-0000-000000000001'::uuid 
WHERE organization_id IS NULL;

UPDATE missions SET organization_id = '00000000-0000-0000-0000-000000000001'::uuid 
WHERE organization_id IS NULL;

UPDATE audit_log SET organization_id = '00000000-0000-0000-0000-000000000001'::uuid 
WHERE organization_id IS NULL;

-- ═══════════════════════════════════════════════════════════════════════════
-- 14. ADD UPDATE TRIGGERS
-- ═══════════════════════════════════════════════════════════════════════════

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for all tables with updated_at
DO $$
DECLARE
    table_rec RECORD;
BEGIN
    FOR table_rec IN 
        SELECT table_name 
        FROM information_schema.columns 
        WHERE table_schema = 'public' 
        AND column_name = 'updated_at'
        AND table_name NOT IN (SELECT tgname FROM pg_trigger WHERE tgname LIKE 'update_%_updated_at')
    LOOP
        EXECUTE format('
            DROP TRIGGER IF EXISTS update_%I_updated_at ON %I;
            CREATE TRIGGER update_%I_updated_at
            BEFORE UPDATE ON %I
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        ', table_rec.table_name, table_rec.table_name, table_rec.table_name, table_rec.table_name);
    END LOOP;
END $$;

COMMIT;

-- ═══════════════════════════════════════════════════════════════════════════
-- VALIDATION SUMMARY
-- ═══════════════════════════════════════════════════════════════════════════

\echo ''
\echo '═══════════════════════════════════════════════════════════════════════'
\echo 'Schema fixes applied successfully!'
\echo '═══════════════════════════════════════════════════════════════════════'
\echo ''
\echo 'Added:'
\echo '  ✓ organizations table'
\echo '  ✓ 35+ missing columns across all tables'
\echo '  ✓ 10+ performance indexes'
\echo '  ✓ Foreign key relationships'
\echo '  ✓ Update triggers for timestamp management'
\echo '  ✓ Default organization for existing data'
\echo ''
\echo 'Next steps:'
\echo '  1. Run validation script again: python 06_validate_production_db.py'
\echo '  2. Verify all tests pass'
\echo '  3. Run backup: ./05_backup_script.sh'
\echo ''
\echo '═══════════════════════════════════════════════════════════════════════'
