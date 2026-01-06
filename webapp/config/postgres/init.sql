-- ===================================================================
-- RAGLOX v3.0 - PostgreSQL Initialization (SaaS Multi-Tenancy)
-- ===================================================================
-- 
-- This schema supports multi-tenant SaaS architecture with:
-- - Organization-based data isolation
-- - Role-based access control
-- - Billing/Subscription support
-- - Comprehensive audit logging
--
-- ===================================================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ===================================================================
-- Organizations Table (Multi-Tenancy Core)
-- ===================================================================
-- Every resource in the system belongs to an organization
-- This ensures complete data isolation between tenants
-- ===================================================================
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,  -- URL-friendly identifier
    description TEXT,
    
    -- Subscription & Billing
    plan VARCHAR(50) DEFAULT 'free',  -- free, starter, professional, enterprise
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    billing_email VARCHAR(255),
    
    -- Limits (based on plan)
    max_users INTEGER DEFAULT 3,
    max_missions_per_month INTEGER DEFAULT 5,
    max_concurrent_missions INTEGER DEFAULT 1,
    max_targets_per_mission INTEGER DEFAULT 10,
    
    -- Usage tracking
    missions_this_month INTEGER DEFAULT 0,
    missions_reset_at TIMESTAMP WITH TIME ZONE DEFAULT (date_trunc('month', CURRENT_TIMESTAMP) + INTERVAL '1 month'),
    
    -- Status
    status VARCHAR(50) DEFAULT 'active',  -- active, suspended, cancelled
    is_trial BOOLEAN DEFAULT true,
    trial_ends_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '14 days'),
    
    -- Metadata
    settings JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_plan CHECK (plan IN ('free', 'starter', 'professional', 'enterprise', 'custom')),
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'cancelled', 'pending'))
);

CREATE INDEX idx_organizations_slug ON organizations(slug);
CREATE INDEX idx_organizations_status ON organizations(status);
CREATE INDEX idx_organizations_plan ON organizations(plan);
CREATE INDEX idx_organizations_stripe ON organizations(stripe_customer_id);

-- ===================================================================
-- Users Table (with Organization Membership)
-- ===================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Identity
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    avatar_url VARCHAR(500),
    
    -- Role within organization
    role VARCHAR(50) DEFAULT 'operator',
    permissions JSONB DEFAULT '[]'::jsonb,  -- Fine-grained permissions
    
    -- Status
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,  -- Platform admin (not org admin)
    is_org_owner BOOLEAN DEFAULT false,  -- Organization owner
    
    -- Security
    email_verified BOOLEAN DEFAULT false,
    email_verification_token VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP WITH TIME ZONE,
    two_factor_enabled BOOLEAN DEFAULT false,
    two_factor_secret VARCHAR(255),
    
    -- Login tracking
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(45),
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Metadata
    settings JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT valid_user_role CHECK (role IN ('admin', 'operator', 'viewer', 'api')),
    CONSTRAINT unique_email_per_org UNIQUE (organization_id, email),
    CONSTRAINT unique_username_per_org UNIQUE (organization_id, username)
);

CREATE INDEX idx_users_organization ON users(organization_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);

-- ===================================================================
-- Organization Invitations
-- ===================================================================
CREATE TABLE IF NOT EXISTS organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'operator',
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    token VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '7 days'),
    accepted_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT valid_invitation_status CHECK (status IN ('pending', 'accepted', 'expired', 'cancelled'))
);

CREATE INDEX idx_invitations_org ON organization_invitations(organization_id);
CREATE INDEX idx_invitations_email ON organization_invitations(email);
CREATE INDEX idx_invitations_token ON organization_invitations(token);

-- ===================================================================
-- Missions Table (with Organization Isolation)
-- ===================================================================
CREATE TABLE IF NOT EXISTS missions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Mission details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'created',
    
    -- Configuration
    scope JSONB DEFAULT '[]'::jsonb,
    goals JSONB DEFAULT '[]'::jsonb,
    constraints JSONB DEFAULT '{}'::jsonb,
    
    -- Environment
    environment_type VARCHAR(50) DEFAULT 'simulated',
    environment_config JSONB DEFAULT '{}'::jsonb,
    
    -- Statistics (cached for performance)
    targets_discovered INTEGER DEFAULT 0,
    vulns_found INTEGER DEFAULT 0,
    creds_harvested INTEGER DEFAULT 0,
    sessions_established INTEGER DEFAULT 0,
    goals_achieved INTEGER DEFAULT 0,
    goals_total INTEGER DEFAULT 0,
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_status CHECK (status IN ('created', 'starting', 'running', 'paused', 'completing', 'completed', 'failed', 'cancelled')),
    CONSTRAINT valid_environment CHECK (environment_type IN ('simulated', 'ssh', 'vm', 'hybrid'))
);

CREATE INDEX idx_missions_organization ON missions(organization_id);
CREATE INDEX idx_missions_status ON missions(status);
CREATE INDEX idx_missions_created_by ON missions(created_by);
CREATE INDEX idx_missions_created_at ON missions(created_at DESC);

-- ===================================================================
-- Targets Table
-- ===================================================================
CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    ip_address VARCHAR(45),
    hostname VARCHAR(255),
    os_type VARCHAR(100),
    os_version VARCHAR(100),
    status VARCHAR(50) DEFAULT 'discovered',
    priority INTEGER DEFAULT 5,
    risk_score DECIMAL(3,1),
    
    ports JSONB DEFAULT '[]'::jsonb,
    services JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    discovered_by VARCHAR(100),
    last_scan_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_target_status CHECK (status IN ('discovered', 'scanning', 'scanned', 'exploiting', 'compromised', 'unreachable'))
);

CREATE INDEX idx_targets_mission ON targets(mission_id);
CREATE INDEX idx_targets_organization ON targets(organization_id);
CREATE INDEX idx_targets_ip ON targets(ip_address);
CREATE INDEX idx_targets_status ON targets(status);

-- ===================================================================
-- Vulnerabilities Table
-- ===================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    cve_id VARCHAR(50),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'unknown',
    cvss_score DECIMAL(3,1),
    exploitability VARCHAR(50),
    
    port INTEGER,
    service VARCHAR(100),
    proof TEXT,
    
    exploit_available BOOLEAN DEFAULT false,
    rx_modules JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    discovered_by VARCHAR(100),
    verified_at TIMESTAMP WITH TIME ZONE,
    exploited_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown'))
);

CREATE INDEX idx_vulns_mission ON vulnerabilities(mission_id);
CREATE INDEX idx_vulns_target ON vulnerabilities(target_id);
CREATE INDEX idx_vulns_organization ON vulnerabilities(organization_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve_id);

-- ===================================================================
-- Tasks Table
-- ===================================================================
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    task_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    assigned_to VARCHAR(100),
    
    input_data JSONB DEFAULT '{}'::jsonb,
    output_data JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,
    
    retries INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    timeout_seconds INTEGER DEFAULT 300,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_task_status CHECK (status IN ('pending', 'claimed', 'running', 'completed', 'failed', 'cancelled', 'timeout'))
);

CREATE INDEX idx_tasks_mission ON tasks(mission_id);
CREATE INDEX idx_tasks_organization ON tasks(organization_id);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_type ON tasks(task_type);
CREATE INDEX idx_tasks_priority ON tasks(priority DESC);

-- ===================================================================
-- Credentials Table
-- ===================================================================
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    credential_type VARCHAR(50) NOT NULL,
    username VARCHAR(255),
    password_encrypted BYTEA,  -- Encrypted with pgcrypto
    hash_value VARCHAR(500),
    hash_type VARCHAR(50),
    domain VARCHAR(255),
    
    source VARCHAR(100),
    is_valid BOOLEAN,
    is_privileged BOOLEAN DEFAULT false,
    privilege_level VARCHAR(50),
    
    metadata JSONB DEFAULT '{}'::jsonb,
    
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    discovered_by VARCHAR(100),
    validated_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_cred_type CHECK (credential_type IN ('password', 'hash', 'key', 'token', 'certificate'))
);

CREATE INDEX idx_creds_mission ON credentials(mission_id);
CREATE INDEX idx_creds_target ON credentials(target_id);
CREATE INDEX idx_creds_organization ON credentials(organization_id);
CREATE INDEX idx_creds_username ON credentials(username);

-- ===================================================================
-- Sessions Table (C2/Post-Exploitation)
-- ===================================================================
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    session_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    
    local_address VARCHAR(45),
    local_port INTEGER,
    remote_address VARCHAR(45),
    remote_port INTEGER,
    
    username VARCHAR(255),
    is_elevated BOOLEAN DEFAULT false,
    platform VARCHAR(100),
    
    via_vuln_id UUID REFERENCES vulnerabilities(id),
    via_cred_id UUID REFERENCES credentials(id),
    
    metadata JSONB DEFAULT '{}'::jsonb,
    
    established_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_checkin_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_session_status CHECK (status IN ('active', 'sleeping', 'dead', 'closed'))
);

CREATE INDEX idx_sessions_mission ON sessions(mission_id);
CREATE INDEX idx_sessions_target ON sessions(target_id);
CREATE INDEX idx_sessions_organization ON sessions(organization_id);
CREATE INDEX idx_sessions_status ON sessions(status);

-- ===================================================================
-- Approvals Table (HITL)
-- ===================================================================
CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    approval_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    description TEXT,
    risk_level VARCHAR(20),
    
    requested_by UUID REFERENCES users(id),
    reviewed_by UUID REFERENCES users(id),
    review_notes TEXT,
    
    request_data JSONB DEFAULT '{}'::jsonb,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_approval_status CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'auto_approved'))
);

CREATE INDEX idx_approvals_mission ON approvals(mission_id);
CREATE INDEX idx_approvals_organization ON approvals(organization_id);
CREATE INDEX idx_approvals_status ON approvals(status);
CREATE INDEX idx_approvals_created ON approvals(created_at DESC);

-- ===================================================================
-- API Keys Table
-- ===================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL,
    
    scopes JSONB DEFAULT '[]'::jsonb,
    is_active BOOLEAN DEFAULT true,
    
    rate_limit INTEGER DEFAULT 1000,  -- Requests per hour
    
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_organization ON api_keys(organization_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- ===================================================================
-- Audit Log Table
-- ===================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    mission_id UUID REFERENCES missions(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    event_type VARCHAR(100) NOT NULL,
    event_source VARCHAR(100),
    action VARCHAR(255) NOT NULL,
    
    resource_type VARCHAR(100),
    resource_id UUID,
    
    details JSONB DEFAULT '{}'::jsonb,
    changes JSONB DEFAULT '{}'::jsonb,  -- Before/after for updates
    
    ip_address VARCHAR(45),
    user_agent TEXT,
    
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_organization ON audit_log(organization_id);
CREATE INDEX idx_audit_mission ON audit_log(mission_id);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- Partitioning for audit_log (for high-volume production)
-- CREATE TABLE audit_log_y2024m01 PARTITION OF audit_log
--     FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- ===================================================================
-- Billing Events Table (for Stripe integration)
-- ===================================================================
CREATE TABLE IF NOT EXISTS billing_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    event_type VARCHAR(100) NOT NULL,  -- invoice.paid, subscription.updated, etc.
    stripe_event_id VARCHAR(255) UNIQUE,
    
    amount_cents INTEGER,
    currency VARCHAR(3) DEFAULT 'USD',
    
    details JSONB DEFAULT '{}'::jsonb,
    
    processed BOOLEAN DEFAULT false,
    processed_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_billing_organization ON billing_events(organization_id);
CREATE INDEX idx_billing_stripe_event ON billing_events(stripe_event_id);

-- ===================================================================
-- Triggers
-- ===================================================================

-- Updated_at Trigger Function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers
CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_missions_updated_at BEFORE UPDATE ON missions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ===================================================================
-- Helper Functions
-- ===================================================================

-- Function to check organization limits
CREATE OR REPLACE FUNCTION check_org_mission_limit(org_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    current_count INTEGER;
    max_allowed INTEGER;
BEGIN
    SELECT missions_this_month, max_missions_per_month
    INTO current_count, max_allowed
    FROM organizations
    WHERE id = org_id;
    
    RETURN current_count < max_allowed;
END;
$$ LANGUAGE plpgsql;

-- Function to increment mission count
CREATE OR REPLACE FUNCTION increment_org_mission_count()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE organizations
    SET missions_this_month = missions_this_month + 1
    WHERE id = NEW.organization_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER increment_mission_count
    AFTER INSERT ON missions
    FOR EACH ROW
    EXECUTE FUNCTION increment_org_mission_count();

-- Function to reset monthly counters
CREATE OR REPLACE FUNCTION reset_monthly_counters()
RETURNS void AS $$
BEGIN
    UPDATE organizations
    SET missions_this_month = 0,
        missions_reset_at = date_trunc('month', CURRENT_TIMESTAMP) + INTERVAL '1 month'
    WHERE missions_reset_at <= CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- ===================================================================
-- Views
-- ===================================================================

-- Active organizations with usage
CREATE VIEW organization_usage AS
SELECT 
    o.id,
    o.name,
    o.plan,
    o.status,
    o.missions_this_month,
    o.max_missions_per_month,
    o.max_users,
    (SELECT COUNT(*) FROM users u WHERE u.organization_id = o.id) as current_users,
    (SELECT COUNT(*) FROM missions m WHERE m.organization_id = o.id AND m.status = 'running') as running_missions
FROM organizations o
WHERE o.status = 'active';

-- Mission summary per organization
CREATE VIEW mission_summary AS
SELECT 
    m.id,
    m.organization_id,
    m.name,
    m.status,
    m.created_at,
    m.started_at,
    m.completed_at,
    m.targets_discovered,
    m.vulns_found,
    m.creds_harvested,
    m.sessions_established,
    u.email as created_by_email,
    EXTRACT(EPOCH FROM (COALESCE(m.completed_at, CURRENT_TIMESTAMP) - m.started_at))/3600 as duration_hours
FROM missions m
LEFT JOIN users u ON m.created_by = u.id;

-- ===================================================================
-- Default Data
-- ===================================================================

-- Create default organization (RAGLOX Platform)
INSERT INTO organizations (id, name, slug, plan, max_users, max_missions_per_month, max_concurrent_missions, max_targets_per_mission, is_trial, status)
VALUES (
    'a0000000-0000-0000-0000-000000000001',
    'RAGLOX Platform',
    'raglox',
    'enterprise',
    1000,
    10000,
    100,
    1000,
    false,
    'active'
) ON CONFLICT (slug) DO NOTHING;

-- Create default admin user
INSERT INTO users (id, organization_id, username, email, password_hash, full_name, role, is_superuser, is_org_owner, email_verified)
VALUES (
    'b0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'admin',
    'admin@raglox.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.a0C/aZuOZCrVGm',  -- admin123
    'RAGLOX Administrator',
    'admin',
    true,
    true,
    true
) ON CONFLICT ON CONSTRAINT unique_username_per_org DO NOTHING;

-- ===================================================================
-- Row Level Security (RLS) - Optional for extra isolation
-- ===================================================================
-- Uncomment these for strict multi-tenant isolation:

-- ALTER TABLE missions ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY mission_isolation ON missions
--     USING (organization_id = current_setting('app.current_organization_id')::uuid);

-- ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY target_isolation ON targets
--     USING (organization_id = current_setting('app.current_organization_id')::uuid);

-- ===================================================================
-- Grants
-- ===================================================================
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO raglox;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO raglox;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO raglox;
