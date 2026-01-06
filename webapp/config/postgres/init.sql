-- ═══════════════════════════════════════════════════════════════════════════════
-- RAGLOX v3.0 - PostgreSQL Initialization
-- ═══════════════════════════════════════════════════════════════════════════════

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ═══════════════════════════════════════════════════════════════════════════════
-- Missions Table
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS missions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'created',
    scope JSONB DEFAULT '[]'::jsonb,
    goals JSONB DEFAULT '[]'::jsonb,
    constraints JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(255),
    CONSTRAINT valid_status CHECK (status IN ('created', 'running', 'paused', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX idx_missions_status ON missions(status);
CREATE INDEX idx_missions_created_at ON missions(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Targets Table
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    hostname VARCHAR(255),
    os_type VARCHAR(100),
    os_version VARCHAR(100),
    status VARCHAR(50) DEFAULT 'discovered',
    ports JSONB DEFAULT '[]'::jsonb,
    services JSONB DEFAULT '[]'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_scan_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_target_status CHECK (status IN ('discovered', 'scanning', 'scanned', 'exploiting', 'compromised'))
);

CREATE INDEX idx_targets_mission ON targets(mission_id);
CREATE INDEX idx_targets_ip ON targets(ip_address);
CREATE INDEX idx_targets_status ON targets(status);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Vulnerabilities Table
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    cve_id VARCHAR(50),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) DEFAULT 'unknown',
    cvss_score DECIMAL(3,1),
    exploitability VARCHAR(50),
    port INTEGER,
    service VARCHAR(100),
    proof TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP WITH TIME ZONE,
    exploited_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown'))
);

CREATE INDEX idx_vulns_mission ON vulnerabilities(mission_id);
CREATE INDEX idx_vulns_target ON vulnerabilities(target_id);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Tasks Table
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    task_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    priority INTEGER DEFAULT 5,
    assigned_to VARCHAR(100),
    input_data JSONB DEFAULT '{}'::jsonb,
    output_data JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,
    retries INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    timeout_seconds INTEGER DEFAULT 300,
    CONSTRAINT valid_task_status CHECK (status IN ('pending', 'claimed', 'running', 'completed', 'failed', 'cancelled', 'timeout'))
);

CREATE INDEX idx_tasks_mission ON tasks(mission_id);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_type ON tasks(task_type);
CREATE INDEX idx_tasks_priority ON tasks(priority DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Credentials Table
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    username VARCHAR(255),
    password_hash VARCHAR(255),
    hash_type VARCHAR(50),
    domain VARCHAR(255),
    source VARCHAR(100),
    is_valid BOOLEAN,
    is_privileged BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}'::jsonb,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    validated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_creds_mission ON credentials(mission_id);
CREATE INDEX idx_creds_target ON credentials(target_id);
CREATE INDEX idx_creds_username ON credentials(username);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Sessions Table (C2/Post-Exploitation)
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
    session_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    local_address VARCHAR(45),
    local_port INTEGER,
    remote_address VARCHAR(45),
    remote_port INTEGER,
    username VARCHAR(255),
    is_elevated BOOLEAN DEFAULT false,
    platform VARCHAR(100),
    metadata JSONB DEFAULT '{}'::jsonb,
    established_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_checkin_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_session_status CHECK (status IN ('active', 'sleeping', 'dead', 'closed'))
);

CREATE INDEX idx_sessions_mission ON sessions(mission_id);
CREATE INDEX idx_sessions_target ON sessions(target_id);
CREATE INDEX idx_sessions_status ON sessions(status);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Approvals Table (HITL)
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
    approval_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    description TEXT,
    risk_level VARCHAR(20),
    requested_by VARCHAR(255),
    reviewed_by VARCHAR(255),
    review_notes TEXT,
    request_data JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_approval_status CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'auto_approved'))
);

CREATE INDEX idx_approvals_mission ON approvals(mission_id);
CREATE INDEX idx_approvals_status ON approvals(status);
CREATE INDEX idx_approvals_created ON approvals(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Audit Log Table
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    event_source VARCHAR(100),
    actor VARCHAR(255),
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB DEFAULT '{}'::jsonb,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_mission ON audit_log(mission_id);
CREATE INDEX idx_audit_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Users Table (for authentication)
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'operator',
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT valid_user_role CHECK (role IN ('admin', 'operator', 'viewer', 'api'))
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- ═══════════════════════════════════════════════════════════════════════════════
-- API Keys Table
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(10) NOT NULL,
    scopes JSONB DEFAULT '[]'::jsonb,
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Updated_at Trigger Function
-- ═══════════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to tables with updated_at
CREATE TRIGGER update_missions_updated_at BEFORE UPDATE ON missions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ═══════════════════════════════════════════════════════════════════════════════
-- Default Admin User (Change password immediately!)
-- Password: admin123 (bcrypt hash)
-- ═══════════════════════════════════════════════════════════════════════════════
INSERT INTO users (username, email, password_hash, full_name, role, is_superuser)
VALUES (
    'admin',
    'admin@raglox.local',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.a0C/aZuOZCrVGm',
    'RAGLOX Administrator',
    'admin',
    true
) ON CONFLICT (username) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════════
-- Grant Permissions
-- ═══════════════════════════════════════════════════════════════════════════════
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO raglox;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO raglox;
