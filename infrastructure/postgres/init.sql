-- ═══════════════════════════════════════════════════════════════
-- RAGLOX v3.0 - PostgreSQL Schema
-- Blackboard Architecture - Persistent Storage Layer
-- ═══════════════════════════════════════════════════════════════

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ═══════════════════════════════════════════════════════════════
-- Users & Authentication
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'operator',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_role CHECK (role IN ('admin', 'operator', 'viewer', 'auditor'))
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- API Keys for programmatic access
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) NOT NULL,
    name VARCHAR(100),
    permissions JSONB DEFAULT '[]',
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- ═══════════════════════════════════════════════════════════════
-- Missions Archive
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE missions (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) NOT NULL,
    scope JSONB NOT NULL,
    goals JSONB NOT NULL,
    constraints JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Statistics (final)
    targets_discovered INTEGER DEFAULT 0,
    vulns_found INTEGER DEFAULT 0,
    creds_harvested INTEGER DEFAULT 0,
    sessions_established INTEGER DEFAULT 0,
    goals_achieved INTEGER DEFAULT 0,
    
    -- Full state snapshot (for replay/analysis)
    final_state JSONB,
    
    CONSTRAINT valid_status CHECK (status IN (
        'created', 'starting', 'running', 'paused', 
        'completing', 'completed', 'failed', 'cancelled', 'archived'
    ))
);

CREATE INDEX idx_missions_status ON missions(status);
CREATE INDEX idx_missions_created_by ON missions(created_by);
CREATE INDEX idx_missions_created_at ON missions(created_at DESC);

-- ═══════════════════════════════════════════════════════════════
-- Targets Archive
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE targets (
    id UUID PRIMARY KEY,
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    ip INET NOT NULL,
    hostname VARCHAR(255),
    os VARCHAR(255),
    status VARCHAR(50),
    priority VARCHAR(20),
    risk_score DECIMAL(3,1),
    discovered_at TIMESTAMP WITH TIME ZONE,
    discovered_by VARCHAR(100),
    
    -- Detailed info
    ports JSONB DEFAULT '{}',
    services JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_targets_mission ON targets(mission_id);
CREATE INDEX idx_targets_ip ON targets(ip);
CREATE INDEX idx_targets_status ON targets(status);

-- ═══════════════════════════════════════════════════════════════
-- Vulnerabilities Archive
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY,
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    cvss DECIMAL(3,1),
    description TEXT,
    status VARCHAR(50),
    discovered_at TIMESTAMP WITH TIME ZONE,
    discovered_by VARCHAR(100),
    exploit_available BOOLEAN DEFAULT false,
    rx_modules JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT valid_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

CREATE INDEX idx_vulns_mission ON vulnerabilities(mission_id);
CREATE INDEX idx_vulns_target ON vulnerabilities(target_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_type ON vulnerabilities(type);

-- ═══════════════════════════════════════════════════════════════
-- Credentials Archive (encrypted)
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE credentials (
    id UUID PRIMARY KEY,
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    username VARCHAR(255),
    domain VARCHAR(255),
    value_encrypted BYTEA NOT NULL,  -- AES-256 encrypted
    source VARCHAR(100),
    discovered_at TIMESTAMP WITH TIME ZONE,
    discovered_by VARCHAR(100),
    verified BOOLEAN DEFAULT false,
    privilege_level VARCHAR(50),
    metadata JSONB DEFAULT '{}',
    
    CONSTRAINT valid_cred_type CHECK (type IN ('password', 'hash', 'key', 'token', 'certificate'))
);

CREATE INDEX idx_creds_mission ON credentials(mission_id);
CREATE INDEX idx_creds_privilege ON credentials(privilege_level);

-- ═══════════════════════════════════════════════════════════════
-- Sessions Archive
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    username VARCHAR(255),
    privilege VARCHAR(50),
    established_at TIMESTAMP WITH TIME ZONE,
    closed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50),
    via_vuln_id UUID REFERENCES vulnerabilities(id),
    via_cred_id UUID REFERENCES credentials(id),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_sessions_mission ON sessions(mission_id);
CREATE INDEX idx_sessions_target ON sessions(target_id);

-- ═══════════════════════════════════════════════════════════════
-- Attack Paths
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE attack_paths (
    id UUID PRIMARY KEY,
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    from_target_id UUID REFERENCES targets(id),
    to_target_id UUID REFERENCES targets(id),
    method VARCHAR(100),
    via_cred_id UUID REFERENCES credentials(id),
    discovered_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_paths_mission ON attack_paths(mission_id);

-- ═══════════════════════════════════════════════════════════════
-- Reports
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mission_id UUID REFERENCES missions(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,  -- 'interim', 'final', 'executive'
    format VARCHAR(20) NOT NULL,  -- 'pdf', 'html', 'json'
    title VARCHAR(255),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    generated_by UUID REFERENCES users(id),
    file_path VARCHAR(500),  -- S3 path
    file_size BIGINT,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_reports_mission ON reports(mission_id);
CREATE INDEX idx_reports_type ON reports(type);

-- ═══════════════════════════════════════════════════════════════
-- Audit Log
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true
);

CREATE INDEX idx_audit_timestamp ON audit_log(timestamp DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);

-- ═══════════════════════════════════════════════════════════════
-- System Settings
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE settings (
    key VARCHAR(100) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

-- ═══════════════════════════════════════════════════════════════
-- Functions
-- ═══════════════════════════════════════════════════════════════

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Function to archive mission from Redis to PostgreSQL
CREATE OR REPLACE FUNCTION archive_mission(p_mission_id UUID, p_state JSONB)
RETURNS VOID AS $$
BEGIN
    -- Update mission with final state
    UPDATE missions 
    SET final_state = p_state,
        status = 'archived',
        completed_at = NOW()
    WHERE id = p_mission_id;
    
    -- Log the archive action
    INSERT INTO audit_log (action, resource_type, resource_id, details)
    VALUES ('archive', 'mission', p_mission_id, '{"action": "archived_from_redis"}');
END;
$$ LANGUAGE plpgsql;

-- Function to get mission statistics
CREATE OR REPLACE FUNCTION get_mission_stats(p_mission_id UUID)
RETURNS TABLE (
    targets_count INTEGER,
    vulns_count INTEGER,
    creds_count INTEGER,
    sessions_count INTEGER,
    critical_vulns INTEGER,
    high_vulns INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (SELECT COUNT(*)::INTEGER FROM targets WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM vulnerabilities WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM credentials WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM sessions WHERE mission_id = p_mission_id),
        (SELECT COUNT(*)::INTEGER FROM vulnerabilities WHERE mission_id = p_mission_id AND severity = 'critical'),
        (SELECT COUNT(*)::INTEGER FROM vulnerabilities WHERE mission_id = p_mission_id AND severity = 'high');
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- Views
-- ═══════════════════════════════════════════════════════════════

-- Active missions view
CREATE VIEW active_missions AS
SELECT 
    m.*,
    u.email as created_by_email,
    (SELECT COUNT(*) FROM targets t WHERE t.mission_id = m.id) as current_targets,
    (SELECT COUNT(*) FROM vulnerabilities v WHERE v.mission_id = m.id) as current_vulns
FROM missions m
LEFT JOIN users u ON m.created_by = u.id
WHERE m.status IN ('created', 'starting', 'running', 'paused');

-- Mission summary view
CREATE VIEW mission_summary AS
SELECT 
    m.id,
    m.name,
    m.status,
    m.created_at,
    m.started_at,
    m.completed_at,
    m.targets_discovered,
    m.vulns_found,
    m.creds_harvested,
    m.sessions_established,
    m.goals_achieved,
    u.email as created_by_email,
    EXTRACT(EPOCH FROM (COALESCE(m.completed_at, NOW()) - m.started_at))/3600 as duration_hours
FROM missions m
LEFT JOIN users u ON m.created_by = u.id;

-- ═══════════════════════════════════════════════════════════════
-- Grants (for future role-based access)
-- ═══════════════════════════════════════════════════════════════

-- Create roles
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'raglox_readonly') THEN
        CREATE ROLE raglox_readonly;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'raglox_operator') THEN
        CREATE ROLE raglox_operator;
    END IF;
END
$$;

-- Grant permissions
GRANT SELECT ON ALL TABLES IN SCHEMA public TO raglox_readonly;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO raglox_operator;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO raglox_operator;
