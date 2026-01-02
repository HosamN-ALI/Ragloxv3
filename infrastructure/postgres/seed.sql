-- ═══════════════════════════════════════════════════════════════
-- RAGLOX v3.0 - Seed Data
-- Initial data for development/testing
-- ═══════════════════════════════════════════════════════════════

-- ═══════════════════════════════════════════════════════════════
-- Default Admin User
-- Password: admin123 (change in production!)
-- ═══════════════════════════════════════════════════════════════

INSERT INTO users (id, email, password_hash, full_name, role, is_active)
VALUES (
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'admin@raglox.local',
    -- bcrypt hash of 'admin123' - CHANGE IN PRODUCTION!
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X.VNFQjFp0D1YqGWi',
    'RAGLOX Administrator',
    'admin',
    true
);

-- ═══════════════════════════════════════════════════════════════
-- Default Settings
-- ═══════════════════════════════════════════════════════════════

INSERT INTO settings (key, value, description) VALUES
('system.version', '"3.0.0"', 'Current system version'),
('system.maintenance_mode', 'false', 'System maintenance mode flag'),
('mission.default_timeout', '86400', 'Default mission timeout in seconds (24 hours)'),
('mission.max_concurrent', '5', 'Maximum concurrent missions'),
('security.session_timeout', '3600', 'API session timeout in seconds'),
('security.max_login_attempts', '5', 'Maximum login attempts before lockout'),
('redis.key_prefix', '"mission"', 'Redis key prefix for missions'),
('storage.max_report_size', '104857600', 'Maximum report size in bytes (100MB)'),
('notifications.enabled', 'true', 'Enable real-time notifications'),
('audit.retention_days', '365', 'Audit log retention in days');

-- ═══════════════════════════════════════════════════════════════
-- Log initial setup
-- ═══════════════════════════════════════════════════════════════

INSERT INTO audit_log (action, resource_type, details)
VALUES (
    'system_init',
    'system',
    '{"message": "RAGLOX v3.0 database initialized", "version": "3.0.0"}'
);

-- ═══════════════════════════════════════════════════════════════
-- Sample Mission (for testing - optional)
-- ═══════════════════════════════════════════════════════════════

-- Uncomment below for sample data

/*
INSERT INTO missions (id, name, description, status, scope, goals, created_by, created_at)
VALUES (
    'b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
    'Sample Pentest Mission',
    'A sample mission for testing purposes',
    'created',
    '["192.168.1.0/24"]',
    '["domain_admin", "data_exfil"]',
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    NOW()
);
*/
