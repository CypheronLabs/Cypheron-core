-- Cypheron API PostgreSQL Database Schema
-- Migration from Google Cloud Firestore to PostgreSQL
-- 
-- This schema follows the migration plan outlined in instructions.json
-- and maintains compatibility with the existing Firestore data structure

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table for future multi-tenancy support
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Indexes
    CONSTRAINT users_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

-- API Keys table - main entity from Firestore migration
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA-256 hash of the API key
    encrypted_key TEXT NOT NULL, -- Base64-encoded encrypted key data
    
    -- Permission and access control
    permissions TEXT[] DEFAULT '{}', -- Array of permission strings
    rate_limit INTEGER DEFAULT 60, -- Requests per minute
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NULL, -- Optional expiration
    last_used TIMESTAMP WITH TIME ZONE NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Status and usage tracking
    is_active BOOLEAN DEFAULT TRUE,
    usage_count BIGINT DEFAULT 0,
    
    -- Future multi-tenancy support
    user_id UUID NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Constraints
    CONSTRAINT api_keys_rate_limit_positive CHECK (rate_limit > 0),
    CONSTRAINT api_keys_usage_count_non_negative CHECK (usage_count >= 0),
    CONSTRAINT api_keys_name_length CHECK (length(name) >= 1 AND length(name) <= 255),
    CONSTRAINT api_keys_key_hash_format CHECK (key_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT api_keys_expiration_future CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Audit logs table for comprehensive audit trail
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    
    -- API key context
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    api_key_hash VARCHAR(64), -- Denormalized for performance
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    request_path VARCHAR(500),
    request_method VARCHAR(10),
    
    -- Response context
    response_status INTEGER,
    response_time_ms INTEGER,
    
    -- Additional context (JSON for flexibility)
    metadata JSONB DEFAULT '{}',
    
    -- Risk assessment
    risk_level VARCHAR(20) DEFAULT 'low',
    
    -- Constraints
    CONSTRAINT audit_logs_event_type_valid CHECK (event_type IN (
        'api_key_created', 'api_key_updated', 'api_key_deleted', 'api_key_used',
        'authentication_success', 'authentication_failed', 'authorization_denied',
        'rate_limit_exceeded', 'crypto_operation', 'security_event', 'system_event'
    )),
    CONSTRAINT audit_logs_response_status_valid CHECK (response_status >= 100 AND response_status < 600),
    CONSTRAINT audit_logs_response_time_positive CHECK (response_time_ms >= 0),
    CONSTRAINT audit_logs_risk_level_valid CHECK (risk_level IN ('low', 'medium', 'high', 'critical'))
);

-- Compliance events table for SOC 2 compliance tracking
CREATE TABLE compliance_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,
    
    -- Compliance context
    control_id VARCHAR(20), -- SOC 2 control reference
    risk_level VARCHAR(20) DEFAULT 'low',
    
    -- Event details
    description TEXT,
    metadata JSONB DEFAULT '{}',
    
    -- Resolution tracking
    status VARCHAR(20) DEFAULT 'open',
    resolved_at TIMESTAMP WITH TIME ZONE NULL,
    resolution_notes TEXT,
    
    -- Constraints
    CONSTRAINT compliance_events_event_type_valid CHECK (event_type IN (
        'security', 'availability', 'processing_integrity', 'confidentiality', 'privacy',
        'access_control', 'data_encryption', 'backup_verification', 'vulnerability_scan',
        'configuration_change', 'incident_response'
    )),
    CONSTRAINT compliance_events_status_valid CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
    CONSTRAINT compliance_events_risk_level_valid CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT compliance_events_resolution_consistency CHECK (
        (resolved_at IS NULL AND resolution_notes IS NULL) OR 
        (resolved_at IS NOT NULL AND status IN ('resolved', 'closed'))
    )
);

-- Analytics table for API usage metrics (write-only)
CREATE TABLE analytics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- API context
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    endpoint VARCHAR(200),
    method VARCHAR(10),
    
    -- Performance metrics
    response_time_ms INTEGER,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,
    
    -- Operational metrics
    success BOOLEAN,
    error_type VARCHAR(50),
    
    -- Geographic and client info (anonymized)
    region VARCHAR(50),
    client_type VARCHAR(50),
    
    -- Additional metrics (JSON for flexibility)
    metrics JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT analytics_response_time_positive CHECK (response_time_ms >= 0),
    CONSTRAINT analytics_request_size_positive CHECK (request_size_bytes >= 0),
    CONSTRAINT analytics_response_size_positive CHECK (response_size_bytes >= 0)
);

-- Indexes for performance optimization

-- API Keys indexes
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX idx_api_keys_expires_at ON api_keys(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_api_keys_last_used ON api_keys(last_used);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_created_at ON api_keys(created_at);

-- Audit logs indexes
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_api_key_id ON audit_logs(api_key_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_risk_level ON audit_logs(risk_level);
CREATE INDEX idx_audit_logs_ip_address ON audit_logs(ip_address);
CREATE INDEX idx_audit_logs_response_status ON audit_logs(response_status);

-- Compliance events indexes
CREATE INDEX idx_compliance_events_timestamp ON compliance_events(timestamp);
CREATE INDEX idx_compliance_events_event_type ON compliance_events(event_type);
CREATE INDEX idx_compliance_events_status ON compliance_events(status);
CREATE INDEX idx_compliance_events_risk_level ON compliance_events(risk_level);
CREATE INDEX idx_compliance_events_control_id ON compliance_events(control_id);

-- Analytics indexes (for time-series queries)
CREATE INDEX idx_analytics_timestamp ON analytics(timestamp);
CREATE INDEX idx_analytics_api_key_id ON analytics(api_key_id);
CREATE INDEX idx_analytics_endpoint ON analytics(endpoint);
CREATE INDEX idx_analytics_success ON analytics(success);

-- Composite indexes for common query patterns
CREATE INDEX idx_api_keys_active_expires ON api_keys(is_active, expires_at) WHERE is_active = true;
CREATE INDEX idx_audit_logs_api_key_timestamp ON audit_logs(api_key_id, timestamp);
CREATE INDEX idx_analytics_api_key_timestamp ON analytics(api_key_id, timestamp);

-- Partial indexes for performance
CREATE INDEX idx_api_keys_active_only ON api_keys(id, name, permissions) WHERE is_active = true;
CREATE INDEX idx_audit_logs_errors_only ON audit_logs(timestamp, event_type) WHERE response_status >= 400;

-- Functions and triggers for data management

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for automatic timestamp updates
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function for audit log cleanup (data retention)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_logs 
    WHERE timestamp < NOW() - INTERVAL '1 day' * retention_days;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    INSERT INTO compliance_events (event_type, control_id, description, metadata)
    VALUES (
        'data_retention',
        'CC6.1',
        'Automated audit log cleanup executed',
        jsonb_build_object('deleted_records', deleted_count, 'retention_days', retention_days)
    );
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function for analytics data cleanup (shorter retention)
CREATE OR REPLACE FUNCTION cleanup_old_analytics(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM analytics 
    WHERE timestamp < NOW() - INTERVAL '1 day' * retention_days;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Row Level Security (RLS) for future multi-tenancy
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE analytics ENABLE ROW LEVEL SECURITY;

-- Views for common queries

-- Active API keys view
CREATE VIEW active_api_keys AS
SELECT 
    id, name, key_hash, permissions, rate_limit,
    created_at, expires_at, last_used, usage_count, user_id
FROM api_keys 
WHERE is_active = true 
  AND (expires_at IS NULL OR expires_at > NOW());

-- Recent audit events view
CREATE VIEW recent_audit_events AS
SELECT 
    id, timestamp, event_type, api_key_id, ip_address,
    request_path, request_method, response_status, risk_level
FROM audit_logs 
WHERE timestamp >= NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;

-- Security events view
CREATE VIEW security_events AS
SELECT 
    id, timestamp, event_type, api_key_id, ip_address,
    response_status, risk_level, metadata
FROM audit_logs 
WHERE event_type IN ('authentication_failed', 'authorization_denied', 'rate_limit_exceeded', 'security_event')
  AND risk_level IN ('medium', 'high', 'critical')
ORDER BY timestamp DESC;

-- Compliance dashboard view
CREATE VIEW compliance_dashboard AS
SELECT 
    event_type,
    risk_level,
    status,
    COUNT(*) as event_count,
    MAX(timestamp) as latest_event,
    COUNT(CASE WHEN status = 'open' THEN 1 END) as open_events
FROM compliance_events 
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY event_type, risk_level, status;

-- API usage statistics view
CREATE VIEW api_usage_stats AS
SELECT 
    DATE_TRUNC('hour', timestamp) as hour,
    endpoint,
    COUNT(*) as request_count,
    AVG(response_time_ms) as avg_response_time,
    COUNT(CASE WHEN success = true THEN 1 END) as success_count,
    COUNT(CASE WHEN success = false THEN 1 END) as error_count
FROM analytics 
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY DATE_TRUNC('hour', timestamp), endpoint
ORDER BY hour DESC, request_count DESC;

-- Sample data for testing (optional - remove in production)
-- INSERT INTO users (email) VALUES ('admin@cypheron.com');
-- INSERT INTO api_keys (name, key_hash, encrypted_key, permissions, user_id) 
-- VALUES ('Test API Key', 'sample_hash_for_testing_only', 'encrypted_data', ARRAY['*'], 
--         (SELECT id FROM users WHERE email = 'admin@cypheron.com'));

-- Grant permissions (adjust based on your application user)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO your_app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO your_app_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO your_app_user;

COMMENT ON SCHEMA public IS 'Cypheron API database schema for PostgreSQL migration';
COMMENT ON TABLE api_keys IS 'API keys with post-quantum encryption and comprehensive security features';
COMMENT ON TABLE audit_logs IS 'Comprehensive audit trail for security and compliance monitoring';
COMMENT ON TABLE compliance_events IS 'SOC 2 compliance event tracking and monitoring';
COMMENT ON TABLE analytics IS 'API usage analytics and performance metrics (write-only)';
COMMENT ON TABLE users IS 'User management table for future multi-tenancy support';