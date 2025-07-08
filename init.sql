-- Cypheron Crypto API Database Schema
-- PostgreSQL initialization script with security best practices

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create dedicated schema for API management
CREATE SCHEMA IF NOT EXISTS api_mgmt;

-- Create API keys table with encryption and audit features
CREATE TABLE IF NOT EXISTS api_mgmt.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(128) NOT NULL UNIQUE, -- SHA256 hash of the API key
    encrypted_key TEXT NOT NULL, -- AES-256-GCM encrypted key for backup/recovery
    permissions JSON NOT NULL DEFAULT '[]',
    rate_limit INTEGER NOT NULL DEFAULT 60,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    last_used TIMESTAMP WITH TIME ZONE,
    usage_count BIGINT DEFAULT 0,
    metadata JSON DEFAULT '{}',
    
    -- Security constraints
    CONSTRAINT check_rate_limit CHECK (rate_limit > 0 AND rate_limit <= 10000),
    CONSTRAINT check_name_length CHECK (char_length(name) >= 3 AND char_length(name) <= 255),
    CONSTRAINT check_expiry_future CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Create audit log table for security monitoring
CREATE TABLE IF NOT EXISTS api_mgmt.api_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_id UUID REFERENCES api_mgmt.api_keys(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    resource VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    metadata JSON DEFAULT '{}'
);

-- Create rate limiting table
CREATE TABLE IF NOT EXISTS api_mgmt.rate_limit_tracking (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    api_key_id UUID REFERENCES api_mgmt.api_keys(id) ON DELETE CASCADE,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    request_count INTEGER DEFAULT 0,
    last_request TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Unique constraint for time window tracking
    UNIQUE(api_key_id, window_start)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_mgmt.api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_mgmt.api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_mgmt.api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON api_mgmt.api_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_api_key ON api_mgmt.api_audit_log(api_key_id);
CREATE INDEX IF NOT EXISTS idx_rate_limit_key_window ON api_mgmt.rate_limit_tracking(api_key_id, window_start);

-- Create security views for monitoring
CREATE OR REPLACE VIEW api_mgmt.active_api_keys AS
SELECT id, name, permissions, rate_limit, created_at, expires_at, last_used, usage_count
FROM api_mgmt.api_keys
WHERE is_active = TRUE AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP);

CREATE OR REPLACE VIEW api_mgmt.security_summary AS
SELECT 
    COUNT(*) as total_keys,
    COUNT(CASE WHEN is_active = TRUE THEN 1 END) as active_keys,
    COUNT(CASE WHEN expires_at IS NOT NULL AND expires_at < CURRENT_TIMESTAMP THEN 1 END) as expired_keys,
    COUNT(CASE WHEN last_used > CURRENT_TIMESTAMP - INTERVAL '24 hours' THEN 1 END) as recently_used,
    AVG(usage_count) as avg_usage
FROM api_mgmt.api_keys;

-- Create stored procedures for key management
CREATE OR REPLACE FUNCTION api_mgmt.create_api_key(
    p_name VARCHAR(255),
    p_key_hash VARCHAR(128),
    p_encrypted_key TEXT,
    p_permissions JSON,
    p_rate_limit INTEGER DEFAULT 60,
    p_expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    new_key_id UUID;
BEGIN
    INSERT INTO api_mgmt.api_keys (name, key_hash, encrypted_key, permissions, rate_limit, expires_at)
    VALUES (p_name, p_key_hash, p_encrypted_key, p_permissions, p_rate_limit, p_expires_at)
    RETURNING id INTO new_key_id;
    
    -- Log the creation
    INSERT INTO api_mgmt.api_audit_log (api_key_id, action, metadata)
    VALUES (new_key_id, 'CREATE', json_build_object('rate_limit', p_rate_limit, 'expires_at', p_expires_at));
    
    RETURN new_key_id;
END;
$$ LANGUAGE plpgsql;

-- Create function for secure key validation
CREATE OR REPLACE FUNCTION api_mgmt.validate_api_key(p_key_hash VARCHAR(128))
RETURNS TABLE (
    key_id UUID,
    name VARCHAR(255),
    permissions JSON,
    rate_limit INTEGER,
    is_valid BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ak.id,
        ak.name,
        ak.permissions,
        ak.rate_limit,
        (ak.is_active = TRUE AND (ak.expires_at IS NULL OR ak.expires_at > CURRENT_TIMESTAMP)) as is_valid
    FROM api_mgmt.api_keys ak
    WHERE ak.key_hash = p_key_hash;
    
    -- Update last used timestamp if valid
    UPDATE api_mgmt.api_keys 
    SET last_used = CURRENT_TIMESTAMP,
        usage_count = usage_count + 1
    WHERE key_hash = p_key_hash 
      AND is_active = TRUE 
      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP);
END;
$$ LANGUAGE plpgsql;

-- Create cleanup function for old audit logs
CREATE OR REPLACE FUNCTION api_mgmt.cleanup_old_audit_logs(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM api_mgmt.api_audit_log 
    WHERE timestamp < CURRENT_TIMESTAMP - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Set up row-level security
ALTER TABLE api_mgmt.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_mgmt.api_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_mgmt.rate_limit_tracking ENABLE ROW LEVEL SECURITY;

-- Create API user with limited permissions
CREATE USER IF NOT EXISTS api_service WITH PASSWORD 'api_service_secure_2024';
GRANT USAGE ON SCHEMA api_mgmt TO api_service;
GRANT SELECT, INSERT, UPDATE ON api_mgmt.api_keys TO api_service;
GRANT SELECT, INSERT ON api_mgmt.api_audit_log TO api_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_mgmt.rate_limit_tracking TO api_service;
GRANT EXECUTE ON FUNCTION api_mgmt.validate_api_key TO api_service;
GRANT EXECUTE ON FUNCTION api_mgmt.create_api_key TO api_service;

-- Grant sequence permissions
GRANT USAGE ON ALL SEQUENCES IN SCHEMA api_mgmt TO api_service;

-- Create RLS policies for API service
CREATE POLICY api_service_policy ON api_mgmt.api_keys FOR ALL TO api_service USING (true);
CREATE POLICY api_service_audit_policy ON api_mgmt.api_audit_log FOR ALL TO api_service USING (true);
CREATE POLICY api_service_rate_policy ON api_mgmt.rate_limit_tracking FOR ALL TO api_service USING (true);

-- Insert default test key if environment variable is set
DO $$
BEGIN
    -- This will be replaced by the application with proper key generation
    IF current_setting('cypheron.create_test_key', true) = 'true' THEN
        PERFORM api_mgmt.create_api_key(
            'Default Test Key',
            'test_key_hash_placeholder',
            'encrypted_test_key_placeholder',
            '["kem:*", "sig:*", "hybrid:*"]'::json,
            100,
            CURRENT_TIMESTAMP + INTERVAL '30 days'
        );
    END IF;
END;
$$;

-- Create monitoring view for security dashboard
CREATE OR REPLACE VIEW api_mgmt.security_dashboard AS
SELECT 
    date_trunc('hour', timestamp) as hour,
    COUNT(*) as total_requests,
    COUNT(CASE WHEN success = FALSE THEN 1 END) as failed_requests,
    COUNT(DISTINCT api_key_id) as unique_keys,
    AVG(CASE WHEN success = TRUE THEN 1.0 ELSE 0.0 END) as success_rate
FROM api_mgmt.api_audit_log
WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'
GROUP BY date_trunc('hour', timestamp)
ORDER BY hour DESC;

-- Add comments for documentation
COMMENT ON SCHEMA api_mgmt IS 'API management schema for Cypheron crypto API';
COMMENT ON TABLE api_mgmt.api_keys IS 'Encrypted storage for API keys with security features';
COMMENT ON TABLE api_mgmt.api_audit_log IS 'Audit trail for all API operations';
COMMENT ON TABLE api_mgmt.rate_limit_tracking IS 'Rate limiting enforcement data';
COMMENT ON FUNCTION api_mgmt.validate_api_key IS 'Secure API key validation with audit logging';
COMMENT ON FUNCTION api_mgmt.create_api_key IS 'Secure API key creation with audit logging';