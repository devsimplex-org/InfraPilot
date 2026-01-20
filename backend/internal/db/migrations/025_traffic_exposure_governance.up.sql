-- Epic 13: Traffic & Exposure Governance
-- Tables for tracking exposed endpoints, rate limiting, and TLS posture

-- Exposed Endpoints: Track all publicly exposed services/endpoints
CREATE TABLE IF NOT EXISTS exposed_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    proxy_host_id UUID REFERENCES proxy_hosts(id) ON DELETE SET NULL,
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,

    -- Endpoint identification
    domain VARCHAR(255) NOT NULL,
    path VARCHAR(500) DEFAULT '/',
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL DEFAULT 'https',  -- http, https, tcp, grpc

    -- Exposure classification
    exposure_type VARCHAR(50) NOT NULL,  -- 'public', 'internal', 'private', 'partner'
    authentication_required BOOLEAN DEFAULT FALSE,
    authentication_type VARCHAR(50),  -- 'none', 'basic', 'oauth', 'api_key', 'mTLS'

    -- Risk assessment
    risk_score INTEGER DEFAULT 0,  -- 0-100
    risk_factors JSONB DEFAULT '[]',  -- Array of risk factor objects
    last_risk_assessment TIMESTAMPTZ,

    -- Traffic metadata
    avg_requests_per_hour NUMERIC,
    peak_requests_per_hour NUMERIC,
    unique_clients_24h INTEGER,
    last_accessed_at TIMESTAMPTZ,

    -- Service metadata
    service_name VARCHAR(100),
    service_owner VARCHAR(100),
    description TEXT,
    tags TEXT[] DEFAULT '{}',

    -- Status
    status VARCHAR(20) DEFAULT 'active',  -- 'active', 'inactive', 'deprecated', 'blocked'
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for exposed_endpoints
CREATE INDEX IF NOT EXISTS idx_exposed_endpoints_org_id ON exposed_endpoints(org_id);
CREATE INDEX IF NOT EXISTS idx_exposed_endpoints_agent_id ON exposed_endpoints(agent_id);
CREATE INDEX IF NOT EXISTS idx_exposed_endpoints_domain ON exposed_endpoints(domain);
CREATE INDEX IF NOT EXISTS idx_exposed_endpoints_exposure_type ON exposed_endpoints(exposure_type);
CREATE INDEX IF NOT EXISTS idx_exposed_endpoints_risk_score ON exposed_endpoints(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_exposed_endpoints_status ON exposed_endpoints(status);

-- Rate Limit Profiles: Reusable rate limiting configurations
CREATE TABLE IF NOT EXISTS rate_limit_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Rate limit settings
    requests_per_second INTEGER,
    requests_per_minute INTEGER,
    requests_per_hour INTEGER,
    burst_size INTEGER DEFAULT 10,

    -- Advanced options
    key_type VARCHAR(50) DEFAULT 'ip',  -- 'ip', 'api_key', 'user', 'custom'
    custom_key_header VARCHAR(100),

    -- Response behavior
    exceeded_action VARCHAR(20) DEFAULT 'reject',  -- 'reject', 'throttle', 'queue'
    exceeded_status_code INTEGER DEFAULT 429,
    exceeded_message TEXT DEFAULT 'Rate limit exceeded',

    -- Metadata
    is_default BOOLEAN DEFAULT FALSE,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_profiles_org_id ON rate_limit_profiles(org_id);

-- Rate Limit Assignments: Apply profiles to endpoints
CREATE TABLE IF NOT EXISTS rate_limit_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES rate_limit_profiles(id) ON DELETE CASCADE,

    -- Target (one of these should be set)
    endpoint_id UUID REFERENCES exposed_endpoints(id) ON DELETE CASCADE,
    proxy_host_id UUID REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    domain_pattern VARCHAR(255),  -- Wildcard pattern like *.api.example.com

    -- Override settings (optional, overrides profile)
    requests_per_second INTEGER,
    requests_per_minute INTEGER,
    burst_size INTEGER,

    priority INTEGER DEFAULT 0,  -- Higher priority takes precedence
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Ensure at least one target is specified
    CONSTRAINT rate_limit_assignment_target CHECK (
        endpoint_id IS NOT NULL OR proxy_host_id IS NOT NULL OR domain_pattern IS NOT NULL
    )
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_assignments_org_id ON rate_limit_assignments(org_id);
CREATE INDEX IF NOT EXISTS idx_rate_limit_assignments_profile_id ON rate_limit_assignments(profile_id);
CREATE INDEX IF NOT EXISTS idx_rate_limit_assignments_endpoint_id ON rate_limit_assignments(endpoint_id);

-- TLS Alert Configuration: Configure alerts for TLS/SSL issues
CREATE TABLE IF NOT EXISTS tls_alert_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Alert thresholds
    expiry_warning_days INTEGER DEFAULT 30,
    expiry_critical_days INTEGER DEFAULT 7,

    -- Alert settings
    alert_on_weak_cipher BOOLEAN DEFAULT TRUE,
    alert_on_protocol_downgrade BOOLEAN DEFAULT TRUE,
    alert_on_cert_mismatch BOOLEAN DEFAULT TRUE,
    alert_on_self_signed BOOLEAN DEFAULT TRUE,
    alert_on_expired BOOLEAN DEFAULT TRUE,

    -- Notification channels (references alert_channels table)
    notification_channels UUID[] DEFAULT '{}',

    -- Scan settings
    auto_scan_enabled BOOLEAN DEFAULT TRUE,
    scan_interval_hours INTEGER DEFAULT 24,
    last_scan_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id)
);

-- TLS Scan Results: Store historical TLS scan data
CREATE TABLE IF NOT EXISTS tls_scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES exposed_endpoints(id) ON DELETE SET NULL,
    proxy_host_id UUID REFERENCES proxy_hosts(id) ON DELETE SET NULL,

    domain VARCHAR(255) NOT NULL,

    -- Certificate info
    cert_valid BOOLEAN,
    cert_issuer VARCHAR(255),
    cert_subject VARCHAR(255),
    cert_expires_at TIMESTAMPTZ,
    cert_days_left INTEGER,
    cert_san TEXT[],
    is_self_signed BOOLEAN DEFAULT FALSE,

    -- Protocol/cipher info
    protocol_version VARCHAR(20),  -- TLS 1.2, TLS 1.3, etc.
    cipher_suite VARCHAR(100),
    key_exchange VARCHAR(50),
    is_weak_cipher BOOLEAN DEFAULT FALSE,

    -- HSTS info
    hsts_enabled BOOLEAN DEFAULT FALSE,
    hsts_max_age INTEGER,
    hsts_preload BOOLEAN DEFAULT FALSE,

    -- Overall assessment
    grade VARCHAR(5),  -- A+, A, B, C, D, F
    score INTEGER,  -- 0-100
    issues JSONB DEFAULT '[]',

    scanned_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tls_scan_results_org_id ON tls_scan_results(org_id);
CREATE INDEX IF NOT EXISTS idx_tls_scan_results_domain ON tls_scan_results(domain);
CREATE INDEX IF NOT EXISTS idx_tls_scan_results_scanned_at ON tls_scan_results(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_tls_scan_results_grade ON tls_scan_results(grade);

-- View: Exposure summary by organization
CREATE OR REPLACE VIEW v_exposure_summary AS
SELECT
    org_id,
    COUNT(*) as total_endpoints,
    COUNT(*) FILTER (WHERE exposure_type = 'public') as public_endpoints,
    COUNT(*) FILTER (WHERE exposure_type = 'internal') as internal_endpoints,
    COUNT(*) FILTER (WHERE authentication_required = false AND exposure_type = 'public') as unauthenticated_public,
    AVG(risk_score)::INTEGER as avg_risk_score,
    COUNT(*) FILTER (WHERE risk_score >= 70) as high_risk_endpoints,
    COUNT(*) FILTER (WHERE status = 'active') as active_endpoints
FROM exposed_endpoints
GROUP BY org_id;

-- View: TLS posture summary
CREATE OR REPLACE VIEW v_tls_posture AS
SELECT
    org_id,
    COUNT(DISTINCT domain) as total_domains,
    COUNT(*) FILTER (WHERE cert_valid = true) as valid_certs,
    COUNT(*) FILTER (WHERE cert_valid = false) as invalid_certs,
    COUNT(*) FILTER (WHERE is_self_signed = true) as self_signed,
    COUNT(*) FILTER (WHERE is_weak_cipher = true) as weak_ciphers,
    COUNT(*) FILTER (WHERE cert_days_left <= 7) as expiring_critical,
    COUNT(*) FILTER (WHERE cert_days_left <= 30 AND cert_days_left > 7) as expiring_warning,
    AVG(score)::INTEGER as avg_score
FROM (
    SELECT DISTINCT ON (org_id, domain) *
    FROM tls_scan_results
    ORDER BY org_id, domain, scanned_at DESC
) latest_scans
GROUP BY org_id;

-- Comments
COMMENT ON TABLE exposed_endpoints IS 'Inventory of all publicly or internally exposed endpoints for traffic governance';
COMMENT ON TABLE rate_limit_profiles IS 'Reusable rate limiting configuration profiles';
COMMENT ON TABLE rate_limit_assignments IS 'Assignment of rate limit profiles to endpoints or domains';
COMMENT ON TABLE tls_alert_config IS 'Configuration for TLS/SSL alerting thresholds';
COMMENT ON TABLE tls_scan_results IS 'Historical TLS scan results for endpoints';
