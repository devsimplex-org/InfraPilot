-- Migration 032: Traffic Resources Architecture
-- Introduces TrafficResource as first-class domain object with unified policy management

-- ============ Traffic Resources ============
-- Core domain object representing declarative traffic configuration

CREATE TABLE IF NOT EXISTS traffic_resources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Routing
    domains TEXT[] NOT NULL,
    paths JSONB DEFAULT '[{"path": "/", "match": "prefix"}]',

    -- Gateway Type
    gateway_type VARCHAR(20) DEFAULT 'application' CHECK (gateway_type IN ('system', 'application')),

    -- Status & Lifecycle
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'pending', 'active', 'disabled', 'error')),
    desired_state JSONB,
    applied_state JSONB,
    last_applied_at TIMESTAMPTZ,
    last_error TEXT,

    -- Metadata
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, agent_id, name)
);

CREATE INDEX IF NOT EXISTS idx_traffic_resources_org_id ON traffic_resources(org_id);
CREATE INDEX IF NOT EXISTS idx_traffic_resources_agent_id ON traffic_resources(agent_id);
CREATE INDEX IF NOT EXISTS idx_traffic_resources_status ON traffic_resources(status);
CREATE INDEX IF NOT EXISTS idx_traffic_resources_gateway_type ON traffic_resources(gateway_type);
CREATE INDEX IF NOT EXISTS idx_traffic_resources_domains ON traffic_resources USING GIN(domains);

-- ============ Traffic Upstreams ============
-- Load balancing configuration with health checks

CREATE TABLE IF NOT EXISTS traffic_upstreams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    traffic_resource_id UUID NOT NULL REFERENCES traffic_resources(id) ON DELETE CASCADE,

    -- Target
    name VARCHAR(100) NOT NULL,
    targets JSONB NOT NULL DEFAULT '[]',

    -- Load Balancing
    lb_method VARCHAR(20) DEFAULT 'round_robin' CHECK (lb_method IN ('round_robin', 'least_conn', 'ip_hash', 'random')),

    -- Health Checks
    health_check_enabled BOOLEAN DEFAULT TRUE,
    health_check_path VARCHAR(255) DEFAULT '/health',
    health_check_interval_sec INTEGER DEFAULT 30,
    health_check_timeout_sec INTEGER DEFAULT 5,
    healthy_threshold INTEGER DEFAULT 2,
    unhealthy_threshold INTEGER DEFAULT 3,

    -- Connection Management
    max_connections INTEGER,
    max_keepalive INTEGER DEFAULT 64,
    connect_timeout_sec INTEGER DEFAULT 5,
    read_timeout_sec INTEGER DEFAULT 60,
    send_timeout_sec INTEGER DEFAULT 60,

    -- Status
    last_health_check TIMESTAMPTZ,
    healthy_targets INTEGER DEFAULT 0,
    total_targets INTEGER DEFAULT 0,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(traffic_resource_id, name)
);

CREATE INDEX IF NOT EXISTS idx_traffic_upstreams_resource_id ON traffic_upstreams(traffic_resource_id);

-- ============ Traffic Policies ============
-- Unified policy configuration for rate limiting, bot protection, etc.

CREATE TABLE IF NOT EXISTS traffic_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(100) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL CHECK (policy_type IN (
        'rate_limit',
        'bot_protection',
        'geo_blocking',
        'captcha',
        'ip_filtering',
        'header_transform',
        'cors',
        'authentication'
    )),

    -- Policy Configuration (type-specific)
    config JSONB NOT NULL DEFAULT '{}',

    -- Scope
    is_global BOOLEAN DEFAULT FALSE,
    priority INTEGER DEFAULT 0,

    -- Status
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_traffic_policies_org_id ON traffic_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_traffic_policies_type ON traffic_policies(policy_type);
CREATE INDEX IF NOT EXISTS idx_traffic_policies_global ON traffic_policies(is_global) WHERE is_global = TRUE;

-- ============ Traffic Policy Assignments ============
-- Maps policies to traffic resources

CREATE TABLE IF NOT EXISTS traffic_policy_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES traffic_policies(id) ON DELETE CASCADE,
    traffic_resource_id UUID REFERENCES traffic_resources(id) ON DELETE CASCADE,

    -- Path-specific override (optional)
    path_pattern VARCHAR(255),

    -- Override config (optional)
    config_override JSONB,

    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Ensure unique assignment per resource/path
    UNIQUE(policy_id, traffic_resource_id, path_pattern)
);

CREATE INDEX IF NOT EXISTS idx_traffic_policy_assignments_policy ON traffic_policy_assignments(policy_id);
CREATE INDEX IF NOT EXISTS idx_traffic_policy_assignments_resource ON traffic_policy_assignments(traffic_resource_id);

-- ============ Traffic TLS Configs ============
-- TLS settings per traffic resource

CREATE TABLE IF NOT EXISTS traffic_tls_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    traffic_resource_id UUID NOT NULL REFERENCES traffic_resources(id) ON DELETE CASCADE,

    -- Certificate Source
    cert_source VARCHAR(20) DEFAULT 'auto' CHECK (cert_source IN ('auto', 'manual', 'acme')),
    cert_id UUID REFERENCES ssl_certificates(id) ON DELETE SET NULL,

    -- TLS Settings
    min_version VARCHAR(10) DEFAULT 'TLSv1.2',
    max_version VARCHAR(10) DEFAULT 'TLSv1.3',
    cipher_suites TEXT[],
    prefer_server_ciphers BOOLEAN DEFAULT TRUE,

    -- HSTS
    hsts_enabled BOOLEAN DEFAULT TRUE,
    hsts_max_age INTEGER DEFAULT 31536000,
    hsts_include_subdomains BOOLEAN DEFAULT TRUE,
    hsts_preload BOOLEAN DEFAULT FALSE,

    -- OCSP
    ocsp_stapling BOOLEAN DEFAULT TRUE,

    -- Client Cert (mTLS)
    mtls_enabled BOOLEAN DEFAULT FALSE,
    mtls_ca_cert TEXT,
    mtls_verify_depth INTEGER DEFAULT 1,
    mtls_verify_client VARCHAR(20) DEFAULT 'optional' CHECK (mtls_verify_client IN ('off', 'optional', 'require')),

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(traffic_resource_id)
);

CREATE INDEX IF NOT EXISTS idx_traffic_tls_configs_resource ON traffic_tls_configs(traffic_resource_id);

-- ============ Traffic Apply History ============
-- Audit trail for all configuration changes

CREATE TABLE IF NOT EXISTS traffic_apply_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    traffic_resource_id UUID NOT NULL REFERENCES traffic_resources(id) ON DELETE CASCADE,

    -- Change Info
    action VARCHAR(20) NOT NULL CHECK (action IN ('create', 'update', 'delete', 'rollback', 'apply', 'validate')),
    previous_state JSONB,
    new_state JSONB,

    -- Validation
    dry_run_result JSONB,
    validation_passed BOOLEAN,
    validation_errors TEXT[],

    -- Execution
    applied_by UUID REFERENCES users(id) ON DELETE SET NULL,
    applied_at TIMESTAMPTZ DEFAULT NOW(),
    apply_duration_ms INTEGER,
    success BOOLEAN,
    error_message TEXT,

    -- Rendered Config
    rendered_nginx_config TEXT,
    config_hash VARCHAR(64)
);

CREATE INDEX IF NOT EXISTS idx_traffic_apply_history_resource ON traffic_apply_history(traffic_resource_id, applied_at DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_apply_history_user ON traffic_apply_history(applied_by);
CREATE INDEX IF NOT EXISTS idx_traffic_apply_history_action ON traffic_apply_history(action);

-- ============ Traffic Upstream Targets ============
-- Individual upstream targets with health status

CREATE TABLE IF NOT EXISTS traffic_upstream_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    upstream_id UUID NOT NULL REFERENCES traffic_upstreams(id) ON DELETE CASCADE,

    -- Target Info
    address VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    weight INTEGER DEFAULT 1,
    max_fails INTEGER DEFAULT 3,
    fail_timeout_sec INTEGER DEFAULT 30,

    -- Health Status
    is_healthy BOOLEAN DEFAULT TRUE,
    last_health_check TIMESTAMPTZ,
    consecutive_failures INTEGER DEFAULT 0,
    last_error TEXT,

    -- Metadata
    labels JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(upstream_id, address, port)
);

CREATE INDEX IF NOT EXISTS idx_traffic_upstream_targets_upstream ON traffic_upstream_targets(upstream_id);
CREATE INDEX IF NOT EXISTS idx_traffic_upstream_targets_health ON traffic_upstream_targets(is_healthy);

-- ============ Views ============

-- Traffic resource summary view
CREATE OR REPLACE VIEW v_traffic_resource_summary AS
SELECT
    tr.org_id,
    COUNT(*) as total_resources,
    COUNT(*) FILTER (WHERE tr.status = 'active') as active_resources,
    COUNT(*) FILTER (WHERE tr.status = 'draft') as draft_resources,
    COUNT(*) FILTER (WHERE tr.status = 'error') as error_resources,
    COUNT(*) FILTER (WHERE tr.gateway_type = 'system') as system_gateways,
    COUNT(*) FILTER (WHERE tr.gateway_type = 'application') as application_gateways,
    COUNT(DISTINCT tr.agent_id) as agents_with_traffic
FROM traffic_resources tr
GROUP BY tr.org_id;

-- Traffic policy usage view
CREATE OR REPLACE VIEW v_traffic_policy_usage AS
SELECT
    tp.id as policy_id,
    tp.org_id,
    tp.name,
    tp.policy_type,
    tp.is_global,
    tp.enabled,
    COUNT(tpa.id) as assignment_count,
    COUNT(DISTINCT tpa.traffic_resource_id) as resource_count
FROM traffic_policies tp
LEFT JOIN traffic_policy_assignments tpa ON tpa.policy_id = tp.id AND tpa.enabled = TRUE
GROUP BY tp.id;

-- Upstream health summary view
CREATE OR REPLACE VIEW v_upstream_health_summary AS
SELECT
    tu.id as upstream_id,
    tu.traffic_resource_id,
    tu.name,
    tu.lb_method,
    tu.health_check_enabled,
    COUNT(tut.id) as total_targets,
    COUNT(tut.id) FILTER (WHERE tut.is_healthy = TRUE) as healthy_targets,
    COUNT(tut.id) FILTER (WHERE tut.is_healthy = FALSE) as unhealthy_targets,
    MAX(tut.last_health_check) as last_health_check
FROM traffic_upstreams tu
LEFT JOIN traffic_upstream_targets tut ON tut.upstream_id = tu.id AND tut.enabled = TRUE
GROUP BY tu.id;

-- ============ Triggers ============

CREATE TRIGGER update_traffic_resources_updated_at BEFORE UPDATE ON traffic_resources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_traffic_upstreams_updated_at BEFORE UPDATE ON traffic_upstreams
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_traffic_policies_updated_at BEFORE UPDATE ON traffic_policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_traffic_tls_configs_updated_at BEFORE UPDATE ON traffic_tls_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_traffic_upstream_targets_updated_at BEFORE UPDATE ON traffic_upstream_targets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============ Comments ============

COMMENT ON TABLE traffic_resources IS 'Core traffic resource representing declarative traffic configuration';
COMMENT ON TABLE traffic_upstreams IS 'Load balancing configuration with health check settings';
COMMENT ON TABLE traffic_policies IS 'Unified policy definitions for rate limiting, bot protection, etc.';
COMMENT ON TABLE traffic_policy_assignments IS 'Maps policies to traffic resources with optional overrides';
COMMENT ON TABLE traffic_tls_configs IS 'TLS/SSL configuration per traffic resource';
COMMENT ON TABLE traffic_apply_history IS 'Audit trail for all traffic configuration changes';
COMMENT ON TABLE traffic_upstream_targets IS 'Individual upstream targets with health status tracking';
