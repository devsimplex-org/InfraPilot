-- Epic 18: External Dependency Mapping
-- Tables for tracking external services, APIs, and dependencies

-- External Services: Track all external services/APIs used
CREATE TABLE IF NOT EXISTS external_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Service identification
    name VARCHAR(255) NOT NULL,
    service_type VARCHAR(50) NOT NULL,  -- 'api', 'database', 'storage', 'messaging', 'cdn', 'dns', 'monitoring', 'auth', 'payment', 'other'
    provider VARCHAR(100),  -- 'aws', 'gcp', 'azure', 'cloudflare', 'stripe', 'twilio', etc.

    -- Connection details
    endpoint_url TEXT,
    base_domain VARCHAR(255),
    port INTEGER,
    protocol VARCHAR(20) DEFAULT 'https',  -- 'http', 'https', 'grpc', 'tcp', 'amqp', 'redis'

    -- Classification
    criticality VARCHAR(20) NOT NULL DEFAULT 'medium',  -- 'critical', 'high', 'medium', 'low'
    data_classification VARCHAR(20),  -- 'public', 'internal', 'confidential', 'restricted'
    environment VARCHAR(20) DEFAULT 'production',

    -- Health & Monitoring
    health_status VARCHAR(20) DEFAULT 'unknown',  -- 'healthy', 'degraded', 'unhealthy', 'unknown'
    last_health_check TIMESTAMPTZ,
    health_check_url TEXT,
    health_check_interval_seconds INTEGER DEFAULT 300,

    -- SLA & Compliance
    expected_uptime_percent DECIMAL(5, 2) DEFAULT 99.9,
    sla_document_url TEXT,
    compliance_requirements TEXT[],  -- 'soc2', 'hipaa', 'gdpr', 'pci'

    -- Authentication
    auth_type VARCHAR(50),  -- 'api_key', 'oauth2', 'basic', 'certificate', 'iam', 'none'
    auth_secret_id UUID REFERENCES secrets_inventory(id) ON DELETE SET NULL,

    -- Ownership
    owner_team VARCHAR(100),
    owner_contact VARCHAR(255),
    vendor_contact VARCHAR(255),
    contract_end_date DATE,

    -- Discovery
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    auto_discovered BOOLEAN DEFAULT FALSE,
    discovery_source VARCHAR(50),  -- 'manual', 'network_scan', 'code_scan', 'config_scan'

    -- Metadata
    description TEXT,
    documentation_url TEXT,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',

    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name, environment)
);

CREATE INDEX IF NOT EXISTS idx_external_services_org_id ON external_services(org_id);
CREATE INDEX IF NOT EXISTS idx_external_services_service_type ON external_services(service_type);
CREATE INDEX IF NOT EXISTS idx_external_services_provider ON external_services(provider);
CREATE INDEX IF NOT EXISTS idx_external_services_criticality ON external_services(criticality);
CREATE INDEX IF NOT EXISTS idx_external_services_health_status ON external_services(health_status);

-- Service Dependencies: Map which internal services depend on external services
CREATE TABLE IF NOT EXISTS service_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Source (internal)
    source_type VARCHAR(50) NOT NULL,  -- 'deployment', 'container', 'service', 'agent'
    source_id UUID,
    source_name VARCHAR(255) NOT NULL,

    -- Target (external)
    external_service_id UUID NOT NULL REFERENCES external_services(id) ON DELETE CASCADE,

    -- Dependency details
    dependency_type VARCHAR(50) NOT NULL DEFAULT 'runtime',  -- 'runtime', 'build', 'test', 'optional'
    is_critical BOOLEAN DEFAULT FALSE,
    fallback_available BOOLEAN DEFAULT FALSE,
    fallback_service_id UUID REFERENCES external_services(id) ON DELETE SET NULL,

    -- Usage
    usage_pattern VARCHAR(50),  -- 'continuous', 'periodic', 'on_demand', 'batch'
    avg_requests_per_minute INTEGER,
    avg_latency_ms INTEGER,

    -- Health impact
    failure_impact VARCHAR(100),  -- 'service_down', 'degraded_performance', 'feature_unavailable', 'minimal'

    -- Discovery
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    auto_discovered BOOLEAN DEFAULT FALSE,
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, source_type, source_name, external_service_id)
);

CREATE INDEX IF NOT EXISTS idx_service_dependencies_org_id ON service_dependencies(org_id);
CREATE INDEX IF NOT EXISTS idx_service_dependencies_external_service_id ON service_dependencies(external_service_id);
CREATE INDEX IF NOT EXISTS idx_service_dependencies_source_name ON service_dependencies(source_name);
CREATE INDEX IF NOT EXISTS idx_service_dependencies_is_critical ON service_dependencies(is_critical);

-- External Service Health History: Track health check results
CREATE TABLE IF NOT EXISTS external_service_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_id UUID NOT NULL REFERENCES external_services(id) ON DELETE CASCADE,

    -- Check result
    status VARCHAR(20) NOT NULL,  -- 'healthy', 'degraded', 'unhealthy', 'timeout', 'error'
    response_time_ms INTEGER,
    status_code INTEGER,

    -- Details
    check_type VARCHAR(50) DEFAULT 'http',  -- 'http', 'tcp', 'dns', 'custom'
    error_message TEXT,

    checked_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_external_service_health_service_id ON external_service_health(service_id);
CREATE INDEX IF NOT EXISTS idx_external_service_health_checked_at ON external_service_health(checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_external_service_health_status ON external_service_health(status);

-- External Service Incidents: Track outages and issues
CREATE TABLE IF NOT EXISTS external_service_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_id UUID NOT NULL REFERENCES external_services(id) ON DELETE CASCADE,

    -- Incident details
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,  -- 'minor', 'major', 'critical'
    incident_type VARCHAR(50),  -- 'outage', 'degradation', 'maintenance', 'security'

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',  -- 'active', 'investigating', 'identified', 'monitoring', 'resolved'

    -- Timeline
    started_at TIMESTAMPTZ NOT NULL,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,

    -- Impact
    affected_services TEXT[],
    impact_description TEXT,
    user_impact VARCHAR(100),  -- 'none', 'minimal', 'significant', 'severe'

    -- Resolution
    resolution_notes TEXT,
    root_cause TEXT,

    -- Source
    reported_by VARCHAR(100),  -- 'health_check', 'vendor_status', 'manual', 'alert'
    vendor_incident_url TEXT,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_external_service_incidents_service_id ON external_service_incidents(service_id);
CREATE INDEX IF NOT EXISTS idx_external_service_incidents_status ON external_service_incidents(status);
CREATE INDEX IF NOT EXISTS idx_external_service_incidents_severity ON external_service_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_external_service_incidents_started_at ON external_service_incidents(started_at DESC);

-- API Endpoints: Detailed tracking of external API endpoints used
CREATE TABLE IF NOT EXISTS external_api_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_id UUID NOT NULL REFERENCES external_services(id) ON DELETE CASCADE,

    -- Endpoint details
    path VARCHAR(500) NOT NULL,
    method VARCHAR(10) NOT NULL DEFAULT 'GET',  -- 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'

    -- Usage statistics
    call_count INTEGER DEFAULT 0,
    last_called_at TIMESTAMPTZ,
    avg_response_time_ms INTEGER,
    error_rate_percent DECIMAL(5, 2) DEFAULT 0,

    -- Rate limiting
    rate_limit_requests INTEGER,
    rate_limit_window_seconds INTEGER,
    current_usage_percent DECIMAL(5, 2),

    -- Classification
    data_sensitivity VARCHAR(20),  -- 'public', 'internal', 'confidential', 'restricted'

    -- Discovery
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    auto_discovered BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, service_id, path, method)
);

CREATE INDEX IF NOT EXISTS idx_external_api_endpoints_service_id ON external_api_endpoints(service_id);
CREATE INDEX IF NOT EXISTS idx_external_api_endpoints_last_called ON external_api_endpoints(last_called_at DESC);

-- View: External service summary with health and dependency counts
CREATE OR REPLACE VIEW v_external_service_summary AS
SELECT
    es.org_id,
    es.id as service_id,
    es.name,
    es.service_type,
    es.provider,
    es.criticality,
    es.health_status,
    es.last_health_check,
    es.environment,
    COUNT(DISTINCT sd.id) as dependent_services_count,
    COUNT(DISTINCT sd.id) FILTER (WHERE sd.is_critical = TRUE) as critical_dependencies,
    COUNT(DISTINCT eae.id) as api_endpoints_count,
    (SELECT COUNT(*) FROM external_service_incidents esi
     WHERE esi.service_id = es.id AND esi.status = 'active') as active_incidents
FROM external_services es
LEFT JOIN service_dependencies sd ON sd.external_service_id = es.id
LEFT JOIN external_api_endpoints eae ON eae.service_id = es.id
WHERE es.enabled = TRUE
GROUP BY es.id;

-- View: Dependency risk assessment
CREATE OR REPLACE VIEW v_dependency_risk AS
SELECT
    sd.org_id,
    sd.source_name,
    sd.source_type,
    es.name as external_service_name,
    es.service_type,
    es.provider,
    es.criticality as service_criticality,
    sd.is_critical as dependency_critical,
    sd.fallback_available,
    es.health_status,
    sd.failure_impact,
    CASE
        WHEN es.criticality = 'critical' AND sd.is_critical AND NOT sd.fallback_available THEN 'critical'
        WHEN es.criticality IN ('critical', 'high') AND sd.is_critical THEN 'high'
        WHEN sd.is_critical OR es.criticality IN ('critical', 'high') THEN 'medium'
        ELSE 'low'
    END as risk_level
FROM service_dependencies sd
JOIN external_services es ON es.id = sd.external_service_id
WHERE es.enabled = TRUE;

-- View: Service health overview
CREATE OR REPLACE VIEW v_external_health_overview AS
SELECT
    org_id,
    COUNT(*) as total_services,
    COUNT(*) FILTER (WHERE health_status = 'healthy') as healthy_services,
    COUNT(*) FILTER (WHERE health_status = 'degraded') as degraded_services,
    COUNT(*) FILTER (WHERE health_status = 'unhealthy') as unhealthy_services,
    COUNT(*) FILTER (WHERE health_status = 'unknown') as unknown_services,
    COUNT(*) FILTER (WHERE criticality = 'critical') as critical_services,
    COUNT(*) FILTER (WHERE criticality = 'critical' AND health_status != 'healthy') as critical_unhealthy
FROM external_services
WHERE enabled = TRUE
GROUP BY org_id;

-- Comments
COMMENT ON TABLE external_services IS 'Track all external services and APIs the organization depends on';
COMMENT ON TABLE service_dependencies IS 'Map internal services to their external dependencies';
COMMENT ON TABLE external_service_health IS 'Health check history for external services';
COMMENT ON TABLE external_service_incidents IS 'Track outages and incidents affecting external services';
COMMENT ON TABLE external_api_endpoints IS 'Detailed tracking of external API endpoints used';
