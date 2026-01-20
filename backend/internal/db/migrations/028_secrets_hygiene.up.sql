-- Epic 16: Secrets Hygiene
-- Tables for tracking secrets inventory, rotation, and hygiene

-- Secrets Inventory: Track all secrets across the infrastructure
CREATE TABLE IF NOT EXISTS secrets_inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,

    -- Secret identification
    name VARCHAR(255) NOT NULL,
    secret_type VARCHAR(50) NOT NULL,  -- 'api_key', 'password', 'certificate', 'ssh_key', 'oauth_token', 'database_credential', 'encryption_key'
    source VARCHAR(50) NOT NULL,  -- 'env_var', 'file', 'vault', 'k8s_secret', 'docker_secret', 'config'
    location VARCHAR(500),  -- Path or identifier where secret is stored

    -- Association
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    container_id VARCHAR(255),
    container_name VARCHAR(255),
    service_name VARCHAR(255),

    -- Classification
    classification VARCHAR(50) DEFAULT 'internal',  -- 'public', 'internal', 'confidential', 'restricted'
    environment VARCHAR(50) DEFAULT 'production',
    is_sensitive BOOLEAN DEFAULT TRUE,

    -- Hygiene status
    age_days INTEGER,
    created_date TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    rotation_policy_days INTEGER DEFAULT 90,
    is_expired BOOLEAN DEFAULT FALSE,
    needs_rotation BOOLEAN DEFAULT FALSE,

    -- Security assessment
    strength VARCHAR(20),  -- 'weak', 'moderate', 'strong', 'unknown'
    is_hardcoded BOOLEAN DEFAULT FALSE,
    is_exposed BOOLEAN DEFAULT FALSE,
    exposure_risk VARCHAR(20) DEFAULT 'low',  -- 'low', 'medium', 'high', 'critical'

    -- Metadata
    description TEXT,
    owner_team VARCHAR(100),
    owner_contact VARCHAR(255),
    tags TEXT[] DEFAULT '{}',

    -- Detection
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    auto_discovered BOOLEAN DEFAULT TRUE,
    last_scanned_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name, source, location)
);

CREATE INDEX IF NOT EXISTS idx_secrets_inventory_org_id ON secrets_inventory(org_id);
CREATE INDEX IF NOT EXISTS idx_secrets_inventory_agent_id ON secrets_inventory(agent_id);
CREATE INDEX IF NOT EXISTS idx_secrets_inventory_secret_type ON secrets_inventory(secret_type);
CREATE INDEX IF NOT EXISTS idx_secrets_inventory_source ON secrets_inventory(source);
CREATE INDEX IF NOT EXISTS idx_secrets_inventory_needs_rotation ON secrets_inventory(needs_rotation) WHERE needs_rotation = TRUE;
CREATE INDEX IF NOT EXISTS idx_secrets_inventory_is_expired ON secrets_inventory(is_expired) WHERE is_expired = TRUE;
CREATE INDEX IF NOT EXISTS idx_secrets_inventory_exposure_risk ON secrets_inventory(exposure_risk);

-- Secret Rotation History: Track rotation events
CREATE TABLE IF NOT EXISTS secret_rotation_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    secret_id UUID NOT NULL REFERENCES secrets_inventory(id) ON DELETE CASCADE,

    -- Rotation details
    rotation_type VARCHAR(50) NOT NULL,  -- 'manual', 'automated', 'forced', 'emergency'
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    triggered_by_email VARCHAR(255),

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'in_progress', 'completed', 'failed', 'rolled_back'
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Results
    old_strength VARCHAR(20),
    new_strength VARCHAR(20),
    error_message TEXT,
    rollback_reason TEXT,

    -- Affected systems
    affected_services TEXT[],
    affected_containers TEXT[],
    restart_required BOOLEAN DEFAULT FALSE,
    services_restarted BOOLEAN DEFAULT FALSE,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secret_rotation_history_org_id ON secret_rotation_history(org_id);
CREATE INDEX IF NOT EXISTS idx_secret_rotation_history_secret_id ON secret_rotation_history(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_rotation_history_status ON secret_rotation_history(status);
CREATE INDEX IF NOT EXISTS idx_secret_rotation_history_created_at ON secret_rotation_history(created_at DESC);

-- Secret Exposure Events: Track detected exposures
CREATE TABLE IF NOT EXISTS secret_exposure_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    secret_id UUID REFERENCES secrets_inventory(id) ON DELETE SET NULL,

    -- Detection details
    detection_type VARCHAR(50) NOT NULL,  -- 'log_leak', 'git_commit', 'config_exposure', 'network_capture', 'public_endpoint', 'error_message'
    detection_source VARCHAR(100),  -- e.g., 'trivy', 'gitleaks', 'log_scanner', 'manual'
    severity VARCHAR(20) NOT NULL DEFAULT 'high',  -- 'low', 'medium', 'high', 'critical'

    -- Exposure context
    exposure_location VARCHAR(500),
    exposure_content TEXT,  -- Redacted snippet showing the exposure
    file_path VARCHAR(500),
    line_number INTEGER,
    commit_sha VARCHAR(64),
    repository_url VARCHAR(500),

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',  -- 'active', 'investigating', 'mitigated', 'false_positive', 'accepted_risk'
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,

    -- Impact assessment
    potential_impact TEXT,
    affected_systems TEXT[],
    was_accessed BOOLEAN,  -- Did the exposed secret get used?
    access_attempts INTEGER DEFAULT 0,

    detected_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secret_exposure_events_org_id ON secret_exposure_events(org_id);
CREATE INDEX IF NOT EXISTS idx_secret_exposure_events_secret_id ON secret_exposure_events(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_exposure_events_severity ON secret_exposure_events(severity);
CREATE INDEX IF NOT EXISTS idx_secret_exposure_events_status ON secret_exposure_events(status);
CREATE INDEX IF NOT EXISTS idx_secret_exposure_events_detected_at ON secret_exposure_events(detected_at DESC);

-- Secret Rotation Policies: Define rotation rules
CREATE TABLE IF NOT EXISTS secret_rotation_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Target selection
    target_secret_types TEXT[] DEFAULT '{}',  -- Empty = all types
    target_sources TEXT[] DEFAULT '{}',
    target_classifications TEXT[] DEFAULT '{}',
    target_environments TEXT[] DEFAULT '{}',

    -- Policy rules
    max_age_days INTEGER NOT NULL DEFAULT 90,
    min_strength VARCHAR(20) DEFAULT 'moderate',
    require_unique BOOLEAN DEFAULT TRUE,
    allow_reuse BOOLEAN DEFAULT FALSE,
    reuse_history_count INTEGER DEFAULT 5,

    -- Automation
    auto_rotate BOOLEAN DEFAULT FALSE,
    rotation_cron VARCHAR(100),  -- When to check for rotation
    notify_before_days INTEGER DEFAULT 14,  -- Days before expiry to notify

    -- Notifications
    notify_on_expiry BOOLEAN DEFAULT TRUE,
    notify_on_exposure BOOLEAN DEFAULT TRUE,
    notification_channels TEXT[],

    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_secret_rotation_policies_org_id ON secret_rotation_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_secret_rotation_policies_enabled ON secret_rotation_policies(enabled);

-- Secret Scan Results: Track secret scanning
CREATE TABLE IF NOT EXISTS secret_scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,

    -- Scan details
    scan_type VARCHAR(50) NOT NULL,  -- 'full', 'incremental', 'targeted'
    scan_target VARCHAR(500),  -- What was scanned
    scanner VARCHAR(50) DEFAULT 'builtin',  -- 'builtin', 'gitleaks', 'trufflehog', 'detect-secrets'

    -- Results
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,

    -- Findings
    secrets_found INTEGER DEFAULT 0,
    high_risk_findings INTEGER DEFAULT 0,
    hardcoded_secrets INTEGER DEFAULT 0,
    expired_secrets INTEGER DEFAULT 0,
    weak_secrets INTEGER DEFAULT 0,

    -- Coverage
    files_scanned INTEGER DEFAULT 0,
    containers_scanned INTEGER DEFAULT 0,
    env_vars_scanned INTEGER DEFAULT 0,

    error_message TEXT,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secret_scan_results_org_id ON secret_scan_results(org_id);
CREATE INDEX IF NOT EXISTS idx_secret_scan_results_agent_id ON secret_scan_results(agent_id);
CREATE INDEX IF NOT EXISTS idx_secret_scan_results_status ON secret_scan_results(status);
CREATE INDEX IF NOT EXISTS idx_secret_scan_results_started_at ON secret_scan_results(started_at DESC);

-- View: Secrets hygiene summary
CREATE OR REPLACE VIEW v_secrets_hygiene_summary AS
SELECT
    org_id,
    COUNT(*) as total_secrets,
    COUNT(*) FILTER (WHERE needs_rotation = true) as needs_rotation,
    COUNT(*) FILTER (WHERE is_expired = true) as expired_secrets,
    COUNT(*) FILTER (WHERE strength = 'weak') as weak_secrets,
    COUNT(*) FILTER (WHERE is_hardcoded = true) as hardcoded_secrets,
    COUNT(*) FILTER (WHERE is_exposed = true) as exposed_secrets,
    COUNT(*) FILTER (WHERE exposure_risk = 'critical') as critical_risk,
    COUNT(*) FILTER (WHERE exposure_risk = 'high') as high_risk,
    AVG(age_days) FILTER (WHERE age_days IS NOT NULL) as avg_age_days
FROM secrets_inventory
GROUP BY org_id;

-- View: Secret exposure summary
CREATE OR REPLACE VIEW v_secret_exposure_summary AS
SELECT
    org_id,
    COUNT(*) as total_exposures,
    COUNT(*) FILTER (WHERE status = 'active') as active_exposures,
    COUNT(*) FILTER (WHERE severity = 'critical') as critical_exposures,
    COUNT(*) FILTER (WHERE severity = 'high') as high_exposures,
    COUNT(*) FILTER (WHERE detected_at > NOW() - INTERVAL '7 days') as exposures_last_7d,
    COUNT(*) FILTER (WHERE detected_at > NOW() - INTERVAL '30 days') as exposures_last_30d
FROM secret_exposure_events
GROUP BY org_id;

-- Comments
COMMENT ON TABLE secrets_inventory IS 'Inventory of all secrets across the infrastructure';
COMMENT ON TABLE secret_rotation_history IS 'History of secret rotation events';
COMMENT ON TABLE secret_exposure_events IS 'Detected secret exposure incidents';
COMMENT ON TABLE secret_rotation_policies IS 'Policies for secret rotation and hygiene';
COMMENT ON TABLE secret_scan_results IS 'Results of secret scanning operations';
