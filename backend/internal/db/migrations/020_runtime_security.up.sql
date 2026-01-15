-- Migration 020: Runtime Security (Epic 3)
-- Adds drift detection and behavioral monitoring for runtime threat detection

-- ============================================================================
-- Drift Events
-- ============================================================================

-- Drift types enum
CREATE TYPE drift_type AS ENUM (
    'image_changed',
    'port_added',
    'port_removed',
    'privilege_escalation',
    'config_modified',
    'container_restarted',
    'resource_exceeded',
    'volume_added',
    'volume_removed',
    'environment_changed',
    'network_changed',
    'user_changed'
);

-- Drift severity enum
CREATE TYPE drift_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- Drift events table
CREATE TABLE drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Container/Deployment linkage
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    container_id VARCHAR(64) NOT NULL,
    container_name VARCHAR(255),

    -- Drift information
    drift_type drift_type NOT NULL,
    severity drift_severity NOT NULL,

    -- Details
    description TEXT NOT NULL,
    expected_state JSONB,
    actual_state JSONB,
    diff JSONB, -- Structured difference

    -- Detection metadata
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    detection_method VARCHAR(50), -- periodic_scan, realtime_event, manual

    -- Resolution
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_action VARCHAR(50), -- ignored, reverted, acknowledged
    resolution_notes TEXT,

    -- Auto-resolution
    auto_resolved BOOLEAN DEFAULT FALSE,
    auto_resolution_reason TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for drift events
CREATE INDEX idx_drift_events_org ON drift_events(org_id);
CREATE INDEX idx_drift_events_agent ON drift_events(agent_id);
CREATE INDEX idx_drift_events_deployment ON drift_events(deployment_id);
CREATE INDEX idx_drift_events_container ON drift_events(container_id);
CREATE INDEX idx_drift_events_type ON drift_events(drift_type);
CREATE INDEX idx_drift_events_severity ON drift_events(severity);
CREATE INDEX idx_drift_events_resolved ON drift_events(resolved);
CREATE INDEX idx_drift_events_detected ON drift_events(detected_at DESC);
CREATE INDEX idx_drift_events_created ON drift_events(created_at DESC);

-- ============================================================================
-- Behavioral Anomalies
-- ============================================================================

-- Anomaly types enum
CREATE TYPE anomaly_type AS ENUM (
    'crash_loop',
    'log_volume_spike',
    'error_rate_spike',
    'cpu_exhaustion',
    'memory_exhaustion',
    'disk_exhaustion',
    'network_spike',
    'unexpected_shutdown',
    'oom_killed',
    'process_spawn_spike'
);

-- Behavioral anomalies table
CREATE TABLE behavioral_anomalies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Container/Deployment linkage
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    container_id VARCHAR(64) NOT NULL,
    container_name VARCHAR(255),

    -- Anomaly information
    anomaly_type anomaly_type NOT NULL,
    severity drift_severity NOT NULL,

    -- Details
    description TEXT NOT NULL,
    baseline_value NUMERIC,
    observed_value NUMERIC,
    threshold_value NUMERIC,

    -- Metrics
    metric_name VARCHAR(100),
    metric_unit VARCHAR(20),
    time_window_minutes INTEGER, -- Observation window

    -- Evidence
    evidence JSONB, -- Supporting data (logs, metrics, events)

    -- Detection
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    first_observed_at TIMESTAMP WITH TIME ZONE,
    last_observed_at TIMESTAMP WITH TIME ZONE,
    occurrence_count INTEGER DEFAULT 1,

    -- Resolution
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for behavioral anomalies
CREATE INDEX idx_behavioral_anomalies_org ON behavioral_anomalies(org_id);
CREATE INDEX idx_behavioral_anomalies_agent ON behavioral_anomalies(agent_id);
CREATE INDEX idx_behavioral_anomalies_deployment ON behavioral_anomalies(deployment_id);
CREATE INDEX idx_behavioral_anomalies_container ON behavioral_anomalies(container_id);
CREATE INDEX idx_behavioral_anomalies_type ON behavioral_anomalies(anomaly_type);
CREATE INDEX idx_behavioral_anomalies_severity ON behavioral_anomalies(severity);
CREATE INDEX idx_behavioral_anomalies_resolved ON behavioral_anomalies(resolved);
CREATE INDEX idx_behavioral_anomalies_detected ON behavioral_anomalies(detected_at DESC);

-- ============================================================================
-- Runtime Security Configuration
-- ============================================================================

-- Runtime security configuration per organization
CREATE TABLE runtime_security_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Drift Detection Settings
    drift_detection_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    drift_scan_interval_seconds INTEGER NOT NULL DEFAULT 60,

    -- Drift type enablement
    detect_image_changes BOOLEAN NOT NULL DEFAULT TRUE,
    detect_port_changes BOOLEAN NOT NULL DEFAULT TRUE,
    detect_privilege_escalation BOOLEAN NOT NULL DEFAULT TRUE,
    detect_config_changes BOOLEAN NOT NULL DEFAULT TRUE,
    detect_volume_changes BOOLEAN NOT NULL DEFAULT TRUE,
    detect_network_changes BOOLEAN NOT NULL DEFAULT TRUE,

    -- Behavioral Monitoring Settings
    behavioral_monitoring_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Crash loop detection
    crash_loop_threshold INTEGER NOT NULL DEFAULT 3, -- restarts
    crash_loop_window_minutes INTEGER NOT NULL DEFAULT 5,

    -- Log volume detection
    log_spike_multiplier NUMERIC NOT NULL DEFAULT 10.0, -- 10x normal
    log_spike_window_minutes INTEGER NOT NULL DEFAULT 5,

    -- Error rate detection
    error_rate_threshold NUMERIC NOT NULL DEFAULT 50.0, -- 50%
    error_rate_window_minutes INTEGER NOT NULL DEFAULT 5,

    -- Resource exhaustion detection
    cpu_exhaustion_threshold NUMERIC NOT NULL DEFAULT 90.0, -- 90%
    memory_exhaustion_threshold NUMERIC NOT NULL DEFAULT 90.0, -- 90%
    disk_exhaustion_threshold NUMERIC NOT NULL DEFAULT 90.0, -- 90%

    -- Alert Settings
    alert_on_critical_drift BOOLEAN NOT NULL DEFAULT TRUE,
    alert_on_high_drift BOOLEAN NOT NULL DEFAULT TRUE,
    alert_on_anomalies BOOLEAN NOT NULL DEFAULT TRUE,

    -- Auto-resolution
    auto_resolve_info_drift BOOLEAN NOT NULL DEFAULT TRUE,
    auto_resolve_after_hours INTEGER DEFAULT 24,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(org_id)
);

-- Index for runtime security config
CREATE INDEX idx_runtime_security_config_org ON runtime_security_config(org_id);

-- ============================================================================
-- Expected Container State
-- ============================================================================

-- Expected state for containers (snapshot at deployment)
CREATE TABLE expected_container_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    container_id VARCHAR(64) NOT NULL,

    -- Expected configuration
    expected_image VARCHAR(500) NOT NULL,
    expected_image_digest VARCHAR(255),
    expected_ports JSONB, -- Array of port mappings
    expected_volumes JSONB, -- Array of volume mounts
    expected_environment JSONB, -- Array of env vars
    expected_user VARCHAR(100),
    expected_privileged BOOLEAN,
    expected_capabilities JSONB,
    expected_network_mode VARCHAR(50),
    expected_restart_policy VARCHAR(50),

    -- Full snapshot
    full_config JSONB,

    -- Metadata
    snapshot_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(deployment_id, container_id)
);

-- Indexes for expected state
CREATE INDEX idx_expected_container_state_org ON expected_container_state(org_id);
CREATE INDEX idx_expected_container_state_deployment ON expected_container_state(deployment_id);
CREATE INDEX idx_expected_container_state_container ON expected_container_state(container_id);

-- ============================================================================
-- Views
-- ============================================================================

-- Recent drift events (last 24 hours)
CREATE VIEW v_recent_drift_events AS
SELECT
    org_id,
    drift_type,
    severity,
    COUNT(*) as event_count,
    COUNT(CASE WHEN NOT resolved THEN 1 END) as unresolved_count,
    MAX(detected_at) as last_detected_at,
    COUNT(DISTINCT container_id) as affected_containers
FROM drift_events
WHERE detected_at > NOW() - INTERVAL '24 hours'
GROUP BY org_id, drift_type, severity
ORDER BY event_count DESC;

-- Recent behavioral anomalies (last 24 hours)
CREATE VIEW v_recent_anomalies AS
SELECT
    org_id,
    anomaly_type,
    severity,
    COUNT(*) as anomaly_count,
    COUNT(CASE WHEN NOT resolved THEN 1 END) as unresolved_count,
    MAX(detected_at) as last_detected_at,
    COUNT(DISTINCT container_id) as affected_containers,
    SUM(occurrence_count) as total_occurrences
FROM behavioral_anomalies
WHERE detected_at > NOW() - INTERVAL '24 hours'
GROUP BY org_id, anomaly_type, severity
ORDER BY anomaly_count DESC;

-- Drift summary per container
CREATE VIEW v_container_drift_summary AS
SELECT
    org_id,
    container_id,
    container_name,
    COUNT(*) as total_drift_events,
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_events,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_events,
    COUNT(CASE WHEN NOT resolved THEN 1 END) as unresolved_events,
    MAX(detected_at) as last_drift_at,
    array_agg(DISTINCT drift_type) as drift_types
FROM drift_events
WHERE detected_at > NOW() - INTERVAL '7 days'
GROUP BY org_id, container_id, container_name
ORDER BY critical_events DESC, high_events DESC;

-- Runtime security posture
CREATE VIEW v_runtime_security_posture AS
SELECT
    de.org_id,
    COUNT(DISTINCT CASE WHEN de.detected_at > NOW() - INTERVAL '24 hours' THEN de.id END) as drift_events_24h,
    COUNT(DISTINCT CASE WHEN ba.detected_at > NOW() - INTERVAL '24 hours' THEN ba.id END) as anomalies_24h,
    COUNT(DISTINCT CASE WHEN de.severity = 'critical' AND NOT de.resolved THEN de.id END) as critical_drift_unresolved,
    COUNT(DISTINCT CASE WHEN de.severity = 'high' AND NOT de.resolved THEN de.id END) as high_drift_unresolved,
    COUNT(DISTINCT CASE WHEN ba.severity = 'critical' AND NOT ba.resolved THEN ba.id END) as critical_anomalies_unresolved,
    COUNT(DISTINCT de.container_id) as containers_with_drift,
    MAX(GREATEST(de.detected_at, ba.detected_at)) as last_event_at,
    CASE
        WHEN COUNT(CASE WHEN de.severity = 'critical' AND NOT de.resolved THEN 1 END) > 0 THEN 'critical'
        WHEN COUNT(CASE WHEN de.severity = 'high' AND NOT de.resolved THEN 1 END) > 0 THEN 'warning'
        WHEN COUNT(CASE WHEN NOT de.resolved THEN 1 END) > 0 THEN 'degraded'
        ELSE 'healthy'
    END as overall_status
FROM drift_events de
FULL OUTER JOIN behavioral_anomalies ba ON de.org_id = ba.org_id
GROUP BY de.org_id;

-- ============================================================================
-- Functions
-- ============================================================================

-- Initialize runtime security config for new organization
CREATE OR REPLACE FUNCTION initialize_runtime_security_config(p_org_id UUID)
RETURNS UUID AS $$
DECLARE
    v_config_id UUID;
BEGIN
    INSERT INTO runtime_security_config (
        org_id,
        drift_detection_enabled,
        drift_scan_interval_seconds,
        detect_image_changes,
        detect_port_changes,
        detect_privilege_escalation,
        detect_config_changes,
        detect_volume_changes,
        detect_network_changes,
        behavioral_monitoring_enabled,
        crash_loop_threshold,
        crash_loop_window_minutes,
        log_spike_multiplier,
        log_spike_window_minutes,
        error_rate_threshold,
        error_rate_window_minutes,
        cpu_exhaustion_threshold,
        memory_exhaustion_threshold,
        disk_exhaustion_threshold,
        alert_on_critical_drift,
        alert_on_high_drift,
        alert_on_anomalies,
        auto_resolve_info_drift,
        auto_resolve_after_hours
    ) VALUES (
        p_org_id,
        TRUE,  -- Drift detection enabled
        60,    -- Scan every 60 seconds
        TRUE,  -- Detect image changes
        TRUE,  -- Detect port changes
        TRUE,  -- Detect privilege escalation
        TRUE,  -- Detect config changes
        TRUE,  -- Detect volume changes
        TRUE,  -- Detect network changes
        TRUE,  -- Behavioral monitoring enabled
        3,     -- 3 restarts = crash loop
        5,     -- Within 5 minutes
        10.0,  -- 10x log volume
        5,     -- Within 5 minutes
        50.0,  -- 50% error rate
        5,     -- Within 5 minutes
        90.0,  -- 90% CPU
        90.0,  -- 90% memory
        90.0,  -- 90% disk
        TRUE,  -- Alert on critical drift
        TRUE,  -- Alert on high drift
        TRUE,  -- Alert on anomalies
        TRUE,  -- Auto-resolve info drift
        24     -- Auto-resolve after 24 hours
    )
    ON CONFLICT (org_id) DO NOTHING
    RETURNING id INTO v_config_id;

    RETURN v_config_id;
END;
$$ LANGUAGE plpgsql;

-- Trigger to initialize runtime config for new organizations
CREATE OR REPLACE FUNCTION trigger_initialize_runtime_config()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM initialize_runtime_security_config(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_org_runtime_security_init
    AFTER INSERT ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION trigger_initialize_runtime_config();

-- Record drift event
CREATE OR REPLACE FUNCTION record_drift_event(
    p_org_id UUID,
    p_agent_id UUID,
    p_deployment_id UUID,
    p_container_id VARCHAR,
    p_container_name VARCHAR,
    p_drift_type drift_type,
    p_severity drift_severity,
    p_description TEXT,
    p_expected_state JSONB,
    p_actual_state JSONB,
    p_diff JSONB DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_drift_id UUID;
    v_config RECORD;
BEGIN
    -- Get runtime security config
    SELECT * INTO v_config
    FROM runtime_security_config
    WHERE org_id = p_org_id;

    -- Check if drift detection is enabled
    IF NOT v_config.drift_detection_enabled THEN
        RETURN NULL;
    END IF;

    -- Insert drift event
    INSERT INTO drift_events (
        org_id,
        agent_id,
        deployment_id,
        container_id,
        container_name,
        drift_type,
        severity,
        description,
        expected_state,
        actual_state,
        diff,
        detection_method
    ) VALUES (
        p_org_id,
        p_agent_id,
        p_deployment_id,
        p_container_id,
        p_container_name,
        p_drift_type,
        p_severity,
        p_description,
        p_expected_state,
        p_actual_state,
        p_diff,
        'periodic_scan'
    ) RETURNING id INTO v_drift_id;

    -- Log to platform security audit
    PERFORM log_platform_security_event(
        p_org_id,
        'drift_detected',
        'runtime_security',
        p_severity::VARCHAR,
        NULL, -- No user (system detected)
        NULL,
        NULL,
        'drift_detection',
        format('Drift detected: %s - %s', p_drift_type, p_description),
        p_expected_state,
        p_actual_state,
        jsonb_build_object(
            'drift_id', v_drift_id,
            'container_id', p_container_id,
            'drift_type', p_drift_type
        )
    );

    RETURN v_drift_id;
END;
$$ LANGUAGE plpgsql;

-- Record behavioral anomaly
CREATE OR REPLACE FUNCTION record_behavioral_anomaly(
    p_org_id UUID,
    p_agent_id UUID,
    p_deployment_id UUID,
    p_container_id VARCHAR,
    p_container_name VARCHAR,
    p_anomaly_type anomaly_type,
    p_severity drift_severity,
    p_description TEXT,
    p_baseline_value NUMERIC,
    p_observed_value NUMERIC,
    p_threshold_value NUMERIC,
    p_metric_name VARCHAR DEFAULT NULL,
    p_evidence JSONB DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_anomaly_id UUID;
    v_existing_id UUID;
    v_config RECORD;
BEGIN
    -- Get runtime security config
    SELECT * INTO v_config
    FROM runtime_security_config
    WHERE org_id = p_org_id;

    -- Check if behavioral monitoring is enabled
    IF NOT v_config.behavioral_monitoring_enabled THEN
        RETURN NULL;
    END IF;

    -- Check for existing unresolved anomaly of same type for same container
    SELECT id INTO v_existing_id
    FROM behavioral_anomalies
    WHERE org_id = p_org_id
      AND container_id = p_container_id
      AND anomaly_type = p_anomaly_type
      AND NOT resolved
      AND detected_at > NOW() - INTERVAL '1 hour'
    ORDER BY detected_at DESC
    LIMIT 1;

    IF v_existing_id IS NOT NULL THEN
        -- Update existing anomaly
        UPDATE behavioral_anomalies
        SET occurrence_count = occurrence_count + 1,
            last_observed_at = NOW(),
            observed_value = p_observed_value,
            evidence = p_evidence,
            updated_at = NOW()
        WHERE id = v_existing_id;

        RETURN v_existing_id;
    ELSE
        -- Insert new anomaly
        INSERT INTO behavioral_anomalies (
            org_id,
            agent_id,
            deployment_id,
            container_id,
            container_name,
            anomaly_type,
            severity,
            description,
            baseline_value,
            observed_value,
            threshold_value,
            metric_name,
            evidence,
            first_observed_at,
            last_observed_at
        ) VALUES (
            p_org_id,
            p_agent_id,
            p_deployment_id,
            p_container_id,
            p_container_name,
            p_anomaly_type,
            p_severity,
            p_description,
            p_baseline_value,
            p_observed_value,
            p_threshold_value,
            p_metric_name,
            p_evidence,
            NOW(),
            NOW()
        ) RETURNING id INTO v_anomaly_id;

        RETURN v_anomaly_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Auto-resolve old info-level drift events
CREATE OR REPLACE FUNCTION auto_resolve_old_drift()
RETURNS INTEGER AS $$
DECLARE
    v_resolved_count INTEGER;
BEGIN
    UPDATE drift_events
    SET resolved = TRUE,
        auto_resolved = TRUE,
        auto_resolution_reason = 'Auto-resolved: low severity and old',
        resolved_at = NOW(),
        updated_at = NOW()
    WHERE NOT resolved
      AND severity = 'info'
      AND detected_at < NOW() - INTERVAL '24 hours';

    GET DIAGNOSTICS v_resolved_count = ROW_COUNT;

    RETURN v_resolved_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE drift_events IS 'Runtime drift events detected by comparing expected vs actual container state';
COMMENT ON TABLE behavioral_anomalies IS 'Behavioral anomalies detected from metrics and logs (crash loops, resource exhaustion, etc.)';
COMMENT ON TABLE runtime_security_config IS 'Configuration for drift detection and behavioral monitoring per organization';
COMMENT ON TABLE expected_container_state IS 'Expected container configuration snapshot taken at deployment time';

COMMENT ON VIEW v_recent_drift_events IS 'Summary of drift events in last 24 hours by type and severity';
COMMENT ON VIEW v_recent_anomalies IS 'Summary of behavioral anomalies in last 24 hours';
COMMENT ON VIEW v_container_drift_summary IS 'Per-container drift summary for last 7 days';
COMMENT ON VIEW v_runtime_security_posture IS 'Overall runtime security posture with drift and anomaly counts';

COMMENT ON FUNCTION record_drift_event IS 'Record a detected drift event with full context and audit trail';
COMMENT ON FUNCTION record_behavioral_anomaly IS 'Record a behavioral anomaly, deduplicating recent occurrences';
COMMENT ON FUNCTION auto_resolve_old_drift IS 'Auto-resolve info-level drift events older than 24 hours';
