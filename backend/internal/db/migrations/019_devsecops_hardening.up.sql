-- Migration 019: DevSecOps Hardening (Epic 6)
-- Adds platform security features: secure defaults, self-protection policies, threat model

-- ============================================================================
-- Platform Security Configuration
-- ============================================================================

-- Configuration table for platform-wide security settings
CREATE TABLE platform_security_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Secure Defaults
    mfa_required_for_admins BOOLEAN NOT NULL DEFAULT TRUE,
    docker_socket_read_only BOOLEAN NOT NULL DEFAULT TRUE,
    tls_only BOOLEAN NOT NULL DEFAULT TRUE,
    min_password_length INTEGER NOT NULL DEFAULT 12,
    password_require_uppercase BOOLEAN NOT NULL DEFAULT TRUE,
    password_require_lowercase BOOLEAN NOT NULL DEFAULT TRUE,
    password_require_numbers BOOLEAN NOT NULL DEFAULT TRUE,
    password_require_special BOOLEAN NOT NULL DEFAULT TRUE,
    session_timeout_minutes INTEGER NOT NULL DEFAULT 30,
    audit_logging_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    audit_logging_immutable BOOLEAN NOT NULL DEFAULT TRUE, -- Cannot be disabled

    -- Self-Protection Policies
    block_privileged_containers BOOLEAN NOT NULL DEFAULT TRUE,
    block_docker_socket_mounts BOOLEAN NOT NULL DEFAULT TRUE,
    block_docker_api_exposure BOOLEAN NOT NULL DEFAULT TRUE,
    block_root_containers BOOLEAN NOT NULL DEFAULT TRUE,
    block_host_network BOOLEAN NOT NULL DEFAULT TRUE,
    block_host_pid BOOLEAN NOT NULL DEFAULT TRUE,
    block_host_ipc BOOLEAN NOT NULL DEFAULT TRUE,
    block_capability_additions BOOLEAN NOT NULL DEFAULT TRUE,

    -- Threat Detection
    track_violation_attempts BOOLEAN NOT NULL DEFAULT TRUE,
    alert_on_violations BOOLEAN NOT NULL DEFAULT TRUE,
    max_violations_before_lockout INTEGER DEFAULT 10,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(org_id)
);

-- Indexes for security config
CREATE INDEX idx_platform_security_config_org ON platform_security_config(org_id);

-- ============================================================================
-- Self-Protection Policy Violations
-- ============================================================================

-- Track attempts to violate self-protection policies
CREATE TABLE policy_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Violation details
    violation_type VARCHAR(100) NOT NULL, -- privileged_container, docker_socket_mount, etc.
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),

    -- Context
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    ip_address INET,
    user_agent TEXT,

    -- What was attempted
    attempted_action VARCHAR(255) NOT NULL,
    blocked BOOLEAN NOT NULL DEFAULT TRUE,
    policy_rule TEXT, -- The policy rule that blocked it

    -- Details
    description TEXT NOT NULL,
    request_payload JSONB,

    -- Resolution
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for policy violations
CREATE INDEX idx_policy_violations_org ON policy_violations(org_id);
CREATE INDEX idx_policy_violations_user ON policy_violations(user_id);
CREATE INDEX idx_policy_violations_type ON policy_violations(violation_type);
CREATE INDEX idx_policy_violations_severity ON policy_violations(severity);
CREATE INDEX idx_policy_violations_blocked ON policy_violations(blocked);
CREATE INDEX idx_policy_violations_acknowledged ON policy_violations(acknowledged);
CREATE INDEX idx_policy_violations_created ON policy_violations(created_at DESC);

-- ============================================================================
-- Platform Security Audit Log
-- ============================================================================

-- Immutable audit log for platform security events
CREATE TABLE platform_security_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Event information
    event_type VARCHAR(100) NOT NULL, -- config_change, policy_update, violation_attempt, etc.
    event_category VARCHAR(50) NOT NULL, -- authentication, authorization, configuration, policy
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),

    -- Actor
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    ip_address INET,
    user_agent TEXT,

    -- Action
    action VARCHAR(255) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,

    -- Details
    description TEXT NOT NULL,
    old_value JSONB,
    new_value JSONB,
    metadata JSONB,

    -- Immutability
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    -- Note: No updated_at - audit logs are immutable
);

-- Indexes for security audit
CREATE INDEX idx_platform_security_audit_org ON platform_security_audit(org_id);
CREATE INDEX idx_platform_security_audit_user ON platform_security_audit(user_id);
CREATE INDEX idx_platform_security_audit_event_type ON platform_security_audit(event_type);
CREATE INDEX idx_platform_security_audit_event_category ON platform_security_audit(event_category);
CREATE INDEX idx_platform_security_audit_severity ON platform_security_audit(severity);
CREATE INDEX idx_platform_security_audit_created ON platform_security_audit(created_at DESC);

-- ============================================================================
-- Platform Security Self-Check
-- ============================================================================

-- Self-check results for platform security posture
CREATE TABLE platform_security_checks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Check metadata
    check_type VARCHAR(100) NOT NULL, -- secure_defaults, self_protection, tls_config, etc.
    check_name VARCHAR(255) NOT NULL,
    check_description TEXT,

    -- Result
    status VARCHAR(20) NOT NULL CHECK (status IN ('pass', 'fail', 'warning', 'info')),
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),

    -- Details
    message TEXT NOT NULL,
    recommendation TEXT,
    remediation_steps TEXT,

    -- Evidence
    evidence JSONB,

    -- Metadata
    check_duration_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for security checks
CREATE INDEX idx_platform_security_checks_org ON platform_security_checks(org_id);
CREATE INDEX idx_platform_security_checks_type ON platform_security_checks(check_type);
CREATE INDEX idx_platform_security_checks_status ON platform_security_checks(status);
CREATE INDEX idx_platform_security_checks_severity ON platform_security_checks(severity);
CREATE INDEX idx_platform_security_checks_created ON platform_security_checks(created_at DESC);

-- ============================================================================
-- Views
-- ============================================================================

-- Latest security posture per organization
CREATE VIEW v_platform_security_posture AS
SELECT
    org_id,
    COUNT(*) as total_checks,
    COUNT(CASE WHEN status = 'pass' THEN 1 END) as passed_checks,
    COUNT(CASE WHEN status = 'fail' THEN 1 END) as failed_checks,
    COUNT(CASE WHEN status = 'warning' THEN 1 END) as warning_checks,
    COUNT(CASE WHEN severity = 'critical' AND status = 'fail' THEN 1 END) as critical_failures,
    COUNT(CASE WHEN severity = 'high' AND status = 'fail' THEN 1 END) as high_failures,
    MAX(created_at) as last_check_at,
    -- Overall status (fail if any critical failures, warning if any high failures, else pass)
    CASE
        WHEN COUNT(CASE WHEN severity = 'critical' AND status = 'fail' THEN 1 END) > 0 THEN 'critical'
        WHEN COUNT(CASE WHEN severity = 'high' AND status = 'fail' THEN 1 END) > 0 THEN 'warning'
        WHEN COUNT(CASE WHEN status = 'fail' THEN 1 END) > 0 THEN 'degraded'
        ELSE 'healthy'
    END as overall_status
FROM platform_security_checks
WHERE created_at > NOW() - INTERVAL '1 hour'  -- Last hour's checks
GROUP BY org_id;

-- Recent policy violations summary
CREATE VIEW v_recent_policy_violations AS
SELECT
    org_id,
    violation_type,
    COUNT(*) as violation_count,
    COUNT(CASE WHEN blocked THEN 1 END) as blocked_count,
    COUNT(CASE WHEN NOT blocked THEN 1 END) as allowed_count,
    MAX(severity) as max_severity,
    MAX(created_at) as last_violation_at,
    COUNT(DISTINCT user_id) as unique_users
FROM policy_violations
WHERE created_at > NOW() - INTERVAL '24 hours'  -- Last 24 hours
GROUP BY org_id, violation_type
ORDER BY violation_count DESC;

-- Security audit summary
CREATE VIEW v_security_audit_summary AS
SELECT
    org_id,
    event_category,
    event_type,
    COUNT(*) as event_count,
    COUNT(CASE WHEN severity IN ('critical', 'high') THEN 1 END) as high_severity_count,
    MAX(severity) as max_severity,
    MAX(created_at) as last_event_at,
    COUNT(DISTINCT user_id) as unique_users
FROM platform_security_audit
WHERE created_at > NOW() - INTERVAL '7 days'  -- Last 7 days
GROUP BY org_id, event_category, event_type
ORDER BY event_count DESC;

-- ============================================================================
-- Functions
-- ============================================================================

-- Initialize platform security config for a new organization
CREATE OR REPLACE FUNCTION initialize_platform_security_config(p_org_id UUID)
RETURNS UUID AS $$
DECLARE
    v_config_id UUID;
BEGIN
    INSERT INTO platform_security_config (
        org_id,
        mfa_required_for_admins,
        docker_socket_read_only,
        tls_only,
        min_password_length,
        password_require_uppercase,
        password_require_lowercase,
        password_require_numbers,
        password_require_special,
        session_timeout_minutes,
        audit_logging_enabled,
        audit_logging_immutable,
        block_privileged_containers,
        block_docker_socket_mounts,
        block_docker_api_exposure,
        block_root_containers,
        block_host_network,
        block_host_pid,
        block_host_ipc,
        block_capability_additions,
        track_violation_attempts,
        alert_on_violations,
        max_violations_before_lockout
    ) VALUES (
        p_org_id,
        TRUE,  -- MFA required
        TRUE,  -- Docker socket read-only
        TRUE,  -- TLS only
        12,    -- Min password length
        TRUE,  -- Require uppercase
        TRUE,  -- Require lowercase
        TRUE,  -- Require numbers
        TRUE,  -- Require special chars
        30,    -- Session timeout 30 minutes
        TRUE,  -- Audit logging enabled
        TRUE,  -- Audit logging immutable
        TRUE,  -- Block privileged containers
        TRUE,  -- Block Docker socket mounts
        TRUE,  -- Block Docker API exposure
        TRUE,  -- Block root containers
        TRUE,  -- Block host network
        TRUE,  -- Block host PID
        TRUE,  -- Block host IPC
        TRUE,  -- Block capability additions
        TRUE,  -- Track violations
        TRUE,  -- Alert on violations
        10     -- Max violations before lockout
    )
    ON CONFLICT (org_id) DO NOTHING
    RETURNING id INTO v_config_id;

    RETURN v_config_id;
END;
$$ LANGUAGE plpgsql;

-- Log a platform security event (audit)
CREATE OR REPLACE FUNCTION log_platform_security_event(
    p_org_id UUID,
    p_event_type VARCHAR,
    p_event_category VARCHAR,
    p_severity VARCHAR,
    p_user_id UUID,
    p_user_email VARCHAR,
    p_ip_address INET,
    p_action VARCHAR,
    p_description TEXT,
    p_old_value JSONB DEFAULT NULL,
    p_new_value JSONB DEFAULT NULL,
    p_metadata JSONB DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_audit_id UUID;
BEGIN
    INSERT INTO platform_security_audit (
        org_id,
        event_type,
        event_category,
        severity,
        user_id,
        user_email,
        ip_address,
        action,
        description,
        old_value,
        new_value,
        metadata
    ) VALUES (
        p_org_id,
        p_event_type,
        p_event_category,
        p_severity,
        p_user_id,
        p_user_email,
        p_ip_address,
        p_action,
        p_description,
        p_old_value,
        p_new_value,
        p_metadata
    ) RETURNING id INTO v_audit_id;

    RETURN v_audit_id;
END;
$$ LANGUAGE plpgsql;

-- Record a policy violation
CREATE OR REPLACE FUNCTION record_policy_violation(
    p_org_id UUID,
    p_violation_type VARCHAR,
    p_severity VARCHAR,
    p_user_id UUID,
    p_user_email VARCHAR,
    p_ip_address INET,
    p_attempted_action VARCHAR,
    p_blocked BOOLEAN,
    p_policy_rule TEXT,
    p_description TEXT,
    p_request_payload JSONB DEFAULT NULL
)
RETURNS UUID AS $$
DECLARE
    v_violation_id UUID;
    v_config RECORD;
BEGIN
    -- Get security config
    SELECT * INTO v_config
    FROM platform_security_config
    WHERE org_id = p_org_id;

    -- Record violation if tracking is enabled
    IF v_config.track_violation_attempts THEN
        INSERT INTO policy_violations (
            org_id,
            violation_type,
            severity,
            user_id,
            user_email,
            ip_address,
            attempted_action,
            blocked,
            policy_rule,
            description,
            request_payload
        ) VALUES (
            p_org_id,
            p_violation_type,
            p_severity,
            p_user_id,
            p_user_email,
            p_ip_address,
            p_attempted_action,
            p_blocked,
            p_policy_rule,
            p_description,
            p_request_payload
        ) RETURNING id INTO v_violation_id;

        -- Also log to audit trail
        PERFORM log_platform_security_event(
            p_org_id,
            'policy_violation',
            'policy',
            p_severity,
            p_user_id,
            p_user_email,
            p_ip_address,
            p_attempted_action,
            p_description,
            NULL,
            jsonb_build_object(
                'violation_type', p_violation_type,
                'blocked', p_blocked,
                'policy_rule', p_policy_rule
            ),
            p_request_payload
        );
    END IF;

    RETURN v_violation_id;
END;
$$ LANGUAGE plpgsql;

-- Run platform security self-check
CREATE OR REPLACE FUNCTION run_platform_security_selfcheck(p_org_id UUID)
RETURNS TABLE (
    check_name VARCHAR,
    status VARCHAR,
    severity VARCHAR,
    message TEXT,
    recommendation TEXT
) AS $$
DECLARE
    v_config RECORD;
    v_check_id UUID;
BEGIN
    -- Get security config
    SELECT * INTO v_config
    FROM platform_security_config
    WHERE org_id = p_org_id;

    IF NOT FOUND THEN
        -- Initialize if missing
        PERFORM initialize_platform_security_config(p_org_id);
        SELECT * INTO v_config FROM platform_security_config WHERE org_id = p_org_id;
    END IF;

    -- Clear old checks (keep last 24 hours)
    DELETE FROM platform_security_checks
    WHERE org_id = p_org_id AND created_at < NOW() - INTERVAL '24 hours';

    -- Check: MFA for admins
    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'secure_defaults',
        'MFA Required for Admins',
        'Verifies that multi-factor authentication is required for administrator accounts',
        CASE WHEN v_config.mfa_required_for_admins THEN 'pass' ELSE 'fail' END,
        'high',
        CASE WHEN v_config.mfa_required_for_admins THEN 'MFA is required for all admin accounts' ELSE 'MFA is not required - admins can access without 2FA' END,
        CASE WHEN v_config.mfa_required_for_admins THEN NULL ELSE 'Enable MFA requirement in platform security settings' END
    );

    -- Check: Docker socket read-only
    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'secure_defaults',
        'Docker Socket Read-Only',
        'Ensures Docker socket is mounted read-only to prevent privilege escalation',
        CASE WHEN v_config.docker_socket_read_only THEN 'pass' ELSE 'fail' END,
        'critical',
        CASE WHEN v_config.docker_socket_read_only THEN 'Docker socket is enforced as read-only' ELSE 'Docker socket can be mounted writable - critical security risk' END,
        CASE WHEN v_config.docker_socket_read_only THEN NULL ELSE 'Enable read-only Docker socket enforcement immediately' END
    );

    -- Check: TLS only
    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'secure_defaults',
        'TLS-Only Access',
        'Verifies that all API access requires TLS encryption',
        CASE WHEN v_config.tls_only THEN 'pass' ELSE 'fail' END,
        'high',
        CASE WHEN v_config.tls_only THEN 'TLS is required for all API access' ELSE 'Unencrypted HTTP access is allowed' END,
        CASE WHEN v_config.tls_only THEN NULL ELSE 'Enable TLS-only mode and configure valid certificates' END
    );

    -- Check: Password complexity
    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'secure_defaults',
        'Password Complexity',
        'Ensures strong password requirements are enforced',
        CASE WHEN v_config.min_password_length >= 12 AND
                  v_config.password_require_uppercase AND
                  v_config.password_require_lowercase AND
                  v_config.password_require_numbers AND
                  v_config.password_require_special
             THEN 'pass' ELSE 'warning' END,
        'medium',
        format('Password requirements: min length %s, uppercase %s, lowercase %s, numbers %s, special chars %s',
            v_config.min_password_length,
            CASE WHEN v_config.password_require_uppercase THEN '✓' ELSE '✗' END,
            CASE WHEN v_config.password_require_lowercase THEN '✓' ELSE '✗' END,
            CASE WHEN v_config.password_require_numbers THEN '✓' ELSE '✗' END,
            CASE WHEN v_config.password_require_special THEN '✓' ELSE '✗' END
        ),
        CASE WHEN v_config.min_password_length >= 12 THEN NULL ELSE 'Increase minimum password length to 12+ characters' END
    );

    -- Check: Session timeout
    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'secure_defaults',
        'Session Timeout',
        'Verifies that user sessions expire after period of inactivity',
        CASE WHEN v_config.session_timeout_minutes <= 30 THEN 'pass' ELSE 'warning' END,
        'low',
        format('Sessions timeout after %s minutes of inactivity', v_config.session_timeout_minutes),
        CASE WHEN v_config.session_timeout_minutes <= 30 THEN NULL ELSE 'Consider reducing session timeout to 30 minutes or less' END
    );

    -- Check: Audit logging
    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'secure_defaults',
        'Audit Logging',
        'Ensures comprehensive audit logging is enabled and immutable',
        CASE WHEN v_config.audit_logging_enabled AND v_config.audit_logging_immutable THEN 'pass' ELSE 'fail' END,
        'critical',
        CASE WHEN v_config.audit_logging_enabled AND v_config.audit_logging_immutable
             THEN 'Audit logging is enabled and immutable'
             ELSE 'Audit logging is disabled or can be modified' END,
        CASE WHEN v_config.audit_logging_enabled THEN NULL ELSE 'Enable immutable audit logging immediately' END
    );

    -- Check: Self-protection policies
    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'self_protection',
        'Privileged Container Blocking',
        'Prevents deployment of privileged containers',
        CASE WHEN v_config.block_privileged_containers THEN 'pass' ELSE 'fail' END,
        'critical',
        CASE WHEN v_config.block_privileged_containers THEN 'Privileged containers are blocked' ELSE 'Privileged containers are allowed - critical risk' END,
        CASE WHEN v_config.block_privileged_containers THEN NULL ELSE 'Enable privileged container blocking' END
    );

    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'self_protection',
        'Docker Socket Mount Protection',
        'Prevents writable Docker socket mounts',
        CASE WHEN v_config.block_docker_socket_mounts THEN 'pass' ELSE 'fail' END,
        'critical',
        CASE WHEN v_config.block_docker_socket_mounts THEN 'Docker socket mounts are blocked' ELSE 'Docker socket can be mounted - allows container escape' END,
        CASE WHEN v_config.block_docker_socket_mounts THEN NULL ELSE 'Enable Docker socket mount blocking' END
    );

    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'self_protection',
        'Docker API Exposure Protection',
        'Prevents exposure of Docker API ports',
        CASE WHEN v_config.block_docker_api_exposure THEN 'pass' ELSE 'fail' END,
        'high',
        CASE WHEN v_config.block_docker_api_exposure THEN 'Docker API ports (2375, 2376) cannot be exposed' ELSE 'Docker API can be exposed publicly' END,
        CASE WHEN v_config.block_docker_api_exposure THEN NULL ELSE 'Enable Docker API exposure blocking' END
    );

    INSERT INTO platform_security_checks (org_id, check_type, check_name, check_description, status, severity, message, recommendation)
    VALUES (
        p_org_id,
        'self_protection',
        'Root Container Blocking',
        'Prevents containers from running as root user',
        CASE WHEN v_config.block_root_containers THEN 'pass' ELSE 'warning' END,
        'medium',
        CASE WHEN v_config.block_root_containers THEN 'Containers must run as non-root users' ELSE 'Containers can run as root' END,
        CASE WHEN v_config.block_root_containers THEN NULL ELSE 'Consider enabling root container blocking' END
    );

    -- Return check results
    RETURN QUERY
    SELECT
        psc.check_name::VARCHAR,
        psc.status::VARCHAR,
        psc.severity::VARCHAR,
        psc.message::TEXT,
        psc.recommendation::TEXT
    FROM platform_security_checks psc
    WHERE psc.org_id = p_org_id
    ORDER BY
        CASE psc.severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END,
        psc.status DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Triggers
-- ============================================================================

-- Trigger to automatically initialize security config for new organizations
CREATE OR REPLACE FUNCTION trigger_initialize_security_config()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM initialize_platform_security_config(NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_org_security_init
    AFTER INSERT ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION trigger_initialize_security_config();

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE platform_security_config IS 'Platform-wide security configuration including secure defaults and self-protection policies';
COMMENT ON TABLE policy_violations IS 'Tracks attempts to violate self-protection policies for threat detection';
COMMENT ON TABLE platform_security_audit IS 'Immutable audit log for all platform security events';
COMMENT ON TABLE platform_security_checks IS 'Results from platform security self-checks';

COMMENT ON VIEW v_platform_security_posture IS 'Overall security posture summary per organization';
COMMENT ON VIEW v_recent_policy_violations IS 'Recent policy violation summary for threat monitoring';
COMMENT ON VIEW v_security_audit_summary IS 'Security audit event summary for compliance reporting';

COMMENT ON FUNCTION initialize_platform_security_config IS 'Initialize secure defaults for a new organization';
COMMENT ON FUNCTION log_platform_security_event IS 'Log an immutable security audit event';
COMMENT ON FUNCTION record_policy_violation IS 'Record a self-protection policy violation with audit trail';
COMMENT ON FUNCTION run_platform_security_selfcheck IS 'Run comprehensive security self-check and return results';
