-- Migration: 014_risk_exceptions
-- Description: Risk acceptance and exception management with governance
-- Epic 9: Risk Acceptance & Exception Management

-- ============ Enums ============

-- Exception status
CREATE TYPE exception_status AS ENUM ('pending', 'approved', 'denied', 'expired', 'revoked');

-- Exception scope type
CREATE TYPE exception_scope_type AS ENUM ('cve', 'policy_rule', 'deployment', 'package', 'image');

-- ============ Risk Exceptions Table ============

CREATE TABLE risk_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Scope of the exception
    scope_type exception_scope_type NOT NULL,
    scope_reference VARCHAR(255) NOT NULL,  -- CVE-ID, policy name, deployment ID, etc.

    -- Optional: Link to specific deployment or scan
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    scan_result_id UUID REFERENCES scan_results(id) ON DELETE SET NULL,

    -- Request details
    requested_by UUID NOT NULL REFERENCES users(id),
    justification TEXT NOT NULL,
    business_impact TEXT,  -- Why this exception is needed
    mitigation_plan TEXT,  -- Compensating controls or mitigation steps

    -- Approval workflow
    status exception_status NOT NULL DEFAULT 'pending',
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    denial_reason TEXT,

    -- Time-boxing
    expires_at TIMESTAMPTZ NOT NULL,
    auto_renewed BOOLEAN NOT NULL DEFAULT FALSE,
    renewal_count INTEGER NOT NULL DEFAULT 0,

    -- Revocation
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id),
    revoked_reason TEXT,

    -- Metadata
    metadata JSONB,  -- Store additional context (severity, affected services, etc.)
    tags VARCHAR(50)[],  -- For categorization: 'legacy', 'temporary', 'critical-business', etc.

    -- Audit trail
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Exception History Table ============

CREATE TABLE exception_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exception_id UUID NOT NULL REFERENCES risk_exceptions(id) ON DELETE CASCADE,

    -- Change tracking
    action VARCHAR(50) NOT NULL,  -- 'created', 'approved', 'denied', 'expired', 'revoked', 'renewed'
    actor_id UUID REFERENCES users(id),
    previous_status exception_status,
    new_status exception_status,

    -- Details
    comment TEXT,
    metadata JSONB,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Exception Templates Table ============

CREATE TABLE exception_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Template identification
    name VARCHAR(100) NOT NULL,
    scope_type exception_scope_type NOT NULL,

    -- Pre-filled content
    justification_template TEXT,
    mitigation_template TEXT,

    -- Auto-approval settings
    auto_approve BOOLEAN NOT NULL DEFAULT FALSE,
    auto_approve_duration_days INTEGER,  -- Max duration for auto-approval
    auto_approve_severity VARCHAR(20)[],  -- e.g., ['low', 'medium']

    -- Configuration
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    default_duration_days INTEGER NOT NULL DEFAULT 30,
    max_duration_days INTEGER NOT NULL DEFAULT 90,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, scope_type, name)
);

-- ============ Indexes ============

-- Risk exceptions indexes
CREATE INDEX idx_risk_exceptions_org ON risk_exceptions(org_id);
CREATE INDEX idx_risk_exceptions_scope ON risk_exceptions(scope_type, scope_reference);
CREATE INDEX idx_risk_exceptions_status ON risk_exceptions(status);
CREATE INDEX idx_risk_exceptions_expires ON risk_exceptions(expires_at);
CREATE INDEX idx_risk_exceptions_deployment ON risk_exceptions(deployment_id) WHERE deployment_id IS NOT NULL;
CREATE INDEX idx_risk_exceptions_requester ON risk_exceptions(requested_by);
CREATE INDEX idx_risk_exceptions_approver ON risk_exceptions(approved_by) WHERE approved_by IS NOT NULL;
CREATE INDEX idx_risk_exceptions_tags ON risk_exceptions USING GIN(tags);

-- Exception history indexes
CREATE INDEX idx_exception_history_exception ON exception_history(exception_id);
CREATE INDEX idx_exception_history_created ON exception_history(created_at DESC);

-- Exception templates indexes
CREATE INDEX idx_exception_templates_org ON exception_templates(org_id);
CREATE INDEX idx_exception_templates_scope ON exception_templates(scope_type);

-- ============ Functions ============

-- Update timestamp function
CREATE OR REPLACE FUNCTION update_risk_exception_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for risk_exceptions
CREATE TRIGGER risk_exceptions_updated
    BEFORE UPDATE ON risk_exceptions
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_exception_timestamp();

-- Trigger for exception_templates
CREATE TRIGGER exception_templates_updated
    BEFORE UPDATE ON exception_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_risk_exception_timestamp();

-- Function to record exception history
CREATE OR REPLACE FUNCTION record_exception_history()
RETURNS TRIGGER AS $$
BEGIN
    -- Only record on status change or revocation
    IF (TG_OP = 'INSERT') THEN
        INSERT INTO exception_history (exception_id, action, actor_id, new_status, comment)
        VALUES (NEW.id, 'created', NEW.requested_by, NEW.status, 'Exception request created');
    ELSIF (TG_OP = 'UPDATE') THEN
        IF (OLD.status != NEW.status) THEN
            INSERT INTO exception_history (exception_id, action, actor_id, previous_status, new_status)
            VALUES (
                NEW.id,
                CASE
                    WHEN NEW.status = 'approved' THEN 'approved'
                    WHEN NEW.status = 'denied' THEN 'denied'
                    WHEN NEW.status = 'expired' THEN 'expired'
                    WHEN NEW.status = 'revoked' THEN 'revoked'
                    ELSE 'status_changed'
                END,
                CASE
                    WHEN NEW.status = 'approved' THEN NEW.approved_by
                    WHEN NEW.status = 'revoked' THEN NEW.revoked_by
                    ELSE NULL
                END,
                OLD.status,
                NEW.status
            );
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-record history
CREATE TRIGGER exception_history_trigger
    AFTER INSERT OR UPDATE ON risk_exceptions
    FOR EACH ROW
    EXECUTE FUNCTION record_exception_history();

-- Function to expire old exceptions (run via cron)
CREATE OR REPLACE FUNCTION expire_old_exceptions()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE risk_exceptions
    SET status = 'expired',
        updated_at = NOW()
    WHERE status = 'approved'
      AND expires_at < NOW()
      AND auto_renewed = FALSE;

    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- ============ Comments ============

COMMENT ON TABLE risk_exceptions IS 'Time-boxed security exceptions with approval workflow';
COMMENT ON TABLE exception_history IS 'Audit trail for all exception lifecycle events';
COMMENT ON TABLE exception_templates IS 'Templates for common exception scenarios with auto-approval rules';

COMMENT ON COLUMN risk_exceptions.scope_reference IS 'The entity being excepted: CVE-2024-1234, deployment UUID, policy name, etc.';
COMMENT ON COLUMN risk_exceptions.justification IS 'Business justification for the exception';
COMMENT ON COLUMN risk_exceptions.mitigation_plan IS 'Compensating controls or mitigation steps';
COMMENT ON COLUMN risk_exceptions.expires_at IS 'Auto-expire at this timestamp (enforced by cron job)';
COMMENT ON COLUMN risk_exceptions.metadata IS 'Additional context: severity, affected services, CVSS score, etc.';

COMMENT ON FUNCTION expire_old_exceptions() IS 'Cron job function to automatically expire approved exceptions past their expiry date';

-- ============ Seed Default Templates ============

-- Insert default CVE exception template
INSERT INTO exception_templates (org_id, name, scope_type, justification_template, mitigation_template, default_duration_days, max_duration_days)
SELECT
    id,
    'default-cve',
    'cve',
    E'This CVE requires an exception for the following business reason:\n\n[Explain business impact and why immediate remediation is not possible]\n\n',
    E'Compensating controls in place:\n\n1. [List any mitigating factors]\n2. [Network isolation, restricted access, etc.]\n3. [Monitoring and detection measures]\n\nRemediation timeline: [Expected fix date]',
    30,
    90
FROM organizations
WHERE NOT EXISTS (
    SELECT 1 FROM exception_templates
    WHERE scope_type = 'cve' AND name = 'default-cve'
);

-- Insert default policy exception template
INSERT INTO exception_templates (org_id, name, scope_type, justification_template, mitigation_template, default_duration_days, max_duration_days)
SELECT
    id,
    'default-policy',
    'policy_rule',
    E'This policy exception is needed for:\n\n[Business justification]\n\nWhy policy cannot be met:\n[Technical or business constraints]\n\n',
    E'Alternative security measures:\n\n1. [List compensating controls]\n2. [Risk mitigation steps]\n3. [Monitoring plan]\n\nPolicy compliance timeline: [Expected compliance date]',
    14,
    60
FROM organizations
WHERE NOT EXISTS (
    SELECT 1 FROM exception_templates
    WHERE scope_type = 'policy_rule' AND name = 'default-policy'
);

-- Insert legacy system template with auto-approval
INSERT INTO exception_templates (org_id, name, scope_type, justification_template, mitigation_template, auto_approve, auto_approve_duration_days, auto_approve_severity, default_duration_days, max_duration_days)
SELECT
    id,
    'legacy-system',
    'deployment',
    E'This is a legacy system that cannot be immediately updated.\n\n[System description and business criticality]\n\n',
    E'Legacy system risk mitigation:\n\n1. Network segmentation and restricted access\n2. Enhanced monitoring and logging\n3. Compensating security controls\n4. Scheduled deprecation/replacement timeline',
    TRUE,
    90,
    ARRAY['low', 'medium'],
    90,
    365
FROM organizations
WHERE NOT EXISTS (
    SELECT 1 FROM exception_templates
    WHERE scope_type = 'deployment' AND name = 'legacy-system'
);
