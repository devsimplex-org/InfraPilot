-- Migration: 013_developer_feedback
-- Description: Developer feedback and shift-left security integration
-- Epic 8: Developer Feedback & Shift-Left Security

-- ============ Enums ============

-- Feedback delivery status
CREATE TYPE feedback_delivery_status AS ENUM ('pending', 'delivered', 'failed', 'skipped');

-- Feedback source type
CREATE TYPE feedback_source_type AS ENUM ('vulnerability', 'policy_violation', 'sbom', 'drift', 'code_quality');

-- VCS provider type
CREATE TYPE vcs_provider AS ENUM ('github', 'gitlab', 'bitbucket', 'azure_devops');

-- ============ Developer Feedback Table ============

CREATE TABLE developer_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Source of the feedback
    source_type feedback_source_type NOT NULL,
    source_id UUID NOT NULL,  -- References vulnerability.id, deployment.id, etc.

    -- VCS Integration
    provider vcs_provider NOT NULL,
    repo_full_name VARCHAR(255) NOT NULL,  -- e.g., "org/repo"

    -- PR/Commit targeting
    pull_request_number INTEGER,
    commit_sha VARCHAR(64),
    branch_name VARCHAR(255),

    -- Feedback content
    severity VARCHAR(20),
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    remediation TEXT,

    -- Metadata
    metadata JSONB,  -- Store additional context (e.g., affected files, line numbers)

    -- Delivery tracking
    delivery_status feedback_delivery_status NOT NULL DEFAULT 'pending',
    delivered_at TIMESTAMPTZ,
    delivery_error TEXT,
    external_id VARCHAR(255),  -- GitHub comment ID, GitLab note ID, etc.

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ VCS Configuration Table ============

CREATE TABLE vcs_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Provider settings
    provider vcs_provider NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Authentication (encrypted)
    auth_type VARCHAR(50) NOT NULL,  -- 'oauth', 'token', 'app'
    credentials_encrypted BYTEA NOT NULL,  -- Encrypted JSON with provider-specific auth

    -- GitHub App specific
    app_id VARCHAR(100),
    installation_id VARCHAR(100),

    -- Configuration
    default_repo VARCHAR(255),
    auto_comment_on_pr BOOLEAN NOT NULL DEFAULT TRUE,
    auto_comment_on_commit BOOLEAN NOT NULL DEFAULT FALSE,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Unique constraint: one config per provider per org
    UNIQUE(org_id, provider)
);

-- ============ Feedback Templates Table ============

CREATE TABLE feedback_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Template identification
    name VARCHAR(100) NOT NULL,
    source_type feedback_source_type NOT NULL,

    -- Template content (Go template syntax)
    title_template TEXT NOT NULL,
    message_template TEXT NOT NULL,
    remediation_template TEXT,

    -- Configuration
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    severity_threshold VARCHAR(20),  -- Only trigger for severity >= threshold

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Unique constraint: one template per source_type per org
    UNIQUE(org_id, source_type, name)
);

-- ============ Indexes ============

-- Developer feedback indexes
CREATE INDEX idx_developer_feedback_org ON developer_feedback(org_id);
CREATE INDEX idx_developer_feedback_source ON developer_feedback(source_type, source_id);
CREATE INDEX idx_developer_feedback_repo ON developer_feedback(repo_full_name);
CREATE INDEX idx_developer_feedback_pr ON developer_feedback(pull_request_number) WHERE pull_request_number IS NOT NULL;
CREATE INDEX idx_developer_feedback_status ON developer_feedback(delivery_status);
CREATE INDEX idx_developer_feedback_created ON developer_feedback(created_at DESC);

-- VCS configurations indexes
CREATE INDEX idx_vcs_configs_org ON vcs_configurations(org_id);
CREATE INDEX idx_vcs_configs_provider ON vcs_configurations(provider);

-- Feedback templates indexes
CREATE INDEX idx_feedback_templates_org ON feedback_templates(org_id);
CREATE INDEX idx_feedback_templates_source ON feedback_templates(source_type);

-- ============ Functions ============

-- Update timestamp function
CREATE OR REPLACE FUNCTION update_developer_feedback_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for developer_feedback
CREATE TRIGGER developer_feedback_updated
    BEFORE UPDATE ON developer_feedback
    FOR EACH ROW
    EXECUTE FUNCTION update_developer_feedback_timestamp();

-- Trigger for vcs_configurations
CREATE TRIGGER vcs_configurations_updated
    BEFORE UPDATE ON vcs_configurations
    FOR EACH ROW
    EXECUTE FUNCTION update_developer_feedback_timestamp();

-- Trigger for feedback_templates
CREATE TRIGGER feedback_templates_updated
    BEFORE UPDATE ON feedback_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_developer_feedback_timestamp();

-- ============ Comments ============

COMMENT ON TABLE developer_feedback IS 'Feedback delivered to developers via VCS (GitHub, GitLab, etc.)';
COMMENT ON TABLE vcs_configurations IS 'VCS provider configurations for delivering feedback';
COMMENT ON TABLE feedback_templates IS 'Customizable templates for generating feedback messages';

COMMENT ON COLUMN developer_feedback.source_id IS 'References the entity that triggered feedback (vulnerability, deployment, etc.)';
COMMENT ON COLUMN developer_feedback.metadata IS 'Additional context: affected files, line numbers, policy rules, etc.';
COMMENT ON COLUMN vcs_configurations.credentials_encrypted IS 'Encrypted JSON containing auth tokens, keys, etc.';
COMMENT ON COLUMN feedback_templates.title_template IS 'Go template for generating feedback title';
COMMENT ON COLUMN feedback_templates.message_template IS 'Go template for generating feedback message body';

-- ============ Seed Default Templates ============

-- Insert default vulnerability feedback template
INSERT INTO feedback_templates (org_id, name, source_type, title_template, message_template, remediation_template, severity_threshold)
SELECT
    id,
    'default-vulnerability',
    'vulnerability',
    '🔒 Security: {{.Severity}} severity vulnerability detected in {{.PackageName}}',
    E'## Security Vulnerability Detected\n\n**CVE:** {{.CVEID}}\n**Severity:** {{.Severity}}\n**Package:** {{.PackageName}}@{{.PackageVersion}}\n\n### Description\n{{.Description}}\n\n### Impact\nThis vulnerability affects {{.AffectedDeployments}} deployment(s) in your infrastructure.\n\n---\n*Detected by InfraPilot Supply Chain Security*',
    E'### Remediation\n{{if .FixedVersion}}✅ **Fixed in version:** {{.FixedVersion}}\n\nUpdate {{.PackageName}} to version {{.FixedVersion}} or later.\n{{else}}⚠️ No fix currently available. Consider:\n- Using an alternative package\n- Requesting a risk exception if acceptable\n- Monitoring for updates{{end}}',
    'medium'
FROM organizations
WHERE NOT EXISTS (
    SELECT 1 FROM feedback_templates
    WHERE source_type = 'vulnerability' AND name = 'default-vulnerability'
);

-- Insert default policy violation template
INSERT INTO feedback_templates (org_id, name, source_type, title_template, message_template, remediation_template)
SELECT
    id,
    'default-policy',
    'policy_violation',
    '⚠️ Policy Violation: {{.PolicyName}}',
    E'## Policy Violation\n\n**Policy:** {{.PolicyName}}\n**Severity:** {{.Severity}}\n**Decision:** {{.Decision}}\n\n### Details\n{{.Reason}}\n\n---\n*Enforced by InfraPilot Policy Engine*',
    E'### Next Steps\n1. Review the policy requirements\n2. Update your deployment to comply\n3. If this is a false positive, request a risk exception\n4. Contact your security team for guidance'
FROM organizations
WHERE NOT EXISTS (
    SELECT 1 FROM feedback_templates
    WHERE source_type = 'policy_violation' AND name = 'default-policy'
);
