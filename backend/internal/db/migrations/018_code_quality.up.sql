-- Migration 018: Code Quality Integration (Epic 12)
-- Adds support for SAST (Semgrep), code quality scanning (SonarQube), and related policies

-- ============================================================================
-- Code Quality Results
-- ============================================================================

-- Code quality result table for storing SAST and code quality scan results
CREATE TABLE code_quality_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Linkage to deployment
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,

    -- Tool information
    tool VARCHAR(50) NOT NULL CHECK (tool IN ('semgrep', 'sonarqube', 'eslint', 'golangci-lint', 'pylint', 'custom')),
    tool_version VARCHAR(50),

    -- Project identification
    project_key VARCHAR(255) NOT NULL,
    project_name VARCHAR(255),

    -- Git information
    git_repo VARCHAR(500),
    git_branch VARCHAR(255),
    commit_sha VARCHAR(64),
    commit_author VARCHAR(255),

    -- Code quality metrics
    bugs INTEGER DEFAULT 0,
    vulnerabilities INTEGER DEFAULT 0,
    code_smells INTEGER DEFAULT 0,
    security_hotspots INTEGER DEFAULT 0,

    -- Severity breakdown (SAST/security issues)
    critical_issues INTEGER DEFAULT 0,
    high_issues INTEGER DEFAULT 0,
    medium_issues INTEGER DEFAULT 0,
    low_issues INTEGER DEFAULT 0,
    info_issues INTEGER DEFAULT 0,

    -- Quality metrics
    coverage DECIMAL(5,2), -- Code coverage percentage (0-100)
    complexity DECIMAL(10,2), -- Cyclomatic complexity
    duplication DECIMAL(5,2), -- Code duplication percentage
    technical_debt_minutes INTEGER, -- Technical debt in minutes

    -- Quality gate result
    quality_gate VARCHAR(20) CHECK (quality_gate IN ('pass', 'warn', 'fail')),
    quality_gate_details TEXT,

    -- Scan metadata
    scan_duration_ms INTEGER,
    lines_of_code INTEGER,
    files_analyzed INTEGER,

    -- Raw report (full JSON output from tool)
    raw_report JSONB,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for code quality results
CREATE INDEX idx_code_quality_org ON code_quality_results(org_id);
CREATE INDEX idx_code_quality_deployment ON code_quality_results(deployment_id);
CREATE INDEX idx_code_quality_tool ON code_quality_results(tool);
CREATE INDEX idx_code_quality_project ON code_quality_results(project_key);
CREATE INDEX idx_code_quality_commit ON code_quality_results(commit_sha);
CREATE INDEX idx_code_quality_quality_gate ON code_quality_results(quality_gate);
CREATE INDEX idx_code_quality_created ON code_quality_results(created_at DESC);

-- ============================================================================
-- Code Quality Issues
-- ============================================================================

-- Individual issues/findings from code quality scans
CREATE TABLE code_quality_issues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_quality_result_id UUID NOT NULL REFERENCES code_quality_results(id) ON DELETE CASCADE,

    -- Issue identification
    issue_key VARCHAR(255), -- Tool-specific unique identifier
    rule_id VARCHAR(255) NOT NULL,
    rule_name VARCHAR(500),

    -- Severity and type
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    issue_type VARCHAR(50) NOT NULL CHECK (issue_type IN ('bug', 'vulnerability', 'code_smell', 'security_hotspot', 'other')),

    -- Location in code
    file_path VARCHAR(1000) NOT NULL,
    start_line INTEGER,
    end_line INTEGER,
    start_column INTEGER,
    end_column INTEGER,

    -- Issue details
    message TEXT NOT NULL,
    description TEXT,

    -- Metadata
    cwe_ids TEXT[], -- Common Weakness Enumeration IDs
    owasp_category VARCHAR(100), -- OWASP Top 10 category
    confidence VARCHAR(20), -- high, medium, low

    -- Fix information
    fix_available BOOLEAN DEFAULT FALSE,
    fix_suggestion TEXT,

    -- Additional data
    metadata JSONB,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for code quality issues
CREATE INDEX idx_code_quality_issues_result ON code_quality_issues(code_quality_result_id);
CREATE INDEX idx_code_quality_issues_severity ON code_quality_issues(severity);
CREATE INDEX idx_code_quality_issues_type ON code_quality_issues(issue_type);
CREATE INDEX idx_code_quality_issues_rule ON code_quality_issues(rule_id);
CREATE INDEX idx_code_quality_issues_file ON code_quality_issues(file_path);

-- ============================================================================
-- Code Quality Policies
-- ============================================================================

-- Policy rules for code quality gates
CREATE TABLE code_quality_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Policy information
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Scope
    environments TEXT[] NOT NULL DEFAULT '{}', -- empty = all environments
    projects TEXT[] NOT NULL DEFAULT '{}', -- empty = all projects
    tools TEXT[] NOT NULL DEFAULT '{}', -- empty = all tools

    -- Thresholds
    max_critical INTEGER, -- null = no limit
    max_high INTEGER,
    max_medium INTEGER,
    max_vulnerabilities INTEGER,
    max_bugs INTEGER,
    max_code_smells INTEGER,

    min_coverage DECIMAL(5,2), -- Minimum required coverage percentage
    max_complexity DECIMAL(10,2), -- Maximum allowed complexity
    max_duplication DECIMAL(5,2), -- Maximum allowed duplication

    -- Enforcement
    enforcement VARCHAR(20) NOT NULL DEFAULT 'warn' CHECK (enforcement IN ('enforce', 'warn', 'disabled')),
    block_deployment BOOLEAN DEFAULT FALSE, -- If true, failing this policy blocks deployment

    -- Versioning
    version INTEGER NOT NULL DEFAULT 1,
    enabled BOOLEAN DEFAULT TRUE,

    -- Audit
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for code quality policies
CREATE INDEX idx_code_quality_policies_org ON code_quality_policies(org_id);
CREATE INDEX idx_code_quality_policies_enabled ON code_quality_policies(enabled);

-- ============================================================================
-- Code Quality Policy Evaluations
-- ============================================================================

-- Track policy evaluation results
CREATE TABLE code_quality_policy_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code_quality_result_id UUID NOT NULL REFERENCES code_quality_results(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES code_quality_policies(id) ON DELETE SET NULL,

    -- Evaluation result
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('pass', 'warn', 'fail')),
    reason TEXT,

    -- Violations
    violations JSONB, -- Array of specific violations

    -- Timing
    evaluation_time_ms INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for policy evaluations
CREATE INDEX idx_code_quality_eval_result ON code_quality_policy_evaluations(code_quality_result_id);
CREATE INDEX idx_code_quality_eval_policy ON code_quality_policy_evaluations(policy_id);
CREATE INDEX idx_code_quality_eval_decision ON code_quality_policy_evaluations(decision);

-- ============================================================================
-- Code Quality Trends
-- ============================================================================

-- Aggregate view of code quality over time (for dashboards)
CREATE TABLE code_quality_trends (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Grouping
    project_key VARCHAR(255) NOT NULL,
    time_period DATE NOT NULL, -- Daily aggregation

    -- Aggregate metrics
    avg_coverage DECIMAL(5,2),
    avg_complexity DECIMAL(10,2),
    avg_duplication DECIMAL(5,2),

    total_bugs INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    total_code_smells INTEGER DEFAULT 0,
    total_security_hotspots INTEGER DEFAULT 0,

    total_critical INTEGER DEFAULT 0,
    total_high INTEGER DEFAULT 0,
    total_medium INTEGER DEFAULT 0,
    total_low INTEGER DEFAULT 0,

    scan_count INTEGER DEFAULT 0, -- Number of scans in this period

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(org_id, project_key, time_period)
);

-- Indexes for trends
CREATE INDEX idx_code_quality_trends_org ON code_quality_trends(org_id);
CREATE INDEX idx_code_quality_trends_project ON code_quality_trends(project_key);
CREATE INDEX idx_code_quality_trends_period ON code_quality_trends(time_period DESC);

-- ============================================================================
-- Views
-- ============================================================================

-- Latest code quality result per project
CREATE VIEW v_latest_code_quality AS
SELECT DISTINCT ON (org_id, project_key)
    id,
    org_id,
    deployment_id,
    tool,
    project_key,
    project_name,
    commit_sha,
    bugs,
    vulnerabilities,
    code_smells,
    security_hotspots,
    critical_issues,
    high_issues,
    medium_issues,
    low_issues,
    coverage,
    complexity,
    duplication,
    quality_gate,
    created_at
FROM code_quality_results
ORDER BY org_id, project_key, created_at DESC;

-- Project quality summary (aggregates across all scans for a project)
CREATE VIEW v_project_quality_summary AS
SELECT
    org_id,
    project_key,
    project_name,
    tool,
    COUNT(*) as total_scans,
    AVG(coverage) as avg_coverage,
    AVG(complexity) as avg_complexity,
    AVG(duplication) as avg_duplication,
    SUM(bugs) as total_bugs,
    SUM(vulnerabilities) as total_vulnerabilities,
    SUM(code_smells) as total_code_smells,
    SUM(critical_issues) as total_critical,
    SUM(high_issues) as total_high,
    COUNT(CASE WHEN quality_gate = 'fail' THEN 1 END) as failed_gates,
    COUNT(CASE WHEN quality_gate = 'pass' THEN 1 END) as passed_gates,
    MAX(created_at) as last_scan_at
FROM code_quality_results
GROUP BY org_id, project_key, project_name, tool;

-- Code quality leaderboard (best to worst projects by quality)
CREATE VIEW v_code_quality_leaderboard AS
SELECT
    org_id,
    project_key,
    project_name,
    tool,
    COALESCE(coverage, 0) as coverage,
    COALESCE(complexity, 0) as complexity,
    (critical_issues + high_issues + medium_issues + low_issues) as total_issues,
    critical_issues,
    high_issues,
    quality_gate,
    created_at as last_scan_at,
    -- Simple quality score (higher is better)
    -- Formula: Coverage bonus - (critical*10 + high*5 + medium*2 + low*1) - complexity penalty
    GREATEST(0, LEAST(100,
        COALESCE(coverage, 0) -
        (critical_issues * 10 + high_issues * 5 + medium_issues * 2 + low_issues * 1) -
        (CASE WHEN complexity > 10 THEN (complexity - 10) ELSE 0 END)
    ))::INTEGER as quality_score
FROM v_latest_code_quality
ORDER BY quality_score DESC;

-- ============================================================================
-- Functions
-- ============================================================================

-- Update code quality trends (called after each scan)
CREATE OR REPLACE FUNCTION update_code_quality_trends()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO code_quality_trends (
        org_id,
        project_key,
        time_period,
        avg_coverage,
        avg_complexity,
        avg_duplication,
        total_bugs,
        total_vulnerabilities,
        total_code_smells,
        total_security_hotspots,
        total_critical,
        total_high,
        total_medium,
        total_low,
        scan_count
    )
    SELECT
        NEW.org_id,
        NEW.project_key,
        CURRENT_DATE,
        AVG(coverage),
        AVG(complexity),
        AVG(duplication),
        SUM(bugs),
        SUM(vulnerabilities),
        SUM(code_smells),
        SUM(security_hotspots),
        SUM(critical_issues),
        SUM(high_issues),
        SUM(medium_issues),
        SUM(low_issues),
        COUNT(*)
    FROM code_quality_results
    WHERE org_id = NEW.org_id
      AND project_key = NEW.project_key
      AND DATE(created_at) = CURRENT_DATE
    GROUP BY org_id, project_key
    ON CONFLICT (org_id, project_key, time_period) DO UPDATE SET
        avg_coverage = EXCLUDED.avg_coverage,
        avg_complexity = EXCLUDED.avg_complexity,
        avg_duplication = EXCLUDED.avg_duplication,
        total_bugs = EXCLUDED.total_bugs,
        total_vulnerabilities = EXCLUDED.total_vulnerabilities,
        total_code_smells = EXCLUDED.total_code_smells,
        total_security_hotspots = EXCLUDED.total_security_hotspots,
        total_critical = EXCLUDED.total_critical,
        total_high = EXCLUDED.total_high,
        total_medium = EXCLUDED.total_medium,
        total_low = EXCLUDED.total_low,
        scan_count = EXCLUDED.scan_count;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update trends automatically
CREATE TRIGGER trigger_update_code_quality_trends
    AFTER INSERT ON code_quality_results
    FOR EACH ROW
    EXECUTE FUNCTION update_code_quality_trends();

-- Evaluate code quality policies for a result
CREATE OR REPLACE FUNCTION evaluate_code_quality_policies(
    p_result_id UUID
)
RETURNS TABLE (
    policy_id UUID,
    policy_name VARCHAR,
    decision VARCHAR,
    reason TEXT
) AS $$
DECLARE
    v_result RECORD;
    v_policy RECORD;
    v_decision VARCHAR;
    v_reason TEXT;
    v_violations TEXT[];
BEGIN
    -- Get the code quality result
    SELECT * INTO v_result
    FROM code_quality_results
    WHERE id = p_result_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Code quality result not found: %', p_result_id;
    END IF;

    -- Evaluate each enabled policy
    FOR v_policy IN
        SELECT *
        FROM code_quality_policies
        WHERE org_id = v_result.org_id
          AND enabled = TRUE
          AND (tools = '{}' OR v_result.tool = ANY(tools))
    LOOP
        v_decision := 'pass';
        v_violations := ARRAY[]::TEXT[];

        -- Check critical issues
        IF v_policy.max_critical IS NOT NULL AND v_result.critical_issues > v_policy.max_critical THEN
            v_decision := 'fail';
            v_violations := array_append(v_violations,
                format('Critical issues: %s (max: %s)', v_result.critical_issues, v_policy.max_critical));
        END IF;

        -- Check high issues
        IF v_policy.max_high IS NOT NULL AND v_result.high_issues > v_policy.max_high THEN
            IF v_policy.enforcement = 'enforce' THEN
                v_decision := 'fail';
            ELSIF v_decision = 'pass' THEN
                v_decision := 'warn';
            END IF;
            v_violations := array_append(v_violations,
                format('High issues: %s (max: %s)', v_result.high_issues, v_policy.max_high));
        END IF;

        -- Check vulnerabilities
        IF v_policy.max_vulnerabilities IS NOT NULL AND v_result.vulnerabilities > v_policy.max_vulnerabilities THEN
            v_decision := 'fail';
            v_violations := array_append(v_violations,
                format('Vulnerabilities: %s (max: %s)', v_result.vulnerabilities, v_policy.max_vulnerabilities));
        END IF;

        -- Check coverage
        IF v_policy.min_coverage IS NOT NULL AND (v_result.coverage IS NULL OR v_result.coverage < v_policy.min_coverage) THEN
            IF v_policy.enforcement = 'enforce' THEN
                v_decision := 'fail';
            ELSIF v_decision = 'pass' THEN
                v_decision := 'warn';
            END IF;
            v_violations := array_append(v_violations,
                format('Coverage: %s%% (min: %s%%)', COALESCE(v_result.coverage, 0), v_policy.min_coverage));
        END IF;

        -- Check complexity
        IF v_policy.max_complexity IS NOT NULL AND v_result.complexity > v_policy.max_complexity THEN
            IF v_policy.enforcement = 'enforce' THEN
                v_decision := 'fail';
            ELSIF v_decision = 'pass' THEN
                v_decision := 'warn';
            END IF;
            v_violations := array_append(v_violations,
                format('Complexity: %s (max: %s)', v_result.complexity, v_policy.max_complexity));
        END IF;

        -- Build reason
        IF array_length(v_violations, 1) > 0 THEN
            v_reason := array_to_string(v_violations, '; ');
        ELSE
            v_reason := 'All checks passed';
        END IF;

        -- Store evaluation
        INSERT INTO code_quality_policy_evaluations (
            code_quality_result_id,
            policy_id,
            decision,
            reason,
            violations
        ) VALUES (
            p_result_id,
            v_policy.id,
            v_decision,
            v_reason,
            to_jsonb(v_violations)
        );

        -- Return result
        RETURN QUERY SELECT v_policy.id, v_policy.name, v_decision, v_reason;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Default Policies
-- ============================================================================

-- Insert a default code quality policy for production environments
-- This is a template - organizations should customize based on their needs
-- Commented out to avoid creating defaults, but kept as reference

-- INSERT INTO code_quality_policies (
--     org_id,
--     name,
--     description,
--     environments,
--     max_critical,
--     max_high,
--     max_vulnerabilities,
--     min_coverage,
--     enforcement,
--     block_deployment
-- ) VALUES (
--     (SELECT id FROM organizations LIMIT 1), -- Replace with actual org_id
--     'Production Code Quality Gate',
--     'Strict quality requirements for production deployments',
--     ARRAY['prod'],
--     0,  -- No critical issues allowed
--     5,  -- Max 5 high issues
--     0,  -- No vulnerabilities allowed
--     80.0, -- Minimum 80% coverage
--     'enforce',
--     TRUE
-- );

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE code_quality_results IS 'Stores SAST and code quality scan results from tools like Semgrep, SonarQube, etc.';
COMMENT ON TABLE code_quality_issues IS 'Individual issues/findings from code quality scans with location and severity information';
COMMENT ON TABLE code_quality_policies IS 'Policy rules defining quality gates and thresholds for deployments';
COMMENT ON TABLE code_quality_policy_evaluations IS 'Results of evaluating code quality against defined policies';
COMMENT ON TABLE code_quality_trends IS 'Daily aggregated metrics for trend analysis and dashboard visualization';

COMMENT ON VIEW v_latest_code_quality IS 'Most recent code quality result for each project';
COMMENT ON VIEW v_project_quality_summary IS 'Aggregate quality metrics across all scans for each project';
COMMENT ON VIEW v_code_quality_leaderboard IS 'Projects ranked by quality score (higher is better)';

COMMENT ON FUNCTION evaluate_code_quality_policies IS 'Evaluates all applicable policies for a code quality result and returns pass/warn/fail decisions';
COMMENT ON FUNCTION update_code_quality_trends IS 'Trigger function that maintains daily trend aggregates';
