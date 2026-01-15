-- Migration: 017_security_maturity
-- Description: Security maturity scoring and team benchmarking
-- Epic 11: Security Maturity Scoring & Team Leaderboards

-- ============ Enums ============

CREATE TYPE score_category AS ENUM (
    'vulnerability_management',
    'policy_compliance',
    'deployment_security',
    'exception_management',
    'response_time'
);

-- ============ Security Scores Table ============

CREATE TABLE security_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Scope
    scope_type VARCHAR(20) NOT NULL CHECK (scope_type IN ('organization', 'team', 'service')),
    scope_reference VARCHAR(255) NOT NULL, -- org name, team name, or service name

    -- Overall score (0-100)
    overall_score INTEGER NOT NULL CHECK (overall_score >= 0 AND overall_score <= 100),

    -- Category scores (0-100 each)
    vulnerability_score INTEGER CHECK (vulnerability_score >= 0 AND vulnerability_score <= 100),
    policy_score INTEGER CHECK (policy_score >= 0 AND policy_score <= 100),
    deployment_score INTEGER CHECK (deployment_score >= 0 AND deployment_score <= 100),
    exception_score INTEGER CHECK (exception_score >= 0 AND exception_score <= 100),
    response_score INTEGER CHECK (response_score >= 0 AND response_score <= 100),

    -- Metrics used for calculation
    total_deployments INTEGER NOT NULL DEFAULT 0,
    vulnerable_deployments INTEGER NOT NULL DEFAULT 0,
    critical_vulnerabilities INTEGER NOT NULL DEFAULT 0,
    high_vulnerabilities INTEGER NOT NULL DEFAULT 0,
    policy_violations INTEGER NOT NULL DEFAULT 0,
    active_exceptions INTEGER NOT NULL DEFAULT 0,
    mean_time_to_fix_hours NUMERIC(10, 2), -- MTTF in hours

    -- Calculation metadata
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Security Metrics Table ============

CREATE TABLE security_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Scope
    scope_type VARCHAR(20) NOT NULL CHECK (scope_type IN ('organization', 'team', 'service')),
    scope_reference VARCHAR(255) NOT NULL,

    -- Metric identification
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC(15, 4) NOT NULL,
    metric_unit VARCHAR(50), -- e.g., 'hours', 'count', 'percentage'

    -- Context
    metadata JSONB,

    -- Time
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Team Benchmarks Table ============

CREATE TABLE team_benchmarks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Team
    team_name VARCHAR(255) NOT NULL,

    -- Ranking metrics
    overall_rank INTEGER,
    vulnerability_rank INTEGER,
    response_time_rank INTEGER,

    -- Trend indicators
    score_trend VARCHAR(20) CHECK (score_trend IN ('improving', 'stable', 'declining')),
    trend_percentage NUMERIC(5, 2), -- % change from previous period

    -- Period
    benchmark_period VARCHAR(20) NOT NULL, -- 'weekly', 'monthly', 'quarterly'
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, team_name, benchmark_period, period_start)
);

-- ============ Indexes ============

-- Security scores indexes
CREATE INDEX idx_security_scores_org ON security_scores(org_id);
CREATE INDEX idx_security_scores_scope ON security_scores(scope_type, scope_reference);
CREATE INDEX idx_security_scores_calculated ON security_scores(calculated_at DESC);
CREATE INDEX idx_security_scores_period ON security_scores(period_start, period_end);
CREATE INDEX idx_security_scores_overall ON security_scores(overall_score DESC);

-- Security metrics indexes
CREATE INDEX idx_security_metrics_org ON security_metrics(org_id);
CREATE INDEX idx_security_metrics_scope ON security_metrics(scope_type, scope_reference);
CREATE INDEX idx_security_metrics_name ON security_metrics(metric_name);
CREATE INDEX idx_security_metrics_recorded ON security_metrics(recorded_at DESC);

-- Team benchmarks indexes
CREATE INDEX idx_team_benchmarks_org ON team_benchmarks(org_id);
CREATE INDEX idx_team_benchmarks_team ON team_benchmarks(team_name);
CREATE INDEX idx_team_benchmarks_period ON team_benchmarks(benchmark_period, period_start);
CREATE INDEX idx_team_benchmarks_rank ON team_benchmarks(overall_rank);

-- ============ Functions ============

-- Calculate vulnerability score (0-100, higher is better)
CREATE OR REPLACE FUNCTION calculate_vulnerability_score(
    p_total_deployments INTEGER,
    p_vulnerable_deployments INTEGER,
    p_critical_count INTEGER,
    p_high_count INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    v_score INTEGER;
    v_vulnerability_rate NUMERIC;
    v_severity_penalty NUMERIC;
BEGIN
    -- If no deployments, return 100 (no vulnerabilities)
    IF p_total_deployments = 0 THEN
        RETURN 100;
    END IF;

    -- Calculate vulnerability rate (0-1)
    v_vulnerability_rate := p_vulnerable_deployments::NUMERIC / p_total_deployments::NUMERIC;

    -- Severity penalty
    v_severity_penalty := (p_critical_count * 10 + p_high_count * 5)::NUMERIC / p_total_deployments::NUMERIC;

    -- Score = 100 - (vulnerability_rate * 50) - (severity_penalty)
    -- Max 50 points for vulnerability rate, max 50 points for severity
    v_score := 100 - LEAST(50, (v_vulnerability_rate * 50)::INTEGER) - LEAST(50, v_severity_penalty::INTEGER);

    -- Ensure score is between 0-100
    RETURN GREATEST(0, LEAST(100, v_score));
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Calculate policy compliance score (0-100, higher is better)
CREATE OR REPLACE FUNCTION calculate_policy_score(
    p_total_deployments INTEGER,
    p_policy_violations INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    v_score INTEGER;
    v_violation_rate NUMERIC;
BEGIN
    IF p_total_deployments = 0 THEN
        RETURN 100;
    END IF;

    v_violation_rate := p_policy_violations::NUMERIC / p_total_deployments::NUMERIC;

    -- 100% compliance = 100 points, 0% compliance = 0 points
    v_score := 100 - (v_violation_rate * 100)::INTEGER;

    RETURN GREATEST(0, LEAST(100, v_score));
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Calculate response time score (0-100, higher is better, based on MTTF)
CREATE OR REPLACE FUNCTION calculate_response_score(
    p_mean_time_to_fix_hours NUMERIC
)
RETURNS INTEGER AS $$
DECLARE
    v_score INTEGER;
BEGIN
    -- If no data, return 50 (neutral)
    IF p_mean_time_to_fix_hours IS NULL THEN
        RETURN 50;
    END IF;

    -- Target: <24 hours = 100 points
    -- 24-48 hours = 80 points
    -- 48-72 hours = 60 points
    -- 72-168 hours (1 week) = 40 points
    -- >168 hours = 20 points

    IF p_mean_time_to_fix_hours < 24 THEN
        v_score := 100;
    ELSIF p_mean_time_to_fix_hours < 48 THEN
        v_score := 80;
    ELSIF p_mean_time_to_fix_hours < 72 THEN
        v_score := 60;
    ELSIF p_mean_time_to_fix_hours < 168 THEN
        v_score := 40;
    ELSE
        v_score := 20;
    END IF;

    RETURN v_score;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Calculate exception management score (0-100, higher is better)
CREATE OR REPLACE FUNCTION calculate_exception_score(
    p_active_exceptions INTEGER,
    p_total_deployments INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    v_score INTEGER;
    v_exception_rate NUMERIC;
BEGIN
    IF p_total_deployments = 0 THEN
        RETURN 100;
    END IF;

    v_exception_rate := p_active_exceptions::NUMERIC / p_total_deployments::NUMERIC;

    -- No exceptions = 100 points
    -- <10% exceptions = 80 points
    -- 10-20% = 60 points
    -- 20-50% = 40 points
    -- >50% = 20 points

    IF v_exception_rate = 0 THEN
        v_score := 100;
    ELSIF v_exception_rate < 0.10 THEN
        v_score := 80;
    ELSIF v_exception_rate < 0.20 THEN
        v_score := 60;
    ELSIF v_exception_rate < 0.50 THEN
        v_score := 40;
    ELSE
        v_score := 20;
    END IF;

    RETURN v_score;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Calculate overall security score (weighted average)
CREATE OR REPLACE FUNCTION calculate_overall_score(
    p_vulnerability_score INTEGER,
    p_policy_score INTEGER,
    p_deployment_score INTEGER,
    p_exception_score INTEGER,
    p_response_score INTEGER
)
RETURNS INTEGER AS $$
DECLARE
    v_weighted_sum NUMERIC;
    v_total_weight NUMERIC;
BEGIN
    -- Weights:
    -- Vulnerability: 30%
    -- Policy: 25%
    -- Deployment: 20%
    -- Exceptions: 15%
    -- Response: 10%

    v_weighted_sum :=
        (COALESCE(p_vulnerability_score, 50) * 0.30) +
        (COALESCE(p_policy_score, 50) * 0.25) +
        (COALESCE(p_deployment_score, 50) * 0.20) +
        (COALESCE(p_exception_score, 50) * 0.15) +
        (COALESCE(p_response_score, 50) * 0.10);

    RETURN v_weighted_sum::INTEGER;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to calculate and store team security score
CREATE OR REPLACE FUNCTION calculate_team_security_score(
    p_org_id UUID,
    p_team_name VARCHAR,
    p_period_start TIMESTAMPTZ,
    p_period_end TIMESTAMPTZ
)
RETURNS UUID AS $$
DECLARE
    v_score_id UUID;
    v_total_deployments INTEGER;
    v_vulnerable_deployments INTEGER;
    v_critical_count INTEGER;
    v_high_count INTEGER;
    v_policy_violations INTEGER;
    v_active_exceptions INTEGER;
    v_mttf_hours NUMERIC;
    v_vuln_score INTEGER;
    v_policy_score INTEGER;
    v_deployment_score INTEGER;
    v_exception_score INTEGER;
    v_response_score INTEGER;
    v_overall_score INTEGER;
BEGIN
    -- Get team's deployments in period
    SELECT COUNT(DISTINCT d.id)
    INTO v_total_deployments
    FROM deployments d
    JOIN service_ownership so ON d.service_name = so.service_name AND d.org_id = so.org_id
    WHERE so.org_id = p_org_id
      AND so.team_name = p_team_name
      AND d.created_at >= p_period_start
      AND d.created_at <= p_period_end;

    -- Count vulnerable deployments (deployments with critical or high vulns)
    SELECT COUNT(DISTINCT d.id)
    INTO v_vulnerable_deployments
    FROM deployments d
    JOIN service_ownership so ON d.service_name = so.service_name AND d.org_id = so.org_id
    JOIN scan_results sr ON d.scan_result_id = sr.id
    WHERE so.org_id = p_org_id
      AND so.team_name = p_team_name
      AND d.created_at >= p_period_start
      AND d.created_at <= p_period_end
      AND (sr.critical_count > 0 OR sr.high_count > 0);

    -- Count critical and high vulnerabilities
    SELECT
        COALESCE(SUM(sr.critical_count), 0),
        COALESCE(SUM(sr.high_count), 0)
    INTO v_critical_count, v_high_count
    FROM deployments d
    JOIN service_ownership so ON d.service_name = so.service_name AND d.org_id = so.org_id
    JOIN scan_results sr ON d.scan_result_id = sr.id
    WHERE so.org_id = p_org_id
      AND so.team_name = p_team_name
      AND d.created_at >= p_period_start
      AND d.created_at <= p_period_end;

    -- Count policy violations (deployments blocked or warned)
    SELECT COUNT(*)
    INTO v_policy_violations
    FROM deployments d
    JOIN service_ownership so ON d.service_name = so.service_name AND d.org_id = so.org_id
    WHERE so.org_id = p_org_id
      AND so.team_name = p_team_name
      AND d.created_at >= p_period_start
      AND d.created_at <= p_period_end
      AND d.policy_decision IN ('deny', 'warn');

    -- Count active exceptions for team's services
    SELECT COUNT(*)
    INTO v_active_exceptions
    FROM risk_exceptions re
    JOIN service_ownership so ON re.org_id = so.org_id
    WHERE so.org_id = p_org_id
      AND so.team_name = p_team_name
      AND re.status = 'approved'
      AND re.expires_at > NOW();

    -- Calculate MTTF (simplified - would need tracking table for real implementation)
    -- For now, use average time between deployment and fix deployment
    v_mttf_hours := 24.0; -- Placeholder

    -- Calculate category scores
    v_vuln_score := calculate_vulnerability_score(v_total_deployments, v_vulnerable_deployments, v_critical_count, v_high_count);
    v_policy_score := calculate_policy_score(v_total_deployments, v_policy_violations);
    v_deployment_score := 100; -- Placeholder - would calculate based on deployment health
    v_exception_score := calculate_exception_score(v_active_exceptions, v_total_deployments);
    v_response_score := calculate_response_score(v_mttf_hours);

    -- Calculate overall score
    v_overall_score := calculate_overall_score(v_vuln_score, v_policy_score, v_deployment_score, v_exception_score, v_response_score);

    -- Insert score record
    INSERT INTO security_scores (
        org_id, scope_type, scope_reference,
        overall_score, vulnerability_score, policy_score, deployment_score,
        exception_score, response_score,
        total_deployments, vulnerable_deployments,
        critical_vulnerabilities, high_vulnerabilities,
        policy_violations, active_exceptions, mean_time_to_fix_hours,
        period_start, period_end
    ) VALUES (
        p_org_id, 'team', p_team_name,
        v_overall_score, v_vuln_score, v_policy_score, v_deployment_score,
        v_exception_score, v_response_score,
        v_total_deployments, v_vulnerable_deployments,
        v_critical_count, v_high_count,
        v_policy_violations, v_active_exceptions, v_mttf_hours,
        p_period_start, p_period_end
    ) RETURNING id INTO v_score_id;

    RETURN v_score_id;
END;
$$ LANGUAGE plpgsql;

-- ============ Views ============

-- Latest security scores per team
CREATE VIEW v_latest_team_scores AS
SELECT DISTINCT ON (org_id, scope_reference)
    org_id,
    scope_reference as team_name,
    overall_score,
    vulnerability_score,
    policy_score,
    deployment_score,
    exception_score,
    response_score,
    total_deployments,
    vulnerable_deployments,
    critical_vulnerabilities,
    high_vulnerabilities,
    mean_time_to_fix_hours,
    calculated_at
FROM security_scores
WHERE scope_type = 'team'
ORDER BY org_id, scope_reference, calculated_at DESC;

-- Team leaderboard
CREATE VIEW v_team_leaderboard AS
SELECT
    org_id,
    scope_reference as team_name,
    overall_score,
    ROW_NUMBER() OVER (PARTITION BY org_id ORDER BY overall_score DESC) as rank,
    vulnerability_score,
    policy_score,
    response_score,
    calculated_at
FROM security_scores
WHERE scope_type = 'team'
  AND calculated_at >= NOW() - INTERVAL '30 days'
ORDER BY overall_score DESC;

-- ============ Comments ============

COMMENT ON TABLE security_scores IS 'Security maturity scores for teams and services';
COMMENT ON TABLE security_metrics IS 'Granular security metrics for trending and analysis';
COMMENT ON TABLE team_benchmarks IS 'Team ranking and benchmark data';

COMMENT ON COLUMN security_scores.overall_score IS 'Weighted average of all category scores (0-100)';
COMMENT ON COLUMN security_scores.vulnerability_score IS 'Score based on vulnerability density and severity';
COMMENT ON COLUMN security_scores.policy_score IS 'Score based on policy compliance rate';
COMMENT ON COLUMN security_scores.response_score IS 'Score based on mean time to fix vulnerabilities';
COMMENT ON COLUMN security_scores.mean_time_to_fix_hours IS 'Average hours from vulnerability detection to fix';

COMMENT ON FUNCTION calculate_team_security_score IS 'Calculate and store security score for a team over a time period';
