-- Epic 7: Research & Metrics Readiness
-- Tables for collecting metrics, telemetry, and research data

-- Metric Definitions: Define what metrics to collect
CREATE TABLE IF NOT EXISTS metric_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Metric identification
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(255),
    description TEXT,
    category VARCHAR(50) NOT NULL,  -- 'security', 'performance', 'compliance', 'usage', 'cost', 'health'
    subcategory VARCHAR(50),

    -- Metric type
    metric_type VARCHAR(20) NOT NULL DEFAULT 'gauge',  -- 'counter', 'gauge', 'histogram', 'summary'
    unit VARCHAR(50),  -- 'count', 'percent', 'seconds', 'bytes', 'requests', etc.
    value_type VARCHAR(20) DEFAULT 'numeric',  -- 'numeric', 'boolean', 'string'

    -- Collection
    collection_method VARCHAR(50) DEFAULT 'automatic',  -- 'automatic', 'manual', 'calculated', 'aggregated'
    collection_interval_seconds INTEGER DEFAULT 300,
    source VARCHAR(100),  -- 'agent', 'api', 'database', 'scan', 'external'
    query_template TEXT,  -- SQL or other query for calculated metrics

    -- Aggregation
    aggregation_type VARCHAR(20),  -- 'sum', 'avg', 'min', 'max', 'count', 'last', 'p50', 'p95', 'p99'
    aggregation_window_seconds INTEGER,

    -- Thresholds
    warning_threshold DECIMAL(20, 4),
    critical_threshold DECIMAL(20, 4),
    threshold_direction VARCHAR(10) DEFAULT 'above',  -- 'above', 'below'

    -- Display
    is_primary BOOLEAN DEFAULT FALSE,
    display_order INTEGER DEFAULT 0,
    chart_type VARCHAR(20),  -- 'line', 'bar', 'pie', 'gauge', 'number'
    color VARCHAR(20),

    -- Status
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_metric_definitions_org_id ON metric_definitions(org_id);
CREATE INDEX IF NOT EXISTS idx_metric_definitions_category ON metric_definitions(category);
CREATE INDEX IF NOT EXISTS idx_metric_definitions_enabled ON metric_definitions(enabled);

-- Metric Values: Store collected metric values
CREATE TABLE IF NOT EXISTS metric_values (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    metric_id UUID NOT NULL REFERENCES metric_definitions(id) ON DELETE CASCADE,

    -- Dimensions/Labels
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    deployment_id UUID,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    labels JSONB DEFAULT '{}',

    -- Value
    value_numeric DECIMAL(20, 4),
    value_string VARCHAR(255),
    value_bool BOOLEAN,

    -- Timing
    collected_at TIMESTAMPTZ NOT NULL,
    period_start TIMESTAMPTZ,
    period_end TIMESTAMPTZ,

    -- Metadata
    source VARCHAR(100),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_metric_values_org_metric ON metric_values(org_id, metric_id);
CREATE INDEX IF NOT EXISTS idx_metric_values_collected_at ON metric_values(collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_metric_values_agent_id ON metric_values(agent_id);
CREATE INDEX IF NOT EXISTS idx_metric_values_resource ON metric_values(resource_type, resource_id);

-- Partition metric values by time (optional, depends on scale)
-- This is a hint for future partitioning strategy

-- Research Data: Store anonymized/aggregated research data
CREATE TABLE IF NOT EXISTS research_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Data identification
    data_type VARCHAR(50) NOT NULL,  -- 'usage_pattern', 'security_posture', 'deployment_frequency', etc.
    period_type VARCHAR(20) NOT NULL,  -- 'hourly', 'daily', 'weekly', 'monthly'
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,

    -- Aggregated data
    data JSONB NOT NULL,
    sample_count INTEGER DEFAULT 0,

    -- Consent & Privacy
    anonymized BOOLEAN DEFAULT TRUE,
    consent_version VARCHAR(20),

    -- Processing
    processed_at TIMESTAMPTZ DEFAULT NOW(),
    exported_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, data_type, period_type, period_start)
);

CREATE INDEX IF NOT EXISTS idx_research_data_org_id ON research_data(org_id);
CREATE INDEX IF NOT EXISTS idx_research_data_data_type ON research_data(data_type);
CREATE INDEX IF NOT EXISTS idx_research_data_period ON research_data(period_start DESC);

-- Dashboards: User-defined dashboards
CREATE TABLE IF NOT EXISTS dashboards (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Dashboard identification
    name VARCHAR(100) NOT NULL,
    description TEXT,
    slug VARCHAR(100),

    -- Ownership
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    is_default BOOLEAN DEFAULT FALSE,
    is_shared BOOLEAN DEFAULT FALSE,

    -- Layout
    layout JSONB DEFAULT '[]',  -- Widget positions and sizes
    settings JSONB DEFAULT '{}',  -- Dashboard-level settings

    -- Access
    visibility VARCHAR(20) DEFAULT 'private',  -- 'private', 'team', 'org', 'public'

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_dashboards_org_id ON dashboards(org_id);
CREATE INDEX IF NOT EXISTS idx_dashboards_created_by ON dashboards(created_by);
CREATE INDEX IF NOT EXISTS idx_dashboards_visibility ON dashboards(visibility);

-- Dashboard Widgets: Individual widgets on dashboards
CREATE TABLE IF NOT EXISTS dashboard_widgets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    dashboard_id UUID NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,

    -- Widget definition
    widget_type VARCHAR(50) NOT NULL,  -- 'metric', 'chart', 'table', 'text', 'alert_summary', etc.
    title VARCHAR(255),

    -- Data source
    metric_ids UUID[],  -- References to metric_definitions
    query JSONB,  -- Custom query configuration
    filters JSONB DEFAULT '{}',

    -- Display
    chart_type VARCHAR(20),  -- 'line', 'bar', 'pie', 'area', 'gauge', 'number', 'table'
    time_range VARCHAR(20),  -- 'last_hour', 'last_24h', 'last_7d', 'last_30d', 'custom'
    refresh_interval_seconds INTEGER DEFAULT 60,

    -- Layout position (used by dashboard)
    position_x INTEGER DEFAULT 0,
    position_y INTEGER DEFAULT 0,
    width INTEGER DEFAULT 4,
    height INTEGER DEFAULT 3,

    -- Settings
    settings JSONB DEFAULT '{}',

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_dashboard_id ON dashboard_widgets(dashboard_id);
CREATE INDEX IF NOT EXISTS idx_dashboard_widgets_org_id ON dashboard_widgets(org_id);

-- Reports: Scheduled or on-demand reports
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Report identification
    name VARCHAR(100) NOT NULL,
    description TEXT,
    report_type VARCHAR(50) NOT NULL,  -- 'security_summary', 'compliance', 'executive', 'custom', etc.

    -- Configuration
    template VARCHAR(100),  -- Report template to use
    config JSONB DEFAULT '{}',  -- Report-specific configuration
    filters JSONB DEFAULT '{}',

    -- Scheduling
    schedule_enabled BOOLEAN DEFAULT FALSE,
    schedule_cron VARCHAR(100),
    schedule_timezone VARCHAR(50) DEFAULT 'UTC',
    next_run_at TIMESTAMPTZ,
    last_run_at TIMESTAMPTZ,

    -- Delivery
    delivery_method VARCHAR(20),  -- 'email', 'download', 'webhook', 's3'
    delivery_config JSONB DEFAULT '{}',
    recipients TEXT[],

    -- Access
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    visibility VARCHAR(20) DEFAULT 'private',

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_org_id ON reports(org_id);
CREATE INDEX IF NOT EXISTS idx_reports_report_type ON reports(report_type);
CREATE INDEX IF NOT EXISTS idx_reports_next_run ON reports(next_run_at) WHERE schedule_enabled = TRUE;

-- Report Executions: Track report generation history
CREATE TABLE IF NOT EXISTS report_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,

    -- Execution details
    triggered_by VARCHAR(50),  -- 'schedule', 'manual', 'api'
    triggered_by_user UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed'
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,

    -- Output
    output_format VARCHAR(20),  -- 'pdf', 'html', 'csv', 'json'
    output_path TEXT,
    output_size_bytes INTEGER,

    -- Delivery
    delivered_at TIMESTAMPTZ,
    delivery_status VARCHAR(20),
    delivery_error TEXT,

    -- Data range
    data_start TIMESTAMPTZ,
    data_end TIMESTAMPTZ,

    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_report_executions_report_id ON report_executions(report_id);
CREATE INDEX IF NOT EXISTS idx_report_executions_status ON report_executions(status);
CREATE INDEX IF NOT EXISTS idx_report_executions_created_at ON report_executions(created_at DESC);

-- Telemetry Settings: Control data collection and research participation
CREATE TABLE IF NOT EXISTS telemetry_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,

    -- Data collection
    collect_usage_metrics BOOLEAN DEFAULT TRUE,
    collect_performance_metrics BOOLEAN DEFAULT TRUE,
    collect_security_metrics BOOLEAN DEFAULT TRUE,
    collect_error_reports BOOLEAN DEFAULT TRUE,

    -- Research participation
    research_participation BOOLEAN DEFAULT FALSE,
    research_consent_date TIMESTAMPTZ,
    research_consent_version VARCHAR(20),

    -- Anonymization
    anonymize_data BOOLEAN DEFAULT TRUE,
    data_retention_days INTEGER DEFAULT 90,

    -- Export
    allow_data_export BOOLEAN DEFAULT TRUE,
    export_format VARCHAR(20) DEFAULT 'json',

    updated_at TIMESTAMPTZ DEFAULT NOW(),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_telemetry_settings_org_id ON telemetry_settings(org_id);

-- View: Metric summary by category
CREATE OR REPLACE VIEW v_metric_summary AS
SELECT
    m.org_id,
    m.category,
    COUNT(*) as total_metrics,
    COUNT(*) FILTER (WHERE m.enabled = TRUE) as enabled_metrics,
    COUNT(DISTINCT mv.metric_id) as metrics_with_data,
    MAX(mv.collected_at) as last_data_collected
FROM metric_definitions m
LEFT JOIN metric_values mv ON mv.metric_id = m.id
GROUP BY m.org_id, m.category;

-- View: Dashboard overview
CREATE OR REPLACE VIEW v_dashboard_overview AS
SELECT
    d.org_id,
    d.id as dashboard_id,
    d.name,
    d.visibility,
    d.is_default,
    COUNT(dw.id) as widget_count,
    d.created_by,
    d.created_at,
    d.updated_at
FROM dashboards d
LEFT JOIN dashboard_widgets dw ON dw.dashboard_id = d.id
GROUP BY d.id;

-- Insert default metric definitions for new organizations (optional)
-- This can be done via application code or triggers

-- Comments
COMMENT ON TABLE metric_definitions IS 'Define metrics to be collected and tracked';
COMMENT ON TABLE metric_values IS 'Store collected metric values over time';
COMMENT ON TABLE research_data IS 'Aggregated and anonymized data for research purposes';
COMMENT ON TABLE dashboards IS 'User-defined dashboards for visualizing metrics';
COMMENT ON TABLE dashboard_widgets IS 'Individual widgets placed on dashboards';
COMMENT ON TABLE reports IS 'Report configurations and schedules';
COMMENT ON TABLE report_executions IS 'Track report generation history';
COMMENT ON TABLE telemetry_settings IS 'Control data collection and research participation per organization';
