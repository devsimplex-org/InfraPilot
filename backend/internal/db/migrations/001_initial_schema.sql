-- Migration: 001_initial_schema
-- Description: Initial database schema for InfraPilot

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============ Organizations ============

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Users & Authentication ============

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    mfa_secret      VARCHAR(255),
    mfa_enabled     BOOLEAN DEFAULT FALSE,
    role            VARCHAR(50) NOT NULL CHECK (role IN ('super_admin', 'operator', 'viewer')),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX idx_users_org ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

-- ============ Refresh Tokens ============

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) UNIQUE NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- ============ Agents ============

CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    hostname        VARCHAR(255),
    fingerprint     VARCHAR(64) UNIQUE,
    enrollment_token VARCHAR(64) UNIQUE,
    last_seen_at    TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'offline')),
    version         VARCHAR(50),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_agents_org ON agents(org_id);
CREATE INDEX idx_agents_status ON agents(status);
CREATE INDEX idx_agents_fingerprint ON agents(fingerprint);

-- ============ Proxy Hosts (Nginx) ============

CREATE TABLE proxy_hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    domain          VARCHAR(255) NOT NULL,
    upstream_target VARCHAR(255) NOT NULL,
    ssl_enabled     BOOLEAN DEFAULT FALSE,
    ssl_cert_path   VARCHAR(500),
    ssl_key_path    VARCHAR(500),
    ssl_expires_at  TIMESTAMPTZ,
    force_ssl       BOOLEAN DEFAULT TRUE,
    http2_enabled   BOOLEAN DEFAULT TRUE,
    config_hash     VARCHAR(64),
    status          VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'error')),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, domain)
);

CREATE INDEX idx_proxy_hosts_agent ON proxy_hosts(agent_id);
CREATE INDEX idx_proxy_hosts_domain ON proxy_hosts(domain);

-- ============ Security Headers ============

CREATE TABLE proxy_security_headers (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id           UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    hsts_enabled            BOOLEAN DEFAULT TRUE,
    hsts_max_age            INTEGER DEFAULT 31536000,
    x_frame_options         VARCHAR(50) DEFAULT 'SAMEORIGIN',
    x_content_type_options  BOOLEAN DEFAULT TRUE,
    x_xss_protection        BOOLEAN DEFAULT TRUE,
    content_security_policy TEXT,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_security_headers_proxy ON proxy_security_headers(proxy_host_id);

-- ============ Rate Limits ============

CREATE TABLE rate_limits (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    zone_name       VARCHAR(100) NOT NULL,
    requests_per    INTEGER NOT NULL,
    time_window     VARCHAR(10) NOT NULL,
    burst           INTEGER DEFAULT 50,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_rate_limits_proxy ON rate_limits(proxy_host_id);

-- ============ IP Rules ============

CREATE TABLE ip_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    ip_cidr         VARCHAR(50) NOT NULL,
    action          VARCHAR(10) NOT NULL CHECK (action IN ('allow', 'deny')),
    priority        INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ip_rules_proxy ON ip_rules(proxy_host_id);

-- ============ Containers ============

CREATE TABLE containers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    container_id    VARCHAR(64) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    image           VARCHAR(500) NOT NULL,
    stack_name      VARCHAR(255),
    status          VARCHAR(50),
    cpu_percent     DECIMAL(5,2),
    memory_mb       INTEGER,
    memory_limit_mb INTEGER,
    restart_count   INTEGER DEFAULT 0,
    container_created_at TIMESTAMPTZ,
    last_synced_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, container_id)
);

CREATE INDEX idx_containers_agent ON containers(agent_id);
CREATE INDEX idx_containers_status ON containers(status);
CREATE INDEX idx_containers_stack ON containers(stack_name);

-- ============ Container Upstreams ============

CREATE TABLE container_upstreams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    container_id    UUID NOT NULL REFERENCES containers(id) ON DELETE CASCADE,
    container_port  INTEGER NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(proxy_host_id, container_id, container_port)
);

CREATE INDEX idx_container_upstreams_proxy ON container_upstreams(proxy_host_id);
CREATE INDEX idx_container_upstreams_container ON container_upstreams(container_id);

-- ============ Alert Channels ============

CREATE TABLE alert_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    channel_type    VARCHAR(50) NOT NULL CHECK (channel_type IN ('smtp', 'slack', 'webhook')),
    config          JSONB NOT NULL,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_alert_channels_org ON alert_channels(org_id);

-- ============ Alert Rules ============

CREATE TABLE alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    rule_type       VARCHAR(50) NOT NULL,
    conditions      JSONB NOT NULL,
    channels        UUID[] NOT NULL,
    cooldown_mins   INTEGER DEFAULT 15,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_alert_rules_org ON alert_rules(org_id);
CREATE INDEX idx_alert_rules_type ON alert_rules(rule_type);

-- ============ Alert History ============

CREATE TABLE alert_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID REFERENCES alert_rules(id) ON DELETE SET NULL,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    triggered_at    TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    severity        VARCHAR(20),
    message         TEXT,
    metadata        JSONB
);

CREATE INDEX idx_alert_history_rule ON alert_history(rule_id, triggered_at DESC);
CREATE INDEX idx_alert_history_agent ON alert_history(agent_id, triggered_at DESC);

-- ============ Monitored Databases ============

CREATE TABLE monitored_databases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    db_type         VARCHAR(50) NOT NULL CHECK (db_type IN ('postgresql', 'mysql', 'redis')),
    host            VARCHAR(255) NOT NULL,
    port            INTEGER NOT NULL,
    username        VARCHAR(255),
    password_enc    BYTEA,
    ssl_mode        VARCHAR(50),
    last_check_at   TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'unknown',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_monitored_databases_agent ON monitored_databases(agent_id);

-- ============ Database Metrics ============

CREATE TABLE database_metrics (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    db_id           UUID NOT NULL REFERENCES monitored_databases(id) ON DELETE CASCADE,
    recorded_at     TIMESTAMPTZ DEFAULT NOW(),
    connections     INTEGER,
    disk_usage_mb   BIGINT,
    slow_queries    INTEGER,
    metrics_json    JSONB
);

CREATE INDEX idx_database_metrics_db ON database_metrics(db_id, recorded_at DESC);

-- ============ Audit Logs ============

CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id) ON DELETE SET NULL,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(100),
    resource_id     UUID,
    ip_address      INET,
    user_agent      TEXT,
    request_body    JSONB,
    response_status INTEGER,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_org_created ON audit_logs(org_id, created_at DESC);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action, created_at DESC);

-- ============ Updated At Trigger ============

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_agents_updated_at BEFORE UPDATE ON agents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_proxy_hosts_updated_at BEFORE UPDATE ON proxy_hosts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_proxy_security_headers_updated_at BEFORE UPDATE ON proxy_security_headers
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_rate_limits_updated_at BEFORE UPDATE ON rate_limits
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alert_channels_updated_at BEFORE UPDATE ON alert_channels
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alert_rules_updated_at BEFORE UPDATE ON alert_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_monitored_databases_updated_at BEFORE UPDATE ON monitored_databases
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
