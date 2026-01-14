-- Migration: SSL Certificate Management
-- Adds support for external/wildcard certificates

-- Add certificate source tracking to proxy_hosts
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS ssl_source VARCHAR(20) DEFAULT 'letsencrypt';
-- Values: 'letsencrypt' (request new), 'external' (use existing path), 'wildcard' (use parent wildcard)

-- Add wildcard domain reference (e.g., 'integrio.live' for *.integrio.live)
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS ssl_wildcard_domain VARCHAR(255);

-- Create table for managing known/registered certificates
CREATE TABLE IF NOT EXISTS ssl_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,  -- e.g., 'integrio.live' for *.integrio.live wildcard
    is_wildcard BOOLEAN DEFAULT FALSE,
    cert_path VARCHAR(500) NOT NULL,
    key_path VARCHAR(500) NOT NULL,
    issuer VARCHAR(255),
    subject VARCHAR(255),
    san TEXT,  -- Subject Alternative Names (JSON array or comma-separated)
    expires_at TIMESTAMPTZ,
    auto_detected BOOLEAN DEFAULT FALSE,  -- True if found by auto-scan
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, cert_path)
);

-- Add reference to ssl_certificates from proxy_hosts
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS ssl_certificate_id UUID REFERENCES ssl_certificates(id) ON DELETE SET NULL;

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_ssl_certificates_org_id ON ssl_certificates(org_id);
CREATE INDEX IF NOT EXISTS idx_ssl_certificates_domain ON ssl_certificates(domain);
CREATE INDEX IF NOT EXISTS idx_proxy_hosts_ssl_certificate_id ON proxy_hosts(ssl_certificate_id);
