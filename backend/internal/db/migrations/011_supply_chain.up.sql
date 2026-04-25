-- Migration: 011_supply_chain
-- Description: Supply chain security with vulnerability scanning and SBOM
-- Epic 1: Supply Chain Security

-- ============ Enums ============

-- Severity level for vulnerabilities
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'unknown');

-- ============ Scan Results Table ============

CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Image information
    image_digest VARCHAR(255) NOT NULL,
    image_repository VARCHAR(255) NOT NULL,
    image_tag VARCHAR(255),

    -- Summary counts
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    unknown_count INTEGER NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,
    fixable_count INTEGER NOT NULL DEFAULT 0,

    -- Scanner info
    scanner_name VARCHAR(50) NOT NULL DEFAULT 'trivy',
    scanner_version VARCHAR(50),
    scan_duration_ms INTEGER,

    -- Raw output (JSON from Trivy)
    raw_output JSONB,

    scanned_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Vulnerabilities Table ============

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,

    -- CVE information
    cve_id VARCHAR(50) NOT NULL,
    severity severity_level NOT NULL,

    -- Package information
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100),
    package_type VARCHAR(50),

    -- Fix information
    fixed_version VARCHAR(100),
    fix_available BOOLEAN NOT NULL DEFAULT FALSE,

    -- Details
    title VARCHAR(500),
    description TEXT,
    reference_urls JSONB,

    -- CVSS scoring
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(100),

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ SBOM Table ============

CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Image information
    image_digest VARCHAR(255) NOT NULL,
    image_repository VARCHAR(255) NOT NULL,

    -- SBOM format
    format VARCHAR(20) NOT NULL CHECK (format IN ('cyclonedx', 'spdx')),
    spec_version VARCHAR(20) NOT NULL,

    -- Package counts
    total_packages INTEGER NOT NULL DEFAULT 0,
    os_packages INTEGER NOT NULL DEFAULT 0,
    library_packages INTEGER NOT NULL DEFAULT 0,

    -- Raw SBOM (full JSON)
    sbom_json JSONB NOT NULL,

    -- Generator information
    generator_name VARCHAR(50) NOT NULL DEFAULT 'syft',
    generator_version VARCHAR(50),

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Link Deployments to Security Artifacts ============

-- Add foreign key constraints to deployments table
-- (scan_result_id and sbom_id columns already exist from 010_deployments.up.sql)
ALTER TABLE deployments
    ADD CONSTRAINT fk_deployments_scan
        FOREIGN KEY (scan_result_id) REFERENCES scan_results(id) ON DELETE SET NULL;

ALTER TABLE deployments
    ADD CONSTRAINT fk_deployments_sbom
        FOREIGN KEY (sbom_id) REFERENCES sboms(id) ON DELETE SET NULL;

-- ============ Indexes ============

-- Scan results indexes
CREATE INDEX idx_scan_results_org ON scan_results(org_id);
CREATE INDEX idx_scan_results_image ON scan_results(image_digest);
CREATE INDEX idx_scan_results_repo ON scan_results(image_repository);
CREATE INDEX idx_scan_results_created ON scan_results(created_at DESC);

-- Vulnerabilities indexes
CREATE INDEX idx_vulnerabilities_scan ON vulnerabilities(scan_result_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_package ON vulnerabilities(package_name);

-- SBOM indexes
CREATE INDEX idx_sboms_org ON sboms(org_id);
CREATE INDEX idx_sboms_image ON sboms(image_digest);
CREATE INDEX idx_sboms_repo ON sboms(image_repository);
CREATE INDEX idx_sboms_created ON sboms(created_at DESC);

-- ============ Comments ============

COMMENT ON TABLE scan_results IS 'Vulnerability scan results from Trivy';
COMMENT ON TABLE vulnerabilities IS 'Individual vulnerabilities found in scans';
COMMENT ON TABLE sboms IS 'Software Bill of Materials (SBOM) in CycloneDX or SPDX format';

COMMENT ON COLUMN scan_results.raw_output IS 'Full Trivy JSON output for reference';
COMMENT ON COLUMN sboms.sbom_json IS 'Full SBOM in CycloneDX or SPDX JSON format';
