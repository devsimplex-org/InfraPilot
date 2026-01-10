-- Migration: 008_default_pages
-- Description: Default pages configuration (welcome, error pages)

CREATE TABLE IF NOT EXISTS default_pages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    page_type       VARCHAR(50) NOT NULL,
    enabled         BOOLEAN DEFAULT FALSE,
    title           VARCHAR(255),
    heading         VARCHAR(255),
    message         TEXT,
    show_logo       BOOLEAN DEFAULT TRUE,
    custom_css      TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, page_type),
    CHECK (page_type IN ('welcome', '404', '502', '503', '500', 'maintenance'))
);

CREATE INDEX IF NOT EXISTS idx_default_pages_org ON default_pages(org_id);

-- Trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION update_default_pages_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_default_pages_updated_at ON default_pages;
CREATE TRIGGER update_default_pages_updated_at
    BEFORE UPDATE ON default_pages
    FOR EACH ROW
    EXECUTE FUNCTION update_default_pages_updated_at();
