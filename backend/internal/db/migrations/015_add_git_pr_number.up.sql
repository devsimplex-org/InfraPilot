-- Migration: 015_add_git_pr_number
-- Description: Add git_pr_number column to deployments for Epic 8 (Developer Feedback)

-- Add git_pr_number column to deployments table
ALTER TABLE deployments
    ADD COLUMN git_pr_number INTEGER;

-- Add index for PR-based queries
CREATE INDEX idx_deployments_git_pr ON deployments(git_pr_number) WHERE git_pr_number IS NOT NULL;

-- Comment
COMMENT ON COLUMN deployments.git_pr_number IS 'Pull request number for GitHub/GitLab PR-based deployments (used for developer feedback)';
