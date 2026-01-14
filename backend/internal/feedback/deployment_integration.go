package feedback

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// DeploymentIntegration handles feedback generation for deployments
type DeploymentIntegration struct {
	db       *pgxpool.Pool
	manager  *FeedbackManager
	renderer *TemplateRenderer
	logger   *zap.Logger
}

// GetManager returns the feedback manager
func (di *DeploymentIntegration) GetManager() *FeedbackManager {
	return di.manager
}

// NewDeploymentIntegration creates a new deployment integration
func NewDeploymentIntegration(db *pgxpool.Pool, manager *FeedbackManager, renderer *TemplateRenderer, logger *zap.Logger) *DeploymentIntegration {
	return &DeploymentIntegration{
		db:       db,
		manager:  manager,
		renderer: renderer,
		logger:   logger,
	}
}

// GenerateFeedbackForDeployment generates feedback for a deployment based on policy decision
func (di *DeploymentIntegration) GenerateFeedbackForDeployment(ctx context.Context, deploymentID uuid.UUID) error {
	// Get deployment details with policy decision
	var deployment struct {
		OrgID          uuid.UUID
		PolicyDecision string
		PolicyReason   *string
		ScanResultID   *uuid.UUID
		GitRepo        *string
		GitBranch      *string
		GitCommit      *string
		GitPR          *int
	}

	query := `
		SELECT org_id, policy_decision, policy_reason, scan_result_id,
		       git_repo, git_branch, git_commit, git_pr_number
		FROM deployments
		WHERE id = $1
	`

	err := di.db.QueryRow(ctx, query, deploymentID).Scan(
		&deployment.OrgID,
		&deployment.PolicyDecision,
		&deployment.PolicyReason,
		&deployment.ScanResultID,
		&deployment.GitRepo,
		&deployment.GitBranch,
		&deployment.GitCommit,
		&deployment.GitPR,
	)
	if err != nil {
		return fmt.Errorf("failed to get deployment: %w", err)
	}

	// Only generate feedback if policy denied
	if deployment.PolicyDecision != "deny" {
		di.logger.Debug("deployment allowed, skipping feedback",
			zap.String("deployment_id", deploymentID.String()),
		)
		return nil
	}

	// Check if we have git metadata
	if deployment.GitRepo == nil {
		di.logger.Warn("no git repo metadata, cannot generate feedback",
			zap.String("deployment_id", deploymentID.String()),
		)
		return nil
	}

	// Parse repo to get provider
	// Assume GitHub for now (format: github.com/owner/repo or owner/repo)
	provider := ProviderGitHub
	repoFullName := di.extractRepoFullName(*deployment.GitRepo)

	// Check if VCS configuration exists and is enabled
	config, err := di.manager.GetConfiguration(ctx, deployment.OrgID, provider)
	if err != nil {
		di.logger.Warn("no VCS configuration found",
			zap.String("org_id", deployment.OrgID.String()),
			zap.String("provider", string(provider)),
		)
		return nil // Don't fail deployment, just skip feedback
	}

	if !config.Enabled || !config.AutoCommentOnPR {
		di.logger.Debug("VCS feedback disabled",
			zap.String("org_id", deployment.OrgID.String()),
		)
		return nil
	}

	// Generate feedback for policy violation
	if err := di.generatePolicyViolationFeedback(ctx, deployment.OrgID, deploymentID, provider, repoFullName, deployment.GitPR, deployment.GitCommit, deployment.PolicyReason); err != nil {
		di.logger.Error("failed to generate policy violation feedback", zap.Error(err))
	}

	// Generate feedback for critical vulnerabilities
	if deployment.ScanResultID != nil {
		if err := di.generateVulnerabilityFeedback(ctx, deployment.OrgID, deploymentID, *deployment.ScanResultID, provider, repoFullName, deployment.GitPR, deployment.GitCommit); err != nil {
			di.logger.Error("failed to generate vulnerability feedback", zap.Error(err))
		}
	}

	return nil
}

// generatePolicyViolationFeedback creates feedback for policy violation
func (di *DeploymentIntegration) generatePolicyViolationFeedback(ctx context.Context, orgID, deploymentID uuid.UUID, provider Provider, repoFullName string, prNumber *int, commitSHA *string, policyReason *string) error {
	// Prepare template data
	data := &PolicyViolationTemplateData{
		PolicyName: "Deployment Security Policy",
		Severity:   "high",
		Decision:   "deny",
		Reason:     "Deployment blocked due to security policy violation",
	}

	if policyReason != nil {
		data.Reason = *policyReason
	}

	// Render feedback content
	content, err := di.renderer.RenderPolicyViolationFeedback(ctx, orgID, data)
	if err != nil {
		return fmt.Errorf("failed to render policy violation feedback: %w", err)
	}

	// Create feedback target
	target := Target{
		Provider:     provider,
		RepoFullName: repoFullName,
		PullRequest:  prNumber,
		CommitSHA:    commitSHA,
	}

	// Create feedback entry
	feedback := &Feedback{
		OrgID:    orgID,
		SourceID: deploymentID,
		Type:     SourcePolicyViolation,
		Target:   target,
		Content:  *content,
		Status:   StatusPending,
		Metadata: map[string]interface{}{
			"deployment_id": deploymentID.String(),
			"policy_reason": data.Reason,
		},
	}

	if err := di.manager.CreateFeedback(ctx, feedback); err != nil {
		return fmt.Errorf("failed to create policy violation feedback: %w", err)
	}

	di.logger.Info("created policy violation feedback",
		zap.String("feedback_id", feedback.ID.String()),
		zap.String("repo", repoFullName),
	)

	return nil
}

// generateVulnerabilityFeedback creates feedback for critical/high vulnerabilities
func (di *DeploymentIntegration) generateVulnerabilityFeedback(ctx context.Context, orgID, deploymentID, scanResultID uuid.UUID, provider Provider, repoFullName string, prNumber *int, commitSHA *string) error {
	// Get top critical/high vulnerabilities
	query := `
		SELECT cve_id, severity, package_name, package_version, fixed_version, description
		FROM vulnerabilities
		WHERE scan_result_id = $1
		  AND severity IN ('critical', 'high')
		ORDER BY
		  CASE severity
		    WHEN 'critical' THEN 1
		    WHEN 'high' THEN 2
		  END,
		  cve_id
		LIMIT 5
	`

	rows, err := di.db.Query(ctx, query, scanResultID)
	if err != nil {
		return fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	vulnCount := 0
	for rows.Next() {
		var vuln struct {
			CVEID          string
			Severity       string
			PackageName    string
			PackageVersion string
			FixedVersion   *string
			Description    string
		}

		if err := rows.Scan(&vuln.CVEID, &vuln.Severity, &vuln.PackageName, &vuln.PackageVersion, &vuln.FixedVersion, &vuln.Description); err != nil {
			di.logger.Warn("failed to scan vulnerability", zap.Error(err))
			continue
		}

		// Prepare template data
		data := &VulnerabilityTemplateData{
			CVEID:               vuln.CVEID,
			Severity:            vuln.Severity,
			PackageName:         vuln.PackageName,
			PackageVersion:      vuln.PackageVersion,
			FixedVersion:        vuln.FixedVersion,
			Description:         vuln.Description,
			AffectedDeployments: 1, // Just this deployment for now
		}

		// Render feedback content
		content, err := di.renderer.RenderVulnerabilityFeedback(ctx, orgID, data)
		if err != nil {
			di.logger.Error("failed to render vulnerability feedback", zap.Error(err))
			continue
		}

		// Create feedback target
		target := Target{
			Provider:     provider,
			RepoFullName: repoFullName,
			PullRequest:  prNumber,
			CommitSHA:    commitSHA,
		}

		// Create feedback entry
		feedback := &Feedback{
			OrgID:    orgID,
			SourceID: deploymentID,
			Type:     SourceVulnerability,
			Target:   target,
			Content:  *content,
			Status:   StatusPending,
			Metadata: map[string]interface{}{
				"deployment_id": deploymentID.String(),
				"cve_id":        vuln.CVEID,
				"package_name":  vuln.PackageName,
				"severity":      vuln.Severity,
			},
		}

		if err := di.manager.CreateFeedback(ctx, feedback); err != nil {
			di.logger.Error("failed to create vulnerability feedback", zap.Error(err))
			continue
		}

		di.logger.Info("created vulnerability feedback",
			zap.String("feedback_id", feedback.ID.String()),
			zap.String("cve_id", vuln.CVEID),
			zap.String("repo", repoFullName),
		)

		vulnCount++
	}

	di.logger.Info("generated vulnerability feedback",
		zap.Int("count", vulnCount),
		zap.String("deployment_id", deploymentID.String()),
	)

	return nil
}

// extractRepoFullName extracts "owner/repo" from various git repo formats
func (di *DeploymentIntegration) extractRepoFullName(gitRepo string) string {
	// Handle various formats:
	// - https://github.com/owner/repo.git
	// - git@github.com:owner/repo.git
	// - github.com/owner/repo
	// - owner/repo

	// Remove .git suffix
	repo := strings.TrimSuffix(gitRepo, ".git")

	// Extract path from URL
	if strings.Contains(repo, "://") {
		// https://github.com/owner/repo -> owner/repo
		parts := strings.Split(repo, "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2] + "/" + parts[len(parts)-1]
		}
	} else if strings.Contains(repo, "@") && strings.Contains(repo, ":") {
		// git@github.com:owner/repo -> owner/repo
		parts := strings.Split(repo, ":")
		if len(parts) == 2 {
			return parts[1]
		}
	} else if strings.Contains(repo, "/") {
		// github.com/owner/repo -> owner/repo or owner/repo -> owner/repo
		parts := strings.Split(repo, "/")
		if len(parts) >= 2 {
			return parts[len(parts)-2] + "/" + parts[len(parts)-1]
		}
	}

	// Fallback: return as-is
	return repo
}

// DeliverPendingFeedback delivers all pending feedback (call from a cron job)
func (di *DeploymentIntegration) DeliverPendingFeedback(ctx context.Context) error {
	return di.manager.DeliverAll(ctx)
}

// ParseGitPRNumber extracts PR number from git branch name or PR reference
// Examples:
//   - "refs/pull/123/head" -> 123
//   - "pr-123" -> 123
//   - "feature/pr-123" -> 123
func ParseGitPRNumber(ref string) *int {
	// Handle refs/pull/123/head format (GitHub)
	if strings.HasPrefix(ref, "refs/pull/") && strings.HasSuffix(ref, "/head") {
		parts := strings.Split(ref, "/")
		if len(parts) >= 3 {
			if num, err := strconv.Atoi(parts[2]); err == nil {
				return &num
			}
		}
	}

	// Handle pr-123 or PR-123 format
	if strings.Contains(strings.ToLower(ref), "pr-") {
		parts := strings.Split(strings.ToLower(ref), "pr-")
		if len(parts) >= 2 {
			// Extract just the number part
			numStr := strings.Split(parts[1], "-")[0]
			numStr = strings.Split(numStr, "/")[0]
			if num, err := strconv.Atoi(numStr); err == nil {
				return &num
			}
		}
	}

	return nil
}
