package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/policy"
)

// ==================== Types ====================

type DeploymentStatus string
type PolicyDecision string

const (
	StatusPending     DeploymentStatus = "pending"
	StatusScanning    DeploymentStatus = "scanning"
	StatusPolicyCheck DeploymentStatus = "policy_check"
	StatusDeploying   DeploymentStatus = "deploying"
	StatusRunning     DeploymentStatus = "running"
	StatusFailed      DeploymentStatus = "failed"
	StatusRolledBack  DeploymentStatus = "rolled_back"
	StatusStopped     DeploymentStatus = "stopped"

	DecisionAllow PolicyDecision = "allow"
	DecisionWarn  PolicyDecision = "warn"
	DecisionDeny  PolicyDecision = "deny"
)

type Deployment struct {
	ID               uuid.UUID       `json:"id"`
	OrgID            uuid.UUID       `json:"org_id"`
	AgentID          uuid.UUID       `json:"agent_id"`
	ServiceName      string          `json:"service_name"`
	Environment      string          `json:"environment"`
	ImageRegistry    *string         `json:"image_registry,omitempty"`
	ImageRepository  string          `json:"image_repository"`
	ImageTag         *string         `json:"image_tag,omitempty"`
	ImageDigest      *string         `json:"image_digest,omitempty"`
	GitRepo          *string         `json:"git_repo,omitempty"`
	GitBranch        *string         `json:"git_branch,omitempty"`
	GitCommit        *string         `json:"git_commit,omitempty"`
	CIProvider       *string         `json:"ci_provider,omitempty"`
	CIPipelineID     *string         `json:"ci_pipeline_id,omitempty"`
	CIBuildURL       *string         `json:"ci_build_url,omitempty"`
	ScanResultID     *uuid.UUID      `json:"scan_result_id,omitempty"`
	SBOMID           *uuid.UUID      `json:"sbom_id,omitempty"`
	PolicyDecision   PolicyDecision  `json:"policy_decision"`
	PolicyReason     *string         `json:"policy_reason,omitempty"`
	Status           DeploymentStatus `json:"status"`
	StatusMessage    *string         `json:"status_message,omitempty"`
	ContainerID      *string         `json:"container_id,omitempty"`
	ContainerName    *string         `json:"container_name,omitempty"`
	ProxyHostID      *uuid.UUID      `json:"proxy_host_id,omitempty"`
	DeployedBy       *uuid.UUID      `json:"deployed_by,omitempty"`
	DeployedAt       *time.Time      `json:"deployed_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

type CreateDeploymentRequest struct {
	ServiceName     string  `json:"service_name" binding:"required"`
	Environment     string  `json:"environment" binding:"required,oneof=dev staging prod"`
	ImageRepository string  `json:"image_repository" binding:"required"`
	ImageTag        *string `json:"image_tag"`
	ImageDigest     *string `json:"image_digest"`
	GitRepo         *string `json:"git_repo"`
	GitBranch       *string `json:"git_branch"`
	GitCommit       *string `json:"git_commit"`
	GitPRNumber     *int    `json:"git_pr_number"`
	CIProvider      *string `json:"ci_provider"`
	CIPipelineID    *string `json:"ci_pipeline_id"`
	CIBuildURL      *string `json:"ci_build_url"`
}

// ==================== List Deployments ====================

func (h *Handler) listDeployments(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentID := c.Param("id")

	// Parse query parameters for filtering
	service := c.Query("service")
	environment := c.Query("environment")
	status := c.Query("status")

	query := `
		SELECT id, org_id, agent_id, service_name, environment,
		       image_registry, image_repository, image_tag, image_digest,
		       git_repo, git_branch, git_commit,
		       ci_provider, ci_pipeline_id, ci_build_url,
		       scan_result_id, sbom_id,
		       policy_decision, policy_reason,
		       status, status_message,
		       container_id, container_name, proxy_host_id,
		       deployed_by, deployed_at, created_at, updated_at
		FROM deployments
		WHERE org_id = $1 AND agent_id = $2
	`
	args := []interface{}{orgID, agentID}
	argIdx := 3

	if service != "" {
		query += fmt.Sprintf(" AND service_name = $%d", argIdx)
		args = append(args, service)
		argIdx++
	}
	if environment != "" {
		query += fmt.Sprintf(" AND environment = $%d", argIdx)
		args = append(args, environment)
		argIdx++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, status)
		argIdx++
	}

	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list deployments", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list deployments"})
		return
	}
	defer rows.Close()

	deployments := []Deployment{}
	for rows.Next() {
		var d Deployment
		if err := rows.Scan(
			&d.ID, &d.OrgID, &d.AgentID, &d.ServiceName, &d.Environment,
			&d.ImageRegistry, &d.ImageRepository, &d.ImageTag, &d.ImageDigest,
			&d.GitRepo, &d.GitBranch, &d.GitCommit,
			&d.CIProvider, &d.CIPipelineID, &d.CIBuildURL,
			&d.ScanResultID, &d.SBOMID,
			&d.PolicyDecision, &d.PolicyReason,
			&d.Status, &d.StatusMessage,
			&d.ContainerID, &d.ContainerName, &d.ProxyHostID,
			&d.DeployedBy, &d.DeployedAt, &d.CreatedAt, &d.UpdatedAt,
		); err != nil {
			h.logger.Warn("Failed to scan deployment", zap.Error(err))
			continue
		}
		deployments = append(deployments, d)
	}

	c.JSON(http.StatusOK, deployments)
}

// ==================== Get Deployment ====================

func (h *Handler) getDeployment(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentID := c.Param("id")
	deploymentID := c.Param("did")

	var d Deployment
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, agent_id, service_name, environment,
		       image_registry, image_repository, image_tag, image_digest,
		       git_repo, git_branch, git_commit,
		       ci_provider, ci_pipeline_id, ci_build_url,
		       scan_result_id, sbom_id,
		       policy_decision, policy_reason,
		       status, status_message,
		       container_id, container_name, proxy_host_id,
		       deployed_by, deployed_at, created_at, updated_at
		FROM deployments
		WHERE id = $1 AND org_id = $2 AND agent_id = $3
	`, deploymentID, orgID, agentID).Scan(
		&d.ID, &d.OrgID, &d.AgentID, &d.ServiceName, &d.Environment,
		&d.ImageRegistry, &d.ImageRepository, &d.ImageTag, &d.ImageDigest,
		&d.GitRepo, &d.GitBranch, &d.GitCommit,
		&d.CIProvider, &d.CIPipelineID, &d.CIBuildURL,
		&d.ScanResultID, &d.SBOMID,
		&d.PolicyDecision, &d.PolicyReason,
		&d.Status, &d.StatusMessage,
		&d.ContainerID, &d.ContainerName, &d.ProxyHostID,
		&d.DeployedBy, &d.DeployedAt, &d.CreatedAt, &d.UpdatedAt,
	)

	if err != nil {
		h.logger.Error("Failed to get deployment", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "deployment not found"})
		return
	}

	c.JSON(http.StatusOK, d)
}

// ==================== Create Deployment ====================

func (h *Handler) createDeployment(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentID := c.Param("id")

	var req CreateDeploymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify agent exists and belongs to org
	var exists bool
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)
	`, agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	var deploymentID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO deployments (
			org_id, agent_id, service_name, environment,
			image_repository, image_tag, image_digest,
			git_repo, git_branch, git_commit, git_pr_number,
			ci_provider, ci_pipeline_id, ci_build_url,
			deployed_by, status
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'pending')
		RETURNING id
	`, orgID, agentID, req.ServiceName, req.Environment,
		req.ImageRepository, req.ImageTag, req.ImageDigest,
		req.GitRepo, req.GitBranch, req.GitCommit, req.GitPRNumber,
		req.CIProvider, req.CIPipelineID, req.CIBuildURL,
		userID,
	).Scan(&deploymentID)

	if err != nil {
		h.logger.Error("Failed to create deployment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create deployment"})
		return
	}

	h.logger.Info("Deployment created",
		zap.String("deployment_id", deploymentID.String()),
		zap.String("service", req.ServiceName),
		zap.String("environment", req.Environment),
	)

	// Trigger deployment pipeline asynchronously
	imageTag := ""
	if req.ImageTag != nil {
		imageTag = *req.ImageTag
	}
	imageDigest := ""
	if req.ImageDigest != nil {
		imageDigest = *req.ImageDigest
	}
	// Use background context for async pipeline (request context will be canceled)
	go h.runDeploymentPipeline(context.Background(), orgID, deploymentID, req.ImageRepository, imageTag, imageDigest)

	c.JSON(http.StatusCreated, gin.H{
		"id":      deploymentID,
		"status":  "pending",
		"message": "Deployment created and scanning initiated",
	})
}

// ==================== Deployment Pipeline ====================

func (h *Handler) runDeploymentPipeline(ctx context.Context, orgID, deploymentID uuid.UUID, imageRepo, imageTag, imageDigest string) {
	logger := h.logger.With(
		zap.String("deployment_id", deploymentID.String()),
		zap.String("org_id", orgID.String()),
	)

	// Build full image reference
	imageRef := imageRepo
	if imageTag != "" {
		imageRef = imageRepo + ":" + imageTag
	} else if imageDigest != "" {
		imageRef = imageRepo + "@" + imageDigest
	}

	logger.Info("Starting deployment pipeline", zap.String("image", imageRef))

	// Step 1: Update status to scanning
	if err := h.updateDeploymentStatus(ctx, deploymentID.String(), "scanning", "Scanning image for vulnerabilities"); err != nil {
		logger.Error("Failed to update deployment status", zap.Error(err))
		return
	}

	// Step 2: Scan image with Trivy
	logger.Info("Scanning image for vulnerabilities")
	scanResult, err := h.scanner.ScanImage(ctx, imageRef)
	if err != nil {
		logger.Error("Image scan failed", zap.Error(err))
		h.updateDeploymentStatus(ctx, deploymentID.String(), "failed", "Image scan failed: "+err.Error())
		return
	}

	// Store scan result
	var scanID uuid.UUID
	err = h.db.QueryRow(ctx, `
		INSERT INTO scan_results (
			org_id, image_digest, image_repository, image_tag,
			critical_count, high_count, medium_count, low_count, unknown_count,
			total_count, fixable_count,
			scanner_name, scan_duration_ms, raw_output
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`, orgID, scanResult.ImageDigest, scanResult.ImageRepository, scanResult.ImageTag,
		scanResult.CriticalCount, scanResult.HighCount, scanResult.MediumCount,
		scanResult.LowCount, scanResult.UnknownCount,
		scanResult.TotalCount, scanResult.FixableCount,
		"trivy", scanResult.ScanDuration.Milliseconds(), scanResult.RawOutput,
	).Scan(&scanID)

	if err != nil {
		logger.Error("Failed to store scan result", zap.Error(err))
		h.updateDeploymentStatus(ctx, deploymentID.String(), "failed", "Failed to store scan result")
		return
	}

	logger.Info("Scan completed",
		zap.String("scan_id", scanID.String()),
		zap.Int("total_vulns", scanResult.TotalCount),
		zap.Int("critical", scanResult.CriticalCount),
	)

	// Store individual vulnerabilities
	for _, vuln := range scanResult.Vulnerabilities {
		_, err = h.db.Exec(ctx, `
			INSERT INTO vulnerabilities (
				scan_result_id, cve_id, severity,
				package_name, package_version, package_type,
				fixed_version, fix_available,
				title, description, cvss_v3_score, cvss_v3_vector,
				reference_urls
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		`, scanID, vuln.CVEID, strings.ToLower(vuln.Severity),
			vuln.PackageName, vuln.PackageVersion, vuln.PackageType,
			vuln.FixedVersion, vuln.FixAvailable,
			vuln.Title, vuln.Description, vuln.CVSSScore, vuln.CVSSVector,
			vuln.References,
		)
		if err != nil {
			logger.Warn("Failed to store vulnerability",
				zap.Error(err),
				zap.String("cve", vuln.CVEID),
			)
		}
	}

	// Step 3: Generate SBOM
	logger.Info("Generating SBOM")
	sbomResult, err := h.sbomGenerator.GenerateSBOM(ctx, imageRef)
	if err != nil {
		logger.Error("SBOM generation failed", zap.Error(err))
		// Continue deployment even if SBOM fails
	}

	var sbomID *uuid.UUID
	if sbomResult != nil {
		var sid uuid.UUID
		err = h.db.QueryRow(ctx, `
			INSERT INTO sboms (
				org_id, image_digest, image_repository,
				format, spec_version,
				total_packages, os_packages, library_packages,
				sbom_json, generator_name, generator_version
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			RETURNING id
		`, orgID, sbomResult.ImageDigest, sbomResult.ImageRepository,
			sbomResult.Format, sbomResult.SpecVersion,
			sbomResult.TotalPackages, sbomResult.OSPackages, sbomResult.LibraryPackages,
			sbomResult.Raw, sbomResult.GeneratorName, sbomResult.GeneratorVersion,
		).Scan(&sid)

		if err != nil {
			logger.Error("Failed to store SBOM", zap.Error(err))
		} else {
			sbomID = &sid
			logger.Info("SBOM generated", zap.String("sbom_id", sid.String()))
		}
	}

	// Step 4: Update deployment with scan results
	_, err = h.db.Exec(ctx, `
		UPDATE deployments
		SET scan_result_id = $1, sbom_id = $2, status = 'policy_check',
		    status_message = 'Evaluating security policy', updated_at = NOW()
		WHERE id = $3
	`, scanID, sbomID, deploymentID)

	if err != nil {
		logger.Error("Failed to update deployment with scan results", zap.Error(err))
		h.updateDeploymentStatus(ctx, deploymentID.String(), "failed", "Failed to update deployment")
		return
	}

	// Step 5: Policy evaluation with OPA
	logger.Info("Evaluating deployment policy")

	// Fetch deployment details for policy evaluation
	var deployment struct {
		ServiceName  string
		Environment  string
		ImageRepo    string
		ImageTag     string
		ImageDigest  string
		GitBranch    string
		GitCommit    string
	}
	err = h.db.QueryRow(ctx, `
		SELECT service_name, environment, image_repository,
		       COALESCE(image_tag, ''), COALESCE(image_digest, ''),
		       COALESCE(git_branch, ''), COALESCE(git_commit, '')
		FROM deployments WHERE id = $1
	`, deploymentID).Scan(
		&deployment.ServiceName, &deployment.Environment, &deployment.ImageRepo,
		&deployment.ImageTag, &deployment.ImageDigest,
		&deployment.GitBranch, &deployment.GitCommit,
	)
	if err != nil {
		logger.Error("Failed to fetch deployment for policy evaluation", zap.Error(err))
		h.updateDeploymentStatus(ctx, deploymentID.String(), "failed", "Failed to evaluate policy")
		return
	}

	// Prepare policy input
	policyInput := policy.PolicyInput{
		Deployment: policy.DeploymentInfo{
			ServiceName: deployment.ServiceName,
			Environment: deployment.Environment,
			ImageRepo:   deployment.ImageRepo,
			ImageTag:    deployment.ImageTag,
			ImageDigest: deployment.ImageDigest,
			GitBranch:   deployment.GitBranch,
			GitCommit:   deployment.GitCommit,
		},
		ScanResult: policy.ScanResultInfo{
			TotalCount:    scanResult.TotalCount,
			CriticalCount: scanResult.CriticalCount,
			HighCount:     scanResult.HighCount,
			MediumCount:   scanResult.MediumCount,
			LowCount:      scanResult.LowCount,
			FixableCount:  scanResult.FixableCount,
		},
		Vulnerabilities: []policy.VulnerabilityInfo{}, // Not needed for basic policy
	}

	// Evaluate policy
	policyResult, err := h.policyEngine.EvaluatePolicy(ctx, policyInput)
	if err != nil {
		logger.Error("Policy evaluation failed", zap.Error(err))
		// Fallback to deny on error
		policyResult = &policy.PolicyResult{
			Decision: "deny",
			Reason:   "Policy evaluation error: " + err.Error(),
		}
	}

	policyDecision := policyResult.Decision
	policyReason := policyResult.Reason

	logger.Info("Policy evaluation completed",
		zap.String("decision", policyDecision),
		zap.String("reason", policyReason),
	)

	_, err = h.db.Exec(ctx, `
		UPDATE deployments
		SET policy_decision = $1, policy_reason = $2,
		    status = 'deploying', status_message = 'Ready for deployment',
		    updated_at = NOW()
		WHERE id = $3
	`, policyDecision, policyReason, deploymentID)

	if err != nil {
		logger.Error("Failed to update deployment policy decision", zap.Error(err))
		return
	}

	logger.Info("Deployment pipeline completed",
		zap.String("policy_decision", policyDecision),
		zap.Int("total_vulns", scanResult.TotalCount),
	)

	// Epic 8: Generate developer feedback for policy violations
	if h.feedbackIntegration != nil {
		if err := h.feedbackIntegration.GenerateFeedbackForDeployment(ctx, deploymentID); err != nil {
			logger.Warn("Failed to generate developer feedback",
				zap.Error(err),
				zap.String("deployment_id", deploymentID.String()),
			)
			// Don't fail deployment on feedback generation errors
		}
	}

	// TODO: In Phase 4, actually deploy the container
	// For now, deployment stops at 'deploying' status
}

// ==================== Rollback Deployment ====================

func (h *Handler) rollbackDeployment(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentID := c.Param("id")
	deploymentID := c.Param("did")

	// Get deployment to rollback
	var serviceName, environment string
	var replacesDeploymentID *uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT service_name, environment, replaces_deployment_id
		FROM deployments
		WHERE id = $1 AND org_id = $2 AND agent_id = $3
	`, deploymentID, orgID, agentID).Scan(&serviceName, &environment, &replacesDeploymentID)

	if err != nil {
		h.logger.Error("Deployment not found for rollback", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "deployment not found"})
		return
	}

	if replacesDeploymentID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no previous deployment to rollback to"})
		return
	}

	// Create rollback deployment (copy from previous deployment)
	var newDeploymentID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO deployments (
			org_id, agent_id, service_name, environment,
			image_registry, image_repository, image_tag, image_digest,
			git_repo, git_branch, git_commit,
			rollback_of_deployment_id, deployed_by, status
		)
		SELECT
			org_id, agent_id, service_name, environment,
			image_registry, image_repository, image_tag, image_digest,
			git_repo, git_branch, git_commit,
			$1, $2, 'pending'
		FROM deployments
		WHERE id = $3
		RETURNING id
	`, deploymentID, userID, replacesDeploymentID).Scan(&newDeploymentID)

	if err != nil {
		h.logger.Error("Failed to create rollback deployment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rollback"})
		return
	}

	// Mark current deployment as rolled back
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE deployments
		SET status = 'rolled_back', status_message = 'Rolled back to previous deployment'
		WHERE id = $1
	`, deploymentID)

	if err != nil {
		h.logger.Warn("Failed to update original deployment status", zap.Error(err))
	}

	h.logger.Info("Rollback initiated",
		zap.String("original_deployment", deploymentID),
		zap.String("new_deployment", newDeploymentID.String()),
	)

	// TODO: In Phase 2, trigger deployment pipeline
	// go h.runDeploymentPipeline(orgID.String(), newDeploymentID.String())

	c.JSON(http.StatusOK, gin.H{
		"id":      newDeploymentID,
		"message": "Rollback initiated successfully",
	})
}

// ==================== Update Deployment Status ====================

func (h *Handler) updateDeploymentStatus(ctx context.Context, id, status, message string) error {
	_, err := h.db.Exec(ctx, `
		UPDATE deployments
		SET status = $1, status_message = $2, updated_at = NOW()
		WHERE id = $3
	`, status, message, id)

	if err != nil {
		h.logger.Error("Failed to update deployment status",
			zap.String("deployment_id", id),
			zap.String("status", status),
			zap.Error(err),
		)
	}

	return err
}

// ==================== List Services ====================

// listServices returns unique services across all agents
func (h *Handler) listServices(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT DISTINCT service_name, environment
		FROM deployments
		WHERE org_id = $1
		ORDER BY service_name, environment
	`, orgID)
	if err != nil {
		h.logger.Error("Failed to list services", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list services"})
		return
	}
	defer rows.Close()

	type ServiceEnv struct {
		Service     string `json:"service"`
		Environment string `json:"environment"`
	}

	services := []ServiceEnv{}
	for rows.Next() {
		var s ServiceEnv
		if err := rows.Scan(&s.Service, &s.Environment); err != nil {
			continue
		}
		services = append(services, s)
	}

	c.JSON(http.StatusOK, services)
}

// ==================== List Service Deployments ====================

func (h *Handler) listServiceDeployments(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	serviceName := c.Param("name")
	environment := c.Query("environment")

	query := `
		SELECT id, agent_id, environment, image_repository, image_tag,
		       git_commit, status, deployed_at, created_at
		FROM deployments
		WHERE org_id = $1 AND service_name = $2
	`
	args := []interface{}{orgID, serviceName}

	if environment != "" {
		query += " AND environment = $3"
		args = append(args, environment)
	}

	query += " ORDER BY created_at DESC LIMIT 50"

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list service deployments", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list deployments"})
		return
	}
	defer rows.Close()

	type ServiceDeployment struct {
		ID              uuid.UUID  `json:"id"`
		AgentID         uuid.UUID  `json:"agent_id"`
		Environment     string     `json:"environment"`
		ImageRepository string     `json:"image_repository"`
		ImageTag        *string    `json:"image_tag"`
		GitCommit       *string    `json:"git_commit"`
		Status          string     `json:"status"`
		DeployedAt      *time.Time `json:"deployed_at"`
		CreatedAt       time.Time  `json:"created_at"`
	}

	deployments := []ServiceDeployment{}
	for rows.Next() {
		var d ServiceDeployment
		if err := rows.Scan(&d.ID, &d.AgentID, &d.Environment,
			&d.ImageRepository, &d.ImageTag, &d.GitCommit,
			&d.Status, &d.DeployedAt, &d.CreatedAt); err != nil {
			continue
		}
		deployments = append(deployments, d)
	}

	c.JSON(http.StatusOK, deployments)
}

// ==================== Get Current Deployment ====================

func (h *Handler) getCurrentDeployment(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	serviceName := c.Param("name")
	environment := c.Query("environment")

	if environment == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "environment parameter is required"})
		return
	}

	var d Deployment
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, agent_id, service_name, environment,
		       image_repository, image_tag, image_digest,
		       git_commit, status, container_id, deployed_at, created_at
		FROM deployments
		WHERE org_id = $1 AND service_name = $2 AND environment = $3
		  AND status = 'running'
		ORDER BY deployed_at DESC
		LIMIT 1
	`, orgID, serviceName, environment).Scan(
		&d.ID, &d.OrgID, &d.AgentID, &d.ServiceName, &d.Environment,
		&d.ImageRepository, &d.ImageTag, &d.ImageDigest,
		&d.GitCommit, &d.Status, &d.ContainerID, &d.DeployedAt, &d.CreatedAt,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "no running deployment found"})
		return
	}

	c.JSON(http.StatusOK, d)
}
