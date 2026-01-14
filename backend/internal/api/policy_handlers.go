package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/policy"
)

// ==================== Types ====================

type PolicyFile struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Content     string    `json:"content"`
	Size        int64     `json:"size"`
	ModifiedAt  time.Time `json:"modified_at"`
	IsDefault   bool      `json:"is_default"`
	Description string    `json:"description"`
}

type PolicyDecisionLog struct {
	ID              string    `json:"id"`
	DeploymentID    string    `json:"deployment_id"`
	ServiceName     string    `json:"service_name"`
	Environment     string    `json:"environment"`
	Decision        string    `json:"decision"`
	Reason          string    `json:"reason"`
	CriticalCount   int       `json:"critical_count"`
	HighCount       int       `json:"high_count"`
	TotalVulns      int       `json:"total_vulns"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
}

type PolicyEvaluationPreview struct {
	Decision string   `json:"decision"`
	Reason   string   `json:"reason"`
	Warnings []string `json:"warnings,omitempty"`
}

// ==================== List Policies ====================

func (h *Handler) listPolicies(c *gin.Context) {
	// Read policy files from /app/policies directory
	policyDir := "/app/policies"

	files, err := os.ReadDir(policyDir)
	if err != nil {
		h.logger.Error("Failed to read policy directory", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read policies"})
		return
	}

	policies := []PolicyFile{}
	for _, file := range files {
		if file.IsDir() || filepath.Ext(file.Name()) != ".rego" {
			continue
		}

		fullPath := filepath.Join(policyDir, file.Name())
		content, err := os.ReadFile(fullPath)
		if err != nil {
			h.logger.Warn("Failed to read policy file", zap.String("file", file.Name()), zap.Error(err))
			continue
		}

		info, _ := file.Info()

		policies = append(policies, PolicyFile{
			Name:        file.Name(),
			Path:        fullPath,
			Content:     string(content),
			Size:        info.Size(),
			ModifiedAt:  info.ModTime(),
			IsDefault:   file.Name() == "deployment.rego",
			Description: h.extractPolicyDescription(string(content)),
		})
	}

	c.JSON(http.StatusOK, policies)
}

// ==================== Get Policy ====================

func (h *Handler) getPolicy(c *gin.Context) {
	policyName := c.Param("name")

	if filepath.Ext(policyName) != ".rego" {
		policyName += ".rego"
	}

	policyPath := filepath.Join("/app/policies", policyName)

	content, err := os.ReadFile(policyPath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	info, err := os.Stat(policyPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get policy info"})
		return
	}

	policy := PolicyFile{
		Name:        policyName,
		Path:        policyPath,
		Content:     string(content),
		Size:        info.Size(),
		ModifiedAt:  info.ModTime(),
		IsDefault:   policyName == "deployment.rego",
		Description: h.extractPolicyDescription(string(content)),
	}

	c.JSON(http.StatusOK, policy)
}

// ==================== Update Policy ====================

func (h *Handler) updatePolicy(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	_ = orgID
	_ = userID

	policyName := c.Param("name")

	if filepath.Ext(policyName) != ".rego" {
		policyName += ".rego"
	}

	var req struct {
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	policyPath := filepath.Join("/app/policies", policyName)

	// Create backup
	backupPath := filepath.Join("/app/policies", "backups", policyName+"."+time.Now().Format("20060102-150405")+".bak")
	os.MkdirAll(filepath.Dir(backupPath), 0755)

	if existingContent, err := os.ReadFile(policyPath); err == nil {
		os.WriteFile(backupPath, existingContent, 0644)
	}

	// Write new policy
	if err := os.WriteFile(policyPath, []byte(req.Content), 0644); err != nil {
		h.logger.Error("Failed to write policy file", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}

	h.logger.Info("Policy updated",
		zap.String("policy", policyName),
		zap.String("user_id", userID.String()),
	)

	c.JSON(http.StatusOK, gin.H{
		"message":    "Policy updated successfully",
		"backup_path": backupPath,
	})
}

// ==================== Get Recent Policy Decisions ====================

func (h *Handler) listPolicyDecisions(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	limit := 50
	if l := c.Query("limit"); l != "" {
		if parsed, err := parseIntParam(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			d.id, d.service_name, d.environment,
			d.policy_decision, d.policy_reason,
			COALESCE(sr.critical_count, 0) as critical_count,
			COALESCE(sr.high_count, 0) as high_count,
			COALESCE(sr.total_count, 0) as total_count,
			d.updated_at
		FROM deployments d
		LEFT JOIN scan_results sr ON d.scan_result_id = sr.id
		WHERE d.org_id = $1 AND d.policy_decision IS NOT NULL
		ORDER BY d.updated_at DESC
		LIMIT $2
	`, orgID, limit)

	if err != nil {
		h.logger.Error("Failed to query policy decisions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve policy decisions"})
		return
	}
	defer rows.Close()

	decisions := []PolicyDecisionLog{}
	for rows.Next() {
		var d PolicyDecisionLog
		err := rows.Scan(
			&d.DeploymentID, &d.ServiceName, &d.Environment,
			&d.Decision, &d.Reason,
			&d.CriticalCount, &d.HighCount, &d.TotalVulns,
			&d.EvaluatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan policy decision", zap.Error(err))
			continue
		}
		decisions = append(decisions, d)
	}

	c.JSON(http.StatusOK, decisions)
}

// ==================== Preview Policy Evaluation ====================

func (h *Handler) previewPolicyEvaluation(c *gin.Context) {
	var input policy.PolicyInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.policyEngine.EvaluatePolicy(c.Request.Context(), input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Policy evaluation failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, PolicyEvaluationPreview{
		Decision: result.Decision,
		Reason:   result.Reason,
		Warnings: result.Warnings,
	})
}

// ==================== Get Policy Statistics ====================

func (h *Handler) getPolicyStats(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Get stats for last 30 days
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			policy_decision,
			COUNT(*) as count
		FROM deployments
		WHERE org_id = $1
			AND policy_decision IS NOT NULL
			AND created_at > NOW() - INTERVAL '30 days'
		GROUP BY policy_decision
	`, orgID)

	if err != nil {
		h.logger.Error("Failed to query policy stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve statistics"})
		return
	}
	defer rows.Close()

	stats := map[string]int{
		"allow": 0,
		"warn":  0,
		"deny":  0,
	}

	for rows.Next() {
		var decision string
		var count int
		if err := rows.Scan(&decision, &count); err != nil {
			continue
		}
		stats[decision] = count
	}

	total := stats["allow"] + stats["warn"] + stats["deny"]

	c.JSON(http.StatusOK, gin.H{
		"period": "last_30_days",
		"total":  total,
		"allow":  stats["allow"],
		"warn":   stats["warn"],
		"deny":   stats["deny"],
		"allow_percentage": percentage(stats["allow"], total),
		"warn_percentage":  percentage(stats["warn"], total),
		"deny_percentage":  percentage(stats["deny"], total),
	})
}

// ==================== Helper Functions ====================

func (h *Handler) extractPolicyDescription(content string) string {
	// Simple extraction of package description from comments
	lines := splitLines(content)
	for _, line := range lines {
		if len(line) > 2 && line[0] == '#' && line[1] == ' ' {
			return line[2:]
		}
	}
	return "Deployment security policy"
}

func splitLines(s string) []string {
	result := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

func percentage(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

func parseIntParam(s string) (int, error) {
	return strconv.Atoi(s)
}
