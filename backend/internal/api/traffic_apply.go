package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	trafficConfigDir    = "/data/nginx/conf.d"
	trafficConfigPrefix = "traffic_"
	stagingDir          = "/tmp/nginx_staging"
)

// ApplyTrafficRequest represents a request to apply a traffic resource
type ApplyTrafficRequest struct {
	Force bool `json:"force"` // Force apply even if validation has warnings
}

// ApplyTrafficResponse represents the response from apply/dry-run operations
type ApplyTrafficResponse struct {
	Success          bool                   `json:"success"`
	ResourceID       uuid.UUID              `json:"resource_id"`
	ResourceName     string                 `json:"resource_name"`
	Action           string                 `json:"action"` // "apply", "dry_run", "rollback"
	ValidationPassed bool                   `json:"validation_passed"`
	ValidationOutput string                 `json:"validation_output,omitempty"`
	Warnings         []string               `json:"warnings,omitempty"`
	Errors           []string               `json:"errors,omitempty"`
	ConfigHash       string                 `json:"config_hash,omitempty"`
	AppliedAt        *time.Time             `json:"applied_at,omitempty"`
	DurationMs       int64                  `json:"duration_ms"`
	NginxConfig      string                 `json:"nginx_config,omitempty"` // Included in dry-run
	Diff             map[string]interface{} `json:"diff,omitempty"`         // Config diff
}

// applyTrafficResource applies a traffic resource configuration to nginx
// POST /traffic/resources/:id/apply
func (h *Handler) applyTrafficResource(c *gin.Context) {
	startTime := time.Now()
	resourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	var req ApplyTrafficRequest
	c.ShouldBindJSON(&req)

	ctx := c.Request.Context()
	var userID *uuid.UUID
	if id, exists := c.Get("user_id"); exists {
		uid := id.(uuid.UUID)
		userID = &uid
	}

	// 1. Compile the traffic resource
	compiled, err := h.compileTrafficResource(ctx, resourceID)
	if err != nil {
		h.logger.Error("Failed to compile traffic resource", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Compilation failed: %v", err)})
		return
	}

	// 2. Write to staging and validate
	validationResult, err := h.validateNginxConfig(compiled)
	if err != nil {
		h.logger.Error("Failed to validate nginx config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Validation failed: %v", err)})
		return
	}

	if !validationResult.Passed && !req.Force {
		c.JSON(http.StatusBadRequest, ApplyTrafficResponse{
			Success:          false,
			ResourceID:       resourceID,
			ResourceName:     compiled.ResourceName,
			Action:           "apply",
			ValidationPassed: false,
			ValidationOutput: validationResult.Output,
			Errors:           validationResult.Errors,
			Warnings:         validationResult.Warnings,
			DurationMs:       time.Since(startTime).Milliseconds(),
		})
		return
	}

	// 3. Get previous state for history
	previousState, _ := h.getResourceAppliedState(ctx, resourceID)

	// 4. Apply the configuration
	configPath := filepath.Join(trafficConfigDir, fmt.Sprintf("%s%s.conf", trafficConfigPrefix, resourceID.String()))
	if err := os.WriteFile(configPath, []byte(compiled.NginxConfig), 0644); err != nil {
		h.logger.Error("Failed to write nginx config", zap.Error(err), zap.String("path", configPath))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write config: %v", err)})
		return
	}

	// 5. Reload nginx
	if err := h.doNginxReload(); err != nil {
		// Rollback - remove the config file
		os.Remove(configPath)
		h.logger.Error("Failed to reload nginx", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Nginx reload failed: %v", err)})
		return
	}

	// 6. Update resource status
	appliedAt := time.Now()
	appliedState := map[string]interface{}{
		"config_hash":  compiled.ConfigHash,
		"nginx_config": compiled.NginxConfig,
		"domains":      compiled.Domains,
		"upstreams":    compiled.Upstreams,
		"policies":     compiled.Policies,
	}

	_, err = h.db.Exec(ctx, `
		UPDATE traffic_resources
		SET status = 'active',
		    applied_state = $1,
		    last_applied_at = $2,
		    last_error = NULL,
		    updated_at = NOW()
		WHERE id = $3
	`, appliedState, appliedAt, resourceID)
	if err != nil {
		h.logger.Error("Failed to update resource status", zap.Error(err))
	}

	// 7. Record in history
	h.recordTrafficApplyHistory(ctx, resourceID, userID, "apply", previousState, appliedState, compiled.NginxConfig, compiled.ConfigHash, true, nil)

	c.JSON(http.StatusOK, ApplyTrafficResponse{
		Success:          true,
		ResourceID:       resourceID,
		ResourceName:     compiled.ResourceName,
		Action:           "apply",
		ValidationPassed: validationResult.Passed,
		ValidationOutput: validationResult.Output,
		Warnings:         validationResult.Warnings,
		ConfigHash:       compiled.ConfigHash,
		AppliedAt:        &appliedAt,
		DurationMs:       time.Since(startTime).Milliseconds(),
	})
}

// dryRunTrafficResource validates a traffic resource without applying
// POST /traffic/resources/:id/dry-run
func (h *Handler) dryRunTrafficResource(c *gin.Context) {
	startTime := time.Now()
	resourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	ctx := c.Request.Context()

	// 1. Compile the traffic resource
	compiled, err := h.compileTrafficResource(ctx, resourceID)
	if err != nil {
		h.logger.Error("Failed to compile traffic resource", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Compilation failed: %v", err)})
		return
	}

	// 2. Validate without applying
	validationResult, err := h.validateNginxConfig(compiled)
	if err != nil {
		h.logger.Error("Failed to validate nginx config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Validation failed: %v", err)})
		return
	}

	// 3. Get current config for diff
	currentConfig := ""
	configPath := filepath.Join(trafficConfigDir, fmt.Sprintf("%s%s.conf", trafficConfigPrefix, resourceID.String()))
	if data, err := os.ReadFile(configPath); err == nil {
		currentConfig = string(data)
	}

	// Calculate diff
	var diff map[string]interface{}
	if currentConfig != "" && currentConfig != compiled.NginxConfig {
		diff = map[string]interface{}{
			"has_changes": true,
			"current":     currentConfig,
			"proposed":    compiled.NginxConfig,
		}
	}

	c.JSON(http.StatusOK, ApplyTrafficResponse{
		Success:          validationResult.Passed,
		ResourceID:       resourceID,
		ResourceName:     compiled.ResourceName,
		Action:           "dry_run",
		ValidationPassed: validationResult.Passed,
		ValidationOutput: validationResult.Output,
		Warnings:         validationResult.Warnings,
		Errors:           validationResult.Errors,
		ConfigHash:       compiled.ConfigHash,
		DurationMs:       time.Since(startTime).Milliseconds(),
		NginxConfig:      compiled.NginxConfig,
		Diff:             diff,
	})
}

// rollbackTrafficResource rolls back to a previous configuration
// POST /traffic/resources/:id/rollback
func (h *Handler) rollbackTrafficResource(c *gin.Context) {
	startTime := time.Now()
	resourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	ctx := c.Request.Context()
	var userID *uuid.UUID
	if id, exists := c.Get("user_id"); exists {
		uid := id.(uuid.UUID)
		userID = &uid
	}

	// 1. Get the previous successful apply from history
	var historyID uuid.UUID
	var previousStateJSON []byte
	var previousConfig string

	err = h.db.QueryRow(ctx, `
		SELECT id, previous_state, rendered_nginx_config
		FROM traffic_apply_history
		WHERE traffic_resource_id = $1
		  AND success = TRUE
		  AND action = 'apply'
		ORDER BY applied_at DESC
		LIMIT 1 OFFSET 1
	`, resourceID).Scan(&historyID, &previousStateJSON, &previousConfig)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No previous configuration found to rollback to"})
		return
	}

	if previousConfig == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Previous configuration is empty"})
		return
	}

	// 2. Get current state for history
	currentState, _ := h.getResourceAppliedState(ctx, resourceID)

	// 3. Apply the previous configuration
	configPath := filepath.Join(trafficConfigDir, fmt.Sprintf("%s%s.conf", trafficConfigPrefix, resourceID.String()))
	if err := os.WriteFile(configPath, []byte(previousConfig), 0644); err != nil {
		h.logger.Error("Failed to write nginx config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to write config: %v", err)})
		return
	}

	// 4. Reload nginx
	if err := h.doNginxReload(); err != nil {
		h.logger.Error("Failed to reload nginx", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Nginx reload failed: %v", err)})
		return
	}

	// 5. Update resource status
	appliedAt := time.Now()
	var previousState map[string]interface{}
	if len(previousStateJSON) > 0 {
		json.Unmarshal(previousStateJSON, &previousState)
	}

	_, err = h.db.Exec(ctx, `
		UPDATE traffic_resources
		SET status = 'active',
		    applied_state = $1,
		    last_applied_at = $2,
		    last_error = NULL,
		    updated_at = NOW()
		WHERE id = $3
	`, previousState, appliedAt, resourceID)
	if err != nil {
		h.logger.Error("Failed to update resource status", zap.Error(err))
	}

	// 6. Record rollback in history
	h.recordTrafficApplyHistory(ctx, resourceID, userID, "rollback", currentState, previousState, previousConfig, "", true, nil)

	c.JSON(http.StatusOK, ApplyTrafficResponse{
		Success:      true,
		ResourceID:   resourceID,
		Action:       "rollback",
		AppliedAt:    &appliedAt,
		DurationMs:   time.Since(startTime).Milliseconds(),
		NginxConfig:  previousConfig,
	})
}

// removeTrafficConfig removes the nginx config for a traffic resource
// Called when a traffic resource is deleted
func (h *Handler) removeTrafficConfig(resourceID uuid.UUID) error {
	configPath := filepath.Join(trafficConfigDir, fmt.Sprintf("%s%s.conf", trafficConfigPrefix, resourceID.String()))

	// Check if config exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil // Config doesn't exist, nothing to remove
	}

	// Remove the config file
	if err := os.Remove(configPath); err != nil {
		return fmt.Errorf("failed to remove config: %w", err)
	}

	// Reload nginx
	return h.doNginxReload()
}

// ValidationResult represents the result of nginx config validation
type ValidationResult struct {
	Passed   bool     `json:"passed"`
	Output   string   `json:"output"`
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

// validateNginxConfig validates the nginx configuration
func (h *Handler) validateNginxConfig(compiled *CompiledTrafficConfig) (*ValidationResult, error) {
	// Ensure staging directory exists
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create staging dir: %w", err)
	}

	// Write config to staging
	stagingPath := filepath.Join(stagingDir, fmt.Sprintf("%s%s.conf", trafficConfigPrefix, compiled.ResourceID.String()))
	if err := os.WriteFile(stagingPath, []byte(compiled.NginxConfig), 0644); err != nil {
		return nil, fmt.Errorf("failed to write staging config: %w", err)
	}
	defer os.Remove(stagingPath)

	// Also write to the actual location temporarily for include testing
	configPath := filepath.Join(trafficConfigDir, fmt.Sprintf("%s%s.conf.staging", trafficConfigPrefix, compiled.ResourceID.String()))
	if err := os.WriteFile(configPath, []byte(compiled.NginxConfig), 0644); err != nil {
		return nil, fmt.Errorf("failed to write test config: %w", err)
	}
	defer os.Remove(configPath)

	// Run nginx -t
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	result := &ValidationResult{
		Output: outputStr,
	}

	// Parse output for warnings and errors
	lines := strings.Split(outputStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "[warn]") {
			result.Warnings = append(result.Warnings, line)
		} else if strings.Contains(line, "[emerg]") || strings.Contains(line, "[error]") {
			result.Errors = append(result.Errors, line)
		}
	}

	// Check if validation passed
	if err == nil && strings.Contains(outputStr, "syntax is ok") && strings.Contains(outputStr, "test is successful") {
		result.Passed = true
	} else if err == nil && len(result.Errors) == 0 {
		// Sometimes nginx -t exits 0 but we need to check for errors
		result.Passed = true
	}

	return result, nil
}

// doNginxReload reloads the nginx configuration
func (h *Handler) doNginxReload() error {
	// First test the configuration
	testCmd := exec.Command("nginx", "-t")
	if output, err := testCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}

	// Reload nginx
	reloadCmd := exec.Command("nginx", "-s", "reload")
	if output, err := reloadCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nginx reload failed: %s", string(output))
	}

	return nil
}

// getResourceAppliedState gets the current applied state of a resource
func (h *Handler) getResourceAppliedState(ctx context.Context, resourceID uuid.UUID) (map[string]interface{}, error) {
	var stateJSON []byte
	err := h.db.QueryRow(ctx, `
		SELECT applied_state FROM traffic_resources WHERE id = $1
	`, resourceID).Scan(&stateJSON)
	if err != nil {
		return nil, err
	}

	var state map[string]interface{}
	if len(stateJSON) > 0 {
		json.Unmarshal(stateJSON, &state)
	}
	return state, nil
}

// recordTrafficApplyHistory records an apply action in the history table
func (h *Handler) recordTrafficApplyHistory(
	ctx context.Context,
	resourceID uuid.UUID,
	userID *uuid.UUID,
	action string,
	previousState, newState map[string]interface{},
	nginxConfig, configHash string,
	success bool,
	errorMsg *string,
) {
	_, err := h.db.Exec(ctx, `
		INSERT INTO traffic_apply_history (
			traffic_resource_id, action, previous_state, new_state,
			applied_by, success, error_message, rendered_nginx_config, config_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, resourceID, action, previousState, newState, userID, success, errorMsg, nginxConfig, configHash)

	if err != nil {
		h.logger.Error("Failed to record apply history",
			zap.Error(err),
			zap.String("resource_id", resourceID.String()),
			zap.String("action", action),
		)
	}
}

// getTrafficResourceConfigPreview returns the compiled nginx config without applying
// GET /traffic/resources/:id/config-preview
func (h *Handler) getTrafficResourceConfigPreview(c *gin.Context) {
	resourceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resource ID"})
		return
	}

	ctx := c.Request.Context()

	compiled, err := h.compileTrafficResource(ctx, resourceID)
	if err != nil {
		h.logger.Error("Failed to compile traffic resource", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Compilation failed: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"resource_id":  compiled.ResourceID,
		"resource_name": compiled.ResourceName,
		"nginx_config": compiled.NginxConfig,
		"config_hash":  compiled.ConfigHash,
		"domains":      compiled.Domains,
		"upstreams":    compiled.Upstreams,
		"policies":     compiled.Policies,
		"tls_config":   compiled.TLSConfig,
	})
}
