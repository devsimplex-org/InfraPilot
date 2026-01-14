package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/feedback"
)

// ==================== Feedback Types ====================

type FeedbackListResponse struct {
	Feedbacks []*feedback.Feedback `json:"feedbacks"`
	Count     int                  `json:"count"`
}

type VCSConfigRequest struct {
	Provider            string `json:"provider" binding:"required"`
	Enabled             bool   `json:"enabled"`
	Token               string `json:"token,omitempty"` // GitHub personal access token
	DefaultRepo         string `json:"default_repo,omitempty"`
	AutoCommentOnPR     bool   `json:"auto_comment_on_pr"`
	AutoCommentOnCommit bool   `json:"auto_comment_on_commit"`
}

// ==================== Feedback Handlers ====================

// listFeedback lists all feedback for an organization
func (h *Handler) listFeedback(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Parse filters
	filters := feedback.FeedbackFilters{
		OrgID:  &orgID,
		Limit:  100,
		Offset: 0,
	}

	// Optional filters
	if sourceType := c.Query("source_type"); sourceType != "" {
		st := feedback.SourceType(sourceType)
		filters.SourceType = &st
	}

	if status := c.Query("status"); status != "" {
		s := feedback.DeliveryStatus(status)
		filters.Status = &s
	}

	if repo := c.Query("repo"); repo != "" {
		filters.Repo = &repo
	}

	// Get feedback manager from handler
	feedbackManager := h.getFeedbackManager()
	if feedbackManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "feedback system not initialized"})
		return
	}

	feedbacks, err := feedbackManager.ListFeedback(c.Request.Context(), filters)
	if err != nil {
		h.logger.Error("failed to list feedback", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list feedback"})
		return
	}

	c.JSON(http.StatusOK, FeedbackListResponse{
		Feedbacks: feedbacks,
		Count:     len(feedbacks),
	})
}

// getFeedback retrieves a specific feedback entry
func (h *Handler) getFeedback(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	feedbackID, err := uuid.Parse(c.Param("fid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid feedback ID"})
		return
	}

	feedbackManager := h.getFeedbackManager()
	if feedbackManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "feedback system not initialized"})
		return
	}

	fb, err := feedbackManager.GetFeedback(c.Request.Context(), feedbackID)
	if err != nil {
		h.logger.Error("failed to get feedback", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "feedback not found"})
		return
	}

	// Verify ownership
	if fb.OrgID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	c.JSON(http.StatusOK, fb)
}

// deliverFeedback manually triggers delivery of a specific feedback
func (h *Handler) deliverFeedback(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	feedbackID, err := uuid.Parse(c.Param("fid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid feedback ID"})
		return
	}

	feedbackManager := h.getFeedbackManager()
	if feedbackManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "feedback system not initialized"})
		return
	}

	// Verify ownership first
	fb, err := feedbackManager.GetFeedback(c.Request.Context(), feedbackID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "feedback not found"})
		return
	}

	if fb.OrgID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	// Deliver
	if err := feedbackManager.DeliverFeedback(c.Request.Context(), feedbackID); err != nil {
		h.logger.Error("failed to deliver feedback", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deliver feedback"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "feedback delivered successfully"})
}

// ==================== VCS Configuration Handlers ====================

// getVCSConfig retrieves VCS configuration for a provider
func (h *Handler) getVCSConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	provider := feedback.Provider(c.Param("provider"))

	feedbackManager := h.getFeedbackManager()
	if feedbackManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "feedback system not initialized"})
		return
	}

	config, err := feedbackManager.GetConfiguration(c.Request.Context(), orgID, provider)
	if err != nil {
		h.logger.Error("failed to get VCS config", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "configuration not found"})
		return
	}

	// Don't expose credentials in response
	config.Credentials = nil

	c.JSON(http.StatusOK, config)
}

// saveVCSConfig saves or updates VCS configuration
func (h *Handler) saveVCSConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req VCSConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	provider := feedback.Provider(req.Provider)

	// Validate provider
	if provider != feedback.ProviderGitHub && provider != feedback.ProviderGitLab {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
		return
	}

	feedbackManager := h.getFeedbackManager()
	if feedbackManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "feedback system not initialized"})
		return
	}

	// Check if config exists
	existingConfig, _ := feedbackManager.GetConfiguration(c.Request.Context(), orgID, provider)

	// Create or update config
	config := &feedback.VCSConfiguration{
		OrgID:               orgID,
		Provider:            provider,
		Enabled:             req.Enabled,
		AuthType:            "token",
		DefaultRepo:         &req.DefaultRepo,
		AutoCommentOnPR:     req.AutoCommentOnPR,
		AutoCommentOnCommit: req.AutoCommentOnCommit,
		Credentials: map[string]interface{}{
			"token": req.Token,
		},
	}

	if existingConfig != nil {
		config.ID = existingConfig.ID
		config.CreatedAt = existingConfig.CreatedAt
	}

	if err := feedbackManager.SaveConfiguration(c.Request.Context(), config); err != nil {
		h.logger.Error("failed to save VCS config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save configuration"})
		return
	}

	// Register deliverer if enabled
	if config.Enabled && req.Token != "" {
		if provider == feedback.ProviderGitHub {
			githubDeliverer := feedback.NewGitHubDeliverer(req.Token, h.logger)
			feedbackManager.RegisterDeliverer(githubDeliverer)
			h.logger.Info("registered GitHub deliverer",
				zap.String("org_id", orgID.String()),
			)
		}
	}

	// Don't expose credentials in response
	config.Credentials = nil

	c.JSON(http.StatusOK, config)
}

// deleteVCSConfig deletes VCS configuration
func (h *Handler) deleteVCSConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	provider := feedback.Provider(c.Param("provider"))

	feedbackManager := h.getFeedbackManager()
	if feedbackManager == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "feedback system not initialized"})
		return
	}

	// Get config to verify ownership
	config, err := feedbackManager.GetConfiguration(c.Request.Context(), orgID, provider)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "configuration not found"})
		return
	}

	// Disable config instead of deleting (preserve history)
	config.Enabled = false
	if err := feedbackManager.SaveConfiguration(c.Request.Context(), config); err != nil {
		h.logger.Error("failed to disable VCS config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable configuration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "configuration disabled successfully"})
}

// ==================== Helper ====================

// getFeedbackManager extracts feedback manager from feedbackIntegration
func (h *Handler) getFeedbackManager() *feedback.FeedbackManager {
	if h.feedbackIntegration == nil {
		return nil
	}
	return h.feedbackIntegration.GetManager()
}
