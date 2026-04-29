package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/infrapilot/backend/internal/registry"
	"go.uber.org/zap"
)

// listRegistries lists all container registries for the organization
func (h *Handler) listRegistries(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	registries, err := h.registryService.ListRegistries(c.Request.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to list registries", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list registries"})
		return
	}

	// Convert to response format (excludes credentials)
	responses := make([]*registry.RegistryResponse, len(registries))
	for i, r := range registries {
		responses[i] = r.ToResponse()
	}

	c.JSON(http.StatusOK, responses)
}

// createRegistry creates a new container registry connection
func (h *Handler) createRegistry(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req registry.CreateRegistryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	reg, err := h.registryService.CreateRegistry(c.Request.Context(), orgID, &req, &userID)
	if err != nil {
		h.logger.Error("failed to create registry", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, reg.ToResponse())
}

// getRegistry retrieves a container registry by ID
func (h *Handler) getRegistry(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	registryID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry ID"})
		return
	}

	reg, err := h.registryService.GetRegistry(c.Request.Context(), orgID, registryID)
	if err != nil {
		h.logger.Error("failed to get registry", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "registry not found"})
		return
	}

	c.JSON(http.StatusOK, reg.ToResponse())
}

// updateRegistry updates a container registry
func (h *Handler) updateRegistry(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	registryID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry ID"})
		return
	}

	var req registry.UpdateRegistryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.registryService.UpdateRegistry(c.Request.Context(), orgID, registryID, &req); err != nil {
		h.logger.Error("failed to update registry", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "registry updated"})
}

// deleteRegistry deletes a container registry
func (h *Handler) deleteRegistry(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	registryID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry ID"})
		return
	}

	if err := h.registryService.DeleteRegistry(c.Request.Context(), orgID, registryID); err != nil {
		h.logger.Error("failed to delete registry", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "registry deleted"})
}

// testRegistryConnection tests the connection to a container registry
func (h *Handler) testRegistryConnection(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	registryID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry ID"})
		return
	}

	if err := h.registryService.TestConnection(c.Request.Context(), orgID, registryID); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "connection successful",
	})
}

// listRegistryRepositories lists repositories for a registry
func (h *Handler) listRegistryRepositories(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	registryID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry ID"})
		return
	}

	// Parse pagination params
	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	repos, err := h.registryService.ListRepositories(c.Request.Context(), orgID, registryID, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list repositories", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, repos)
}

// listRegistryTags lists tags for a repository
func (h *Handler) listRegistryTags(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	registryID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry ID"})
		return
	}

	repository := c.Param("repo")
	if repository == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "repository name is required"})
		return
	}

	// Parse pagination params
	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	tags, err := h.registryService.ListTags(c.Request.Context(), orgID, registryID, repository, page, pageSize)
	if err != nil {
		h.logger.Error("failed to list tags", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tags)
}
