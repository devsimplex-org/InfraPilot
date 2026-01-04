package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// OrgHeader is the header name for specifying the current organization
	OrgHeader = "X-Org-ID"
	// OrgContextKey is the gin context key for the current organization ID
	OrgContextKey = "org_id"
)

// OrgMiddleware extracts the organization ID from the request and sets it in the context.
// For community edition, this simply gets the org_id from the users table.
func (h *Handler) OrgMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if this is an internal service call (already has org_id set by AuthMiddleware)
		if isInternal, exists := c.Get("internal_service"); exists && isInternal.(bool) {
			// org_id is already set by AuthMiddleware for internal calls
			if _, orgExists := c.Get(OrgContextKey); orgExists {
				c.Next()
				return
			}
		}

		// Get user ID from auth context (must be after AuthMiddleware)
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
			c.Abort()
			return
		}

		var orgID uuid.UUID

		// Get user's org_id from users table (community edition - single org per user)
		err := h.db.QueryRow(c.Request.Context(), `
			SELECT org_id FROM users WHERE id = $1
		`, userID).Scan(&orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to determine organization"})
			c.Abort()
			return
		}

		// Set org_id in gin context for handlers
		c.Set(OrgContextKey, orgID)

		c.Next()
	}
}

// GetOrgID retrieves the organization ID from the gin context
func GetOrgID(c *gin.Context) (uuid.UUID, bool) {
	orgID, exists := c.Get(OrgContextKey)
	if !exists {
		return uuid.Nil, false
	}
	id, ok := orgID.(uuid.UUID)
	return id, ok
}

// RequireOrg is a helper middleware that ensures org_id is present in context
func RequireOrg() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(OrgContextKey)
		if !exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Organization context required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
