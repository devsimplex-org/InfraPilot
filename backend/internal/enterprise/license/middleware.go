package license

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Middleware adds license information to the request context
// and sets response headers indicating license status
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		lic := Current()

		// Add license to context
		ctx := WithContext(c.Request.Context(), lic)
		c.Request = c.Request.WithContext(ctx)

		// Set license status headers (noisy, not blocky)
		c.Header("X-InfraPilot-Edition", string(lic.Edition))

		if lic.Edition == Community {
			c.Header("X-License-Status", "community")
		} else if lic.IsExpired() {
			c.Header("X-License-Status", "expired")
		} else {
			c.Header("X-License-Status", "valid")
		}

		c.Next()
	}
}

// RequireFeatureMiddleware creates middleware that requires a specific feature
// Use this for entire route groups that require enterprise features
func RequireFeatureMiddleware(feature string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := RequireFeature(c.Request.Context(), feature); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   err.Error(),
				"code":    "ENTERPRISE_REQUIRED",
				"feature": feature,
				"upgrade": "https://infrapilot.io/pricing",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireEnterpriseMiddleware creates middleware that requires any enterprise license
func RequireEnterpriseMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := RequireEnterprise(c.Request.Context()); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   err.Error(),
				"code":    "ENTERPRISE_REQUIRED",
				"upgrade": "https://infrapilot.io/pricing",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// LicenseInfoHandler returns current license information
// Useful for UI to show license status and available features
func LicenseInfoHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		lic := FromContext(c.Request.Context())

		// Handle expires_at - return nil if zero time (no expiration)
		var expiresAt interface{}
		if !lic.ExpiresAt.IsZero() {
			expiresAt = lic.ExpiresAt
		}

		// Don't expose sensitive license details, just what UI needs
		c.JSON(http.StatusOK, gin.H{
			"edition":      lic.Edition,
			"organization": lic.Organization,
			"features":     GetFeatureInfo(c.Request.Context()),
			"limits": gin.H{
				"max_users":     lic.Limits.MaxUsers,
				"max_agents":    lic.Limits.MaxAgents,
				"max_resources": lic.Limits.MaxResources,
			},
			"valid":      lic.Valid(),
			"expires_at": expiresAt,
		})
	}
}
