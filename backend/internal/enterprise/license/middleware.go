package license

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Middleware adds edition information to the request context
// and sets response headers indicating edition status
func Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		lic := Current()

		// Add license to context
		ctx := WithContext(c.Request.Context(), lic)
		c.Request = c.Request.WithContext(ctx)

		// Set edition header
		c.Header("X-InfraPilot-Edition", string(lic.Edition))

		c.Next()
	}
}

// RequireFeatureMiddleware creates middleware that requires a specific feature
// Use this for entire route groups that require SaaS features
func RequireFeatureMiddleware(feature string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := RequireFeature(c.Request.Context(), feature); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   err.Error(),
				"code":    "SAAS_REQUIRED",
				"feature": feature,
				"upgrade": "https://infrapilot.sh",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequireSaaSMiddleware creates middleware that requires SaaS edition
func RequireSaaSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := RequireSaaS(c.Request.Context()); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   err.Error(),
				"code":    "SAAS_REQUIRED",
				"upgrade": "https://infrapilot.sh",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// EditionInfoHandler returns current edition information
// Useful for UI to show edition status and available features
func EditionInfoHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		lic := FromContext(c.Request.Context())

		c.JSON(http.StatusOK, gin.H{
			"edition":  lic.Edition,
			"features": GetFeatureInfo(c.Request.Context()),
			"limits": gin.H{
				"max_users":     lic.Limits.MaxUsers,
				"max_agents":    lic.Limits.MaxAgents,
				"max_resources": lic.Limits.MaxResources,
			},
		})
	}
}

// LicenseInfoHandler is an alias for EditionInfoHandler for backwards compatibility
func LicenseInfoHandler() gin.HandlerFunc {
	return EditionInfoHandler()
}
