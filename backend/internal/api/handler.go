package api

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/auth"
	agentgrpc "github.com/infrapilot/backend/internal/grpc"
)

type Handler struct {
	db     *pgxpool.Pool
	auth   *auth.Service
	logger *zap.Logger
}

func NewHandler(db *pgxpool.Pool, authService *auth.Service, logger *zap.Logger) *Handler {
	return &Handler{
		db:     db,
		auth:   authService,
		logger: logger,
	}
}

func (h *Handler) RegisterRoutes(r *gin.Engine) {
	// Health check
	r.GET("/health", h.healthCheck)

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		// Setup routes (public - only work when no users exist)
		v1.GET("/setup/status", h.getSetupStatus)
		v1.POST("/setup", h.createInitialAdmin)

		// Auth routes (public)
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/login", h.login)
			authGroup.POST("/logout", h.logout)
			authGroup.POST("/refresh", h.refreshToken)
			authGroup.POST("/mfa/verify", h.verifyMFA) // Public - uses MFA token
			authGroup.GET("/me", h.AuthMiddleware(), h.getCurrentUser)

			// MFA management (requires auth)
			authGroup.POST("/mfa/setup", h.AuthMiddleware(), h.setupMFA)
			authGroup.POST("/mfa/confirm", h.AuthMiddleware(), h.confirmMFASetup)
			authGroup.POST("/mfa/disable", h.AuthMiddleware(), h.disableMFA)
			authGroup.POST("/mfa/backup-codes", h.AuthMiddleware(), h.regenerateBackupCodes)
		}

		// Protected routes
		protected := v1.Group("")
		protected.Use(h.AuthMiddleware())
		protected.Use(h.OrgMiddleware())
		{
			// Agents
			agents := protected.Group("/agents")
			{
				agents.GET("", h.listAgents)
				agents.POST("", h.RequireRole(auth.RoleSuperAdmin), h.createAgent)
				agents.GET("/:id", h.getAgent)
				agents.DELETE("/:id", h.RequireRole(auth.RoleSuperAdmin), h.deleteAgent)
				agents.GET("/:id/metrics", h.getAgentMetrics)

				// Proxy hosts
				agents.GET("/:id/proxies", h.listProxyHosts)
				agents.POST("/:id/proxies", h.RequireModifyProxy(), h.createProxyHost)
				agents.GET("/:id/proxies/:pid", h.getProxyHost)
				agents.PUT("/:id/proxies/:pid", h.RequireModifyProxy(), h.updateProxyHost)
				agents.DELETE("/:id/proxies/:pid", h.RequireModifyProxy(), h.deleteProxyHost)
				agents.POST("/:id/proxies/:pid/ssl", h.RequireModifyProxy(), h.requestSSL)
				agents.GET("/:id/proxies/:pid/config", h.getProxyConfig)
				agents.POST("/:id/proxies/:pid/test", h.RequireModifyProxy(), h.testProxyConfig)
				agents.GET("/:id/proxies/:pid/security-headers", h.getSecurityHeaders)
				agents.PUT("/:id/proxies/:pid/security-headers", h.RequireModifyProxy(), h.updateSecurityHeaders)

				// Nginx management
				agents.POST("/:id/nginx/test", h.RequireModifyProxy(), h.testNginxConfig)
				agents.POST("/:id/nginx/reload", h.RequireModifyProxy(), h.reloadNginx)

				// Rate limits
				agents.GET("/:id/proxies/:pid/rate-limits", h.listRateLimits)
				agents.POST("/:id/proxies/:pid/rate-limits", h.RequireModifyProxy(), h.createRateLimit)
				agents.PUT("/:id/proxies/:pid/rate-limits/:rlid", h.RequireModifyProxy(), h.updateRateLimit)
				agents.DELETE("/:id/proxies/:pid/rate-limits/:rlid", h.RequireModifyProxy(), h.deleteRateLimit)

				// Containers
				agents.GET("/:id/containers", h.listContainersReal)
				agents.GET("/:id/containers/:cid", h.getContainerReal)
				agents.POST("/:id/containers/:cid/start", h.RequireModifyContainers(), h.startContainerReal)
				agents.POST("/:id/containers/:cid/stop", h.RequireModifyContainers(), h.stopContainerReal)
				agents.POST("/:id/containers/:cid/restart", h.RequireModifyContainers(), h.restartContainerReal)
				agents.DELETE("/:id/containers/:cid", h.RequireModifyContainers(), h.deleteContainerReal)
				agents.GET("/:id/containers/:cid/logs", h.getContainerLogsReal)
				agents.GET("/:id/containers/:cid/logs/stream", h.streamContainerLogs)
				agents.GET("/:id/containers/:cid/exec", h.execContainer)
				agents.GET("/:id/containers/:cid/networks", h.getContainerNetworks)
				agents.GET("/:id/stacks", h.listStacksReal)

				// Networks (for nginx cross-network proxying)
				agents.GET("/:id/networks", h.listNetworks)
				agents.GET("/:id/networks/attachments", h.listNginxNetworkAttachments)
				agents.POST("/:id/networks/attach", h.RequireModifyProxy(), h.attachNginxNetwork)
				agents.POST("/:id/networks/detach", h.RequireModifyProxy(), h.detachNginxNetwork)
				agents.GET("/:id/networks/:nid/check-nginx", h.checkNginxNetwork)

				// Logs
				agents.GET("/:id/logs/nginx", h.getNginxLogsReal)
				agents.GET("/:id/logs/unified", h.getUnifiedLogsReal)
				agents.GET("/:id/logs/stream", h.streamUnifiedLogs)

				// Databases
				agents.GET("/:id/databases", h.listDatabases)
				agents.POST("/:id/databases", h.RequireModifyContainers(), h.addDatabase)
				agents.DELETE("/:id/databases/:did", h.RequireModifyContainers(), h.removeDatabase)
				agents.GET("/:id/databases/:did/metrics", h.getDatabaseMetrics)
			}

			// Alerts
			alerts := protected.Group("/alerts")
			{
				alerts.GET("/channels", h.listAlertChannelsReal)
				alerts.POST("/channels", h.RequireManageAlerts(), h.createAlertChannelReal)
				alerts.PUT("/channels/:id", h.RequireManageAlerts(), h.updateAlertChannelReal)
				alerts.DELETE("/channels/:id", h.RequireManageAlerts(), h.deleteAlertChannelReal)
				alerts.POST("/channels/:id/test", h.RequireManageAlerts(), h.testAlertChannelReal)

				alerts.GET("/rules", h.listAlertRulesReal)
				alerts.POST("/rules", h.RequireManageAlerts(), h.createAlertRuleReal)
				alerts.PUT("/rules/:id", h.RequireManageAlerts(), h.updateAlertRuleReal)
				alerts.DELETE("/rules/:id", h.RequireManageAlerts(), h.deleteAlertRuleReal)

				alerts.GET("/history", h.getAlertHistoryReal)
			}

			// Health & Monitoring
			protected.GET("/health/tls", h.getTLSHealth)
			protected.GET("/health/database", h.getDBHealth)
			protected.GET("/health/system", h.getSystemHealth)

			// Audit
			protected.GET("/audit", h.getAuditLogsReal)

			// Users (super_admin only)
			users := protected.Group("/users")
			users.Use(h.RequireRole(auth.RoleSuperAdmin))
			{
				users.GET("", h.listUsersReal)
				users.POST("", h.createUserReal)
				users.PUT("/:id", h.updateUserReal)
				users.DELETE("/:id", h.deleteUserReal)
			}

			// System Settings (super_admin only)
			settings := protected.Group("/settings")
			settings.Use(h.RequireRole(auth.RoleSuperAdmin))
			{
				settings.GET("", h.getSystemSettings)
				settings.GET("/domain", h.getInfraPilotDomain)
				settings.PUT("/domain", h.updateInfraPilotDomain)
				settings.DELETE("/domain", h.deleteInfraPilotDomain)

				// Default pages
				settings.GET("/default-pages", h.listDefaultPages)
				settings.GET("/default-pages/:type", h.getDefaultPage)
				settings.PUT("/default-pages/:type", h.updateDefaultPage)
				settings.GET("/default-pages/:type/preview", h.previewDefaultPage)
			}

			// SSL/TLS Management
			ssl := protected.Group("/ssl")
			{
				ssl.GET("/check/:domain", h.checkDomainSSL)
				ssl.GET("/check-wildcard/:domain", h.checkWildcardSSL)
				ssl.GET("/verify-dns/:domain", h.verifyDNS)
				ssl.GET("/dns-instructions/:domain", h.getDNSInstructions)
				ssl.GET("/status", h.getSSLStatus)
				ssl.PUT("/settings", h.RequireRole(auth.RoleSuperAdmin), h.updateSSLSettings)
				ssl.POST("/request", h.RequireRole(auth.RoleSuperAdmin), h.requestSSLCertificate)

				// Certificate management
				ssl.GET("/certificates", h.listSSLCertificates)
				ssl.GET("/certificates/scan", h.scanSSLCertificates)
				ssl.POST("/certificates", h.RequireRole(auth.RoleSuperAdmin), h.registerSSLCertificate)
				ssl.GET("/certificates/:id", h.getSSLCertificate)
				ssl.DELETE("/certificates/:id", h.RequireRole(auth.RoleSuperAdmin), h.deleteSSLCertificate)
			}
		}

		// Agent enrollment routes
		v1.POST("/agents/enroll", h.EnrollAgent)
		v1.GET("/agents/enroll/status", h.GetEnrollmentStatus)
		v1.POST("/agents/heartbeat", h.AgentHeartbeat)

		// Agent WebSocket command stream
		v1.GET("/agents/:id/ws/commands", h.agentCommandStream)

		// Log ingestion (agents push logs)
		v1.POST("/logs/ingest", h.IngestLogs)
	}

	// Protected log routes (require auth)
	logs := v1.Group("/logs")
	logs.Use(h.AuthMiddleware())
	logs.Use(h.OrgMiddleware())
	{
		logs.GET("/persisted", h.GetPersistedLogs)
		logs.GET("/sources", h.GetLogSources)
		logs.GET("/retention", h.GetLogRetentionConfig)
		logs.PUT("/retention", h.RequireRole(auth.RoleSuperAdmin), h.UpdateLogRetentionConfig)
		logs.GET("/stats", h.GetLogStats)
		logs.POST("/cleanup", h.RequireRole(auth.RoleSuperAdmin), h.RunLogCleanup)
	}
}

// Health check endpoint
func (h *Handler) healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "ok",
		"edition": "community",
	})
}

// StartBackgroundTasks starts background tasks like dispatching default page config
// This should be called after the HTTP server starts
func (h *Handler) StartBackgroundTasks(ctx context.Context) {
	go h.dispatchDefaultPageConfigOnStartup(ctx)
}

// dispatchDefaultPageConfigOnStartup checks if a domain is configured and dispatches
// the default page config and system proxy config once an agent connects
func (h *Handler) dispatchDefaultPageConfigOnStartup(ctx context.Context) {
	// Wait a bit for the agent to connect
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	dispatched := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if dispatched {
				return
			}

			// Check if a domain is configured for InfraPilot
			var agentID uuid.UUID
			var proxyID uuid.UUID
			var orgID uuid.UUID
			var domain string
			var sslEnabled, forceSSL, http2 bool
			var sslCertPath, sslKeyPath *string

			err := h.db.QueryRow(ctx, `
				SELECT ph.id, ph.agent_id, a.org_id, ph.domain, ph.ssl_enabled, ph.force_ssl, ph.http2_enabled,
				       ph.ssl_cert_path, ph.ssl_key_path
				FROM proxy_hosts ph
				JOIN agents a ON a.id = ph.agent_id
				WHERE ph.is_system_proxy = TRUE
				LIMIT 1
			`).Scan(&proxyID, &agentID, &orgID, &domain, &sslEnabled, &forceSSL, &http2, &sslCertPath, &sslKeyPath)

			if err != nil {
				// No domain configured, nothing to do
				h.logger.Debug("No InfraPilot domain configured yet")
				return
			}

			// Check if agent is connected
			agentIDStr := agentID.String()
			if !agentgrpc.IsAgentConnected(agentIDStr) {
				h.logger.Debug("Waiting for agent to connect before dispatching startup config")
				continue
			}

			// Agent is connected and domain is configured
			h.logger.Info("Dispatching startup configs",
				zap.String("domain", domain),
				zap.String("agent_id", agentIDStr),
			)

			// Get cert paths from settings if available
			certPath := ""
			keyPath := ""
			if sslCertPath != nil {
				certPath = *sslCertPath
			}
			if sslKeyPath != nil {
				keyPath = *sslKeyPath
			}

			// Dispatch the InfraPilot system proxy config (routes /api to backend)
			h.dispatchInfraPilotProxyConfigWithCert(ctx, agentID, proxyID, domain, forceSSL, http2, sslEnabled, certPath, keyPath)

			// Dispatch the default page config (welcome page for IP access)
			h.dispatchDefaultPageConfig(agentID, orgID, true)

			dispatched = true
		}
	}
}
