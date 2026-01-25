package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/auth"
	"github.com/infrapilot/backend/internal/crypto"
	"github.com/infrapilot/backend/internal/feedback"
	agentgrpc "github.com/infrapilot/backend/internal/grpc"
	"github.com/infrapilot/backend/internal/policy"
	"github.com/infrapilot/backend/internal/registry"
	"github.com/infrapilot/backend/internal/scanner"
	"github.com/infrapilot/backend/internal/webhook"
)

type Handler struct {
	db                  *pgxpool.Pool
	auth                *auth.Service
	logger              *zap.Logger
	scanner             *scanner.Scanner
	sbomGenerator       *scanner.SBOMGenerator
	policyEngine        *policy.PolicyEngine
	webhookService      *webhook.Service
	feedbackIntegration *feedback.DeploymentIntegration
	registryService     *registry.Service
	encryptionSvc       *crypto.EncryptionService
}

func NewHandler(db *pgxpool.Pool, authService *auth.Service, logger *zap.Logger, encryptionSvc *crypto.EncryptionService) *Handler {
	// Initialize feedback system
	feedbackManager := feedback.NewManager(db, logger)
	feedbackRenderer := feedback.NewTemplateRenderer(db, logger)
	feedbackIntegration := feedback.NewDeploymentIntegration(db, feedbackManager, feedbackRenderer, logger)

	// TODO: Register GitHub deliverer when token is configured
	// This would typically be done after reading VCS configuration from DB
	// For now, the deliverer will be registered when configuration is saved

	return &Handler{
		db:                  db,
		auth:                authService,
		logger:              logger,
		scanner:             scanner.NewScanner(logger),
		sbomGenerator:       scanner.NewSBOMGenerator(logger),
		policyEngine:        policy.NewPolicyEngine(logger, "/app/policies"),
		webhookService:      webhook.NewService(db, logger, encryptionSvc),
		feedbackIntegration: feedbackIntegration,
		registryService:     registry.NewService(db, logger, encryptionSvc),
		encryptionSvc:       encryptionSvc,
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

			// SSO/OIDC routes (public)
			authGroup.GET("/sso/providers", h.getAvailableSSOProviders)
			authGroup.GET("/sso/:config_id/login", h.ssoLogin)
			authGroup.GET("/sso/:config_id/callback", h.ssoCallback)
		}

		// Webhook receiver (public - uses signature verification)
		webhooks := v1.Group("/webhooks")
		{
			webhooks.POST("/:id/receive", h.receiveWebhook)
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
				agents.POST("/:id/proxies/test-network", h.RequireModifyProxy(), h.testNetworkConnectivity)
				agents.GET("/:id/proxies/:pid", h.getProxyHost)
				agents.PUT("/:id/proxies/:pid", h.RequireModifyProxy(), h.updateProxyHost)
				agents.DELETE("/:id/proxies/:pid", h.RequireModifyProxy(), h.deleteProxyHost)
				agents.POST("/:id/proxies/:pid/ssl", h.RequireModifyProxy(), h.requestSSL)
				agents.POST("/:id/proxies/:pid/ssl/wildcard", h.RequireModifyProxy(), h.applyWildcardSSL)
				agents.GET("/:id/proxies/:pid/config", h.getProxyConfig)
				agents.POST("/:id/proxies/:pid/config/preview", h.RequireModifyProxy(), h.previewProxyConfig)
				agents.POST("/:id/proxies/:pid/test", h.RequireModifyProxy(), h.testProxyConfig)
				agents.GET("/:id/proxies/:pid/security-headers", h.getSecurityHeaders)
				agents.PUT("/:id/proxies/:pid/security-headers", h.RequireModifyProxy(), h.updateSecurityHeaders)

				// Basic auth users
				agents.GET("/:id/proxies/:pid/auth-users", h.listAuthUsers)
				agents.POST("/:id/proxies/:pid/auth-users", h.RequireModifyProxy(), h.createAuthUser)
				agents.DELETE("/:id/proxies/:pid/auth-users/:uid", h.RequireModifyProxy(), h.deleteAuthUser)

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

				// Docker Resources (networks, volumes, images)
				docker := agents.Group("/:id/docker")
				{
					// Networks (full CRUD)
					docker.GET("/networks", h.listDockerNetworks)
					docker.GET("/networks/:nid", h.inspectDockerNetwork)
					docker.POST("/networks", h.RequireModifyContainers(), h.createDockerNetwork)
					docker.DELETE("/networks/:nid", h.RequireModifyContainers(), h.deleteDockerNetwork)

					// Volumes
					docker.GET("/volumes", h.listDockerVolumes)
					docker.GET("/volumes/:name", h.inspectDockerVolume)
					docker.POST("/volumes", h.RequireModifyContainers(), h.createDockerVolume)
					docker.DELETE("/volumes/:name", h.RequireModifyContainers(), h.deleteDockerVolume)

					// Images
					docker.GET("/images", h.listDockerImages)
					docker.GET("/images/:imgid", h.inspectDockerImage)
					docker.POST("/images/pull", h.RequireModifyContainers(), h.pullDockerImage)
					docker.DELETE("/images/:imgid", h.RequireModifyContainers(), h.deleteDockerImage)
				}

				// Logs
				agents.GET("/:id/logs/nginx", h.getNginxLogsReal)
				agents.GET("/:id/logs/unified", h.getUnifiedLogsReal)
				agents.GET("/:id/logs/stream", h.streamUnifiedLogs)

				// Databases
				agents.GET("/:id/databases", h.listDatabases)
				agents.POST("/:id/databases", h.RequireModifyContainers(), h.addDatabase)
				agents.DELETE("/:id/databases/:did", h.RequireModifyContainers(), h.removeDatabase)
				agents.GET("/:id/databases/:did/metrics", h.getDatabaseMetrics)

				// Deployments (Epic 0: DevSecOps Foundations)
				agents.GET("/:id/deployments", h.listDeployments)
				agents.POST("/:id/deployments", h.RequireModifyContainers(), h.createDeployment)
				agents.GET("/:id/deployments/:did", h.getDeployment)
				agents.GET("/:id/deployments/:did/spine", h.getDeploymentSpine)
				agents.POST("/:id/deployments/:did/rollback", h.RequireModifyContainers(), h.rollbackDeployment)
				agents.POST("/:id/deployments/:did/redeploy", h.RequireModifyContainers(), h.redeployDeployment)
				agents.DELETE("/:id/deployments/:did", h.RequireModifyContainers(), h.deleteDeployment)
				agents.POST("/:id/deployments/sync", h.syncDeploymentStatus)

				// Webhooks (Epic 4: Dev Integration)
				agents.GET("/:id/webhooks", h.listWebhooks)
				agents.POST("/:id/webhooks", h.RequireModifyContainers(), h.createWebhook)
				agents.GET("/:id/webhooks/:wid", h.getWebhook)
				agents.PUT("/:id/webhooks/:wid", h.RequireModifyContainers(), h.updateWebhook)
				agents.DELETE("/:id/webhooks/:wid", h.RequireModifyContainers(), h.deleteWebhook)
				agents.GET("/:id/webhooks/:wid/events", h.listWebhookEvents)
				agents.POST("/:id/webhooks/:wid/regenerate", h.RequireModifyContainers(), h.regenerateWebhookSecret)

			// CVE-Centric View (Epic 1: Supply Chain Security)
			agents.GET(":id/cves", h.getCVESummaries)
			agents.GET(":id/cves/:cve_id", h.getCVEDetail)

			// Secret Migrations (agent-scoped)
			agents.GET("/:id/secrets/migrations", h.listSecretMigrations)
			agents.POST("/:id/secrets/migrations", h.RequireModifyContainers(), h.createMigration)
			agents.GET("/:id/secrets/migrations/:migration_id", h.getMigration)
			agents.POST("/:id/secrets/migrations/:migration_id/rollback", h.RequireModifyContainers(), h.rollbackMigration)

			// Secret Import (import .env to container)
			agents.POST("/:id/secrets/import", h.RequireModifyContainers(), h.importSecrets)
		}

			// Services view (cross-agent)
			protected.GET("/services", h.listServices)
			protected.GET("/services/:name/deployments", h.listServiceDeployments)
			protected.GET("/services/:name/current", h.getCurrentDeployment)

			// Security Scanning (Epic 1: Supply Chain Security)
			protected.POST("/scans", h.RequireModifyContainers(), h.triggerImageScan)
			protected.GET("/scans", h.listScans)
			protected.GET("/scans/ws", h.scanWebSocket) // WebSocket for real-time scans (must be before :sid)
			protected.GET("/pulls/ws", h.pullWebSocket)   // WebSocket for real-time image pulls
			protected.GET("/imports/ws", h.importSecretsWebSocket) // WebSocket for real-time secrets import
			protected.GET("/scans/:sid", h.getScanDetails)
			protected.GET("/scans/:sid/vulnerabilities", h.getScanVulnerabilities)

			// SBOM Management
			protected.POST("/sboms", h.RequireModifyContainers(), h.generateSBOM)
			protected.GET("/sboms", h.listSBOMs)
			protected.GET("/sboms/:sid", h.getSBOMDetails)
			protected.GET("/sboms/:sid/download", h.downloadSBOM)
			protected.GET("/sboms/:sid/packages/search", h.searchSBOMPackages)

			// Policy Management (Epic 2: Policy-as-Code)
			policies := protected.Group("/policies")
			{
				policies.GET("", h.listPolicies)
				policies.GET("/:name", h.getPolicy)
				policies.PUT("/:name", h.RequireManageAlerts(), h.updatePolicy)
				policies.GET("/decisions/recent", h.listPolicyDecisions)
				policies.GET("/decisions/stats", h.getPolicyStats)
				policies.POST("/evaluate/preview", h.previewPolicyEvaluation)
			}

			// Security Dashboard (Epic 5: DevSecOps Observability)
			protected.GET("/security/posture", h.getSecurityPosture)

			// Developer Feedback (Epic 8: Shift-Left Security)
			feedback := protected.Group("/feedback")
			{
				feedback.GET("", h.listFeedback)
				feedback.GET("/:fid", h.getFeedback)
				feedback.POST("/:fid/deliver", h.RequireModifyContainers(), h.deliverFeedback)
			}

			// VCS Configuration (Epic 8: Shift-Left Security)
			vcs := protected.Group("/vcs")
			{
				vcs.GET("/:provider", h.getVCSConfig)
				vcs.PUT("/:provider", h.RequireManageAlerts(), h.saveVCSConfig)
				vcs.DELETE("/:provider", h.RequireManageAlerts(), h.deleteVCSConfig)
			}

			// Risk Exceptions (Epic 9: Risk Acceptance & Exception Management)
			exceptions := protected.Group("/exceptions")
			{
				exceptions.GET("", h.listExceptions)
				exceptions.POST("", h.RequireModifyContainers(), h.createException)
				exceptions.GET("/:eid", h.getException)
				exceptions.POST("/:eid/approve", h.RequireManageAlerts(), h.approveException)
				exceptions.POST("/:eid/deny", h.RequireManageAlerts(), h.denyException)
				exceptions.POST("/:eid/revoke", h.RequireManageAlerts(), h.revokeException)
				exceptions.GET("/:eid/history", h.getExceptionHistory)
			}

			// Service Ownership (Epic 10: Ownership & Accountability)
			ownership := protected.Group("/ownership")
			{
				ownership.GET("/services", h.listServiceOwnerships)
				ownership.POST("/services", h.RequireManageAlerts(), h.createServiceOwnership)
				ownership.GET("/services/:oid", h.getServiceOwnership)
				ownership.PUT("/services/:oid", h.RequireManageAlerts(), h.updateServiceOwnership)
				ownership.DELETE("/services/:oid", h.RequireManageAlerts(), h.deleteServiceOwnership)

				ownership.GET("/teams", h.listTeams)
				ownership.POST("/teams", h.RequireManageAlerts(), h.createTeam)
				ownership.PUT("/teams/:tid", h.RequireManageAlerts(), h.updateTeam)
				ownership.DELETE("/teams/:tid", h.RequireManageAlerts(), h.deleteTeam)
			}

			// Security Maturity (Epic 11: Security Maturity Scoring)
			maturity := protected.Group("/maturity")
			{
				maturity.GET("/scores", h.listSecurityScores)
				maturity.POST("/scores/calculate", h.RequireManageAlerts(), h.calculateSecurityScore)
				maturity.POST("/scores/calculate-all", h.RequireManageAlerts(), h.calculateAllTeamScores)
				maturity.GET("/scores/teams", h.getLatestTeamScores)
				maturity.GET("/scores/leaderboard", h.getTeamLeaderboard)
				maturity.GET("/scores/trend", h.getScoreTrend)
				maturity.GET("/metrics", h.listSecurityMetrics)
			}

			// Code Quality (Epic 12: Code Quality Integration)
			codeQuality := protected.Group("/code-quality")
			{
				// Results
				codeQuality.GET("/results", h.listCodeQualityResults)
				codeQuality.GET("/results/:id", h.getCodeQualityResult)
				codeQuality.POST("/results", h.RequireModifyContainers(), h.createCodeQualityResult)
				codeQuality.GET("/results/:id/issues", h.getCodeQualityIssues)
				codeQuality.GET("/results/:id/evaluations", h.getCodeQualityPolicyEvaluations)
				codeQuality.POST("/results/:id/evaluate", h.RequireManageAlerts(), h.evaluateCodeQualityPolicies)

				// Summaries & Leaderboard
				codeQuality.GET("/summary", h.getProjectQualitySummary)
				codeQuality.GET("/leaderboard", h.getCodeQualityLeaderboard)

				// Policies
				codeQuality.GET("/policies", h.listCodeQualityPolicies)
				codeQuality.POST("/policies", h.RequireManageAlerts(), h.createCodeQualityPolicy)
				codeQuality.PUT("/policies/:id", h.RequireManageAlerts(), h.updateCodeQualityPolicy)
				codeQuality.DELETE("/policies/:id", h.RequireManageAlerts(), h.deleteCodeQualityPolicy)
			}

			// Platform Security (Epic 6: DevSecOps Hardening)
			security := protected.Group("/security")
			{
				// Configuration
				security.GET("/config", h.getPlatformSecurityConfig)
				security.PUT("/config", h.RequireManageAlerts(), h.updatePlatformSecurityConfig)

				// Self-Check & Posture
				security.POST("/self-check", h.runSecuritySelfCheck)
				security.GET("/platform-posture", h.getPlatformSecurityPosture)

				// Policy Violations
				security.GET("/violations", h.listPolicyViolations)
				security.GET("/violations/summary", h.getViolationSummary)
				security.POST("/violations/:id/acknowledge", h.RequireManageAlerts(), h.acknowledgeViolation)
			}

			// Runtime Security (Epic 3: Runtime Security & Drift Detection)
			runtime := protected.Group("/runtime")
			{
				// Drift Events
				runtime.GET("/drift-events", h.listDriftEvents)
				runtime.GET("/drift-events/:id", h.getDriftEvent)
				runtime.POST("/drift-events/:id/resolve", h.RequireManageAlerts(), h.resolveDriftEvent)

				// Behavioral Anomalies
				runtime.GET("/anomalies", h.listBehavioralAnomalies)
				runtime.GET("/anomalies/:id", h.getBehavioralAnomaly)
				runtime.POST("/anomalies/:id/resolve", h.RequireManageAlerts(), h.resolveBehavioralAnomaly)

				// Configuration & Posture
				runtime.GET("/config", h.getRuntimeSecurityConfig)
				runtime.PUT("/config", h.RequireManageAlerts(), h.updateRuntimeSecurityConfig)
				runtime.GET("/posture", h.getRuntimeSecurityPosture)
			}

			// Traffic & Exposure Governance (Epic 13)
			exposure := protected.Group("/exposure")
			{
				exposure.GET("/endpoints", h.listExposedEndpoints)
				exposure.GET("/endpoints/:id", h.getExposedEndpoint)
				exposure.POST("/endpoints", h.RequireManageAlerts(), h.createExposedEndpoint)
				exposure.PUT("/endpoints/:id", h.RequireManageAlerts(), h.updateExposedEndpoint)
				exposure.DELETE("/endpoints/:id", h.RequireManageAlerts(), h.deleteExposedEndpoint)
				exposure.GET("/summary", h.getExposureSummary)
				exposure.GET("/map", h.getExposureMap)
			}

			// Rate Limit Profiles (Epic 13)
			ratelimits := protected.Group("/ratelimits")
			{
				ratelimits.GET("/profiles", h.listRateLimitProfiles)
				ratelimits.POST("/profiles", h.RequireManageAlerts(), h.createRateLimitProfile)
				ratelimits.PUT("/profiles/:id", h.RequireManageAlerts(), h.updateRateLimitProfile)
				ratelimits.DELETE("/profiles/:id", h.RequireManageAlerts(), h.deleteRateLimitProfile)
			}

			// TLS Governance (Epic 13)
			tls := protected.Group("/tls")
			{
				tls.GET("/posture", h.getTLSPosture)
				tls.GET("/scans", h.listTLSScans)
				tls.GET("/config", h.getTLSAlertConfig)
				tls.PUT("/config", h.RequireManageAlerts(), h.updateTLSAlertConfig)
			}

			// Traffic Resources & Policies (Epic 13 v2)
			traffic := protected.Group("/traffic")
			{
				// Traffic summary
				traffic.GET("/summary", h.getTrafficSummary)

				// Traffic Resources
				traffic.GET("/resources", h.listTrafficResources)
				traffic.GET("/resources/:id", h.getTrafficResource)
				traffic.POST("/resources", h.RequireManageAlerts(), h.createTrafficResource)
				traffic.PUT("/resources/:id", h.RequireManageAlerts(), h.updateTrafficResource)
				traffic.DELETE("/resources/:id", h.RequireManageAlerts(), h.deleteTrafficResource)

				// Traffic Resource Upstreams
				traffic.GET("/resources/:id/upstreams", h.listTrafficUpstreams)
				traffic.POST("/resources/:id/upstreams", h.RequireManageAlerts(), h.createTrafficUpstream)

				// Traffic Resource History
				traffic.GET("/resources/:id/history", h.getTrafficApplyHistory)

				// Traffic Policies
				traffic.GET("/policies", h.listTrafficPolicies)
				traffic.GET("/policies/:id", h.getTrafficPolicy)
				traffic.POST("/policies", h.RequireManageAlerts(), h.createTrafficPolicy)
				traffic.PUT("/policies/:id", h.RequireManageAlerts(), h.updateTrafficPolicy)
				traffic.DELETE("/policies/:id", h.RequireManageAlerts(), h.deleteTrafficPolicy)

				// Policy Assignment
				traffic.POST("/policies/:id/assign", h.RequireManageAlerts(), h.assignTrafficPolicy)
			}

			// Database & Data Governance (Epic 14)
			databases := protected.Group("/databases")
			{
				databases.GET("", h.listDatabaseInventory)
				databases.GET("/posture", h.getDatabasePosture)
				databases.GET("/compliance", h.getDatabaseBackupCompliance)
				databases.POST("", h.RequireManageAlerts(), h.createDatabaseInventory)
				databases.GET("/:id", h.getDatabaseInventoryItem)
				databases.PUT("/:id", h.RequireManageAlerts(), h.updateDatabaseInventory)
				databases.DELETE("/:id", h.RequireManageAlerts(), h.deleteDatabaseInventory)
				databases.GET("/:id/backups", h.listDatabaseBackups)
			}

			// Backup & Recovery (Epic 15)
			backups := protected.Group("/backups")
			{
				backups.GET("/overview", h.getBackupOverview)
				backups.GET("/jobs", h.listBackupJobs)
				backups.POST("/jobs", h.RequireManageAlerts(), h.triggerBackup)
				backups.GET("/restores", h.listRestoreOperations)
				backups.POST("/restores", h.RequireManageAlerts(), h.triggerRestore)
				backups.GET("/recovery-tests", h.listRecoveryTests)
				backups.POST("/recovery-tests", h.RequireManageAlerts(), h.triggerRecoveryTest)
				backups.GET("/readiness", h.getRecoveryReadiness)
				backups.GET("/alerts", h.listBackupAlerts)
				backups.PUT("/alerts/:id", h.RequireManageAlerts(), h.updateBackupAlertStatus)
				backups.GET("/storage", h.listBackupStorage)
				backups.POST("/storage", h.RequireManageAlerts(), h.createBackupStorage)
				backups.DELETE("/storage/:id", h.RequireManageAlerts(), h.deleteBackupStorage)
			}

			// Secrets Hygiene (Epic 16)
			secrets := protected.Group("/secrets")
			{
				secrets.GET("", h.listSecrets)
				secrets.GET("/hygiene", h.getSecretsHygieneSummary)
				secrets.POST("", h.RequireManageAlerts(), h.createSecret)
				secrets.GET("/:id", h.getSecret)
				secrets.DELETE("/:id", h.RequireManageAlerts(), h.deleteSecret)
				secrets.GET("/exposures", h.listSecretExposures)
				secrets.GET("/exposures/summary", h.getSecretExposureSummary)
				secrets.PUT("/exposures/:id", h.RequireManageAlerts(), h.updateExposureStatus)
				secrets.GET("/rotations", h.listRotationHistory)
				secrets.GET("/policies", h.listRotationPolicies)
				secrets.POST("/policies", h.RequireManageAlerts(), h.createRotationPolicy)
				secrets.DELETE("/policies/:id", h.RequireManageAlerts(), h.deleteRotationPolicy)
				secrets.GET("/scans", h.listSecretScans)
				secrets.POST("/scans", h.RequireManageAlerts(), h.triggerSecretScan)
			}

			// Background Jobs & Workers (Epic 17)
			jobs := protected.Group("/jobs")
			{
				jobs.GET("", h.listJobs)
				jobs.GET("/statistics", h.getJobStatistics)
				jobs.POST("", h.RequireManageAlerts(), h.createJob)
				jobs.GET("/:id", h.getJob)
				jobs.POST("/:id/cancel", h.RequireManageAlerts(), h.cancelJob)
				jobs.POST("/:id/retry", h.RequireManageAlerts(), h.retryJob)
				jobs.GET("/:id/logs", h.getJobLogs)
				jobs.GET("/schedules", h.listSchedules)
				jobs.POST("/schedules", h.RequireManageAlerts(), h.createSchedule)
				jobs.PUT("/schedules/:id/toggle", h.RequireManageAlerts(), h.toggleSchedule)
				jobs.DELETE("/schedules/:id", h.RequireManageAlerts(), h.deleteSchedule)
				jobs.GET("/workers", h.listWorkers)
				jobs.GET("/workers/summary", h.getWorkerSummary)
			}

			// External Dependencies (Epic 18)
			dependencies := protected.Group("/dependencies")
			{
				dependencies.GET("", h.listExternalServices)
				dependencies.GET("/overview", h.getExternalHealthOverview)
				dependencies.GET("/risks", h.getDependencyRisks)
				dependencies.POST("", h.RequireManageAlerts(), h.createExternalService)
				dependencies.GET("/:serviceId", h.getExternalService)
				dependencies.PUT("/:serviceId", h.RequireManageAlerts(), h.updateExternalService)
				dependencies.DELETE("/:serviceId", h.RequireManageAlerts(), h.deleteExternalService)
				dependencies.GET("/:serviceId/health", h.getServiceHealthHistory)
				dependencies.GET("/mappings", h.listServiceDependencies)
				dependencies.POST("/mappings", h.RequireManageAlerts(), h.createServiceDependency)
				dependencies.DELETE("/mappings/:dependencyId", h.RequireManageAlerts(), h.deleteServiceDependency)
				dependencies.GET("/incidents", h.listExternalIncidents)
				dependencies.POST("/incidents", h.RequireManageAlerts(), h.createExternalIncident)
				dependencies.PUT("/incidents/:incidentId", h.RequireManageAlerts(), h.updateExternalIncidentStatus)
			}

			// Research & Metrics (Epic 7)
			metrics := protected.Group("/metrics")
			{
				metrics.GET("", h.listMetricDefinitions)
				metrics.POST("", h.RequireManageAlerts(), h.createMetricDefinition)
				metrics.DELETE("/:metricId", h.RequireManageAlerts(), h.deleteMetricDefinition)
				metrics.GET("/:metricId/values", h.getMetricValues)
				metrics.GET("/summary", h.getMetricSummary)
			}
			dashboards := protected.Group("/dashboards")
			{
				dashboards.GET("", h.listDashboards)
				dashboards.POST("", h.RequireManageAlerts(), h.createDashboard)
				dashboards.DELETE("/:dashboardId", h.RequireManageAlerts(), h.deleteDashboard)
			}
			reports := protected.Group("/reports")
			{
				reports.GET("", h.listReports)
				reports.POST("", h.RequireManageAlerts(), h.createReport)
				reports.POST("/:reportId/run", h.RequireManageAlerts(), h.runReport)
				reports.GET("/executions", h.listReportExecutions)
			}
			telemetry := protected.Group("/telemetry")
			{
				telemetry.GET("/settings", h.getTelemetrySettings)
				telemetry.PUT("/settings", h.RequireManageAlerts(), h.updateTelemetrySettings)
			}

			// Container Registries
			registries := protected.Group("/registries")
			{
				registries.GET("", h.listRegistries)
				registries.POST("", h.RequireManageAlerts(), h.createRegistry)
				registries.GET("/:rid", h.getRegistry)
				registries.PUT("/:rid", h.RequireManageAlerts(), h.updateRegistry)
				registries.DELETE("/:rid", h.RequireManageAlerts(), h.deleteRegistry)
				registries.POST("/:rid/test", h.RequireManageAlerts(), h.testRegistryConnection)
				registries.GET("/:rid/repositories", h.listRegistryRepositories)
				registries.GET("/:rid/repositories/:repo/tags", h.listRegistryTags)
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

				// SSO Configuration
				settings.GET("/sso", h.listSSOConfigs)
				settings.POST("/sso", h.createSSOConfig)
				settings.GET("/sso/:id", h.getSSOConfig)
				settings.DELETE("/sso/:id", h.deleteSSOConfig)
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

				// DNS-01 Challenge (for wildcard certificates)
				ssl.POST("/dns-challenge/start", h.RequireRole(auth.RoleSuperAdmin), h.startDNSChallenge)
				ssl.POST("/dns-challenge/complete", h.RequireRole(auth.RoleSuperAdmin), h.completeDNSChallenge)
				ssl.GET("/dns-challenge/:domain", h.getDNSChallenge)
				ssl.GET("/dns-challenge/verify/:domain", h.verifyDNSTXTRecord)

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
			var basicAuthEnabled bool
			var basicAuthRealm string

			err := h.db.QueryRow(ctx, `
				SELECT ph.id, ph.agent_id, a.org_id, ph.domain, ph.ssl_enabled, ph.force_ssl, ph.http2_enabled,
				       ph.ssl_cert_path, ph.ssl_key_path,
				       COALESCE(ph.basic_auth_enabled, false), COALESCE(ph.basic_auth_realm, 'Restricted')
				FROM proxy_hosts ph
				JOIN agents a ON a.id = ph.agent_id
				WHERE ph.is_system_proxy = TRUE
				LIMIT 1
			`).Scan(&proxyID, &agentID, &orgID, &domain, &sslEnabled, &forceSSL, &http2, &sslCertPath, &sslKeyPath, &basicAuthEnabled, &basicAuthRealm)

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

			// Determine htpasswd path for this proxy (use sanitized domain)
			htpasswdPath := ""
			if basicAuthEnabled {
				htpasswdPath = fmt.Sprintf("/data/nginx/conf.d/.htpasswd_%s", strings.ReplaceAll(domain, ".", "_"))
			}

			// Dispatch the InfraPilot system proxy config (routes /api to backend)
			h.dispatchInfraPilotProxyConfigWithCert(ctx, agentID, proxyID, domain, forceSSL, http2, sslEnabled, certPath, keyPath, basicAuthEnabled, basicAuthRealm, htpasswdPath)

			// Dispatch the default page config (welcome page for IP access)
			h.dispatchDefaultPageConfig(agentID, orgID, true)

			dispatched = true
		}
	}
}
