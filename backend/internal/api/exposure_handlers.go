package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Exposure Types

type ExposedEndpoint struct {
	ID                     uuid.UUID              `json:"id"`
	OrgID                  uuid.UUID              `json:"org_id"`
	AgentID                uuid.UUID              `json:"agent_id"`
	ProxyHostID            *uuid.UUID             `json:"proxy_host_id,omitempty"`
	DeploymentID           *uuid.UUID             `json:"deployment_id,omitempty"`
	Domain                 string                 `json:"domain"`
	Path                   string                 `json:"path"`
	Port                   int                    `json:"port"`
	Protocol               string                 `json:"protocol"`
	ExposureType           string                 `json:"exposure_type"`
	AuthenticationRequired bool                   `json:"authentication_required"`
	AuthenticationType     *string                `json:"authentication_type,omitempty"`
	RiskScore              int                    `json:"risk_score"`
	RiskFactors            map[string]interface{} `json:"risk_factors"`
	LastRiskAssessment     *time.Time             `json:"last_risk_assessment,omitempty"`
	AvgRequestsPerHour     *float64               `json:"avg_requests_per_hour,omitempty"`
	PeakRequestsPerHour    *float64               `json:"peak_requests_per_hour,omitempty"`
	UniqueClients24h       *int                   `json:"unique_clients_24h,omitempty"`
	LastAccessedAt         *time.Time             `json:"last_accessed_at,omitempty"`
	ServiceName            *string                `json:"service_name,omitempty"`
	ServiceOwner           *string                `json:"service_owner,omitempty"`
	Description            *string                `json:"description,omitempty"`
	Tags                   []string               `json:"tags"`
	Status                 string                 `json:"status"`
	DiscoveredAt           time.Time              `json:"discovered_at"`
	CreatedAt              time.Time              `json:"created_at"`
	UpdatedAt              time.Time              `json:"updated_at"`
}

type RateLimitProfile struct {
	ID                 uuid.UUID `json:"id"`
	OrgID              uuid.UUID `json:"org_id"`
	Name               string    `json:"name"`
	Description        *string   `json:"description,omitempty"`
	RequestsPerSecond  *int      `json:"requests_per_second,omitempty"`
	RequestsPerMinute  *int      `json:"requests_per_minute,omitempty"`
	RequestsPerHour    *int      `json:"requests_per_hour,omitempty"`
	BurstSize          int       `json:"burst_size"`
	KeyType            string    `json:"key_type"`
	CustomKeyHeader    *string   `json:"custom_key_header,omitempty"`
	ExceededAction     string    `json:"exceeded_action"`
	ExceededStatusCode int       `json:"exceeded_status_code"`
	ExceededMessage    string    `json:"exceeded_message"`
	IsDefault          bool      `json:"is_default"`
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type RateLimitAssignment struct {
	ID                uuid.UUID  `json:"id"`
	OrgID             uuid.UUID  `json:"org_id"`
	ProfileID         uuid.UUID  `json:"profile_id"`
	EndpointID        *uuid.UUID `json:"endpoint_id,omitempty"`
	ProxyHostID       *uuid.UUID `json:"proxy_host_id,omitempty"`
	DomainPattern     *string    `json:"domain_pattern,omitempty"`
	RequestsPerSecond *int       `json:"requests_per_second,omitempty"`
	RequestsPerMinute *int       `json:"requests_per_minute,omitempty"`
	BurstSize         *int       `json:"burst_size,omitempty"`
	Priority          int        `json:"priority"`
	Enabled           bool       `json:"enabled"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type TLSAlertConfig struct {
	ID                       uuid.UUID   `json:"id"`
	OrgID                    uuid.UUID   `json:"org_id"`
	ExpiryWarningDays        int         `json:"expiry_warning_days"`
	ExpiryCriticalDays       int         `json:"expiry_critical_days"`
	AlertOnWeakCipher        bool        `json:"alert_on_weak_cipher"`
	AlertOnProtocolDowngrade bool        `json:"alert_on_protocol_downgrade"`
	AlertOnCertMismatch      bool        `json:"alert_on_cert_mismatch"`
	AlertOnSelfSigned        bool        `json:"alert_on_self_signed"`
	AlertOnExpired           bool        `json:"alert_on_expired"`
	NotificationChannels     []uuid.UUID `json:"notification_channels"`
	AutoScanEnabled          bool        `json:"auto_scan_enabled"`
	ScanIntervalHours        int         `json:"scan_interval_hours"`
	LastScanAt               *time.Time  `json:"last_scan_at,omitempty"`
	CreatedAt                time.Time   `json:"created_at"`
	UpdatedAt                time.Time   `json:"updated_at"`
}

type TLSScanResult struct {
	ID              uuid.UUID              `json:"id"`
	OrgID           uuid.UUID              `json:"org_id"`
	EndpointID      *uuid.UUID             `json:"endpoint_id,omitempty"`
	ProxyHostID     *uuid.UUID             `json:"proxy_host_id,omitempty"`
	Domain          string                 `json:"domain"`
	CertValid       bool                   `json:"cert_valid"`
	CertIssuer      *string                `json:"cert_issuer,omitempty"`
	CertSubject     *string                `json:"cert_subject,omitempty"`
	CertExpiresAt   *time.Time             `json:"cert_expires_at,omitempty"`
	CertDaysLeft    *int                   `json:"cert_days_left,omitempty"`
	CertSAN         []string               `json:"cert_san"`
	IsSelfSigned    bool                   `json:"is_self_signed"`
	ProtocolVersion *string                `json:"protocol_version,omitempty"`
	CipherSuite     *string                `json:"cipher_suite,omitempty"`
	KeyExchange     *string                `json:"key_exchange,omitempty"`
	IsWeakCipher    bool                   `json:"is_weak_cipher"`
	HSTSEnabled     bool                   `json:"hsts_enabled"`
	HSTSMaxAge      *int                   `json:"hsts_max_age,omitempty"`
	HSTSPreload     bool                   `json:"hsts_preload"`
	Grade           *string                `json:"grade,omitempty"`
	Score           *int                   `json:"score,omitempty"`
	Issues          map[string]interface{} `json:"issues"`
	ScannedAt       time.Time              `json:"scanned_at"`
	CreatedAt       time.Time              `json:"created_at"`
}

type ExposureSummary struct {
	OrgID                   uuid.UUID `json:"org_id"`
	TotalEndpoints          int       `json:"total_endpoints"`
	PublicEndpoints         int       `json:"public_endpoints"`
	InternalEndpoints       int       `json:"internal_endpoints"`
	UnauthenticatedPublic   int       `json:"unauthenticated_public"`
	AvgRiskScore            int       `json:"avg_risk_score"`
	HighRiskEndpoints       int       `json:"high_risk_endpoints"`
	ActiveEndpoints         int       `json:"active_endpoints"`
}

type TLSPosture struct {
	OrgID            uuid.UUID `json:"org_id"`
	TotalDomains     int       `json:"total_domains"`
	ValidCerts       int       `json:"valid_certs"`
	InvalidCerts     int       `json:"invalid_certs"`
	SelfSigned       int       `json:"self_signed"`
	WeakCiphers      int       `json:"weak_ciphers"`
	ExpiringCritical int       `json:"expiring_critical"`
	ExpiringWarning  int       `json:"expiring_warning"`
	AvgScore         int       `json:"avg_score"`
}

type ExposureMap struct {
	Endpoints         []ExposedEndpoint `json:"endpoints"`
	ConnectionMatrix  []Connection      `json:"connection_matrix"`
	ExternalDomains   []string          `json:"external_domains"`
	InternalServices  []string          `json:"internal_services"`
}

type Connection struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Encrypted   bool   `json:"encrypted"`
}

// GET /api/v1/exposure/endpoints
func (h *Handler) listExposedEndpoints(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Query parameters
	exposureType := c.Query("exposure_type")
	status := c.Query("status")
	minRiskScore := c.Query("min_risk_score")
	limit := c.DefaultQuery("limit", "100")
	offset := c.DefaultQuery("offset", "0")

	query := `
		SELECT
			id, org_id, agent_id, proxy_host_id, deployment_id,
			domain, path, port, protocol, exposure_type,
			authentication_required, authentication_type,
			risk_score, risk_factors, last_risk_assessment,
			avg_requests_per_hour, peak_requests_per_hour, unique_clients_24h, last_accessed_at,
			service_name, service_owner, description, tags, status,
			discovered_at, created_at, updated_at
		FROM exposed_endpoints
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argCount := 1

	if exposureType != "" {
		argCount++
		query += ` AND exposure_type = $` + string(rune(argCount+48))
		args = append(args, exposureType)
	}
	if status != "" {
		argCount++
		query += ` AND status = $` + string(rune(argCount+48))
		args = append(args, status)
	}
	if minRiskScore != "" {
		argCount++
		query += ` AND risk_score >= $` + string(rune(argCount+48))
		args = append(args, minRiskScore)
	}

	query += ` ORDER BY risk_score DESC, created_at DESC LIMIT $` + string(rune(argCount+49)) + ` OFFSET $` + string(rune(argCount+50))
	args = append(args, limit, offset)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch exposed endpoints"})
		return
	}
	defer rows.Close()

	var endpoints []ExposedEndpoint
	for rows.Next() {
		var ep ExposedEndpoint
		err := rows.Scan(
			&ep.ID, &ep.OrgID, &ep.AgentID, &ep.ProxyHostID, &ep.DeploymentID,
			&ep.Domain, &ep.Path, &ep.Port, &ep.Protocol, &ep.ExposureType,
			&ep.AuthenticationRequired, &ep.AuthenticationType,
			&ep.RiskScore, &ep.RiskFactors, &ep.LastRiskAssessment,
			&ep.AvgRequestsPerHour, &ep.PeakRequestsPerHour, &ep.UniqueClients24h, &ep.LastAccessedAt,
			&ep.ServiceName, &ep.ServiceOwner, &ep.Description, &ep.Tags, &ep.Status,
			&ep.DiscoveredAt, &ep.CreatedAt, &ep.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan endpoint: " + err.Error())
			continue
		}
		endpoints = append(endpoints, ep)
	}

	if endpoints == nil {
		endpoints = []ExposedEndpoint{}
	}

	// Get total count
	countQuery := `SELECT COUNT(*) FROM exposed_endpoints WHERE org_id = $1`
	var total int
	h.db.QueryRow(c.Request.Context(), countQuery, orgID).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"endpoints": endpoints,
		"total":     total,
	})
}

// GET /api/v1/exposure/endpoints/:id
func (h *Handler) getExposedEndpoint(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	endpointID := c.Param("id")

	endpointUUID, err := uuid.Parse(endpointID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid endpoint ID"})
		return
	}

	query := `
		SELECT
			id, org_id, agent_id, proxy_host_id, deployment_id,
			domain, path, port, protocol, exposure_type,
			authentication_required, authentication_type,
			risk_score, risk_factors, last_risk_assessment,
			avg_requests_per_hour, peak_requests_per_hour, unique_clients_24h, last_accessed_at,
			service_name, service_owner, description, tags, status,
			discovered_at, created_at, updated_at
		FROM exposed_endpoints
		WHERE id = $1 AND org_id = $2
	`

	var ep ExposedEndpoint
	err = h.db.QueryRow(c.Request.Context(), query, endpointUUID, orgID).Scan(
		&ep.ID, &ep.OrgID, &ep.AgentID, &ep.ProxyHostID, &ep.DeploymentID,
		&ep.Domain, &ep.Path, &ep.Port, &ep.Protocol, &ep.ExposureType,
		&ep.AuthenticationRequired, &ep.AuthenticationType,
		&ep.RiskScore, &ep.RiskFactors, &ep.LastRiskAssessment,
		&ep.AvgRequestsPerHour, &ep.PeakRequestsPerHour, &ep.UniqueClients24h, &ep.LastAccessedAt,
		&ep.ServiceName, &ep.ServiceOwner, &ep.Description, &ep.Tags, &ep.Status,
		&ep.DiscoveredAt, &ep.CreatedAt, &ep.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Endpoint not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch endpoint"})
		return
	}

	c.JSON(http.StatusOK, ep)
}

// POST /api/v1/exposure/endpoints
func (h *Handler) createExposedEndpoint(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req struct {
		AgentID                string   `json:"agent_id" binding:"required"`
		ProxyHostID            *string  `json:"proxy_host_id"`
		DeploymentID           *string  `json:"deployment_id"`
		Domain                 string   `json:"domain" binding:"required"`
		Path                   string   `json:"path"`
		Port                   int      `json:"port" binding:"required"`
		Protocol               string   `json:"protocol"`
		ExposureType           string   `json:"exposure_type" binding:"required"`
		AuthenticationRequired bool     `json:"authentication_required"`
		AuthenticationType     *string  `json:"authentication_type"`
		ServiceName            *string  `json:"service_name"`
		ServiceOwner           *string  `json:"service_owner"`
		Description            *string  `json:"description"`
		Tags                   []string `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	agentUUID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	// Set defaults
	if req.Path == "" {
		req.Path = "/"
	}
	if req.Protocol == "" {
		req.Protocol = "https"
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	// Calculate initial risk score
	riskScore := calculateEndpointRiskScore(req.ExposureType, req.AuthenticationRequired, req.Protocol)
	riskFactors := map[string]interface{}{
		"exposure_type":    req.ExposureType,
		"unauthenticated":  !req.AuthenticationRequired,
		"unencrypted":      req.Protocol == "http",
	}

	var proxyHostID, deploymentID *uuid.UUID
	if req.ProxyHostID != nil {
		id, _ := uuid.Parse(*req.ProxyHostID)
		proxyHostID = &id
	}
	if req.DeploymentID != nil {
		id, _ := uuid.Parse(*req.DeploymentID)
		deploymentID = &id
	}

	query := `
		INSERT INTO exposed_endpoints (
			org_id, agent_id, proxy_host_id, deployment_id,
			domain, path, port, protocol, exposure_type,
			authentication_required, authentication_type,
			risk_score, risk_factors, last_risk_assessment,
			service_name, service_owner, description, tags
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), $14, $15, $16, $17)
		RETURNING id, created_at, updated_at, discovered_at
	`

	var ep ExposedEndpoint
	ep.OrgID = orgID
	ep.AgentID = agentUUID
	ep.ProxyHostID = proxyHostID
	ep.DeploymentID = deploymentID
	ep.Domain = req.Domain
	ep.Path = req.Path
	ep.Port = req.Port
	ep.Protocol = req.Protocol
	ep.ExposureType = req.ExposureType
	ep.AuthenticationRequired = req.AuthenticationRequired
	ep.AuthenticationType = req.AuthenticationType
	ep.RiskScore = riskScore
	ep.RiskFactors = riskFactors
	ep.ServiceName = req.ServiceName
	ep.ServiceOwner = req.ServiceOwner
	ep.Description = req.Description
	ep.Tags = req.Tags
	ep.Status = "active"

	err = h.db.QueryRow(c.Request.Context(), query,
		orgID, agentUUID, proxyHostID, deploymentID,
		req.Domain, req.Path, req.Port, req.Protocol, req.ExposureType,
		req.AuthenticationRequired, req.AuthenticationType,
		riskScore, riskFactors,
		req.ServiceName, req.ServiceOwner, req.Description, req.Tags,
	).Scan(&ep.ID, &ep.CreatedAt, &ep.UpdatedAt, &ep.DiscoveredAt)

	if err != nil {
		h.logger.Error("Failed to create endpoint: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create endpoint"})
		return
	}

	c.JSON(http.StatusCreated, ep)
}

// PUT /api/v1/exposure/endpoints/:id
func (h *Handler) updateExposedEndpoint(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	endpointID := c.Param("id")

	endpointUUID, err := uuid.Parse(endpointID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid endpoint ID"})
		return
	}

	var req struct {
		ExposureType           *string  `json:"exposure_type"`
		AuthenticationRequired *bool    `json:"authentication_required"`
		AuthenticationType     *string  `json:"authentication_type"`
		ServiceName            *string  `json:"service_name"`
		ServiceOwner           *string  `json:"service_owner"`
		Description            *string  `json:"description"`
		Tags                   []string `json:"tags"`
		Status                 *string  `json:"status"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	query := `
		UPDATE exposed_endpoints SET
			exposure_type = COALESCE($1, exposure_type),
			authentication_required = COALESCE($2, authentication_required),
			authentication_type = COALESCE($3, authentication_type),
			service_name = COALESCE($4, service_name),
			service_owner = COALESCE($5, service_owner),
			description = COALESCE($6, description),
			tags = COALESCE($7, tags),
			status = COALESCE($8, status),
			updated_at = NOW()
		WHERE id = $9 AND org_id = $10
		RETURNING id
	`

	var returnedID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), query,
		req.ExposureType, req.AuthenticationRequired, req.AuthenticationType,
		req.ServiceName, req.ServiceOwner, req.Description, req.Tags, req.Status,
		endpointUUID, orgID,
	).Scan(&returnedID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Endpoint not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update endpoint"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Endpoint updated successfully"})
}

// DELETE /api/v1/exposure/endpoints/:id
func (h *Handler) deleteExposedEndpoint(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	endpointID := c.Param("id")

	endpointUUID, err := uuid.Parse(endpointID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid endpoint ID"})
		return
	}

	query := `DELETE FROM exposed_endpoints WHERE id = $1 AND org_id = $2`
	result, err := h.db.Exec(c.Request.Context(), query, endpointUUID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete endpoint"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Endpoint not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Endpoint deleted successfully"})
}

// GET /api/v1/exposure/summary
func (h *Handler) getExposureSummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `SELECT * FROM v_exposure_summary WHERE org_id = $1`

	var summary ExposureSummary
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&summary.OrgID, &summary.TotalEndpoints, &summary.PublicEndpoints,
		&summary.InternalEndpoints, &summary.UnauthenticatedPublic,
		&summary.AvgRiskScore, &summary.HighRiskEndpoints, &summary.ActiveEndpoints,
	)

	if err == sql.ErrNoRows {
		// Return empty summary
		summary = ExposureSummary{OrgID: orgID}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch exposure summary"})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// GET /api/v1/exposure/map
func (h *Handler) getExposureMap(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Get all endpoints
	query := `
		SELECT
			id, org_id, agent_id, proxy_host_id, deployment_id,
			domain, path, port, protocol, exposure_type,
			authentication_required, authentication_type,
			risk_score, risk_factors, last_risk_assessment,
			avg_requests_per_hour, peak_requests_per_hour, unique_clients_24h, last_accessed_at,
			service_name, service_owner, description, tags, status,
			discovered_at, created_at, updated_at
		FROM exposed_endpoints
		WHERE org_id = $1 AND status = 'active'
		ORDER BY domain, path
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch exposure map"})
		return
	}
	defer rows.Close()

	var endpoints []ExposedEndpoint
	externalDomains := make(map[string]bool)
	internalServices := make(map[string]bool)

	for rows.Next() {
		var ep ExposedEndpoint
		err := rows.Scan(
			&ep.ID, &ep.OrgID, &ep.AgentID, &ep.ProxyHostID, &ep.DeploymentID,
			&ep.Domain, &ep.Path, &ep.Port, &ep.Protocol, &ep.ExposureType,
			&ep.AuthenticationRequired, &ep.AuthenticationType,
			&ep.RiskScore, &ep.RiskFactors, &ep.LastRiskAssessment,
			&ep.AvgRequestsPerHour, &ep.PeakRequestsPerHour, &ep.UniqueClients24h, &ep.LastAccessedAt,
			&ep.ServiceName, &ep.ServiceOwner, &ep.Description, &ep.Tags, &ep.Status,
			&ep.DiscoveredAt, &ep.CreatedAt, &ep.UpdatedAt,
		)
		if err != nil {
			continue
		}
		endpoints = append(endpoints, ep)

		if ep.ExposureType == "public" {
			externalDomains[ep.Domain] = true
		}
		if ep.ServiceName != nil && *ep.ServiceName != "" {
			internalServices[*ep.ServiceName] = true
		}
	}

	// Build connection matrix
	var connections []Connection
	for _, ep := range endpoints {
		if ep.ServiceName != nil && *ep.ServiceName != "" {
			connections = append(connections, Connection{
				Source:    "external",
				Target:    *ep.ServiceName,
				Protocol:  ep.Protocol,
				Port:      ep.Port,
				Encrypted: ep.Protocol == "https" || ep.Protocol == "grpcs",
			})
		}
	}

	// Convert maps to slices
	var extDomains []string
	for d := range externalDomains {
		extDomains = append(extDomains, d)
	}
	var intServices []string
	for s := range internalServices {
		intServices = append(intServices, s)
	}

	c.JSON(http.StatusOK, ExposureMap{
		Endpoints:        endpoints,
		ConnectionMatrix: connections,
		ExternalDomains:  extDomains,
		InternalServices: intServices,
	})
}

// GET /api/v1/ratelimits/profiles
func (h *Handler) listRateLimitProfiles(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			id, org_id, name, description,
			requests_per_second, requests_per_minute, requests_per_hour, burst_size,
			key_type, custom_key_header,
			exceeded_action, exceeded_status_code, exceeded_message,
			is_default, enabled, created_at, updated_at
		FROM rate_limit_profiles
		WHERE org_id = $1
		ORDER BY name
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch rate limit profiles"})
		return
	}
	defer rows.Close()

	var profiles []RateLimitProfile
	for rows.Next() {
		var p RateLimitProfile
		err := rows.Scan(
			&p.ID, &p.OrgID, &p.Name, &p.Description,
			&p.RequestsPerSecond, &p.RequestsPerMinute, &p.RequestsPerHour, &p.BurstSize,
			&p.KeyType, &p.CustomKeyHeader,
			&p.ExceededAction, &p.ExceededStatusCode, &p.ExceededMessage,
			&p.IsDefault, &p.Enabled, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			continue
		}
		profiles = append(profiles, p)
	}

	if profiles == nil {
		profiles = []RateLimitProfile{}
	}

	c.JSON(http.StatusOK, gin.H{"profiles": profiles})
}

// POST /api/v1/ratelimits/profiles
func (h *Handler) createRateLimitProfile(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req struct {
		Name               string  `json:"name" binding:"required"`
		Description        *string `json:"description"`
		RequestsPerSecond  *int    `json:"requests_per_second"`
		RequestsPerMinute  *int    `json:"requests_per_minute"`
		RequestsPerHour    *int    `json:"requests_per_hour"`
		BurstSize          int     `json:"burst_size"`
		KeyType            string  `json:"key_type"`
		CustomKeyHeader    *string `json:"custom_key_header"`
		ExceededAction     string  `json:"exceeded_action"`
		ExceededStatusCode int     `json:"exceeded_status_code"`
		ExceededMessage    string  `json:"exceeded_message"`
		IsDefault          bool    `json:"is_default"`
		Enabled            bool    `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Set defaults
	if req.BurstSize == 0 {
		req.BurstSize = 10
	}
	if req.KeyType == "" {
		req.KeyType = "ip"
	}
	if req.ExceededAction == "" {
		req.ExceededAction = "reject"
	}
	if req.ExceededStatusCode == 0 {
		req.ExceededStatusCode = 429
	}
	if req.ExceededMessage == "" {
		req.ExceededMessage = "Rate limit exceeded"
	}

	query := `
		INSERT INTO rate_limit_profiles (
			org_id, name, description,
			requests_per_second, requests_per_minute, requests_per_hour, burst_size,
			key_type, custom_key_header,
			exceeded_action, exceeded_status_code, exceeded_message,
			is_default, enabled
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id, created_at, updated_at
	`

	var profile RateLimitProfile
	profile.OrgID = orgID
	profile.Name = req.Name
	profile.Description = req.Description
	profile.RequestsPerSecond = req.RequestsPerSecond
	profile.RequestsPerMinute = req.RequestsPerMinute
	profile.RequestsPerHour = req.RequestsPerHour
	profile.BurstSize = req.BurstSize
	profile.KeyType = req.KeyType
	profile.CustomKeyHeader = req.CustomKeyHeader
	profile.ExceededAction = req.ExceededAction
	profile.ExceededStatusCode = req.ExceededStatusCode
	profile.ExceededMessage = req.ExceededMessage
	profile.IsDefault = req.IsDefault
	profile.Enabled = req.Enabled

	err := h.db.QueryRow(c.Request.Context(), query,
		orgID, req.Name, req.Description,
		req.RequestsPerSecond, req.RequestsPerMinute, req.RequestsPerHour, req.BurstSize,
		req.KeyType, req.CustomKeyHeader,
		req.ExceededAction, req.ExceededStatusCode, req.ExceededMessage,
		req.IsDefault, req.Enabled,
	).Scan(&profile.ID, &profile.CreatedAt, &profile.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create profile"})
		return
	}

	c.JSON(http.StatusCreated, profile)
}

// PUT /api/v1/ratelimits/profiles/:id
func (h *Handler) updateRateLimitProfile(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	profileID := c.Param("id")

	profileUUID, err := uuid.Parse(profileID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid profile ID"})
		return
	}

	var req struct {
		Name               *string `json:"name"`
		Description        *string `json:"description"`
		RequestsPerSecond  *int    `json:"requests_per_second"`
		RequestsPerMinute  *int    `json:"requests_per_minute"`
		RequestsPerHour    *int    `json:"requests_per_hour"`
		BurstSize          *int    `json:"burst_size"`
		KeyType            *string `json:"key_type"`
		ExceededAction     *string `json:"exceeded_action"`
		ExceededStatusCode *int    `json:"exceeded_status_code"`
		ExceededMessage    *string `json:"exceeded_message"`
		Enabled            *bool   `json:"enabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	query := `
		UPDATE rate_limit_profiles SET
			name = COALESCE($1, name),
			description = COALESCE($2, description),
			requests_per_second = COALESCE($3, requests_per_second),
			requests_per_minute = COALESCE($4, requests_per_minute),
			requests_per_hour = COALESCE($5, requests_per_hour),
			burst_size = COALESCE($6, burst_size),
			key_type = COALESCE($7, key_type),
			exceeded_action = COALESCE($8, exceeded_action),
			exceeded_status_code = COALESCE($9, exceeded_status_code),
			exceeded_message = COALESCE($10, exceeded_message),
			enabled = COALESCE($11, enabled),
			updated_at = NOW()
		WHERE id = $12 AND org_id = $13
		RETURNING id
	`

	var returnedID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), query,
		req.Name, req.Description,
		req.RequestsPerSecond, req.RequestsPerMinute, req.RequestsPerHour, req.BurstSize,
		req.KeyType, req.ExceededAction, req.ExceededStatusCode, req.ExceededMessage,
		req.Enabled, profileUUID, orgID,
	).Scan(&returnedID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Profile not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// DELETE /api/v1/ratelimits/profiles/:id
func (h *Handler) deleteRateLimitProfile(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	profileID := c.Param("id")

	profileUUID, err := uuid.Parse(profileID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid profile ID"})
		return
	}

	query := `DELETE FROM rate_limit_profiles WHERE id = $1 AND org_id = $2`
	result, err := h.db.Exec(c.Request.Context(), query, profileUUID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete profile"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Profile not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile deleted successfully"})
}

// GET /api/v1/tls/posture
func (h *Handler) getTLSPosture(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `SELECT * FROM v_tls_posture WHERE org_id = $1`

	var posture TLSPosture
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&posture.OrgID, &posture.TotalDomains, &posture.ValidCerts,
		&posture.InvalidCerts, &posture.SelfSigned, &posture.WeakCiphers,
		&posture.ExpiringCritical, &posture.ExpiringWarning, &posture.AvgScore,
	)

	if err == sql.ErrNoRows {
		posture = TLSPosture{OrgID: orgID}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch TLS posture"})
		return
	}

	c.JSON(http.StatusOK, posture)
}

// GET /api/v1/tls/scans
func (h *Handler) listTLSScans(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	domain := c.Query("domain")
	limit := c.DefaultQuery("limit", "50")

	query := `
		SELECT
			id, org_id, endpoint_id, proxy_host_id, domain,
			cert_valid, cert_issuer, cert_subject, cert_expires_at, cert_days_left, cert_san,
			is_self_signed, protocol_version, cipher_suite, key_exchange, is_weak_cipher,
			hsts_enabled, hsts_max_age, hsts_preload,
			grade, score, issues, scanned_at, created_at
		FROM tls_scan_results
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argCount := 1

	if domain != "" {
		argCount++
		query += ` AND domain = $` + string(rune(argCount+48))
		args = append(args, domain)
	}

	query += ` ORDER BY scanned_at DESC LIMIT $` + string(rune(argCount+49))
	args = append(args, limit)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch TLS scans"})
		return
	}
	defer rows.Close()

	var scans []TLSScanResult
	for rows.Next() {
		var s TLSScanResult
		err := rows.Scan(
			&s.ID, &s.OrgID, &s.EndpointID, &s.ProxyHostID, &s.Domain,
			&s.CertValid, &s.CertIssuer, &s.CertSubject, &s.CertExpiresAt, &s.CertDaysLeft, &s.CertSAN,
			&s.IsSelfSigned, &s.ProtocolVersion, &s.CipherSuite, &s.KeyExchange, &s.IsWeakCipher,
			&s.HSTSEnabled, &s.HSTSMaxAge, &s.HSTSPreload,
			&s.Grade, &s.Score, &s.Issues, &s.ScannedAt, &s.CreatedAt,
		)
		if err != nil {
			continue
		}
		scans = append(scans, s)
	}

	if scans == nil {
		scans = []TLSScanResult{}
	}

	c.JSON(http.StatusOK, gin.H{"scans": scans})
}

// GET /api/v1/tls/config
func (h *Handler) getTLSAlertConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			id, org_id, expiry_warning_days, expiry_critical_days,
			alert_on_weak_cipher, alert_on_protocol_downgrade, alert_on_cert_mismatch,
			alert_on_self_signed, alert_on_expired,
			notification_channels, auto_scan_enabled, scan_interval_hours, last_scan_at,
			created_at, updated_at
		FROM tls_alert_config
		WHERE org_id = $1
	`

	var config TLSAlertConfig
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&config.ID, &config.OrgID, &config.ExpiryWarningDays, &config.ExpiryCriticalDays,
		&config.AlertOnWeakCipher, &config.AlertOnProtocolDowngrade, &config.AlertOnCertMismatch,
		&config.AlertOnSelfSigned, &config.AlertOnExpired,
		&config.NotificationChannels, &config.AutoScanEnabled, &config.ScanIntervalHours, &config.LastScanAt,
		&config.CreatedAt, &config.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// Create default config
		config = TLSAlertConfig{
			OrgID:                    orgID,
			ExpiryWarningDays:        30,
			ExpiryCriticalDays:       7,
			AlertOnWeakCipher:        true,
			AlertOnProtocolDowngrade: true,
			AlertOnCertMismatch:      true,
			AlertOnSelfSigned:        true,
			AlertOnExpired:           true,
			NotificationChannels:     []uuid.UUID{},
			AutoScanEnabled:          true,
			ScanIntervalHours:        24,
		}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch TLS config"})
		return
	}

	c.JSON(http.StatusOK, config)
}

// PUT /api/v1/tls/config
func (h *Handler) updateTLSAlertConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req TLSAlertConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	query := `
		INSERT INTO tls_alert_config (
			org_id, expiry_warning_days, expiry_critical_days,
			alert_on_weak_cipher, alert_on_protocol_downgrade, alert_on_cert_mismatch,
			alert_on_self_signed, alert_on_expired,
			notification_channels, auto_scan_enabled, scan_interval_hours
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (org_id) DO UPDATE SET
			expiry_warning_days = EXCLUDED.expiry_warning_days,
			expiry_critical_days = EXCLUDED.expiry_critical_days,
			alert_on_weak_cipher = EXCLUDED.alert_on_weak_cipher,
			alert_on_protocol_downgrade = EXCLUDED.alert_on_protocol_downgrade,
			alert_on_cert_mismatch = EXCLUDED.alert_on_cert_mismatch,
			alert_on_self_signed = EXCLUDED.alert_on_self_signed,
			alert_on_expired = EXCLUDED.alert_on_expired,
			notification_channels = EXCLUDED.notification_channels,
			auto_scan_enabled = EXCLUDED.auto_scan_enabled,
			scan_interval_hours = EXCLUDED.scan_interval_hours,
			updated_at = NOW()
		RETURNING id
	`

	var returnedID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), query,
		orgID, req.ExpiryWarningDays, req.ExpiryCriticalDays,
		req.AlertOnWeakCipher, req.AlertOnProtocolDowngrade, req.AlertOnCertMismatch,
		req.AlertOnSelfSigned, req.AlertOnExpired,
		req.NotificationChannels, req.AutoScanEnabled, req.ScanIntervalHours,
	).Scan(&returnedID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update TLS config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TLS config updated successfully"})
}

// Helper function to calculate endpoint risk score
func calculateEndpointRiskScore(exposureType string, authRequired bool, protocol string) int {
	score := 0

	// Exposure type weight
	switch exposureType {
	case "public":
		score += 40
	case "partner":
		score += 25
	case "internal":
		score += 10
	case "private":
		score += 5
	}

	// Authentication weight
	if !authRequired {
		score += 30
	}

	// Protocol weight
	if protocol == "http" {
		score += 30
	} else if protocol == "tcp" {
		score += 20
	}

	if score > 100 {
		score = 100
	}

	return score
}
