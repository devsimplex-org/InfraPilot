package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// External Service types
type ExternalService struct {
	ID                       uuid.UUID              `json:"id"`
	OrgID                    uuid.UUID              `json:"org_id"`
	Name                     string                 `json:"name"`
	ServiceType              string                 `json:"service_type"`
	Provider                 *string                `json:"provider,omitempty"`
	EndpointURL              *string                `json:"endpoint_url,omitempty"`
	BaseDomain               *string                `json:"base_domain,omitempty"`
	Port                     *int                   `json:"port,omitempty"`
	Protocol                 string                 `json:"protocol"`
	Criticality              string                 `json:"criticality"`
	DataClassification       *string                `json:"data_classification,omitempty"`
	Environment              string                 `json:"environment"`
	HealthStatus             string                 `json:"health_status"`
	LastHealthCheck          *time.Time             `json:"last_health_check,omitempty"`
	HealthCheckURL           *string                `json:"health_check_url,omitempty"`
	HealthCheckIntervalSecs  int                    `json:"health_check_interval_seconds"`
	ExpectedUptimePercent    *float64               `json:"expected_uptime_percent,omitempty"`
	SLADocumentURL           *string                `json:"sla_document_url,omitempty"`
	ComplianceRequirements   []string               `json:"compliance_requirements"`
	AuthType                 *string                `json:"auth_type,omitempty"`
	AuthSecretID             *uuid.UUID             `json:"auth_secret_id,omitempty"`
	OwnerTeam                *string                `json:"owner_team,omitempty"`
	OwnerContact             *string                `json:"owner_contact,omitempty"`
	VendorContact            *string                `json:"vendor_contact,omitempty"`
	ContractEndDate          *time.Time             `json:"contract_end_date,omitempty"`
	DiscoveredAt             time.Time              `json:"discovered_at"`
	AutoDiscovered           bool                   `json:"auto_discovered"`
	DiscoverySource          *string                `json:"discovery_source,omitempty"`
	Description              *string                `json:"description,omitempty"`
	DocumentationURL         *string                `json:"documentation_url,omitempty"`
	Tags                     []string               `json:"tags"`
	Metadata                 map[string]interface{} `json:"metadata,omitempty"`
	Enabled                  bool                   `json:"enabled"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
}

type ServiceDependency struct {
	ID                   uuid.UUID  `json:"id"`
	OrgID                uuid.UUID  `json:"org_id"`
	SourceType           string     `json:"source_type"`
	SourceID             *uuid.UUID `json:"source_id,omitempty"`
	SourceName           string     `json:"source_name"`
	ExternalServiceID    uuid.UUID  `json:"external_service_id"`
	DependencyType       string     `json:"dependency_type"`
	IsCritical           bool       `json:"is_critical"`
	FallbackAvailable    bool       `json:"fallback_available"`
	FallbackServiceID    *uuid.UUID `json:"fallback_service_id,omitempty"`
	UsagePattern         *string    `json:"usage_pattern,omitempty"`
	AvgRequestsPerMinute *int       `json:"avg_requests_per_minute,omitempty"`
	AvgLatencyMs         *int       `json:"avg_latency_ms,omitempty"`
	FailureImpact        *string    `json:"failure_impact,omitempty"`
	DiscoveredAt         time.Time  `json:"discovered_at"`
	AutoDiscovered       bool       `json:"auto_discovered"`
	LastSeenAt           time.Time  `json:"last_seen_at"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
	// Joined fields
	ExternalServiceName *string `json:"external_service_name,omitempty"`
	ExternalServiceType *string `json:"external_service_type,omitempty"`
	Provider            *string `json:"provider,omitempty"`
}

type ExternalServiceHealth struct {
	ID             uuid.UUID  `json:"id"`
	OrgID          uuid.UUID  `json:"org_id"`
	ServiceID      uuid.UUID  `json:"service_id"`
	Status         string     `json:"status"`
	ResponseTimeMs *int       `json:"response_time_ms,omitempty"`
	StatusCode     *int       `json:"status_code,omitempty"`
	CheckType      string     `json:"check_type"`
	ErrorMessage   *string    `json:"error_message,omitempty"`
	CheckedAt      time.Time  `json:"checked_at"`
	// Joined fields
	ServiceName *string `json:"service_name,omitempty"`
}

type ExternalServiceIncident struct {
	ID                 uuid.UUID  `json:"id"`
	OrgID              uuid.UUID  `json:"org_id"`
	ServiceID          uuid.UUID  `json:"service_id"`
	Title              string     `json:"title"`
	Description        *string    `json:"description,omitempty"`
	Severity           string     `json:"severity"`
	IncidentType       *string    `json:"incident_type,omitempty"`
	Status             string     `json:"status"`
	StartedAt          time.Time  `json:"started_at"`
	DetectedAt         time.Time  `json:"detected_at"`
	AcknowledgedAt     *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt         *time.Time `json:"resolved_at,omitempty"`
	AffectedServices   []string   `json:"affected_services"`
	ImpactDescription  *string    `json:"impact_description,omitempty"`
	UserImpact         *string    `json:"user_impact,omitempty"`
	ResolutionNotes    *string    `json:"resolution_notes,omitempty"`
	RootCause          *string    `json:"root_cause,omitempty"`
	ReportedBy         *string    `json:"reported_by,omitempty"`
	VendorIncidentURL  *string    `json:"vendor_incident_url,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	// Joined fields
	ServiceName *string `json:"service_name,omitempty"`
}

type ExternalAPIEndpoint struct {
	ID                     uuid.UUID  `json:"id"`
	OrgID                  uuid.UUID  `json:"org_id"`
	ServiceID              uuid.UUID  `json:"service_id"`
	Path                   string     `json:"path"`
	Method                 string     `json:"method"`
	CallCount              int        `json:"call_count"`
	LastCalledAt           *time.Time `json:"last_called_at,omitempty"`
	AvgResponseTimeMs      *int       `json:"avg_response_time_ms,omitempty"`
	ErrorRatePercent       *float64   `json:"error_rate_percent,omitempty"`
	RateLimitRequests      *int       `json:"rate_limit_requests,omitempty"`
	RateLimitWindowSeconds *int       `json:"rate_limit_window_seconds,omitempty"`
	CurrentUsagePercent    *float64   `json:"current_usage_percent,omitempty"`
	DataSensitivity        *string    `json:"data_sensitivity,omitempty"`
	DiscoveredAt           time.Time  `json:"discovered_at"`
	AutoDiscovered         bool       `json:"auto_discovered"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
	// Joined fields
	ServiceName *string `json:"service_name,omitempty"`
}

type ExternalServiceSummary struct {
	ServiceID               uuid.UUID `json:"service_id"`
	Name                    string    `json:"name"`
	ServiceType             string    `json:"service_type"`
	Provider                *string   `json:"provider,omitempty"`
	Criticality             string    `json:"criticality"`
	HealthStatus            string    `json:"health_status"`
	LastHealthCheck         *time.Time`json:"last_health_check,omitempty"`
	Environment             string    `json:"environment"`
	DependentServicesCount  int       `json:"dependent_services_count"`
	CriticalDependencies    int       `json:"critical_dependencies"`
	APIEndpointsCount       int       `json:"api_endpoints_count"`
	ActiveIncidents         int       `json:"active_incidents"`
}

type DependencyRisk struct {
	SourceName          string  `json:"source_name"`
	SourceType          string  `json:"source_type"`
	ExternalServiceName string  `json:"external_service_name"`
	ServiceType         string  `json:"service_type"`
	Provider            *string `json:"provider,omitempty"`
	ServiceCriticality  string  `json:"service_criticality"`
	DependencyCritical  bool    `json:"dependency_critical"`
	FallbackAvailable   bool    `json:"fallback_available"`
	HealthStatus        string  `json:"health_status"`
	FailureImpact       *string `json:"failure_impact,omitempty"`
	RiskLevel           string  `json:"risk_level"`
}

type ExternalHealthOverview struct {
	TotalServices      int `json:"total_services"`
	HealthyServices    int `json:"healthy_services"`
	DegradedServices   int `json:"degraded_services"`
	UnhealthyServices  int `json:"unhealthy_services"`
	UnknownServices    int `json:"unknown_services"`
	CriticalServices   int `json:"critical_services"`
	CriticalUnhealthy  int `json:"critical_unhealthy"`
}

// List external services
func (h *Handler) listExternalServices(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Query params
	serviceType := c.Query("service_type")
	provider := c.Query("provider")
	criticality := c.Query("criticality")
	healthStatus := c.Query("health_status")
	environment := c.Query("environment")
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, _ := strconv.Atoi(limitStr)
	offset, _ := strconv.Atoi(offsetStr)

	query := `
		SELECT id, org_id, name, service_type, provider, endpoint_url, base_domain,
			port, protocol, criticality, data_classification, environment,
			health_status, last_health_check, health_check_url, health_check_interval_seconds,
			expected_uptime_percent, sla_document_url, compliance_requirements,
			auth_type, auth_secret_id, owner_team, owner_contact, vendor_contact,
			contract_end_date, discovered_at, auto_discovered, discovery_source,
			description, documentation_url, tags, metadata, enabled, created_at, updated_at
		FROM external_services
		WHERE org_id = $1 AND enabled = TRUE`

	args := []interface{}{orgID}
	argPos := 2

	if serviceType != "" {
		query += ` AND service_type = $` + strconv.Itoa(argPos)
		args = append(args, serviceType)
		argPos++
	}
	if provider != "" {
		query += ` AND provider = $` + strconv.Itoa(argPos)
		args = append(args, provider)
		argPos++
	}
	if criticality != "" {
		query += ` AND criticality = $` + strconv.Itoa(argPos)
		args = append(args, criticality)
		argPos++
	}
	if healthStatus != "" {
		query += ` AND health_status = $` + strconv.Itoa(argPos)
		args = append(args, healthStatus)
		argPos++
	}
	if environment != "" {
		query += ` AND environment = $` + strconv.Itoa(argPos)
		args = append(args, environment)
		argPos++
	}

	query += ` ORDER BY criticality DESC, name ASC LIMIT $` + strconv.Itoa(argPos) + ` OFFSET $` + strconv.Itoa(argPos+1)
	args = append(args, limit, offset)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to query external services", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch external services"})
		return
	}
	defer rows.Close()

	services := []ExternalService{}
	for rows.Next() {
		var s ExternalService
		err := rows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.ServiceType, &s.Provider, &s.EndpointURL, &s.BaseDomain,
			&s.Port, &s.Protocol, &s.Criticality, &s.DataClassification, &s.Environment,
			&s.HealthStatus, &s.LastHealthCheck, &s.HealthCheckURL, &s.HealthCheckIntervalSecs,
			&s.ExpectedUptimePercent, &s.SLADocumentURL, &s.ComplianceRequirements,
			&s.AuthType, &s.AuthSecretID, &s.OwnerTeam, &s.OwnerContact, &s.VendorContact,
			&s.ContractEndDate, &s.DiscoveredAt, &s.AutoDiscovered, &s.DiscoverySource,
			&s.Description, &s.DocumentationURL, &s.Tags, &s.Metadata, &s.Enabled, &s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan external service", "error", err)
			continue
		}
		services = append(services, s)
	}

	c.JSON(http.StatusOK, gin.H{"services": services, "total": len(services)})
}

// Get single external service
func (h *Handler) getExternalService(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	serviceID, err := uuid.Parse(c.Param("serviceId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}

	var s ExternalService
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, name, service_type, provider, endpoint_url, base_domain,
			port, protocol, criticality, data_classification, environment,
			health_status, last_health_check, health_check_url, health_check_interval_seconds,
			expected_uptime_percent, sla_document_url, compliance_requirements,
			auth_type, auth_secret_id, owner_team, owner_contact, vendor_contact,
			contract_end_date, discovered_at, auto_discovered, discovery_source,
			description, documentation_url, tags, metadata, enabled, created_at, updated_at
		FROM external_services
		WHERE id = $1 AND org_id = $2`,
		serviceID, orgID,
	).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.ServiceType, &s.Provider, &s.EndpointURL, &s.BaseDomain,
		&s.Port, &s.Protocol, &s.Criticality, &s.DataClassification, &s.Environment,
		&s.HealthStatus, &s.LastHealthCheck, &s.HealthCheckURL, &s.HealthCheckIntervalSecs,
		&s.ExpectedUptimePercent, &s.SLADocumentURL, &s.ComplianceRequirements,
		&s.AuthType, &s.AuthSecretID, &s.OwnerTeam, &s.OwnerContact, &s.VendorContact,
		&s.ContractEndDate, &s.DiscoveredAt, &s.AutoDiscovered, &s.DiscoverySource,
		&s.Description, &s.DocumentationURL, &s.Tags, &s.Metadata, &s.Enabled, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "External service not found"})
		return
	}

	c.JSON(http.StatusOK, s)
}

// Create external service
func (h *Handler) createExternalService(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req struct {
		Name                    string                 `json:"name" binding:"required"`
		ServiceType             string                 `json:"service_type" binding:"required"`
		Provider                *string                `json:"provider"`
		EndpointURL             *string                `json:"endpoint_url"`
		BaseDomain              *string                `json:"base_domain"`
		Port                    *int                   `json:"port"`
		Protocol                *string                `json:"protocol"`
		Criticality             *string                `json:"criticality"`
		DataClassification      *string                `json:"data_classification"`
		Environment             *string                `json:"environment"`
		HealthCheckURL          *string                `json:"health_check_url"`
		HealthCheckIntervalSecs *int                   `json:"health_check_interval_seconds"`
		ExpectedUptimePercent   *float64               `json:"expected_uptime_percent"`
		AuthType                *string                `json:"auth_type"`
		OwnerTeam               *string                `json:"owner_team"`
		OwnerContact            *string                `json:"owner_contact"`
		VendorContact           *string                `json:"vendor_contact"`
		Description             *string                `json:"description"`
		DocumentationURL        *string                `json:"documentation_url"`
		Tags                    []string               `json:"tags"`
		Metadata                map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	protocol := "https"
	if req.Protocol != nil {
		protocol = *req.Protocol
	}
	criticality := "medium"
	if req.Criticality != nil {
		criticality = *req.Criticality
	}
	environment := "production"
	if req.Environment != nil {
		environment = *req.Environment
	}
	healthCheckInterval := 300
	if req.HealthCheckIntervalSecs != nil {
		healthCheckInterval = *req.HealthCheckIntervalSecs
	}

	var id uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO external_services (
			org_id, name, service_type, provider, endpoint_url, base_domain,
			port, protocol, criticality, data_classification, environment,
			health_check_url, health_check_interval_seconds, expected_uptime_percent,
			auth_type, owner_team, owner_contact, vendor_contact,
			description, documentation_url, tags, metadata, discovery_source
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, 'manual')
		RETURNING id`,
		orgID, req.Name, req.ServiceType, req.Provider, req.EndpointURL, req.BaseDomain,
		req.Port, protocol, criticality, req.DataClassification, environment,
		req.HealthCheckURL, healthCheckInterval, req.ExpectedUptimePercent,
		req.AuthType, req.OwnerTeam, req.OwnerContact, req.VendorContact,
		req.Description, req.DocumentationURL, req.Tags, req.Metadata,
	).Scan(&id)

	if err != nil {
		h.logger.Error("failed to create external service", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create external service"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "External service created"})
}

// Update external service
func (h *Handler) updateExternalService(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	serviceID, err := uuid.Parse(c.Param("serviceId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Build dynamic update query
	setClauses := []string{}
	args := []interface{}{}
	argPos := 1

	allowedFields := []string{
		"name", "service_type", "provider", "endpoint_url", "base_domain",
		"port", "protocol", "criticality", "data_classification", "environment",
		"health_status", "health_check_url", "health_check_interval_seconds",
		"expected_uptime_percent", "auth_type", "owner_team", "owner_contact",
		"vendor_contact", "description", "documentation_url", "tags", "metadata", "enabled",
	}

	for _, field := range allowedFields {
		if val, ok := req[field]; ok {
			setClauses = append(setClauses, field+"=$"+strconv.Itoa(argPos))
			args = append(args, val)
			argPos++
		}
	}

	if len(setClauses) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	setClauses = append(setClauses, "updated_at=NOW()")
	args = append(args, serviceID, orgID)

	query := "UPDATE external_services SET " + joinStrings(setClauses, ", ") +
		" WHERE id=$" + strconv.Itoa(argPos) + " AND org_id=$" + strconv.Itoa(argPos+1)

	_, err = h.db.Exec(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to update external service", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update external service"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "External service updated"})
}

// Delete external service
func (h *Handler) deleteExternalService(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	serviceID, err := uuid.Parse(c.Param("serviceId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}

	_, err = h.db.Exec(c.Request.Context(),
		`DELETE FROM external_services WHERE id = $1 AND org_id = $2`,
		serviceID, orgID,
	)
	if err != nil {
		h.logger.Error("failed to delete external service", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete external service"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "External service deleted"})
}

// Get external health overview
func (h *Handler) getExternalHealthOverview(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var overview ExternalHealthOverview
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT
			COUNT(*) as total_services,
			COUNT(*) FILTER (WHERE health_status = 'healthy') as healthy_services,
			COUNT(*) FILTER (WHERE health_status = 'degraded') as degraded_services,
			COUNT(*) FILTER (WHERE health_status = 'unhealthy') as unhealthy_services,
			COUNT(*) FILTER (WHERE health_status = 'unknown') as unknown_services,
			COUNT(*) FILTER (WHERE criticality = 'critical') as critical_services,
			COUNT(*) FILTER (WHERE criticality = 'critical' AND health_status != 'healthy') as critical_unhealthy
		FROM external_services
		WHERE org_id = $1 AND enabled = TRUE`,
		orgID,
	).Scan(
		&overview.TotalServices, &overview.HealthyServices, &overview.DegradedServices,
		&overview.UnhealthyServices, &overview.UnknownServices, &overview.CriticalServices,
		&overview.CriticalUnhealthy,
	)
	if err != nil {
		h.logger.Error("failed to get external health overview", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch health overview"})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// List service dependencies
func (h *Handler) listServiceDependencies(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	sourceName := c.Query("source_name")
	externalServiceID := c.Query("external_service_id")
	isCritical := c.Query("is_critical")

	query := `
		SELECT sd.id, sd.org_id, sd.source_type, sd.source_id, sd.source_name,
			sd.external_service_id, sd.dependency_type, sd.is_critical,
			sd.fallback_available, sd.fallback_service_id, sd.usage_pattern,
			sd.avg_requests_per_minute, sd.avg_latency_ms, sd.failure_impact,
			sd.discovered_at, sd.auto_discovered, sd.last_seen_at, sd.created_at, sd.updated_at,
			es.name as external_service_name, es.service_type as external_service_type, es.provider
		FROM service_dependencies sd
		JOIN external_services es ON es.id = sd.external_service_id
		WHERE sd.org_id = $1`

	args := []interface{}{orgID}
	argPos := 2

	if sourceName != "" {
		query += ` AND sd.source_name = $` + strconv.Itoa(argPos)
		args = append(args, sourceName)
		argPos++
	}
	if externalServiceID != "" {
		query += ` AND sd.external_service_id = $` + strconv.Itoa(argPos)
		args = append(args, externalServiceID)
		argPos++
	}
	if isCritical != "" {
		query += ` AND sd.is_critical = $` + strconv.Itoa(argPos)
		args = append(args, isCritical == "true")
		argPos++
	}

	query += ` ORDER BY sd.is_critical DESC, es.criticality DESC`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to query service dependencies", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dependencies"})
		return
	}
	defer rows.Close()

	dependencies := []ServiceDependency{}
	for rows.Next() {
		var d ServiceDependency
		err := rows.Scan(
			&d.ID, &d.OrgID, &d.SourceType, &d.SourceID, &d.SourceName,
			&d.ExternalServiceID, &d.DependencyType, &d.IsCritical,
			&d.FallbackAvailable, &d.FallbackServiceID, &d.UsagePattern,
			&d.AvgRequestsPerMinute, &d.AvgLatencyMs, &d.FailureImpact,
			&d.DiscoveredAt, &d.AutoDiscovered, &d.LastSeenAt, &d.CreatedAt, &d.UpdatedAt,
			&d.ExternalServiceName, &d.ExternalServiceType, &d.Provider,
		)
		if err != nil {
			h.logger.Error("failed to scan service dependency", "error", err)
			continue
		}
		dependencies = append(dependencies, d)
	}

	c.JSON(http.StatusOK, gin.H{"dependencies": dependencies, "total": len(dependencies)})
}

// Create service dependency
func (h *Handler) createServiceDependency(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req struct {
		SourceType           string     `json:"source_type" binding:"required"`
		SourceID             *uuid.UUID `json:"source_id"`
		SourceName           string     `json:"source_name" binding:"required"`
		ExternalServiceID    uuid.UUID  `json:"external_service_id" binding:"required"`
		DependencyType       *string    `json:"dependency_type"`
		IsCritical           *bool      `json:"is_critical"`
		FallbackAvailable    *bool      `json:"fallback_available"`
		FallbackServiceID    *uuid.UUID `json:"fallback_service_id"`
		UsagePattern         *string    `json:"usage_pattern"`
		AvgRequestsPerMinute *int       `json:"avg_requests_per_minute"`
		AvgLatencyMs         *int       `json:"avg_latency_ms"`
		FailureImpact        *string    `json:"failure_impact"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dependencyType := "runtime"
	if req.DependencyType != nil {
		dependencyType = *req.DependencyType
	}
	isCritical := false
	if req.IsCritical != nil {
		isCritical = *req.IsCritical
	}
	fallbackAvailable := false
	if req.FallbackAvailable != nil {
		fallbackAvailable = *req.FallbackAvailable
	}

	var id uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO service_dependencies (
			org_id, source_type, source_id, source_name, external_service_id,
			dependency_type, is_critical, fallback_available, fallback_service_id,
			usage_pattern, avg_requests_per_minute, avg_latency_ms, failure_impact
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id`,
		orgID, req.SourceType, req.SourceID, req.SourceName, req.ExternalServiceID,
		dependencyType, isCritical, fallbackAvailable, req.FallbackServiceID,
		req.UsagePattern, req.AvgRequestsPerMinute, req.AvgLatencyMs, req.FailureImpact,
	).Scan(&id)

	if err != nil {
		h.logger.Error("failed to create service dependency", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create dependency"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Dependency created"})
}

// Delete service dependency
func (h *Handler) deleteServiceDependency(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	depID, err := uuid.Parse(c.Param("dependencyId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid dependency ID"})
		return
	}

	_, err = h.db.Exec(c.Request.Context(),
		`DELETE FROM service_dependencies WHERE id = $1 AND org_id = $2`,
		depID, orgID,
	)
	if err != nil {
		h.logger.Error("failed to delete service dependency", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete dependency"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dependency deleted"})
}

// Get dependency risk assessment
func (h *Handler) getDependencyRisks(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	riskLevel := c.Query("risk_level")

	query := `
		SELECT
			sd.source_name,
			sd.source_type,
			es.name as external_service_name,
			es.service_type,
			es.provider,
			es.criticality as service_criticality,
			sd.is_critical as dependency_critical,
			sd.fallback_available,
			es.health_status,
			sd.failure_impact,
			CASE
				WHEN es.criticality = 'critical' AND sd.is_critical AND NOT sd.fallback_available THEN 'critical'
				WHEN es.criticality IN ('critical', 'high') AND sd.is_critical THEN 'high'
				WHEN sd.is_critical OR es.criticality IN ('critical', 'high') THEN 'medium'
				ELSE 'low'
			END as risk_level
		FROM service_dependencies sd
		JOIN external_services es ON es.id = sd.external_service_id
		WHERE sd.org_id = $1 AND es.enabled = TRUE`

	args := []interface{}{orgID}

	if riskLevel != "" {
		// Filter by risk level in subquery
		query = `SELECT * FROM (` + query + `) AS risks WHERE risk_level = $2`
		args = append(args, riskLevel)
	}

	query += ` ORDER BY
		CASE risk_level
			WHEN 'critical' THEN 1
			WHEN 'high' THEN 2
			WHEN 'medium' THEN 3
			ELSE 4
		END`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to query dependency risks", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dependency risks"})
		return
	}
	defer rows.Close()

	risks := []DependencyRisk{}
	for rows.Next() {
		var r DependencyRisk
		err := rows.Scan(
			&r.SourceName, &r.SourceType, &r.ExternalServiceName,
			&r.ServiceType, &r.Provider, &r.ServiceCriticality,
			&r.DependencyCritical, &r.FallbackAvailable, &r.HealthStatus,
			&r.FailureImpact, &r.RiskLevel,
		)
		if err != nil {
			h.logger.Error("failed to scan dependency risk", "error", err)
			continue
		}
		risks = append(risks, r)
	}

	c.JSON(http.StatusOK, gin.H{"risks": risks, "total": len(risks)})
}

// List external service incidents
func (h *Handler) listExternalIncidents(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	serviceID := c.Query("service_id")
	status := c.Query("status")
	severity := c.Query("severity")

	query := `
		SELECT i.id, i.org_id, i.service_id, i.title, i.description, i.severity,
			i.incident_type, i.status, i.started_at, i.detected_at, i.acknowledged_at,
			i.resolved_at, i.affected_services, i.impact_description, i.user_impact,
			i.resolution_notes, i.root_cause, i.reported_by, i.vendor_incident_url,
			i.created_at, i.updated_at,
			es.name as service_name
		FROM external_service_incidents i
		JOIN external_services es ON es.id = i.service_id
		WHERE i.org_id = $1`

	args := []interface{}{orgID}
	argPos := 2

	if serviceID != "" {
		query += ` AND i.service_id = $` + strconv.Itoa(argPos)
		args = append(args, serviceID)
		argPos++
	}
	if status != "" {
		query += ` AND i.status = $` + strconv.Itoa(argPos)
		args = append(args, status)
		argPos++
	}
	if severity != "" {
		query += ` AND i.severity = $` + strconv.Itoa(argPos)
		args = append(args, severity)
		argPos++
	}

	query += ` ORDER BY i.started_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to query external incidents", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch incidents"})
		return
	}
	defer rows.Close()

	incidents := []ExternalServiceIncident{}
	for rows.Next() {
		var i ExternalServiceIncident
		err := rows.Scan(
			&i.ID, &i.OrgID, &i.ServiceID, &i.Title, &i.Description, &i.Severity,
			&i.IncidentType, &i.Status, &i.StartedAt, &i.DetectedAt, &i.AcknowledgedAt,
			&i.ResolvedAt, &i.AffectedServices, &i.ImpactDescription, &i.UserImpact,
			&i.ResolutionNotes, &i.RootCause, &i.ReportedBy, &i.VendorIncidentURL,
			&i.CreatedAt, &i.UpdatedAt,
			&i.ServiceName,
		)
		if err != nil {
			h.logger.Error("failed to scan external incident", "error", err)
			continue
		}
		incidents = append(incidents, i)
	}

	c.JSON(http.StatusOK, gin.H{"incidents": incidents, "total": len(incidents)})
}

// Create external service incident
func (h *Handler) createExternalIncident(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req struct {
		ServiceID         uuid.UUID  `json:"service_id" binding:"required"`
		Title             string     `json:"title" binding:"required"`
		Description       *string    `json:"description"`
		Severity          string     `json:"severity" binding:"required"`
		IncidentType      *string    `json:"incident_type"`
		StartedAt         *time.Time `json:"started_at"`
		AffectedServices  []string   `json:"affected_services"`
		ImpactDescription *string    `json:"impact_description"`
		UserImpact        *string    `json:"user_impact"`
		VendorIncidentURL *string    `json:"vendor_incident_url"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	startedAt := time.Now()
	if req.StartedAt != nil {
		startedAt = *req.StartedAt
	}

	var id uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO external_service_incidents (
			org_id, service_id, title, description, severity, incident_type,
			started_at, affected_services, impact_description, user_impact,
			vendor_incident_url, reported_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'manual')
		RETURNING id`,
		orgID, req.ServiceID, req.Title, req.Description, req.Severity, req.IncidentType,
		startedAt, req.AffectedServices, req.ImpactDescription, req.UserImpact,
		req.VendorIncidentURL,
	).Scan(&id)

	if err != nil {
		h.logger.Error("failed to create external incident", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create incident"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Incident created"})
}

// Update external incident status
func (h *Handler) updateExternalIncidentStatus(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	incidentID, err := uuid.Parse(c.Param("incidentId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid incident ID"})
		return
	}

	var req struct {
		Status          string  `json:"status" binding:"required"`
		ResolutionNotes *string `json:"resolution_notes"`
		RootCause       *string `json:"root_cause"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `UPDATE external_service_incidents SET status = $1, updated_at = NOW()`
	args := []interface{}{req.Status}
	argPos := 2

	if req.Status == "acknowledged" {
		query += `, acknowledged_at = NOW()`
	}
	if req.Status == "resolved" {
		query += `, resolved_at = NOW()`
	}
	if req.ResolutionNotes != nil {
		query += `, resolution_notes = $` + strconv.Itoa(argPos)
		args = append(args, *req.ResolutionNotes)
		argPos++
	}
	if req.RootCause != nil {
		query += `, root_cause = $` + strconv.Itoa(argPos)
		args = append(args, *req.RootCause)
		argPos++
	}

	query += ` WHERE id = $` + strconv.Itoa(argPos) + ` AND org_id = $` + strconv.Itoa(argPos+1)
	args = append(args, incidentID, orgID)

	_, err = h.db.Exec(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to update incident status", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update incident"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Incident updated"})
}

// Get service health history
func (h *Handler) getServiceHealthHistory(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	serviceID, err := uuid.Parse(c.Param("serviceId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid service ID"})
		return
	}

	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, service_id, status, response_time_ms, status_code,
			check_type, error_message, checked_at
		FROM external_service_health
		WHERE service_id = $1 AND org_id = $2
		ORDER BY checked_at DESC
		LIMIT $3`,
		serviceID, orgID, limit,
	)
	if err != nil {
		h.logger.Error("failed to query health history", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch health history"})
		return
	}
	defer rows.Close()

	history := []ExternalServiceHealth{}
	for rows.Next() {
		var h ExternalServiceHealth
		err := rows.Scan(
			&h.ID, &h.OrgID, &h.ServiceID, &h.Status, &h.ResponseTimeMs,
			&h.StatusCode, &h.CheckType, &h.ErrorMessage, &h.CheckedAt,
		)
		if err != nil {
			continue
		}
		history = append(history, h)
	}

	c.JSON(http.StatusOK, gin.H{"history": history, "total": len(history)})
}

// Helper function to join strings
func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
