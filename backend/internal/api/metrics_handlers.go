package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Metrics types
type MetricDefinition struct {
	ID                       uuid.UUID              `json:"id"`
	OrgID                    uuid.UUID              `json:"org_id"`
	Name                     string                 `json:"name"`
	DisplayName              *string                `json:"display_name,omitempty"`
	Description              *string                `json:"description,omitempty"`
	Category                 string                 `json:"category"`
	Subcategory              *string                `json:"subcategory,omitempty"`
	MetricType               string                 `json:"metric_type"`
	Unit                     *string                `json:"unit,omitempty"`
	ValueType                string                 `json:"value_type"`
	CollectionMethod         string                 `json:"collection_method"`
	CollectionIntervalSecs   int                    `json:"collection_interval_seconds"`
	Source                   *string                `json:"source,omitempty"`
	QueryTemplate            *string                `json:"query_template,omitempty"`
	AggregationType          *string                `json:"aggregation_type,omitempty"`
	AggregationWindowSecs    *int                   `json:"aggregation_window_seconds,omitempty"`
	WarningThreshold         *float64               `json:"warning_threshold,omitempty"`
	CriticalThreshold        *float64               `json:"critical_threshold,omitempty"`
	ThresholdDirection       string                 `json:"threshold_direction"`
	IsPrimary                bool                   `json:"is_primary"`
	DisplayOrder             int                    `json:"display_order"`
	ChartType                *string                `json:"chart_type,omitempty"`
	Color                    *string                `json:"color,omitempty"`
	Enabled                  bool                   `json:"enabled"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
}

type MetricValue struct {
	ID            uuid.UUID              `json:"id"`
	OrgID         uuid.UUID              `json:"org_id"`
	MetricID      uuid.UUID              `json:"metric_id"`
	AgentID       *uuid.UUID             `json:"agent_id,omitempty"`
	DeploymentID  *uuid.UUID             `json:"deployment_id,omitempty"`
	ResourceType  *string                `json:"resource_type,omitempty"`
	ResourceID    *string                `json:"resource_id,omitempty"`
	Labels        map[string]interface{} `json:"labels,omitempty"`
	ValueNumeric  *float64               `json:"value_numeric,omitempty"`
	ValueString   *string                `json:"value_string,omitempty"`
	ValueBool     *bool                  `json:"value_bool,omitempty"`
	CollectedAt   time.Time              `json:"collected_at"`
	PeriodStart   *time.Time             `json:"period_start,omitempty"`
	PeriodEnd     *time.Time             `json:"period_end,omitempty"`
	Source        *string                `json:"source,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	// Joined fields
	MetricName    *string                `json:"metric_name,omitempty"`
	MetricCategory *string               `json:"metric_category,omitempty"`
}

type Dashboard struct {
	ID          uuid.UUID              `json:"id"`
	OrgID       uuid.UUID              `json:"org_id"`
	Name        string                 `json:"name"`
	Description *string                `json:"description,omitempty"`
	Slug        *string                `json:"slug,omitempty"`
	CreatedBy   *uuid.UUID             `json:"created_by,omitempty"`
	IsDefault   bool                   `json:"is_default"`
	IsShared    bool                   `json:"is_shared"`
	Layout      interface{}            `json:"layout"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
	Visibility  string                 `json:"visibility"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	// Joined fields
	WidgetCount *int                   `json:"widget_count,omitempty"`
}

type DashboardWidget struct {
	ID                   uuid.UUID              `json:"id"`
	OrgID                uuid.UUID              `json:"org_id"`
	DashboardID          uuid.UUID              `json:"dashboard_id"`
	WidgetType           string                 `json:"widget_type"`
	Title                *string                `json:"title,omitempty"`
	MetricIDs            []uuid.UUID            `json:"metric_ids,omitempty"`
	Query                map[string]interface{} `json:"query,omitempty"`
	Filters              map[string]interface{} `json:"filters,omitempty"`
	ChartType            *string                `json:"chart_type,omitempty"`
	TimeRange            *string                `json:"time_range,omitempty"`
	RefreshIntervalSecs  int                    `json:"refresh_interval_seconds"`
	PositionX            int                    `json:"position_x"`
	PositionY            int                    `json:"position_y"`
	Width                int                    `json:"width"`
	Height               int                    `json:"height"`
	Settings             map[string]interface{} `json:"settings,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

type Report struct {
	ID               uuid.UUID              `json:"id"`
	OrgID            uuid.UUID              `json:"org_id"`
	Name             string                 `json:"name"`
	Description      *string                `json:"description,omitempty"`
	ReportType       string                 `json:"report_type"`
	Template         *string                `json:"template,omitempty"`
	Config           map[string]interface{} `json:"config,omitempty"`
	Filters          map[string]interface{} `json:"filters,omitempty"`
	ScheduleEnabled  bool                   `json:"schedule_enabled"`
	ScheduleCron     *string                `json:"schedule_cron,omitempty"`
	ScheduleTimezone string                 `json:"schedule_timezone"`
	NextRunAt        *time.Time             `json:"next_run_at,omitempty"`
	LastRunAt        *time.Time             `json:"last_run_at,omitempty"`
	DeliveryMethod   *string                `json:"delivery_method,omitempty"`
	DeliveryConfig   map[string]interface{} `json:"delivery_config,omitempty"`
	Recipients       []string               `json:"recipients,omitempty"`
	CreatedBy        *uuid.UUID             `json:"created_by,omitempty"`
	Visibility       string                 `json:"visibility"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

type ReportExecution struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	ReportID        uuid.UUID  `json:"report_id"`
	TriggeredBy     *string    `json:"triggered_by,omitempty"`
	TriggeredByUser *uuid.UUID `json:"triggered_by_user,omitempty"`
	Status          string     `json:"status"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	DurationSeconds *int       `json:"duration_seconds,omitempty"`
	OutputFormat    *string    `json:"output_format,omitempty"`
	OutputPath      *string    `json:"output_path,omitempty"`
	OutputSizeBytes *int       `json:"output_size_bytes,omitempty"`
	DeliveredAt     *time.Time `json:"delivered_at,omitempty"`
	DeliveryStatus  *string    `json:"delivery_status,omitempty"`
	DeliveryError   *string    `json:"delivery_error,omitempty"`
	DataStart       *time.Time `json:"data_start,omitempty"`
	DataEnd         *time.Time `json:"data_end,omitempty"`
	ErrorMessage    *string    `json:"error_message,omitempty"`
	RetryCount      int        `json:"retry_count"`
	CreatedAt       time.Time  `json:"created_at"`
	// Joined fields
	ReportName      *string    `json:"report_name,omitempty"`
}

type TelemetrySettings struct {
	ID                       uuid.UUID  `json:"id"`
	OrgID                    uuid.UUID  `json:"org_id"`
	CollectUsageMetrics      bool       `json:"collect_usage_metrics"`
	CollectPerformanceMetrics bool      `json:"collect_performance_metrics"`
	CollectSecurityMetrics   bool       `json:"collect_security_metrics"`
	CollectErrorReports      bool       `json:"collect_error_reports"`
	ResearchParticipation    bool       `json:"research_participation"`
	ResearchConsentDate      *time.Time `json:"research_consent_date,omitempty"`
	ResearchConsentVersion   *string    `json:"research_consent_version,omitempty"`
	AnonymizeData            bool       `json:"anonymize_data"`
	DataRetentionDays        int        `json:"data_retention_days"`
	AllowDataExport          bool       `json:"allow_data_export"`
	ExportFormat             string     `json:"export_format"`
	UpdatedAt                time.Time  `json:"updated_at"`
	UpdatedBy                *uuid.UUID `json:"updated_by,omitempty"`
}

type MetricSummary struct {
	Category          string     `json:"category"`
	TotalMetrics      int        `json:"total_metrics"`
	EnabledMetrics    int        `json:"enabled_metrics"`
	MetricsWithData   int        `json:"metrics_with_data"`
	LastDataCollected *time.Time `json:"last_data_collected,omitempty"`
}

// List metric definitions
func (h *Handler) listMetricDefinitions(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	category := c.Query("category")
	enabled := c.Query("enabled")

	query := `
		SELECT id, org_id, name, display_name, description, category, subcategory,
			metric_type, unit, value_type, collection_method, collection_interval_seconds,
			source, query_template, aggregation_type, aggregation_window_seconds,
			warning_threshold, critical_threshold, threshold_direction,
			is_primary, display_order, chart_type, color, enabled, created_at, updated_at
		FROM metric_definitions
		WHERE org_id = $1`

	args := []interface{}{orgID}
	argPos := 2

	if category != "" {
		query += ` AND category = $` + strconv.Itoa(argPos)
		args = append(args, category)
		argPos++
	}
	if enabled != "" {
		query += ` AND enabled = $` + strconv.Itoa(argPos)
		args = append(args, enabled == "true")
		argPos++
	}

	query += ` ORDER BY display_order, name`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to query metric definitions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch metric definitions"})
		return
	}
	defer rows.Close()

	metrics := []MetricDefinition{}
	for rows.Next() {
		var m MetricDefinition
		err := rows.Scan(
			&m.ID, &m.OrgID, &m.Name, &m.DisplayName, &m.Description, &m.Category, &m.Subcategory,
			&m.MetricType, &m.Unit, &m.ValueType, &m.CollectionMethod, &m.CollectionIntervalSecs,
			&m.Source, &m.QueryTemplate, &m.AggregationType, &m.AggregationWindowSecs,
			&m.WarningThreshold, &m.CriticalThreshold, &m.ThresholdDirection,
			&m.IsPrimary, &m.DisplayOrder, &m.ChartType, &m.Color, &m.Enabled, &m.CreatedAt, &m.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan metric definition", zap.Error(err))
			continue
		}
		metrics = append(metrics, m)
	}

	c.JSON(http.StatusOK, gin.H{"metrics": metrics, "total": len(metrics)})
}

// Create metric definition
func (h *Handler) createMetricDefinition(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req struct {
		Name                   string   `json:"name" binding:"required"`
		DisplayName            *string  `json:"display_name"`
		Description            *string  `json:"description"`
		Category               string   `json:"category" binding:"required"`
		Subcategory            *string  `json:"subcategory"`
		MetricType             *string  `json:"metric_type"`
		Unit                   *string  `json:"unit"`
		ValueType              *string  `json:"value_type"`
		CollectionMethod       *string  `json:"collection_method"`
		CollectionIntervalSecs *int     `json:"collection_interval_seconds"`
		Source                 *string  `json:"source"`
		AggregationType        *string  `json:"aggregation_type"`
		WarningThreshold       *float64 `json:"warning_threshold"`
		CriticalThreshold      *float64 `json:"critical_threshold"`
		ThresholdDirection     *string  `json:"threshold_direction"`
		IsPrimary              *bool    `json:"is_primary"`
		ChartType              *string  `json:"chart_type"`
		Color                  *string  `json:"color"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	metricType := "gauge"
	if req.MetricType != nil {
		metricType = *req.MetricType
	}
	valueType := "numeric"
	if req.ValueType != nil {
		valueType = *req.ValueType
	}
	collectionMethod := "automatic"
	if req.CollectionMethod != nil {
		collectionMethod = *req.CollectionMethod
	}
	collectionInterval := 300
	if req.CollectionIntervalSecs != nil {
		collectionInterval = *req.CollectionIntervalSecs
	}
	thresholdDirection := "above"
	if req.ThresholdDirection != nil {
		thresholdDirection = *req.ThresholdDirection
	}
	isPrimary := false
	if req.IsPrimary != nil {
		isPrimary = *req.IsPrimary
	}

	var id uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO metric_definitions (
			org_id, name, display_name, description, category, subcategory,
			metric_type, unit, value_type, collection_method, collection_interval_seconds,
			source, aggregation_type, warning_threshold, critical_threshold,
			threshold_direction, is_primary, chart_type, color
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING id`,
		orgID, req.Name, req.DisplayName, req.Description, req.Category, req.Subcategory,
		metricType, req.Unit, valueType, collectionMethod, collectionInterval,
		req.Source, req.AggregationType, req.WarningThreshold, req.CriticalThreshold,
		thresholdDirection, isPrimary, req.ChartType, req.Color,
	).Scan(&id)

	if err != nil {
		h.logger.Error("failed to create metric definition", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create metric definition"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Metric definition created"})
}

// Delete metric definition
func (h *Handler) deleteMetricDefinition(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	metricID, err := uuid.Parse(c.Param("metricId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metric ID"})
		return
	}

	_, err = h.db.Exec(c.Request.Context(),
		`DELETE FROM metric_definitions WHERE id = $1 AND org_id = $2`,
		metricID, orgID,
	)
	if err != nil {
		h.logger.Error("failed to delete metric definition", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete metric definition"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Metric definition deleted"})
}

// Get metric values
func (h *Handler) getMetricValues(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	metricID, err := uuid.Parse(c.Param("metricId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid metric ID"})
		return
	}

	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT mv.id, mv.org_id, mv.metric_id, mv.agent_id, mv.deployment_id,
			mv.resource_type, mv.resource_id, mv.labels,
			mv.value_numeric, mv.value_string, mv.value_bool,
			mv.collected_at, mv.period_start, mv.period_end, mv.source, mv.metadata,
			md.name as metric_name, md.category as metric_category
		FROM metric_values mv
		JOIN metric_definitions md ON md.id = mv.metric_id
		WHERE mv.metric_id = $1 AND mv.org_id = $2
		ORDER BY mv.collected_at DESC
		LIMIT $3`,
		metricID, orgID, limit,
	)
	if err != nil {
		h.logger.Error("failed to query metric values", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch metric values"})
		return
	}
	defer rows.Close()

	values := []MetricValue{}
	for rows.Next() {
		var v MetricValue
		err := rows.Scan(
			&v.ID, &v.OrgID, &v.MetricID, &v.AgentID, &v.DeploymentID,
			&v.ResourceType, &v.ResourceID, &v.Labels,
			&v.ValueNumeric, &v.ValueString, &v.ValueBool,
			&v.CollectedAt, &v.PeriodStart, &v.PeriodEnd, &v.Source, &v.Metadata,
			&v.MetricName, &v.MetricCategory,
		)
		if err != nil {
			h.logger.Error("failed to scan metric value", zap.Error(err))
			continue
		}
		values = append(values, v)
	}

	c.JSON(http.StatusOK, gin.H{"values": values, "total": len(values)})
}

// Get metric summary
func (h *Handler) getMetricSummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT
			m.category,
			COUNT(*) as total_metrics,
			COUNT(*) FILTER (WHERE m.enabled = TRUE) as enabled_metrics,
			COUNT(DISTINCT mv.metric_id) as metrics_with_data,
			MAX(mv.collected_at) as last_data_collected
		FROM metric_definitions m
		LEFT JOIN metric_values mv ON mv.metric_id = m.id
		WHERE m.org_id = $1
		GROUP BY m.category
		ORDER BY m.category`,
		orgID,
	)
	if err != nil {
		h.logger.Error("failed to query metric summary", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch metric summary"})
		return
	}
	defer rows.Close()

	summaries := []MetricSummary{}
	for rows.Next() {
		var s MetricSummary
		err := rows.Scan(&s.Category, &s.TotalMetrics, &s.EnabledMetrics, &s.MetricsWithData, &s.LastDataCollected)
		if err != nil {
			h.logger.Error("failed to scan metric summary", zap.Error(err))
			continue
		}
		summaries = append(summaries, s)
	}

	c.JSON(http.StatusOK, gin.H{"summaries": summaries})
}

// List dashboards
func (h *Handler) listDashboards(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT d.id, d.org_id, d.name, d.description, d.slug, d.created_by,
			d.is_default, d.is_shared, d.layout, d.settings, d.visibility,
			d.created_at, d.updated_at,
			COUNT(dw.id) as widget_count
		FROM dashboards d
		LEFT JOIN dashboard_widgets dw ON dw.dashboard_id = d.id
		WHERE d.org_id = $1
		GROUP BY d.id
		ORDER BY d.is_default DESC, d.name`,
		orgID,
	)
	if err != nil {
		h.logger.Error("failed to query dashboards", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch dashboards"})
		return
	}
	defer rows.Close()

	dashboards := []Dashboard{}
	for rows.Next() {
		var d Dashboard
		err := rows.Scan(
			&d.ID, &d.OrgID, &d.Name, &d.Description, &d.Slug, &d.CreatedBy,
			&d.IsDefault, &d.IsShared, &d.Layout, &d.Settings, &d.Visibility,
			&d.CreatedAt, &d.UpdatedAt, &d.WidgetCount,
		)
		if err != nil {
			h.logger.Error("failed to scan dashboard", zap.Error(err))
			continue
		}
		dashboards = append(dashboards, d)
	}

	c.JSON(http.StatusOK, gin.H{"dashboards": dashboards, "total": len(dashboards)})
}

// Create dashboard
func (h *Handler) createDashboard(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req struct {
		Name        string                 `json:"name" binding:"required"`
		Description *string                `json:"description"`
		Slug        *string                `json:"slug"`
		IsDefault   *bool                  `json:"is_default"`
		IsShared    *bool                  `json:"is_shared"`
		Layout      interface{}            `json:"layout"`
		Settings    map[string]interface{} `json:"settings"`
		Visibility  *string                `json:"visibility"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	isDefault := false
	if req.IsDefault != nil {
		isDefault = *req.IsDefault
	}
	isShared := false
	if req.IsShared != nil {
		isShared = *req.IsShared
	}
	visibility := "private"
	if req.Visibility != nil {
		visibility = *req.Visibility
	}

	var id uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO dashboards (
			org_id, name, description, slug, created_by,
			is_default, is_shared, layout, settings, visibility
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		orgID, req.Name, req.Description, req.Slug, userID,
		isDefault, isShared, req.Layout, req.Settings, visibility,
	).Scan(&id)

	if err != nil {
		h.logger.Error("failed to create dashboard", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create dashboard"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Dashboard created"})
}

// Delete dashboard
func (h *Handler) deleteDashboard(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	dashboardID, err := uuid.Parse(c.Param("dashboardId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid dashboard ID"})
		return
	}

	_, err = h.db.Exec(c.Request.Context(),
		`DELETE FROM dashboards WHERE id = $1 AND org_id = $2`,
		dashboardID, orgID,
	)
	if err != nil {
		h.logger.Error("failed to delete dashboard", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete dashboard"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Dashboard deleted"})
}

// List reports
func (h *Handler) listReports(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	reportType := c.Query("report_type")

	query := `
		SELECT id, org_id, name, description, report_type, template, config, filters,
			schedule_enabled, schedule_cron, schedule_timezone, next_run_at, last_run_at,
			delivery_method, delivery_config, recipients, created_by, visibility,
			created_at, updated_at
		FROM reports
		WHERE org_id = $1`

	args := []interface{}{orgID}

	if reportType != "" {
		query += ` AND report_type = $2`
		args = append(args, reportType)
	}

	query += ` ORDER BY name`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to query reports", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch reports"})
		return
	}
	defer rows.Close()

	reports := []Report{}
	for rows.Next() {
		var r Report
		err := rows.Scan(
			&r.ID, &r.OrgID, &r.Name, &r.Description, &r.ReportType, &r.Template, &r.Config, &r.Filters,
			&r.ScheduleEnabled, &r.ScheduleCron, &r.ScheduleTimezone, &r.NextRunAt, &r.LastRunAt,
			&r.DeliveryMethod, &r.DeliveryConfig, &r.Recipients, &r.CreatedBy, &r.Visibility,
			&r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan report", zap.Error(err))
			continue
		}
		reports = append(reports, r)
	}

	c.JSON(http.StatusOK, gin.H{"reports": reports, "total": len(reports)})
}

// Create report
func (h *Handler) createReport(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req struct {
		Name             string                 `json:"name" binding:"required"`
		Description      *string                `json:"description"`
		ReportType       string                 `json:"report_type" binding:"required"`
		Template         *string                `json:"template"`
		Config           map[string]interface{} `json:"config"`
		Filters          map[string]interface{} `json:"filters"`
		ScheduleEnabled  *bool                  `json:"schedule_enabled"`
		ScheduleCron     *string                `json:"schedule_cron"`
		ScheduleTimezone *string                `json:"schedule_timezone"`
		DeliveryMethod   *string                `json:"delivery_method"`
		DeliveryConfig   map[string]interface{} `json:"delivery_config"`
		Recipients       []string               `json:"recipients"`
		Visibility       *string                `json:"visibility"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scheduleEnabled := false
	if req.ScheduleEnabled != nil {
		scheduleEnabled = *req.ScheduleEnabled
	}
	scheduleTimezone := "UTC"
	if req.ScheduleTimezone != nil {
		scheduleTimezone = *req.ScheduleTimezone
	}
	visibility := "private"
	if req.Visibility != nil {
		visibility = *req.Visibility
	}

	var id uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO reports (
			org_id, name, description, report_type, template, config, filters,
			schedule_enabled, schedule_cron, schedule_timezone,
			delivery_method, delivery_config, recipients, created_by, visibility
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id`,
		orgID, req.Name, req.Description, req.ReportType, req.Template, req.Config, req.Filters,
		scheduleEnabled, req.ScheduleCron, scheduleTimezone,
		req.DeliveryMethod, req.DeliveryConfig, req.Recipients, userID, visibility,
	).Scan(&id)

	if err != nil {
		h.logger.Error("failed to create report", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create report"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Report created"})
}

// Run report
func (h *Handler) runReport(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	reportID, err := uuid.Parse(c.Param("reportId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid report ID"})
		return
	}

	var id uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO report_executions (
			org_id, report_id, triggered_by, triggered_by_user, status
		) VALUES ($1, $2, 'manual', $3, 'pending')
		RETURNING id`,
		orgID, reportID, userID,
	).Scan(&id)

	if err != nil {
		h.logger.Error("failed to create report execution", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to trigger report"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{"id": id, "status": "pending", "message": "Report execution started"})
}

// List report executions
func (h *Handler) listReportExecutions(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	reportID := c.Query("report_id")

	query := `
		SELECT re.id, re.org_id, re.report_id, re.triggered_by, re.triggered_by_user,
			re.status, re.started_at, re.completed_at, re.duration_seconds,
			re.output_format, re.output_path, re.output_size_bytes,
			re.delivered_at, re.delivery_status, re.delivery_error,
			re.data_start, re.data_end, re.error_message, re.retry_count, re.created_at,
			r.name as report_name
		FROM report_executions re
		JOIN reports r ON r.id = re.report_id
		WHERE re.org_id = $1`

	args := []interface{}{orgID}

	if reportID != "" {
		query += ` AND re.report_id = $2`
		args = append(args, reportID)
	}

	query += ` ORDER BY re.created_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to query report executions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch report executions"})
		return
	}
	defer rows.Close()

	executions := []ReportExecution{}
	for rows.Next() {
		var e ReportExecution
		err := rows.Scan(
			&e.ID, &e.OrgID, &e.ReportID, &e.TriggeredBy, &e.TriggeredByUser,
			&e.Status, &e.StartedAt, &e.CompletedAt, &e.DurationSeconds,
			&e.OutputFormat, &e.OutputPath, &e.OutputSizeBytes,
			&e.DeliveredAt, &e.DeliveryStatus, &e.DeliveryError,
			&e.DataStart, &e.DataEnd, &e.ErrorMessage, &e.RetryCount, &e.CreatedAt,
			&e.ReportName,
		)
		if err != nil {
			h.logger.Error("failed to scan report execution", zap.Error(err))
			continue
		}
		executions = append(executions, e)
	}

	c.JSON(http.StatusOK, gin.H{"executions": executions, "total": len(executions)})
}

// Get telemetry settings
func (h *Handler) getTelemetrySettings(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var settings TelemetrySettings
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, collect_usage_metrics, collect_performance_metrics,
			collect_security_metrics, collect_error_reports,
			research_participation, research_consent_date, research_consent_version,
			anonymize_data, data_retention_days, allow_data_export, export_format,
			updated_at, updated_by
		FROM telemetry_settings
		WHERE org_id = $1`,
		orgID,
	).Scan(
		&settings.ID, &settings.OrgID, &settings.CollectUsageMetrics, &settings.CollectPerformanceMetrics,
		&settings.CollectSecurityMetrics, &settings.CollectErrorReports,
		&settings.ResearchParticipation, &settings.ResearchConsentDate, &settings.ResearchConsentVersion,
		&settings.AnonymizeData, &settings.DataRetentionDays, &settings.AllowDataExport, &settings.ExportFormat,
		&settings.UpdatedAt, &settings.UpdatedBy,
	)
	if err != nil {
		// Return defaults if no settings exist
		c.JSON(http.StatusOK, TelemetrySettings{
			OrgID:                     orgID,
			CollectUsageMetrics:      true,
			CollectPerformanceMetrics: true,
			CollectSecurityMetrics:   true,
			CollectErrorReports:      true,
			ResearchParticipation:    false,
			AnonymizeData:            true,
			DataRetentionDays:        90,
			AllowDataExport:          true,
			ExportFormat:             "json",
		})
		return
	}

	c.JSON(http.StatusOK, settings)
}

// Update telemetry settings
func (h *Handler) updateTelemetrySettings(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req struct {
		CollectUsageMetrics       *bool   `json:"collect_usage_metrics"`
		CollectPerformanceMetrics *bool   `json:"collect_performance_metrics"`
		CollectSecurityMetrics    *bool   `json:"collect_security_metrics"`
		CollectErrorReports       *bool   `json:"collect_error_reports"`
		ResearchParticipation     *bool   `json:"research_participation"`
		AnonymizeData             *bool   `json:"anonymize_data"`
		DataRetentionDays         *int    `json:"data_retention_days"`
		AllowDataExport           *bool   `json:"allow_data_export"`
		ExportFormat              *string `json:"export_format"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Upsert telemetry settings
	_, err := h.db.Exec(c.Request.Context(), `
		INSERT INTO telemetry_settings (
			org_id, collect_usage_metrics, collect_performance_metrics,
			collect_security_metrics, collect_error_reports, research_participation,
			anonymize_data, data_retention_days, allow_data_export, export_format,
			updated_by
		) VALUES ($1,
			COALESCE($2, TRUE), COALESCE($3, TRUE), COALESCE($4, TRUE), COALESCE($5, TRUE),
			COALESCE($6, FALSE), COALESCE($7, TRUE), COALESCE($8, 90),
			COALESCE($9, TRUE), COALESCE($10, 'json'), $11
		)
		ON CONFLICT (org_id) DO UPDATE SET
			collect_usage_metrics = COALESCE($2, telemetry_settings.collect_usage_metrics),
			collect_performance_metrics = COALESCE($3, telemetry_settings.collect_performance_metrics),
			collect_security_metrics = COALESCE($4, telemetry_settings.collect_security_metrics),
			collect_error_reports = COALESCE($5, telemetry_settings.collect_error_reports),
			research_participation = COALESCE($6, telemetry_settings.research_participation),
			anonymize_data = COALESCE($7, telemetry_settings.anonymize_data),
			data_retention_days = COALESCE($8, telemetry_settings.data_retention_days),
			allow_data_export = COALESCE($9, telemetry_settings.allow_data_export),
			export_format = COALESCE($10, telemetry_settings.export_format),
			updated_at = NOW(),
			updated_by = $11`,
		orgID, req.CollectUsageMetrics, req.CollectPerformanceMetrics,
		req.CollectSecurityMetrics, req.CollectErrorReports, req.ResearchParticipation,
		req.AnonymizeData, req.DataRetentionDays, req.AllowDataExport, req.ExportFormat,
		userID,
	)

	if err != nil {
		h.logger.Error("failed to update telemetry settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update telemetry settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Telemetry settings updated"})
}
