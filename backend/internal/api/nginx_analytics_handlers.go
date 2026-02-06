package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// =============================================================================
// Types for Nginx Analytics
// =============================================================================

// NginxLogEntry represents a single nginx access log entry from the agent
type NginxLogEntry struct {
	Time          time.Time `json:"time"`
	ClientIP      string    `json:"client_ip"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	QueryString   string    `json:"query_string,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
	StatusCode    int       `json:"status_code"`
	ResponseBytes int64     `json:"response_bytes"`
	ResponseTime  float64   `json:"response_time,omitempty"`
	Host          string    `json:"host,omitempty"`
	Referer       string    `json:"referer,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	Upstream      string    `json:"upstream,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
}

// NginxLogBatch represents a batch of nginx log entries from an agent
type NginxLogBatch struct {
	AgentID string          `json:"agent_id"`
	Entries []NginxLogEntry `json:"entries"`
}

// NginxAnalyticsQuery represents query parameters for analytics endpoints
type NginxAnalyticsQuery struct {
	Interval  string    `form:"interval" binding:"omitempty,oneof=1m 5m 1h 1d"` // Aggregation interval
	Hours     int       `form:"hours" binding:"omitempty,min=1,max=720"`         // Time range in hours
	StartTime time.Time `form:"start_time"`
	EndTime   time.Time `form:"end_time"`
	AgentID   string    `form:"agent_id"`
}

// NginxAnalyticsResponse represents time-series analytics data
type NginxAnalyticsResponse struct {
	Interval   string                   `json:"interval"`
	StartTime  time.Time                `json:"start_time"`
	EndTime    time.Time                `json:"end_time"`
	DataPoints []NginxAnalyticsDataPoint `json:"data_points"`
}

// NginxAnalyticsDataPoint represents a single data point in the time series
type NginxAnalyticsDataPoint struct {
	Bucket           time.Time `json:"bucket"`
	TotalRequests    int64     `json:"total_requests"`
	Count2xx         int64     `json:"count_2xx"`
	Count3xx         int64     `json:"count_3xx"`
	Count4xx         int64     `json:"count_4xx"`
	Count5xx         int64     `json:"count_5xx"`
	TotalBytes       int64     `json:"total_bytes"`
	AvgResponseTime  float64   `json:"avg_response_time"`
	P95ResponseTime  float64   `json:"p95_response_time"`
	P99ResponseTime  float64   `json:"p99_response_time"`
	MaxResponseTime  float64   `json:"max_response_time"`
	MinResponseTime  float64   `json:"min_response_time"`
	UniqueVisitors   int64     `json:"unique_visitors"`
}

// NginxAnalyticsSummary represents summary statistics for a time period
type NginxAnalyticsSummary struct {
	TotalRequests      int64   `json:"total_requests"`
	TotalBytes         int64   `json:"total_bytes"`
	UniqueVisitors     int64   `json:"unique_visitors"`
	AvgResponseTime    float64 `json:"avg_response_time"`
	P95ResponseTime    float64 `json:"p95_response_time"`
	P99ResponseTime    float64 `json:"p99_response_time"`
	ErrorRate          float64 `json:"error_rate"` // Percentage of 4xx + 5xx
	Count2xx           int64   `json:"count_2xx"`
	Count3xx           int64   `json:"count_3xx"`
	Count4xx           int64   `json:"count_4xx"`
	Count5xx           int64   `json:"count_5xx"`
	RequestsPerSecond  float64 `json:"requests_per_second"`
	BytesPerSecond     float64 `json:"bytes_per_second"`
	TopMethod          string  `json:"top_method"`
	TopStatusCode      int     `json:"top_status_code"`
}

// NginxTopPath represents aggregated stats for a path
type NginxTopPath struct {
	Path            string  `json:"path"`
	RequestCount    int64   `json:"request_count"`
	TotalBytes      int64   `json:"total_bytes"`
	AvgResponseTime float64 `json:"avg_response_time"`
	P95ResponseTime float64 `json:"p95_response_time"`
	Count4xx        int64   `json:"count_4xx"`
	Count5xx        int64   `json:"count_5xx"`
	ErrorRate       float64 `json:"error_rate"`
	UniqueVisitors  int64   `json:"unique_visitors"`
}

// NginxStatusCodeDistribution represents status code breakdown
type NginxStatusCodeDistribution struct {
	StatusCode int   `json:"status_code"`
	Count      int64 `json:"count"`
	Percentage float64 `json:"percentage"`
}

// =============================================================================
// Handlers
// =============================================================================

// IngestNginxLogs handles bulk ingestion of nginx access logs
// POST /api/v1/logs/nginx/ingest
func (h *Handler) IngestNginxLogs(c *gin.Context) {
	var batch NginxLogBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	if batch.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}

	if len(batch.Entries) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "No entries to ingest"})
		return
	}

	// Get agent and org ID
	agentID, err := uuid.Parse(batch.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent_id"})
		return
	}

	var orgID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT org_id FROM agents WHERE id = $1
	`, agentID).Scan(&orgID)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
		h.logger.Error("Failed to get agent org_id", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}

	// Use COPY for bulk insert (much faster than individual INSERTs)
	ctx := c.Request.Context()
	inserted, err := h.bulkInsertNginxLogs(ctx, orgID, agentID, batch.Entries)
	if err != nil {
		h.logger.Error("Failed to insert nginx logs",
			zap.Error(err),
			zap.Int("entries", len(batch.Entries)),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Logs ingested successfully",
		"inserted": inserted,
	})
}

// bulkInsertNginxLogs performs bulk insert using batch insert
func (h *Handler) bulkInsertNginxLogs(ctx context.Context, orgID, agentID uuid.UUID, entries []NginxLogEntry) (int64, error) {
	// Build batch insert
	query := `
		INSERT INTO nginx_access_logs (
			time, org_id, agent_id, client_ip, method, path, query_string, protocol,
			status_code, response_bytes, response_time, host, referer, user_agent, upstream, request_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`

	batch := &pgx.Batch{}
	for _, entry := range entries {
		// Parse client IP
		clientIP := net.ParseIP(entry.ClientIP)
		if clientIP == nil {
			// Try to extract IP from X-Forwarded-For format
			parts := strings.Split(entry.ClientIP, ",")
			if len(parts) > 0 {
				clientIP = net.ParseIP(strings.TrimSpace(parts[0]))
			}
		}
		if clientIP == nil {
			clientIP = net.ParseIP("0.0.0.0")
		}

		// Use current time if entry time is zero
		entryTime := entry.Time
		if entryTime.IsZero() {
			entryTime = time.Now()
		}

		batch.Queue(query,
			entryTime,
			orgID,
			agentID,
			clientIP.String(),
			entry.Method,
			entry.Path,
			nullString(entry.QueryString),
			nullString(entry.Protocol),
			entry.StatusCode,
			entry.ResponseBytes,
			nullFloat64(entry.ResponseTime),
			nullString(entry.Host),
			nullString(entry.Referer),
			nullString(entry.UserAgent),
			nullString(entry.Upstream),
			nullString(entry.RequestID),
		)
	}

	results := h.db.SendBatch(ctx, batch)
	defer results.Close()

	var inserted int64
	for range entries {
		_, err := results.Exec()
		if err != nil {
			// Log but continue with other entries
			h.logger.Debug("Failed to insert nginx log entry", zap.Error(err))
			continue
		}
		inserted++
	}

	return inserted, nil
}

// GetTrafficAnalytics returns time-series analytics data
// GET /api/v1/traffic/analytics
func (h *Handler) GetTrafficAnalytics(c *gin.Context) {
	// Get org_id - middleware stores it as uuid.UUID
	orgUUID, _ := c.Get("org_id")
	orgID := orgUUID.(uuid.UUID)

	// Parse query params
	interval := c.DefaultQuery("interval", "1h")

	// Support both hours and minutes parameters
	var duration time.Duration
	if minutesStr := c.Query("minutes"); minutesStr != "" {
		minutes, _ := strconv.Atoi(minutesStr)
		if minutes < 1 {
			minutes = 5
		}
		if minutes > 1440 { // Max 24 hours in minutes
			minutes = 1440
		}
		duration = time.Duration(minutes) * time.Minute
	} else {
		hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
		if hours < 1 {
			hours = 24
		}
		if hours > 720 { // Max 30 days
			hours = 720
		}
		duration = time.Duration(hours) * time.Hour
	}

	agentIDStr := c.Query("agent_id")
	var agentID *uuid.UUID
	if agentIDStr != "" {
		parsed, err := uuid.Parse(agentIDStr)
		if err == nil {
			agentID = &parsed
		}
	}

	endTime := time.Now()
	startTime := endTime.Add(-duration)

	// Select the appropriate materialized view based on interval
	var viewName string
	switch interval {
	case "1m", "5m":
		viewName = "nginx_stats_1m"
	case "1h":
		// Use 1m aggregate for real-time data, it will just have more granular buckets
		// The 1h aggregate may not be refreshed yet for recent data
		viewName = "nginx_stats_1m"
	case "1d":
		viewName = "nginx_stats_daily"
	default:
		viewName = "nginx_stats_1m"
	}

	// Build query
	var rows pgx.Rows
	var err error

	ctx := c.Request.Context()

	// Note: Materialized views don't have p95/p99 columns (requires TSL license features)
	// We query max_response_time as a proxy for high latency spikes
	if agentID != nil {
		rows, err = h.db.Query(ctx, fmt.Sprintf(`
			SELECT
				bucket,
				COALESCE(SUM(total_requests), 0),
				COALESCE(SUM(count_2xx), 0),
				COALESCE(SUM(count_3xx), 0),
				COALESCE(SUM(count_4xx), 0),
				COALESCE(SUM(count_5xx), 0),
				COALESCE(SUM(total_bytes), 0),
				COALESCE(AVG(avg_response_time), 0),
				COALESCE(MAX(max_response_time), 0),
				COALESCE(MIN(min_response_time), 0),
				COALESCE(SUM(unique_visitors), 0)
			FROM %s
			WHERE org_id = $1 AND agent_id = $2 AND bucket >= $3 AND bucket <= $4
			GROUP BY bucket
			ORDER BY bucket ASC
		`, viewName), orgID, agentID, startTime, endTime)
	} else {
		rows, err = h.db.Query(ctx, fmt.Sprintf(`
			SELECT
				bucket,
				COALESCE(SUM(total_requests), 0),
				COALESCE(SUM(count_2xx), 0),
				COALESCE(SUM(count_3xx), 0),
				COALESCE(SUM(count_4xx), 0),
				COALESCE(SUM(count_5xx), 0),
				COALESCE(SUM(total_bytes), 0),
				COALESCE(AVG(avg_response_time), 0),
				COALESCE(MAX(max_response_time), 0),
				COALESCE(MIN(min_response_time), 0),
				COALESCE(SUM(unique_visitors), 0)
			FROM %s
			WHERE org_id = $1 AND bucket >= $2 AND bucket <= $3
			GROUP BY bucket
			ORDER BY bucket ASC
		`, viewName), orgID, startTime, endTime)
	}

	if err != nil {
		h.logger.Error("Failed to query analytics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve analytics"})
		return
	}
	defer rows.Close()

	var dataPoints []NginxAnalyticsDataPoint
	for rows.Next() {
		var dp NginxAnalyticsDataPoint
		err := rows.Scan(
			&dp.Bucket,
			&dp.TotalRequests,
			&dp.Count2xx,
			&dp.Count3xx,
			&dp.Count4xx,
			&dp.Count5xx,
			&dp.TotalBytes,
			&dp.AvgResponseTime,
			&dp.MaxResponseTime,
			&dp.MinResponseTime,
			&dp.UniqueVisitors,
		)
		if err != nil {
			h.logger.Error("Failed to scan analytics row", zap.Error(err))
			continue
		}
		// P95/P99 not available from materialized views (requires TSL license)
		// Use max as upper bound indicator
		dp.P95ResponseTime = dp.MaxResponseTime
		dp.P99ResponseTime = dp.MaxResponseTime
		dataPoints = append(dataPoints, dp)
	}

	c.JSON(http.StatusOK, NginxAnalyticsResponse{
		Interval:   interval,
		StartTime:  startTime,
		EndTime:    endTime,
		DataPoints: dataPoints,
	})
}

// GetTrafficAnalyticsSummary returns summary statistics
// GET /api/v1/traffic/analytics/summary
func (h *Handler) GetTrafficAnalyticsSummary(c *gin.Context) {
	// Get org_id - middleware stores it as uuid.UUID
	orgUUIDVal, _ := c.Get("org_id")
	orgID := orgUUIDVal.(uuid.UUID)

	// Support both hours and minutes parameters
	var duration time.Duration
	var durationSeconds float64
	if minutesStr := c.Query("minutes"); minutesStr != "" {
		minutes, _ := strconv.Atoi(minutesStr)
		if minutes < 1 {
			minutes = 5
		}
		duration = time.Duration(minutes) * time.Minute
		durationSeconds = float64(minutes * 60)
	} else {
		hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
		if hours < 1 {
			hours = 24
		}
		duration = time.Duration(hours) * time.Hour
		durationSeconds = float64(hours * 3600)
	}

	agentIDStr := c.Query("agent_id")
	var agentID *uuid.UUID
	if agentIDStr != "" {
		parsed, err := uuid.Parse(agentIDStr)
		if err == nil {
			agentID = &parsed
		}
	}

	endTime := time.Now()
	startTime := endTime.Add(-duration)

	ctx := c.Request.Context()

	var summary NginxAnalyticsSummary
	var err error

	// Query raw table for accurate percentile calculations
	if agentID != nil {
		err = h.db.QueryRow(ctx, `
			SELECT
				COUNT(*),
				COALESCE(SUM(response_bytes), 0),
				COUNT(DISTINCT client_ip),
				COALESCE(AVG(response_time), 0),
				COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time), 0),
				COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time), 0),
				COALESCE(SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END), 0)
			FROM nginx_access_logs
			WHERE org_id = $1 AND agent_id = $2 AND time >= $3 AND time <= $4
		`, orgID, agentID, startTime, endTime).Scan(
			&summary.TotalRequests,
			&summary.TotalBytes,
			&summary.UniqueVisitors,
			&summary.AvgResponseTime,
			&summary.P95ResponseTime,
			&summary.P99ResponseTime,
			&summary.Count2xx,
			&summary.Count3xx,
			&summary.Count4xx,
			&summary.Count5xx,
		)
	} else {
		err = h.db.QueryRow(ctx, `
			SELECT
				COUNT(*),
				COALESCE(SUM(response_bytes), 0),
				COUNT(DISTINCT client_ip),
				COALESCE(AVG(response_time), 0),
				COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time), 0),
				COALESCE(percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time), 0),
				COALESCE(SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END), 0),
				COALESCE(SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END), 0)
			FROM nginx_access_logs
			WHERE org_id = $1 AND time >= $2 AND time <= $3
		`, orgID, startTime, endTime).Scan(
			&summary.TotalRequests,
			&summary.TotalBytes,
			&summary.UniqueVisitors,
			&summary.AvgResponseTime,
			&summary.P95ResponseTime,
			&summary.P99ResponseTime,
			&summary.Count2xx,
			&summary.Count3xx,
			&summary.Count4xx,
			&summary.Count5xx,
		)
	}

	if err != nil && err != pgx.ErrNoRows {
		h.logger.Error("Failed to query summary", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve summary"})
		return
	}

	// Calculate derived metrics
	if summary.TotalRequests > 0 {
		summary.ErrorRate = float64(summary.Count4xx+summary.Count5xx) / float64(summary.TotalRequests) * 100
	}

	if durationSeconds > 0 {
		summary.RequestsPerSecond = float64(summary.TotalRequests) / durationSeconds
		summary.BytesPerSecond = float64(summary.TotalBytes) / durationSeconds
	}

	h.logger.Info("Analytics summary response",
		zap.Int64("total_requests", summary.TotalRequests),
		zap.Int64("total_bytes", summary.TotalBytes),
		zap.Int64("count_4xx", summary.Count4xx),
		zap.Time("start_time", startTime),
		zap.Time("end_time", endTime),
	)

	c.JSON(http.StatusOK, summary)
}

// GetTopPaths returns top paths by request count
// GET /api/v1/traffic/analytics/top-paths
func (h *Handler) GetTopPaths(c *gin.Context) {
	// Get org_id - middleware stores it as uuid.UUID
	orgUUIDVal, _ := c.Get("org_id")
	orgID := orgUUIDVal.(uuid.UUID)

	// Support both hours and minutes parameters
	var duration time.Duration
	if minutesStr := c.Query("minutes"); minutesStr != "" {
		minutes, _ := strconv.Atoi(minutesStr)
		if minutes < 1 {
			minutes = 5
		}
		duration = time.Duration(minutes) * time.Minute
	} else {
		hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
		if hours < 1 {
			hours = 24
		}
		duration = time.Duration(hours) * time.Hour
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit < 1 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	agentIDStr := c.Query("agent_id")
	var agentID *uuid.UUID
	if agentIDStr != "" {
		parsed, err := uuid.Parse(agentIDStr)
		if err == nil {
			agentID = &parsed
		}
	}

	endTime := time.Now()
	startTime := endTime.Add(-duration)

	ctx := c.Request.Context()

	var rows pgx.Rows
	var err error

	// Query raw table for real-time data (aggregate may not be refreshed for current hour)
	if agentID != nil {
		rows, err = h.db.Query(ctx, `
			SELECT
				path,
				COUNT(*) as total_requests,
				COALESCE(SUM(response_bytes), 0) as total_bytes,
				COALESCE(AVG(response_time), 0) as avg_response_time,
				COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time), 0) as p95_response_time,
				SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) as count_4xx,
				SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) as count_5xx,
				COUNT(DISTINCT client_ip) as unique_visitors
			FROM nginx_access_logs
			WHERE org_id = $1 AND agent_id = $2 AND time >= $3 AND time <= $4
			GROUP BY path
			ORDER BY total_requests DESC
			LIMIT $5
		`, orgID, agentID, startTime, endTime, limit)
	} else {
		rows, err = h.db.Query(ctx, `
			SELECT
				path,
				COUNT(*) as total_requests,
				COALESCE(SUM(response_bytes), 0) as total_bytes,
				COALESCE(AVG(response_time), 0) as avg_response_time,
				COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time), 0) as p95_response_time,
				SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) as count_4xx,
				SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) as count_5xx,
				COUNT(DISTINCT client_ip) as unique_visitors
			FROM nginx_access_logs
			WHERE org_id = $1 AND time >= $2 AND time <= $3
			GROUP BY path
			ORDER BY total_requests DESC
			LIMIT $4
		`, orgID, startTime, endTime, limit)
	}

	if err != nil {
		h.logger.Error("Failed to query top paths", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve top paths"})
		return
	}
	defer rows.Close()

	var topPaths []NginxTopPath
	for rows.Next() {
		var tp NginxTopPath
		err := rows.Scan(
			&tp.Path,
			&tp.RequestCount,
			&tp.TotalBytes,
			&tp.AvgResponseTime,
			&tp.P95ResponseTime,
			&tp.Count4xx,
			&tp.Count5xx,
			&tp.UniqueVisitors,
		)
		if err != nil {
			h.logger.Error("Failed to scan top path row", zap.Error(err))
			continue
		}
		if tp.RequestCount > 0 {
			tp.ErrorRate = float64(tp.Count4xx+tp.Count5xx) / float64(tp.RequestCount) * 100
		}
		topPaths = append(topPaths, tp)
	}

	c.JSON(http.StatusOK, gin.H{
		"paths":      topPaths,
		"start_time": startTime,
		"end_time":   endTime,
		"limit":      limit,
	})
}

// GetStatusCodeDistribution returns status code breakdown
// GET /api/v1/traffic/analytics/status-codes
func (h *Handler) GetStatusCodeDistribution(c *gin.Context) {
	// Get org_id - middleware stores it as uuid.UUID
	orgUUIDVal, _ := c.Get("org_id")
	orgID := orgUUIDVal.(uuid.UUID)

	// Support both hours and minutes parameters
	var duration time.Duration
	if minutesStr := c.Query("minutes"); minutesStr != "" {
		minutes, _ := strconv.Atoi(minutesStr)
		if minutes < 1 {
			minutes = 5
		}
		duration = time.Duration(minutes) * time.Minute
	} else {
		hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
		if hours < 1 {
			hours = 24
		}
		duration = time.Duration(hours) * time.Hour
	}

	agentIDStr := c.Query("agent_id")
	var agentID *uuid.UUID
	if agentIDStr != "" {
		parsed, err := uuid.Parse(agentIDStr)
		if err == nil {
			agentID = &parsed
		}
	}

	endTime := time.Now()
	startTime := endTime.Add(-duration)

	ctx := c.Request.Context()

	var rows pgx.Rows
	var err error

	// Query raw logs for status code distribution
	if agentID != nil {
		rows, err = h.db.Query(ctx, `
			SELECT
				status_code,
				COUNT(*) as count
			FROM nginx_access_logs
			WHERE org_id = $1 AND agent_id = $2 AND time >= $3 AND time <= $4
			GROUP BY status_code
			ORDER BY count DESC
		`, orgID, agentID, startTime, endTime)
	} else {
		rows, err = h.db.Query(ctx, `
			SELECT
				status_code,
				COUNT(*) as count
			FROM nginx_access_logs
			WHERE org_id = $1 AND time >= $2 AND time <= $3
			GROUP BY status_code
			ORDER BY count DESC
		`, orgID, startTime, endTime)
	}

	if err != nil {
		h.logger.Error("Failed to query status codes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve status codes"})
		return
	}
	defer rows.Close()

	var distributions []NginxStatusCodeDistribution
	var total int64 = 0

	for rows.Next() {
		var dist NginxStatusCodeDistribution
		err := rows.Scan(&dist.StatusCode, &dist.Count)
		if err != nil {
			h.logger.Error("Failed to scan status code row", zap.Error(err))
			continue
		}
		total += dist.Count
		distributions = append(distributions, dist)
	}

	// Calculate percentages
	for i := range distributions {
		if total > 0 {
			distributions[i].Percentage = float64(distributions[i].Count) / float64(total) * 100
		}
	}

	// Also return grouped by category
	categories := map[string]int64{
		"2xx": 0,
		"3xx": 0,
		"4xx": 0,
		"5xx": 0,
	}
	for _, d := range distributions {
		switch {
		case d.StatusCode >= 200 && d.StatusCode < 300:
			categories["2xx"] += d.Count
		case d.StatusCode >= 300 && d.StatusCode < 400:
			categories["3xx"] += d.Count
		case d.StatusCode >= 400 && d.StatusCode < 500:
			categories["4xx"] += d.Count
		case d.StatusCode >= 500:
			categories["5xx"] += d.Count
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status_codes": distributions,
		"categories":   categories,
		"total":        total,
		"start_time":   startTime,
		"end_time":     endTime,
	})
}

// Helper functions

func nullFloat64(f float64) *float64 {
	// 0 is a valid response time (very fast responses), so only return nil for negative values
	if f < 0 {
		return nil
	}
	return &f
}
