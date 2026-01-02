package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RateLimit represents a rate limit configuration
type RateLimit struct {
	ID          uuid.UUID `json:"id"`
	ProxyHostID uuid.UUID `json:"proxy_host_id"`
	ZoneName    string    `json:"zone_name"`
	RequestsPer int       `json:"requests_per"`
	TimeWindow  string    `json:"time_window"`
	Burst       int       `json:"burst"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RateLimitRequest is the request body for creating/updating rate limits
type RateLimitRequest struct {
	ZoneName    string `json:"zone_name" binding:"required"`
	RequestsPer int    `json:"requests_per" binding:"required,min=1"`
	TimeWindow  string `json:"time_window" binding:"required,oneof=1s 10s 1m 5m 10m 1h"`
	Burst       int    `json:"burst" binding:"min=0"`
	Enabled     bool   `json:"enabled"`
}

// listRateLimits returns all rate limits for a proxy host
func (h *Handler) listRateLimits(c *gin.Context) {
	proxyID, err := uuid.Parse(c.Param("pid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy ID"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, proxy_host_id, zone_name, requests_per, time_window, burst, enabled, created_at, updated_at
		FROM rate_limits
		WHERE proxy_host_id = $1
		ORDER BY created_at DESC
	`, proxyID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch rate limits"})
		return
	}
	defer rows.Close()

	rateLimits := []RateLimit{}
	for rows.Next() {
		var rl RateLimit
		if err := rows.Scan(&rl.ID, &rl.ProxyHostID, &rl.ZoneName, &rl.RequestsPer, &rl.TimeWindow, &rl.Burst, &rl.Enabled, &rl.CreatedAt, &rl.UpdatedAt); err != nil {
			continue
		}
		rateLimits = append(rateLimits, rl)
	}

	c.JSON(http.StatusOK, rateLimits)
}

// createRateLimit creates a new rate limit for a proxy host
func (h *Handler) createRateLimit(c *gin.Context) {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	proxyID, err := uuid.Parse(c.Param("pid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy ID"})
		return
	}

	var req RateLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify proxy exists and belongs to agent
	var exists bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM proxy_hosts WHERE id = $1 AND agent_id = $2)
	`, proxyID, agentID).Scan(&exists)

	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy host not found"})
		return
	}

	// Check for duplicate zone name
	var duplicate bool
	h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM rate_limits WHERE proxy_host_id = $1 AND zone_name = $2)
	`, proxyID, req.ZoneName).Scan(&duplicate)

	if duplicate {
		c.JSON(http.StatusConflict, gin.H{"error": "zone name already exists for this proxy"})
		return
	}

	// Set default burst if not provided
	burst := req.Burst
	if burst == 0 {
		burst = 50
	}

	var rl RateLimit
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO rate_limits (proxy_host_id, zone_name, requests_per, time_window, burst, enabled)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, proxy_host_id, zone_name, requests_per, time_window, burst, enabled, created_at, updated_at
	`, proxyID, req.ZoneName, req.RequestsPer, req.TimeWindow, burst, req.Enabled).Scan(
		&rl.ID, &rl.ProxyHostID, &rl.ZoneName, &rl.RequestsPer, &rl.TimeWindow, &rl.Burst, &rl.Enabled, &rl.CreatedAt, &rl.UpdatedAt,
	)

	if err != nil {
		h.logger.Error("Failed to create rate limit")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rate limit"})
		return
	}

	// Audit log
	userID := c.MustGet("user_id").(uuid.UUID)
	orgID := c.MustGet("org_id").(uuid.UUID)
	h.auditLog(c, userID, orgID, "rate_limit.created", "rate_limit", rl.ID, req)

	c.JSON(http.StatusCreated, rl)
}

// updateRateLimit updates an existing rate limit
func (h *Handler) updateRateLimit(c *gin.Context) {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	proxyID, err := uuid.Parse(c.Param("pid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy ID"})
		return
	}

	rlID, err := uuid.Parse(c.Param("rlid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rate limit ID"})
		return
	}

	var req RateLimitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify proxy exists and belongs to agent
	var exists bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM proxy_hosts WHERE id = $1 AND agent_id = $2)
	`, proxyID, agentID).Scan(&exists)

	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy host not found"})
		return
	}

	// Check for duplicate zone name (excluding current)
	var duplicate bool
	h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM rate_limits WHERE proxy_host_id = $1 AND zone_name = $2 AND id != $3)
	`, proxyID, req.ZoneName, rlID).Scan(&duplicate)

	if duplicate {
		c.JSON(http.StatusConflict, gin.H{"error": "zone name already exists for this proxy"})
		return
	}

	burst := req.Burst
	if burst == 0 {
		burst = 50
	}

	var rl RateLimit
	err = h.db.QueryRow(c.Request.Context(), `
		UPDATE rate_limits
		SET zone_name = $1, requests_per = $2, time_window = $3, burst = $4, enabled = $5, updated_at = NOW()
		WHERE id = $6 AND proxy_host_id = $7
		RETURNING id, proxy_host_id, zone_name, requests_per, time_window, burst, enabled, created_at, updated_at
	`, req.ZoneName, req.RequestsPer, req.TimeWindow, burst, req.Enabled, rlID, proxyID).Scan(
		&rl.ID, &rl.ProxyHostID, &rl.ZoneName, &rl.RequestsPer, &rl.TimeWindow, &rl.Burst, &rl.Enabled, &rl.CreatedAt, &rl.UpdatedAt,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rate limit not found"})
		return
	}

	// Audit log
	userID := c.MustGet("user_id").(uuid.UUID)
	orgID := c.MustGet("org_id").(uuid.UUID)
	h.auditLog(c, userID, orgID, "rate_limit.updated", "rate_limit", rl.ID, req)

	c.JSON(http.StatusOK, rl)
}

// deleteRateLimit deletes a rate limit
func (h *Handler) deleteRateLimit(c *gin.Context) {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	proxyID, err := uuid.Parse(c.Param("pid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy ID"})
		return
	}

	rlID, err := uuid.Parse(c.Param("rlid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rate limit ID"})
		return
	}

	// Verify proxy exists and belongs to agent
	var exists bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM proxy_hosts WHERE id = $1 AND agent_id = $2)
	`, proxyID, agentID).Scan(&exists)

	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy host not found"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM rate_limits WHERE id = $1 AND proxy_host_id = $2
	`, rlID, proxyID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete rate limit"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "rate limit not found"})
		return
	}

	// Audit log
	userID := c.MustGet("user_id").(uuid.UUID)
	orgID := c.MustGet("org_id").(uuid.UUID)
	h.auditLog(c, userID, orgID, "rate_limit.deleted", "rate_limit", rlID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "rate limit deleted"})
}
