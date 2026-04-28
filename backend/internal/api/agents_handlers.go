package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Agent struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	Name            string     `json:"name"`
	Hostname        *string    `json:"hostname"`
	Status          string     `json:"status"`
	Version         *string    `json:"version"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	CreatedAt       time.Time  `json:"created_at"`
	EnrollmentToken *string    `json:"enrollment_token,omitempty"`
	// Resource metrics — updated on each heartbeat
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsedMB  int64   `json:"memory_used_mb"`
	MemoryTotalMB int64   `json:"memory_total_mb"`
	DiskUsedMB    int64   `json:"disk_used_mb"`
	DiskTotalMB   int64   `json:"disk_total_mb"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

type CreateAgentRequest struct {
	Name string `json:"name" binding:"required"`
}

func (h *Handler) listAgents(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, name, hostname, status, version, last_seen_at, created_at,
		       cpu_percent, memory_used_mb, memory_total_mb, disk_used_mb, disk_total_mb, uptime_seconds
		FROM agents
		WHERE org_id = $1
		ORDER BY created_at DESC
	`, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch agents"})
		return
	}
	defer rows.Close()

	agents := []Agent{}
	for rows.Next() {
		var a Agent
		if err := rows.Scan(
			&a.ID, &a.OrgID, &a.Name, &a.Hostname, &a.Status, &a.Version, &a.LastSeenAt, &a.CreatedAt,
			&a.CPUPercent, &a.MemoryUsedMB, &a.MemoryTotalMB, &a.DiskUsedMB, &a.DiskTotalMB, &a.UptimeSeconds,
		); err != nil {
			continue
		}
		agents = append(agents, a)
	}

	c.JSON(http.StatusOK, agents)
}

func (h *Handler) createAgent(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req CreateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate enrollment token
	enrollmentToken, err := h.auth.GenerateEnrollmentToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate enrollment token"})
		return
	}

	var agentID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO agents (org_id, name, enrollment_token, status)
		VALUES ($1, $2, $3, 'pending')
		RETURNING id
	`, orgID, req.Name, enrollmentToken).Scan(&agentID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create agent"})
		return
	}

	h.auditLog(c, userID, orgID, "agent.create", "agent", agentID, req)

	c.JSON(http.StatusCreated, gin.H{
		"id":               agentID,
		"name":             req.Name,
		"enrollment_token": enrollmentToken,
		"status":           "pending",
	})
}

func (h *Handler) getAgent(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var a Agent
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, name, hostname, status, version, last_seen_at, created_at
		FROM agents
		WHERE id = $1 AND org_id = $2
	`, agentID, orgID).Scan(&a.ID, &a.OrgID, &a.Name, &a.Hostname, &a.Status, &a.Version, &a.LastSeenAt, &a.CreatedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, a)
}

func (h *Handler) deleteAgent(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM agents WHERE id = $1 AND org_id = $2
	`, agentID, orgID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete agent"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	h.auditLog(c, userID, orgID, "agent.delete", "agent", agentID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "agent deleted"})
}

func (h *Handler) getAgentMetrics(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var m struct {
		AgentID       uuid.UUID `json:"agent_id"`
		CPUPercent    float64   `json:"cpu_percent"`
		MemoryUsedMB  int64     `json:"memory_used_mb"`
		MemoryTotalMB int64     `json:"memory_total_mb"`
		DiskUsedMB    int64     `json:"disk_used_mb"`
		DiskTotalMB   int64     `json:"disk_total_mb"`
		UptimeSeconds int64     `json:"uptime_seconds"`
	}
	m.AgentID = agentID

	err = h.db.QueryRow(c.Request.Context(), `
		SELECT cpu_percent, memory_used_mb, memory_total_mb, disk_used_mb, disk_total_mb, uptime_seconds
		FROM agents WHERE id = $1 AND org_id = $2
	`, agentID, orgID).Scan(
		&m.CPUPercent, &m.MemoryUsedMB, &m.MemoryTotalMB, &m.DiskUsedMB, &m.DiskTotalMB, &m.UptimeSeconds,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, m)
}
