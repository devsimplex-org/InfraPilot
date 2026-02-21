package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Agent-scoped database endpoints: /api/v1/agents/:id/databases

// GET /api/v1/agents/:id/databases
func (h *Handler) listDatabases(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, name, db_type, version, host, port, status, environment, created_at
		FROM database_inventory
		WHERE agent_id = $1 AND org_id = $2
		ORDER BY created_at DESC
	`, agentUUID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch databases"})
		return
	}
	defer rows.Close()

	type agentDB struct {
		ID          uuid.UUID `json:"id"`
		Name        string    `json:"name"`
		DBType      string    `json:"db_type"`
		Version     *string   `json:"version,omitempty"`
		Host        *string   `json:"host,omitempty"`
		Port        *int      `json:"port,omitempty"`
		Status      string    `json:"status"`
		Environment string    `json:"environment"`
		CreatedAt   time.Time `json:"created_at"`
	}

	databases := []agentDB{}
	for rows.Next() {
		var db agentDB
		if err := rows.Scan(&db.ID, &db.Name, &db.DBType, &db.Version, &db.Host, &db.Port, &db.Status, &db.Environment, &db.CreatedAt); err != nil {
			h.logger.Error("Failed to scan database: " + err.Error())
			continue
		}
		databases = append(databases, db)
	}

	c.JSON(http.StatusOK, gin.H{"databases": databases})
}

// POST /api/v1/agents/:id/databases
func (h *Handler) addDatabase(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	var req struct {
		Name        string  `json:"name" binding:"required"`
		DBType      string  `json:"db_type" binding:"required"`
		Host        *string `json:"host"`
		Port        *int    `json:"port"`
		Environment string  `json:"environment"`
		Version     *string `json:"version"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Environment == "" {
		req.Environment = "production"
	}

	var id uuid.UUID
	var createdAt time.Time
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO database_inventory (org_id, agent_id, name, db_type, host, port, environment, version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at
	`, orgID, agentUUID, req.Name, req.DBType, req.Host, req.Port, req.Environment, req.Version).Scan(&id, &createdAt)
	if err != nil {
		h.logger.Error("Failed to add database: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add database"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":          id,
		"name":        req.Name,
		"db_type":     req.DBType,
		"host":        req.Host,
		"port":        req.Port,
		"environment": req.Environment,
		"version":     req.Version,
		"agent_id":    agentUUID,
		"org_id":      orgID,
		"created_at":  createdAt,
	})
}

// DELETE /api/v1/agents/:id/databases/:did
func (h *Handler) removeDatabase(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}
	dbUUID, err := uuid.Parse(c.Param("did"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid database ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM database_inventory
		WHERE id = $1 AND agent_id = $2 AND org_id = $3
	`, dbUUID, agentUUID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete database"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Database not found"})
		return
	}

	c.Status(http.StatusNoContent)
}

// GET /api/v1/agents/:id/databases/:did/metrics
func (h *Handler) getDatabaseMetrics(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentUUID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}
	dbUUID, err := uuid.Parse(c.Param("did"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid database ID"})
		return
	}

	var name, dbType, status, environment string
	var version *string
	var sizeBytes *int64
	var activeConnections, maxConnections *int
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT name, db_type, status, environment, version, size_bytes, active_connections, max_connections
		FROM database_inventory
		WHERE id = $1 AND agent_id = $2 AND org_id = $3
	`, dbUUID, agentUUID, orgID).Scan(
		&name, &dbType, &status, &environment, &version,
		&sizeBytes, &activeConnections, &maxConnections,
	)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Database not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch database metrics"})
		return
	}

	sizeVal := int64(0)
	if sizeBytes != nil {
		sizeVal = *sizeBytes
	}
	connVal := 0
	if activeConnections != nil {
		connVal = *activeConnections
	}
	maxConnVal := 0
	if maxConnections != nil {
		maxConnVal = *maxConnections
	}

	c.JSON(http.StatusOK, gin.H{
		"database_id":      dbUUID,
		"name":             name,
		"db_type":          dbType,
		"status":           status,
		"environment":      environment,
		"version":          version,
		"size_bytes":       sizeVal,
		"connection_count": connVal,
		"max_connections":  maxConnVal,
	})
}
