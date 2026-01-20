package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Database Governance Types

type DatabaseInventory struct {
	ID                  uuid.UUID  `json:"id"`
	OrgID               uuid.UUID  `json:"org_id"`
	AgentID             uuid.UUID  `json:"agent_id"`
	DeploymentID        *uuid.UUID `json:"deployment_id,omitempty"`
	Name                string     `json:"name"`
	DBType              string     `json:"db_type"`
	Version             *string    `json:"version,omitempty"`
	ContainerID         *string    `json:"container_id,omitempty"`
	ContainerName       *string    `json:"container_name,omitempty"`
	Host                *string    `json:"host,omitempty"`
	Port                *int       `json:"port,omitempty"`
	DatabaseName        *string    `json:"database_name,omitempty"`
	DataClassification  string     `json:"data_classification"`
	Environment         string     `json:"environment"`
	IsPrimary           bool       `json:"is_primary"`
	IsReplica           bool       `json:"is_replica"`
	ReplicaOf           *uuid.UUID `json:"replica_of,omitempty"`
	PIIData             bool       `json:"pii_data"`
	PCIData             bool       `json:"pci_data"`
	HIPAAData           bool       `json:"hipaa_data"`
	GDPRRelevant        bool       `json:"gdpr_relevant"`
	SizeBytes           *int64     `json:"size_bytes,omitempty"`
	TableCount          *int       `json:"table_count,omitempty"`
	ActiveConnections   *int       `json:"active_connections,omitempty"`
	MaxConnections      *int       `json:"max_connections,omitempty"`
	Status              string     `json:"status"`
	LastHealthCheck     *time.Time `json:"last_health_check,omitempty"`
	ReplicationLagSecs  *int       `json:"replication_lag_seconds,omitempty"`
	OwnerTeam           *string    `json:"owner_team,omitempty"`
	OwnerContact        *string    `json:"owner_contact,omitempty"`
	Description         *string    `json:"description,omitempty"`
	Tags                []string   `json:"tags"`
	DiscoveredAt        time.Time  `json:"discovered_at"`
	AutoDiscovered      bool       `json:"auto_discovered"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type DatabaseBackup struct {
	ID                       uuid.UUID  `json:"id"`
	OrgID                    uuid.UUID  `json:"org_id"`
	DatabaseID               uuid.UUID  `json:"database_id"`
	BackupType               string     `json:"backup_type"`
	BackupName               *string    `json:"backup_name,omitempty"`
	BackupPath               *string    `json:"backup_path,omitempty"`
	SizeBytes                *int64     `json:"size_bytes,omitempty"`
	CompressedSizeBytes      *int64     `json:"compressed_size_bytes,omitempty"`
	CompressionRatio         *float64   `json:"compression_ratio,omitempty"`
	EncryptionEnabled        bool       `json:"encryption_enabled"`
	EncryptionAlgorithm      *string    `json:"encryption_algorithm,omitempty"`
	StartedAt                time.Time  `json:"started_at"`
	CompletedAt              *time.Time `json:"completed_at,omitempty"`
	DurationSeconds          *int       `json:"duration_seconds,omitempty"`
	Status                   string     `json:"status"`
	ErrorMessage             *string    `json:"error_message,omitempty"`
	RetentionDays            int        `json:"retention_days"`
	ExpiresAt                *time.Time `json:"expires_at,omitempty"`
	IsOffsite                bool       `json:"is_offsite"`
	OffsiteLocation          *string    `json:"offsite_location,omitempty"`
	LastVerifiedAt           *time.Time `json:"last_verified_at,omitempty"`
	VerificationStatus       *string    `json:"verification_status,omitempty"`
	VerificationNotes        *string    `json:"verification_notes,omitempty"`
	RPOMinutes               *int       `json:"recovery_point_objective_minutes,omitempty"`
	RTOMinutes               *int       `json:"recovery_time_objective_minutes,omitempty"`
	CanPointInTimeRestore    bool       `json:"can_point_in_time_restore"`
	EarliestRestorePoint     *time.Time `json:"earliest_restore_point,omitempty"`
	LatestRestorePoint       *time.Time `json:"latest_restore_point,omitempty"`
	CreatedAt                time.Time  `json:"created_at"`
}

type DatabasePosture struct {
	OrgID               uuid.UUID `json:"org_id"`
	TotalDatabases      int       `json:"total_databases"`
	HealthyDatabases    int       `json:"healthy_databases"`
	DegradedDatabases   int       `json:"degraded_databases"`
	UnhealthyDatabases  int       `json:"unhealthy_databases"`
	PIIDatabases        int       `json:"pii_databases"`
	RestrictedDatabases int       `json:"restricted_databases"`
	ReplicaCount        int       `json:"replica_count"`
	TotalSizeBytes      *int64    `json:"total_size_bytes,omitempty"`
}

type BackupCompliance struct {
	OrgID              uuid.UUID  `json:"org_id"`
	DatabaseID         uuid.UUID  `json:"database_id"`
	DatabaseName       string     `json:"database_name"`
	DBType             string     `json:"db_type"`
	DataClassification string     `json:"data_classification"`
	LastBackupAt       *time.Time `json:"last_backup_at,omitempty"`
	BackupsLast24h     int        `json:"backups_last_24h"`
	BackupsLast7d      int        `json:"backups_last_7d"`
	ComplianceStatus   string     `json:"compliance_status"`
}

// GET /api/v1/databases
func (h *Handler) listDatabaseInventory(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Query parameters
	dbType := c.Query("db_type")
	environment := c.Query("environment")
	status := c.Query("status")
	dataClassification := c.Query("data_classification")
	limit := c.DefaultQuery("limit", "100")
	offset := c.DefaultQuery("offset", "0")

	query := `
		SELECT
			id, org_id, agent_id, deployment_id, name, db_type, version,
			container_id, container_name, host, port, database_name,
			data_classification, environment, is_primary, is_replica, replica_of,
			pii_data, pci_data, hipaa_data, gdpr_relevant,
			size_bytes, table_count, active_connections, max_connections,
			status, last_health_check, replication_lag_seconds,
			owner_team, owner_contact, description, tags,
			discovered_at, auto_discovered, created_at, updated_at
		FROM database_inventory
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argCount := 1

	if dbType != "" {
		argCount++
		query += ` AND db_type = $` + string(rune(argCount+48))
		args = append(args, dbType)
	}
	if environment != "" {
		argCount++
		query += ` AND environment = $` + string(rune(argCount+48))
		args = append(args, environment)
	}
	if status != "" {
		argCount++
		query += ` AND status = $` + string(rune(argCount+48))
		args = append(args, status)
	}
	if dataClassification != "" {
		argCount++
		query += ` AND data_classification = $` + string(rune(argCount+48))
		args = append(args, dataClassification)
	}

	query += ` ORDER BY name LIMIT $` + string(rune(argCount+49)) + ` OFFSET $` + string(rune(argCount+50))
	args = append(args, limit, offset)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch databases"})
		return
	}
	defer rows.Close()

	var databases []DatabaseInventory
	for rows.Next() {
		var db DatabaseInventory
		err := rows.Scan(
			&db.ID, &db.OrgID, &db.AgentID, &db.DeploymentID, &db.Name, &db.DBType, &db.Version,
			&db.ContainerID, &db.ContainerName, &db.Host, &db.Port, &db.DatabaseName,
			&db.DataClassification, &db.Environment, &db.IsPrimary, &db.IsReplica, &db.ReplicaOf,
			&db.PIIData, &db.PCIData, &db.HIPAAData, &db.GDPRRelevant,
			&db.SizeBytes, &db.TableCount, &db.ActiveConnections, &db.MaxConnections,
			&db.Status, &db.LastHealthCheck, &db.ReplicationLagSecs,
			&db.OwnerTeam, &db.OwnerContact, &db.Description, &db.Tags,
			&db.DiscoveredAt, &db.AutoDiscovered, &db.CreatedAt, &db.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan database: " + err.Error())
			continue
		}
		databases = append(databases, db)
	}

	if databases == nil {
		databases = []DatabaseInventory{}
	}

	// Get total count
	countQuery := `SELECT COUNT(*) FROM database_inventory WHERE org_id = $1`
	var total int
	h.db.QueryRow(c.Request.Context(), countQuery, orgID).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"databases": databases,
		"total":     total,
	})
}

// GET /api/v1/databases/:id
func (h *Handler) getDatabaseInventoryItem(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	databaseID := c.Param("id")

	databaseUUID, err := uuid.Parse(databaseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid database ID"})
		return
	}

	query := `
		SELECT
			id, org_id, agent_id, deployment_id, name, db_type, version,
			container_id, container_name, host, port, database_name,
			data_classification, environment, is_primary, is_replica, replica_of,
			pii_data, pci_data, hipaa_data, gdpr_relevant,
			size_bytes, table_count, active_connections, max_connections,
			status, last_health_check, replication_lag_seconds,
			owner_team, owner_contact, description, tags,
			discovered_at, auto_discovered, created_at, updated_at
		FROM database_inventory
		WHERE id = $1 AND org_id = $2
	`

	var db DatabaseInventory
	err = h.db.QueryRow(c.Request.Context(), query, databaseUUID, orgID).Scan(
		&db.ID, &db.OrgID, &db.AgentID, &db.DeploymentID, &db.Name, &db.DBType, &db.Version,
		&db.ContainerID, &db.ContainerName, &db.Host, &db.Port, &db.DatabaseName,
		&db.DataClassification, &db.Environment, &db.IsPrimary, &db.IsReplica, &db.ReplicaOf,
		&db.PIIData, &db.PCIData, &db.HIPAAData, &db.GDPRRelevant,
		&db.SizeBytes, &db.TableCount, &db.ActiveConnections, &db.MaxConnections,
		&db.Status, &db.LastHealthCheck, &db.ReplicationLagSecs,
		&db.OwnerTeam, &db.OwnerContact, &db.Description, &db.Tags,
		&db.DiscoveredAt, &db.AutoDiscovered, &db.CreatedAt, &db.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Database not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch database"})
		return
	}

	c.JSON(http.StatusOK, db)
}

// POST /api/v1/databases
func (h *Handler) createDatabaseInventory(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req struct {
		AgentID            string   `json:"agent_id" binding:"required"`
		DeploymentID       *string  `json:"deployment_id"`
		Name               string   `json:"name" binding:"required"`
		DBType             string   `json:"db_type" binding:"required"`
		Version            *string  `json:"version"`
		ContainerID        *string  `json:"container_id"`
		ContainerName      *string  `json:"container_name"`
		Host               *string  `json:"host"`
		Port               *int     `json:"port"`
		DatabaseName       *string  `json:"database_name"`
		DataClassification string   `json:"data_classification"`
		Environment        string   `json:"environment"`
		IsPrimary          bool     `json:"is_primary"`
		IsReplica          bool     `json:"is_replica"`
		ReplicaOf          *string  `json:"replica_of"`
		PIIData            bool     `json:"pii_data"`
		PCIData            bool     `json:"pci_data"`
		HIPAAData          bool     `json:"hipaa_data"`
		GDPRRelevant       bool     `json:"gdpr_relevant"`
		OwnerTeam          *string  `json:"owner_team"`
		OwnerContact       *string  `json:"owner_contact"`
		Description        *string  `json:"description"`
		Tags               []string `json:"tags"`
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
	if req.DataClassification == "" {
		req.DataClassification = "internal"
	}
	if req.Environment == "" {
		req.Environment = "production"
	}
	if req.Tags == nil {
		req.Tags = []string{}
	}

	var deploymentID, replicaOf *uuid.UUID
	if req.DeploymentID != nil {
		id, _ := uuid.Parse(*req.DeploymentID)
		deploymentID = &id
	}
	if req.ReplicaOf != nil {
		id, _ := uuid.Parse(*req.ReplicaOf)
		replicaOf = &id
	}

	query := `
		INSERT INTO database_inventory (
			org_id, agent_id, deployment_id, name, db_type, version,
			container_id, container_name, host, port, database_name,
			data_classification, environment, is_primary, is_replica, replica_of,
			pii_data, pci_data, hipaa_data, gdpr_relevant,
			owner_team, owner_contact, description, tags, auto_discovered
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, false)
		RETURNING id, created_at, updated_at, discovered_at
	`

	var db DatabaseInventory
	db.OrgID = orgID
	db.AgentID = agentUUID
	db.DeploymentID = deploymentID
	db.Name = req.Name
	db.DBType = req.DBType
	db.Version = req.Version
	db.ContainerID = req.ContainerID
	db.ContainerName = req.ContainerName
	db.Host = req.Host
	db.Port = req.Port
	db.DatabaseName = req.DatabaseName
	db.DataClassification = req.DataClassification
	db.Environment = req.Environment
	db.IsPrimary = req.IsPrimary
	db.IsReplica = req.IsReplica
	db.ReplicaOf = replicaOf
	db.PIIData = req.PIIData
	db.PCIData = req.PCIData
	db.HIPAAData = req.HIPAAData
	db.GDPRRelevant = req.GDPRRelevant
	db.OwnerTeam = req.OwnerTeam
	db.OwnerContact = req.OwnerContact
	db.Description = req.Description
	db.Tags = req.Tags
	db.Status = "healthy"
	db.AutoDiscovered = false

	err = h.db.QueryRow(c.Request.Context(), query,
		orgID, agentUUID, deploymentID, req.Name, req.DBType, req.Version,
		req.ContainerID, req.ContainerName, req.Host, req.Port, req.DatabaseName,
		req.DataClassification, req.Environment, req.IsPrimary, req.IsReplica, replicaOf,
		req.PIIData, req.PCIData, req.HIPAAData, req.GDPRRelevant,
		req.OwnerTeam, req.OwnerContact, req.Description, req.Tags,
	).Scan(&db.ID, &db.CreatedAt, &db.UpdatedAt, &db.DiscoveredAt)

	if err != nil {
		h.logger.Error("Failed to create database: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create database"})
		return
	}

	c.JSON(http.StatusCreated, db)
}

// PUT /api/v1/databases/:id
func (h *Handler) updateDatabaseInventory(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	databaseID := c.Param("id")

	databaseUUID, err := uuid.Parse(databaseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid database ID"})
		return
	}

	var req struct {
		DataClassification *string  `json:"data_classification"`
		Environment        *string  `json:"environment"`
		PIIData            *bool    `json:"pii_data"`
		PCIData            *bool    `json:"pci_data"`
		HIPAAData          *bool    `json:"hipaa_data"`
		GDPRRelevant       *bool    `json:"gdpr_relevant"`
		Status             *string  `json:"status"`
		OwnerTeam          *string  `json:"owner_team"`
		OwnerContact       *string  `json:"owner_contact"`
		Description        *string  `json:"description"`
		Tags               []string `json:"tags"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	query := `
		UPDATE database_inventory SET
			data_classification = COALESCE($1, data_classification),
			environment = COALESCE($2, environment),
			pii_data = COALESCE($3, pii_data),
			pci_data = COALESCE($4, pci_data),
			hipaa_data = COALESCE($5, hipaa_data),
			gdpr_relevant = COALESCE($6, gdpr_relevant),
			status = COALESCE($7, status),
			owner_team = COALESCE($8, owner_team),
			owner_contact = COALESCE($9, owner_contact),
			description = COALESCE($10, description),
			tags = COALESCE($11, tags),
			updated_at = NOW()
		WHERE id = $12 AND org_id = $13
		RETURNING id
	`

	var returnedID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), query,
		req.DataClassification, req.Environment,
		req.PIIData, req.PCIData, req.HIPAAData, req.GDPRRelevant,
		req.Status, req.OwnerTeam, req.OwnerContact, req.Description, req.Tags,
		databaseUUID, orgID,
	).Scan(&returnedID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Database not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Database updated successfully"})
}

// DELETE /api/v1/databases/:id
func (h *Handler) deleteDatabaseInventory(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	databaseID := c.Param("id")

	databaseUUID, err := uuid.Parse(databaseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid database ID"})
		return
	}

	query := `DELETE FROM database_inventory WHERE id = $1 AND org_id = $2`
	result, err := h.db.Exec(c.Request.Context(), query, databaseUUID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete database"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Database not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Database deleted successfully"})
}

// GET /api/v1/databases/posture
func (h *Handler) getDatabasePosture(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `SELECT * FROM v_database_posture WHERE org_id = $1`

	var posture DatabasePosture
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&posture.OrgID, &posture.TotalDatabases, &posture.HealthyDatabases,
		&posture.DegradedDatabases, &posture.UnhealthyDatabases,
		&posture.PIIDatabases, &posture.RestrictedDatabases,
		&posture.ReplicaCount, &posture.TotalSizeBytes,
	)

	if err == sql.ErrNoRows {
		posture = DatabasePosture{OrgID: orgID}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch database posture"})
		return
	}

	c.JSON(http.StatusOK, posture)
}

// GET /api/v1/databases/:id/backups
func (h *Handler) listDatabaseBackups(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	databaseID := c.Param("id")

	databaseUUID, err := uuid.Parse(databaseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid database ID"})
		return
	}

	limit := c.DefaultQuery("limit", "50")
	status := c.Query("status")

	query := `
		SELECT
			id, org_id, database_id, backup_type, backup_name, backup_path,
			size_bytes, compressed_size_bytes, compression_ratio,
			encryption_enabled, encryption_algorithm,
			started_at, completed_at, duration_seconds, status, error_message,
			retention_days, expires_at, is_offsite, offsite_location,
			last_verified_at, verification_status, verification_notes,
			recovery_point_objective_minutes, recovery_time_objective_minutes,
			can_point_in_time_restore, earliest_restore_point, latest_restore_point,
			created_at
		FROM database_backups
		WHERE database_id = $1 AND org_id = $2
	`
	args := []interface{}{databaseUUID, orgID}
	argCount := 2

	if status != "" {
		argCount++
		query += ` AND status = $` + string(rune(argCount+48))
		args = append(args, status)
	}

	query += ` ORDER BY started_at DESC LIMIT $` + string(rune(argCount+49))
	args = append(args, limit)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch backups"})
		return
	}
	defer rows.Close()

	var backups []DatabaseBackup
	for rows.Next() {
		var b DatabaseBackup
		err := rows.Scan(
			&b.ID, &b.OrgID, &b.DatabaseID, &b.BackupType, &b.BackupName, &b.BackupPath,
			&b.SizeBytes, &b.CompressedSizeBytes, &b.CompressionRatio,
			&b.EncryptionEnabled, &b.EncryptionAlgorithm,
			&b.StartedAt, &b.CompletedAt, &b.DurationSeconds, &b.Status, &b.ErrorMessage,
			&b.RetentionDays, &b.ExpiresAt, &b.IsOffsite, &b.OffsiteLocation,
			&b.LastVerifiedAt, &b.VerificationStatus, &b.VerificationNotes,
			&b.RPOMinutes, &b.RTOMinutes,
			&b.CanPointInTimeRestore, &b.EarliestRestorePoint, &b.LatestRestorePoint,
			&b.CreatedAt,
		)
		if err != nil {
			continue
		}
		backups = append(backups, b)
	}

	if backups == nil {
		backups = []DatabaseBackup{}
	}

	c.JSON(http.StatusOK, gin.H{"backups": backups})
}

// GET /api/v1/databases/compliance
func (h *Handler) getDatabaseBackupCompliance(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `SELECT * FROM v_backup_compliance WHERE org_id = $1`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch backup compliance"})
		return
	}
	defer rows.Close()

	var compliance []BackupCompliance
	for rows.Next() {
		var bc BackupCompliance
		err := rows.Scan(
			&bc.OrgID, &bc.DatabaseID, &bc.DatabaseName, &bc.DBType,
			&bc.DataClassification, &bc.LastBackupAt,
			&bc.BackupsLast24h, &bc.BackupsLast7d, &bc.ComplianceStatus,
		)
		if err != nil {
			continue
		}
		compliance = append(compliance, bc)
	}

	if compliance == nil {
		compliance = []BackupCompliance{}
	}

	// Calculate summary
	compliant := 0
	warning := 0
	nonCompliant := 0
	for _, bc := range compliance {
		switch bc.ComplianceStatus {
		case "compliant":
			compliant++
		case "warning":
			warning++
		case "non_compliant":
			nonCompliant++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"compliance": compliance,
		"summary": gin.H{
			"total":         len(compliance),
			"compliant":     compliant,
			"warning":       warning,
			"non_compliant": nonCompliant,
		},
	})
}
