package api

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==================== Types ====================

type ServiceOwnership struct {
	ID                     uuid.UUID  `json:"id"`
	OrgID                  uuid.UUID  `json:"org_id"`
	ServiceName            string     `json:"service_name"`
	TeamName               string     `json:"team_name"`
	TeamEmail              *string    `json:"team_email,omitempty"`
	TeamSlackChannel       *string    `json:"team_slack_channel,omitempty"`
	TeamSlackWebhook       *string    `json:"team_slack_webhook,omitempty"`
	PrimaryContactID       *uuid.UUID `json:"primary_contact_id,omitempty"`
	SecondaryContactID     *uuid.UUID `json:"secondary_contact_id,omitempty"`
	PrimaryContactEmail    *string    `json:"primary_contact_email,omitempty"`
	SecondaryContactEmail  *string    `json:"secondary_contact_email,omitempty"`
	Description            *string    `json:"description,omitempty"`
	RepositoryURL          *string    `json:"repository_url,omitempty"`
	DocumentationURL       *string    `json:"documentation_url,omitempty"`
	OncallURL              *string    `json:"oncall_url,omitempty"`
	Tags                   []string   `json:"tags,omitempty"`
	Status                 string     `json:"status"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

type Team struct {
	ID                      uuid.UUID  `json:"id"`
	OrgID                   uuid.UUID  `json:"org_id"`
	Name                    string     `json:"name"`
	DisplayName             *string    `json:"display_name,omitempty"`
	Email                   *string    `json:"email,omitempty"`
	SlackChannel            *string    `json:"slack_channel,omitempty"`
	SlackWebhook            *string    `json:"slack_webhook,omitempty"`
	PagerDutyIntegrationKey *string    `json:"pagerduty_integration_key,omitempty"`
	Description             *string    `json:"description,omitempty"`
	ManagerID               *uuid.UUID `json:"manager_id,omitempty"`
	Tags                    []string   `json:"tags,omitempty"`
	Active                  bool       `json:"active"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

type TeamMember struct {
	ID        uuid.UUID `json:"id"`
	TeamID    uuid.UUID `json:"team_id"`
	UserID    uuid.UUID `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateServiceOwnershipRequest struct {
	ServiceName           string   `json:"service_name" binding:"required"`
	TeamName              string   `json:"team_name" binding:"required"`
	TeamEmail             *string  `json:"team_email,omitempty"`
	TeamSlackChannel      *string  `json:"team_slack_channel,omitempty"`
	TeamSlackWebhook      *string  `json:"team_slack_webhook,omitempty"`
	PrimaryContactEmail   *string  `json:"primary_contact_email,omitempty"`
	SecondaryContactEmail *string  `json:"secondary_contact_email,omitempty"`
	Description           *string  `json:"description,omitempty"`
	RepositoryURL         *string  `json:"repository_url,omitempty"`
	DocumentationURL      *string  `json:"documentation_url,omitempty"`
	OncallURL             *string  `json:"oncall_url,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
	Status                *string  `json:"status,omitempty"`
}

type CreateTeamRequest struct {
	Name                    string   `json:"name" binding:"required"`
	DisplayName             *string  `json:"display_name,omitempty"`
	Email                   *string  `json:"email,omitempty"`
	SlackChannel            *string  `json:"slack_channel,omitempty"`
	SlackWebhook            *string  `json:"slack_webhook,omitempty"`
	PagerDutyIntegrationKey *string  `json:"pagerduty_integration_key,omitempty"`
	Description             *string  `json:"description,omitempty"`
	Tags                    []string `json:"tags,omitempty"`
}

type AddTeamMemberRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Role   string `json:"role" binding:"required,oneof=lead member oncall"`
}

// ==================== Service Ownership Handlers ====================

func (h *Handler) listServiceOwnerships(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	serviceName := c.Query("service_name")
	teamName := c.Query("team_name")
	status := c.Query("status")

	query := `
		SELECT id, org_id, service_name, team_name, team_email, team_slack_channel,
		       team_slack_webhook, primary_contact_id, secondary_contact_id,
		       primary_contact_email, secondary_contact_email,
		       description, repository_url, documentation_url, oncall_url,
		       tags, status, created_at, updated_at
		FROM service_ownership
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	if serviceName != "" {
		query += ` AND service_name ILIKE $` + string(rune('0'+argIdx))
		args = append(args, "%"+serviceName+"%")
		argIdx++
	}

	if teamName != "" {
		query += ` AND team_name ILIKE $` + string(rune('0'+argIdx))
		args = append(args, "%"+teamName+"%")
		argIdx++
	}

	if status != "" {
		query += ` AND status = $` + string(rune('0'+argIdx))
		args = append(args, status)
		argIdx++
	}

	query += ` ORDER BY service_name`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to list service ownerships", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list service ownerships"})
		return
	}
	defer rows.Close()

	var ownerships []ServiceOwnership
	for rows.Next() {
		var o ServiceOwnership
		var tags []string

		err := rows.Scan(
			&o.ID, &o.OrgID, &o.ServiceName, &o.TeamName, &o.TeamEmail, &o.TeamSlackChannel,
			&o.TeamSlackWebhook, &o.PrimaryContactID, &o.SecondaryContactID,
			&o.PrimaryContactEmail, &o.SecondaryContactEmail,
			&o.Description, &o.RepositoryURL, &o.DocumentationURL, &o.OncallURL,
			&tags, &o.Status, &o.CreatedAt, &o.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan service ownership", zap.Error(err))
			continue
		}
		o.Tags = tags
		ownerships = append(ownerships, o)
	}

	c.JSON(http.StatusOK, gin.H{
		"ownerships": ownerships,
		"count":      len(ownerships),
	})
}

func (h *Handler) getServiceOwnership(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	ownershipID, err := uuid.Parse(c.Param("oid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ownership ID"})
		return
	}

	var o ServiceOwnership
	var tags []string

	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, service_name, team_name, team_email, team_slack_channel,
		       team_slack_webhook, primary_contact_id, secondary_contact_id,
		       primary_contact_email, secondary_contact_email,
		       description, repository_url, documentation_url, oncall_url,
		       tags, status, created_at, updated_at
		FROM service_ownership
		WHERE id = $1 AND org_id = $2
	`, ownershipID, orgID).Scan(
		&o.ID, &o.OrgID, &o.ServiceName, &o.TeamName, &o.TeamEmail, &o.TeamSlackChannel,
		&o.TeamSlackWebhook, &o.PrimaryContactID, &o.SecondaryContactID,
		&o.PrimaryContactEmail, &o.SecondaryContactEmail,
		&o.Description, &o.RepositoryURL, &o.DocumentationURL, &o.OncallURL,
		&tags, &o.Status, &o.CreatedAt, &o.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "service ownership not found"})
		return
	}
	if err != nil {
		h.logger.Error("failed to get service ownership", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get service ownership"})
		return
	}

	o.Tags = tags
	c.JSON(http.StatusOK, o)
}

func (h *Handler) createServiceOwnership(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CreateServiceOwnershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	status := "active"
	if req.Status != nil {
		status = *req.Status
	}

	var ownershipID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO service_ownership (
			org_id, service_name, team_name, team_email, team_slack_channel,
			team_slack_webhook, primary_contact_email, secondary_contact_email,
			description, repository_url, documentation_url, oncall_url,
			tags, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`, orgID, req.ServiceName, req.TeamName, req.TeamEmail, req.TeamSlackChannel,
		req.TeamSlackWebhook, req.PrimaryContactEmail, req.SecondaryContactEmail,
		req.Description, req.RepositoryURL, req.DocumentationURL, req.OncallURL,
		req.Tags, status,
	).Scan(&ownershipID)

	if err != nil {
		h.logger.Error("failed to create service ownership", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create service ownership"})
		return
	}

	h.logger.Info("service ownership created",
		zap.String("id", ownershipID.String()),
		zap.String("service", req.ServiceName),
		zap.String("team", req.TeamName),
	)

	c.JSON(http.StatusCreated, gin.H{"id": ownershipID, "message": "service ownership created"})
}

func (h *Handler) updateServiceOwnership(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	ownershipID, err := uuid.Parse(c.Param("oid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ownership ID"})
		return
	}

	var req CreateServiceOwnershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	status := "active"
	if req.Status != nil {
		status = *req.Status
	}

	result, err := h.db.Exec(c.Request.Context(), `
		UPDATE service_ownership
		SET team_name = $1, team_email = $2, team_slack_channel = $3,
		    team_slack_webhook = $4, primary_contact_email = $5, secondary_contact_email = $6,
		    description = $7, repository_url = $8, documentation_url = $9, oncall_url = $10,
		    tags = $11, status = $12, updated_at = NOW()
		WHERE id = $13 AND org_id = $14
	`, req.TeamName, req.TeamEmail, req.TeamSlackChannel,
		req.TeamSlackWebhook, req.PrimaryContactEmail, req.SecondaryContactEmail,
		req.Description, req.RepositoryURL, req.DocumentationURL, req.OncallURL,
		req.Tags, status, ownershipID, orgID,
	)

	if err != nil {
		h.logger.Error("failed to update service ownership", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update service ownership"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "service ownership not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "service ownership updated"})
}

func (h *Handler) deleteServiceOwnership(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	ownershipID, err := uuid.Parse(c.Param("oid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ownership ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM service_ownership WHERE id = $1 AND org_id = $2
	`, ownershipID, orgID)

	if err != nil {
		h.logger.Error("failed to delete service ownership", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete service ownership"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "service ownership not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "service ownership deleted"})
}

// ==================== Team Handlers ====================

func (h *Handler) listTeams(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	activeOnly := c.Query("active") == "true"

	query := `
		SELECT id, org_id, name, display_name, email, slack_channel, slack_webhook,
		       pagerduty_integration_key, description, manager_id, tags, active,
		       created_at, updated_at
		FROM teams
		WHERE org_id = $1
	`
	args := []interface{}{orgID}

	if activeOnly {
		query += ` AND active = true`
	}

	query += ` ORDER BY name`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to list teams", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list teams"})
		return
	}
	defer rows.Close()

	var teams []Team
	for rows.Next() {
		var t Team
		var tags []string

		err := rows.Scan(
			&t.ID, &t.OrgID, &t.Name, &t.DisplayName, &t.Email, &t.SlackChannel,
			&t.SlackWebhook, &t.PagerDutyIntegrationKey, &t.Description, &t.ManagerID,
			&tags, &t.Active, &t.CreatedAt, &t.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan team", zap.Error(err))
			continue
		}
		t.Tags = tags
		teams = append(teams, t)
	}

	c.JSON(http.StatusOK, gin.H{
		"teams": teams,
		"count": len(teams),
	})
}

func (h *Handler) createTeam(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CreateTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var teamID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO teams (
			org_id, name, display_name, email, slack_channel, slack_webhook,
			pagerduty_integration_key, description, tags
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`, orgID, req.Name, req.DisplayName, req.Email, req.SlackChannel,
		req.SlackWebhook, req.PagerDutyIntegrationKey, req.Description, req.Tags,
	).Scan(&teamID)

	if err != nil {
		h.logger.Error("failed to create team", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create team"})
		return
	}

	h.logger.Info("team created",
		zap.String("id", teamID.String()),
		zap.String("name", req.Name),
	)

	c.JSON(http.StatusCreated, gin.H{"id": teamID, "message": "team created"})
}

func (h *Handler) updateTeam(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	teamID, err := uuid.Parse(c.Param("tid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid team ID"})
		return
	}

	var req CreateTeamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		UPDATE teams
		SET display_name = $1, email = $2, slack_channel = $3, slack_webhook = $4,
		    pagerduty_integration_key = $5, description = $6, tags = $7, updated_at = NOW()
		WHERE id = $8 AND org_id = $9
	`, req.DisplayName, req.Email, req.SlackChannel, req.SlackWebhook,
		req.PagerDutyIntegrationKey, req.Description, req.Tags, teamID, orgID,
	)

	if err != nil {
		h.logger.Error("failed to update team", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update team"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "team not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "team updated"})
}

func (h *Handler) deleteTeam(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	teamID, err := uuid.Parse(c.Param("tid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid team ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM teams WHERE id = $1 AND org_id = $2
	`, teamID, orgID)

	if err != nil {
		h.logger.Error("failed to delete team", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete team"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "team not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "team deleted"})
}

// ==================== Helper Functions ====================

// GetServiceOwner retrieves ownership info for a service (used by other handlers)
func (h *Handler) GetServiceOwner(orgID uuid.UUID, serviceName string) (*ServiceOwnership, error) {
	var o ServiceOwnership
	var tags []string

	err := h.db.QueryRow(context.Background(), `
		SELECT id, org_id, service_name, team_name, team_email, team_slack_channel,
		       team_slack_webhook, primary_contact_id, secondary_contact_id,
		       primary_contact_email, secondary_contact_email,
		       description, repository_url, documentation_url, oncall_url,
		       tags, status, created_at, updated_at
		FROM service_ownership
		WHERE org_id = $1 AND service_name = $2 AND status = 'active'
	`, orgID, serviceName).Scan(
		&o.ID, &o.OrgID, &o.ServiceName, &o.TeamName, &o.TeamEmail, &o.TeamSlackChannel,
		&o.TeamSlackWebhook, &o.PrimaryContactID, &o.SecondaryContactID,
		&o.PrimaryContactEmail, &o.SecondaryContactEmail,
		&o.Description, &o.RepositoryURL, &o.DocumentationURL, &o.OncallURL,
		&tags, &o.Status, &o.CreatedAt, &o.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	o.Tags = tags
	return &o, nil
}
