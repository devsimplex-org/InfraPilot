package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID           uuid.UUID              `json:"id"`
	OrgID        *uuid.UUID             `json:"org_id,omitempty"`
	UserID       *uuid.UUID             `json:"user_id,omitempty"`
	UserEmail    *string                `json:"user_email,omitempty"`
	AgentID      *uuid.UUID             `json:"agent_id,omitempty"`
	AgentName    *string                `json:"agent_name,omitempty"`
	Action       string                 `json:"action"`
	ResourceType *string                `json:"resource_type,omitempty"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty"`
	IPAddress    *string                `json:"ip_address,omitempty"`
	UserAgent    *string                `json:"user_agent,omitempty"`
	RequestBody  map[string]interface{} `json:"request_body,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// getAuditLogsReal returns audit logs for the organization
func (h *Handler) getAuditLogsReal(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Parse query params
	limit := 100
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	offset := 0
	if o := c.Query("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	action := c.Query("action")
	resourceType := c.Query("resource_type")
	userID := c.Query("user_id")

	// Build query
	query := `
		SELECT
			al.id, al.org_id, al.user_id, u.email, al.agent_id, a.name,
			al.action, al.resource_type, al.resource_id,
			al.ip_address::text, al.user_agent, al.request_body, al.created_at
		FROM audit_logs al
		LEFT JOIN users u ON al.user_id = u.id
		LEFT JOIN agents a ON al.agent_id = a.id
		WHERE al.org_id = $1
	`
	args := []interface{}{orgID}
	argNum := 2

	if action != "" {
		query += ` AND al.action = $` + strconv.Itoa(argNum)
		args = append(args, action)
		argNum++
	}

	if resourceType != "" {
		query += ` AND al.resource_type = $` + strconv.Itoa(argNum)
		args = append(args, resourceType)
		argNum++
	}

	if userID != "" {
		if uid, err := uuid.Parse(userID); err == nil {
			query += ` AND al.user_id = $` + strconv.Itoa(argNum)
			args = append(args, uid)
			argNum++
		}
	}

	query += ` ORDER BY al.created_at DESC LIMIT $` + strconv.Itoa(argNum) + ` OFFSET $` + strconv.Itoa(argNum+1)
	args = append(args, limit, offset)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to get audit logs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get audit logs"})
		return
	}
	defer rows.Close()

	var logs []AuditLogEntry
	for rows.Next() {
		var entry AuditLogEntry
		var requestBody []byte
		if err := rows.Scan(
			&entry.ID, &entry.OrgID, &entry.UserID, &entry.UserEmail,
			&entry.AgentID, &entry.AgentName, &entry.Action, &entry.ResourceType,
			&entry.ResourceID, &entry.IPAddress, &entry.UserAgent, &requestBody,
			&entry.CreatedAt,
		); err != nil {
			continue
		}
		if len(requestBody) > 0 {
			// Parse JSON but don't fail if it doesn't work
			_ = json.Unmarshal(requestBody, &entry.RequestBody)
		}
		logs = append(logs, entry)
	}

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE org_id = $1`
	h.db.QueryRow(c.Request.Context(), countQuery, orgID).Scan(&total)

	c.JSON(http.StatusOK, gin.H{
		"logs":   logs,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// logAuditEvent records an audit log entry
func (h *Handler) logAuditEvent(c *gin.Context, action, resourceType string, resourceID *uuid.UUID, requestBody interface{}) {
	orgID, _ := c.Get("org_id")
	userID, _ := c.Get("user_id")

	var orgUUID, userUUID *uuid.UUID
	if o, ok := orgID.(uuid.UUID); ok {
		orgUUID = &o
	}
	if u, ok := userID.(uuid.UUID); ok {
		userUUID = &u
	}

	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	var bodyJSON []byte
	if requestBody != nil {
		bodyJSON, _ = json.Marshal(requestBody)
	}

	_, err := h.db.Exec(c.Request.Context(), `
		INSERT INTO audit_logs (org_id, user_id, action, resource_type, resource_id, ip_address, user_agent, request_body)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, orgUUID, userUUID, action, resourceType, resourceID, ipAddress, userAgent, bodyJSON)

	if err != nil {
		h.logger.Warn("Failed to record audit log", zap.Error(err))
	}
}
