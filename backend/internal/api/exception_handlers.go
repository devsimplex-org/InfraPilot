package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==================== Types ====================

type ExceptionStatus string
type ExceptionScopeType string

const (
	ExceptionStatusPending  ExceptionStatus = "pending"
	ExceptionStatusApproved ExceptionStatus = "approved"
	ExceptionStatusDenied   ExceptionStatus = "denied"
	ExceptionStatusExpired  ExceptionStatus = "expired"
	ExceptionStatusRevoked  ExceptionStatus = "revoked"

	ScopeTypeCVE        ExceptionScopeType = "cve"
	ScopeTypePolicyRule ExceptionScopeType = "policy_rule"
	ScopeTypeDeployment ExceptionScopeType = "deployment"
	ScopeTypePackage    ExceptionScopeType = "package"
	ScopeTypeImage      ExceptionScopeType = "image"
)

type RiskException struct {
	ID             uuid.UUID          `json:"id"`
	OrgID          uuid.UUID          `json:"org_id"`
	ScopeType      ExceptionScopeType `json:"scope_type"`
	ScopeReference string             `json:"scope_reference"`
	DeploymentID   *uuid.UUID         `json:"deployment_id,omitempty"`
	ScanResultID   *uuid.UUID         `json:"scan_result_id,omitempty"`
	RequestedBy    uuid.UUID          `json:"requested_by"`
	Justification  string             `json:"justification"`
	BusinessImpact *string            `json:"business_impact,omitempty"`
	MitigationPlan *string            `json:"mitigation_plan,omitempty"`
	Status         ExceptionStatus    `json:"status"`
	ApprovedBy     *uuid.UUID         `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time         `json:"approved_at,omitempty"`
	DenialReason   *string            `json:"denial_reason,omitempty"`
	ExpiresAt      time.Time          `json:"expires_at"`
	AutoRenewed    bool               `json:"auto_renewed"`
	RenewalCount   int                `json:"renewal_count"`
	RevokedAt      *time.Time         `json:"revoked_at,omitempty"`
	RevokedBy      *uuid.UUID         `json:"revoked_by,omitempty"`
	RevokedReason  *string            `json:"revoked_reason,omitempty"`
	Tags           []string           `json:"tags,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
	UpdatedAt      time.Time          `json:"updated_at"`
}

type CreateExceptionRequest struct {
	ScopeType      string  `json:"scope_type" binding:"required,oneof=cve policy_rule deployment package image"`
	ScopeReference string  `json:"scope_reference" binding:"required"`
	DeploymentID   *string `json:"deployment_id,omitempty"`
	ScanResultID   *string `json:"scan_result_id,omitempty"`
	Justification  string  `json:"justification" binding:"required,min=50"`
	BusinessImpact string  `json:"business_impact,omitempty"`
	MitigationPlan string  `json:"mitigation_plan,omitempty"`
	DurationDays   int     `json:"duration_days" binding:"required,min=1,max=365"`
	Tags           []string `json:"tags,omitempty"`
}

type ApproveExceptionRequest struct {
	Comment *string `json:"comment,omitempty"`
}

type DenyExceptionRequest struct {
	Reason string `json:"reason" binding:"required"`
}

type RevokeExceptionRequest struct {
	Reason string `json:"reason" binding:"required"`
}

type ExceptionListResponse struct {
	Exceptions []RiskException `json:"exceptions"`
	Count      int             `json:"count"`
}

// ==================== List Exceptions ====================

func (h *Handler) listExceptions(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Filters
	scopeType := c.Query("scope_type")
	status := c.Query("status")
	scopeRef := c.Query("scope_reference")

	query := `
		SELECT id, org_id, scope_type, scope_reference, deployment_id, scan_result_id,
		       requested_by, justification, business_impact, mitigation_plan,
		       status, approved_by, approved_at, denial_reason,
		       expires_at, auto_renewed, renewal_count,
		       revoked_at, revoked_by, revoked_reason, tags,
		       created_at, updated_at
		FROM risk_exceptions
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	if scopeType != "" {
		query += ` AND scope_type = $` + string(rune(argIdx))
		args = append(args, scopeType)
		argIdx++
	}

	if status != "" {
		query += ` AND status = $` + string(rune(argIdx))
		args = append(args, status)
		argIdx++
	}

	if scopeRef != "" {
		query += ` AND scope_reference ILIKE $` + string(rune(argIdx))
		args = append(args, "%"+scopeRef+"%")
		argIdx++
	}

	query += ` ORDER BY created_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to list exceptions", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list exceptions"})
		return
	}
	defer rows.Close()

	var exceptions []RiskException
	for rows.Next() {
		var ex RiskException
		var tags []string

		err := rows.Scan(
			&ex.ID, &ex.OrgID, &ex.ScopeType, &ex.ScopeReference, &ex.DeploymentID, &ex.ScanResultID,
			&ex.RequestedBy, &ex.Justification, &ex.BusinessImpact, &ex.MitigationPlan,
			&ex.Status, &ex.ApprovedBy, &ex.ApprovedAt, &ex.DenialReason,
			&ex.ExpiresAt, &ex.AutoRenewed, &ex.RenewalCount,
			&ex.RevokedAt, &ex.RevokedBy, &ex.RevokedReason, &tags,
			&ex.CreatedAt, &ex.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan exception", zap.Error(err))
			continue
		}
		ex.Tags = tags
		exceptions = append(exceptions, ex)
	}

	c.JSON(http.StatusOK, ExceptionListResponse{
		Exceptions: exceptions,
		Count:      len(exceptions),
	})
}

// ==================== Get Exception ====================

func (h *Handler) getException(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	exceptionID, err := uuid.Parse(c.Param("eid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exception ID"})
		return
	}

	var ex RiskException
	var tags []string

	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, scope_type, scope_reference, deployment_id, scan_result_id,
		       requested_by, justification, business_impact, mitigation_plan,
		       status, approved_by, approved_at, denial_reason,
		       expires_at, auto_renewed, renewal_count,
		       revoked_at, revoked_by, revoked_reason, tags,
		       created_at, updated_at
		FROM risk_exceptions
		WHERE id = $1 AND org_id = $2
	`, exceptionID, orgID).Scan(
		&ex.ID, &ex.OrgID, &ex.ScopeType, &ex.ScopeReference, &ex.DeploymentID, &ex.ScanResultID,
		&ex.RequestedBy, &ex.Justification, &ex.BusinessImpact, &ex.MitigationPlan,
		&ex.Status, &ex.ApprovedBy, &ex.ApprovedAt, &ex.DenialReason,
		&ex.ExpiresAt, &ex.AutoRenewed, &ex.RenewalCount,
		&ex.RevokedAt, &ex.RevokedBy, &ex.RevokedReason, &tags,
		&ex.CreatedAt, &ex.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "exception not found"})
		return
	}
	if err != nil {
		h.logger.Error("failed to get exception", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get exception"})
		return
	}

	ex.Tags = tags
	c.JSON(http.StatusOK, ex)
}

// ==================== Create Exception ====================

func (h *Handler) createException(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req CreateExceptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Calculate expiry date
	expiresAt := time.Now().AddDate(0, 0, req.DurationDays)

	// Parse optional UUIDs
	var deploymentID, scanResultID *uuid.UUID
	if req.DeploymentID != nil {
		id, err := uuid.Parse(*req.DeploymentID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid deployment_id"})
			return
		}
		deploymentID = &id
	}
	if req.ScanResultID != nil {
		id, err := uuid.Parse(*req.ScanResultID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan_result_id"})
			return
		}
		scanResultID = &id
	}

	var exceptionID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO risk_exceptions (
			org_id, scope_type, scope_reference, deployment_id, scan_result_id,
			requested_by, justification, business_impact, mitigation_plan,
			expires_at, tags, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending')
		RETURNING id
	`, orgID, req.ScopeType, req.ScopeReference, deploymentID, scanResultID,
		userID, req.Justification, nullString(req.BusinessImpact), nullString(req.MitigationPlan),
		expiresAt, req.Tags,
	).Scan(&exceptionID)

	if err != nil {
		h.logger.Error("failed to create exception", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create exception"})
		return
	}

	// Retrieve created exception
	h.getException(c)
}

// ==================== Approve Exception ====================

func (h *Handler) approveException(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	exceptionID, err := uuid.Parse(c.Param("eid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exception ID"})
		return
	}

	var req ApproveExceptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if exception exists and is pending
	var currentStatus string
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT status FROM risk_exceptions WHERE id = $1 AND org_id = $2
	`, exceptionID, orgID).Scan(&currentStatus)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "exception not found"})
		return
	}
	if err != nil {
		h.logger.Error("failed to check exception status", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check exception"})
		return
	}

	if currentStatus != string(ExceptionStatusPending) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exception is not pending"})
		return
	}

	// Approve exception
	now := time.Now()
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE risk_exceptions
		SET status = 'approved', approved_by = $1, approved_at = $2, updated_at = $2
		WHERE id = $3 AND org_id = $4
	`, userID, now, exceptionID, orgID)

	if err != nil {
		h.logger.Error("failed to approve exception", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to approve exception"})
		return
	}

	h.logger.Info("exception approved",
		zap.String("exception_id", exceptionID.String()),
		zap.String("approved_by", userID.String()),
	)

	c.JSON(http.StatusOK, gin.H{"message": "exception approved successfully"})
}

// ==================== Deny Exception ====================

func (h *Handler) denyException(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	exceptionID, err := uuid.Parse(c.Param("eid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exception ID"})
		return
	}

	var req DenyExceptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if exception exists and is pending
	var currentStatus string
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT status FROM risk_exceptions WHERE id = $1 AND org_id = $2
	`, exceptionID, orgID).Scan(&currentStatus)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "exception not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check exception"})
		return
	}

	if currentStatus != string(ExceptionStatusPending) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exception is not pending"})
		return
	}

	// Deny exception
	now := time.Now()
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE risk_exceptions
		SET status = 'denied', approved_by = $1, approved_at = $2, denial_reason = $3, updated_at = $2
		WHERE id = $4 AND org_id = $5
	`, userID, now, req.Reason, exceptionID, orgID)

	if err != nil {
		h.logger.Error("failed to deny exception", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deny exception"})
		return
	}

	h.logger.Info("exception denied",
		zap.String("exception_id", exceptionID.String()),
		zap.String("denied_by", userID.String()),
		zap.String("reason", req.Reason),
	)

	c.JSON(http.StatusOK, gin.H{"message": "exception denied successfully"})
}

// ==================== Revoke Exception ====================

func (h *Handler) revokeException(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	exceptionID, err := uuid.Parse(c.Param("eid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exception ID"})
		return
	}

	var req RevokeExceptionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if exception exists and is approved
	var currentStatus string
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT status FROM risk_exceptions WHERE id = $1 AND org_id = $2
	`, exceptionID, orgID).Scan(&currentStatus)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "exception not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check exception"})
		return
	}

	if currentStatus != string(ExceptionStatusApproved) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only approved exceptions can be revoked"})
		return
	}

	// Revoke exception
	now := time.Now()
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE risk_exceptions
		SET status = 'revoked', revoked_by = $1, revoked_at = $2, revoked_reason = $3, updated_at = $2
		WHERE id = $4 AND org_id = $5
	`, userID, now, req.Reason, exceptionID, orgID)

	if err != nil {
		h.logger.Error("failed to revoke exception", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke exception"})
		return
	}

	h.logger.Info("exception revoked",
		zap.String("exception_id", exceptionID.String()),
		zap.String("revoked_by", userID.String()),
		zap.String("reason", req.Reason),
	)

	c.JSON(http.StatusOK, gin.H{"message": "exception revoked successfully"})
}

// ==================== Get Exception History ====================

func (h *Handler) getExceptionHistory(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	exceptionID, err := uuid.Parse(c.Param("eid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid exception ID"})
		return
	}

	// Verify exception belongs to org
	var count int
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT COUNT(*) FROM risk_exceptions WHERE id = $1 AND org_id = $2
	`, exceptionID, orgID).Scan(&count)

	if err != nil || count == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "exception not found"})
		return
	}

	// Get history
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, action, actor_id, previous_status, new_status, comment, metadata, created_at
		FROM exception_history
		WHERE exception_id = $1
		ORDER BY created_at DESC
	`, exceptionID)

	if err != nil {
		h.logger.Error("failed to get exception history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get history"})
		return
	}
	defer rows.Close()

	type HistoryEntry struct {
		ID             uuid.UUID  `json:"id"`
		Action         string     `json:"action"`
		ActorID        *uuid.UUID `json:"actor_id,omitempty"`
		PreviousStatus *string    `json:"previous_status,omitempty"`
		NewStatus      *string    `json:"new_status,omitempty"`
		Comment        *string    `json:"comment,omitempty"`
		Metadata       []byte     `json:"metadata,omitempty"`
		CreatedAt      time.Time  `json:"created_at"`
	}

	var history []HistoryEntry
	for rows.Next() {
		var entry HistoryEntry
		err := rows.Scan(
			&entry.ID, &entry.Action, &entry.ActorID,
			&entry.PreviousStatus, &entry.NewStatus,
			&entry.Comment, &entry.Metadata, &entry.CreatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan history entry", zap.Error(err))
			continue
		}
		history = append(history, entry)
	}

	c.JSON(http.StatusOK, gin.H{
		"history": history,
		"count":   len(history),
	})
}

// ==================== Helper ====================

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
