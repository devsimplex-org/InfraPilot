package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TrafficResourceSummary struct {
	OrgID               uuid.UUID `json:"org_id"`
	TotalResources      int       `json:"total_resources"`
	ActiveResources     int       `json:"active_resources"`
	DraftResources      int       `json:"draft_resources"`
	ErrorResources      int       `json:"error_resources"`
	SystemGateways      int       `json:"system_gateways"`
	ApplicationGateways int       `json:"application_gateways"`
	AgentsWithTraffic   int       `json:"agents_with_traffic"`
}

// GET /api/v1/traffic/summary
func (h *Handler) getTrafficSummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `SELECT * FROM v_traffic_resource_summary WHERE org_id = $1`

	var summary TrafficResourceSummary
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&summary.OrgID, &summary.TotalResources, &summary.ActiveResources,
		&summary.DraftResources, &summary.ErrorResources,
		&summary.SystemGateways, &summary.ApplicationGateways,
		&summary.AgentsWithTraffic,
	)

	if err == pgx.ErrNoRows {
		summary = TrafficResourceSummary{OrgID: orgID}
	} else if err != nil {
		h.logger.Error("Failed to fetch traffic summary: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch traffic summary"})
		return
	}

	c.JSON(http.StatusOK, summary)
}
