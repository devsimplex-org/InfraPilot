package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	agentgrpc "github.com/infrapilot/backend/internal/grpc"
)

// ============ Types ============

// NetworkInfo represents Docker network info from agent
type NetworkInfo struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	Internal   bool              `json:"internal"`
	Containers map[string]string `json:"containers"`
}

// ContainerNetworkInfo represents a container's network membership
type ContainerNetworkInfo struct {
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name"`
	IPAddress   string `json:"ip_address"`
}

// NginxNetworkAttachment represents a tracked network attachment
type NginxNetworkAttachment struct {
	ID           uuid.UUID  `json:"id"`
	AgentID      uuid.UUID  `json:"agent_id"`
	NetworkID    string     `json:"network_id"`
	NetworkName  string     `json:"network_name"`
	AttachedAt   time.Time  `json:"attached_at"`
	AttachedBy   *uuid.UUID `json:"attached_by,omitempty"`
	Status       string     `json:"status"`
	ErrorMessage *string    `json:"error_message,omitempty"`
}

// AttachNetworkRequest is the request body for attaching nginx to a network
type AttachNetworkRequest struct {
	NetworkID string `json:"network_id" binding:"required"`
}

// DetachNetworkRequest is the request body for detaching nginx from a network
type DetachNetworkRequest struct {
	NetworkID string `json:"network_id" binding:"required"`
}

// NetworkCheckResponse represents the result of checking nginx network connection
type NetworkCheckResponse struct {
	Connected   bool   `json:"connected"`
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name,omitempty"`
}

// ============ Handlers ============

// listNetworks returns all Docker networks available on the agent
// GET /api/v1/agents/:id/networks
func (h *Handler) listNetworks(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Verify agent belongs to organization
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)`,
		agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	h.logger.Info("Listing networks for agent",
		zap.String("agent_id", agentID.String()),
	)

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Send gRPC command to agent
	cmdPayload, _ := json.Marshal(agentgrpc.NetworkCommand{
		Action: agentgrpc.NetworkActionListNetworks,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "network",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to list networks", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list networks"})
		return
	}

	// Parse response
	if result, err := resp.GetCommandResult(); err == nil && result != nil && result.Success {
		var networks []NetworkInfo
		if err := json.Unmarshal(result.Data, &networks); err == nil {
			c.JSON(http.StatusOK, networks)
			return
		}
	}

	c.JSON(http.StatusOK, []NetworkInfo{})
}

// getContainerNetworks returns networks a specific container is connected to
// GET /api/v1/agents/:id/containers/:cid/networks
func (h *Handler) getContainerNetworks(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	containerID := c.Param("cid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Verify agent belongs to organization
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)`,
		agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	h.logger.Info("Getting container networks",
		zap.String("agent_id", agentID.String()),
		zap.String("container_id", containerID),
	)

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Send gRPC command to agent
	cmdPayload, _ := json.Marshal(agentgrpc.NetworkCommand{
		Action:      agentgrpc.NetworkActionGetContainerNetworks,
		ContainerID: containerID,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "network",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to get container networks", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get container networks"})
		return
	}

	// Parse response
	if result, err := resp.GetCommandResult(); err == nil && result != nil && result.Success {
		var networks []ContainerNetworkInfo
		if err := json.Unmarshal(result.Data, &networks); err == nil {
			c.JSON(http.StatusOK, networks)
			return
		}
	}

	c.JSON(http.StatusOK, []ContainerNetworkInfo{})
}

// checkNginxNetwork checks if nginx is connected to a specific network
// GET /api/v1/agents/:id/networks/:nid/check-nginx
func (h *Handler) checkNginxNetwork(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	networkID := c.Param("nid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Verify agent belongs to organization
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)`,
		agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	h.logger.Info("Checking nginx network connection",
		zap.String("agent_id", agentID.String()),
		zap.String("network_id", networkID),
	)

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Send gRPC command to agent
	cmdPayload, _ := json.Marshal(agentgrpc.NetworkCommand{
		Action:    agentgrpc.NetworkActionCheckNginxNetwork,
		NetworkID: networkID,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "network",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to check nginx network", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check network"})
		return
	}

	// Parse response
	response := NetworkCheckResponse{
		Connected: false,
		NetworkID: networkID,
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		response.Connected = result.Success
	}

	c.JSON(http.StatusOK, response)
}

// listNginxNetworkAttachments returns all networks attached by InfraPilot
// GET /api/v1/agents/:id/networks/attachments
func (h *Handler) listNginxNetworkAttachments(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Verify agent belongs to organization
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)`,
		agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	// Query nginx network attachments
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, agent_id, network_id, network_name, attached_at, attached_by, status, error_message
		FROM nginx_network_attachments
		WHERE agent_id = $1 AND status = 'attached'
		ORDER BY attached_at DESC
	`, agentID)
	if err != nil {
		h.logger.Error("Failed to query network attachments", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query attachments"})
		return
	}
	defer rows.Close()

	attachments := []NginxNetworkAttachment{}
	for rows.Next() {
		var a NginxNetworkAttachment
		err := rows.Scan(&a.ID, &a.AgentID, &a.NetworkID, &a.NetworkName, &a.AttachedAt, &a.AttachedBy, &a.Status, &a.ErrorMessage)
		if err != nil {
			h.logger.Error("Failed to scan attachment", zap.Error(err))
			continue
		}
		attachments = append(attachments, a)
	}

	c.JSON(http.StatusOK, attachments)
}

// attachNginxNetwork attaches nginx to a Docker network
// POST /api/v1/agents/:id/networks/attach
func (h *Handler) attachNginxNetwork(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var req AttachNetworkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify agent belongs to organization
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)`,
		agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	// Check if already attached in our records
	var existingID uuid.UUID
	var networkName string
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT id, network_name FROM nginx_network_attachments WHERE agent_id = $1 AND network_id = $2 AND status = 'attached'`,
		agentID, req.NetworkID).Scan(&existingID, &networkName)
	if err == nil {
		// Already attached - return success instead of error
		c.JSON(http.StatusOK, gin.H{
			"success":      true,
			"network_id":   req.NetworkID,
			"network_name": networkName,
			"message":      "nginx is already attached to this network",
		})
		return
	}

	h.logger.Info("Attaching nginx to network",
		zap.String("agent_id", agentID.String()),
		zap.String("network_id", req.NetworkID),
		zap.String("user_id", userID.String()),
	)

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Send gRPC command to agent
	cmdPayload, _ := json.Marshal(agentgrpc.NetworkCommand{
		Action:    agentgrpc.NetworkActionAttachNginxNetwork,
		NetworkID: req.NetworkID,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "network",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to attach network", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to attach network"})
		return
	}

	// Check response
	var attachResult agentgrpc.NetworkAttachResult
	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}
		json.Unmarshal(result.Data, &attachResult)
	}

	resultNetworkName := attachResult.NetworkName
	if resultNetworkName == "" {
		resultNetworkName = req.NetworkID
	}
	var attachmentID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO nginx_network_attachments (agent_id, network_id, network_name, attached_by, status)
		VALUES ($1, $2, $3, $4, 'attached')
		RETURNING id
	`, agentID, req.NetworkID, resultNetworkName, userID).Scan(&attachmentID)
	if err != nil {
		h.logger.Error("Failed to record network attachment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record attachment"})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "network.attach", "nginx_network", attachmentID, map[string]string{
		"network_id":   req.NetworkID,
		"network_name": resultNetworkName,
	})

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"id":           attachmentID,
		"network_id":   req.NetworkID,
		"network_name": resultNetworkName,
	})
}

// detachNginxNetwork detaches nginx from a Docker network
// POST /api/v1/agents/:id/networks/detach
func (h *Handler) detachNginxNetwork(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var req DetachNetworkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify agent belongs to organization
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)`,
		agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	h.logger.Info("Detaching nginx from network",
		zap.String("agent_id", agentID.String()),
		zap.String("network_id", req.NetworkID),
		zap.String("user_id", userID.String()),
	)

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Send gRPC command to agent
	cmdPayload, _ := json.Marshal(agentgrpc.NetworkCommand{
		Action:    agentgrpc.NetworkActionDetachNginxNetwork,
		NetworkID: req.NetworkID,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "network",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to detach network", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to detach network"})
		return
	}

	// Check response
	if result, err := resp.GetCommandResult(); err == nil && result != nil && !result.Success {
		c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
		return
	}

	// Update the attachment record
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE nginx_network_attachments
		SET status = 'detached', updated_at = NOW()
		WHERE agent_id = $1 AND network_id = $2 AND status = 'attached'
	`, agentID, req.NetworkID)
	if err != nil {
		h.logger.Error("Failed to update network attachment", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update attachment"})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "network.detach", "nginx_network", uuid.Nil, map[string]string{
		"network_id": req.NetworkID,
	})

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"network_id": req.NetworkID,
	})
}

