package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	agentgrpc "github.com/infrapilot/backend/internal/grpc"
	"github.com/infrapilot/backend/internal/registry"
)

// ============ Docker Resource Types ============

// NetworkDetailInfo represents detailed Docker network information
type NetworkDetailInfo struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Driver     string                     `json:"driver"`
	Scope      string                     `json:"scope"`
	Internal   bool                       `json:"internal"`
	Attachable bool                       `json:"attachable"`
	IPAM       NetworkIPAMConfig          `json:"ipam"`
	Containers map[string]NetworkEndpoint `json:"containers"`
	Options    map[string]string          `json:"options"`
	Labels     map[string]string          `json:"labels"`
	CreatedAt  string                     `json:"created_at"`
}

// NetworkIPAMConfig represents IPAM configuration
type NetworkIPAMConfig struct {
	Driver  string           `json:"driver"`
	Configs []IPAMPoolConfig `json:"configs"`
}

// IPAMPoolConfig represents a single IPAM pool configuration
type IPAMPoolConfig struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
	IPRange string `json:"ip_range,omitempty"`
}

// NetworkEndpoint represents a container endpoint on a network
type NetworkEndpoint struct {
	Name        string `json:"name"`
	EndpointID  string `json:"endpoint_id"`
	MacAddress  string `json:"mac_address"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address,omitempty"`
}

// CreateNetworkRequest is the request body for creating a network
type CreateNetworkRequest struct {
	Name       string            `json:"name" binding:"required"`
	Driver     string            `json:"driver"`
	Internal   bool              `json:"internal"`
	Attachable bool              `json:"attachable"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// VolumeInfo represents Docker volume information
type VolumeInfo struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	Scope      string            `json:"scope"`
	Labels     map[string]string `json:"labels"`
	CreatedAt  string            `json:"created_at"`
	UsedBy     []string          `json:"used_by"`
}

// CreateVolumeRequest is the request body for creating a volume
type CreateVolumeRequest struct {
	Name       string            `json:"name" binding:"required"`
	Driver     string            `json:"driver"`
	DriverOpts map[string]string `json:"driver_opts,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ImageInfo represents Docker image information
type ImageInfo struct {
	ID          string   `json:"id"`
	Tags        []string `json:"tags"`
	Size        int64    `json:"size"`
	SizeMB      int64    `json:"size_mb"`
	Created     string   `json:"created"`
	RepoDigests []string `json:"repo_digests"`
	UsedBy      []string `json:"used_by"`
}

// PullImageRequest is the request body for pulling an image
type PullImageRequest struct {
	Image      string  `json:"image" binding:"required"`
	RegistryID *string `json:"registry_id,omitempty"`
}

// DockerAuthConfig represents authentication for Docker registry operations
type DockerAuthConfig struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	ServerAddress string `json:"server_address,omitempty"`
}

// ============ Network Handlers ============

// listDockerNetworks returns all Docker networks with full details
// GET /api/v1/agents/:id/docker/networks
func (h *Handler) listDockerNetworks(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Verify agent belongs to organization
	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Listing Docker networks",
		zap.String("agent_id", agentID.String()),
	)

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Use the existing network list command
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

	if result, err := resp.GetCommandResult(); err == nil && result != nil && result.Success {
		var networks []NetworkInfo
		if err := json.Unmarshal(result.Data, &networks); err == nil {
			c.JSON(http.StatusOK, networks)
			return
		}
	}

	c.JSON(http.StatusOK, []NetworkInfo{})
}

// inspectDockerNetwork returns detailed information about a specific network
// GET /api/v1/agents/:id/docker/networks/:nid
func (h *Handler) inspectDockerNetwork(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	networkID := c.Param("nid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Inspecting Docker network",
		zap.String("agent_id", agentID.String()),
		zap.String("network_id", networkID),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:    agentgrpc.DockerActionInspectNetwork,
		NetworkID: networkID,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to inspect network", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to inspect network"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}
		var network NetworkDetailInfo
		if err := json.Unmarshal(result.Data, &network); err == nil {
			c.JSON(http.StatusOK, network)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "network not found"})
}

// createDockerNetwork creates a new Docker network
// POST /api/v1/agents/:id/docker/networks
func (h *Handler) createDockerNetwork(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var req CreateNetworkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Creating Docker network",
		zap.String("agent_id", agentID.String()),
		zap.String("name", req.Name),
		zap.String("user_id", userID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	options := map[string]interface{}{
		"name":       req.Name,
		"driver":     req.Driver,
		"internal":   req.Internal,
		"attachable": req.Attachable,
	}
	if req.Labels != nil {
		options["labels"] = req.Labels
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:  agentgrpc.DockerActionCreateNetwork,
		Options: options,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to create network", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create network"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}
		var network NetworkInfo
		json.Unmarshal(result.Data, &network)

		// Audit log
		h.auditLog(c, userID, orgID, "docker.network.create", "docker_network", uuid.Nil, map[string]string{
			"name":   req.Name,
			"driver": req.Driver,
		})

		c.JSON(http.StatusCreated, network)
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected response"})
}

// deleteDockerNetwork removes a Docker network
// DELETE /api/v1/agents/:id/docker/networks/:nid
func (h *Handler) deleteDockerNetwork(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	networkID := c.Param("nid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	force := c.Query("force") == "true"

	h.logger.Info("Deleting Docker network",
		zap.String("agent_id", agentID.String()),
		zap.String("network_id", networkID),
		zap.Bool("force", force),
		zap.String("user_id", userID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:    agentgrpc.DockerActionDeleteNetwork,
		NetworkID: networkID,
		Force:     force,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to delete network", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete network"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}

		// Audit log
		h.auditLog(c, userID, orgID, "docker.network.delete", "docker_network", uuid.Nil, map[string]string{
			"network_id": networkID,
		})

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "network deleted"})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected response"})
}

// ============ Volume Handlers ============

// listDockerVolumes returns all Docker volumes
// GET /api/v1/agents/:id/docker/volumes
func (h *Handler) listDockerVolumes(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Listing Docker volumes",
		zap.String("agent_id", agentID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action: agentgrpc.DockerActionListVolumes,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to list volumes", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list volumes"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil && result.Success {
		var volumes []VolumeInfo
		if err := json.Unmarshal(result.Data, &volumes); err == nil {
			c.JSON(http.StatusOK, volumes)
			return
		}
	}

	c.JSON(http.StatusOK, []VolumeInfo{})
}

// inspectDockerVolume returns detailed information about a specific volume
// GET /api/v1/agents/:id/docker/volumes/:name
func (h *Handler) inspectDockerVolume(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	volumeName := c.Param("name")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Inspecting Docker volume",
		zap.String("agent_id", agentID.String()),
		zap.String("volume_name", volumeName),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:     agentgrpc.DockerActionInspectVolume,
		VolumeName: volumeName,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to inspect volume", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to inspect volume"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}
		var volume VolumeInfo
		if err := json.Unmarshal(result.Data, &volume); err == nil {
			c.JSON(http.StatusOK, volume)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "volume not found"})
}

// createDockerVolume creates a new Docker volume
// POST /api/v1/agents/:id/docker/volumes
func (h *Handler) createDockerVolume(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var req CreateVolumeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Creating Docker volume",
		zap.String("agent_id", agentID.String()),
		zap.String("name", req.Name),
		zap.String("user_id", userID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	options := map[string]interface{}{
		"name":   req.Name,
		"driver": req.Driver,
	}
	if req.DriverOpts != nil {
		options["driver_opts"] = req.DriverOpts
	}
	if req.Labels != nil {
		options["labels"] = req.Labels
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:  agentgrpc.DockerActionCreateVolume,
		Options: options,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to create volume", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create volume"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}
		var volume VolumeInfo
		json.Unmarshal(result.Data, &volume)

		// Audit log
		h.auditLog(c, userID, orgID, "docker.volume.create", "docker_volume", uuid.Nil, map[string]string{
			"name":   req.Name,
			"driver": req.Driver,
		})

		c.JSON(http.StatusCreated, volume)
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected response"})
}

// deleteDockerVolume removes a Docker volume
// DELETE /api/v1/agents/:id/docker/volumes/:name
func (h *Handler) deleteDockerVolume(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	volumeName := c.Param("name")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	force := c.Query("force") == "true"

	h.logger.Info("Deleting Docker volume",
		zap.String("agent_id", agentID.String()),
		zap.String("volume_name", volumeName),
		zap.Bool("force", force),
		zap.String("user_id", userID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:     agentgrpc.DockerActionDeleteVolume,
		VolumeName: volumeName,
		Force:      force,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to delete volume", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete volume"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}

		// Audit log
		h.auditLog(c, userID, orgID, "docker.volume.delete", "docker_volume", uuid.Nil, map[string]string{
			"volume_name": volumeName,
		})

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "volume deleted"})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected response"})
}

// ============ Image Handlers ============

// listDockerImages returns all Docker images
// GET /api/v1/agents/:id/docker/images
func (h *Handler) listDockerImages(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Listing Docker images",
		zap.String("agent_id", agentID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action: agentgrpc.DockerActionListImages,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to list images", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list images"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil && result.Success {
		var images []ImageInfo
		if err := json.Unmarshal(result.Data, &images); err == nil {
			c.JSON(http.StatusOK, images)
			return
		}
	}

	c.JSON(http.StatusOK, []ImageInfo{})
}

// inspectDockerImage returns detailed information about a specific image
// GET /api/v1/agents/:id/docker/images/:imgid
func (h *Handler) inspectDockerImage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	imageID := c.Param("imgid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Inspecting Docker image",
		zap.String("agent_id", agentID.String()),
		zap.String("image_id", imageID),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:  agentgrpc.DockerActionInspectImage,
		ImageID: imageID,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to inspect image", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to inspect image"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}
		var image ImageInfo
		if err := json.Unmarshal(result.Data, &image); err == nil {
			c.JSON(http.StatusOK, image)
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{"error": "image not found"})
}

// pullDockerImage pulls a Docker image from a registry
// POST /api/v1/agents/:id/docker/images/pull
func (h *Handler) pullDockerImage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var req PullImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	h.logger.Info("Pulling Docker image",
		zap.String("agent_id", agentID.String()),
		zap.String("image", req.Image),
		zap.String("user_id", userID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Build auth config if registry ID is provided
	var authConfig *agentgrpc.DockerAuthConfig
	if req.RegistryID != nil && *req.RegistryID != "" {
		registryID, err := uuid.Parse(*req.RegistryID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registry ID"})
			return
		}

		// Get registry and decrypt credentials
		authConfig, err = h.buildAuthConfigFromRegistry(c.Request.Context(), orgID, registryID)
		if err != nil {
			h.logger.Warn("Failed to build auth config from registry",
				zap.String("registry_id", registryID.String()),
				zap.Error(err),
			)
			// Continue without auth - the pull might still work for public images
		}
	}

	dockerCmd := agentgrpc.DockerResourceCommand{
		Action:   agentgrpc.DockerActionPullImage,
		ImageRef: req.Image,
	}
	if authConfig != nil {
		dockerCmd.AuthConfig = authConfig
	}

	cmdPayload, _ := json.Marshal(dockerCmd)
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	// Use longer timeout for image pulls
	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 5*time.Minute)
	if err != nil {
		h.logger.Error("Failed to pull image", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to pull image"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}

		// Audit log
		h.auditLog(c, userID, orgID, "docker.image.pull", "docker_image", uuid.Nil, map[string]string{
			"image": req.Image,
		})

		c.JSON(http.StatusOK, gin.H{"success": true, "message": result.Message})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected response"})
}

// buildAuthConfigFromRegistry looks up a registry by ID and builds Docker auth config
func (h *Handler) buildAuthConfigFromRegistry(ctx context.Context, orgID, registryID uuid.UUID) (*agentgrpc.DockerAuthConfig, error) {
	reg, err := h.registryService.GetRegistry(ctx, orgID, registryID)
	if err != nil {
		return nil, err
	}

	// Decrypt credentials
	creds, err := h.registryService.GetDecryptedCredentials(ctx, orgID, registryID)
	if err != nil {
		return nil, err
	}

	// Build auth config based on provider
	authConfig := &agentgrpc.DockerAuthConfig{}

	switch reg.Provider {
	case registry.ProviderGHCR:
		// GHCR uses token-based auth with username as placeholder
		authConfig.Username = "oauth2accesstoken"
		authConfig.Password = creds.Token
		authConfig.ServerAddress = "ghcr.io"

	case registry.ProviderDockerHub:
		authConfig.Username = creds.Username
		authConfig.Password = creds.Password
		authConfig.ServerAddress = "https://index.docker.io/v1/"

	case registry.ProviderECR:
		// ECR would need AWS SDK to get temporary credentials
		// For now, return nil as ECR auth is more complex
		return nil, nil

	case registry.ProviderGCR:
		// GCR uses service account JSON as password
		authConfig.Username = "_json_key"
		authConfig.Password = creds.GCPServiceAccountJSON
		authConfig.ServerAddress = "gcr.io"

	case registry.ProviderACR:
		// ACR uses service principal
		authConfig.Username = creds.AzureClientID
		authConfig.Password = creds.AzureClientSecret
		if creds.AzureRegistryName != "" {
			authConfig.ServerAddress = creds.AzureRegistryName + ".azurecr.io"
		}

	default:
		return nil, nil
	}

	return authConfig, nil
}

// deleteDockerImage removes a Docker image
// DELETE /api/v1/agents/:id/docker/images/:imgid
func (h *Handler) deleteDockerImage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	imageID := c.Param("imgid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if !h.verifyAgentOrg(c, agentID, orgID) {
		return
	}

	force := c.Query("force") == "true"

	h.logger.Info("Deleting Docker image",
		zap.String("agent_id", agentID.String()),
		zap.String("image_id", imageID),
		zap.Bool("force", force),
		zap.String("user_id", userID.String()),
	)

	if !agentgrpc.IsAgentConnected(agentID.String()) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action:  agentgrpc.DockerActionDeleteImage,
		ImageID: imageID,
		Force:   force,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 30*time.Second)
	if err != nil {
		h.logger.Error("Failed to delete image", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete image"})
		return
	}

	if result, err := resp.GetCommandResult(); err == nil && result != nil {
		if !result.Success {
			c.JSON(http.StatusBadRequest, gin.H{"error": result.Message})
			return
		}

		// Audit log
		h.auditLog(c, userID, orgID, "docker.image.delete", "docker_image", uuid.Nil, map[string]string{
			"image_id": imageID,
		})

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "image deleted"})
		return
	}

	c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected response"})
}

// ============ Helper Functions ============

// verifyAgentOrg checks if an agent belongs to the organization
func (h *Handler) verifyAgentOrg(c *gin.Context, agentID, orgID uuid.UUID) bool {
	var exists bool
	err := h.db.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND org_id = $2)`,
		agentID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return false
	}
	return true
}
