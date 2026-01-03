package api

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/infrapilot/backend/internal/enterprise/policy"
)

// ContainerResponse represents a container in the API response
type ContainerResponse struct {
	ID          string   `json:"id"`
	ContainerID string   `json:"container_id"`
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Status      string   `json:"status"`
	State       string   `json:"state"`
	StackName   string   `json:"stack_name,omitempty"`
	CPUPercent  float64  `json:"cpu_percent"`
	MemoryMB    int64    `json:"memory_mb"`
	Networks    []string `json:"networks"`
	CreatedAt   string   `json:"created_at"`
}

// listContainersReal fetches containers from Docker daemon
// NOTE: This is for local development only. In production, this should
// query the database which is populated by the agent via gRPC.
func (h *Handler) listContainersReal(c *gin.Context) {
	// agentID := c.Param("id") // Would use this to route to correct agent

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Connect to local Docker daemon
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker: " + err.Error()})
		return
	}
	defer cli.Close()

	// List all containers (including stopped)
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list containers: " + err.Error()})
		return
	}

	// Convert to response format
	result := make([]ContainerResponse, 0, len(containers))
	for _, ctr := range containers {
		name := ""
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}

		// Determine status
		status := "unknown"
		if ctr.State == "running" {
			status = "running"
		} else if ctr.State == "exited" {
			status = "exited"
		} else if ctr.State == "paused" {
			status = "paused"
		} else {
			status = ctr.State
		}

		// Get stack name from labels (docker-compose)
		stackName := ""
		if project, ok := ctr.Labels["com.docker.compose.project"]; ok {
			stackName = project
		}

		// Get network names
		networks := make([]string, 0)
		for netName := range ctr.NetworkSettings.Networks {
			networks = append(networks, netName)
		}

		result = append(result, ContainerResponse{
			ID:          ctr.ID,
			ContainerID: ctr.ID,
			Name:        name,
			Image:       ctr.Image,
			Status:      status,
			State:       ctr.State,
			StackName:   stackName,
			CPUPercent:  0, // Would need stats API for real values
			MemoryMB:    0, // Would need stats API for real values
			Networks:    networks,
			CreatedAt:   time.Unix(ctr.Created, 0).Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, result)
}

// getDockerClient creates a Docker client for local development
func getDockerClient() (*client.Client, error) {
	return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
}

// evaluateContainerPolicy checks policies before container actions
func (h *Handler) evaluateContainerPolicy(c *gin.Context, containerID string, action string) (bool, string) {
	// Get org ID from context
	orgIDVal, exists := c.Get("org_id")
	if !exists {
		// No org context, skip policy evaluation
		return false, ""
	}
	orgID, ok := orgIDVal.(uuid.UUID)
	if !ok {
		return false, ""
	}

	// Get container details for policy evaluation
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	cli, err := getDockerClient()
	if err != nil {
		return false, ""
	}
	defer cli.Close()

	inspect, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return false, ""
	}

	// Build resource for policy evaluation
	resource := policy.Resource{
		Type: "container",
		ID:   containerID,
		Attributes: map[string]interface{}{
			"name":       strings.TrimPrefix(inspect.Name, "/"),
			"image":      inspect.Config.Image,
			"user":       inspect.Config.User,
			"privileged": inspect.HostConfig.Privileged,
			"action":     action,
			"state":      inspect.State.Status,
			"labels":     inspect.Config.Labels,
		},
	}

	// Evaluate policies
	evaluator := policy.NewEvaluator(h.db, h.logger)
	blocked, message, err := evaluator.EvaluateAndBlock(ctx, orgID, resource)
	if err != nil {
		h.logger.Warn("Policy evaluation failed",
			// Log but don't block on evaluation errors
		)
		return false, ""
	}

	return blocked, message
}

// startContainerReal starts a Docker container
func (h *Handler) startContainerReal(c *gin.Context) {
	containerID := c.Param("cid")

	// Check policies before action
	if blocked, message := h.evaluateContainerPolicy(c, containerID, "start"); blocked {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "Action blocked by policy",
			"message": message,
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	cli, err := getDockerClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer cli.Close()

	if err := cli.ContainerStart(ctx, containerID, container.StartOptions{}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start container: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "container started", "container_id": containerID})
}

// stopContainerReal stops a Docker container
func (h *Handler) stopContainerReal(c *gin.Context) {
	containerID := c.Param("cid")

	// Check policies before action
	if blocked, message := h.evaluateContainerPolicy(c, containerID, "stop"); blocked {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "Action blocked by policy",
			"message": message,
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	cli, err := getDockerClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer cli.Close()

	timeout := 10 // seconds
	if err := cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to stop container: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "container stopped", "container_id": containerID})
}

// restartContainerReal restarts a Docker container
func (h *Handler) restartContainerReal(c *gin.Context) {
	containerID := c.Param("cid")

	// Check policies before action
	if blocked, message := h.evaluateContainerPolicy(c, containerID, "restart"); blocked {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "Action blocked by policy",
			"message": message,
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	cli, err := getDockerClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer cli.Close()

	timeout := 10 // seconds
	if err := cli.ContainerRestart(ctx, containerID, container.StopOptions{Timeout: &timeout}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to restart container: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "container restarted", "container_id": containerID})
}

// getContainerLogsReal fetches logs from a Docker container
func (h *Handler) getContainerLogsReal(c *gin.Context) {
	containerID := c.Param("cid")

	// Query params
	tail := c.DefaultQuery("tail", "100")
	since := c.DefaultQuery("since", "")
	timestamps := c.DefaultQuery("timestamps", "true")

	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	cli, err := getDockerClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer cli.Close()

	showTimestamps, _ := strconv.ParseBool(timestamps)

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       tail,
		Timestamps: showTimestamps,
	}
	if since != "" {
		options.Since = since
	}

	reader, err := cli.ContainerLogs(ctx, containerID, options)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get container logs: " + err.Error()})
		return
	}
	defer reader.Close()

	// Read logs
	logs, err := io.ReadAll(reader)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read logs: " + err.Error()})
		return
	}

	// Return as JSON with the raw log content
	c.JSON(http.StatusOK, gin.H{
		"container_id": containerID,
		"logs":         string(logs),
	})
}

// getContainerReal fetches details for a single container
func (h *Handler) getContainerReal(c *gin.Context) {
	containerID := c.Param("cid")

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	cli, err := getDockerClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer cli.Close()

	info, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "container not found: " + err.Error()})
		return
	}

	// Get network names
	networks := make([]string, 0)
	for netName := range info.NetworkSettings.Networks {
		networks = append(networks, netName)
	}

	// Get stack name
	stackName := ""
	if project, ok := info.Config.Labels["com.docker.compose.project"]; ok {
		stackName = project
	}

	response := ContainerResponse{
		ID:          info.ID,
		ContainerID: info.ID,
		Name:        strings.TrimPrefix(info.Name, "/"),
		Image:       info.Config.Image,
		Status:      info.State.Status,
		State:       info.State.Status,
		StackName:   stackName,
		Networks:    networks,
		CreatedAt:   info.Created,
	}

	c.JSON(http.StatusOK, response)
}

// StackResponse represents a docker-compose stack
type StackResponse struct {
	Name          string              `json:"name"`
	ContainerCount int                `json:"container_count"`
	RunningCount  int                 `json:"running_count"`
	Status        string              `json:"status"`
	Containers    []ContainerResponse `json:"containers"`
}

// listStacksReal fetches docker-compose stacks from Docker daemon
func (h *Handler) listStacksReal(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	cli, err := getDockerClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer cli.Close()

	// List all containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list containers: " + err.Error()})
		return
	}

	// Group containers by stack (compose project)
	stackMap := make(map[string]*StackResponse)

	for _, ctr := range containers {
		stackName := ""
		if project, ok := ctr.Labels["com.docker.compose.project"]; ok {
			stackName = project
		}

		// Skip containers not part of a compose stack
		if stackName == "" {
			continue
		}

		// Create stack entry if not exists
		if _, exists := stackMap[stackName]; !exists {
			stackMap[stackName] = &StackResponse{
				Name:       stackName,
				Containers: make([]ContainerResponse, 0),
			}
		}

		stack := stackMap[stackName]

		// Convert container to response format
		name := ""
		if len(ctr.Names) > 0 {
			name = strings.TrimPrefix(ctr.Names[0], "/")
		}

		status := ctr.State
		if ctr.State == "running" {
			stack.RunningCount++
		}

		// Get network names
		networks := make([]string, 0)
		for netName := range ctr.NetworkSettings.Networks {
			networks = append(networks, netName)
		}

		stack.Containers = append(stack.Containers, ContainerResponse{
			ID:          ctr.ID,
			ContainerID: ctr.ID,
			Name:        name,
			Image:       ctr.Image,
			Status:      status,
			State:       ctr.State,
			StackName:   stackName,
			Networks:    networks,
			CreatedAt:   time.Unix(ctr.Created, 0).Format(time.RFC3339),
		})

		stack.ContainerCount = len(stack.Containers)
	}

	// Convert map to slice and determine stack status
	result := make([]StackResponse, 0, len(stackMap))
	for _, stack := range stackMap {
		if stack.RunningCount == stack.ContainerCount {
			stack.Status = "running"
		} else if stack.RunningCount > 0 {
			stack.Status = "partial"
		} else {
			stack.Status = "stopped"
		}
		result = append(result, *stack)
	}

	c.JSON(http.StatusOK, result)
}
