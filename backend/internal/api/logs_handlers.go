package api

import (
	"bufio"
	"context"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// LogEntry represents a unified log entry
type LogEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	Source        string    `json:"source"`
	ContainerID   string    `json:"container_id,omitempty"`
	ContainerName string    `json:"container_name,omitempty"`
	Stream        string    `json:"stream"` // stdout, stderr, access, error
	Level         string    `json:"level"`  // info, warn, error, debug
	Message       string    `json:"message"`
}

// UnifiedLogsRequest represents query parameters for log fetching
type UnifiedLogsRequest struct {
	Sources    []string `form:"sources"`    // container names or "nginx"
	Levels     []string `form:"levels"`     // info, warn, error, debug
	Search     string   `form:"search"`     // text search
	Since      string   `form:"since"`      // time range start
	Until      string   `form:"until"`      // time range end
	Tail       int      `form:"tail"`       // number of lines
	Containers []string `form:"containers"` // specific container IDs
}

// getUnifiedLogsReal returns aggregated logs from multiple sources
func (h *Handler) getUnifiedLogsReal(c *gin.Context) {
	var req UnifiedLogsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default tail to 200 lines
	if req.Tail == 0 {
		req.Tail = 200
	}
	if req.Tail > 1000 {
		req.Tail = 1000
	}

	// Create Docker client
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		h.logger.Error("Failed to connect to Docker", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer docker.Close()

	ctx := context.Background()

	// Get containers to fetch logs from
	containers, err := docker.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		h.logger.Error("Failed to list containers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list containers"})
		return
	}

	var allLogs []LogEntry

	// Filter containers if specific ones requested
	for _, cont := range containers {
		name := ""
		if len(cont.Names) > 0 {
			name = strings.TrimPrefix(cont.Names[0], "/")
		}

		// Skip if specific containers requested and this isn't one
		if len(req.Containers) > 0 {
			found := false
			for _, c := range req.Containers {
				if c == cont.ID[:12] || c == name {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Skip if specific sources requested and this isn't one
		if len(req.Sources) > 0 {
			found := false
			for _, s := range req.Sources {
				if s == name || s == "all" {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Get logs for this container
		logs, err := h.getContainerLogEntries(ctx, docker, cont.ID, name, req)
		if err != nil {
			h.logger.Warn("Failed to get logs for container",
				zap.String("container", name),
				zap.Error(err))
			continue
		}
		allLogs = append(allLogs, logs...)
	}

	// Sort by timestamp descending
	sort.Slice(allLogs, func(i, j int) bool {
		return allLogs[i].Timestamp.After(allLogs[j].Timestamp)
	})

	// Apply tail limit
	if len(allLogs) > req.Tail {
		allLogs = allLogs[:req.Tail]
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  allLogs,
		"count": len(allLogs),
	})
}

func (h *Handler) getContainerLogEntries(ctx context.Context, docker *client.Client, containerID, containerName string, req UnifiedLogsRequest) ([]LogEntry, error) {
	opts := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: true,
		Tail:       strconv.Itoa(req.Tail),
	}

	if req.Since != "" {
		opts.Since = req.Since
	}
	if req.Until != "" {
		opts.Until = req.Until
	}

	logs, err := docker.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return nil, err
	}
	defer logs.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(logs)

	// Docker log format: [8-byte header][timestamp] message
	// For TTY containers, no header
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var stream string
		var msg []byte

		// Check for Docker multiplexed stream header
		if len(line) > 8 && (line[0] == 1 || line[0] == 2) {
			if line[0] == 1 {
				stream = "stdout"
			} else {
				stream = "stderr"
			}
			msg = line[8:]
		} else {
			stream = "stdout"
			msg = line
		}

		// Parse timestamp if present
		msgStr := string(msg)
		timestamp := time.Now()
		if len(msgStr) > 30 && msgStr[4] == '-' {
			// Try to parse RFC3339 timestamp
			if t, err := time.Parse(time.RFC3339Nano, msgStr[:30]); err == nil {
				timestamp = t
				msgStr = strings.TrimSpace(msgStr[31:])
			}
		}

		// Detect log level
		level := detectLogLevel(msgStr)

		// Apply level filter
		if len(req.Levels) > 0 {
			found := false
			for _, l := range req.Levels {
				if l == level {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Apply search filter
		if req.Search != "" {
			if !strings.Contains(strings.ToLower(msgStr), strings.ToLower(req.Search)) {
				continue
			}
		}

		entries = append(entries, LogEntry{
			Timestamp:     timestamp,
			Source:        "container",
			ContainerID:   containerID[:12],
			ContainerName: containerName,
			Stream:        stream,
			Level:         level,
			Message:       msgStr,
		})
	}

	return entries, nil
}

// detectLogLevel attempts to detect the log level from the message
func detectLogLevel(msg string) string {
	lower := strings.ToLower(msg)

	// Check for common log level patterns
	errorPatterns := []string{"error", "err ", "fatal", "panic", "exception", "failed", "failure"}
	warnPatterns := []string{"warn", "warning", "caution"}
	debugPatterns := []string{"debug", "trace", "verbose"}

	for _, p := range errorPatterns {
		if strings.Contains(lower, p) {
			return "error"
		}
	}
	for _, p := range warnPatterns {
		if strings.Contains(lower, p) {
			return "warn"
		}
	}
	for _, p := range debugPatterns {
		if strings.Contains(lower, p) {
			return "debug"
		}
	}

	return "info"
}

// streamUnifiedLogs streams logs from multiple containers via WebSocket
func (h *Handler) streamUnifiedLogs(c *gin.Context) {
	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket", zap.Error(err))
		return
	}
	defer conn.Close()

	// Parse query params
	sources := c.QueryArray("sources")
	levels := c.QueryArray("levels")
	search := c.Query("search")

	h.logger.Info("Starting unified log stream",
		zap.Strings("sources", sources),
		zap.Strings("levels", levels))

	// Create Docker client
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		h.sendWSError(conn, "Failed to connect to Docker")
		return
	}
	defer docker.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get containers
	containers, err := docker.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		h.sendWSError(conn, "Failed to list containers")
		return
	}

	// Start log streaming for each container
	for _, cont := range containers {
		name := ""
		if len(cont.Names) > 0 {
			name = strings.TrimPrefix(cont.Names[0], "/")
		}

		// Filter by sources if specified
		if len(sources) > 0 {
			found := false
			for _, s := range sources {
				if s == name || s == "all" {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		go h.streamContainerToWS(ctx, docker, conn, cont.ID, name, levels, search)
	}

	// Handle WebSocket close
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			cancel()
			return
		}
	}
}

func (h *Handler) streamContainerToWS(ctx context.Context, docker *client.Client, conn *websocket.Conn, containerID, containerName string, levels []string, search string) {
	logs, err := docker.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "10",
		Timestamps: true,
	})
	if err != nil {
		return
	}
	defer logs.Close()

	scanner := bufio.NewScanner(logs)
	searchRegex, _ := regexp.Compile("(?i)" + regexp.QuoteMeta(search))

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var stream string
		var msg []byte

		if len(line) > 8 && (line[0] == 1 || line[0] == 2) {
			if line[0] == 1 {
				stream = "stdout"
			} else {
				stream = "stderr"
			}
			msg = line[8:]
		} else {
			stream = "stdout"
			msg = line
		}

		msgStr := string(msg)
		timestamp := time.Now()
		if len(msgStr) > 30 && msgStr[4] == '-' {
			if t, err := time.Parse(time.RFC3339Nano, msgStr[:30]); err == nil {
				timestamp = t
				msgStr = strings.TrimSpace(msgStr[31:])
			}
		}

		level := detectLogLevel(msgStr)

		// Apply filters
		if len(levels) > 0 {
			found := false
			for _, l := range levels {
				if l == level {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if search != "" && !searchRegex.MatchString(msgStr) {
			continue
		}

		entry := LogEntry{
			Timestamp:     timestamp,
			Source:        "container",
			ContainerID:   containerID[:12],
			ContainerName: containerName,
			Stream:        stream,
			Level:         level,
			Message:       msgStr,
		}

		if err := conn.WriteJSON(entry); err != nil {
			return
		}
	}
}

// getNginxLogsReal returns nginx access and error logs
func (h *Handler) getNginxLogsReal(c *gin.Context) {
	tail := 100
	if t := c.Query("tail"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 {
			tail = parsed
		}
	}
	if tail > 500 {
		tail = 500
	}

	logType := c.DefaultQuery("type", "access") // access or error

	// Create Docker client
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		h.logger.Error("Failed to connect to Docker", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer docker.Close()

	ctx := context.Background()

	// Find nginx container
	containers, err := docker.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list containers"})
		return
	}

	var nginxContainerID string
	for _, cont := range containers {
		for _, name := range cont.Names {
			if strings.Contains(name, "nginx") {
				nginxContainerID = cont.ID
				break
			}
		}
		if nginxContainerID != "" {
			break
		}
	}

	if nginxContainerID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "nginx container not found"})
		return
	}

	// Execute command to read log file
	logFile := "/var/log/nginx/access.log"
	if logType == "error" {
		logFile = "/var/log/nginx/error.log"
	}

	execConfig := container.ExecOptions{
		Cmd:          []string{"tail", "-n", strconv.Itoa(tail), logFile},
		AttachStdout: true,
		AttachStderr: true,
	}

	execResp, err := docker.ContainerExecCreate(ctx, nginxContainerID, execConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create exec"})
		return
	}

	attachResp, err := docker.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to attach exec"})
		return
	}
	defer attachResp.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(attachResp.Reader)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		// Skip Docker header if present
		if len(line) > 8 && (line[0] == 1 || line[0] == 2) {
			line = line[8:]
		}

		entry := LogEntry{
			Timestamp:     time.Now(),
			Source:        "nginx",
			ContainerName: "nginx",
			Stream:        logType,
			Level:         "info",
			Message:       line,
		}

		// Parse nginx log format for better data
		if logType == "access" {
			entry.Level = "info"
			// Check for error status codes
			if strings.Contains(line, "\" 4") || strings.Contains(line, "\" 5") {
				entry.Level = "warn"
			}
		} else {
			// Error log level detection
			if strings.Contains(line, "[error]") {
				entry.Level = "error"
			} else if strings.Contains(line, "[warn]") {
				entry.Level = "warn"
			} else if strings.Contains(line, "[notice]") {
				entry.Level = "info"
			}
		}

		logs = append(logs, entry)
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"type":  logType,
		"count": len(logs),
	})
}
