package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
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
	// Also support "lines" param from frontend
	if t := c.Query("lines"); t != "" {
		if parsed, err := strconv.Atoi(t); err == nil && parsed > 0 {
			tail = parsed
		}
	}
	if tail > 500 {
		tail = 500
	}

	logType := c.DefaultQuery("type", "access") // access or error
	domain := c.Query("domain")

	// Check if running in all-in-one mode (nginx running locally, not in a container)
	// by checking if local nginx log file exists
	var localLogFile string
	if domain != "" {
		if logType == "error" {
			localLogFile = fmt.Sprintf("/var/log/nginx/domains/%s.error.log", domain)
		} else {
			localLogFile = fmt.Sprintf("/var/log/nginx/domains/%s.access.log", domain)
		}
	} else {
		if logType == "error" {
			localLogFile = "/var/log/nginx/error.log"
		} else {
			localLogFile = "/var/log/nginx/access.log"
		}
	}

	// Try to read from local filesystem first (all-in-one mode)
	if _, err := os.Stat(localLogFile); err == nil {
		h.logger.Debug("Reading nginx logs from local filesystem (all-in-one mode)",
			zap.String("file", localLogFile))

		logs, err := h.getNginxLogsFromLocalFile(localLogFile, logType, tail)
		if err != nil {
			h.logger.Error("Failed to read local nginx logs", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read logs"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"logs":  logs,
			"type":  logType,
			"count": len(logs),
		})
		return
	}

	// Fall back to Docker container mode
	// Create Docker client
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		h.logger.Error("Failed to connect to Docker", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to connect to Docker"})
		return
	}
	defer docker.Close()

	ctx := context.Background()

	// Find nginx container - prefer "infrapilot" container over dev containers
	containers, err := docker.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		h.logger.Error("Failed to list containers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list containers"})
		return
	}

	var nginxContainerID string
	var nginxContainerName string
	for _, cont := range containers {
		for _, name := range cont.Names {
			// Skip dev nginx containers when looking for production nginx
			if strings.Contains(name, "infrapilot-nginx") || strings.Contains(name, "-dev-") {
				continue
			}
			if strings.Contains(name, "nginx") || strings.Contains(name, "infrapilot") {
				nginxContainerID = cont.ID
				nginxContainerName = strings.TrimPrefix(name, "/")
				break
			}
		}
		if nginxContainerID != "" {
			break
		}
	}

	// If no production nginx found, try any nginx container
	if nginxContainerID == "" {
		for _, cont := range containers {
			for _, name := range cont.Names {
				if strings.Contains(name, "nginx") {
					nginxContainerID = cont.ID
					nginxContainerName = strings.TrimPrefix(name, "/")
					break
				}
			}
			if nginxContainerID != "" {
				break
			}
		}
	}

	if nginxContainerID == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "nginx container not found"})
		return
	}

	h.logger.Debug("Found nginx container", zap.String("id", nginxContainerID), zap.String("name", nginxContainerName))

	// Support per-domain log files if domain is specified
	var logs []LogEntry

	if domain != "" {
		// Use per-domain log file via exec tail
		var logFile string
		if logType == "error" {
			logFile = fmt.Sprintf("/var/log/nginx/domains/%s.error.log", domain)
		} else {
			logFile = fmt.Sprintf("/var/log/nginx/domains/%s.access.log", domain)
		}

		logs, err = h.getNginxLogsFromFile(ctx, docker, nginxContainerID, logFile, logType, tail)
		if err != nil {
			h.logger.Warn("Failed to get per-domain logs, trying container logs",
				zap.String("domain", domain),
				zap.Error(err))
			// Fall back to container logs
			logs, err = h.getNginxLogsFromContainer(ctx, docker, nginxContainerID, logType, tail)
			if err != nil {
				h.logger.Error("Failed to get container logs", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get logs"})
				return
			}
		}
	} else {
		// For global logs, try reading from log file first (if nginx writes to files)
		// Then fall back to Docker container logs API (if logs are symlinked to stdout/stderr)
		var logFile string
		if logType == "error" {
			logFile = "/var/log/nginx/error.log"
		} else {
			logFile = "/var/log/nginx/access.log"
		}

		h.logger.Info("Attempting to read nginx logs from file",
			zap.String("file", logFile),
			zap.String("container", nginxContainerID),
		)

		logs, err = h.getNginxLogsFromFile(ctx, docker, nginxContainerID, logFile, logType, tail)
		if err != nil {
			h.logger.Info("Failed to get logs from file, trying container logs",
				zap.String("file", logFile),
				zap.Error(err))
			// Fall back to container logs
			logs, err = h.getNginxLogsFromContainer(ctx, docker, nginxContainerID, logType, tail)
			if err != nil {
				h.logger.Error("Failed to get container logs", zap.Error(err))
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get logs"})
				return
			}
		} else {
			h.logger.Info("Successfully read logs from file",
				zap.String("file", logFile),
				zap.Int("count", len(logs)))
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"type":  logType,
		"count": len(logs),
	})
}

// getNginxLogsFromContainer gets logs using Docker container logs API
func (h *Handler) getNginxLogsFromContainer(ctx context.Context, docker *client.Client, containerID, logType string, tail int) ([]LogEntry, error) {
	opts := container.LogsOptions{
		ShowStdout: logType == "access",
		ShowStderr: logType == "error",
		Tail:       strconv.Itoa(tail),
		Timestamps: true,
	}

	reader, err := docker.ContainerLogs(ctx, containerID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}
	defer reader.Close()

	var logs []LogEntry
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var msg []byte
		// Check for Docker multiplexed stream header
		if len(line) > 8 && (line[0] == 1 || line[0] == 2) {
			msg = line[8:]
		} else {
			msg = line
		}

		msgStr := string(msg)
		timestamp := time.Now()

		// Parse timestamp if present (format: 2006-01-02T15:04:05.999999999Z)
		if len(msgStr) > 30 && msgStr[4] == '-' {
			if t, err := time.Parse(time.RFC3339Nano, msgStr[:30]); err == nil {
				timestamp = t
				msgStr = strings.TrimSpace(msgStr[31:])
			}
		}

		entry := LogEntry{
			Timestamp:     timestamp,
			Source:        "nginx",
			ContainerName: "nginx",
			Stream:        logType,
			Level:         "info",
			Message:       msgStr,
		}

		// Detect log level
		if logType == "access" {
			if strings.Contains(msgStr, "\" 4") || strings.Contains(msgStr, "\" 5") {
				entry.Level = "warn"
			}
		} else {
			if strings.Contains(msgStr, "[error]") || strings.Contains(msgStr, "[emerg]") {
				entry.Level = "error"
			} else if strings.Contains(msgStr, "[warn]") {
				entry.Level = "warn"
			}
		}

		logs = append(logs, entry)
	}

	return logs, nil
}

// getNginxLogsFromFile gets logs from a specific file using exec tail
func (h *Handler) getNginxLogsFromFile(ctx context.Context, docker *client.Client, containerID, logFile, logType string, tail int) ([]LogEntry, error) {
	// First check if file exists
	checkConfig := container.ExecOptions{
		Cmd:          []string{"test", "-f", logFile},
		AttachStdout: true,
		AttachStderr: true,
	}

	checkResp, err := docker.ContainerExecCreate(ctx, containerID, checkConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create check exec: %w", err)
	}

	if err := docker.ContainerExecStart(ctx, checkResp.ID, container.ExecStartOptions{}); err != nil {
		return nil, fmt.Errorf("failed to start check exec: %w", err)
	}

	// Wait for exec to complete and check exit code
	inspect, err := docker.ContainerExecInspect(ctx, checkResp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect check exec: %w", err)
	}

	if inspect.ExitCode != 0 {
		return nil, fmt.Errorf("log file does not exist: %s", logFile)
	}

	// Now tail the file
	execConfig := container.ExecOptions{
		Cmd:          []string{"tail", "-n", strconv.Itoa(tail), logFile},
		AttachStdout: true,
		AttachStderr: true,
	}

	execResp, err := docker.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %w", err)
	}

	attachResp, err := docker.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach exec: %w", err)
	}
	defer attachResp.Close()

	// Demultiplex the Docker stream properly
	var stdout, stderr bytes.Buffer
	_, err = stdcopy.StdCopy(&stdout, &stderr, attachResp.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read exec output: %w", err)
	}

	var logs []LogEntry
	scanner := bufio.NewScanner(&stdout)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		entry := LogEntry{
			Timestamp:     time.Now(),
			Source:        "nginx",
			ContainerName: "nginx",
			Stream:        logType,
			Level:         "info",
			Message:       line,
		}

		// Detect log level
		if logType == "access" {
			if strings.Contains(line, "\" 4") || strings.Contains(line, "\" 5") {
				entry.Level = "warn"
			}
		} else {
			if strings.Contains(line, "[error]") || strings.Contains(line, "[emerg]") {
				entry.Level = "error"
			} else if strings.Contains(line, "[warn]") {
				entry.Level = "warn"
			}
		}

		logs = append(logs, entry)
	}

	h.logger.Debug("Read logs from file",
		zap.String("file", logFile),
		zap.Int("count", len(logs)),
		zap.Int("stdout_bytes", stdout.Len()),
		zap.Int("stderr_bytes", stderr.Len()),
	)

	return logs, nil
}

// getNginxLogsFromLocalFile reads nginx logs directly from the local filesystem
// This is used in all-in-one mode where nginx runs in the same container as the backend
func (h *Handler) getNginxLogsFromLocalFile(logFile, logType string, tail int) ([]LogEntry, error) {
	file, err := os.Open(logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// Read all lines then take the last N (tail)
	var allLines []string
	scanner := bufio.NewScanner(file)
	// Increase buffer size for long log lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			allLines = append(allLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read log file: %w", err)
	}

	// Get the last N lines
	startIdx := 0
	if len(allLines) > tail {
		startIdx = len(allLines) - tail
	}
	tailLines := allLines[startIdx:]

	var logs []LogEntry
	for _, line := range tailLines {
		entry := LogEntry{
			Timestamp:     time.Now(),
			Source:        "nginx",
			ContainerName: "nginx-local",
			Stream:        logType,
			Level:         "info",
			Message:       line,
		}

		// Parse nginx log format to extract timestamp and level
		if logType == "access" {
			// Try to parse timestamp from nginx combined log format
			// Format: 192.168.1.1 - - [02/Jan/2006:15:04:05 +0000] "GET / HTTP/1.1" 200 ...
			if idx := strings.Index(line, "["); idx != -1 {
				if endIdx := strings.Index(line[idx:], "]"); endIdx != -1 {
					timeStr := line[idx+1 : idx+endIdx]
					// Parse nginx time format: 02/Jan/2006:15:04:05 +0000
					if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timeStr); err == nil {
						entry.Timestamp = t
					}
				}
			}
			// Detect error status codes (4xx, 5xx)
			if strings.Contains(line, "\" 4") || strings.Contains(line, "\" 5") {
				entry.Level = "warn"
			}
		} else {
			// Error log format: 2006/01/02 15:04:05 [error] ...
			if len(line) >= 19 {
				timeStr := line[:19]
				if t, err := time.Parse("2006/01/02 15:04:05", timeStr); err == nil {
					entry.Timestamp = t
				}
			}
			// Detect log level from nginx error log
			if strings.Contains(line, "[error]") || strings.Contains(line, "[emerg]") || strings.Contains(line, "[crit]") {
				entry.Level = "error"
			} else if strings.Contains(line, "[warn]") {
				entry.Level = "warn"
			}
		}

		logs = append(logs, entry)
	}

	h.logger.Debug("Read logs from local file",
		zap.String("file", logFile),
		zap.Int("total_lines", len(allLines)),
		zap.Int("returned", len(logs)),
	)

	return logs, nil
}
