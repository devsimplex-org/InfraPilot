package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	agentgrpc "github.com/infrapilot/backend/internal/grpc"
	"github.com/infrapilot/backend/internal/scanner"
	"go.uber.org/zap"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Allow all origins in development
		// TODO: Restrict in production
		return true
	},
}

// execContainer handles WebSocket exec sessions to containers
func (h *Handler) execContainer(c *gin.Context) {
	containerId := c.Param("cid")

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket", zap.Error(err))
		return
	}
	defer conn.Close()

	h.logger.Info("WebSocket exec session started",
		zap.String("container", containerId))

	// Create Docker client
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		h.sendWSError(conn, "Failed to connect to Docker")
		return
	}
	defer docker.Close()

	ctx := context.Background()

	// Create exec instance
	execConfig := container.ExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          []string{"/bin/sh"},
	}

	execResp, err := docker.ContainerExecCreate(ctx, containerId, execConfig)
	if err != nil {
		h.logger.Error("Failed to create exec", zap.Error(err))
		h.sendWSError(conn, "Failed to create exec session: "+err.Error())
		return
	}

	// Attach to exec
	attachResp, err := docker.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		h.logger.Error("Failed to attach to exec", zap.Error(err))
		h.sendWSError(conn, "Failed to attach to exec session: "+err.Error())
		return
	}
	defer attachResp.Close()

	// Create done channel
	done := make(chan struct{})
	var once sync.Once

	// Forward Docker output to WebSocket
	go func() {
		defer once.Do(func() { close(done) })
		buf := make([]byte, 1024)
		for {
			n, err := attachResp.Reader.Read(buf)
			if err != nil {
				if err != io.EOF {
					h.logger.Debug("Docker read error", zap.Error(err))
				}
				return
			}
			if n > 0 {
				if err := conn.WriteMessage(websocket.TextMessage, buf[:n]); err != nil {
					h.logger.Debug("WebSocket write error", zap.Error(err))
					return
				}
			}
		}
	}()

	// Forward WebSocket input to Docker
	go func() {
		defer once.Do(func() { close(done) })
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					h.logger.Debug("WebSocket read error", zap.Error(err))
				}
				return
			}
			if _, err := attachResp.Conn.Write(msg); err != nil {
				h.logger.Debug("Docker write error", zap.Error(err))
				return
			}
		}
	}()

	// Keep connection alive with pings
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	// Wait for session to end
	<-done

	h.logger.Info("WebSocket exec session ended",
		zap.String("container", containerId))
}

// streamContainerLogs handles WebSocket log streaming
func (h *Handler) streamContainerLogs(c *gin.Context) {
	containerId := c.Param("cid")

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket", zap.Error(err))
		return
	}
	defer conn.Close()

	h.logger.Info("WebSocket log stream started",
		zap.String("container", containerId))

	// Create Docker client
	docker, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		h.sendWSError(conn, "Failed to connect to Docker")
		return
	}
	defer docker.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Get container logs with follow
	logs, err := docker.ContainerLogs(ctx, containerId, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "100",
		Timestamps: true,
	})
	if err != nil {
		h.logger.Error("Failed to get container logs", zap.Error(err))
		h.sendWSError(conn, "Failed to get logs: "+err.Error())
		return
	}
	defer logs.Close()

	done := make(chan struct{})

	// Forward logs to WebSocket
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := logs.Read(buf)
			if err != nil {
				if err != io.EOF {
					h.logger.Debug("Log read error", zap.Error(err))
				}
				return
			}
			if n > 0 {
				// Docker log format has 8-byte header for multiplexed streams
				// For TTY containers, no header; for non-TTY, strip header
				data := buf[:n]
				if len(data) > 8 && (data[0] == 1 || data[0] == 2) {
					// Has header, strip it
					data = data[8:]
				}
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					h.logger.Debug("WebSocket write error", zap.Error(err))
					return
				}
			}
		}
	}()

	// Handle WebSocket close
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// Keep connection alive
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()

	<-done

	h.logger.Info("WebSocket log stream ended",
		zap.String("container", containerId))
}

func (h *Handler) sendWSError(conn *websocket.Conn, msg string) {
	conn.WriteMessage(websocket.TextMessage, []byte("\x1b[31mError: "+msg+"\x1b[0m\r\n"))
}

// agentCommandStream handles WebSocket command streaming for agents
// This replaces the gRPC bidirectional stream with a WebSocket-based approach
// ==================== Scan WebSocket ====================

// ScanWSRequest represents a scan request from the frontend
type ScanWSRequest struct {
	Action string `json:"action"` // "scan", "sbom", "both"
	Images []struct {
		Image       string `json:"image"`
		ImageDigest string `json:"image_digest,omitempty"`
		ImageTag    string `json:"image_tag,omitempty"`
	} `json:"images"`
}

// ScanWSProgressMessage is sent to indicate scan progress
type ScanWSProgressMessage struct {
	Type     string `json:"type"`              // "progress"
	Image    string `json:"image"`
	Stage    string `json:"stage"`             // "queued", "pulling", "scanning", "analyzing", "complete", "error"
	Progress int    `json:"progress,omitempty"` // 0-100
	Message  string `json:"message,omitempty"`
}

// ScanWSResultMessage is sent when a scan completes
type ScanWSResultMessage struct {
	Type           string `json:"type"` // "scan_result"
	Image          string `json:"image"`
	ScanID         string `json:"scan_id"`
	CriticalCount  int    `json:"critical_count"`
	HighCount      int    `json:"high_count"`
	MediumCount    int    `json:"medium_count"`
	LowCount       int    `json:"low_count"`
	TotalCount     int    `json:"total_count"`
	FixableCount   int    `json:"fixable_count"`
	ScanDurationMs int64  `json:"scan_duration_ms,omitempty"`
}

// ScanWSSBOMResultMessage is sent when SBOM generation completes
type ScanWSSBOMResultMessage struct {
	Type            string `json:"type"` // "sbom_result"
	Image           string `json:"image"`
	SBOMID          string `json:"sbom_id"`
	TotalPackages   int    `json:"total_packages"`
	OSPackages      int    `json:"os_packages"`
	LibraryPackages int    `json:"library_packages"`
}

// ScanWSErrorMessage is sent when an error occurs
type ScanWSErrorMessage struct {
	Type  string `json:"type"` // "error"
	Image string `json:"image,omitempty"`
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// ScanWSCompleteMessage is sent when all scans are complete
type ScanWSCompleteMessage struct {
	Type        string `json:"type"` // "complete"
	TotalImages int    `json:"total_images"`
	Successful  int    `json:"successful"`
	Failed      int    `json:"failed"`
}

// scanWebSocket handles WebSocket connections for scan operations
func (h *Handler) scanWebSocket(c *gin.Context) {
	// Get org_id from context (set by auth middleware)
	orgID, exists := c.Get("org_id")
	if !exists {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket for scan", zap.Error(err))
		return
	}
	defer conn.Close()

	h.logger.Info("Scan WebSocket connection established",
		zap.String("org_id", orgID.(uuid.UUID).String()))

	// Mutex for thread-safe sending
	var sendMu sync.Mutex
	sendJSON := func(v interface{}) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return conn.WriteJSON(v)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})

	// Keep connection alive with pings
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sendMu.Lock()
				err := conn.WriteMessage(websocket.PingMessage, nil)
				sendMu.Unlock()
				if err != nil {
					cancel()
					return
				}
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Read messages from client
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				h.logger.Debug("Scan WebSocket read error", zap.Error(err))
			}
			break
		}

		var req ScanWSRequest
		if err := json.Unmarshal(message, &req); err != nil {
			sendJSON(ScanWSErrorMessage{
				Type:  "error",
				Error: "Invalid request format",
			})
			continue
		}

		// Process scan request in goroutine
		go h.processScanWSRequest(ctx, orgID.(uuid.UUID), req, sendJSON)
	}

	close(done)
	h.logger.Info("Scan WebSocket connection closed",
		zap.String("org_id", orgID.(uuid.UUID).String()))
}

// processScanWSRequest handles a scan request from WebSocket
func (h *Handler) processScanWSRequest(ctx context.Context, orgID uuid.UUID, req ScanWSRequest, send func(interface{}) error) {
	successful := 0
	failed := 0

	for _, img := range req.Images {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Send queued status
		send(ScanWSProgressMessage{
			Type:    "progress",
			Image:   img.Image,
			Stage:   "queued",
			Message: "Scan queued",
		})

		var scanErr error
		var sbomErr error

		// Run vulnerability scan
		if req.Action == "scan" || req.Action == "both" {
			// Send pulling progress
			send(ScanWSProgressMessage{
				Type:     "progress",
				Image:    img.Image,
				Stage:    "pulling",
				Progress: 10,
				Message:  "Preparing image...",
			})

			// Send scanning progress
			send(ScanWSProgressMessage{
				Type:     "progress",
				Image:    img.Image,
				Stage:    "scanning",
				Progress: 30,
				Message:  "Running Trivy vulnerability scan...",
			})

			scanResult, err := h.scanner.ScanImage(ctx, img.Image)
			if err != nil {
				h.logger.Error("Scan failed", zap.Error(err), zap.String("image", img.Image))
				send(ScanWSErrorMessage{
					Type:  "error",
					Image: img.Image,
					Error: err.Error(),
				})
				scanErr = err
			} else {
				// Send analyzing progress
				send(ScanWSProgressMessage{
					Type:     "progress",
					Image:    img.Image,
					Stage:    "analyzing",
					Progress: 80,
					Message:  "Analyzing results...",
				})

				// Use provided digest or the one from scan
				imageDigest := img.ImageDigest
				if imageDigest == "" {
					imageDigest = scanResult.ImageDigest
				}

				// Store scan result in database
				var scanID uuid.UUID
				err = h.db.QueryRow(ctx, `
					INSERT INTO scan_results (
						org_id, image_digest, image_repository, image_tag,
						critical_count, high_count, medium_count, low_count, unknown_count,
						total_count, fixable_count,
						scanner_name, scan_duration_ms, raw_output
					)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
					RETURNING id
				`, orgID, imageDigest, scanResult.ImageRepository, scanResult.ImageTag,
					scanResult.CriticalCount, scanResult.HighCount, scanResult.MediumCount,
					scanResult.LowCount, scanResult.UnknownCount,
					scanResult.TotalCount, scanResult.FixableCount,
					"trivy", scanResult.ScanDuration.Milliseconds(), scanResult.RawOutput,
				).Scan(&scanID)

				if err != nil {
					h.logger.Error("Failed to store scan result", zap.Error(err))
					send(ScanWSErrorMessage{
						Type:  "error",
						Image: img.Image,
						Error: "Failed to store scan result",
					})
					scanErr = err
				} else {
					// Store individual vulnerabilities (non-blocking)
					go func(scanID uuid.UUID, vulns []scanner.Vulnerability) {
						for _, v := range vulns {
							h.db.Exec(context.Background(), `
								INSERT INTO vulnerabilities (
									scan_result_id, cve_id, severity,
									package_name, package_version, package_type,
									fixed_version, fix_available,
									title, description, cvss_v3_score, cvss_v3_vector,
									reference_urls
								)
								VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
							`, scanID, v.CVEID, v.Severity,
								v.PackageName, v.PackageVersion, v.PackageType,
								v.FixedVersion, v.FixAvailable,
								v.Title, v.Description, v.CVSSScore, v.CVSSVector,
								v.References,
							)
						}
					}(scanID, scanResult.Vulnerabilities)

					// Send scan result
					send(ScanWSResultMessage{
						Type:           "scan_result",
						Image:          img.Image,
						ScanID:         scanID.String(),
						CriticalCount:  scanResult.CriticalCount,
						HighCount:      scanResult.HighCount,
						MediumCount:    scanResult.MediumCount,
						LowCount:       scanResult.LowCount,
						TotalCount:     scanResult.TotalCount,
						FixableCount:   scanResult.FixableCount,
						ScanDurationMs: scanResult.ScanDuration.Milliseconds(),
					})
				}
			}
		}

		// Generate SBOM
		if req.Action == "sbom" || req.Action == "both" {
			// Send SBOM progress
			send(ScanWSProgressMessage{
				Type:     "progress",
				Image:    img.Image,
				Stage:    "analyzing",
				Progress: 50,
				Message:  "Generating SBOM with Syft...",
			})

			sbomResult, err := h.sbomGenerator.GenerateSBOM(ctx, img.Image)
			if err != nil {
				h.logger.Error("SBOM generation failed", zap.Error(err), zap.String("image", img.Image))
				send(ScanWSErrorMessage{
					Type:  "error",
					Image: img.Image,
					Error: "SBOM generation failed: " + err.Error(),
				})
				sbomErr = err
			} else {
				// Store SBOM in database
				var sbomID uuid.UUID
				err = h.db.QueryRow(ctx, `
					INSERT INTO sboms (
						org_id, image_digest, image_repository,
						format, spec_version,
						total_packages, os_packages, library_packages,
						sbom_json, generator_name, generator_version
					)
					VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
					RETURNING id
				`, orgID, sbomResult.ImageDigest, sbomResult.ImageRepository,
					sbomResult.Format, sbomResult.SpecVersion,
					sbomResult.TotalPackages, sbomResult.OSPackages, sbomResult.LibraryPackages,
					sbomResult.Raw, sbomResult.GeneratorName, sbomResult.GeneratorVersion,
				).Scan(&sbomID)

				if err != nil {
					h.logger.Error("Failed to store SBOM", zap.Error(err))
					send(ScanWSErrorMessage{
						Type:  "error",
						Image: img.Image,
						Error: "Failed to store SBOM",
					})
					sbomErr = err
				} else {
					send(ScanWSSBOMResultMessage{
						Type:            "sbom_result",
						Image:           img.Image,
						SBOMID:          sbomID.String(),
						TotalPackages:   sbomResult.TotalPackages,
						OSPackages:      sbomResult.OSPackages,
						LibraryPackages: sbomResult.LibraryPackages,
					})
				}
			}
		}

		// Send complete progress for this image
		if scanErr == nil && sbomErr == nil {
			send(ScanWSProgressMessage{
				Type:     "progress",
				Image:    img.Image,
				Stage:    "complete",
				Progress: 100,
				Message:  "Scan complete",
			})
			successful++
		} else {
			// Partial success if one action succeeded
			if (req.Action == "both" && (scanErr == nil || sbomErr == nil)) {
				successful++
			} else {
				failed++
			}
		}
	}

	// Send completion message
	send(ScanWSCompleteMessage{
		Type:        "complete",
		TotalImages: len(req.Images),
		Successful:  successful,
		Failed:      failed,
	})
}

func (h *Handler) agentCommandStream(c *gin.Context) {
	agentIDStr := c.Param("id")

	// Validate agent ID
	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Verify agent exists
	var exists bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1)
	`, agentID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.logger.Error("Failed to upgrade WebSocket for agent", zap.Error(err))
		return
	}
	defer conn.Close()

	h.logger.Info("Agent connected via WebSocket",
		zap.String("agent_id", agentIDStr))

	// Create channels for command stream
	recvCh := make(chan *agentgrpc.AgentMessage, 100)
	sendCh := make(chan *agentgrpc.BackendMessage, 100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the backend's command stream handler in a goroutine
	go func() {
		agentService := agentgrpc.NewAgentService(h.db, h.logger)
		err := agentService.CommandStream(agentIDStr, recvCh, sendCh)
		if err != nil {
			h.logger.Debug("Agent command stream ended", zap.Error(err))
		}
		cancel()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine to send commands to agent via WebSocket
	go func() {
		defer wg.Done()
		for {
			select {
			case cmd, ok := <-sendCh:
				if !ok {
					return
				}
				data, err := json.Marshal(cmd)
				if err != nil {
					h.logger.Error("Failed to marshal command", zap.Error(err))
					continue
				}
				if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
					h.logger.Debug("WebSocket write error", zap.Error(err))
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Goroutine to receive responses from agent via WebSocket
	go func() {
		defer wg.Done()
		defer close(recvCh)
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					h.logger.Debug("WebSocket read error", zap.Error(err))
				}
				cancel()
				return
			}

			var agentMsg agentgrpc.AgentMessage
			if err := json.Unmarshal(msg, &agentMsg); err != nil {
				h.logger.Error("Failed to unmarshal agent message", zap.Error(err))
				continue
			}

			select {
			case recvCh <- &agentMsg:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Keep connection alive with pings
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for context to be cancelled
	<-ctx.Done()
	wg.Wait()

	h.logger.Info("Agent disconnected from WebSocket",
		zap.String("agent_id", agentIDStr))
}
