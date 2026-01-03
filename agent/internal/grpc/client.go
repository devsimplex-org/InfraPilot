package grpc

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/infrapilot/agent/internal/docker"
	"github.com/infrapilot/agent/internal/metrics"
)

const agentVersion = "0.1.0"

type Client struct {
	conn            *grpc.ClientConn
	logger          *zap.Logger
	enrollmentToken string
	agentID         string

	// Command stream
	sendCh   chan *AgentMessage
	recvCh   chan *BackendMessage
	streamMu sync.Mutex
}

// ============ Command Types (matching backend) ============

type BackendMessage struct {
	RequestId string          `json:"request_id"`
	Command   json.RawMessage `json:"command"`
	Type      string          `json:"type"` // "nginx", "docker", "network"
}

type AgentMessage struct {
	RequestId string      `json:"request_id"`
	Response  interface{} `json:"response"`
}

type NginxCommand struct {
	Action        string `json:"action"`
	ConfigContent string `json:"config_content"`
	ConfigPath    string `json:"config_path"`
	Domain        string `json:"domain"`
	Email         string `json:"email"`
	DNSProvider   string `json:"dns_provider"`
}

type NetworkCommand struct {
	Action      string `json:"action"`
	NetworkID   string `json:"network_id"`
	ContainerID string `json:"container_id"`
}

type CommandResult struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewClient(addr, enrollmentToken string, logger *zap.Logger) (*Client, error) {
	// In production, use mTLS credentials
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	return &Client{
		conn:            conn,
		logger:          logger,
		enrollmentToken: enrollmentToken,
		sendCh:          make(chan *AgentMessage, 100),
		recvCh:          make(chan *BackendMessage, 100),
	}, nil
}

func (c *Client) Close() error {
	close(c.sendCh)
	return c.conn.Close()
}

// SetAgentID sets the agent ID after registration
func (c *Client) SetAgentID(agentID string) {
	c.agentID = agentID
}

// GetRecvChannel returns the channel for receiving commands from backend
func (c *Client) GetRecvChannel() <-chan *BackendMessage {
	return c.recvCh
}

// SendResponse sends a response back to the backend
func (c *Client) SendResponse(requestID string, result *CommandResult) {
	c.sendCh <- &AgentMessage{
		RequestId: requestID,
		Response:  result,
	}
}

// SendError sends an error response back to the backend
func (c *Client) SendError(requestID string, code int, message string) {
	c.sendCh <- &AgentMessage{
		RequestId: requestID,
		Response: ErrorResponse{
			Code:    code,
			Message: message,
		},
	}
}

func (c *Client) Register(ctx context.Context, hostname string) (string, error) {
	// In production, use generated protobuf client
	c.logger.Info("Registering agent",
		zap.String("hostname", hostname),
		zap.String("version", agentVersion),
	)

	osInfo := runtime.GOOS + "/" + runtime.GOARCH

	// Placeholder for actual gRPC call
	// In production:
	// client := pb.NewAgentServiceClient(c.conn)
	// resp, err := client.Register(ctx, &pb.RegisterRequest{...})

	_ = osInfo
	_ = c.enrollmentToken

	// Return placeholder agent ID
	return "", nil
}

func (c *Client) Heartbeat(ctx context.Context, agentID string, sysMetrics *metrics.SystemMetrics, containers []docker.ContainerInfo) error {
	// In production, use generated protobuf client
	c.logger.Debug("Sending heartbeat",
		zap.String("agent_id", agentID),
		zap.Float64("cpu_percent", sysMetrics.CPUPercent),
		zap.Int64("memory_used_mb", sysMetrics.MemoryUsedMB),
		zap.Int("container_count", len(containers)),
	)

	// Placeholder for actual gRPC call
	return nil
}

// ConnectCommandStream establishes a bidirectional command stream with the backend
// This simulates what would be a real gRPC streaming connection
func (c *Client) ConnectCommandStream(ctx context.Context, handler CommandHandler) error {
	c.logger.Info("Connecting command stream", zap.String("agent_id", c.agentID))

	// In production, this would use actual gRPC streaming:
	// stream, err := c.client.CommandStream(ctx)
	// For now, we simulate with polling and WebSocket-like behavior

	// Start goroutine to process incoming commands
	go func() {
		for {
			select {
			case <-ctx.Done():
				c.logger.Info("Command stream context cancelled")
				return
			case cmd, ok := <-c.recvCh:
				if !ok {
					c.logger.Info("Command receive channel closed")
					return
				}

				c.logger.Debug("Received command",
					zap.String("request_id", cmd.RequestId),
					zap.String("type", cmd.Type),
				)

				// Process command in separate goroutine
				go func(cmd *BackendMessage) {
					result := handler.HandleCommand(ctx, cmd)
					c.SendResponse(cmd.RequestId, result)
				}(cmd)
			}
		}
	}()

	// Start goroutine to send responses
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-c.sendCh:
				if !ok {
					return
				}

				// In production, this would send via gRPC stream
				c.logger.Debug("Sending response",
					zap.String("request_id", msg.RequestId),
				)

				// Simulate sending (in production: stream.Send(msg))
				_ = msg
			}
		}
	}()

	// Keep connection alive with heartbeats
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			c.logger.Debug("Command stream heartbeat")
		}
	}
}

// CommandHandler interface for processing backend commands
type CommandHandler interface {
	HandleCommand(ctx context.Context, cmd *BackendMessage) *CommandResult
}

// QueueCommand adds a command to the receive queue (for testing/simulation)
func (c *Client) QueueCommand(cmd *BackendMessage) {
	select {
	case c.recvCh <- cmd:
	default:
		c.logger.Warn("Command queue full, dropping command",
			zap.String("request_id", cmd.RequestId),
		)
	}
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
