package alerts

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"time"

	"go.uber.org/zap"
)

// Notifier handles sending notifications to various channels
type Notifier struct {
	httpClient *http.Client
	logger     *zap.Logger
}

// NewNotifier creates a new notification service
func NewNotifier(logger *zap.Logger) *Notifier {
	return &Notifier{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// AlertPayload represents the data sent to notification channels
type AlertPayload struct {
	RuleName    string                 `json:"rule_name"`
	RuleType    string                 `json:"rule_type"`
	Severity    string                 `json:"severity"`
	Message     string                 `json:"message"`
	AgentName   string                 `json:"agent_name,omitempty"`
	ContainerID string                 `json:"container_id,omitempty"`
	TriggeredAt time.Time              `json:"triggered_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ChannelConfig represents configuration for a notification channel
type ChannelConfig struct {
	Type   string
	Config map[string]interface{}
}

// SendNotification sends an alert to the specified channel
func (n *Notifier) SendNotification(ctx context.Context, channel ChannelConfig, payload AlertPayload) error {
	switch channel.Type {
	case "slack":
		return n.sendSlack(ctx, channel.Config, payload)
	case "webhook":
		return n.sendWebhook(ctx, channel.Config, payload)
	case "smtp":
		return n.sendEmail(ctx, channel.Config, payload)
	default:
		return fmt.Errorf("unsupported channel type: %s", channel.Type)
	}
}

// sendSlack sends a notification to Slack via webhook
func (n *Notifier) sendSlack(ctx context.Context, config map[string]interface{}, payload AlertPayload) error {
	webhookURL, ok := config["webhook_url"].(string)
	if !ok || webhookURL == "" {
		return fmt.Errorf("slack webhook_url not configured")
	}

	// Build Slack message with blocks for better formatting
	color := "#ff0000" // red for critical
	switch payload.Severity {
	case "warning":
		color = "#ffcc00"
	case "info":
		color = "#0066ff"
	}

	slackPayload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"blocks": []map[string]interface{}{
					{
						"type": "header",
						"text": map[string]string{
							"type":  "plain_text",
							"text":  fmt.Sprintf("🚨 Alert: %s", payload.RuleName),
							"emoji": "true",
						},
					},
					{
						"type": "section",
						"text": map[string]string{
							"type": "mrkdwn",
							"text": payload.Message,
						},
					},
					{
						"type": "context",
						"elements": []map[string]string{
							{
								"type": "mrkdwn",
								"text": fmt.Sprintf("*Type:* %s | *Severity:* %s | *Time:* %s",
									payload.RuleType, payload.Severity, payload.TriggeredAt.Format(time.RFC3339)),
							},
						},
					},
				},
			},
		},
	}

	if channel, ok := config["channel"].(string); ok && channel != "" {
		slackPayload["channel"] = channel
	}

	body, err := json.Marshal(slackPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-200 status: %d", resp.StatusCode)
	}

	n.logger.Info("Slack notification sent",
		zap.String("rule", payload.RuleName),
		zap.String("severity", payload.Severity))

	return nil
}

// sendWebhook sends a notification to a generic webhook
func (n *Notifier) sendWebhook(ctx context.Context, config map[string]interface{}, payload AlertPayload) error {
	url, ok := config["url"].(string)
	if !ok || url == "" {
		return fmt.Errorf("webhook url not configured")
	}

	method := "POST"
	if m, ok := config["method"].(string); ok && m != "" {
		method = m
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	if headers, ok := config["headers"].(map[string]interface{}); ok {
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				req.Header.Set(k, vs)
			}
		}
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-2xx status: %d", resp.StatusCode)
	}

	n.logger.Info("Webhook notification sent",
		zap.String("rule", payload.RuleName),
		zap.String("url", url))

	return nil
}

// sendEmail sends a notification via SMTP
func (n *Notifier) sendEmail(ctx context.Context, config map[string]interface{}, payload AlertPayload) error {
	host, _ := config["host"].(string)
	port, _ := config["port"].(float64)
	from, _ := config["from"].(string)
	username, _ := config["username"].(string)
	password, _ := config["password"].(string)
	useTLS, _ := config["use_tls"].(bool)

	if host == "" || from == "" {
		return fmt.Errorf("smtp host and from are required")
	}

	// Get recipients
	var to []string
	if toList, ok := config["to"].([]interface{}); ok {
		for _, t := range toList {
			if ts, ok := t.(string); ok {
				to = append(to, ts)
			}
		}
	}
	if len(to) == 0 {
		return fmt.Errorf("no recipients configured")
	}

	// Build email
	subject := fmt.Sprintf("[%s] Alert: %s", payload.Severity, payload.RuleName)
	body := fmt.Sprintf(`Alert: %s
Type: %s
Severity: %s
Time: %s

%s

---
This alert was sent by InfraPilot
`, payload.RuleName, payload.RuleType, payload.Severity, payload.TriggeredAt.Format(time.RFC3339), payload.Message)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from, to[0], subject, body)

	addr := fmt.Sprintf("%s:%d", host, int(port))

	var auth smtp.Auth
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}

	if useTLS {
		// Use TLS connection
		tlsConfig := &tls.Config{
			ServerName: host,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, host)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP auth failed: %w", err)
			}
		}

		if err := client.Mail(from); err != nil {
			return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
		}

		for _, rcpt := range to {
			if err := client.Rcpt(rcpt); err != nil {
				return fmt.Errorf("SMTP RCPT TO failed: %w", err)
			}
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA failed: %w", err)
		}

		_, err = w.Write([]byte(msg))
		if err != nil {
			return fmt.Errorf("failed to write email: %w", err)
		}

		err = w.Close()
		if err != nil {
			return fmt.Errorf("failed to close email: %w", err)
		}
	} else {
		// Use plain SMTP
		err := smtp.SendMail(addr, auth, from, to, []byte(msg))
		if err != nil {
			return fmt.Errorf("failed to send email: %w", err)
		}
	}

	n.logger.Info("Email notification sent",
		zap.String("rule", payload.RuleName),
		zap.Strings("to", to))

	return nil
}

// TestChannel sends a test notification to verify channel configuration
func (n *Notifier) TestChannel(ctx context.Context, channel ChannelConfig) error {
	testPayload := AlertPayload{
		RuleName:    "Test Alert",
		RuleType:    "test",
		Severity:    "info",
		Message:     "This is a test notification from InfraPilot to verify your alert channel is configured correctly.",
		TriggeredAt: time.Now(),
	}

	return n.SendNotification(ctx, channel, testPayload)
}
