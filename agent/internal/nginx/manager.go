package nginx

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

type Manager struct {
	configPath string
	logger     *zap.Logger
}

func NewManager(configPath string, logger *zap.Logger) *Manager {
	return &Manager{
		configPath: configPath,
		logger:     logger,
	}
}

// TestConfig runs nginx -t to validate configuration
func (m *Manager) TestConfig() error {
	cmd := exec.Command("nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.Error("Nginx config test failed",
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}
	return nil
}

// Reload sends SIGHUP to nginx to reload configuration
func (m *Manager) Reload() error {
	// First test the config
	if err := m.TestConfig(); err != nil {
		return err
	}

	cmd := exec.Command("nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.Error("Nginx reload failed",
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return fmt.Errorf("nginx reload failed: %s", string(output))
	}

	m.logger.Info("Nginx reloaded successfully")
	return nil
}

// WriteConfig writes a server configuration file
func (m *Manager) WriteConfig(filename, content string) error {
	path := filepath.Join(m.configPath, filename)

	// Write to temp file first
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Rename atomically
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}

	m.logger.Info("Wrote nginx config", zap.String("path", path))
	return nil
}

// DeleteConfig removes a server configuration file
func (m *Manager) DeleteConfig(filename string) error {
	path := filepath.Join(m.configPath, filename)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}
	m.logger.Info("Deleted nginx config", zap.String("path", path))
	return nil
}

// GetConfig reads a server configuration file
func (m *Manager) GetConfig(filename string) (string, error) {
	path := filepath.Join(m.configPath, filename)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}
	return string(content), nil
}

// ListConfigs lists all .conf files in the config directory
func (m *Manager) ListConfigs() ([]string, error) {
	entries, err := os.ReadDir(m.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list configs: %w", err)
	}

	var configs []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			configs = append(configs, entry.Name())
		}
	}
	return configs, nil
}

// GenerateServerBlock generates nginx server configuration for a proxy host
func (m *Manager) GenerateServerBlock(domain, upstream string, sslEnabled, forceSSL, http2 bool, sslCertPath, sslKeyPath string) string {
	var sb strings.Builder

	// HTTP server (redirect or serve)
	sb.WriteString(fmt.Sprintf(`server {
    listen 80;
    listen [::]:80;
    server_name %s;

`, domain))

	if sslEnabled && forceSSL {
		sb.WriteString(`    return 301 https://$host$request_uri;
}

`)
	} else {
		sb.WriteString(fmt.Sprintf(`    location / {
        proxy_pass %s;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

`, upstream))
	}

	// HTTPS server
	if sslEnabled {
		listenSSL := "443 ssl"
		if http2 {
			listenSSL = "443 ssl http2"
		}

		sb.WriteString(fmt.Sprintf(`server {
    listen %s;
    listen [::]:%s;
    server_name %s;

    ssl_certificate %s;
    ssl_certificate_key %s;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass %s;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`, listenSSL, listenSSL, domain, sslCertPath, sslKeyPath, upstream))
	}

	return sb.String()
}
