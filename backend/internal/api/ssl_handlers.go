package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	agentgrpc "github.com/infrapilot/backend/internal/grpc"
)

// SSLCertificateInfo represents SSL certificate information
type SSLCertificateInfo struct {
	Exists      bool      `json:"exists"`
	Domain      string    `json:"domain"`
	Issuer      string    `json:"issuer,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	DaysLeft    int       `json:"days_left,omitempty"`
	IsWildcard  bool      `json:"is_wildcard,omitempty"`
	ValidForDomain bool   `json:"valid_for_domain"`
	Error       string    `json:"error,omitempty"`
	SANs        []string  `json:"sans,omitempty"`
}

// SSLCheckRequest is the request for checking SSL status
type SSLCheckRequest struct {
	Domain      string `json:"domain" binding:"required"`
	CheckRemote bool   `json:"check_remote"` // Check remote server, not local files
}

// SSLRequestOptions represents options for requesting a certificate
type SSLRequestOptions struct {
	Domain       string `json:"domain" binding:"required"`
	Email        string `json:"email"`
	DNSProvider  string `json:"dns_provider,omitempty"` // For DNS-01 challenge
	Staging      bool   `json:"staging"`                // Use Let's Encrypt staging
	ForceRenew   bool   `json:"force_renew"`            // Force renewal even if valid
}

// SSLStatusResponse represents the SSL configuration status
type SSLStatusResponse struct {
	LetsEncryptEmail   string `json:"letsencrypt_email"`
	LetsEncryptStaging bool   `json:"letsencrypt_staging"`
	AccountConfigured  bool   `json:"account_configured"`
	CertDirectory      string `json:"cert_directory"`
}

// checkDomainSSL checks SSL certificate status for a domain
// GET /api/v1/ssl/check/:domain
func (h *Handler) checkDomainSSL(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	// Check remote means checking the actual server's certificate
	checkRemote := c.Query("remote") == "true"

	var certInfo SSLCertificateInfo
	certInfo.Domain = domain

	if checkRemote {
		// Check the remote server's SSL certificate
		certInfo = h.checkRemoteSSL(domain)
	} else {
		// Check local Let's Encrypt certificates via agent
		// First, try to get info from any connected agent
		orgID := c.MustGet("org_id").(uuid.UUID)
		certInfo = h.checkLocalSSL(c, orgID, domain)
	}

	c.JSON(http.StatusOK, certInfo)
}

// checkRemoteSSL checks the SSL certificate served by a remote domain
func (h *Handler) checkRemoteSSL(domain string) SSLCertificateInfo {
	info := SSLCertificateInfo{
		Domain: domain,
		Exists: false,
	}

	// Connect to the server with a timeout
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true, // We want to check even invalid certs
	})
	if err != nil {
		// Don't show technical errors for expected cases
		// Connection refused, reset, timeout, EOF are all expected for domains without SSL
		errStr := err.Error()
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "connection reset") ||
			strings.Contains(errStr, "no such host") ||
			strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "i/o timeout") ||
			strings.Contains(errStr, "EOF") ||
			strings.Contains(errStr, "eof") {
			// This is expected for new domains - no error message needed
			return info
		}
		info.Error = fmt.Sprintf("Could not connect: %v", err)
		return info
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		info.Error = "No certificates found"
		return info
	}

	cert := certs[0]
	info.Exists = true
	info.Issuer = cert.Issuer.CommonName
	info.Subject = cert.Subject.CommonName
	info.ExpiresAt = cert.NotAfter
	info.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	info.SANs = cert.DNSNames

	// Check if cert is valid for this domain
	info.ValidForDomain = false
	for _, san := range cert.DNSNames {
		if san == domain {
			info.ValidForDomain = true
			break
		}
		// Check for wildcard match
		if strings.HasPrefix(san, "*.") {
			parentDomain := san[2:] // Remove "*."
			if strings.HasSuffix(domain, parentDomain) {
				// Check if it's a direct subdomain (not nested)
				prefix := strings.TrimSuffix(domain, parentDomain)
				prefix = strings.TrimSuffix(prefix, ".")
				if !strings.Contains(prefix, ".") {
					info.ValidForDomain = true
					info.IsWildcard = true
					break
				}
			}
		}
	}

	// Also check against common name
	if cert.Subject.CommonName == domain {
		info.ValidForDomain = true
	}

	return info
}

// checkLocalSSL checks if Let's Encrypt certificate exists locally via agent
func (h *Handler) checkLocalSSL(c *gin.Context, orgID uuid.UUID, domain string) SSLCertificateInfo {
	info := SSLCertificateInfo{
		Domain: domain,
		Exists: false,
	}

	// Find an active agent for this org
	var agentID string
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id FROM agents WHERE org_id = $1 AND status = 'active' LIMIT 1
	`, orgID).Scan(&agentID)
	if err != nil {
		info.Error = "No active agent found"
		return info
	}

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentID) {
		info.Error = "Agent not connected"
		return info
	}

	// Send command to check certificate
	cmd := agentgrpc.NewSSLCheckCommand(domain)
	resp, err := agentgrpc.SendCommand(agentID, cmd, 15*time.Second)
	if err != nil {
		h.logger.Error("Failed to check SSL via agent", zap.Error(err))
		info.Error = fmt.Sprintf("Agent communication error: %v", err)
		return info
	}

	// Parse response
	if result, ok := resp.Response.(*agentgrpc.SSLCheckResult); ok {
		info.Exists = result.Exists
		info.Issuer = result.Issuer
		info.ExpiresAt = result.ExpiresAt
		info.DaysLeft = result.DaysLeft
		info.ValidForDomain = result.ValidForDomain
		info.IsWildcard = result.IsWildcard
		info.SANs = result.SANs
		if result.Error != "" {
			info.Error = result.Error
		}
	}

	return info
}

// checkWildcardSSL checks if a wildcard certificate covers this domain
// GET /api/v1/ssl/check-wildcard/:domain
func (h *Handler) checkWildcardSSL(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	// Extract parent domain for wildcard check
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain"})
		return
	}

	results := []SSLCertificateInfo{}

	// Check exact domain
	exactInfo := h.checkRemoteSSL(domain)
	exactInfo.Domain = domain
	results = append(results, exactInfo)

	// Check parent domain for wildcard
	if len(parts) >= 2 {
		parentDomain := strings.Join(parts[1:], ".")
		wildcardDomain := "*." + parentDomain

		// Check if there's a cert for the parent domain
		parentInfo := h.checkRemoteSSL(parentDomain)
		parentInfo.Domain = wildcardDomain

		// Check if any SAN is a wildcard covering our domain
		for _, san := range parentInfo.SANs {
			if san == wildcardDomain {
				parentInfo.IsWildcard = true
				parentInfo.ValidForDomain = true
				break
			}
		}
		results = append(results, parentInfo)
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":       domain,
		"certificates": results,
	})
}

// getSSLStatus returns the SSL/Let's Encrypt configuration status
// GET /api/v1/ssl/status
func (h *Handler) getSSLStatus(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Get Let's Encrypt settings from system_settings
	var settingsJSON []byte
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT setting_value FROM system_settings
		WHERE org_id = $1 AND setting_key = 'letsencrypt_config'
	`, orgID).Scan(&settingsJSON)

	status := SSLStatusResponse{
		LetsEncryptStaging: true, // Default to staging
		CertDirectory:      "/etc/letsencrypt",
	}

	if err == nil && len(settingsJSON) > 0 {
		// Parse existing settings
		var settings struct {
			Email   string `json:"email"`
			Staging bool   `json:"staging"`
		}
		if err := json.Unmarshal(settingsJSON, &settings); err == nil {
			status.LetsEncryptEmail = settings.Email
			status.LetsEncryptStaging = settings.Staging
			status.AccountConfigured = settings.Email != ""
		}
	}

	c.JSON(http.StatusOK, status)
}

// updateSSLSettings updates the SSL/Let's Encrypt settings
// PUT /api/v1/ssl/settings
func (h *Handler) updateSSLSettings(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req struct {
		Email   string `json:"email" binding:"required,email"`
		Staging bool   `json:"staging"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	settingsJSON, _ := json.Marshal(map[string]interface{}{
		"email":   req.Email,
		"staging": req.Staging,
	})

	_, err := h.db.Exec(c.Request.Context(), `
		INSERT INTO system_settings (org_id, setting_key, setting_value)
		VALUES ($1, 'letsencrypt_config', $2)
		ON CONFLICT (org_id, setting_key) DO UPDATE SET
			setting_value = EXCLUDED.setting_value,
			updated_at = NOW()
	`, orgID, settingsJSON)

	if err != nil {
		h.logger.Error("Failed to update SSL settings", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update settings"})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "ssl.settings.update", "system_settings", uuid.Nil, req)

	c.JSON(http.StatusOK, gin.H{
		"email":   req.Email,
		"staging": req.Staging,
		"message": "SSL settings updated",
	})
}

// requestSSLCertificate requests a new SSL certificate
// POST /api/v1/ssl/request
func (h *Handler) requestSSLCertificate(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req SSLRequestOptions
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get email from settings if not provided
	if req.Email == "" {
		var settingsJSON []byte
		h.db.QueryRow(c.Request.Context(), `
			SELECT setting_value FROM system_settings
			WHERE org_id = $1 AND setting_key = 'letsencrypt_config'
		`, orgID).Scan(&settingsJSON)

		if len(settingsJSON) > 0 {
			var settings struct {
				Email   string `json:"email"`
				Staging bool   `json:"staging"`
			}
			if err := json.Unmarshal(settingsJSON, &settings); err == nil {
				req.Email = settings.Email
				if !req.Staging {
					req.Staging = settings.Staging
				}
			}
		}
	}

	if req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required for Let's Encrypt"})
		return
	}

	// Find an active agent
	var agentID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id FROM agents WHERE org_id = $1 AND status = 'active' LIMIT 1
	`, orgID).Scan(&agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no active agent found"})
		return
	}

	agentIDStr := agentID.String()

	// Check if agent is connected
	if !agentgrpc.IsAgentConnected(agentIDStr) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent not connected"})
		return
	}

	// Send SSL request to agent and wait for response (up to 2 minutes for ACME challenge)
	cmd := agentgrpc.NewSSLRequestCommand(req.Domain, req.Email, req.DNSProvider, req.Staging)

	h.logger.Info("Sending SSL request to agent",
		zap.String("agent_id", agentIDStr),
		zap.String("domain", req.Domain),
		zap.String("email", req.Email),
		zap.Bool("staging", req.Staging),
	)

	resp, err := agentgrpc.SendCommand(agentIDStr, cmd, 120*time.Second)
	if err != nil {
		h.logger.Error("SSL request failed", zap.Error(err), zap.String("domain", req.Domain))
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   fmt.Sprintf("SSL request failed: %v", err),
			"domain":  req.Domain,
		})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "ssl.request", "domain", uuid.Nil, req)

	// Parse response from agent
	success := false
	message := ""

	if result, ok := resp.Response.(*agentgrpc.CommandResult); ok {
		success = result.Success
		message = result.Message
	} else if resultMap, ok := resp.Response.(map[string]interface{}); ok {
		success, _ = resultMap["success"].(bool)
		message, _ = resultMap["message"].(string)
	}

	if success {
		// Update proxy_hosts to enable SSL and regenerate nginx config
		var proxyID uuid.UUID
		var forceSSL, http2Enabled, isSystemProxy bool
		err := h.db.QueryRow(c.Request.Context(), `
			UPDATE proxy_hosts SET ssl_enabled = true, force_ssl = true, status = 'active', updated_at = NOW()
			WHERE agent_id = $1 AND domain = $2
			RETURNING id, force_ssl, http2_enabled, is_system_proxy
		`, agentID, req.Domain).Scan(&proxyID, &forceSSL, &http2Enabled, &isSystemProxy)

		if err == nil {
			h.logger.Info("Updated proxy_hosts for SSL",
				zap.String("domain", req.Domain),
				zap.String("proxy_id", proxyID.String()),
			)

			// Regenerate and dispatch nginx config with SSL enabled
			if isSystemProxy {
				go h.dispatchInfraPilotProxyConfig(c.Request.Context(), agentID, proxyID, req.Domain, true, http2Enabled, true)
			} else {
				// For regular proxies, get upstream and dispatch
				var upstream string
				h.db.QueryRow(c.Request.Context(), `SELECT upstream_target FROM proxy_hosts WHERE id = $1`, proxyID).Scan(&upstream)
				if upstream != "" {
					go h.dispatchProxyConfig(c.Request.Context(), agentID, proxyID, req.Domain, upstream, true, http2Enabled, true)
				}
			}
		} else {
			h.logger.Warn("Could not find proxy_host to update SSL status",
				zap.String("domain", req.Domain),
				zap.Error(err),
			)
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": message,
			"domain":  req.Domain,
			"email":   req.Email,
			"staging": req.Staging,
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   message,
			"domain":  req.Domain,
		})
	}
}

// dispatchSSLRequestWithOptions sends SSL request with full options
func (h *Handler) dispatchSSLRequestWithOptions(agentID uuid.UUID, domain, email, dnsProvider string, staging bool) {
	agentIDStr := agentID.String()

	if !agentgrpc.IsAgentConnected(agentIDStr) {
		h.logger.Warn("Agent not connected for SSL request",
			zap.String("agent_id", agentIDStr),
			zap.String("domain", domain),
		)
		return
	}

	cmd := agentgrpc.NewSSLRequestCommand(domain, email, dnsProvider, staging)

	if err := agentgrpc.SendCommandAsync(agentIDStr, cmd); err != nil {
		h.logger.Error("Failed to dispatch SSL request",
			zap.Error(err),
			zap.String("domain", domain),
		)
		return
	}

	h.logger.Info("Dispatched SSL request to agent",
		zap.String("agent_id", agentIDStr),
		zap.String("domain", domain),
		zap.String("email", email),
		zap.Bool("staging", staging),
	)
}

// getPublicIP tries to detect the server's public IP
func getPublicIP() string {
	// Try multiple services for reliability
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, svc := range services {
		resp, err := client.Get(svc)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body := make([]byte, 64)
		n, _ := resp.Body.Read(body)
		ip := strings.TrimSpace(string(body[:n]))

		// Validate it looks like an IP
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// getDNSInstructions returns DNS configuration instructions for a domain
// GET /api/v1/ssl/dns-instructions/:domain
func (h *Handler) getDNSInstructions(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	// Get server's public IP
	serverIP := getPublicIP()

	// Fallback message if still not found
	if serverIP == "" {
		serverIP = "YOUR_SERVER_IP"
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":    domain,
		"server_ip": serverIP,
		"records": []gin.H{
			{
				"type":  "A",
				"name":  domain,
				"value": serverIP,
				"ttl":   300,
			},
		},
		"instructions": fmt.Sprintf(`
To configure SSL for %s:

1. Add an A record pointing to your server:
   - Type: A
   - Name: %s
   - Value: %s
   - TTL: 300 (or Auto)

2. Wait for DNS propagation (usually 1-5 minutes, can take up to 48 hours)

3. Click "Request Certificate" to obtain SSL from Let's Encrypt

4. Let's Encrypt will verify domain ownership via HTTP-01 challenge
`, domain, domain, serverIP),
	})
}

// verifyDNS checks if DNS is properly configured for a domain
// GET /api/v1/ssl/verify-dns/:domain
func (h *Handler) verifyDNS(c *gin.Context) {
	domain := c.Param("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	// Lookup A records
	ips, err := net.LookupIP(domain)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"domain":     domain,
			"configured": false,
			"error":      fmt.Sprintf("DNS lookup failed: %v", err),
		})
		return
	}

	// Get expected IP
	expectedIP := getPublicIP()

	// Check if any IP matches
	ipStrings := []string{}
	matches := false
	for _, ip := range ips {
		ipStr := ip.String()
		ipStrings = append(ipStrings, ipStr)
		if ipStr == expectedIP {
			matches = true
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"domain":      domain,
		"configured":  len(ips) > 0,
		"resolved_ips": ipStrings,
		"expected_ip": expectedIP,
		"matches":     matches,
	})
}
