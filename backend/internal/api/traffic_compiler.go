package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// parseJSON is a helper to unmarshal JSON bytes into a target
func parseJSON(data []byte, target interface{}) {
	json.Unmarshal(data, target)
}

// CompiledTrafficConfig represents the output of the traffic compiler
type CompiledTrafficConfig struct {
	ResourceID   uuid.UUID              `json:"resource_id"`
	ResourceName string                 `json:"resource_name"`
	NginxConfig  string                 `json:"nginx_config"`
	ConfigHash   string                 `json:"config_hash"`
	Domains      []string               `json:"domains"`
	Upstreams    []TrafficUpstream      `json:"upstreams"`
	Policies     []TrafficPolicy        `json:"policies"`
	TLSConfig    *TrafficTLSConfig      `json:"tls_config,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// compileTrafficResource generates nginx configuration from a TrafficResource
func (h *Handler) compileTrafficResource(ctx context.Context, resourceID uuid.UUID) (*CompiledTrafficConfig, error) {
	// 1. Load the traffic resource
	resource, err := h.loadTrafficResource(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to load traffic resource: %w", err)
	}

	// 2. Load upstreams
	upstreams, err := h.loadTrafficUpstreams(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to load upstreams: %w", err)
	}

	// 3. Load assigned policies
	policies, err := h.loadAssignedPolicies(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// 4. Load TLS config
	tlsConfig, err := h.loadTrafficTLSConfig(ctx, resourceID)
	if err != nil && err != pgx.ErrNoRows {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	// 5. Generate nginx configuration
	nginxConfig := h.generateTrafficNginxConfig(resource, upstreams, policies, tlsConfig)

	// 6. Calculate config hash
	hash := sha256.Sum256([]byte(nginxConfig))
	configHash := hex.EncodeToString(hash[:])

	return &CompiledTrafficConfig{
		ResourceID:   resource.ID,
		ResourceName: resource.Name,
		NginxConfig:  nginxConfig,
		ConfigHash:   configHash,
		Domains:      resource.Domains,
		Upstreams:    upstreams,
		Policies:     policies,
		TLSConfig:    tlsConfig,
		Metadata: map[string]interface{}{
			"gateway_type": resource.GatewayType,
			"paths":        resource.Paths,
		},
	}, nil
}

// loadTrafficResource loads a single traffic resource by ID
func (h *Handler) loadTrafficResource(ctx context.Context, resourceID uuid.UUID) (*TrafficResource, error) {
	var resource TrafficResource
	var pathsJSON, labelsJSON, annotationsJSON, desiredJSON, appliedJSON []byte

	err := h.db.QueryRow(ctx, `
		SELECT id, org_id, agent_id, name, description, domains, paths,
		       gateway_type, status, desired_state, applied_state,
		       last_applied_at, last_error, labels, annotations,
		       created_at, updated_at
		FROM traffic_resources
		WHERE id = $1
	`, resourceID).Scan(
		&resource.ID, &resource.OrgID, &resource.AgentID, &resource.Name,
		&resource.Description, &resource.Domains, &pathsJSON,
		&resource.GatewayType, &resource.Status, &desiredJSON, &appliedJSON,
		&resource.LastAppliedAt, &resource.LastError, &labelsJSON, &annotationsJSON,
		&resource.CreatedAt, &resource.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Parse JSON fields
	if len(pathsJSON) > 0 {
		parseJSON(pathsJSON, &resource.Paths)
	}
	if len(labelsJSON) > 0 {
		parseJSON(labelsJSON, &resource.Labels)
	}
	if len(annotationsJSON) > 0 {
		parseJSON(annotationsJSON, &resource.Annotations)
	}
	if len(desiredJSON) > 0 {
		parseJSON(desiredJSON, &resource.DesiredState)
	}
	if len(appliedJSON) > 0 {
		parseJSON(appliedJSON, &resource.AppliedState)
	}

	return &resource, nil
}

// loadTrafficUpstreams loads all upstreams for a traffic resource
func (h *Handler) loadTrafficUpstreams(ctx context.Context, resourceID uuid.UUID) ([]TrafficUpstream, error) {
	rows, err := h.db.Query(ctx, `
		SELECT id, traffic_resource_id, name, targets, lb_method,
		       health_check_enabled, health_check_path, health_check_interval_sec,
		       health_check_timeout_sec, healthy_threshold, unhealthy_threshold,
		       max_connections, max_keepalive, connect_timeout_sec, read_timeout_sec,
		       send_timeout_sec, last_health_check, healthy_targets, total_targets,
		       created_at, updated_at
		FROM traffic_upstreams
		WHERE traffic_resource_id = $1
		ORDER BY name
	`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var upstreams []TrafficUpstream
	for rows.Next() {
		var u TrafficUpstream
		var targetsJSON []byte

		err := rows.Scan(
			&u.ID, &u.TrafficResourceID, &u.Name, &targetsJSON, &u.LBMethod,
			&u.HealthCheckEnabled, &u.HealthCheckPath, &u.HealthCheckIntervalSec,
			&u.HealthCheckTimeoutSec, &u.HealthyThreshold, &u.UnhealthyThreshold,
			&u.MaxConnections, &u.MaxKeepalive, &u.ConnectTimeoutSec, &u.ReadTimeoutSec,
			&u.SendTimeoutSec, &u.LastHealthCheck, &u.HealthyTargets, &u.TotalTargets,
			&u.CreatedAt, &u.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if len(targetsJSON) > 0 {
			parseJSON(targetsJSON, &u.Targets)
		}

		upstreams = append(upstreams, u)
	}

	return upstreams, nil
}

// loadAssignedPolicies loads all policies assigned to a traffic resource
func (h *Handler) loadAssignedPolicies(ctx context.Context, resourceID uuid.UUID) ([]TrafficPolicy, error) {
	rows, err := h.db.Query(ctx, `
		SELECT p.id, p.org_id, p.name, p.description, p.policy_type,
		       p.config, p.is_global, p.priority, p.enabled,
		       p.created_at, p.updated_at
		FROM traffic_policies p
		LEFT JOIN traffic_policy_assignments a ON a.policy_id = p.id
		WHERE (a.traffic_resource_id = $1 AND a.enabled = TRUE)
		   OR (p.is_global = TRUE AND p.enabled = TRUE)
		ORDER BY p.priority DESC, p.name
	`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []TrafficPolicy
	for rows.Next() {
		var p TrafficPolicy
		var configJSON []byte

		err := rows.Scan(
			&p.ID, &p.OrgID, &p.Name, &p.Description, &p.PolicyType,
			&configJSON, &p.IsGlobal, &p.Priority, &p.Enabled,
			&p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if len(configJSON) > 0 {
			parseJSON(configJSON, &p.Config)
		}

		policies = append(policies, p)
	}

	return policies, nil
}

// loadTrafficTLSConfig loads TLS configuration for a traffic resource
func (h *Handler) loadTrafficTLSConfig(ctx context.Context, resourceID uuid.UUID) (*TrafficTLSConfig, error) {
	var config TrafficTLSConfig

	err := h.db.QueryRow(ctx, `
		SELECT id, traffic_resource_id, cert_source, cert_id,
		       min_version, max_version, cipher_suites, prefer_server_ciphers,
		       hsts_enabled, hsts_max_age, hsts_include_subdomains, hsts_preload,
		       ocsp_stapling, mtls_enabled, mtls_ca_cert, mtls_verify_depth,
		       mtls_verify_client
		FROM traffic_tls_configs
		WHERE traffic_resource_id = $1
	`, resourceID).Scan(
		&config.ID, &config.TrafficResourceID, &config.CertSource, &config.CertID,
		&config.MinVersion, &config.MaxVersion, &config.CipherSuites, &config.PreferServerCiphers,
		&config.HSTSEnabled, &config.HSTSMaxAge, &config.HSTSIncludeSubdomains, &config.HSTSPreload,
		&config.OCSPStapling, &config.MTLSEnabled, &config.MTLSCACert, &config.MTLSVerifyDepth,
		&config.MTLSVerifyClient,
	)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// generateTrafficNginxConfig generates the nginx configuration string
func (h *Handler) generateTrafficNginxConfig(
	resource *TrafficResource,
	upstreams []TrafficUpstream,
	policies []TrafficPolicy,
	tlsConfig *TrafficTLSConfig,
) string {
	var config strings.Builder
	resourceIDShort := resource.ID.String()[:8]

	config.WriteString(fmt.Sprintf("# Traffic Resource: %s (%s)\n", resource.Name, resource.ID))
	config.WriteString(fmt.Sprintf("# Generated by InfraPilot Traffic Module\n\n"))

	// Generate rate limit zones for rate_limit policies
	for _, policy := range policies {
		if policy.PolicyType == "rate_limit" && policy.Enabled {
			zone := h.generateRateLimitZone(policy, resourceIDShort)
			if zone != "" {
				config.WriteString(zone)
				config.WriteString("\n")
			}
		}
	}

	// Generate upstream blocks
	for _, upstream := range upstreams {
		upstreamConfig := h.generateUpstreamBlock(upstream, resourceIDShort)
		config.WriteString(upstreamConfig)
		config.WriteString("\n")
	}

	// Generate server block
	serverBlock := h.generateServerBlock(resource, upstreams, policies, tlsConfig, resourceIDShort)
	config.WriteString(serverBlock)

	return config.String()
}

// generateRateLimitZone generates nginx rate limit zone configuration
func (h *Handler) generateRateLimitZone(policy TrafficPolicy, resourceID string) string {
	rps, _ := policy.Config["requests_per_second"].(float64)
	if rps == 0 {
		rps = 10 // default
	}

	key := "binary_remote_addr"
	if keyConfig, ok := policy.Config["key"].(string); ok {
		switch keyConfig {
		case "ip":
			key = "binary_remote_addr"
		case "uri":
			key = "request_uri"
		default:
			if strings.HasPrefix(keyConfig, "header:") {
				headerName := strings.TrimPrefix(keyConfig, "header:")
				key = fmt.Sprintf("http_%s", strings.ToLower(strings.ReplaceAll(headerName, "-", "_")))
			}
		}
	}

	zoneName := fmt.Sprintf("traffic_%s_%s", resourceID, policy.ID.String()[:8])
	return fmt.Sprintf("limit_req_zone $%s zone=%s:10m rate=%dr/s;\n", key, zoneName, int(rps))
}

// generateUpstreamBlock generates nginx upstream configuration
func (h *Handler) generateUpstreamBlock(upstream TrafficUpstream, resourceID string) string {
	var config strings.Builder
	upstreamName := fmt.Sprintf("traffic_%s_%s", resourceID, upstream.Name)

	config.WriteString(fmt.Sprintf("upstream %s {\n", upstreamName))

	// Load balancing method
	switch upstream.LBMethod {
	case "least_conn":
		config.WriteString("    least_conn;\n")
	case "ip_hash":
		config.WriteString("    ip_hash;\n")
	case "random":
		config.WriteString("    random;\n")
	// round_robin is default, no directive needed
	}

	// Server entries
	for _, target := range upstream.Targets {
		serverLine := fmt.Sprintf("    server %s:%d", target.Address, target.Port)
		if target.Weight > 1 {
			serverLine += fmt.Sprintf(" weight=%d", target.Weight)
		}
		if target.MaxFails > 0 {
			serverLine += fmt.Sprintf(" max_fails=%d", target.MaxFails)
		}
		if target.FailTimeoutSec > 0 {
			serverLine += fmt.Sprintf(" fail_timeout=%ds", target.FailTimeoutSec)
		}
		if !target.Enabled {
			serverLine += " down"
		}
		serverLine += ";\n"
		config.WriteString(serverLine)
	}

	// Keepalive connections
	if upstream.MaxKeepalive > 0 {
		config.WriteString(fmt.Sprintf("    keepalive %d;\n", upstream.MaxKeepalive))
	}

	config.WriteString("}\n")
	return config.String()
}

// generateServerBlock generates the nginx server block
func (h *Handler) generateServerBlock(
	resource *TrafficResource,
	upstreams []TrafficUpstream,
	policies []TrafficPolicy,
	tlsConfig *TrafficTLSConfig,
	resourceID string,
) string {
	var config strings.Builder
	domains := strings.Join(resource.Domains, " ")
	primaryDomain := resource.Domains[0]

	// Determine if SSL is enabled
	sslEnabled := tlsConfig != nil

	// HTTP server block (redirect to HTTPS if SSL enabled)
	config.WriteString("server {\n")
	config.WriteString("    listen 80;\n")
	config.WriteString("    listen [::]:80;\n")
	config.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))

	// Per-domain logging
	config.WriteString(fmt.Sprintf("    access_log /var/log/nginx/domains/%s.access.log combined;\n", primaryDomain))
	config.WriteString(fmt.Sprintf("    error_log /var/log/nginx/domains/%s.error.log warn;\n\n", primaryDomain))

	if sslEnabled {
		// ACME challenge location
		config.WriteString("    location /.well-known/acme-challenge/ {\n")
		config.WriteString("        root /var/www/certbot;\n")
		config.WriteString("    }\n\n")
		// Redirect to HTTPS
		config.WriteString("    location / {\n")
		config.WriteString("        return 301 https://$host$request_uri;\n")
		config.WriteString("    }\n")
	} else {
		// No SSL - serve directly
		config.WriteString(h.generateLocationBlocks(resource, upstreams, policies, resourceID))
	}
	config.WriteString("}\n\n")

	// HTTPS server block
	if sslEnabled {
		config.WriteString("server {\n")
		config.WriteString("    listen 443 ssl;\n")
		config.WriteString("    listen [::]:443 ssl;\n")
		config.WriteString("    http2 on;\n")
		config.WriteString(fmt.Sprintf("    server_name %s;\n\n", domains))

		// Per-domain logging
		config.WriteString(fmt.Sprintf("    access_log /var/log/nginx/domains/%s.access.log combined;\n", primaryDomain))
		config.WriteString(fmt.Sprintf("    error_log /var/log/nginx/domains/%s.error.log warn;\n\n", primaryDomain))

		// SSL certificate paths
		certPath := fmt.Sprintf("/etc/letsencrypt/live/%s/fullchain.pem", primaryDomain)
		keyPath := fmt.Sprintf("/etc/letsencrypt/live/%s/privkey.pem", primaryDomain)

		config.WriteString(fmt.Sprintf("    ssl_certificate %s;\n", certPath))
		config.WriteString(fmt.Sprintf("    ssl_certificate_key %s;\n\n", keyPath))

		// TLS settings
		minVersion := "TLSv1.2"
		maxVersion := "TLSv1.3"
		if tlsConfig != nil {
			if tlsConfig.MinVersion != "" {
				minVersion = tlsConfig.MinVersion
			}
			if tlsConfig.MaxVersion != "" {
				maxVersion = tlsConfig.MaxVersion
			}
		}
		config.WriteString(fmt.Sprintf("    ssl_protocols %s %s;\n", minVersion, maxVersion))
		config.WriteString("    ssl_prefer_server_ciphers on;\n")
		config.WriteString("    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n\n")

		// OCSP Stapling
		if tlsConfig == nil || tlsConfig.OCSPStapling {
			config.WriteString("    ssl_stapling on;\n")
			config.WriteString("    ssl_stapling_verify on;\n\n")
		}

		// HSTS
		if tlsConfig == nil || tlsConfig.HSTSEnabled {
			maxAge := 31536000
			if tlsConfig != nil && tlsConfig.HSTSMaxAge > 0 {
				maxAge = tlsConfig.HSTSMaxAge
			}
			hstsValue := fmt.Sprintf("max-age=%d", maxAge)
			if tlsConfig == nil || tlsConfig.HSTSIncludeSubdomains {
				hstsValue += "; includeSubDomains"
			}
			if tlsConfig != nil && tlsConfig.HSTSPreload {
				hstsValue += "; preload"
			}
			config.WriteString(fmt.Sprintf("    add_header Strict-Transport-Security \"%s\" always;\n\n", hstsValue))
		}

		// Security headers from policies
		config.WriteString(h.generateSecurityHeadersFromPolicies(policies))

		// Location blocks
		config.WriteString(h.generateLocationBlocks(resource, upstreams, policies, resourceID))

		config.WriteString("}\n")
	}

	return config.String()
}

// generateLocationBlocks generates nginx location blocks
func (h *Handler) generateLocationBlocks(
	resource *TrafficResource,
	upstreams []TrafficUpstream,
	policies []TrafficPolicy,
	resourceID string,
) string {
	var config strings.Builder

	// Determine upstream name
	upstreamName := "localhost:8080" // default
	if len(upstreams) > 0 {
		upstreamName = fmt.Sprintf("traffic_%s_%s", resourceID, upstreams[0].Name)
	}

	// Generate location blocks based on paths
	paths := resource.Paths
	if len(paths) == 0 {
		paths = []PathConfig{{Path: "/", Match: "prefix"}}
	}

	for _, pathCfg := range paths {
		locationDirective := "location "
		switch pathCfg.Match {
		case "exact":
			locationDirective += "= "
		case "regex":
			locationDirective += "~ "
		case "regex_insensitive":
			locationDirective += "~* "
		// prefix is default (no modifier)
		}
		locationDirective += pathCfg.Path

		config.WriteString(fmt.Sprintf("    %s {\n", locationDirective))

		// Rate limiting
		for _, policy := range policies {
			if policy.PolicyType == "rate_limit" && policy.Enabled {
				zoneName := fmt.Sprintf("traffic_%s_%s", resourceID, policy.ID.String()[:8])
				burst := 50
				if burstConfig, ok := policy.Config["burst_size"].(float64); ok {
					burst = int(burstConfig)
				}
				config.WriteString(fmt.Sprintf("        limit_req zone=%s burst=%d nodelay;\n", zoneName, burst))
			}
		}

		// IP filtering
		for _, policy := range policies {
			if policy.PolicyType == "ip_filtering" && policy.Enabled {
				config.WriteString(h.generateIPFilteringRules(policy))
			}
		}

		// Geo blocking
		for _, policy := range policies {
			if policy.PolicyType == "geo_blocking" && policy.Enabled {
				config.WriteString(h.generateGeoBlockingRules(policy))
			}
		}

		// Proxy settings
		if len(upstreams) > 0 {
			config.WriteString(fmt.Sprintf("        proxy_pass http://%s;\n", upstreamName))
		} else {
			// If no upstreams defined, use the first domain's desired upstream from desired_state
			if target, ok := resource.DesiredState["upstream_target"].(string); ok && target != "" {
				config.WriteString(fmt.Sprintf("        proxy_pass %s;\n", target))
			} else {
				config.WriteString("        proxy_pass http://localhost:8080;\n")
			}
		}

		config.WriteString("        proxy_http_version 1.1;\n")
		config.WriteString("        proxy_set_header Host $host;\n")
		config.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		config.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		config.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		config.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		config.WriteString("        proxy_set_header Connection \"upgrade\";\n")

		// Timeouts from upstream config
		if len(upstreams) > 0 {
			u := upstreams[0]
			config.WriteString(fmt.Sprintf("        proxy_connect_timeout %ds;\n", u.ConnectTimeoutSec))
			config.WriteString(fmt.Sprintf("        proxy_read_timeout %ds;\n", u.ReadTimeoutSec))
			config.WriteString(fmt.Sprintf("        proxy_send_timeout %ds;\n", u.SendTimeoutSec))
		}

		config.WriteString("    }\n\n")
	}

	return config.String()
}

// generateSecurityHeadersFromPolicies generates security headers from header_transform policies
func (h *Handler) generateSecurityHeadersFromPolicies(policies []TrafficPolicy) string {
	var config strings.Builder

	for _, policy := range policies {
		if policy.PolicyType == "header_transform" && policy.Enabled {
			if responseHeaders, ok := policy.Config["response_headers"].(map[string]interface{}); ok {
				if addHeaders, ok := responseHeaders["add"].(map[string]interface{}); ok {
					for name, value := range addHeaders {
						config.WriteString(fmt.Sprintf("    add_header %s \"%v\" always;\n", name, value))
					}
				}
			}
		}
	}

	// Default security headers if no policy defined
	if config.Len() == 0 {
		config.WriteString("    add_header X-Frame-Options \"SAMEORIGIN\" always;\n")
		config.WriteString("    add_header X-Content-Type-Options \"nosniff\" always;\n")
		config.WriteString("    add_header X-XSS-Protection \"1; mode=block\" always;\n")
	}

	config.WriteString("\n")
	return config.String()
}

// generateIPFilteringRules generates IP allow/deny rules
func (h *Handler) generateIPFilteringRules(policy TrafficPolicy) string {
	var config strings.Builder

	mode, _ := policy.Config["mode"].(string)
	rules, _ := policy.Config["rules"].([]interface{})

	for _, rule := range rules {
		if r, ok := rule.(map[string]interface{}); ok {
			cidr, _ := r["cidr"].(string)
			action, _ := r["action"].(string)

			if cidr != "" {
				if action == "allow" {
					config.WriteString(fmt.Sprintf("        allow %s;\n", cidr))
				} else {
					config.WriteString(fmt.Sprintf("        deny %s;\n", cidr))
				}
			}
		}
	}

	// Default action based on mode
	if mode == "allowlist" {
		config.WriteString("        deny all;\n")
	}

	return config.String()
}

// generateGeoBlockingRules generates geo-based blocking rules
func (h *Handler) generateGeoBlockingRules(policy TrafficPolicy) string {
	var config strings.Builder

	mode, _ := policy.Config["mode"].(string)
	countries, _ := policy.Config["countries"].([]interface{})

	if len(countries) == 0 {
		return ""
	}

	var countryList []string
	for _, c := range countries {
		if country, ok := c.(string); ok {
			countryList = append(countryList, country)
		}
	}

	if len(countryList) > 0 {
		pattern := strings.Join(countryList, "|")
		if mode == "allowlist" {
			config.WriteString(fmt.Sprintf("        if ($geoip_country_code !~ ^(%s)$) {\n", pattern))
			config.WriteString("            return 403;\n")
			config.WriteString("        }\n")
		} else {
			config.WriteString(fmt.Sprintf("        if ($geoip_country_code ~ ^(%s)$) {\n", pattern))
			config.WriteString("            return 403;\n")
			config.WriteString("        }\n")
		}
	}

	return config.String()
}
