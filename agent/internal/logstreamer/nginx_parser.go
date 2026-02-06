package logstreamer

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NginxLogEntry represents a parsed nginx access log entry
type NginxLogEntry struct {
	Time          time.Time `json:"time"`
	ClientIP      string    `json:"client_ip"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	QueryString   string    `json:"query_string,omitempty"`
	Protocol      string    `json:"protocol,omitempty"`
	StatusCode    int       `json:"status_code"`
	ResponseBytes int64     `json:"response_bytes"`
	ResponseTime  float64   `json:"response_time,omitempty"` // in seconds
	Host          string    `json:"host,omitempty"`
	Referer       string    `json:"referer,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	Upstream      string    `json:"upstream,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
}

// NginxLogParser parses nginx access log lines
type NginxLogParser struct {
	// Combined log format regex:
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
	combinedRegex *regexp.Regexp

	// Extended log format regex (includes response time and host):
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time "$host" "$upstream_addr"
	extendedRegex *regexp.Regexp
}

// NewNginxLogParser creates a new nginx log parser
func NewNginxLogParser() *NginxLogParser {
	// Combined log format pattern
	// Example: 192.168.1.1 - - [02/Feb/2026:10:00:00 +0000] "GET /api/health HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
	combinedPattern := `^(\S+)\s+` + // remote_addr
		`\S+\s+` + // remote_user (usually -)
		`(\S+)\s+` + // authenticated user (usually -)
		`\[([^\]]+)\]\s+` + // time_local
		`"([A-Z]+)\s+([^\s"?]+)(\?[^\s"]*)?(?:\s+([^"]*))?"\s+` + // request (method, path, query, protocol)
		`(\d+)\s+` + // status
		`(\d+|-)\s*` + // body_bytes_sent
		`"([^"]*)"\s*` + // referer
		`"([^"]*)"` // user_agent

	// Extended log format pattern (includes response time, host, and upstream)
	// Example: 192.168.1.1 - - [02/Feb/2026:10:00:00 +0000] "GET /api/health HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0" 0.042 "example.com" "127.0.0.1:8080"
	extendedPattern := `^(\S+)\s+` + // remote_addr
		`\S+\s+` + // remote_user (usually -)
		`(\S+)\s+` + // authenticated user (usually -)
		`\[([^\]]+)\]\s+` + // time_local
		`"([A-Z]+)\s+([^\s"?]+)(\?[^\s"]*)?(?:\s+([^"]*))?"\s+` + // request (method, path, query, protocol)
		`(\d+)\s+` + // status
		`(\d+|-)\s+` + // body_bytes_sent
		`"([^"]*)"\s+` + // referer
		`"([^"]*)"\s+` + // user_agent
		`(\d+\.?\d*|-)\s*` + // request_time
		`(?:"([^"]*)"\s*)?` + // host (optional)
		`(?:"([^"]*)")?` // upstream_addr (optional)

	return &NginxLogParser{
		combinedRegex: regexp.MustCompile(combinedPattern),
		extendedRegex: regexp.MustCompile(extendedPattern),
	}
}

// Parse parses a single nginx access log line
func (p *NginxLogParser) Parse(line string) (*NginxLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	// Try extended format first
	if entry := p.parseExtended(line); entry != nil {
		return entry, nil
	}

	// Fall back to combined format
	if entry := p.parseCombined(line); entry != nil {
		return entry, nil
	}

	return nil, nil // Unable to parse, skip silently
}

// parseCombined parses a line in nginx combined log format
func (p *NginxLogParser) parseCombined(line string) *NginxLogEntry {
	matches := p.combinedRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	entry := &NginxLogEntry{
		ClientIP:    matches[1],
		Method:      matches[4],
		Path:        matches[5],
		QueryString: strings.TrimPrefix(matches[6], "?"),
		Protocol:    matches[7],
		Referer:     cleanDash(matches[10]),
		UserAgent:   matches[11],
	}

	// Parse time
	entry.Time = parseNginxTime(matches[3])

	// Parse status code
	entry.StatusCode, _ = strconv.Atoi(matches[8])

	// Parse response bytes
	if matches[9] != "-" {
		entry.ResponseBytes, _ = strconv.ParseInt(matches[9], 10, 64)
	}

	return entry
}

// parseExtended parses a line in extended log format with response time
func (p *NginxLogParser) parseExtended(line string) *NginxLogEntry {
	matches := p.extendedRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	entry := &NginxLogEntry{
		ClientIP:    matches[1],
		Method:      matches[4],
		Path:        matches[5],
		QueryString: strings.TrimPrefix(matches[6], "?"),
		Protocol:    matches[7],
		Referer:     cleanDash(matches[10]),
		UserAgent:   matches[11],
	}

	// Parse time
	entry.Time = parseNginxTime(matches[3])

	// Parse status code
	entry.StatusCode, _ = strconv.Atoi(matches[8])

	// Parse response bytes
	if matches[9] != "-" {
		entry.ResponseBytes, _ = strconv.ParseInt(matches[9], 10, 64)
	}

	// Parse response time (in seconds)
	if len(matches) > 12 && matches[12] != "-" && matches[12] != "" {
		entry.ResponseTime, _ = strconv.ParseFloat(matches[12], 64)
	}

	// Parse host
	if len(matches) > 13 {
		entry.Host = cleanDash(matches[13])
	}

	// Parse upstream
	if len(matches) > 14 {
		entry.Upstream = cleanDash(matches[14])
	}

	return entry
}

// parseNginxTime parses nginx time format: 02/Feb/2026:10:00:00 +0000
func parseNginxTime(timeStr string) time.Time {
	// Nginx time format
	layout := "02/Jan/2006:15:04:05 -0700"
	t, err := time.Parse(layout, timeStr)
	if err != nil {
		// Try without timezone
		layout = "02/Jan/2006:15:04:05"
		t, err = time.Parse(layout, timeStr)
		if err != nil {
			return time.Now()
		}
	}
	return t
}

// cleanDash returns empty string if value is "-"
func cleanDash(value string) string {
	if value == "-" {
		return ""
	}
	return value
}

// ParseRequestLine parses a request line like "GET /path?query HTTP/1.1"
func ParseRequestLine(requestLine string) (method, path, query, protocol string) {
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return
	}

	method = parts[0]

	// Split path and query
	pathParts := strings.SplitN(parts[1], "?", 2)
	path = pathParts[0]
	if len(pathParts) > 1 {
		query = pathParts[1]
	}

	if len(parts) > 2 {
		protocol = parts[2]
	}

	return
}

// IsHealthCheck returns true if the request looks like a health check
func IsHealthCheck(path, userAgent string) bool {
	// Common health check paths
	healthPaths := []string{"/health", "/healthz", "/ready", "/readyz", "/ping", "/status", "/_health"}
	for _, hp := range healthPaths {
		if path == hp || strings.HasPrefix(path, hp+"?") {
			return true
		}
	}

	// Common health check user agents (only automated/internal probes)
	healthAgents := []string{"kube-probe", "GoogleHC", "ELB-HealthChecker"}
	for _, ha := range healthAgents {
		if strings.Contains(strings.ToLower(userAgent), strings.ToLower(ha)) {
			return true
		}
	}

	return false
}

// NormalizePath normalizes a URL path for grouping (e.g., /users/123 -> /users/:id)
func NormalizePath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}

		// Check if this looks like an ID (UUID, numeric, or alphanumeric ID)
		if isLikelyID(part) {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

// isLikelyID checks if a path segment looks like an ID
func isLikelyID(segment string) bool {
	// Pure numeric
	if _, err := strconv.ParseInt(segment, 10, 64); err == nil {
		return true
	}

	// UUID format (with or without dashes)
	if len(segment) == 36 || len(segment) == 32 {
		uuidRegex := regexp.MustCompile(`^[a-fA-F0-9-]{32,36}$`)
		if uuidRegex.MatchString(segment) {
			return true
		}
	}

	// Alphanumeric ID (looks like MongoDB ObjectId or similar)
	if len(segment) >= 12 && len(segment) <= 32 {
		alnumRegex := regexp.MustCompile(`^[a-fA-F0-9]+$`)
		if alnumRegex.MatchString(segment) {
			return true
		}
	}

	return false
}
