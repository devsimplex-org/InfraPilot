package api

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// TLSHealthResult represents the health status of a TLS certificate
type TLSHealthResult struct {
	Domain       string    `json:"domain"`
	ProxyID      string    `json:"proxy_id"`
	SSLEnabled   bool      `json:"ssl_enabled"`
	Valid        bool      `json:"valid"`
	Issuer       string    `json:"issuer,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	DaysLeft     int       `json:"days_left,omitempty"`
	Score        int       `json:"score"` // 0-100
	Status       string    `json:"status"` // healthy, warning, critical, expired, none
	ErrorMessage string    `json:"error_message,omitempty"`
}

// TLSHealthSummary provides overall TLS health
type TLSHealthSummary struct {
	TotalProxies   int               `json:"total_proxies"`
	SSLEnabled     int               `json:"ssl_enabled"`
	Healthy        int               `json:"healthy"`
	Warning        int               `json:"warning"`
	Critical       int               `json:"critical"`
	Expired        int               `json:"expired"`
	OverallScore   int               `json:"overall_score"`
	Certificates   []TLSHealthResult `json:"certificates"`
}

// getTLSHealth returns TLS certificate health for all proxies
func (h *Handler) getTLSHealth(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Get all proxy hosts with SSL
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT ph.id, ph.domain, ph.ssl_enabled, ph.ssl_expires_at
		FROM proxy_hosts ph
		JOIN agents a ON ph.agent_id = a.id
		WHERE a.org_id = $1
		ORDER BY ph.ssl_expires_at ASC NULLS LAST
	`, orgID)
	if err != nil {
		h.logger.Error("Failed to get proxies for TLS health", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get TLS health"})
		return
	}
	defer rows.Close()

	var results []TLSHealthResult
	summary := TLSHealthSummary{}

	for rows.Next() {
		var proxyID uuid.UUID
		var domain string
		var sslEnabled bool
		var sslExpiresAt *time.Time

		if err := rows.Scan(&proxyID, &domain, &sslEnabled, &sslExpiresAt); err != nil {
			continue
		}

		summary.TotalProxies++

		result := TLSHealthResult{
			Domain:     domain,
			ProxyID:    proxyID.String(),
			SSLEnabled: sslEnabled,
		}

		if !sslEnabled {
			result.Status = "none"
			result.Score = 0
			results = append(results, result)
			continue
		}

		summary.SSLEnabled++

		// Check certificate by connecting to the domain
		certInfo := checkCertificate(domain)
		result.Valid = certInfo.Valid
		result.Issuer = certInfo.Issuer
		result.ExpiresAt = certInfo.ExpiresAt
		result.ErrorMessage = certInfo.ErrorMessage

		if certInfo.Valid {
			result.DaysLeft = int(time.Until(certInfo.ExpiresAt).Hours() / 24)

			// Calculate score based on days left
			switch {
			case result.DaysLeft > 60:
				result.Score = 100
				result.Status = "healthy"
				summary.Healthy++
			case result.DaysLeft > 30:
				result.Score = 80
				result.Status = "healthy"
				summary.Healthy++
			case result.DaysLeft > 14:
				result.Score = 60
				result.Status = "warning"
				summary.Warning++
			case result.DaysLeft > 7:
				result.Score = 40
				result.Status = "warning"
				summary.Warning++
			case result.DaysLeft > 0:
				result.Score = 20
				result.Status = "critical"
				summary.Critical++
			default:
				result.Score = 0
				result.Status = "expired"
				summary.Expired++
			}
		} else {
			result.Score = 0
			result.Status = "critical"
			summary.Critical++
		}

		results = append(results, result)
	}

	// Calculate overall score
	if summary.SSLEnabled > 0 {
		totalScore := 0
		for _, r := range results {
			if r.SSLEnabled {
				totalScore += r.Score
			}
		}
		summary.OverallScore = totalScore / summary.SSLEnabled
	}

	summary.Certificates = results
	c.JSON(http.StatusOK, summary)
}

type certCheckResult struct {
	Valid        bool
	Issuer       string
	ExpiresAt    time.Time
	ErrorMessage string
}

func checkCertificate(domain string) certCheckResult {
	result := certCheckResult{}

	// Connect with TLS
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true, // We want to check even expired certs
	})
	if err != nil {
		result.ErrorMessage = "Failed to connect: " + err.Error()
		return result
	}
	defer conn.Close()

	// Get certificate info
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.ErrorMessage = "No certificates found"
		return result
	}

	cert := certs[0]
	result.ExpiresAt = cert.NotAfter
	result.Issuer = cert.Issuer.CommonName

	// Check if still valid
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		result.ErrorMessage = "Certificate expired or not yet valid"
		return result
	}

	result.Valid = true
	return result
}

// DatabaseHealth represents database health metrics
type DatabaseHealth struct {
	Status          string  `json:"status"` // healthy, degraded, unhealthy
	Connected       bool    `json:"connected"`
	Latency         float64 `json:"latency_ms"`
	ActiveConns     int     `json:"active_connections"`
	MaxConns        int     `json:"max_connections"`
	IdleConns       int     `json:"idle_connections"`
	WaitingQueries  int     `json:"waiting_queries"`
	DatabaseSize    string  `json:"database_size,omitempty"`
	TableCount      int     `json:"table_count"`
	Score           int     `json:"score"` // 0-100
}

// getDBHealth returns database health metrics
func (h *Handler) getDBHealth(c *gin.Context) {
	ctx := c.Request.Context()

	health := DatabaseHealth{
		Connected: true,
	}

	// Check latency with a simple query
	start := time.Now()
	var one int
	err := h.db.QueryRow(ctx, "SELECT 1").Scan(&one)
	health.Latency = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		health.Connected = false
		health.Status = "unhealthy"
		health.Score = 0
		c.JSON(http.StatusOK, health)
		return
	}

	// Get connection pool stats
	stats := h.db.Stat()
	health.ActiveConns = int(stats.AcquiredConns())
	health.MaxConns = int(stats.MaxConns())
	health.IdleConns = int(stats.IdleConns())

	// Get database size
	var dbSize string
	h.db.QueryRow(ctx, "SELECT pg_size_pretty(pg_database_size(current_database()))").Scan(&dbSize)
	health.DatabaseSize = dbSize

	// Get table count
	var tableCount int
	h.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
	`).Scan(&tableCount)
	health.TableCount = tableCount

	// Calculate score
	score := 100

	// Latency scoring
	if health.Latency > 100 {
		score -= 30
	} else if health.Latency > 50 {
		score -= 15
	} else if health.Latency > 20 {
		score -= 5
	}

	// Connection pool scoring
	connUsage := float64(health.ActiveConns) / float64(health.MaxConns)
	if connUsage > 0.9 {
		score -= 30
	} else if connUsage > 0.7 {
		score -= 15
	} else if connUsage > 0.5 {
		score -= 5
	}

	if score < 0 {
		score = 0
	}

	health.Score = score

	// Determine status
	switch {
	case score >= 80:
		health.Status = "healthy"
	case score >= 50:
		health.Status = "degraded"
	default:
		health.Status = "unhealthy"
	}

	c.JSON(http.StatusOK, health)
}

// SystemHealth provides overall system health
type SystemHealth struct {
	Status     string  `json:"status"`
	Uptime     string  `json:"uptime"`
	GoRoutines int     `json:"goroutines"`
	MemoryMB   float64 `json:"memory_mb"`
	CPUCores   int     `json:"cpu_cores"`
}

var startTime = time.Now()

// getSystemHealth returns system health metrics
func (h *Handler) getSystemHealth(c *gin.Context) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	uptime := time.Since(startTime)
	uptimeStr := formatDuration(uptime)

	health := SystemHealth{
		Status:     "healthy",
		Uptime:     uptimeStr,
		GoRoutines: runtime.NumGoroutine(),
		MemoryMB:   float64(m.Alloc) / 1024 / 1024,
		CPUCores:   runtime.NumCPU(),
	}

	c.JSON(http.StatusOK, health)
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
