package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// DefaultPage represents a default page configuration
type DefaultPage struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	PageType  string    `json:"page_type"`
	Enabled   bool      `json:"enabled"`
	Title     string    `json:"title"`
	Heading   string    `json:"heading"`
	Message   string    `json:"message"`
	ShowLogo  bool      `json:"show_logo"`
	CustomCSS *string   `json:"custom_css,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Default templates for each page type
var defaultPageTemplates = map[string]DefaultPage{
	"welcome": {
		PageType: "welcome",
		Title:    "Welcome",
		Heading:  "Welcome",
		Message:  "This site is being configured. Please check back soon.",
		ShowLogo: true,
	},
	"404": {
		PageType: "404",
		Title:    "Page Not Found",
		Heading:  "404",
		Message:  "The page you're looking for doesn't exist.",
		ShowLogo: true,
	},
	"500": {
		PageType: "500",
		Title:    "Server Error",
		Heading:  "500",
		Message:  "An internal server error occurred. Please try again later.",
		ShowLogo: true,
	},
	"502": {
		PageType: "502",
		Title:    "Bad Gateway",
		Heading:  "502",
		Message:  "The server is temporarily unavailable. Please try again later.",
		ShowLogo: true,
	},
	"503": {
		PageType: "503",
		Title:    "Service Unavailable",
		Heading:  "503",
		Message:  "The service is temporarily unavailable. Please try again later.",
		ShowLogo: true,
	},
	"maintenance": {
		PageType: "maintenance",
		Title:    "Maintenance",
		Heading:  "Under Maintenance",
		Message:  "We're performing scheduled maintenance. We'll be back shortly.",
		ShowLogo: true,
	},
}

// listDefaultPages returns all default pages for the organization
func (h *Handler) listDefaultPages(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, page_type, enabled, title, heading, message, show_logo, custom_css, created_at, updated_at
		FROM default_pages
		WHERE org_id = $1
		ORDER BY page_type
	`, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch default pages"})
		return
	}
	defer rows.Close()

	// Start with all templates
	pages := make(map[string]DefaultPage)
	for pageType, template := range defaultPageTemplates {
		page := template
		page.OrgID = orgID
		pages[pageType] = page
	}

	// Override with saved pages
	for rows.Next() {
		var page DefaultPage
		if err := rows.Scan(&page.ID, &page.OrgID, &page.PageType, &page.Enabled, &page.Title, &page.Heading, &page.Message, &page.ShowLogo, &page.CustomCSS, &page.CreatedAt, &page.UpdatedAt); err != nil {
			continue
		}
		pages[page.PageType] = page
	}

	// Convert to slice
	result := make([]DefaultPage, 0, len(pages))
	for _, page := range pages {
		result = append(result, page)
	}

	c.JSON(http.StatusOK, result)
}

// getDefaultPage returns a specific default page
func (h *Handler) getDefaultPage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	pageType := c.Param("type")

	// Validate page type
	template, ok := defaultPageTemplates[pageType]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid page type"})
		return
	}

	var page DefaultPage
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, page_type, enabled, title, heading, message, show_logo, custom_css, created_at, updated_at
		FROM default_pages
		WHERE org_id = $1 AND page_type = $2
	`, orgID, pageType).Scan(&page.ID, &page.OrgID, &page.PageType, &page.Enabled, &page.Title, &page.Heading, &page.Message, &page.ShowLogo, &page.CustomCSS, &page.CreatedAt, &page.UpdatedAt)

	if err != nil {
		// Return default template if not found
		page = template
		page.OrgID = orgID
	}

	c.JSON(http.StatusOK, page)
}

// UpdateDefaultPageRequest is the request body for updating a default page
type UpdateDefaultPageRequest struct {
	Enabled   *bool   `json:"enabled"`
	Title     *string `json:"title"`
	Heading   *string `json:"heading"`
	Message   *string `json:"message"`
	ShowLogo  *bool   `json:"show_logo"`
	CustomCSS *string `json:"custom_css"`
}

// updateDefaultPage updates a default page configuration
func (h *Handler) updateDefaultPage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	pageType := c.Param("type")

	// Validate page type
	template, ok := defaultPageTemplates[pageType]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid page type"})
		return
	}

	var req UpdateDefaultPageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get current page or use template
	var currentPage DefaultPage
	var pageID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, enabled, title, heading, message, show_logo, custom_css
		FROM default_pages
		WHERE org_id = $1 AND page_type = $2
	`, orgID, pageType).Scan(&pageID, &currentPage.Enabled, &currentPage.Title, &currentPage.Heading, &currentPage.Message, &currentPage.ShowLogo, &currentPage.CustomCSS)

	if err != nil {
		// Page doesn't exist, use template defaults
		currentPage = template
	}

	// Apply updates
	if req.Enabled != nil {
		currentPage.Enabled = *req.Enabled
	}
	if req.Title != nil {
		currentPage.Title = *req.Title
	}
	if req.Heading != nil {
		currentPage.Heading = *req.Heading
	}
	if req.Message != nil {
		currentPage.Message = *req.Message
	}
	if req.ShowLogo != nil {
		currentPage.ShowLogo = *req.ShowLogo
	}
	if req.CustomCSS != nil {
		currentPage.CustomCSS = req.CustomCSS
	}

	// Upsert the page
	var resultPage DefaultPage
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO default_pages (org_id, page_type, enabled, title, heading, message, show_logo, custom_css)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (org_id, page_type) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			title = EXCLUDED.title,
			heading = EXCLUDED.heading,
			message = EXCLUDED.message,
			show_logo = EXCLUDED.show_logo,
			custom_css = EXCLUDED.custom_css,
			updated_at = NOW()
		RETURNING id, org_id, page_type, enabled, title, heading, message, show_logo, custom_css, created_at, updated_at
	`, orgID, pageType, currentPage.Enabled, currentPage.Title, currentPage.Heading, currentPage.Message, currentPage.ShowLogo, currentPage.CustomCSS).Scan(
		&resultPage.ID, &resultPage.OrgID, &resultPage.PageType, &resultPage.Enabled, &resultPage.Title,
		&resultPage.Heading, &resultPage.Message, &resultPage.ShowLogo, &resultPage.CustomCSS,
		&resultPage.CreatedAt, &resultPage.UpdatedAt,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update default page"})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "settings.default_pages.update", "default_pages", resultPage.ID, req)

	c.JSON(http.StatusOK, resultPage)
}

// previewDefaultPage returns the rendered HTML for a default page
func (h *Handler) previewDefaultPage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	pageType := c.Param("type")

	// Validate page type
	template, ok := defaultPageTemplates[pageType]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid page type"})
		return
	}

	var page DefaultPage
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, page_type, enabled, title, heading, message, show_logo, custom_css, created_at, updated_at
		FROM default_pages
		WHERE org_id = $1 AND page_type = $2
	`, orgID, pageType).Scan(&page.ID, &page.OrgID, &page.PageType, &page.Enabled, &page.Title, &page.Heading, &page.Message, &page.ShowLogo, &page.CustomCSS, &page.CreatedAt, &page.UpdatedAt)

	if err != nil {
		page = template
	}

	html := generateDefaultPageHTML(page)
	c.JSON(http.StatusOK, gin.H{"html": html})
}

// generateDefaultPageHTML creates clean HTML for a default page
func generateDefaultPageHTML(page DefaultPage) string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>`)
	b.WriteString(page.Title)
	b.WriteString(`</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            padding: 20px;
        }
        .container {
            text-align: center;
            max-width: 600px;
        }
        .heading {
            font-size: 6rem;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 1rem;
        }
        .message {
            font-size: 1.25rem;
            color: rgba(255,255,255,0.7);
            line-height: 1.6;
        }
        .logo {
            width: 64px;
            height: 64px;
            margin-bottom: 2rem;
            opacity: 0.8;
        }
`)

	// Add custom CSS if present
	if page.CustomCSS != nil && *page.CustomCSS != "" {
		b.WriteString(*page.CustomCSS)
	}

	b.WriteString(`
    </style>
</head>
<body>
    <div class="container">
`)

	if page.ShowLogo {
		b.WriteString(`        <svg class="logo" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 2L2 7L12 12L22 7L12 2Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M2 17L12 22L22 17" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M2 12L12 17L22 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
`)
	}

	b.WriteString(fmt.Sprintf(`        <h1 class="heading">%s</h1>
        <p class="message">%s</p>
    </div>
</body>
</html>`, page.Heading, page.Message))

	return b.String()
}
