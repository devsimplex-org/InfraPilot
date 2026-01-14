package feedback

import (
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// TemplateRenderer renders feedback templates
type TemplateRenderer struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

// NewTemplateRenderer creates a new template renderer
func NewTemplateRenderer(db *pgxpool.Pool, logger *zap.Logger) *TemplateRenderer {
	return &TemplateRenderer{
		db:     db,
		logger: logger,
	}
}

// RenderFeedback renders feedback content using templates
func (r *TemplateRenderer) RenderFeedback(ctx context.Context, orgID uuid.UUID, sourceType SourceType, data interface{}) (*FeedbackContent, error) {
	// Get template for source type
	tmpl, err := r.getTemplate(ctx, orgID, sourceType)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	if tmpl == nil {
		return nil, fmt.Errorf("no template found for source type: %s", sourceType)
	}

	// Render title
	title, err := r.renderString(tmpl.TitleTemplate, data)
	if err != nil {
		return nil, fmt.Errorf("failed to render title: %w", err)
	}

	// Render message
	message, err := r.renderString(tmpl.MessageTemplate, data)
	if err != nil {
		return nil, fmt.Errorf("failed to render message: %w", err)
	}

	// Render remediation (optional)
	var remediation string
	if tmpl.RemediationTemplate != nil {
		remediation, err = r.renderString(*tmpl.RemediationTemplate, data)
		if err != nil {
			r.logger.Warn("failed to render remediation", zap.Error(err))
		}
	}

	// Extract severity from data if available
	severity := "unknown"
	if v, ok := data.(interface{ GetSeverity() string }); ok {
		severity = v.GetSeverity()
	} else if m, ok := data.(map[string]interface{}); ok {
		if s, ok := m["Severity"].(string); ok {
			severity = s
		}
	}

	content := &FeedbackContent{
		Severity:    severity,
		Title:       title,
		Message:     message,
		Remediation: remediation,
	}

	return content, nil
}

// RenderVulnerabilityFeedback renders feedback for a vulnerability
func (r *TemplateRenderer) RenderVulnerabilityFeedback(ctx context.Context, orgID uuid.UUID, data *VulnerabilityTemplateData) (*FeedbackContent, error) {
	content, err := r.RenderFeedback(ctx, orgID, SourceVulnerability, data)
	if err != nil {
		return nil, err
	}

	// Override severity from vulnerability data
	content.Severity = data.Severity

	return content, nil
}

// RenderPolicyViolationFeedback renders feedback for a policy violation
func (r *TemplateRenderer) RenderPolicyViolationFeedback(ctx context.Context, orgID uuid.UUID, data *PolicyViolationTemplateData) (*FeedbackContent, error) {
	content, err := r.RenderFeedback(ctx, orgID, SourcePolicyViolation, data)
	if err != nil {
		return nil, err
	}

	// Override severity from policy data
	content.Severity = data.Severity

	return content, nil
}

// getTemplate retrieves the template for a source type
func (r *TemplateRenderer) getTemplate(ctx context.Context, orgID uuid.UUID, sourceType SourceType) (*FeedbackTemplate, error) {
	query := `
		SELECT
			id, org_id, name, source_type,
			title_template, message_template, remediation_template,
			enabled, severity_threshold,
			created_at, updated_at
		FROM feedback_templates
		WHERE org_id = $1
		  AND source_type = $2
		  AND enabled = true
		ORDER BY created_at DESC
		LIMIT 1
	`

	var tmpl FeedbackTemplate

	err := r.db.QueryRow(ctx, query, orgID, sourceType).Scan(
		&tmpl.ID, &tmpl.OrgID, &tmpl.Name, &tmpl.SourceType,
		&tmpl.TitleTemplate, &tmpl.MessageTemplate, &tmpl.RemediationTemplate,
		&tmpl.Enabled, &tmpl.SeverityThreshold,
		&tmpl.CreatedAt, &tmpl.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query template: %w", err)
	}

	return &tmpl, nil
}

// renderString renders a template string with the given data
func (r *TemplateRenderer) renderString(templateStr string, data interface{}) (string, error) {
	// Create template
	tmpl, err := template.New("feedback").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// CreateDefaultTemplates creates default templates for an organization
func (r *TemplateRenderer) CreateDefaultTemplates(ctx context.Context, orgID uuid.UUID) error {
	templates := []struct {
		Name                string
		SourceType          SourceType
		TitleTemplate       string
		MessageTemplate     string
		RemediationTemplate *string
		SeverityThreshold   *string
	}{
		{
			Name:       "default-vulnerability",
			SourceType: SourceVulnerability,
			TitleTemplate: "🔒 Security: {{.Severity}} severity vulnerability detected in {{.PackageName}}",
			MessageTemplate: `## Security Vulnerability Detected

**CVE:** {{.CVEID}}
**Severity:** {{.Severity}}
**Package:** {{.PackageName}}@{{.PackageVersion}}

### Description
{{.Description}}

### Impact
This vulnerability affects {{.AffectedDeployments}} deployment(s) in your infrastructure.

---
*Detected by InfraPilot Supply Chain Security*`,
			RemediationTemplate: stringPtr(`### Remediation
{{if .FixedVersion}}✅ **Fixed in version:** {{.FixedVersion}}

Update {{.PackageName}} to version {{.FixedVersion}} or later.
{{else}}⚠️ No fix currently available. Consider:
- Using an alternative package
- Requesting a risk exception if acceptable
- Monitoring for updates{{end}}`),
			SeverityThreshold: stringPtr("medium"),
		},
		{
			Name:       "default-policy",
			SourceType: SourcePolicyViolation,
			TitleTemplate: "⚠️ Policy Violation: {{.PolicyName}}",
			MessageTemplate: `## Policy Violation

**Policy:** {{.PolicyName}}
**Severity:** {{.Severity}}
**Decision:** {{.Decision}}

### Details
{{.Reason}}

---
*Enforced by InfraPilot Policy Engine*`,
			RemediationTemplate: stringPtr(`### Next Steps
1. Review the policy requirements
2. Update your deployment to comply
3. If this is a false positive, request a risk exception
4. Contact your security team for guidance`),
		},
	}

	for _, t := range templates {
		query := `
			INSERT INTO feedback_templates (
				org_id, name, source_type,
				title_template, message_template, remediation_template,
				enabled, severity_threshold
			) VALUES (
				$1, $2, $3, $4, $5, $6, true, $7
			)
			ON CONFLICT (org_id, source_type, name) DO NOTHING
		`

		_, err := r.db.Exec(ctx, query,
			orgID, t.Name, t.SourceType,
			t.TitleTemplate, t.MessageTemplate, t.RemediationTemplate,
			t.SeverityThreshold,
		)
		if err != nil {
			return fmt.Errorf("failed to create template %s: %w", t.Name, err)
		}

		r.logger.Info("created default template",
			zap.String("org_id", orgID.String()),
			zap.String("name", t.Name),
		)
	}

	return nil
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}
