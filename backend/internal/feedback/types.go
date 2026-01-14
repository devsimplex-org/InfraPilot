package feedback

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ==================== Core Types ====================

// SourceType represents the type of security finding
type SourceType string

const (
	SourceVulnerability   SourceType = "vulnerability"
	SourcePolicyViolation SourceType = "policy_violation"
	SourceSBOM            SourceType = "sbom"
	SourceDrift           SourceType = "drift"
	SourceCodeQuality     SourceType = "code_quality"
)

// DeliveryStatus represents the delivery state of feedback
type DeliveryStatus string

const (
	StatusPending   DeliveryStatus = "pending"
	StatusDelivered DeliveryStatus = "delivered"
	StatusFailed    DeliveryStatus = "failed"
	StatusSkipped   DeliveryStatus = "skipped"
)

// Provider represents a VCS provider
type Provider string

const (
	ProviderGitHub      Provider = "github"
	ProviderGitLab      Provider = "gitlab"
	ProviderBitbucket   Provider = "bitbucket"
	ProviderAzureDevOps Provider = "azure_devops"
)

// ==================== Feedback Model ====================

// Feedback represents a security finding to be delivered to developers
type Feedback struct {
	ID       uuid.UUID      `json:"id"`
	OrgID    uuid.UUID      `json:"org_id"`
	SourceID uuid.UUID      `json:"source_id"`
	Type     SourceType     `json:"source_type"`
	Target   Target         `json:"target"`
	Content  FeedbackContent `json:"content"`
	Status   DeliveryStatus `json:"delivery_status"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Delivery tracking
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
	DeliveryError *string    `json:"delivery_error,omitempty"`
	ExternalID    *string    `json:"external_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FeedbackContent contains the actual feedback message
type FeedbackContent struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// Target represents where to deliver the feedback (PR, commit, etc.)
type Target struct {
	Provider        Provider `json:"provider"`
	RepoFullName    string   `json:"repo_full_name"`  // e.g., "org/repo"
	PullRequest     *int     `json:"pull_request,omitempty"`
	CommitSHA       *string  `json:"commit_sha,omitempty"`
	BranchName      *string  `json:"branch_name,omitempty"`
}

// ==================== Configuration ====================

// VCSConfiguration represents VCS provider configuration
type VCSConfiguration struct {
	ID       uuid.UUID `json:"id"`
	OrgID    uuid.UUID `json:"org_id"`
	Provider Provider  `json:"provider"`
	Enabled  bool      `json:"enabled"`

	// Authentication (encrypted in DB)
	AuthType    string `json:"auth_type"`  // 'oauth', 'token', 'app'
	Credentials map[string]interface{} `json:"credentials"`

	// GitHub App specific
	AppID          *string `json:"app_id,omitempty"`
	InstallationID *string `json:"installation_id,omitempty"`

	// Settings
	DefaultRepo        *string `json:"default_repo,omitempty"`
	AutoCommentOnPR    bool    `json:"auto_comment_on_pr"`
	AutoCommentOnCommit bool   `json:"auto_comment_on_commit"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ==================== Template ====================

// FeedbackTemplate represents a customizable feedback template
type FeedbackTemplate struct {
	ID               uuid.UUID  `json:"id"`
	OrgID            uuid.UUID  `json:"org_id"`
	Name             string     `json:"name"`
	SourceType       SourceType `json:"source_type"`
	TitleTemplate    string     `json:"title_template"`
	MessageTemplate  string     `json:"message_template"`
	RemediationTemplate *string `json:"remediation_template,omitempty"`
	Enabled          bool       `json:"enabled"`
	SeverityThreshold *string   `json:"severity_threshold,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// ==================== Interfaces ====================

// Deliverer delivers feedback to a specific VCS provider
type Deliverer interface {
	// DeliverPRComment posts a comment on a pull request
	DeliverPRComment(ctx context.Context, target Target, content FeedbackContent) (externalID string, err error)

	// DeliverCommitComment posts a comment on a commit
	DeliverCommitComment(ctx context.Context, target Target, content FeedbackContent) (externalID string, err error)

	// UpdatePRStatus updates the status check on a PR
	UpdatePRStatus(ctx context.Context, target Target, status PRStatus) error

	// Provider returns the VCS provider this deliverer handles
	Provider() Provider
}

// PRStatus represents a PR status check
type PRStatus struct {
	State       string // "pending", "success", "failure", "error"
	Context     string // e.g., "infrapilot/security"
	Description string
	TargetURL   *string
}

// Manager manages feedback lifecycle
type Manager interface {
	// CreateFeedback creates a new feedback entry
	CreateFeedback(ctx context.Context, feedback *Feedback) error

	// DeliverFeedback delivers pending feedback
	DeliverFeedback(ctx context.Context, feedbackID uuid.UUID) error

	// DeliverAll delivers all pending feedback
	DeliverAll(ctx context.Context) error

	// GetFeedback retrieves feedback by ID
	GetFeedback(ctx context.Context, feedbackID uuid.UUID) (*Feedback, error)

	// ListFeedback lists feedback with filters
	ListFeedback(ctx context.Context, filters FeedbackFilters) ([]*Feedback, error)

	// GetConfiguration retrieves VCS configuration
	GetConfiguration(ctx context.Context, orgID uuid.UUID, provider Provider) (*VCSConfiguration, error)

	// SaveConfiguration saves or updates VCS configuration
	SaveConfiguration(ctx context.Context, config *VCSConfiguration) error
}

// FeedbackFilters for querying feedback
type FeedbackFilters struct {
	OrgID      *uuid.UUID
	SourceType *SourceType
	Status     *DeliveryStatus
	Repo       *string
	PRNumber   *int
	Limit      int
	Offset     int
}

// ==================== Template Data ====================

// VulnerabilityTemplateData is data passed to vulnerability feedback templates
type VulnerabilityTemplateData struct {
	CVEID              string
	Severity           string
	PackageName        string
	PackageVersion     string
	FixedVersion       *string
	Description        string
	AffectedDeployments int
	References         []string
}

// PolicyViolationTemplateData is data passed to policy violation templates
type PolicyViolationTemplateData struct {
	PolicyName string
	Severity   string
	Decision   string
	Reason     string
	Rule       string
}
