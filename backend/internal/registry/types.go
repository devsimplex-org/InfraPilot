package registry

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Provider represents a container registry provider
type Provider string

const (
	ProviderGHCR      Provider = "ghcr"
	ProviderDockerHub Provider = "dockerhub"
	ProviderECR       Provider = "ecr" // AWS Elastic Container Registry
	ProviderGCR       Provider = "gcr" // Google Container Registry / Artifact Registry
	ProviderACR       Provider = "acr" // Azure Container Registry
)

// AuthType represents the authentication method
type AuthType string

const (
	AuthTypeToken            AuthType = "token"
	AuthTypeUsernamePassword AuthType = "username_password"
)

// ConnectionStatus represents the registry connection status
type ConnectionStatus string

const (
	StatusPending   ConnectionStatus = "pending"
	StatusConnected ConnectionStatus = "connected"
	StatusFailed    ConnectionStatus = "failed"
)

// Registry represents a container registry connection
type Registry struct {
	ID                   uuid.UUID        `json:"id"`
	OrgID                uuid.UUID        `json:"org_id"`
	Name                 string           `json:"name"`
	Provider             Provider         `json:"provider"`
	Enabled              bool             `json:"enabled"`
	AuthType             AuthType         `json:"auth_type"`
	CredentialsEncrypted []byte           `json:"-"` // Never expose in JSON
	Namespace            *string          `json:"namespace,omitempty"`
	ConnectionStatus     ConnectionStatus `json:"connection_status"`
	ConnectionError      *string          `json:"connection_error,omitempty"`
	LastConnectedAt      *time.Time       `json:"last_connected_at,omitempty"`
	CreatedAt            time.Time        `json:"created_at"`
	UpdatedAt            time.Time        `json:"updated_at"`
	CreatedBy            *uuid.UUID       `json:"created_by,omitempty"`
}

// Credentials holds decrypted credential data
type Credentials struct {
	// For token-based auth (GHCR)
	Token string `json:"token,omitempty"`

	// For username/password auth (Docker Hub)
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// AWS ECR credentials
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	AWSRegion          string `json:"aws_region,omitempty"`
	AWSAccountID       string `json:"aws_account_id,omitempty"`

	// GCP GCR/Artifact Registry credentials
	GCPServiceAccountJSON string `json:"gcp_service_account_json,omitempty"`
	GCPProjectID          string `json:"gcp_project_id,omitempty"`

	// Azure ACR credentials
	AzureTenantID     string `json:"azure_tenant_id,omitempty"`
	AzureClientID     string `json:"azure_client_id,omitempty"`
	AzureClientSecret string `json:"azure_client_secret,omitempty"`
	AzureRegistryName string `json:"azure_registry_name,omitempty"`
}

// Repository represents a container repository
type Repository struct {
	Name            string  `json:"name"`
	FullName        string  `json:"full_name"`
	Description     *string `json:"description,omitempty"`
	IsPrivate       bool    `json:"is_private"`
	PullCount       int64   `json:"pull_count"`
	UpdatedAt       *string `json:"updated_at,omitempty"`
	// Internal: used for namespace filtering, not serialised to API consumers
	Owner           string  `json:"-"`
	NamespacedOwner string  `json:"-"`
}

// Tag represents a container image tag
type Tag struct {
	Name      string  `json:"name"`
	Digest    *string `json:"digest,omitempty"`
	SizeBytes int64   `json:"size_bytes"`
	PushedAt  *string `json:"pushed_at,omitempty"`
}

// ListRepositoriesResponse contains paginated repository results
type ListRepositoriesResponse struct {
	Repositories []Repository `json:"repositories"`
	TotalCount   int          `json:"total_count"`
	Page         int          `json:"page"`
	PageSize     int          `json:"page_size"`
}

// ListTagsResponse contains paginated tag results
type ListTagsResponse struct {
	Tags       []Tag  `json:"tags"`
	TotalCount int    `json:"total_count"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
}

// Client defines the interface for registry clients
type Client interface {
	// TestConnection tests the connection to the registry
	TestConnection(ctx context.Context) error

	// ListRepositories lists repositories with pagination
	ListRepositories(ctx context.Context, page, pageSize int) (*ListRepositoriesResponse, error)

	// ListTags lists tags for a repository with pagination
	ListTags(ctx context.Context, repository string, page, pageSize int) (*ListTagsResponse, error)

	// Provider returns the provider type
	Provider() Provider
}

// CreateRegistryRequest represents a request to create a registry
type CreateRegistryRequest struct {
	Name      string   `json:"name" binding:"required,min=1,max=100"`
	Provider  Provider `json:"provider" binding:"required,oneof=ghcr dockerhub ecr gcr acr"`
	Namespace *string  `json:"namespace,omitempty"`

	// Token-based auth (GHCR)
	Token *string `json:"token,omitempty"`

	// Username/password auth (Docker Hub)
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`

	// AWS ECR credentials
	AWSAccessKeyID     *string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey *string `json:"aws_secret_access_key,omitempty"`
	AWSRegion          *string `json:"aws_region,omitempty"`
	AWSAccountID       *string `json:"aws_account_id,omitempty"`

	// GCP GCR/Artifact Registry credentials
	GCPServiceAccountJSON *string `json:"gcp_service_account_json,omitempty"`
	GCPProjectID          *string `json:"gcp_project_id,omitempty"`

	// Azure ACR credentials
	AzureTenantID     *string `json:"azure_tenant_id,omitempty"`
	AzureClientID     *string `json:"azure_client_id,omitempty"`
	AzureClientSecret *string `json:"azure_client_secret,omitempty"`
	AzureRegistryName *string `json:"azure_registry_name,omitempty"`
}

// UpdateRegistryRequest represents a request to update a registry
type UpdateRegistryRequest struct {
	Name      *string `json:"name,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
	Namespace *string `json:"namespace,omitempty"`

	// Token-based auth (GHCR)
	Token *string `json:"token,omitempty"`

	// Username/password auth (Docker Hub)
	Username *string `json:"username,omitempty"`
	Password *string `json:"password,omitempty"`
}

// RegistryResponse is the API response for a registry (excludes credentials)
type RegistryResponse struct {
	ID               uuid.UUID        `json:"id"`
	Name             string           `json:"name"`
	Provider         Provider         `json:"provider"`
	Enabled          bool             `json:"enabled"`
	Namespace        *string          `json:"namespace,omitempty"`
	ConnectionStatus ConnectionStatus `json:"connection_status"`
	ConnectionError  *string          `json:"connection_error,omitempty"`
	LastConnectedAt  *time.Time       `json:"last_connected_at,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
}

// ToResponse converts a Registry to a RegistryResponse
func (r *Registry) ToResponse() *RegistryResponse {
	return &RegistryResponse{
		ID:               r.ID,
		Name:             r.Name,
		Provider:         r.Provider,
		Enabled:          r.Enabled,
		Namespace:        r.Namespace,
		ConnectionStatus: r.ConnectionStatus,
		ConnectionError:  r.ConnectionError,
		LastConnectedAt:  r.LastConnectedAt,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
}
