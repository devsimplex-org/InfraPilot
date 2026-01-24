package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/crypto"
)

// Service manages container registry operations
type Service struct {
	db            *pgxpool.Pool
	logger        *zap.Logger
	encryptionSvc *crypto.EncryptionService
}

// NewService creates a new registry service
func NewService(db *pgxpool.Pool, logger *zap.Logger, encryptionSvc *crypto.EncryptionService) *Service {
	return &Service{
		db:            db,
		logger:        logger,
		encryptionSvc: encryptionSvc,
	}
}

// CreateRegistry creates a new registry connection
func (s *Service) CreateRegistry(ctx context.Context, orgID uuid.UUID, req *CreateRegistryRequest, createdBy *uuid.UUID) (*Registry, error) {
	// Determine auth type and build credentials
	var authType AuthType
	var creds Credentials

	switch req.Provider {
	case ProviderGHCR:
		if req.Token == nil || *req.Token == "" {
			return nil, fmt.Errorf("token is required for GHCR")
		}
		authType = AuthTypeToken
		creds.Token = *req.Token

	case ProviderDockerHub:
		if req.Username == nil || *req.Username == "" || req.Password == nil || *req.Password == "" {
			return nil, fmt.Errorf("username and password are required for Docker Hub")
		}
		authType = AuthTypeUsernamePassword
		creds.Username = *req.Username
		creds.Password = *req.Password

	case ProviderECR:
		if req.AWSAccessKeyID == nil || *req.AWSAccessKeyID == "" ||
			req.AWSSecretAccessKey == nil || *req.AWSSecretAccessKey == "" ||
			req.AWSRegion == nil || *req.AWSRegion == "" {
			return nil, fmt.Errorf("aws_access_key_id, aws_secret_access_key, and aws_region are required for ECR")
		}
		authType = AuthTypeToken // ECR uses IAM credentials
		creds.AWSAccessKeyID = *req.AWSAccessKeyID
		creds.AWSSecretAccessKey = *req.AWSSecretAccessKey
		creds.AWSRegion = *req.AWSRegion
		if req.AWSAccountID != nil {
			creds.AWSAccountID = *req.AWSAccountID
		}

	case ProviderGCR:
		if req.GCPServiceAccountJSON == nil || *req.GCPServiceAccountJSON == "" ||
			req.GCPProjectID == nil || *req.GCPProjectID == "" {
			return nil, fmt.Errorf("gcp_service_account_json and gcp_project_id are required for GCR")
		}
		authType = AuthTypeToken // GCR uses service account
		creds.GCPServiceAccountJSON = *req.GCPServiceAccountJSON
		creds.GCPProjectID = *req.GCPProjectID

	case ProviderACR:
		if req.AzureTenantID == nil || *req.AzureTenantID == "" ||
			req.AzureClientID == nil || *req.AzureClientID == "" ||
			req.AzureClientSecret == nil || *req.AzureClientSecret == "" ||
			req.AzureRegistryName == nil || *req.AzureRegistryName == "" {
			return nil, fmt.Errorf("azure_tenant_id, azure_client_id, azure_client_secret, and azure_registry_name are required for ACR")
		}
		authType = AuthTypeToken // ACR uses service principal
		creds.AzureTenantID = *req.AzureTenantID
		creds.AzureClientID = *req.AzureClientID
		creds.AzureClientSecret = *req.AzureClientSecret
		creds.AzureRegistryName = *req.AzureRegistryName

	default:
		return nil, fmt.Errorf("unsupported provider: %s", req.Provider)
	}

	// Serialize and encrypt credentials
	credsJSON, err := json.Marshal(creds)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credentials: %w", err)
	}

	var encryptedCreds []byte
	if s.encryptionSvc != nil {
		encryptedCreds, err = s.encryptionSvc.Encrypt(credsJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt credentials: %w", err)
		}
	} else {
		// Fallback to unencrypted storage (not recommended)
		s.logger.Warn("encryption service not configured, storing credentials unencrypted")
		encryptedCreds = credsJSON
	}

	registry := &Registry{
		ID:                   uuid.New(),
		OrgID:                orgID,
		Name:                 req.Name,
		Provider:             req.Provider,
		Enabled:              true,
		AuthType:             authType,
		CredentialsEncrypted: encryptedCreds,
		Namespace:            req.Namespace,
		ConnectionStatus:     StatusPending,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
		CreatedBy:            createdBy,
	}

	query := `
		INSERT INTO container_registries (
			id, org_id, name, provider, enabled,
			auth_type, credentials_encrypted, namespace,
			connection_status, created_at, updated_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = s.db.Exec(ctx, query,
		registry.ID, registry.OrgID, registry.Name, registry.Provider, registry.Enabled,
		registry.AuthType, registry.CredentialsEncrypted, registry.Namespace,
		registry.ConnectionStatus, registry.CreatedAt, registry.UpdatedAt, registry.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	s.logger.Info("created container registry",
		zap.String("registry_id", registry.ID.String()),
		zap.String("name", registry.Name),
		zap.String("provider", string(registry.Provider)),
	)

	return registry, nil
}

// GetRegistry retrieves a registry by ID
func (s *Service) GetRegistry(ctx context.Context, orgID, registryID uuid.UUID) (*Registry, error) {
	query := `
		SELECT
			id, org_id, name, provider, enabled,
			auth_type, credentials_encrypted, namespace,
			connection_status, connection_error, last_connected_at,
			created_at, updated_at, created_by
		FROM container_registries
		WHERE id = $1 AND org_id = $2
	`

	var registry Registry
	err := s.db.QueryRow(ctx, query, registryID, orgID).Scan(
		&registry.ID, &registry.OrgID, &registry.Name, &registry.Provider, &registry.Enabled,
		&registry.AuthType, &registry.CredentialsEncrypted, &registry.Namespace,
		&registry.ConnectionStatus, &registry.ConnectionError, &registry.LastConnectedAt,
		&registry.CreatedAt, &registry.UpdatedAt, &registry.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("registry not found: %w", err)
	}

	return &registry, nil
}

// ListRegistries lists all registries for an organization
func (s *Service) ListRegistries(ctx context.Context, orgID uuid.UUID) ([]*Registry, error) {
	query := `
		SELECT
			id, org_id, name, provider, enabled,
			auth_type, credentials_encrypted, namespace,
			connection_status, connection_error, last_connected_at,
			created_at, updated_at, created_by
		FROM container_registries
		WHERE org_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list registries: %w", err)
	}
	defer rows.Close()

	var registries []*Registry
	for rows.Next() {
		var registry Registry
		err := rows.Scan(
			&registry.ID, &registry.OrgID, &registry.Name, &registry.Provider, &registry.Enabled,
			&registry.AuthType, &registry.CredentialsEncrypted, &registry.Namespace,
			&registry.ConnectionStatus, &registry.ConnectionError, &registry.LastConnectedAt,
			&registry.CreatedAt, &registry.UpdatedAt, &registry.CreatedBy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan registry: %w", err)
		}
		registries = append(registries, &registry)
	}

	return registries, nil
}

// UpdateRegistry updates a registry
func (s *Service) UpdateRegistry(ctx context.Context, orgID, registryID uuid.UUID, req *UpdateRegistryRequest) error {
	// Get existing registry
	registry, err := s.GetRegistry(ctx, orgID, registryID)
	if err != nil {
		return err
	}

	// Update fields
	if req.Name != nil {
		registry.Name = *req.Name
	}
	if req.Enabled != nil {
		registry.Enabled = *req.Enabled
	}
	if req.Namespace != nil {
		registry.Namespace = req.Namespace
	}

	// Update credentials if provided
	if req.Token != nil || req.Username != nil || req.Password != nil {
		var creds Credentials

		// Decrypt existing credentials
		if len(registry.CredentialsEncrypted) > 0 {
			if err := json.Unmarshal(registry.CredentialsEncrypted, &creds); err != nil {
				return fmt.Errorf("failed to unmarshal credentials: %w", err)
			}
		}

		// Update with new values
		if req.Token != nil {
			creds.Token = *req.Token
			registry.AuthType = AuthTypeToken
		}
		if req.Username != nil {
			creds.Username = *req.Username
		}
		if req.Password != nil {
			creds.Password = *req.Password
		}

		// Re-serialize
		credsJSON, err := json.Marshal(creds)
		if err != nil {
			return fmt.Errorf("failed to marshal credentials: %w", err)
		}
		registry.CredentialsEncrypted = credsJSON

		// Reset connection status when credentials change
		registry.ConnectionStatus = StatusPending
		registry.ConnectionError = nil
	}

	registry.UpdatedAt = time.Now()

	query := `
		UPDATE container_registries
		SET name = $3, enabled = $4, namespace = $5,
			auth_type = $6, credentials_encrypted = $7,
			connection_status = $8, connection_error = $9,
			updated_at = $10
		WHERE id = $1 AND org_id = $2
	`

	_, err = s.db.Exec(ctx, query,
		registryID, orgID,
		registry.Name, registry.Enabled, registry.Namespace,
		registry.AuthType, registry.CredentialsEncrypted,
		registry.ConnectionStatus, registry.ConnectionError,
		registry.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update registry: %w", err)
	}

	s.logger.Info("updated container registry",
		zap.String("registry_id", registryID.String()),
	)

	return nil
}

// DeleteRegistry deletes a registry
func (s *Service) DeleteRegistry(ctx context.Context, orgID, registryID uuid.UUID) error {
	query := `DELETE FROM container_registries WHERE id = $1 AND org_id = $2`

	result, err := s.db.Exec(ctx, query, registryID, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete registry: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("registry not found")
	}

	s.logger.Info("deleted container registry",
		zap.String("registry_id", registryID.String()),
	)

	return nil
}

// TestConnection tests the connection to a registry
func (s *Service) TestConnection(ctx context.Context, orgID, registryID uuid.UUID) error {
	registry, err := s.GetRegistry(ctx, orgID, registryID)
	if err != nil {
		return err
	}

	client, err := s.getClient(registry)
	if err != nil {
		s.updateConnectionStatus(ctx, registryID, StatusFailed, err.Error())
		return err
	}

	if err := client.TestConnection(ctx); err != nil {
		s.updateConnectionStatus(ctx, registryID, StatusFailed, err.Error())
		return err
	}

	s.updateConnectionStatus(ctx, registryID, StatusConnected, "")
	return nil
}

// ListRepositories lists repositories for a registry
func (s *Service) ListRepositories(ctx context.Context, orgID, registryID uuid.UUID, page, pageSize int) (*ListRepositoriesResponse, error) {
	registry, err := s.GetRegistry(ctx, orgID, registryID)
	if err != nil {
		return nil, err
	}

	client, err := s.getClient(registry)
	if err != nil {
		return nil, err
	}

	return client.ListRepositories(ctx, page, pageSize)
}

// ListTags lists tags for a repository
func (s *Service) ListTags(ctx context.Context, orgID, registryID uuid.UUID, repository string, page, pageSize int) (*ListTagsResponse, error) {
	registry, err := s.GetRegistry(ctx, orgID, registryID)
	if err != nil {
		return nil, err
	}

	client, err := s.getClient(registry)
	if err != nil {
		return nil, err
	}

	return client.ListTags(ctx, repository, page, pageSize)
}

// GetDecryptedCredentials retrieves and decrypts credentials for a registry
func (s *Service) GetDecryptedCredentials(ctx context.Context, orgID, registryID uuid.UUID) (*Credentials, error) {
	registry, err := s.GetRegistry(ctx, orgID, registryID)
	if err != nil {
		return nil, err
	}

	return s.decryptCredentials(registry)
}

// decryptCredentials decrypts the credentials for a registry
func (s *Service) decryptCredentials(registry *Registry) (*Credentials, error) {
	var creds Credentials
	if len(registry.CredentialsEncrypted) > 0 {
		var credsJSON []byte
		if s.encryptionSvc != nil {
			var err error
			credsJSON, err = s.encryptionSvc.Decrypt(registry.CredentialsEncrypted)
			if err != nil {
				// Try to parse as unencrypted JSON (for backwards compatibility)
				credsJSON = registry.CredentialsEncrypted
				s.logger.Warn("failed to decrypt credentials, trying as plain JSON",
					zap.String("registry_id", registry.ID.String()),
				)
			}
		} else {
			credsJSON = registry.CredentialsEncrypted
		}

		if err := json.Unmarshal(credsJSON, &creds); err != nil {
			return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
		}
	}

	return &creds, nil
}

// getClient creates a registry client for the given registry
func (s *Service) getClient(registry *Registry) (Client, error) {
	creds, err := s.decryptCredentials(registry)
	if err != nil {
		return nil, err
	}

	namespace := ""
	if registry.Namespace != nil {
		namespace = *registry.Namespace
	}

	switch registry.Provider {
	case ProviderGHCR:
		return NewGHCRClient(creds.Token, namespace), nil

	case ProviderDockerHub:
		return NewDockerHubClient(creds.Username, creds.Password, namespace), nil

	case ProviderECR:
		return NewECRClient(creds.AWSAccessKeyID, creds.AWSSecretAccessKey, creds.AWSRegion, creds.AWSAccountID), nil

	case ProviderGCR:
		return NewGCRClient(creds.GCPServiceAccountJSON, creds.GCPProjectID), nil

	case ProviderACR:
		return NewACRClient(creds.AzureTenantID, creds.AzureClientID, creds.AzureClientSecret, creds.AzureRegistryName), nil

	default:
		return nil, fmt.Errorf("unsupported provider: %s", registry.Provider)
	}
}

// updateConnectionStatus updates the connection status of a registry
func (s *Service) updateConnectionStatus(ctx context.Context, registryID uuid.UUID, status ConnectionStatus, errorMsg string) {
	var connError *string
	if errorMsg != "" {
		connError = &errorMsg
	}

	var lastConnected *time.Time
	if status == StatusConnected {
		now := time.Now()
		lastConnected = &now
	}

	query := `
		UPDATE container_registries
		SET connection_status = $2, connection_error = $3, last_connected_at = COALESCE($4, last_connected_at), updated_at = NOW()
		WHERE id = $1
	`

	_, err := s.db.Exec(ctx, query, registryID, status, connError, lastConnected)
	if err != nil {
		s.logger.Error("failed to update connection status",
			zap.String("registry_id", registryID.String()),
			zap.Error(err),
		)
	}
}
