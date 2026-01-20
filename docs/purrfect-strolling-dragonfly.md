# InfraPilot P0/P1 Gaps Implementation Plan

## Overview

Implement 5 critical gaps in priority order with shared dependencies.

**Implementation Order:**
1. **Encryption Service** (P0) - Foundation for #2, #4, #5
2. **Webhook Signature Verification** (P0) - Security critical
3. **Container Deployment** (P0) - Core functionality (parallel with #2)
4. **ECR/GCR/ACR Support** (P1) - Cloud registry expansion
5. **SSO/OIDC** (P1) - Enterprise auth

---

## Phase 1: Encryption Service Foundation

**Purpose:** Shared encryption for webhooks, registries, and SSO credentials

### Files to Create/Modify

**NEW:** `backend/internal/crypto/encryption.go`
```go
// AES-256-GCM encryption service
type EncryptionService struct {
    key []byte // 32 bytes
}

func NewEncryptionService(keyHex string) (*EncryptionService, error)
func (s *EncryptionService) Encrypt(plaintext []byte) ([]byte, error)
func (s *EncryptionService) Decrypt(ciphertext []byte) ([]byte, error)
```

**MODIFY:** `backend/internal/config/config.go`
- Add `EncryptionKey string` field
- Load from `ENCRYPTION_KEY` env var (32-byte hex or base64)

**MODIFY:** `backend/cmd/server/main.go`
- Initialize EncryptionService
- Inject into services that need it

---

## Phase 2: Webhook Signature Verification

**Problem:** Secrets stored as bcrypt hashes (one-way), but HMAC needs plaintext secret

**Solution:** Store encrypted secrets instead of hashed

### Database Migration

**NEW:** `backend/internal/db/migrations/022_webhook_encrypted_secrets.up.sql`
```sql
ALTER TABLE webhook_configs ADD COLUMN secret_encrypted BYTEA;
-- Keep secret_hash temporarily for migration reference
```

### Files to Modify

**`backend/internal/webhook/service.go`**

1. Add `encryptionSvc *crypto.EncryptionService` to Service struct

2. Update `CreateWebhook()` (line ~50):
   ```go
   // REMOVE: secretHash, err := bcrypt.GenerateFromPassword(...)
   // ADD:
   encryptedSecret, err := s.encryptionSvc.Encrypt([]byte(secret))
   config.SecretEncrypted = encryptedSecret
   ```

3. Update `VerifyAndParse()` (line ~198):
   ```go
   // REMOVE the warning and skip logic
   // ADD:
   secret, err := s.encryptionSvc.Decrypt(config.SecretEncrypted)
   if err != nil {
       return nil, fmt.Errorf("failed to decrypt webhook secret: %w", err)
   }

   verifier, err := GetVerifier(config.Provider)
   if err != nil {
       return nil, err
   }

   signature := s.getSignatureHeader(headers, config.Provider)
   if err := verifier.Verify(payload, signature, string(secret)); err != nil {
       return nil, fmt.Errorf("signature verification failed: %w", err)
   }
   ```

4. Add helper method:
   ```go
   func (s *Service) getSignatureHeader(headers map[string]string, provider string) string {
       switch provider {
       case "github":
           return headers["X-Hub-Signature-256"]
       case "gitlab":
           return headers["X-Gitlab-Token"]
       default:
           return headers["X-Webhook-Signature"]
       }
   }
   ```

**`backend/internal/webhook/models.go`**
- Add `SecretEncrypted []byte` to WebhookConfig struct

---

## Phase 3: Container Deployment Completion

**Problem:** Pipeline stops at "deploying" status, never starts container

### Files to Modify

**`backend/internal/grpc/service.go`**

Add constants and types:
```go
const DockerActionRunContainer = "run_container"

type ContainerRunCommand struct {
    Action        string            `json:"action"`
    ImageRef      string            `json:"image_ref"`
    Name          string            `json:"name"`
    NetworkID     string            `json:"network_id,omitempty"`
    Env           map[string]string `json:"env,omitempty"`
    Ports         map[string]string `json:"ports,omitempty"`
    RestartPolicy string            `json:"restart_policy,omitempty"`
    Labels        map[string]string `json:"labels,omitempty"`
}

type ContainerRunResult struct {
    ContainerID string `json:"container_id"`
    Name        string `json:"name"`
    Status      string `json:"status"`
}
```

**`agent/internal/docker/client.go`**

Add RunContainer method:
```go
func (c *Client) RunContainer(ctx context.Context, cfg ContainerRunConfig) (*ContainerRunResult, error) {
    // 1. Pull image if not exists
    // 2. Create container with docker.ContainerCreate()
    // 3. Start container with docker.ContainerStart()
    // 4. Return container ID
}
```

**`agent/cmd/agent/main.go`**

Add handler in `handleDockerCommand()` (around line 1207):
```go
case "run_container":
    var runCmd ContainerRunCommand
    if err := json.Unmarshal(dockerCmd.Options, &runCmd); err != nil {
        return &agentgrpc.CommandResult{Success: false, Message: err.Error()}
    }

    result, err := h.docker.RunContainer(ctx, docker.ContainerRunConfig{
        ImageRef:      runCmd.ImageRef,
        Name:          runCmd.Name,
        NetworkID:     runCmd.NetworkID,
        Env:           runCmd.Env,
        Ports:         runCmd.Ports,
        RestartPolicy: runCmd.RestartPolicy,
        Labels:        runCmd.Labels,
    })
    if err != nil {
        return &agentgrpc.CommandResult{Success: false, Message: err.Error()}
    }

    data, _ := json.Marshal(result)
    return &agentgrpc.CommandResult{Success: true, Message: "container started", Data: data}
```

**`backend/internal/api/deployment_handlers.go`**

Replace TODO at line 507-508 with:
```go
// Phase 4: Deploy container to agent
if policyDecision != "deny" {
    containerResult, err := h.deployContainerToAgent(ctx, deployment, agentID)
    if err != nil {
        h.updateDeploymentStatus(ctx, deploymentID, "failed",
            fmt.Sprintf("Container deployment failed: %v", err))
        return
    }

    // Update deployment with container info
    _, err = h.db.Exec(ctx, `
        UPDATE deployments
        SET status = 'running',
            container_id = $1,
            container_name = $2,
            deployed_at = NOW(),
            status_message = 'Container running successfully'
        WHERE id = $3`,
        containerResult.ContainerID,
        containerResult.Name,
        deploymentID,
    )
    if err != nil {
        h.logger.Error("failed to update deployment", zap.Error(err))
    }
} else {
    h.updateDeploymentStatus(ctx, deploymentID, "failed",
        fmt.Sprintf("Blocked by policy: %s", policyReason))
}
```

Add helper method:
```go
func (h *Handler) deployContainerToAgent(ctx context.Context, deployment *Deployment, agentID uuid.UUID) (*grpc.ContainerRunResult, error) {
    imageRef := deployment.ImageRepository
    if deployment.ImageTag != "" {
        imageRef += ":" + deployment.ImageTag
    }

    cmd := &grpc.ContainerRunCommand{
        Action:   "run_container",
        ImageRef: imageRef,
        Name:     fmt.Sprintf("%s-%s-%s", deployment.ServiceName, deployment.Environment, deployment.ID.String()[:8]),
        Labels: map[string]string{
            "infrapilot.deployment_id": deployment.ID.String(),
            "infrapilot.service":       deployment.ServiceName,
            "infrapilot.environment":   deployment.Environment,
        },
        RestartPolicy: "unless-stopped",
    }

    result, err := h.grpcService.SendDockerCommand(ctx, agentID, cmd, 60*time.Second)
    if err != nil {
        return nil, err
    }

    var containerResult grpc.ContainerRunResult
    if err := json.Unmarshal(result.Data, &containerResult); err != nil {
        return nil, err
    }

    return &containerResult, nil
}
```

---

## Phase 4: Registry Credential Encryption

**Problem:** Credentials stored as plaintext JSON despite column name

### Files to Modify

**`backend/internal/registry/service.go`**

1. Add `encryptionSvc *crypto.EncryptionService` to Service struct

2. Update `CreateRegistry()` (line ~55):
   ```go
   // REMOVE: credsJSON, err := json.Marshal(creds)
   // ADD:
   credsJSON, err := json.Marshal(creds)
   if err != nil {
       return nil, fmt.Errorf("failed to marshal credentials: %w", err)
   }
   encryptedCreds, err := s.encryptionSvc.Encrypt(credsJSON)
   if err != nil {
       return nil, fmt.Errorf("failed to encrypt credentials: %w", err)
   }
   registry.CredentialsEncrypted = encryptedCreds
   ```

3. Update `getClient()` (line ~324):
   ```go
   // REMOVE: if err := json.Unmarshal(registry.CredentialsEncrypted, &creds)
   // ADD:
   decrypted, err := s.encryptionSvc.Decrypt(registry.CredentialsEncrypted)
   if err != nil {
       return nil, fmt.Errorf("failed to decrypt credentials: %w", err)
   }
   var creds Credentials
   if err := json.Unmarshal(decrypted, &creds); err != nil {
       return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
   }
   ```

---

## Phase 5: ECR/GCR/ACR Support

### Database Migration

**NEW:** `backend/internal/db/migrations/023_registry_cloud_providers.up.sql`
```sql
ALTER TYPE registry_provider ADD VALUE IF NOT EXISTS 'ecr';
ALTER TYPE registry_provider ADD VALUE IF NOT EXISTS 'gcr';
ALTER TYPE registry_provider ADD VALUE IF NOT EXISTS 'acr';
```

### Files to Create

**NEW:** `backend/internal/registry/ecr.go`
```go
type ECRClient struct {
    accessKeyID, secretAccessKey, region, accountID string
}

func NewECRClient(accessKeyID, secretAccessKey, region, accountID string) *ECRClient
func (c *ECRClient) TestConnection(ctx context.Context) error
func (c *ECRClient) ListRepositories(ctx context.Context, page, pageSize int) (*ListRepositoriesResponse, error)
func (c *ECRClient) ListTags(ctx context.Context, repo string, page, pageSize int) (*ListTagsResponse, error)
func (c *ECRClient) Provider() Provider { return ProviderECR }
```

**NEW:** `backend/internal/registry/gcr.go`
```go
type GCRClient struct {
    serviceAccountJSON, projectID string
}
// Similar interface implementation
```

**NEW:** `backend/internal/registry/acr.go`
```go
type ACRClient struct {
    tenantID, clientID, clientSecret, registryName string
}
// Similar interface implementation
```

### Files to Modify

**`backend/internal/registry/types.go`**

Add providers:
```go
const (
    ProviderECR Provider = "ecr"
    ProviderGCR Provider = "gcr"
    ProviderACR Provider = "acr"
)
```

Extend Credentials:
```go
type Credentials struct {
    // Existing
    Token, Username, Password string

    // ECR
    AWSAccessKeyID, AWSSecretAccessKey, AWSRegion, AWSAccountID string

    // GCR
    GCPServiceAccountJSON, GCPProjectID string

    // ACR
    AzureTenantID, AzureClientID, AzureClientSecret, AzureRegistryName string
}
```

**`backend/internal/registry/service.go`**

Update `getClient()`:
```go
case ProviderECR:
    return NewECRClient(creds.AWSAccessKeyID, creds.AWSSecretAccessKey,
        creds.AWSRegion, creds.AWSAccountID), nil
case ProviderGCR:
    return NewGCRClient(creds.GCPServiceAccountJSON, creds.GCPProjectID), nil
case ProviderACR:
    return NewACRClient(creds.AzureTenantID, creds.AzureClientID,
        creds.AzureClientSecret, creds.AzureRegistryName), nil
```

### Dependencies to Add

```
go get github.com/aws/aws-sdk-go-v2/service/ecr
go get github.com/aws/aws-sdk-go-v2/config
```

---

## Phase 6: SSO/OIDC Support

### Database Migration

**NEW:** `backend/internal/db/migrations/024_sso_oidc.up.sql`
```sql
CREATE TABLE sso_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    provider VARCHAR(50) NOT NULL,  -- 'oidc', 'okta', 'azure_ad', 'google'
    name VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    issuer_url VARCHAR(500),
    client_id VARCHAR(255),
    client_secret_encrypted BYTEA,
    redirect_uri VARCHAR(500),
    scopes TEXT[],
    email_claim VARCHAR(100) DEFAULT 'email',
    role_mappings JSONB DEFAULT '{}',
    jit_provisioning BOOLEAN DEFAULT FALSE,
    default_role VARCHAR(50) DEFAULT 'viewer',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, name)
);
```

### Files to Create

**NEW:** `backend/internal/auth/sso.go`
```go
type SSOService struct {
    db            *pgxpool.Pool
    encryptionSvc *crypto.EncryptionService
}

func (s *SSOService) GetOIDCAuthURL(ctx context.Context, configID uuid.UUID, state string) (string, error)
func (s *SSOService) HandleOIDCCallback(ctx context.Context, configID uuid.UUID, code, state string) (*User, error)
func (s *SSOService) CreateSSOConfig(ctx context.Context, orgID uuid.UUID, req *CreateSSORequest) (*SSOConfig, error)
```

**NEW:** `backend/internal/api/sso_handlers.go`
```go
// Routes:
// GET  /auth/sso/:config_id/login
// GET  /auth/sso/:config_id/callback
// GET  /settings/sso
// POST /settings/sso
```

### Dependencies to Add

```
go get github.com/coreos/go-oidc/v3
```

---

## Verification Plan

### Phase 1 (Encryption)
```bash
# Unit tests
go test ./backend/internal/crypto/...

# Verify encryption round-trip
# Test with empty, unicode, large payloads
```

### Phase 2 (Webhooks)
```bash
# Run migrations
go run ./backend/cmd/migrate up

# Test with curl
curl -X POST https://infra.integrio.live/api/v1/webhooks/{id}/receive \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$(echo -n '{}' | openssl dgst -sha256 -hmac 'secret' | cut -d' ' -f2)" \
  -d '{}'

# Verify webhook event shows verified=true
```

### Phase 3 (Container Deployment)
```bash
# Create deployment via API
curl -X POST https://infra.integrio.live/api/v1/agents/{id}/deployments \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"service_name":"test","environment":"dev","image_repository":"nginx","image_tag":"latest"}'

# Watch status progression: pending -> scanning -> policy_check -> deploying -> running

# Verify container running on agent
docker ps | grep infrapilot
```

### Phase 4 (Registry Encryption + Cloud)
```bash
# Test existing registries still work after encryption migration
# Test new ECR/GCR/ACR connections
```

### Phase 5 (SSO)
```bash
# Test with local Keycloak or Auth0 dev tenant
# Verify login flow and user creation
```

---

## Environment Variables Required

```bash
# Required for encryption (generate with: openssl rand -hex 32)
ENCRYPTION_KEY=<64-char-hex-string>

# Optional for cloud registries
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

---

## Rollback Strategy

1. **Encryption:** Keep key backed up; data unrecoverable without it
2. **Webhooks:** Old webhooks need secret regeneration (can't recover from bcrypt)
3. **Deployments:** Revert handler code; orphan containers need manual cleanup
4. **Cloud registries:** Remove enum values via down migration
5. **SSO:** Drop tables; convert JIT users to local auth first
