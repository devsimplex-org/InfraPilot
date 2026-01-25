# .env to Docker Secrets Migration Feature

## Summary

Implement a secrets hygiene feature that allows users to migrate secrets from `.env` files (discovered during container scans) to Docker Secrets, then redeploy containers with the secrets properly attached. This improves security posture by removing plaintext secrets from containers.

## Current State

**Already exists:**
- Secret scanning: Agent scans containers for env vars and .env files
- Secrets inventory: `secrets_inventory` table stores discovered secrets
- Frontend: Secrets page with Inventory tab showing discovered secrets
- Docker client: Basic container operations

**Gap:** No way to migrate discovered `.env` secrets to Docker Secrets and redeploy containers.

## Architecture Overview

### Secrets Migration Flow

```
.env file in container → Scan discovers secrets → User selects secrets to migrate
                                                          ↓
                              ← Container recreated ← Docker Secrets created
                                  with secrets attached
```

### Approach: File-Mounted Secrets (Standalone Docker Compatible)

Since Docker Swarm may not be enabled, we'll use a hybrid approach:
1. **Default**: Create file-mounted secrets in `/run/secrets/` directory
2. **Optional**: Use Docker Swarm secrets when swarm mode is active

For standalone Docker:
- Store secrets in encrypted files on host
- Mount secrets directory into container at `/run/secrets/`
- Application reads from `/run/secrets/<secret_name>`

## Implementation Plan

### Phase 1: Database Schema

**New tables in `backend/internal/db/migrations/`**

```sql
-- secret_migrations: Track migration jobs
CREATE TABLE secret_migrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    container_id VARCHAR(255) NOT NULL,
    container_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL, -- 'env_file', 'env_var'
    source_path VARCHAR(500),         -- e.g., '/app/.env'
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- Status: pending → creating_secrets → stopping_container → starting_container → verifying → completed/failed/rolled_back
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- secret_migration_items: Individual secrets in a migration
CREATE TABLE secret_migration_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id UUID NOT NULL REFERENCES secret_migrations(id) ON DELETE CASCADE,
    secret_name VARCHAR(255) NOT NULL,
    secret_type VARCHAR(50),          -- 'api_key', 'password', etc.
    old_source VARCHAR(50) NOT NULL,  -- 'env_file', 'env_var'
    new_source VARCHAR(50) NOT NULL,  -- 'docker_secret', 'file_secret'
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- Status: pending → created → attached → verified → completed/failed
    mount_path VARCHAR(500),          -- '/run/secrets/DB_PASSWORD'
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Phase 2: Agent Docker Extensions

**File: `agent/internal/docker/client.go`**

Add methods for secret management:

```go
// CheckSwarmMode checks if Docker is running in swarm mode
func (c *Client) CheckSwarmMode(ctx context.Context) (bool, error)

// CreateFileSecret creates a file-based secret (standalone Docker)
func (c *Client) CreateFileSecret(ctx context.Context, name, value string) (string, error)
// - Creates /var/lib/infrapilot/secrets/<name> with restricted permissions (0600)
// - Returns the mount path

// RemoveFileSecret removes a file-based secret
func (c *Client) RemoveFileSecret(ctx context.Context, name string) error

// RecreateContainerWithSecrets stops container, creates new one with secret mounts
func (c *Client) RecreateContainerWithSecrets(ctx context.Context, containerID string, secrets []SecretMount, removeEnvVars []string) (string, error)
// - Inspects original container config
// - Stops and removes original container
// - Creates new container with:
//   - Original config minus specified env vars
//   - Added volume mounts for /run/secrets
// - Starts new container
// - Returns new container ID
```

**File: `agent/cmd/agent/main.go`**

Add new actions to `handleDockerCommand`:

```go
case "migrate_secrets":
    // Input: container_id, secrets [{name, value}], remove_env_vars []string
    // 1. Create file secrets for each secret
    // 2. Recreate container with secret mounts
    // 3. Remove original .env file from new container (if applicable)
    // Returns: new_container_id, mounted_secrets

case "verify_migration":
    // Input: container_id, expected_secrets []string
    // 1. Exec into container
    // 2. Check /run/secrets/ contains expected files
    // 3. Verify container is healthy
    // Returns: verification_result

case "rollback_migration":
    // Input: container_id, original_config
    // 1. Stop migrated container
    // 2. Recreate original container
    // 3. Clean up created secrets
    // Returns: original_container_id
```

### Phase 3: Backend API

**File: `backend/internal/api/secrets_handlers.go`**

Add migration endpoints:

```go
// POST /api/v1/agents/:id/secrets/migrations
// Create a new migration job
type CreateMigrationRequest struct {
    ContainerID   string   `json:"container_id" binding:"required"`
    ContainerName string   `json:"container_name" binding:"required"`
    SourceType    string   `json:"source_type" binding:"required"` // env_file
    SourcePath    string   `json:"source_path,omitempty"`
    Secrets       []struct {
        Name  string `json:"name" binding:"required"`
        Value string `json:"value" binding:"required"`
        Type  string `json:"type,omitempty"`
    } `json:"secrets" binding:"required,min=1"`
}

// GET /api/v1/agents/:id/secrets/migrations
// List migrations for an agent

// GET /api/v1/agents/:id/secrets/migrations/:migration_id
// Get migration details with items

// POST /api/v1/agents/:id/secrets/migrations/:migration_id/rollback
// Trigger rollback of a migration
```

**Migration execution flow:**

```go
func (h *Handler) executeMigration(ctx context.Context, migration *Migration) {
    // 1. Update status: creating_secrets
    // 2. Send migrate_secrets command to agent
    // 3. Update status: verifying
    // 4. Send verify_migration command
    // 5. Update status: completed (or failed with rollback)
    // 6. Update secrets_inventory records with new source
}
```

### Phase 4: Frontend Migration UI

**File: `frontend/app/(dashboard)/data/secrets/page.tsx`**

Add Migration tab to secrets page:

```typescript
// Tab structure
<TabsList>
  <TabsTrigger value="secrets">Secrets</TabsTrigger>
  <TabsTrigger value="inventory">Inventory</TabsTrigger>
  <TabsTrigger value="migrations">Migrations</TabsTrigger>  // NEW
</TabsList>
```

**Migrations Tab content:**

1. **Migrations List Table**
   - Columns: Container, Source, Status, Secrets Count, Created, Actions
   - Row expansion shows individual secret items
   - Status badges: pending (yellow), in_progress (blue), completed (green), failed (red)

2. **"New Migration" Button**
   - Opens migration wizard dialog

**File: `frontend/components/MigrationWizard.tsx`** (new)

Multi-step wizard dialog:

```typescript
interface MigrationWizardProps {
  isOpen: boolean;
  onClose: () => void;
  agentId: string;
  // Pre-selected from inventory
  preselectedSecrets?: SecretInventory[];
}

// Steps:
// 1. Select Container - Choose container with .env secrets
// 2. Select Secrets - Checkboxes for secrets to migrate (shows name, type, risk)
// 3. Review - Summary of changes, warnings about container restart
// 4. Execute - Progress indicator, real-time status updates
```

**Wizard Step Details:**

Step 1 - Select Container:
- Dropdown of containers with .env file secrets (from inventory)
- Shows: container name, .env file path, secret count

Step 2 - Select Secrets:
- Table with checkboxes for each secret
- Columns: Select, Name, Type, Current Value (masked), Risk Level
- "Select All" option
- Warning: "Selected secrets will be removed from .env and mounted as files"

Step 3 - Review:
- Summary card showing:
  - Container to be restarted
  - Number of secrets being migrated
  - New mount path: `/run/secrets/`
  - Warning: "Container will be stopped and recreated"
- Confirm checkbox: "I understand the container will restart"

Step 4 - Execute:
- Progress steps with status indicators
- Real-time polling of migration status
- Success: "Migration complete! Container restarted with secrets."
- Failure: "Migration failed. [Error message]. Rollback available."
- Rollback button if failed

### Phase 5: Inventory Enhancement

**File: `frontend/app/(dashboard)/data/secrets/page.tsx`**

Add "Migrate" action to inventory table for .env file secrets:

```typescript
// In inventory table row actions
{secret.source === 'env_file' && (
  <Button
    variant="outline"
    size="sm"
    onClick={() => openMigrationWizard([secret])}
  >
    <ArrowRightLeft className="h-4 w-4 mr-1" />
    Migrate
  </Button>
)}

// Bulk action when multiple .env secrets selected
{selectedSecrets.length > 0 && (
  <Button onClick={() => openMigrationWizard(selectedSecrets)}>
    Migrate Selected ({selectedSecrets.length})
  </Button>
)}
```

## Files to Modify/Create

| File | Changes |
|------|---------|
| `backend/internal/db/migrations/029_secret_migrations.up.sql` | **NEW** - Migration tracking tables |
| `agent/internal/docker/client.go` | Add CheckSwarmMode, CreateFileSecret, RecreateContainerWithSecrets |
| `agent/cmd/agent/main.go` | Add migrate_secrets, verify_migration, rollback_migration actions |
| `backend/internal/api/secrets_handlers.go` | Add migration endpoints and execution logic |
| `backend/internal/api/routes.go` | Register new migration routes |
| `frontend/lib/api.ts` | Add migration API methods |
| `frontend/app/(dashboard)/data/secrets/page.tsx` | Add Migrations tab, enhance Inventory with migrate action |
| `frontend/components/MigrationWizard.tsx` | **NEW** - Multi-step migration wizard |

## User Flow

### Happy Path: Migrate .env Secrets

1. User goes to Secrets → Inventory
2. User sees secrets discovered from `.env` file (amber badge)
3. User selects secrets and clicks "Migrate"
4. Migration wizard opens with secrets pre-selected
5. User reviews and confirms container restart
6. User clicks "Start Migration"
7. Progress shows: Creating secrets → Stopping container → Starting container → Verifying
8. Success: Container now running with secrets mounted at `/run/secrets/`
9. User can verify: `docker exec <container> ls /run/secrets/`

### Error Handling

- **Container fails to start**: Automatic rollback to original container
- **Partial failure**: Show which secrets succeeded, offer retry
- **Network timeout**: Migration remains in `pending`, user can retry

## Verification

1. **Scan and discover .env secrets:**
   - Run scan from Inventory tab
   - Verify .env file secrets appear with amber badge

2. **Create migration:**
   - Select .env secrets, click Migrate
   - Complete wizard steps
   - Verify migration record created

3. **Migration execution:**
   - Watch status progress through steps
   - Verify container stops and restarts
   - Check new container has `/run/secrets/` mounted

4. **Verify secrets accessible:**
   ```bash
   docker exec <container> cat /run/secrets/DB_PASSWORD
   ```

5. **Rollback test:**
   - Create a failing migration (invalid secret name)
   - Verify rollback restores original container

6. **Inventory update:**
   - After migration, secret source should change from `env_file` to `file_secret`
