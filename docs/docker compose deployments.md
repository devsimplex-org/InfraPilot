# Stack Deploy Feature - Implementation Plan

Deploy multiple services from docker-compose.yml files with individual scanning and tracking per service.

## Overview

- Parse docker-compose.yml → extract services
- Create separate deployment record per service (for individual scan/policy)
- New `stacks` table to group deployments together
- Handle networks, volumes, depends_on ordering
- Variable substitution: `${REGISTRY:-default}`, `${TAG:-latest}`

---

## Database Schema

**File:** `backend/internal/db/migrations/041_stacks.up.sql`

```sql
CREATE TYPE stack_status AS ENUM (
    'pending', 'deploying', 'running', 'partial', 'failed', 'stopped'
);

CREATE TABLE stacks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    name VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),
    compose_yaml TEXT NOT NULL,
    variables JSONB DEFAULT '{}',
    service_count INT DEFAULT 0,
    running_count INT DEFAULT 0,
    failed_count INT DEFAULT 0,
    status stack_status DEFAULT 'pending',
    status_message TEXT,
    deployed_by UUID REFERENCES users(id),
    deployed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Link deployments to stacks
ALTER TABLE deployments ADD COLUMN stack_id UUID REFERENCES stacks(id);
ALTER TABLE deployments ADD COLUMN service_order INT DEFAULT 0;
```

---

## Backend API

**New File:** `backend/internal/api/stack_handlers.go`

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/agents/{id}/stacks/parse` | Parse & validate compose YAML, return preview |
| POST | `/agents/{id}/stacks` | Create stack, trigger multi-service deployment |
| GET | `/agents/{id}/stacks` | List stacks |
| GET | `/agents/{id}/stacks/{sid}` | Get stack with deployments |
| GET | `/agents/{id}/stacks/{sid}/progress` | Deployment progress (polling) |
| DELETE | `/agents/{id}/stacks/{sid}` | Delete stack & stop containers |

### Key Structs

```go
type CreateStackRequest struct {
    Name        string            `json:"name" binding:"required"`
    Environment string            `json:"environment" binding:"required"`
    ComposeYAML string            `json:"compose_yaml" binding:"required"`
    Variables   map[string]string `json:"variables,omitempty"`
    Overrides   []ServiceOverride `json:"overrides,omitempty"`
}

type ServiceOverride struct {
    ServiceName  string            `json:"service_name"`
    TagOverride  *string           `json:"tag_override,omitempty"`
    EnvOverrides map[string]string `json:"env_overrides,omitempty"`
    Enabled      bool              `json:"enabled"`
}

type ParsedCompose struct {
    Services []ComposeService `json:"services"`
    Networks []ComposeNetwork `json:"networks"`
    Volumes  []ComposeVolume  `json:"volumes"`
}
```

### Pipeline Flow

1. Parse YAML with variable substitution
2. Topological sort by `depends_on`
3. Create stack record + all deployment records (status: pending)
4. Async: For each service in order:
   - Wait for dependencies to reach "running"
   - Run normal deployment pipeline (scan → policy → deploy)
   - Update stack counts
5. Final stack status: running/partial/failed

---

## Frontend

### New Types in `frontend/lib/api.ts`

```typescript
interface Stack {
  id: string;
  name: string;
  environment: string;
  status: "pending" | "deploying" | "running" | "partial" | "failed" | "stopped";
  service_count: number;
  running_count: number;
  failed_count: number;
  deployments?: Deployment[];
}

interface CreateStackRequest {
  name: string;
  environment: string;
  compose_yaml: string;
  variables?: Record<string, string>;
  overrides?: ServiceOverride[];
}
```

### New Component: `frontend/components/StackDeployWizard.tsx`

5-step wizard:

1. **YAML** - Upload/paste docker-compose.yml, syntax validation
2. **Variables** - Set ${REGISTRY}, ${TAG}, etc.
3. **Services** - Toggle services, per-service tag/env overrides
4. **Resources** - Review networks & volumes to create
5. **Review** - Summary, deploy, progress tracking

---

## Files to Create/Modify

### New Files
- `backend/internal/db/migrations/041_stacks.up.sql`
- `backend/internal/db/migrations/041_stacks.down.sql`
- `backend/internal/api/stack_handlers.go`
- `frontend/components/StackDeployWizard.tsx`

### Modified Files
- `backend/internal/api/handler.go` - Register stack routes
- `backend/internal/api/deployment_handlers.go` - Add stack_id support
- `frontend/lib/api.ts` - Add Stack types & API functions
- `frontend/app/(dashboard)/docker/page.tsx` - Add "Deploy Stack" button

---

## Variable Substitution

Support patterns:
- `${VAR}` - Required variable
- `${VAR:-default}` - Default if unset
- `${VAR-default}` - Default only if undefined

Common variables:
- `REGISTRY` - ghcr.io/tybali
- `TAG` - latest, v1.0.0

---

## Depends_on Handling

1. Build dependency graph from compose
2. Detect cycles (error if found)
3. Topological sort for deployment order
4. Deploy in order, waiting for dependencies to reach "running"

---

## No Agent Changes Required

Existing `RunContainerExtended()` handles:
- Networks (create if missing)
- Volumes (named + bind mounts)
- Environment variables
- Labels (for compose project tracking)

---

## Implementation Order

1. Database migration (stacks table)
2. Backend stack handlers with YAML parsing
3. Parse endpoint for validation/preview
4. Create stack endpoint with async pipeline
5. Frontend StackDeployWizard component
6. Integration with docker page

---

## Verification

1. Create test docker-compose.yml with 2-3 services
2. Upload via wizard, verify parsing
3. Set variables, verify substitution preview
4. Deploy stack, verify:
   - All deployment records created
   - Services scanned individually
   - Containers started in depends_on order
   - Stack status updates correctly
5. Test partial failure scenario
6. Test delete stack (stops containers)
