# Per-Service Environment Files — Implementation Plan

## Problem

Currently the Variables step treats ALL variables as global (substituted across the entire compose YAML). But `env_file` in docker-compose means per-service env vars — different services get different `.env` files. When a user uploads/pastes an env file, all KEY=VALUEs should only go to the specific service that declared `env_file`, not to all services.

## Solution

1. Parse `env_file` from compose YAML (backend)
2. Return `env_files: string[]` per service in `ComposeService`
3. In the wizard **Services step**, show an env file upload/paste section for each service that has `env_file`
4. Per-service env vars flow through `ServiceOverride.env_overrides` (already exists)
5. The existing global Variables step stays for `${REGISTRY}`, `${TAG}` etc.

---

## Files to Modify

### 1. `backend/internal/api/stack_handlers.go`

**Parse `env_file` from YAML struct** (line ~162):
```go
// Add to the services struct inside parseCompose:
EnvFile interface{} `yaml:"env_file"`
```

**Add `EnvFiles` to `ComposeService` struct** (line ~80):
```go
type ComposeService struct {
    // ... existing fields ...
    EnvFiles []string `json:"env_files,omitempty"`  // NEW
}
```

**Parse env_file in the service loop** (after line ~220):
```go
// Parse env_file (can be string or list)
cs.EnvFiles = parseEnvFile(svc.EnvFile)
```

**Add `parseEnvFile` helper function:**
```go
func parseEnvFile(v interface{}) []string {
    if v == nil { return nil }
    switch val := v.(type) {
    case string:
        return []string{val}
    case []interface{}:
        files := make([]string, 0, len(val))
        for _, f := range val {
            if s, ok := f.(string); ok {
                files = append(files, s)
            }
        }
        return files
    }
    return nil
}
```

No other backend changes needed — `ServiceOverride.EnvOverrides` already handles per-service env vars passed from the frontend.

### 2. `frontend/lib/api.ts`

**Add `env_files` to `ComposeService` interface:**
```typescript
interface ComposeService {
    // ... existing fields ...
    env_files?: string[];  // NEW
}
```

### 3. `frontend/components/StackDeployWizard.tsx`

**Add per-service env state** (after line ~92):
```typescript
const [serviceEnvFiles, setServiceEnvFiles] = useState<Record<string, string>>({});
// Key: service name, Value: raw .env file content (for textarea display)
```

**Add per-service env parser function:**
```typescript
const parseServiceEnvFile = (serviceName: string, content: string) => {
    const parsed: Record<string, string> = {};
    for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
        if (match) {
            let value = match[2].trim();
            if ((value.startsWith('"') && value.endsWith('"')) ||
                (value.startsWith("'") && value.endsWith("'"))) {
                value = value.slice(1, -1);
            }
            parsed[match[1]] = value;
        }
    }
    // Store in serviceConfigs as envOverrides for this service
    setServiceConfigs(prev => ({
        ...prev,
        [serviceName]: {
            ...prev[serviceName],
            envOverrides: { ...prev[serviceName]?.envOverrides, ...parsed },
        },
    }));
};
```

**Modify the Services step UI** (line ~618, inside the service card when `config.enabled`):

For each service that has `env_files`, add an expandable section:
- Show the `env_file` paths from compose (e.g., `../websites/devsimplex.com/.env.local`) as labels
- Upload button + paste textarea (reuse existing pattern from Variables step)
- On upload/paste, parse KEY=VALUE and store in `serviceConfigs[serviceName].envOverrides`
- Show count of parsed variables
- Show the parsed key-value pairs as editable fields below

Layout within each service card:
```
[x] devsimplex
    ghcr.io/tybali/devsimplex:latest
    Tag Override: [___________]

    Environment File: ../websites/devsimplex.com/.env.local
    [Upload .env] or paste below
    [textarea for .env content]
    ✓ 5 variables loaded

    KEY1 = [value1]
    KEY2 = [value2]
    ...
```

Services WITHOUT `env_files` won't show this section (just tag override + depends_on as now).

**Reset `serviceEnvFiles` on dialog open** (line ~206):
```typescript
setServiceEnvFiles({});
```

**No changes to `handleDeploy`** — it already sends `env_overrides` from `serviceConfigs` via the `overrides` array.

---

## Data Flow

```
Compose YAML with env_file:
  devsimplex:
    env_file: .env.local

      ↓ parseCompose (backend)

ComposeService.env_files = [".env.local"]

      ↓ returned to frontend

Services step shows upload/paste for devsimplex

      ↓ user pastes .env content

parseServiceEnvFile("devsimplex", content)
  → serviceConfigs["devsimplex"].envOverrides = {KEY1: "val1", ...}

      ↓ handleDeploy

overrides: [{
  service_name: "devsimplex",
  env_overrides: {KEY1: "val1", ...},
  enabled: true
}]

      ↓ backend createStack

DeploymentContainerConfig.EnvVars = compose env + env_overrides (merged)
```

---

## Verification

1. Use the websites compose YAML (has `env_file` for devsimplex, admin-devsimplex-net, resellvouchers)
2. Upload compose → parse → verify `env_files` returned per service
3. Services step should show env file upload for those 3 services only
4. Upload/paste .env content → verify vars appear per-service
5. Deploy → verify only the correct service gets its env vars
6. Services without `env_file` (solarwaterheaterexperts, etc.) should have no env section
