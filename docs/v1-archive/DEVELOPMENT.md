# Development Guide

This guide explains how to set up a local development environment for InfraPilot and contribute to the project.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Initial Setup](#initial-setup)
- [Development Workflow](#development-workflow)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Building](#building)
- [Database Migrations](#database-migrations)
- [gRPC Development](#grpc-development)
- [Frontend Development](#frontend-development)
- [Debugging](#debugging)
- [Code Style](#code-style)
- [Common Tasks](#common-tasks)
- [Contributing](#contributing)

## Prerequisites

Before you begin, ensure you have the following installed:

### Required

- **Docker** 24+ and Docker Compose
- **Go** 1.24+
- **Node.js** 20+ and **pnpm**
- **Git**

### Optional (Recommended)

- **Air** - For Go hot-reload: `go install github.com/cosmtrek/air@latest`
- **protoc** - Protocol Buffer compiler (for gRPC development)
- **Make** - Build automation

### Installation Commands

**macOS** (using Homebrew):
```bash
brew install go node pnpm docker protobuf
```

**Ubuntu/Debian**:
```bash
# Go
wget https://go.dev/dl/go1.24.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.linux-amd64.tar.gz

# Node.js & pnpm
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
npm install -g pnpm

# Docker
curl -fsSL https://get.docker.com | sh

# Protobuf
sudo apt-get install -y protobuf-compiler
```

## Initial Setup

### 1. Clone the Repository

```bash
git clone https://github.com/devsimplex-org/InfraPilot.git
cd InfraPilot
```

### 2. Start Development Infrastructure

This starts PostgreSQL and Redis in Docker containers:

```bash
./scripts/dev.sh up
```

**What this does**:
- Starts PostgreSQL on port 5432
- Starts Redis on port 6379
- Creates necessary databases
- Runs in the background

**To stop**:
```bash
./scripts/dev.sh down
```

### 3. Set Environment Variables

Create a `.env` file in the root directory:

```bash
# Backend
JWT_SECRET=dev-jwt-secret-change-in-production
DATABASE_URL=postgres://infrapilot:infrapilot@localhost:5432/infrapilot?sslmode=disable
REDIS_URL=redis://localhost:6379
HTTP_PORT=8080
GRPC_PORT=9090
ENV=development

# Agent
AGENT_ID=dev-agent
BACKEND_URL=localhost:9090
DOCKER_HOST=unix:///var/run/docker.sock

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8080/api/v1
```

### 4. Install Dependencies

**Backend**:
```bash
cd backend
go mod download
```

**Agent**:
```bash
cd agent
go mod download
```

**Frontend**:
```bash
cd frontend
pnpm install
```

## Development Workflow

### Running All Components

You'll typically run three terminal sessions:

**Terminal 1 - Backend**:
```bash
cd backend
air  # Hot-reload enabled
# Or without hot-reload:
# go run cmd/server/main.go
```

**Terminal 2 - Agent**:
```bash
cd agent
go run cmd/agent/main.go
```

**Terminal 3 - Frontend**:
```bash
cd frontend
pnpm dev
```

### Access Points

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8080/api/v1
- **Backend Health**: http://localhost:8080/health
- **gRPC**: localhost:9090

### First Run Setup

1. Open http://localhost:3000
2. Complete the initial setup wizard
3. Create your admin account
4. Start developing!

## Project Structure

```
InfraPilot/
├── backend/                # Go backend
│   ├── cmd/
│   │   └── server/         # Entry point (main.go:163)
│   ├── internal/
│   │   ├── api/            # REST handlers
│   │   ├── auth/           # Authentication
│   │   ├── db/             # Database & migrations
│   │   ├── grpc/           # gRPC services
│   │   └── ...
│   ├── go.mod
│   └── .air.toml           # Hot-reload config
│
├── agent/                  # Go agent
│   ├── cmd/
│   │   └── agent/          # Entry point (main.go:1304)
│   ├── internal/
│   │   ├── docker/         # Docker client
│   │   ├── nginx/          # Nginx management
│   │   ├── ssl/            # SSL/ACME
│   │   └── ...
│   └── go.mod
│
├── frontend/               # Next.js frontend
│   ├── app/                # App Router
│   │   ├── (auth)/         # Auth pages
│   │   └── (dashboard)/    # Dashboard pages
│   ├── components/         # React components
│   ├── lib/                # Utilities
│   ├── package.json
│   └── next.config.js
│
├── proto/                  # Protocol Buffers
│   └── agent/v1/
│       └── agent.proto
│
├── deployments/            # Docker configs
├── scripts/                # Helper scripts
└── docs/                   # Documentation
```

## Running Tests

### Backend Tests

```bash
cd backend
go test ./...                    # All tests
go test ./internal/api/...       # Specific package
go test -v ./...                 # Verbose
go test -cover ./...             # With coverage
```

### Agent Tests

```bash
cd agent
go test ./...
go test -v ./internal/docker/... # Specific package
```

### Frontend Tests

```bash
cd frontend
pnpm test                        # Run tests
pnpm test:watch                  # Watch mode
pnpm test:coverage               # With coverage
```

### Integration Tests

```bash
# Start all services first
./scripts/dev.sh up
cd backend && air &
cd agent && go run cmd/agent/main.go &
cd frontend && pnpm dev &

# Run integration tests
./scripts/integration-test.sh
```

## Building

### Build All Components

```bash
# From root directory
make build
```

### Build Individual Components

**Backend**:
```bash
cd backend
go build -o bin/server cmd/server/main.go
./bin/server
```

**Agent**:
```bash
cd agent
go build -o bin/agent cmd/agent/main.go
./bin/agent
```

**Frontend**:
```bash
cd frontend
pnpm build
pnpm start  # Production server
```

### Build Docker Image

```bash
# From root directory
docker build -t infrapilot:dev .

# Run the image
docker run -d \
  --name infrapilot-dev \
  -p 80:80 -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e JWT_SECRET=dev-secret \
  infrapilot:dev
```

### Build Specific Stage

The Dockerfile has multi-stage builds:

```bash
# Build only backend
docker build --target backend-builder -t infrapilot-backend:dev .

# Build only agent
docker build --target agent-builder -t infrapilot-agent:dev .

# Build only frontend
docker build --target frontend-builder -t infrapilot-frontend:dev .
```

## Database Migrations

### Create a New Migration

```bash
cd backend/internal/db/migrations

# Create new migration files
touch 010_add_new_feature.up.sql
touch 010_add_new_feature.down.sql
```

**Example migration** (`010_add_new_feature.up.sql`):
```sql
-- Add new feature
CREATE TABLE IF NOT EXISTS new_feature (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add index
CREATE INDEX idx_new_feature_name ON new_feature(name);
```

**Down migration** (`010_add_new_feature.down.sql`):
```sql
-- Rollback new feature
DROP TABLE IF EXISTS new_feature;
```

### Run Migrations

Migrations run automatically on backend startup. To run manually:

```bash
cd backend
go run cmd/server/main.go  # Runs migrations on start
```

### Migration Naming Convention

Format: `NNN_description_of_change.up.sql` / `.down.sql`

Examples:
- `001_initial_schema.up.sql`
- `002_add_users_table.up.sql`
- `003_add_mfa_fields.up.sql`

## gRPC Development

### Modify gRPC Services

1. **Edit Protocol Buffer definitions**:

```bash
vim proto/agent/v1/agent.proto
```

2. **Generate Go code**:

```bash
make proto
# Or manually:
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/agent/v1/agent.proto
```

3. **Implement new methods**:

**Backend** (`backend/internal/grpc/service.go`):
```go
func (s *AgentService) NewMethod(ctx context.Context, req *agentpb.NewRequest) (*agentpb.NewResponse, error) {
    // Implementation
    return &agentpb.NewResponse{}, nil
}
```

**Agent** (`agent/internal/grpc/client.go`):
```go
// Call new method
resp, err := client.NewMethod(ctx, &agentpb.NewRequest{})
```

### Test gRPC Endpoints

Use `grpcurl` for testing:

```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# List services
grpcurl -plaintext localhost:9090 list

# Call method
grpcurl -plaintext -d '{"agent_id": "test"}' \
    localhost:9090 agent.v1.AgentService/Heartbeat
```

## Frontend Development

### Add a New Page

1. **Create page file**:

```bash
cd frontend/app/(dashboard)
mkdir my-feature
touch my-feature/page.tsx
```

2. **Implement page**:

```typescript
// frontend/app/(dashboard)/my-feature/page.tsx
export default function MyFeaturePage() {
  return (
    <div>
      <h1>My Feature</h1>
    </div>
  );
}
```

3. **Add navigation** (if needed):

```typescript
// frontend/components/Sidebar.tsx
const navItems = [
  // ...
  { name: 'My Feature', href: '/my-feature', icon: IconName },
];
```

### Add API Integration

1. **Create API client**:

```typescript
// frontend/lib/api/my-feature.ts
export async function getMyFeature() {
  const res = await fetch('/api/v1/my-feature');
  if (!res.ok) throw new Error('Failed to fetch');
  return res.json();
}
```

2. **Use in component**:

```typescript
import { useQuery } from '@tanstack/react-query';
import { getMyFeature } from '@/lib/api/my-feature';

export default function MyFeature() {
  const { data, isLoading } = useQuery({
    queryKey: ['my-feature'],
    queryFn: getMyFeature,
  });

  if (isLoading) return <div>Loading...</div>;

  return <div>{JSON.stringify(data)}</div>;
}
```

### UI Components

Use existing components from `/frontend/components`:

```typescript
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
```

### Styling

InfraPilot uses Tailwind CSS:

```typescript
<div className="flex items-center justify-between p-4 bg-gray-100 dark:bg-gray-800">
  <h1 className="text-2xl font-bold">Title</h1>
  <Button variant="primary">Action</Button>
</div>
```

## Debugging

### Backend Debugging

**Using Delve**:

```bash
cd backend
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug
dlv debug cmd/server/main.go
```

**VS Code** (`.vscode/launch.json`):
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Backend",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}/backend/cmd/server/main.go",
      "env": {
        "JWT_SECRET": "dev-secret",
        "DATABASE_URL": "postgres://infrapilot:infrapilot@localhost:5432/infrapilot?sslmode=disable"
      }
    }
  ]
}
```

### Agent Debugging

```bash
cd agent
dlv debug cmd/agent/main.go -- --backend-url=localhost:9090
```

### Frontend Debugging

**Browser DevTools**: Use React DevTools extension

**VS Code**:
```json
{
  "name": "Debug Frontend",
  "type": "chrome",
  "request": "launch",
  "url": "http://localhost:3000",
  "webRoot": "${workspaceFolder}/frontend"
}
```

### Database Debugging

```bash
# Connect to PostgreSQL
psql postgres://infrapilot:infrapilot@localhost:5432/infrapilot

# Useful queries
\dt                              -- List tables
\d table_name                    -- Describe table
SELECT * FROM users;             -- Query data
EXPLAIN ANALYZE SELECT ...;      -- Query plan
```

### Logs

**Backend logs**:
```bash
cd backend
air 2>&1 | tee backend.log  # Save to file
```

**Agent logs**:
```bash
cd agent
go run cmd/agent/main.go 2>&1 | tee agent.log
```

**Frontend logs**: Check browser console and terminal

## Code Style

### Go Code Style

Follow standard Go conventions:

```bash
# Format code
go fmt ./...

# Lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
golangci-lint run

# Vet
go vet ./...
```

**Style Guidelines**:
- Use `gofmt` for formatting
- Follow [Effective Go](https://go.dev/doc/effective_go)
- Use meaningful variable names
- Add comments for exported functions
- Keep functions small and focused

### TypeScript/React Style

```bash
cd frontend

# Format
pnpm format

# Lint
pnpm lint

# Type check
pnpm type-check
```

**Style Guidelines**:
- Use functional components with hooks
- Use TypeScript for type safety
- Follow React best practices
- Use Tailwind utility classes
- Keep components small and reusable

## Common Tasks

### Add a New REST API Endpoint

1. **Define handler** (`backend/internal/api/my_handlers.go`):

```go
func (h *Handler) myNewEndpoint(c *gin.Context) {
    // Implementation
    c.JSON(200, gin.H{"message": "success"})
}
```

2. **Register route** (`backend/internal/api/handler.go`):

```go
protected.GET("/my-endpoint", h.myNewEndpoint)
```

3. **Add frontend client** (`frontend/lib/api/my-api.ts`):

```typescript
export async function callMyEndpoint() {
  const res = await fetch('/api/v1/my-endpoint');
  return res.json();
}
```

### Add a New Database Table

1. **Create migration** (see [Database Migrations](#database-migrations))

2. **Define model** (`backend/internal/db/models.go` or similar):

```go
type MyModel struct {
    ID        uuid.UUID `json:"id"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
}
```

3. **Add queries** (`backend/internal/db/queries.go` or similar):

```go
func (db *DB) CreateMyModel(ctx context.Context, name string) (*MyModel, error) {
    var model MyModel
    err := db.pool.QueryRow(ctx, `
        INSERT INTO my_models (name) VALUES ($1)
        RETURNING id, name, created_at
    `, name).Scan(&model.ID, &model.Name, &model.CreatedAt)
    return &model, err
}
```

### Add a New Docker Operation

1. **Implement in agent** (`agent/internal/docker/operations.go`):

```go
func (c *Client) MyDockerOperation(ctx context.Context) error {
    // Use c.cli (Docker client)
    return c.cli.SomeDockerAPI(ctx, ...)
}
```

2. **Add gRPC method** (update `proto/agent/v1/agent.proto` and regenerate)

3. **Implement backend handler**

4. **Add frontend UI**

## Contributing

### Before Submitting a PR

1. **Test your changes**:
```bash
make test
```

2. **Format code**:
```bash
# Go
go fmt ./...

# TypeScript
cd frontend && pnpm format
```

3. **Lint**:
```bash
golangci-lint run
cd frontend && pnpm lint
```

4. **Update documentation** if needed

5. **Write meaningful commit messages**:
```
feat: Add container restart policy support

- Add restart_policy field to containers table
- Implement restart policy in agent
- Add UI for configuring restart policies
- Add tests for restart policy functionality

Closes #123
```

### Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Maintenance tasks

### PR Guidelines

1. **Branch naming**: `feature/my-feature` or `fix/my-bug`
2. **Keep PRs focused**: One feature/fix per PR
3. **Write tests**: For new functionality
4. **Update docs**: If adding new features
5. **Request review**: From maintainers

## Useful Scripts

```bash
# Start dev environment
./scripts/dev.sh up

# Stop dev environment
./scripts/dev.sh down

# Reset database
./scripts/dev.sh reset

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Rebuild everything
make clean build

# Run all tests
make test

# Generate proto files
make proto
```

## Environment Variables Reference

See [CONFIGURATION.md](CONFIGURATION.md) for full reference.

**Development-specific**:

```bash
ENV=development              # Enable dev mode
LOG_LEVEL=debug             # Verbose logging
DISABLE_AUTH=false          # For testing only
```

## Troubleshooting Development Issues

### Port Already in Use

```bash
# Find process using port 8080
lsof -i :8080
# Kill process
kill -9 <PID>
```

### Database Connection Failed

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Restart database
./scripts/dev.sh down
./scripts/dev.sh up
```

### Hot Reload Not Working

```bash
# Backend: Restart air
cd backend
pkill air
air

# Frontend: Restart dev server
cd frontend
pkill next-dev
pnpm dev
```

### Module Not Found (Go)

```bash
cd backend  # or agent
go mod tidy
go mod download
```

### Package Not Found (Frontend)

```bash
cd frontend
rm -rf node_modules
pnpm install
```

## Performance Profiling

### Go Profiling

```bash
# CPU profiling
go test -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof ./...
go tool pprof mem.prof
```

### Frontend Profiling

Use React DevTools Profiler tab in browser.

## Additional Resources

- [Go Documentation](https://go.dev/doc/)
- [Next.js Documentation](https://nextjs.org/docs)
- [Docker API Reference](https://docs.docker.com/engine/api/)
- [gRPC Documentation](https://grpc.io/docs/)
- [Tailwind CSS Documentation](https://tailwindcss.com/docs)

---

**Last Updated**: 2026-01-14

For questions, open an issue on GitHub or contact the development team.
