# InfraPilot Architecture

This document describes the system architecture, component interactions, and design decisions behind InfraPilot.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Components](#components)
- [Communication Flow](#communication-flow)
- [Data Flow](#data-flow)
- [Directory Structure](#directory-structure)
- [Technology Stack](#technology-stack)
- [Design Decisions](#design-decisions)

## Overview

InfraPilot uses a **microservices-based architecture** with three core components running in a single Docker container:

1. **Backend** - Go-based REST API and gRPC server
2. **Agent** - Go-based Docker/Nginx controller with gRPC client
3. **Frontend** - Next.js React application

All components are orchestrated by Nginx as a reverse proxy, with embedded PostgreSQL and Redis for data persistence and caching.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│           Single Docker Container                       │
│         (devsimplex/infrapilot)                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │                Nginx :80/:443                     │  │
│  │          (Reverse Proxy & SSL)                    │  │
│  └───────────┬──────────────────────┬─────────────┬──┘  │
│              │                      │             │     │
│   ┌──────────▼────────┐  ┌──────────▼───────┐    │     │
│   │    Frontend       │  │    Backend       │    │     │
│   │   (Next.js)       │  │     (Go)         │    │     │
│   │     :3000         │  │  :8080 / :9090   │    │     │
│   └───────────────────┘  └──────────┬───────┘    │     │
│                                     │ gRPC       │     │
│                          ┌──────────▼──────────┐  │     │
│                          │   Agent (Go)        │  │     │
│                          │     :9091           │◄─┘     │
│                          └──────────┬──────────┘        │
│                                     │                   │
│                          ┌──────────▼──────────┐        │
│                          │  Docker Daemon API  │        │
│                          │  (via unix socket)  │        │
│                          └─────────────────────┘        │
│                                                         │
│  ┌──────────────────┐           ┌──────────────────┐   │
│  │  PostgreSQL 16   │           │    Redis 7       │   │
│  │   (embedded)     │           │  (embedded)      │   │
│  │     :5432        │           │    :6379         │   │
│  └──────────────────┘           └──────────────────┘   │
│                                                         │
│  Volume: /data                                          │
│  - PostgreSQL data                                      │
│  - SSL certificates                                     │
│  - Nginx configurations                                 │
│  - Logs and metadata                                    │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. Backend (Go)

**Location**: `/backend`

**Responsibilities**:
- REST API server for web dashboard (port 8080)
- gRPC server for agent communication (port 9090)
- Authentication and authorization (JWT, MFA)
- Database operations and migrations
- Alert evaluation engine
- User and organization management

**Key Packages**:

| Package | Purpose |
|---------|---------|
| `cmd/server/` | Main entry point |
| `internal/api/` | REST endpoint handlers |
| `internal/auth/` | JWT, MFA, password hashing |
| `internal/db/` | PostgreSQL migrations and queries |
| `internal/grpc/` | Agent communication service |
| `internal/alerts/` | Alert rule evaluation |
| `internal/config/` | Configuration loading |

**Technology**:
- Framework: Gin (REST API)
- gRPC: google.golang.org/grpc
- Database: pgx/v5 (PostgreSQL driver)
- Authentication: golang-jwt/jwt, pquerna/otp
- Logging: go.uber.org/zap

### 2. Agent (Go)

**Location**: `/agent`

**Responsibilities**:
- Manages local Nginx reverse proxy
- Monitors Docker daemon via API
- Collects system and container metrics
- Handles SSL certificate requests (Let's Encrypt)
- Streams container logs to backend
- Executes commands from backend in real-time

**Key Packages**:

| Package | Purpose |
|---------|---------|
| `cmd/agent/` | Main entry point (1,304 lines) |
| `internal/docker/` | Docker API client |
| `internal/nginx/` | Nginx config management |
| `internal/ssl/` | Let's Encrypt ACME client |
| `internal/grpc/` | Backend communication |
| `internal/logstreamer/` | Log collection and streaming |
| `internal/metrics/` | System metrics collection |
| `internal/enrollment/` | Agent registration |

**Technology**:
- Docker: docker/docker client library
- SSL/ACME: go-acme/lego v4.30
- gRPC: google.golang.org/grpc
- Nginx: Direct configuration file management

**Operational Modes**:
1. **Managed Mode** (default): InfraPilot controls Nginx
2. **External Mode**: Uses external reverse proxy, read-only

### 3. Frontend (Next.js/React)

**Location**: `/frontend`

**Responsibilities**:
- Web-based dashboard UI
- Real-time WebSocket log streaming
- Web terminal (xterm.js)
- Theme management (light/dark)
- API integration with backend

**Key Routes**:

```
app/
├── (auth)/
│   └── auth/              # Login and setup pages
└── (dashboard)/
    ├── page.tsx           # Dashboard home
    ├── proxies/           # Reverse proxy management
    ├── containers/        # Container operations
    ├── logs/              # Log viewer
    ├── alerts/            # Alert configuration
    ├── docker/            # Docker resources
    └── settings/          # User & system settings
```

**Technology**:
- Framework: Next.js 16 (App Router)
- UI: React 19, TypeScript 5.7
- Styling: Tailwind CSS 3.4
- State: Zustand 5.0
- Data Fetching: React Query 5.62
- Terminal: XTerm.js 5.5
- Icons: Lucide React

### 4. Nginx

**Purpose**: Reverse proxy for all traffic

**Configuration**:
- Listens on ports 80 (HTTP) and 443 (HTTPS)
- Routes traffic to frontend (:3000) and backend (:8080)
- Manages SSL certificates
- Provides load balancing for proxy hosts

**Managed by**: Agent component

### 5. PostgreSQL

**Purpose**: Primary data store

**Schema Highlights**:
- Organizations (multi-org support)
- Users (with MFA, roles, audit logs)
- Agents (deployed Docker hosts)
- Proxy hosts (Nginx virtual hosts)
- Containers (running Docker containers)
- Logs (unified log aggregation)
- SSL certificates
- Rate limits
- Alerts and webhooks

**Migrations**: 9 migration files in `backend/internal/db/migrations/`

### 6. Redis

**Purpose**: Caching and session storage

**Use Cases**:
- Session management
- Rate limiting counters
- Temporary data caching

## Communication Flow

### 1. User Request Flow

```
User Browser
    │
    │ HTTP/HTTPS
    ▼
Nginx (:80/:443)
    │
    ├─► Frontend (:3000) ──► Static pages & client-side routing
    │
    └─► Backend (:8080)
            │
            ├─► PostgreSQL ──► Read/Write data
            ├─► Redis ──► Cache/Session
            └─► Agent (gRPC :9090) ──► Commands
                    │
                    └─► Docker Daemon ──► Container operations
```

### 2. Agent Communication Flow

```
Agent (:9091)
    │
    │ gRPC Stream (bidirectional)
    ▼
Backend (:9090)
    │
    ├─► Send Commands ──► Agent executes
    ├─► Receive Heartbeats ──► Track agent status
    ├─► Receive Metrics ──► Store in PostgreSQL
    └─► Receive Logs ──► Store in PostgreSQL
```

### 3. Reverse Proxy Request Flow

```
External Request (:80/:443)
    │
    ▼
Nginx (InfraPilot)
    │
    │ Check proxy_hosts table
    ▼
Route based on hostname/path
    │
    ├─► Container A (:8080) ──► Application
    ├─► Container B (:3000) ──► Application
    └─► Container C (:9000) ──► Application
```

## Data Flow

### 1. Container Log Collection

```
Container
    │
    │ Docker logs API
    ▼
Agent (Log Streamer)
    │
    │ gRPC Stream
    ▼
Backend
    │
    │ Store in PostgreSQL
    ▼
Frontend (WebSocket)
    │
    └─► User Browser (Real-time display)
```

### 2. Metrics Collection

```
Docker Daemon
    │
    │ Container stats API
    ▼
Agent (Metrics Collector)
    │
    │ gRPC (periodic)
    ▼
Backend
    │
    │ Store in PostgreSQL
    ▼
Frontend (Polling/WebSocket)
    │
    └─► User Dashboard (Charts)
```

### 3. SSL Certificate Provisioning

```
User (Create Proxy Host)
    │
    ▼
Backend (Store config)
    │
    │ gRPC Command
    ▼
Agent
    │
    ├─► Let's Encrypt ACME ──► HTTP-01/DNS-01 Challenge
    │       │
    │       └─► Certificate issued
    ├─► Store cert in /data/ssl/
    └─► Update Nginx config
        │
        └─► Reload Nginx
```

## Directory Structure

```
/Users/redapple/DX/infrapilot-community/
├── backend/                    # Go REST API & gRPC server
│   ├── cmd/server/            # Backend entry point
│   │   └── main.go            # main.go:163
│   ├── internal/
│   │   ├── api/               # REST handlers (20+ files)
│   │   ├── auth/              # JWT & MFA authentication
│   │   ├── config/            # Configuration loading
│   │   ├── db/                # PostgreSQL migrations & queries
│   │   │   └── migrations/    # 9 migration files
│   │   ├── grpc/              # Agent communication
│   │   ├── alerts/            # Alert evaluation engine
│   │   └── nginx/             # Nginx config management
│   └── go.mod
│
├── agent/                      # Go gRPC client
│   ├── cmd/agent/             # Agent entry point
│   │   └── main.go            # main.go:1304
│   ├── internal/
│   │   ├── docker/            # Docker API client
│   │   ├── grpc/              # gRPC communication
│   │   ├── nginx/             # Nginx control & config
│   │   ├── ssl/               # Let's Encrypt ACME
│   │   ├── logstreamer/       # Log streaming
│   │   ├── metrics/           # System metrics
│   │   ├── enrollment/        # Agent registration
│   │   └── sync/              # Config synchronization
│   └── go.mod
│
├── frontend/                   # Next.js React application
│   ├── app/                   # Next.js App Router
│   │   ├── (auth)/            # Login/setup pages
│   │   └── (dashboard)/       # Protected dashboard routes
│   ├── components/            # Reusable React components
│   ├── lib/                   # Utilities and hooks
│   └── package.json
│
├── proto/                      # Protocol Buffers
│   └── agent/v1/
│       └── agent.proto        # gRPC service definitions
│
├── deployments/                # Docker/supervisor config
│   ├── nginx/                 # Nginx templates
│   ├── supervisor/            # Process management
│   └── docker-entrypoint.sh   # Container startup script
│
├── docs/                       # Documentation
│   ├── README.md              # Documentation overview
│   ├── ARCHITECTURE.md        # This file
│   ├── API-REFERENCE.md       # API documentation
│   ├── DEVELOPMENT.md         # Development guide
│   ├── DEPLOYMENT.md          # Deployment guide
│   ├── CONFIGURATION.md       # Configuration reference
│   └── TROUBLESHOOTING.md     # Common issues
│
├── scripts/                    # Helper scripts
├── Dockerfile                  # Multi-stage build
├── docker-compose.yml          # Production deployment
├── docker-compose.dev.yml      # Development environment
└── README.md                   # Project overview
```

## Technology Stack

### Backend
- **Language**: Go 1.24
- **Web Framework**: Gin v1.9
- **RPC**: gRPC v1.77
- **Database**: PostgreSQL 16 (pgx/v5 driver)
- **Cache**: Redis 7
- **Authentication**: golang-jwt/jwt v5, pquerna/otp
- **Docker**: docker/docker v27
- **SSL**: go-acme/lego v4.30
- **Logging**: go.uber.org/zap
- **WebSocket**: gorilla/websocket

### Agent
- **Language**: Go 1.24
- **Docker**: docker/docker client
- **SSL**: go-acme/lego v4.30
- **gRPC**: google.golang.org/grpc

### Frontend
- **Framework**: Next.js 16
- **Language**: TypeScript 5.7
- **UI Library**: React 19
- **Styling**: Tailwind CSS 3.4
- **Package Manager**: pnpm
- **State Management**: Zustand 5.0
- **Data Fetching**: React Query 5.62
- **Terminal**: XTerm.js 5.5
- **Icons**: Lucide React

### Infrastructure
- **Container Runtime**: Docker
- **Process Manager**: Supervisor
- **Reverse Proxy**: Nginx
- **Database**: PostgreSQL 16
- **Cache**: Redis 7

## Design Decisions

### 1. Single Container Deployment

**Decision**: Package all components (backend, agent, nginx, databases) in one Docker container.

**Rationale**:
- Simplifies deployment for single-node setups
- Reduces operational complexity
- Suitable for target audience (small teams, single servers)
- Can still use external databases for high availability

**Trade-offs**:
- Less flexible scaling (can't scale components independently)
- Larger container image size
- Not suitable for multi-node deployments (use Enterprise Edition)

### 2. gRPC for Agent Communication

**Decision**: Use gRPC with bidirectional streaming for backend-agent communication.

**Rationale**:
- Efficient binary protocol (vs REST/JSON)
- Bidirectional streaming for real-time commands
- Strong typing with Protocol Buffers
- Built-in support for connection management

**Trade-offs**:
- More complex than REST
- Requires Protocol Buffer compilation step
- Harder to debug (binary protocol)

### 3. Embedded vs External Databases

**Decision**: Support both embedded (default) and external PostgreSQL/Redis.

**Rationale**:
- Easy setup for development and small deployments
- Flexibility for production deployments
- Clear upgrade path to external databases

**Implementation**:
- Default: Embedded PostgreSQL and Redis in container
- Optional: External via `DATABASE_URL` and `REDIS_URL`

### 4. Managed vs External Proxy Mode

**Decision**: Support two proxy modes.

**Modes**:
1. **Managed Mode** (default): InfraPilot controls Nginx
2. **External Mode**: Integrate with existing reverse proxy

**Rationale**:
- Most users want turnkey solution (managed)
- Some users have existing proxy infrastructure (external)
- Provides flexibility without forcing a choice

### 5. Multi-Tenancy Support

**Decision**: Built-in organization support in data model.

**Rationale**:
- Future-proof for SaaS deployments
- Enables Enterprise Edition features
- Minimal overhead in Community Edition

**Implementation**:
- Every resource belongs to an organization
- Single organization in Community Edition
- Multi-org in Enterprise Edition

### 6. Role-Based Access Control

**Decision**: Three permission levels.

**Roles**:
1. **super_admin**: Full system access
2. **operator**: Can manage containers and proxies
3. **viewer**: Read-only access

**Rationale**:
- Simple enough for small teams
- Flexible enough for larger organizations
- Industry-standard approach

### 7. No SSH Required

**Decision**: All operations through APIs (Docker API, Nginx config files).

**Rationale**:
- Security: Reduce attack surface
- Auditability: All actions logged
- Accessibility: Web-based interface for non-technical users
- Flexibility: Can run without host OS access

### 8. Let's Encrypt Integration

**Decision**: Built-in ACME client for automatic SSL.

**Rationale**:
- Free SSL certificates
- Automatic renewal
- Industry standard
- Reduces operational burden

**Implementation**:
- HTTP-01 challenge (default)
- DNS-01 challenge (for wildcards)
- Staging environment for testing

## Security Architecture

### Authentication Flow

```
User Login
    │
    ▼
Backend (Validate credentials)
    │
    ├─► Check password hash
    ├─► Verify TOTP (if MFA enabled)
    └─► Generate JWT token
            │
            └─► Return to client
                    │
                    └─► Store in HTTP-only cookie
```

### Authorization Flow

```
API Request
    │
    ▼
Backend Middleware
    │
    ├─► Validate JWT token
    ├─► Extract user ID and role
    ├─► Check permission for endpoint
    │
    ├─► Allowed ──► Process request
    └─► Denied ──► 403 Forbidden
```

### Audit Trail

All actions are logged:
- User actions (login, logout, config changes)
- Container operations (start, stop, restart)
- Proxy host modifications
- SSL certificate requests
- Alert triggers

Stored in PostgreSQL `audit_logs` table.

## Performance Considerations

### Database Connections

- **Backend**: Connection pool (max 20 connections)
- **Agent**: Dedicated connection for metrics
- **Migrations**: Automatic on startup

### Caching Strategy

- **Redis**: Session data, rate limit counters
- **Frontend**: React Query for API response caching
- **Nginx**: Static file caching

### Real-time Updates

- **Logs**: WebSocket streaming from backend
- **Metrics**: Polling every 5 seconds
- **Container Status**: gRPC streaming from agent

## Scalability

### Current Limitations (Community Edition)

- **Single Node**: All components in one container
- **Vertical Scaling Only**: Scale by adding more CPU/RAM
- **Embedded Databases**: Limited by single instance

### Scale-Out Options (Enterprise Edition)

- **Multi-Node Clustering**: Deploy multiple agent nodes
- **External Databases**: PostgreSQL cluster, Redis cluster
- **Load Balancing**: Multiple backend instances
- **High Availability**: Redundant components

## Extensibility

### Adding New API Endpoints

1. Define handler in `backend/internal/api/`
2. Add route in `backend/cmd/server/main.go`
3. Add frontend API call in `frontend/lib/`
4. Update UI components

### Adding New Database Tables

1. Create migration file in `backend/internal/db/migrations/`
2. Define schema with `CREATE TABLE`
3. Add model structs in relevant package
4. Write queries using pgx

### Adding New gRPC Methods

1. Update `proto/agent/v1/agent.proto`
2. Regenerate Go code: `make proto`
3. Implement method in `backend/internal/grpc/`
4. Add handler in `agent/internal/grpc/`

## Monitoring and Observability

### Logs

- **Backend**: Structured logging with zap
- **Agent**: Structured logging with zap
- **Frontend**: Browser console + Next.js logs
- **Nginx**: Access and error logs

### Metrics

- **System**: CPU, memory, disk usage
- **Containers**: CPU, memory, network, disk I/O
- **Application**: Request counts, error rates

### Health Checks

- **Backend**: `/health` endpoint
- **Agent**: Heartbeat to backend every 30s
- **Database**: Connection pool health
- **Redis**: PING command

## Disaster Recovery

### Backup Strategy

**Critical Data** (stored in `/data` volume):
- PostgreSQL database
- SSL certificates
- Nginx configurations
- Application logs

**Backup Recommendations**:
- Daily volume snapshots
- Offsite backup storage
- Test restore procedures regularly

### Recovery Procedures

1. **Container Failure**: Docker auto-restart
2. **Data Loss**: Restore from volume backup
3. **Database Corruption**: Restore from PostgreSQL backup
4. **SSL Certificate Loss**: Re-issue from Let's Encrypt

## Future Architecture Improvements

### Planned Enhancements

1. **Distributed Tracing**: Add OpenTelemetry support
2. **Metrics Export**: Prometheus exporter
3. **Event Sourcing**: Append-only event log
4. **Plugin System**: Third-party integrations
5. **API Versioning**: Support multiple API versions
6. **GraphQL API**: Alternative to REST
7. **Real-time Sync**: WebSocket for all updates

### Community Feedback

See [GitHub Issues](https://github.com/devsimplex-org/InfraPilot/issues) for feature requests and discussions.

---

**Last Updated**: 2026-01-14
**Version**: Community Edition
