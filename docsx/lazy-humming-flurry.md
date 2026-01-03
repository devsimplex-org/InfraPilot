# InfraPilot Technical Architecture

## Tech Stack Summary
| Component | Technology |
|-----------|------------|
| Backend API | Go 1.22+ |
| Database | PostgreSQL 16 |
| Agent Protocol | gRPC + mTLS |
| Frontend | Next.js 15 (App Router) |
| Cache/Realtime | Redis (pub/sub for logs) |
| ORM | sqlc (type-safe SQL) |

---

## 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        INFRAPILOT DASHBOARD                      │
│                      (Next.js 15 + Tailwind)                     │
└─────────────────────────────┬───────────────────────────────────┘
                              │ HTTPS (REST + WebSocket)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        INFRAPILOT BACKEND                        │
│                           (Go API)                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ Auth/JWT │ │ Nginx    │ │ Docker   │ │ Alerts   │            │
│  │ Handler  │ │ Handler  │ │ Handler  │ │ Handler  │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
│                              │                                   │
│  ┌───────────────────────────┴────────────────────────────────┐ │
│  │                      gRPC Server                            │ │
│  │               (Agent Communication Hub)                     │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────┬─────────────────────────────────┬────────────────┘
               │                                 │
               ▼                                 ▼
┌──────────────────────────┐       ┌──────────────────────────────┐
│       PostgreSQL         │       │           Redis              │
│  (Config, Users, Audit)  │       │  (Pub/Sub Logs, Sessions)    │
└──────────────────────────┘       └──────────────────────────────┘
                                             │
               ┌─────────────────────────────┘
               │ gRPC + mTLS
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                      INFRAPILOT AGENT                            │
│                    (Go binary on host)                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │ Docker   │ │ Nginx    │ │ Metrics  │ │ Log      │            │
│  │ Watcher  │ │ Manager  │ │ Collector│ │ Streamer │            │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘            │
└─────────────────────────────────────────────────────────────────┘
        │               │               │
        ▼               ▼               ▼
   Docker API      Nginx Config    Container Logs
```

---

## 2. Database Schema (PostgreSQL)

### Core Tables

```sql
-- Multi-tenancy ready
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Users & Authentication
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    mfa_secret      VARCHAR(255),
    mfa_enabled     BOOLEAN DEFAULT FALSE,
    role            VARCHAR(50) NOT NULL CHECK (role IN ('super_admin', 'operator', 'viewer')),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

-- Agents registered with backend
CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    name            VARCHAR(255) NOT NULL,
    hostname        VARCHAR(255),
    fingerprint     VARCHAR(64) UNIQUE NOT NULL,  -- mTLS cert fingerprint
    last_seen_at    TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'offline')),
    version         VARCHAR(50),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Nginx proxy hosts
CREATE TABLE proxy_hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id) ON DELETE CASCADE,
    domain          VARCHAR(255) NOT NULL,
    upstream_target VARCHAR(255) NOT NULL,  -- e.g., "container:port" or "ip:port"
    ssl_enabled     BOOLEAN DEFAULT FALSE,
    ssl_cert_path   VARCHAR(500),
    ssl_key_path    VARCHAR(500),
    ssl_expires_at  TIMESTAMPTZ,
    force_ssl       BOOLEAN DEFAULT TRUE,
    http2_enabled   BOOLEAN DEFAULT TRUE,
    config_hash     VARCHAR(64),  -- SHA256 of generated config
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, domain)
);

-- Security headers config per host
CREATE TABLE proxy_security_headers (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id           UUID REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    hsts_enabled            BOOLEAN DEFAULT TRUE,
    hsts_max_age            INTEGER DEFAULT 31536000,
    x_frame_options         VARCHAR(50) DEFAULT 'SAMEORIGIN',
    x_content_type_options  BOOLEAN DEFAULT TRUE,
    x_xss_protection        BOOLEAN DEFAULT TRUE,
    content_security_policy TEXT,
    created_at              TIMESTAMPTZ DEFAULT NOW()
);

-- Rate limiting rules
CREATE TABLE rate_limits (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    zone_name       VARCHAR(100) NOT NULL,
    requests_per    INTEGER NOT NULL,       -- e.g., 100
    time_window     VARCHAR(10) NOT NULL,   -- e.g., "1s", "1m"
    burst           INTEGER DEFAULT 50,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- IP allow/deny lists
CREATE TABLE ip_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    ip_cidr         VARCHAR(50) NOT NULL,   -- e.g., "192.168.1.0/24"
    action          VARCHAR(10) NOT NULL CHECK (action IN ('allow', 'deny')),
    priority        INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Docker containers (synced from agent)
CREATE TABLE containers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id) ON DELETE CASCADE,
    container_id    VARCHAR(64) NOT NULL,   -- Docker container ID
    name            VARCHAR(255) NOT NULL,
    image           VARCHAR(500) NOT NULL,
    stack_name      VARCHAR(255),           -- docker-compose project name
    status          VARCHAR(50),            -- running, stopped, etc.
    cpu_percent     DECIMAL(5,2),
    memory_mb       INTEGER,
    memory_limit_mb INTEGER,
    restart_count   INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ,
    last_synced_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, container_id)
);

-- Container to proxy host linking
CREATE TABLE container_upstreams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_host_id   UUID REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    container_id    UUID REFERENCES containers(id) ON DELETE CASCADE,
    container_port  INTEGER NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(proxy_host_id, container_id, container_port)
);

-- Alert configurations
CREATE TABLE alert_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    name            VARCHAR(255) NOT NULL,
    channel_type    VARCHAR(50) NOT NULL CHECK (channel_type IN ('smtp', 'slack', 'webhook')),
    config          JSONB NOT NULL,         -- channel-specific config
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    name            VARCHAR(255) NOT NULL,
    rule_type       VARCHAR(50) NOT NULL,   -- container_crash, ssl_expiry, high_5xx, etc.
    conditions      JSONB NOT NULL,         -- threshold conditions
    channels        UUID[] NOT NULL,        -- array of alert_channel IDs
    cooldown_mins   INTEGER DEFAULT 15,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE alert_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID REFERENCES alert_rules(id),
    agent_id        UUID REFERENCES agents(id),
    triggered_at    TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    severity        VARCHAR(20),
    message         TEXT,
    metadata        JSONB
);

-- Database connections for monitoring
CREATE TABLE monitored_databases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    db_type         VARCHAR(50) NOT NULL CHECK (db_type IN ('postgresql', 'mysql', 'redis')),
    host            VARCHAR(255) NOT NULL,
    port            INTEGER NOT NULL,
    username        VARCHAR(255),
    password_enc    BYTEA,                  -- encrypted
    ssl_mode        VARCHAR(50),
    last_check_at   TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'unknown',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE database_metrics (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    db_id           UUID REFERENCES monitored_databases(id) ON DELETE CASCADE,
    recorded_at     TIMESTAMPTZ DEFAULT NOW(),
    connections     INTEGER,
    disk_usage_mb   BIGINT,
    slow_queries    INTEGER,
    metrics_json    JSONB                   -- additional DB-specific metrics
);

-- Comprehensive audit log
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    user_id         UUID REFERENCES users(id),
    agent_id        UUID REFERENCES agents(id),
    action          VARCHAR(100) NOT NULL,  -- e.g., "container.start", "proxy.create"
    resource_type   VARCHAR(100),
    resource_id     UUID,
    ip_address      INET,
    user_agent      TEXT,
    request_body    JSONB,
    response_status INTEGER,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_audit_logs_org_created ON audit_logs(org_id, created_at DESC);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_containers_agent ON containers(agent_id);
CREATE INDEX idx_proxy_hosts_agent ON proxy_hosts(agent_id);
CREATE INDEX idx_alert_history_rule ON alert_history(rule_id, triggered_at DESC);
```

---

## 3. REST API Contracts (Backend ↔ Frontend)

### Authentication

```
POST   /api/v1/auth/login           # Email + password → JWT
POST   /api/v1/auth/logout          # Invalidate session
POST   /api/v1/auth/refresh         # Refresh JWT
POST   /api/v1/auth/mfa/setup       # Generate TOTP secret
POST   /api/v1/auth/mfa/verify      # Verify TOTP code
GET    /api/v1/auth/me              # Current user info
```

### Agents

```
GET    /api/v1/agents               # List agents
POST   /api/v1/agents               # Register new agent (returns enrollment token)
GET    /api/v1/agents/:id           # Agent details + status
DELETE /api/v1/agents/:id           # Remove agent
GET    /api/v1/agents/:id/metrics   # Agent system metrics
```

### Proxy Hosts (Nginx)

```
GET    /api/v1/agents/:id/proxies              # List proxy hosts
POST   /api/v1/agents/:id/proxies              # Create proxy host
GET    /api/v1/agents/:id/proxies/:pid         # Get proxy details
PUT    /api/v1/agents/:id/proxies/:pid         # Update proxy
DELETE /api/v1/agents/:id/proxies/:pid         # Delete proxy
POST   /api/v1/agents/:id/proxies/:pid/ssl     # Request SSL cert
GET    /api/v1/agents/:id/proxies/:pid/config  # View generated nginx config
POST   /api/v1/agents/:id/proxies/:pid/test    # Test config validity
```

### Containers

```
GET    /api/v1/agents/:id/containers                    # List containers
GET    /api/v1/agents/:id/containers/:cid               # Container details
POST   /api/v1/agents/:id/containers/:cid/start         # Start container
POST   /api/v1/agents/:id/containers/:cid/stop          # Stop container
POST   /api/v1/agents/:id/containers/:cid/restart       # Restart container
GET    /api/v1/agents/:id/containers/:cid/logs          # Container logs (paginated)
WS     /api/v1/agents/:id/containers/:cid/logs/stream   # Live log stream
WS     /api/v1/agents/:id/containers/:cid/exec          # Interactive exec shell
GET    /api/v1/agents/:id/stacks                        # List compose stacks
```

### Logs (Unified)

```
GET    /api/v1/agents/:id/logs/nginx          # Nginx access/error logs
GET    /api/v1/agents/:id/logs/unified        # Combined searchable logs
WS     /api/v1/agents/:id/logs/stream         # Real-time unified log stream
```

### Alerts

```
GET    /api/v1/alerts/channels         # List alert channels
POST   /api/v1/alerts/channels         # Create channel
PUT    /api/v1/alerts/channels/:id     # Update channel
DELETE /api/v1/alerts/channels/:id     # Delete channel
POST   /api/v1/alerts/channels/:id/test # Test channel

GET    /api/v1/alerts/rules            # List alert rules
POST   /api/v1/alerts/rules            # Create rule
PUT    /api/v1/alerts/rules/:id        # Update rule
DELETE /api/v1/alerts/rules/:id        # Delete rule

GET    /api/v1/alerts/history          # Alert history
```

### Database Monitoring

```
GET    /api/v1/agents/:id/databases            # List monitored DBs
POST   /api/v1/agents/:id/databases            # Add DB connection
DELETE /api/v1/agents/:id/databases/:did       # Remove DB
GET    /api/v1/agents/:id/databases/:did/metrics # DB metrics
```

### Audit

```
GET    /api/v1/audit                  # Query audit logs
```

---

## 4. gRPC Agent Protocol (Backend ↔ Agent)

### Proto Definition

```protobuf
syntax = "proto3";
package infrapilot.agent.v1;

// Agent ↔ Backend bidirectional service
service AgentService {
  // Agent registration and heartbeat
  rpc Register(RegisterRequest) returns (RegisterResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // Bidirectional command stream
  rpc CommandStream(stream AgentMessage) returns (stream BackendMessage);

  // Log streaming
  rpc StreamLogs(LogStreamRequest) returns (stream LogEntry);

  // Metrics push
  rpc PushMetrics(MetricsRequest) returns (MetricsResponse);
}

// Registration
message RegisterRequest {
  string enrollment_token = 1;
  string hostname = 2;
  string agent_version = 3;
  string os_info = 4;
}

message RegisterResponse {
  string agent_id = 1;
  bytes client_cert = 2;      // mTLS cert for future connections
  bytes client_key = 3;
  int32 heartbeat_interval_sec = 4;
}

// Heartbeat
message HeartbeatRequest {
  string agent_id = 1;
  SystemMetrics metrics = 2;
  repeated ContainerState containers = 3;
}

message HeartbeatResponse {
  bool acknowledged = 1;
  repeated PendingCommand pending_commands = 2;
}

// Commands from backend to agent
message BackendMessage {
  string request_id = 1;
  oneof command {
    DockerCommand docker = 10;
    NginxCommand nginx = 11;
    ExecCommand exec = 12;
    LogRequest logs = 13;
    DatabaseCheckCommand db_check = 14;
  }
}

message AgentMessage {
  string request_id = 1;
  oneof response {
    CommandResult result = 10;
    LogEntry log = 11;
    ExecOutput exec_output = 12;
    ErrorResponse error = 13;
  }
}

// Docker commands
message DockerCommand {
  enum Action {
    LIST = 0;
    START = 1;
    STOP = 2;
    RESTART = 3;
    INSPECT = 4;
    LOGS = 5;
    STATS = 6;
  }
  Action action = 1;
  string container_id = 2;
  map<string, string> options = 3;
}

// Nginx commands
message NginxCommand {
  enum Action {
    GET_CONFIG = 0;
    WRITE_CONFIG = 1;
    TEST_CONFIG = 2;
    RELOAD = 3;
    GET_STATUS = 4;
  }
  Action action = 1;
  string config_content = 2;  // For WRITE_CONFIG
  string config_path = 3;
}

// Container exec (shell access)
message ExecCommand {
  string container_id = 1;
  repeated string command = 2;  // e.g., ["/bin/sh", "-c", "ls -la"]
  bool interactive = 3;
  bool tty = 4;
}

message ExecOutput {
  bytes stdout = 1;
  bytes stderr = 2;
  int32 exit_code = 3;
  bool is_final = 4;
}

// System metrics
message SystemMetrics {
  double cpu_percent = 1;
  int64 memory_used_mb = 2;
  int64 memory_total_mb = 3;
  int64 disk_used_mb = 4;
  int64 disk_total_mb = 5;
  int64 uptime_seconds = 6;
}

message ContainerState {
  string container_id = 1;
  string name = 2;
  string image = 3;
  string status = 4;
  string stack_name = 5;
  double cpu_percent = 6;
  int64 memory_mb = 7;
  int64 memory_limit_mb = 8;
  int32 restart_count = 9;
}

// Logs
message LogStreamRequest {
  enum Source {
    NGINX_ACCESS = 0;
    NGINX_ERROR = 1;
    CONTAINER = 2;
  }
  Source source = 1;
  string container_id = 2;  // For CONTAINER source
  int64 since_timestamp = 3;
  bool follow = 4;
}

message LogEntry {
  int64 timestamp = 1;
  string source = 2;
  string level = 3;
  string message = 4;
  map<string, string> metadata = 5;
}

// Database check
message DatabaseCheckCommand {
  string db_type = 1;     // postgresql, mysql, redis
  string host = 2;
  int32 port = 3;
  string username = 4;
  string password = 5;
  string database = 6;
  bool ssl_enabled = 7;
}

message CommandResult {
  bool success = 1;
  string message = 2;
  bytes data = 3;  // JSON-encoded result data
}

message ErrorResponse {
  int32 code = 1;
  string message = 2;
}
```

---

## 5. Security Model

### Authentication Flow

```
┌──────────┐      ┌──────────┐      ┌──────────┐
│  Browser │      │  Backend │      │ Postgres │
└────┬─────┘      └────┬─────┘      └────┬─────┘
     │ POST /login     │                  │
     │ {email, pass}   │                  │
     │────────────────>│                  │
     │                 │ Verify password  │
     │                 │─────────────────>│
     │                 │<─────────────────│
     │                 │                  │
     │                 │ If MFA enabled:  │
     │<────────────────│ {mfa_required}   │
     │                 │                  │
     │ POST /mfa/verify│                  │
     │ {totp_code}     │                  │
     │────────────────>│                  │
     │                 │                  │
     │<────────────────│                  │
     │ {access_token,  │                  │
     │  refresh_token} │                  │
```

### Agent mTLS Enrollment

```
┌──────────┐      ┌──────────┐
│   Agent  │      │  Backend │
└────┬─────┘      └────┬─────┘
     │                  │
     │ gRPC Register()  │
     │ {enrollment_token│
     │  hostname}       │
     │─────────────────>│
     │                  │
     │                  │ Validate token
     │                  │ Generate cert
     │                  │
     │<─────────────────│
     │ {agent_id,       │
     │  client_cert,    │
     │  client_key}     │
     │                  │
     │ Subsequent calls │
     │ use mTLS with    │
     │ issued cert      │
     │═════════════════>│
```

### RBAC Permissions Matrix

| Resource | super_admin | operator | viewer |
|----------|-------------|----------|--------|
| View agents | ✅ | ✅ | ✅ |
| Add/remove agents | ✅ | ❌ | ❌ |
| View containers | ✅ | ✅ | ✅ |
| Start/stop containers | ✅ | ✅ | ❌ |
| Container exec | ✅ | ✅ | ❌ |
| View proxy hosts | ✅ | ✅ | ✅ |
| Modify proxy hosts | ✅ | ✅ | ❌ |
| View logs | ✅ | ✅ | ✅ |
| Manage alerts | ✅ | ✅ | ❌ |
| View audit logs | ✅ | ✅ | ✅ |
| Manage users | ✅ | ❌ | ❌ |
| Manage org settings | ✅ | ❌ | ❌ |

---

## 6. Project Structure

```
infrapilot/
├── backend/                    # Go API server
│   ├── cmd/
│   │   └── server/
│   │       └── main.go
│   ├── internal/
│   │   ├── api/               # HTTP handlers
│   │   │   ├── auth.go
│   │   │   ├── agents.go
│   │   │   ├── containers.go
│   │   │   ├── proxies.go
│   │   │   ├── alerts.go
│   │   │   └── middleware.go
│   │   ├── grpc/              # gRPC server for agents
│   │   │   ├── server.go
│   │   │   └── handlers.go
│   │   ├── db/                # Database layer
│   │   │   ├── queries/       # SQL files for sqlc
│   │   │   ├── migrations/    # SQL migrations
│   │   │   └── sqlc.go
│   │   ├── auth/              # JWT, MFA, RBAC
│   │   ├── nginx/             # Nginx config generator
│   │   └── alerts/            # Alert engine
│   ├── proto/                 # Protobuf definitions
│   ├── go.mod
│   └── Dockerfile
│
├── agent/                      # Go agent binary
│   ├── cmd/
│   │   └── agent/
│   │       └── main.go
│   ├── internal/
│   │   ├── docker/            # Docker API client
│   │   ├── nginx/             # Nginx manager
│   │   ├── metrics/           # System metrics collector
│   │   ├── logs/              # Log streamer
│   │   └── grpc/              # gRPC client
│   ├── go.mod
│   └── Dockerfile
│
├── frontend/                   # Next.js 15 dashboard
│   ├── app/                   # App router pages
│   │   ├── (auth)/
│   │   │   ├── login/
│   │   │   └── mfa/
│   │   ├── (dashboard)/
│   │   │   ├── layout.tsx
│   │   │   ├── page.tsx       # Overview
│   │   │   ├── agents/
│   │   │   ├── containers/
│   │   │   ├── proxies/
│   │   │   ├── logs/
│   │   │   ├── alerts/
│   │   │   └── settings/
│   │   └── layout.tsx
│   ├── components/
│   │   ├── ui/                # Shadcn/ui components
│   │   ├── containers/
│   │   ├── proxies/
│   │   └── logs/
│   ├── lib/
│   │   ├── api.ts             # API client
│   │   ├── auth.ts            # Auth helpers
│   │   └── websocket.ts       # WS connection manager
│   ├── package.json
│   └── Dockerfile
│
├── proto/                      # Shared protobuf definitions
│   └── agent/v1/
│       └── agent.proto
│
├── deployments/
│   ├── docker-compose.yml     # Local development
│   ├── docker-compose.prod.yml
│   └── k8s/                   # Optional K8s manifests
│
├── scripts/
│   ├── generate-proto.sh
│   └── dev.sh
│
└── README.md
```

---

## 7. Implementation Phases

### Phase 1: Foundation (MVP Core)
1. Project scaffolding (monorepo structure)
2. Database schema + migrations
3. Backend: Auth (JWT + MFA), basic RBAC
4. Agent: Registration + heartbeat over gRPC
5. Frontend: Login, dashboard shell

### Phase 2: Module 1 - Nginx Proxy
1. Backend: Proxy host CRUD API
2. Agent: Nginx config writer + reload
3. Frontend: Proxy management UI
4. SSL certificate automation (Let's Encrypt)

### Phase 3: Module 2 - Docker Operations
1. Backend: Container API endpoints
2. Agent: Docker API integration
3. Frontend: Container list, controls
4. Container exec (WebSocket terminal)

### Phase 4: Module 3 - Logs
1. Agent: Log streaming to Redis pub/sub
2. Backend: Unified log aggregation
3. Frontend: Real-time log viewer

### Phase 5: Module 5 - Alerts
1. Alert engine in backend
2. SMTP + Slack + Webhook channels
3. Frontend: Alert configuration UI

### Phase 6: Polish
1. Audit logging throughout
2. Database health monitoring (read-only)
3. TLS health scoring
4. Rate limiting UI

---

## 8. Key Dependencies

### Backend (Go)
```
github.com/gin-gonic/gin          # HTTP router
github.com/jackc/pgx/v5           # PostgreSQL driver
github.com/sqlc-dev/sqlc          # Type-safe SQL
google.golang.org/grpc            # gRPC
github.com/golang-jwt/jwt/v5      # JWT
github.com/pquerna/otp            # TOTP/MFA
github.com/redis/go-redis/v9      # Redis client
github.com/docker/docker          # Docker client
go.uber.org/zap                   # Logging
```

### Agent (Go)
```
google.golang.org/grpc
github.com/docker/docker
github.com/shirou/gopsutil        # System metrics
github.com/fsnotify/fsnotify      # File watching
```

### Frontend (Next.js)
```
next@15
react@19
tailwindcss
@shadcn/ui
@tanstack/react-query
zustand                           # State management
xterm.js                          # Terminal emulator
recharts                          # Charts
```
