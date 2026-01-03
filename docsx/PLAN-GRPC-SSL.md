# Implementation Plan: gRPC Streaming + SSL Automation

> Status: COMPLETED (2026-01-02)

## Overview

Wire up bidirectional gRPC streaming between backend and agent, then implement Let's Encrypt SSL automation.

**Order matters:** gRPC must work first because SSL certificate requests need to reach the agent.

---

## Part 1: gRPC Command Streaming ✅

### 1.1 Backend: Implement CommandStream ✅

**File:** `backend/internal/grpc/service.go`

- Implemented `CommandStream()` method with bidirectional streaming
- Track connected agents by ID in a `sync.Map`
- Added `SendCommand(agentID, command)` function for API handlers
- Added `SendCommandAsync(agentID, command)` for non-blocking dispatch

**Design:**
```go
type AgentConnection struct {
    AgentID   string
    SendCh    chan *BackendMessage
    ResponseCh map[string]chan *AgentMessage
    mu        sync.Mutex
    ctx       context.Context
    cancel    context.CancelFunc
}

var connectedAgents = sync.Map{} // agentID -> *AgentConnection
```

### 1.2 Agent: Implement CommandStream Client ✅

**File:** `agent/internal/grpc/client.go`

- Implemented `ConnectCommandStream()` for persistent connection
- Receives commands from backend, dispatches to handlers
- Sends responses back through stream

**File:** `agent/cmd/agent/main.go`

- Added `HandleCommand()` to CommandHandler struct
- Routes commands to nginx, network, and docker handlers

### 1.3 Wire Backend API to gRPC ✅

**File:** `backend/internal/api/proxies_handlers.go`

Wired handlers to dispatch gRPC commands:
- `createProxyHost()` → dispatches nginx config
- `updateProxyHost()` → dispatches nginx config
- `deleteProxyHost()` → dispatches delete command
- `testProxyConfig()` → dispatches test command with response
- `requestSSL()` → dispatches SSL request command

### 1.4 Agent Command Handlers ✅

**File:** `agent/cmd/agent/main.go`

Implemented handlers:
- `handleNginxCommand()` - write_config, test_config, reload, request_ssl
- `handleNetworkCommand()` - list_networks, get_container_networks, check_nginx, attach_nginx, detach_nginx
- `handleDockerCommand()` - placeholder (uses HTTP API)

---

## Part 2: SSL Automation (Let's Encrypt) ✅

### 2.1 ACME Client Integration ✅

**File:** `agent/internal/ssl/acme.go`

- Uses `github.com/go-acme/lego/v4` library
- Stores certs in shared volume: `/etc/letsencrypt/live/{domain}/`

**Challenge Methods:**
- **HTTP-01** (implemented): Nginx serves `/.well-known/acme-challenge/` on port 80

**Functions:**
```go
type CertManager struct {
    CertDir     string
    Email       string
    Staging     bool
    logger      *zap.Logger
    accountFile string
}

func (m *CertManager) RequestCertificate(domain string) error
func (m *CertManager) RenewCertificate(domain string) error
func (m *CertManager) GetCertificateExpiry(domain string) (time.Time, error)
func (m *CertManager) NeedsRenewal(domain string, daysBeforeExpiry int) (bool, error)
```

### 2.2 Certificate Request Flow ✅

1. Backend API receives SSL request
2. Backend sends NginxCommand{Action: REQUEST_SSL} via gRPC
3. Agent runs ACME HTTP-01 challenge
4. Agent writes certs to `/etc/letsencrypt/live/{domain}/`
5. Agent reloads nginx
6. Agent sends success/failure response via gRPC

### 2.3 Certificate Renewal ✅

**File:** `agent/cmd/agent/main.go`

- Background goroutine runs daily
- Checks all certificates in `/etc/letsencrypt/live/`
- Auto-renews certs expiring within 30 days
- Reloads nginx after successful renewals

---

## File Changes Summary

| File | Changes |
|------|---------|
| `backend/internal/grpc/service.go` | CommandStream, agent tracking, command helpers |
| `backend/internal/api/proxies_handlers.go` | gRPC dispatch for CRUD and SSL |
| `backend/internal/api/networks_handlers.go` | gRPC dispatch for network operations |
| `agent/internal/grpc/client.go` | CommandStream client, message types |
| `agent/cmd/agent/main.go` | Command handlers, SSL integration, renewal job |
| `agent/internal/ssl/acme.go` | **NEW** - ACME/Let's Encrypt client |
| `agent/internal/nginx/controller.go` | WriteConfigFile method |
| `agent/internal/config/config.go` | SSL config options |

---

## Configuration

**Agent Environment Variables:**
```bash
LETSENCRYPT_DIR=/etc/letsencrypt     # Certificate storage directory
LETSENCRYPT_EMAIL=admin@example.com  # Required for Let's Encrypt account
LETSENCRYPT_STAGING=false            # Use staging server for testing
```

---

## Design Decisions

- **ACME Challenge:** HTTP-01 (default), DNS-01 can be added later
- **Certificate Storage:** Shared volume at `/etc/letsencrypt/`
- **Renewal Threshold:** 30 days before expiry
- **gRPC Pattern:** Channel-based command routing with response tracking

---

## Future Enhancements

1. DNS-01 challenge support for wildcard certificates
2. Certificate status tracking in database
3. Email notifications for renewal failures
4. Support for custom certificate upload
