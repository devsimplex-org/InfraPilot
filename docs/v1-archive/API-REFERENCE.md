# API Reference

This document describes the InfraPilot REST API endpoints, request/response formats, and authentication.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Common Patterns](#common-patterns)
- [API Endpoints](#api-endpoints)
  - [Health & Setup](#health--setup)
  - [Authentication](#authentication-endpoints)
  - [Agents](#agents)
  - [Proxy Hosts](#proxy-hosts)
  - [SSL/TLS](#ssltls)
  - [Containers](#containers)
  - [Docker Resources](#docker-resources)
  - [Logs](#logs)
  - [Alerts](#alerts)
  - [Users](#users)
  - [Settings](#settings)
  - [Audit](#audit)

## Overview

**Base URL**: `http://your-infrapilot-domain/api/v1`

**Content Type**: All requests and responses use `application/json`

**API Version**: v1 (current)

## Authentication

Most API endpoints require authentication using JSON Web Tokens (JWT).

### Authentication Flow

1. **Login** via `POST /api/v1/auth/login` with email and password
2. Receive JWT token in response
3. Include token in subsequent requests via:
   - **Cookie**: `token=<jwt>` (recommended)
   - **Header**: `Authorization: Bearer <jwt>`

### MFA (Multi-Factor Authentication)

If MFA is enabled for a user:

1. Login returns `mfa_required: true` with an `mfa_token`
2. Verify MFA code via `POST /api/v1/auth/mfa/verify` with the MFA token and TOTP code
3. Receive JWT token upon successful verification

### Role-Based Access Control

Three roles with different permissions:

| Role | Permissions |
|------|-------------|
| `super_admin` | Full system access, user management, system settings |
| `operator` | Manage containers, proxies, view logs, create alerts |
| `viewer` | Read-only access to all resources |

## Common Patterns

### Pagination

List endpoints support pagination:

```
GET /api/v1/resource?page=1&limit=20
```

**Parameters**:
- `page` - Page number (default: 1)
- `limit` - Items per page (default: 20, max: 100)

**Response**:
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100
  }
}
```

### Filtering

Some endpoints support filtering:

```
GET /api/v1/logs?level=error&source=container-abc
```

### Error Responses

All errors follow this format:

```json
{
  "error": "Error message",
  "code": "ERROR_CODE"
}
```

**Common HTTP Status Codes**:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

## API Endpoints

### Health & Setup

#### Health Check

```http
GET /health
```

**Response**:
```json
{
  "status": "ok",
  "edition": "community"
}
```

**Authentication**: None required

---

#### Get Setup Status

```http
GET /api/v1/setup/status
```

**Response**:
```json
{
  "setup_required": true
}
```

**Authentication**: None required

---

#### Create Initial Admin

```http
POST /api/v1/setup
```

**Request Body**:
```json
{
  "email": "admin@example.com",
  "password": "secure-password",
  "full_name": "Admin User"
}
```

**Response**:
```json
{
  "user": {
    "id": "uuid",
    "email": "admin@example.com",
    "full_name": "Admin User",
    "role": "super_admin"
  },
  "token": "jwt-token"
}
```

**Authentication**: None required (only works when no users exist)

---

### Authentication Endpoints

#### Login

```http
POST /api/v1/auth/login
```

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "password"
}
```

**Response (No MFA)**:
```json
{
  "token": "jwt-token",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "full_name": "User Name",
    "role": "operator",
    "mfa_enabled": false
  }
}
```

**Response (MFA Required)**:
```json
{
  "mfa_required": true,
  "mfa_token": "temporary-token"
}
```

---

#### Verify MFA

```http
POST /api/v1/auth/mfa/verify
```

**Request Body**:
```json
{
  "mfa_token": "temporary-token",
  "code": "123456"
}
```

**Response**:
```json
{
  "token": "jwt-token",
  "user": { ... }
}
```

---

#### Get Current User

```http
GET /api/v1/auth/me
```

**Response**:
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "full_name": "User Name",
  "role": "operator",
  "mfa_enabled": true,
  "org_id": "uuid"
}
```

**Authentication**: Required

---

#### Setup MFA

```http
POST /api/v1/auth/mfa/setup
```

**Response**:
```json
{
  "secret": "BASE32SECRET",
  "qr_code": "otpauth://totp/InfraPilot:user@example.com?secret=BASE32SECRET&issuer=InfraPilot"
}
```

**Authentication**: Required

---

#### Confirm MFA Setup

```http
POST /api/v1/auth/mfa/confirm
```

**Request Body**:
```json
{
  "code": "123456"
}
```

**Response**:
```json
{
  "success": true,
  "backup_codes": ["code1", "code2", "..."]
}
```

**Authentication**: Required

---

#### Logout

```http
POST /api/v1/auth/logout
```

**Response**:
```json
{
  "success": true
}
```

**Authentication**: Required

---

### Agents

#### List Agents

```http
GET /api/v1/agents
```

**Response**:
```json
{
  "agents": [
    {
      "id": "uuid",
      "name": "docker-host-1",
      "hostname": "docker1.example.com",
      "status": "online",
      "last_seen": "2026-01-14T10:30:00Z",
      "cpu_usage": 45.2,
      "memory_usage": 62.8,
      "disk_usage": 38.5
    }
  ]
}
```

**Authentication**: Required

---

#### Create Agent

```http
POST /api/v1/agents
```

**Request Body**:
```json
{
  "name": "docker-host-2",
  "description": "Secondary Docker host"
}
```

**Response**:
```json
{
  "agent": {
    "id": "uuid",
    "name": "docker-host-2",
    "enrollment_token": "token-for-agent-to-use"
  }
}
```

**Authentication**: Required (super_admin only)

---

#### Get Agent

```http
GET /api/v1/agents/:id
```

**Response**:
```json
{
  "id": "uuid",
  "name": "docker-host-1",
  "hostname": "docker1.example.com",
  "status": "online",
  "last_seen": "2026-01-14T10:30:00Z",
  "cpu_usage": 45.2,
  "memory_usage": 62.8,
  "disk_usage": 38.5,
  "docker_version": "24.0.5",
  "os": "Ubuntu 22.04",
  "architecture": "x86_64"
}
```

**Authentication**: Required

---

#### Delete Agent

```http
DELETE /api/v1/agents/:id
```

**Response**:
```json
{
  "success": true
}
```

**Authentication**: Required (super_admin only)

---

#### Get Agent Metrics

```http
GET /api/v1/agents/:id/metrics?period=1h
```

**Query Parameters**:
- `period` - Time period: `5m`, `1h`, `24h`, `7d`, `30d` (default: `1h`)

**Response**:
```json
{
  "metrics": [
    {
      "timestamp": "2026-01-14T10:30:00Z",
      "cpu_usage": 45.2,
      "memory_usage": 62.8,
      "disk_usage": 38.5,
      "network_in": 1024000,
      "network_out": 2048000
    }
  ]
}
```

**Authentication**: Required

---

### Proxy Hosts

#### List Proxy Hosts

```http
GET /api/v1/agents/:id/proxies
```

**Response**:
```json
{
  "proxies": [
    {
      "id": "uuid",
      "agent_id": "uuid",
      "domain": "app.example.com",
      "forward_host": "container-name",
      "forward_port": 8080,
      "ssl_enabled": true,
      "ssl_cert_path": "/data/ssl/app.example.com/fullchain.pem",
      "ssl_key_path": "/data/ssl/app.example.com/privkey.pem",
      "force_ssl": true,
      "http2_enabled": true,
      "status": "active"
    }
  ]
}
```

**Authentication**: Required

---

#### Create Proxy Host

```http
POST /api/v1/agents/:id/proxies
```

**Request Body**:
```json
{
  "domain": "app.example.com",
  "forward_host": "container-name",
  "forward_port": 8080,
  "ssl_enabled": false,
  "force_ssl": false,
  "http2_enabled": true,
  "custom_locations": [
    {
      "path": "/api",
      "forward_host": "api-container",
      "forward_port": 3000
    }
  ]
}
```

**Response**:
```json
{
  "proxy": {
    "id": "uuid",
    "domain": "app.example.com",
    ...
  }
}
```

**Authentication**: Required (operator or super_admin)

---

#### Get Proxy Host

```http
GET /api/v1/agents/:id/proxies/:pid
```

**Response**:
```json
{
  "id": "uuid",
  "agent_id": "uuid",
  "domain": "app.example.com",
  "forward_host": "container-name",
  "forward_port": 8080,
  "ssl_enabled": true,
  "custom_locations": [...]
}
```

**Authentication**: Required

---

#### Update Proxy Host

```http
PUT /api/v1/agents/:id/proxies/:pid
```

**Request Body**: Same as create

**Response**: Same as create

**Authentication**: Required (operator or super_admin)

---

#### Delete Proxy Host

```http
DELETE /api/v1/agents/:id/proxies/:pid
```

**Response**:
```json
{
  "success": true
}
```

**Authentication**: Required (operator or super_admin)

---

#### Request SSL Certificate

```http
POST /api/v1/agents/:id/proxies/:pid/ssl
```

**Request Body**:
```json
{
  "email": "admin@example.com",
  "staging": false
}
```

**Response**:
```json
{
  "success": true,
  "certificate": {
    "domain": "app.example.com",
    "expiry": "2026-04-14T10:30:00Z"
  }
}
```

**Authentication**: Required (operator or super_admin)

---

#### Get Proxy Config

```http
GET /api/v1/agents/:id/proxies/:pid/config
```

**Response**:
```nginx
server {
    listen 80;
    listen [::]:80;
    server_name app.example.com;

    location / {
        proxy_pass http://container-name:8080;
        ...
    }
}
```

**Content-Type**: `text/plain`

**Authentication**: Required

---

#### Test Proxy Config

```http
POST /api/v1/agents/:id/proxies/:pid/test
```

**Response**:
```json
{
  "success": true,
  "message": "Configuration is valid"
}
```

**Authentication**: Required (operator or super_admin)

---

### SSL/TLS

#### List SSL Certificates

```http
GET /api/v1/ssl/certificates
```

**Response**:
```json
{
  "certificates": [
    {
      "id": "uuid",
      "domain": "app.example.com",
      "issued_at": "2026-01-14T00:00:00Z",
      "expires_at": "2026-04-14T00:00:00Z",
      "is_wildcard": false,
      "status": "valid"
    }
  ]
}
```

**Authentication**: Required

---

#### Check Domain SSL

```http
GET /api/v1/ssl/check/:domain
```

**Response**:
```json
{
  "available": true,
  "domain": "app.example.com",
  "issuer": "Let's Encrypt",
  "expires_at": "2026-04-14T00:00:00Z",
  "days_until_expiry": 90
}
```

**Authentication**: Required

---

#### Request SSL Certificate

```http
POST /api/v1/ssl/request
```

**Request Body**:
```json
{
  "domain": "app.example.com",
  "email": "admin@example.com",
  "challenge_type": "http-01",
  "staging": false
}
```

**Response**:
```json
{
  "success": true,
  "certificate_id": "uuid"
}
```

**Authentication**: Required (super_admin only)

---

#### Start DNS Challenge (Wildcard)

```http
POST /api/v1/ssl/dns-challenge/start
```

**Request Body**:
```json
{
  "domain": "*.example.com",
  "email": "admin@example.com",
  "staging": false
}
```

**Response**:
```json
{
  "challenge_id": "uuid",
  "txt_record_name": "_acme-challenge.example.com",
  "txt_record_value": "random-value",
  "instructions": "Add TXT record to your DNS..."
}
```

**Authentication**: Required (super_admin only)

---

#### Complete DNS Challenge

```http
POST /api/v1/ssl/dns-challenge/complete
```

**Request Body**:
```json
{
  "challenge_id": "uuid"
}
```

**Response**:
```json
{
  "success": true,
  "certificate": {
    "domain": "*.example.com",
    "expires_at": "2026-04-14T00:00:00Z"
  }
}
```

**Authentication**: Required (super_admin only)

---

### Containers

#### List Containers

```http
GET /api/v1/agents/:id/containers
```

**Response**:
```json
{
  "containers": [
    {
      "id": "container-id",
      "name": "webapp",
      "image": "nginx:latest",
      "status": "running",
      "state": "Up 2 hours",
      "cpu_usage": 5.2,
      "memory_usage": 128000000,
      "memory_limit": 512000000,
      "networks": ["bridge"],
      "ports": [
        {
          "private_port": 80,
          "public_port": 8080,
          "type": "tcp"
        }
      ]
    }
  ]
}
```

**Authentication**: Required

---

#### Get Container

```http
GET /api/v1/agents/:id/containers/:cid
```

**Response**:
```json
{
  "id": "container-id",
  "name": "webapp",
  "image": "nginx:latest",
  "status": "running",
  "created": "2026-01-14T09:00:00Z",
  "started_at": "2026-01-14T09:01:00Z",
  "environment": {
    "NODE_ENV": "production"
  },
  "volumes": [...],
  "networks": [...],
  "labels": {...}
}
```

**Authentication**: Required

---

#### Start Container

```http
POST /api/v1/agents/:id/containers/:cid/start
```

**Response**:
```json
{
  "success": true,
  "message": "Container started"
}
```

**Authentication**: Required (operator or super_admin)

---

#### Stop Container

```http
POST /api/v1/agents/:id/containers/:cid/stop
```

**Request Body** (optional):
```json
{
  "timeout": 10
}
```

**Response**:
```json
{
  "success": true,
  "message": "Container stopped"
}
```

**Authentication**: Required (operator or super_admin)

---

#### Restart Container

```http
POST /api/v1/agents/:id/containers/:cid/restart
```

**Request Body** (optional):
```json
{
  "timeout": 10
}
```

**Response**:
```json
{
  "success": true,
  "message": "Container restarted"
}
```

**Authentication**: Required (operator or super_admin)

---

#### Delete Container

```http
DELETE /api/v1/agents/:id/containers/:cid?force=true
```

**Query Parameters**:
- `force` - Force remove (default: false)

**Response**:
```json
{
  "success": true,
  "message": "Container deleted"
}
```

**Authentication**: Required (operator or super_admin)

---

#### Get Container Logs

```http
GET /api/v1/agents/:id/containers/:cid/logs?tail=100&follow=false
```

**Query Parameters**:
- `tail` - Number of lines (default: 100)
- `follow` - Stream logs (default: false)
- `since` - Show logs since timestamp
- `timestamps` - Include timestamps (default: true)

**Response**:
```json
{
  "logs": "log line 1\nlog line 2\n..."
}
```

**Authentication**: Required

---

#### Stream Container Logs (WebSocket)

```http
GET /api/v1/agents/:id/containers/:cid/logs/stream
```

**Protocol**: WebSocket

**Messages**:
```json
{
  "type": "log",
  "data": "log line",
  "timestamp": "2026-01-14T10:30:00Z"
}
```

**Authentication**: Required (via query param `token=jwt`)

---

#### Container Exec (WebSocket)

```http
GET /api/v1/agents/:id/containers/:cid/exec?cmd=/bin/sh
```

**Protocol**: WebSocket (terminal emulation)

**Query Parameters**:
- `cmd` - Command to execute (default: `/bin/sh`)

**Authentication**: Required (via query param `token=jwt`)

---

### Docker Resources

#### List Docker Networks

```http
GET /api/v1/agents/:id/docker/networks
```

**Response**:
```json
{
  "networks": [
    {
      "id": "network-id",
      "name": "bridge",
      "driver": "bridge",
      "scope": "local",
      "containers": 5
    }
  ]
}
```

**Authentication**: Required

---

#### Create Docker Network

```http
POST /api/v1/agents/:id/docker/networks
```

**Request Body**:
```json
{
  "name": "my-network",
  "driver": "bridge",
  "internal": false,
  "ipam": {
    "subnet": "172.20.0.0/16",
    "gateway": "172.20.0.1"
  }
}
```

**Response**:
```json
{
  "id": "network-id",
  "name": "my-network"
}
```

**Authentication**: Required (operator or super_admin)

---

#### Delete Docker Network

```http
DELETE /api/v1/agents/:id/docker/networks/:nid
```

**Response**:
```json
{
  "success": true
}
```

**Authentication**: Required (operator or super_admin)

---

#### List Docker Volumes

```http
GET /api/v1/agents/:id/docker/volumes
```

**Response**:
```json
{
  "volumes": [
    {
      "name": "my-volume",
      "driver": "local",
      "mountpoint": "/var/lib/docker/volumes/my-volume/_data",
      "created_at": "2026-01-14T09:00:00Z"
    }
  ]
}
```

**Authentication**: Required

---

#### List Docker Images

```http
GET /api/v1/agents/:id/docker/images
```

**Response**:
```json
{
  "images": [
    {
      "id": "sha256:abc123...",
      "tags": ["nginx:latest"],
      "size": 142000000,
      "created": "2026-01-10T00:00:00Z"
    }
  ]
}
```

**Authentication**: Required

---

#### Pull Docker Image

```http
POST /api/v1/agents/:id/docker/images/pull
```

**Request Body**:
```json
{
  "image": "nginx:latest"
}
```

**Response**:
```json
{
  "success": true,
  "image_id": "sha256:abc123..."
}
```

**Authentication**: Required (operator or super_admin)

---

### Logs

#### Get Unified Logs

```http
GET /api/v1/agents/:id/logs/unified?limit=100&level=error
```

**Query Parameters**:
- `limit` - Number of log entries (default: 100)
- `level` - Filter by level: `debug`, `info`, `warn`, `error`
- `source` - Filter by source (container name, nginx, etc.)
- `since` - Show logs since timestamp

**Response**:
```json
{
  "logs": [
    {
      "timestamp": "2026-01-14T10:30:00Z",
      "level": "error",
      "source": "nginx",
      "message": "Connection refused",
      "metadata": {...}
    }
  ]
}
```

**Authentication**: Required

---

#### Stream Unified Logs (WebSocket)

```http
GET /api/v1/agents/:id/logs/stream?level=error
```

**Protocol**: WebSocket

**Authentication**: Required (via query param `token=jwt`)

---

#### Get Persisted Logs

```http
GET /api/v1/logs/persisted?page=1&limit=100
```

**Query Parameters**:
- `page` - Page number (default: 1)
- `limit` - Items per page (default: 100)
- `level` - Filter by level
- `source` - Filter by source
- `search` - Full-text search

**Response**:
```json
{
  "logs": [...],
  "pagination": {
    "page": 1,
    "limit": 100,
    "total": 1000
  }
}
```

**Authentication**: Required

---

### Alerts

#### List Alert Channels

```http
GET /api/v1/alerts/channels
```

**Response**:
```json
{
  "channels": [
    {
      "id": "uuid",
      "name": "Slack Alerts",
      "type": "slack",
      "config": {
        "webhook_url": "https://hooks.slack.com/..."
      },
      "enabled": true
    }
  ]
}
```

**Authentication**: Required

---

#### Create Alert Channel

```http
POST /api/v1/alerts/channels
```

**Request Body (Slack)**:
```json
{
  "name": "Slack Alerts",
  "type": "slack",
  "config": {
    "webhook_url": "https://hooks.slack.com/..."
  },
  "enabled": true
}
```

**Request Body (Email)**:
```json
{
  "name": "Email Alerts",
  "type": "smtp",
  "config": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "alerts@example.com",
    "smtp_password": "password",
    "from_email": "alerts@example.com",
    "to_emails": ["admin@example.com"]
  },
  "enabled": true
}
```

**Response**:
```json
{
  "channel": {
    "id": "uuid",
    ...
  }
}
```

**Authentication**: Required (operator or super_admin)

---

#### Test Alert Channel

```http
POST /api/v1/alerts/channels/:id/test
```

**Response**:
```json
{
  "success": true,
  "message": "Test alert sent successfully"
}
```

**Authentication**: Required (operator or super_admin)

---

#### List Alert Rules

```http
GET /api/v1/alerts/rules
```

**Response**:
```json
{
  "rules": [
    {
      "id": "uuid",
      "name": "High CPU Usage",
      "type": "metric",
      "condition": "cpu > 80",
      "channels": ["channel-uuid"],
      "enabled": true
    }
  ]
}
```

**Authentication**: Required

---

#### Create Alert Rule

```http
POST /api/v1/alerts/rules
```

**Request Body**:
```json
{
  "name": "High CPU Usage",
  "type": "metric",
  "condition": "cpu > 80",
  "channels": ["channel-uuid"],
  "enabled": true,
  "cooldown": 300
}
```

**Response**:
```json
{
  "rule": {
    "id": "uuid",
    ...
  }
}
```

**Authentication**: Required (operator or super_admin)

---

### Users

#### List Users

```http
GET /api/v1/users
```

**Response**:
```json
{
  "users": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "full_name": "User Name",
      "role": "operator",
      "mfa_enabled": true,
      "created_at": "2026-01-14T00:00:00Z"
    }
  ]
}
```

**Authentication**: Required (super_admin only)

---

#### Create User

```http
POST /api/v1/users
```

**Request Body**:
```json
{
  "email": "newuser@example.com",
  "password": "secure-password",
  "full_name": "New User",
  "role": "operator"
}
```

**Response**:
```json
{
  "user": {
    "id": "uuid",
    ...
  }
}
```

**Authentication**: Required (super_admin only)

---

#### Update User

```http
PUT /api/v1/users/:id
```

**Request Body**:
```json
{
  "full_name": "Updated Name",
  "role": "viewer"
}
```

**Response**:
```json
{
  "user": {
    "id": "uuid",
    ...
  }
}
```

**Authentication**: Required (super_admin only)

---

#### Delete User

```http
DELETE /api/v1/users/:id
```

**Response**:
```json
{
  "success": true
}
```

**Authentication**: Required (super_admin only)

---

### Settings

#### Get System Settings

```http
GET /api/v1/settings
```

**Response**:
```json
{
  "domain": "infrapilot.example.com",
  "ssl_enabled": true,
  "letsencrypt_email": "admin@example.com",
  "log_retention_days": 30
}
```

**Authentication**: Required (super_admin only)

---

#### Get InfraPilot Domain

```http
GET /api/v1/settings/domain
```

**Response**:
```json
{
  "domain": "infrapilot.example.com",
  "ssl_enabled": true,
  "force_ssl": true
}
```

**Authentication**: Required (super_admin only)

---

#### Update InfraPilot Domain

```http
PUT /api/v1/settings/domain
```

**Request Body**:
```json
{
  "domain": "infrapilot.example.com",
  "ssl_enabled": true,
  "force_ssl": true
}
```

**Response**:
```json
{
  "success": true,
  "domain": "infrapilot.example.com"
}
```

**Authentication**: Required (super_admin only)

---

### Audit

#### Get Audit Logs

```http
GET /api/v1/audit?page=1&limit=100
```

**Query Parameters**:
- `page` - Page number
- `limit` - Items per page
- `user_id` - Filter by user
- `action` - Filter by action type
- `since` - Show logs since timestamp

**Response**:
```json
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "user_email": "user@example.com",
      "action": "container.start",
      "resource_type": "container",
      "resource_id": "container-id",
      "metadata": {...},
      "timestamp": "2026-01-14T10:30:00Z",
      "ip_address": "192.168.1.100"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 100,
    "total": 500
  }
}
```

**Authentication**: Required

---

## Rate Limiting

API requests are rate-limited based on user role:

| Role | Requests per Minute |
|------|---------------------|
| super_admin | 1000 |
| operator | 500 |
| viewer | 200 |

**Rate Limit Headers**:
```
X-RateLimit-Limit: 500
X-RateLimit-Remaining: 499
X-RateLimit-Reset: 1642156800
```

## Webhooks

InfraPilot can send webhooks for various events. Configure webhooks in alert channels.

**Webhook Payload**:
```json
{
  "event": "container.crashed",
  "timestamp": "2026-01-14T10:30:00Z",
  "data": {
    "container_id": "abc123",
    "container_name": "webapp",
    "exit_code": 1
  }
}
```

**Webhook Events**:
- `container.started`
- `container.stopped`
- `container.crashed`
- `proxy.created`
- `proxy.deleted`
- `ssl.issued`
- `ssl.expiring`
- `alert.triggered`

## WebSocket Endpoints

WebSocket endpoints require authentication via query parameter:

```
ws://your-domain/api/v1/endpoint?token=jwt-token
```

**Available WebSocket Endpoints**:
- `/api/v1/agents/:id/containers/:cid/logs/stream` - Container log streaming
- `/api/v1/agents/:id/containers/:cid/exec` - Container terminal
- `/api/v1/agents/:id/logs/stream` - Unified log streaming
- `/api/v1/agents/:id/ws/commands` - Agent command stream (internal)

## Error Codes

| Code | Description |
|------|-------------|
| `UNAUTHORIZED` | Invalid or missing authentication token |
| `FORBIDDEN` | Insufficient permissions |
| `NOT_FOUND` | Resource not found |
| `VALIDATION_ERROR` | Invalid request parameters |
| `DUPLICATE_ENTRY` | Resource already exists |
| `AGENT_OFFLINE` | Agent is not connected |
| `OPERATION_FAILED` | Operation failed on agent |
| `RATE_LIMIT_EXCEEDED` | Too many requests |

## API Versioning

Current version: **v1**

Future versions will be available at `/api/v2`, `/api/v3`, etc.

Deprecated versions will be supported for at least 6 months after a new version is released.

---

**Last Updated**: 2026-01-14
**API Version**: v1
