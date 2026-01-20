# Configuration Reference

Complete reference for all InfraPilot configuration options.

## Table of Contents

- [Environment Variables](#environment-variables)
- [Required Variables](#required-variables)
- [Database Configuration](#database-configuration)
- [SSL/TLS Configuration](#ssltls-configuration)
- [Network Configuration](#network-configuration)
- [Proxy Configuration](#proxy-configuration)
- [Logging Configuration](#logging-configuration)
- [Security Configuration](#security-configuration)
- [Agent Configuration](#agent-configuration)
- [Runtime Configuration](#runtime-configuration)
- [Feature Flags](#feature-flags)

## Environment Variables

InfraPilot is configured primarily through environment variables. These can be set:

1. **Docker Run**: `-e VARIABLE=value`
2. **Docker Compose**: In `.env` file or `environment:` section
3. **System**: Export in shell

### Example .env File

```bash
# Required
JWT_SECRET=your-secret-key-here

# Database (optional)
DATABASE_URL=postgres://user:pass@host:5432/infrapilot
REDIS_URL=redis://:pass@host:6379

# Embedded databases
POSTGRES_PASSWORD=strong-password
REDIS_PASSWORD=strong-password

# SSL
LETSENCRYPT_EMAIL=admin@example.com
LETSENCRYPT_STAGING=false

# Ports
HTTP_PORT=80
HTTPS_PORT=443

# Proxy Mode
PROXY_MODE=managed

# Logging
LOG_LEVEL=info
```

## Required Variables

### JWT_SECRET

**Description**: Secret key for JWT token generation and validation

**Type**: String

**Required**: Yes

**Example**:
```bash
JWT_SECRET=$(openssl rand -base64 32)
```

**Security Notes**:
- Must be at least 32 characters
- Use cryptographically secure random generation
- Never commit to version control
- Rotate periodically
- Different per environment

**Default**: None (must be set)

---

## Database Configuration

### DATABASE_URL

**Description**: PostgreSQL connection string

**Type**: String (URL)

**Required**: No (uses embedded PostgreSQL if not set)

**Format**:
```
postgres://username:password@hostname:port/database?sslmode=require
```

**Examples**:
```bash
# Standard connection
DATABASE_URL=postgres://infrapilot:password@localhost:5432/infrapilot

# With SSL
DATABASE_URL=postgres://infrapilot:password@db.example.com:5432/infrapilot?sslmode=require

# With connection pool settings
DATABASE_URL=postgres://infrapilot:password@localhost:5432/infrapilot?pool_max_conns=20
```

**Default**: Embedded PostgreSQL at `/data/postgres`

**Connection Pool Settings** (via query parameters):
- `pool_max_conns`: Maximum connections (default: 20)
- `pool_min_conns`: Minimum connections (default: 2)
- `sslmode`: SSL mode (`disable`, `require`, `verify-full`)

---

### POSTGRES_PASSWORD

**Description**: Password for embedded PostgreSQL

**Type**: String

**Required**: No (only if using embedded PostgreSQL)

**Default**: `infrapilot`

**Security Note**: Change in production

**Example**:
```bash
POSTGRES_PASSWORD=$(openssl rand -base64 32)
```

---

### REDIS_URL

**Description**: Redis connection string

**Type**: String (URL)

**Required**: No (uses embedded Redis if not set)

**Format**:
```
redis://[:password@]hostname:port[/database]
```

**Examples**:
```bash
# No password
REDIS_URL=redis://localhost:6379

# With password
REDIS_URL=redis://:mypassword@localhost:6379

# Specific database
REDIS_URL=redis://:mypassword@localhost:6379/1

# With TLS
REDIS_URL=rediss://:mypassword@redis.example.com:6380
```

**Default**: Embedded Redis at `/data/redis`

---

### REDIS_PASSWORD

**Description**: Password for embedded Redis

**Type**: String

**Required**: No (only if using embedded Redis)

**Default**: `infrapilot`

**Security Note**: Change in production

**Example**:
```bash
REDIS_PASSWORD=$(openssl rand -base64 32)
```

---

## SSL/TLS Configuration

### LETSENCRYPT_EMAIL

**Description**: Email for Let's Encrypt certificate notifications

**Type**: String (email)

**Required**: No (required for automatic SSL)

**Example**:
```bash
LETSENCRYPT_EMAIL=admin@example.com
```

**Purpose**:
- Certificate expiry notifications
- Let's Encrypt account registration
- Important security alerts

---

### LETSENCRYPT_STAGING

**Description**: Use Let's Encrypt staging environment

**Type**: Boolean

**Required**: No

**Values**: `true`, `false`

**Default**: `true`

**Example**:
```bash
# Production (real certificates)
LETSENCRYPT_STAGING=false

# Development (test certificates)
LETSENCRYPT_STAGING=true
```

**Usage**:
- Set to `false` for production
- Set to `true` for testing (avoid rate limits)

**Let's Encrypt Rate Limits**:
- Production: 50 certificates per domain per week
- Staging: Much higher limits

---

### SSL_CERT_PATH

**Description**: Path to SSL certificate (for manual SSL)

**Type**: String (file path)

**Required**: No

**Example**:
```bash
SSL_CERT_PATH=/data/ssl/mydomain.com/fullchain.pem
```

---

### SSL_KEY_PATH

**Description**: Path to SSL private key (for manual SSL)

**Type**: String (file path)

**Required**: No

**Example**:
```bash
SSL_KEY_PATH=/data/ssl/mydomain.com/privkey.pem
```

---

## Network Configuration

### HTTP_PORT

**Description**: HTTP port

**Type**: Integer

**Required**: No

**Default**: `80`

**Example**:
```bash
HTTP_PORT=8080
```

**Note**: Change if port 80 is already in use

---

### HTTPS_PORT

**Description**: HTTPS port

**Type**: Integer

**Required**: No

**Default**: `443`

**Example**:
```bash
HTTPS_PORT=8443
```

**Note**: Change if port 443 is already in use

---

### GRPC_PORT

**Description**: gRPC server port (internal)

**Type**: Integer

**Required**: No

**Default**: `9090`

**Example**:
```bash
GRPC_PORT=9090
```

**Note**: Internal port, not exposed externally

---

### BACKEND_PORT

**Description**: Backend API port (internal)

**Type**: Integer

**Required**: No

**Default**: `8080`

**Example**:
```bash
BACKEND_PORT=8080
```

---

### FRONTEND_PORT

**Description**: Frontend port (internal)

**Type**: Integer

**Required**: No

**Default**: `3000`

**Example**:
```bash
FRONTEND_PORT=3000
```

---

### ALLOWED_ORIGINS

**Description**: CORS allowed origins

**Type**: String (comma-separated URLs)

**Required**: No

**Default**: `*` (all origins)

**Example**:
```bash
ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

**Security Note**: Restrict in production

---

## Proxy Configuration

### PROXY_MODE

**Description**: Reverse proxy mode

**Type**: String

**Required**: No

**Values**:
- `managed` - InfraPilot controls Nginx (default)
- `external` - Use external reverse proxy

**Default**: `managed`

**Example**:
```bash
# InfraPilot manages Nginx
PROXY_MODE=managed

# Use Caddy/Traefik/external Nginx
PROXY_MODE=external
```

**Implications**:
- **managed**: InfraPilot configures and reloads Nginx
- **external**: InfraPilot is read-only, you manage the reverse proxy

---

### NGINX_WORKER_PROCESSES

**Description**: Nginx worker processes

**Type**: Integer or `auto`

**Required**: No

**Default**: `auto`

**Example**:
```bash
NGINX_WORKER_PROCESSES=4
```

---

### NGINX_WORKER_CONNECTIONS

**Description**: Nginx worker connections

**Type**: Integer

**Required**: No

**Default**: `1024`

**Example**:
```bash
NGINX_WORKER_CONNECTIONS=2048
```

---

## Logging Configuration

### LOG_LEVEL

**Description**: Application log level

**Type**: String

**Required**: No

**Values**: `debug`, `info`, `warn`, `error`

**Default**: `info`

**Example**:
```bash
# Development
LOG_LEVEL=debug

# Production
LOG_LEVEL=info
```

**Log Levels**:
- `debug`: Verbose logging (development only)
- `info`: Standard logging
- `warn`: Warnings and errors only
- `error`: Errors only

---

### LOG_FORMAT

**Description**: Log output format

**Type**: String

**Required**: No

**Values**: `json`, `text`

**Default**: `json`

**Example**:
```bash
# JSON (for log aggregation)
LOG_FORMAT=json

# Human-readable (development)
LOG_FORMAT=text
```

---

### LOG_RETENTION_DAYS

**Description**: Days to retain logs

**Type**: Integer

**Required**: No

**Default**: `30`

**Example**:
```bash
LOG_RETENTION_DAYS=90
```

**Storage Impact**: More days = more disk usage

---

## Security Configuration

### JWT_EXPIRY

**Description**: JWT token expiry duration

**Type**: Duration string

**Required**: No

**Default**: `24h`

**Format**: Go duration (`1h`, `30m`, `24h`, `7d`)

**Example**:
```bash
# 12 hours
JWT_EXPIRY=12h

# 7 days
JWT_EXPIRY=168h
```

**Security Note**: Shorter = more secure, but more frequent logins

---

### SESSION_TIMEOUT

**Description**: Session inactivity timeout

**Type**: Duration string

**Required**: No

**Default**: `30m`

**Example**:
```bash
SESSION_TIMEOUT=1h
```

---

### MFA_REQUIRED

**Description**: Enforce MFA for all users

**Type**: Boolean

**Required**: No

**Default**: `false`

**Example**:
```bash
MFA_REQUIRED=true
```

**Note**: Users without MFA will be prompted to set it up

---

### PASSWORD_MIN_LENGTH

**Description**: Minimum password length

**Type**: Integer

**Required**: No

**Default**: `8`

**Example**:
```bash
PASSWORD_MIN_LENGTH=12
```

---

### MAX_LOGIN_ATTEMPTS

**Description**: Maximum failed login attempts before lockout

**Type**: Integer

**Required**: No

**Default**: `5`

**Example**:
```bash
MAX_LOGIN_ATTEMPTS=3
```

---

### LOCKOUT_DURATION

**Description**: Account lockout duration

**Type**: Duration string

**Required**: No

**Default**: `15m`

**Example**:
```bash
LOCKOUT_DURATION=30m
```

---

## Agent Configuration

### AGENT_ID

**Description**: Unique agent identifier

**Type**: String (UUID)

**Required**: No (auto-generated if not set)

**Example**:
```bash
AGENT_ID=550e8400-e29b-41d4-a716-446655440000
```

---

### AGENT_NAME

**Description**: Human-readable agent name

**Type**: String

**Required**: No

**Default**: Hostname

**Example**:
```bash
AGENT_NAME=production-docker-01
```

---

### AGENT_HEARTBEAT_INTERVAL

**Description**: Heartbeat interval to backend

**Type**: Duration string

**Required**: No

**Default**: `30s`

**Example**:
```bash
AGENT_HEARTBEAT_INTERVAL=60s
```

---

### METRICS_COLLECTION_INTERVAL

**Description**: Metrics collection interval

**Type**: Duration string

**Required**: No

**Default**: `30s`

**Example**:
```bash
METRICS_COLLECTION_INTERVAL=60s
```

---

### DOCKER_HOST

**Description**: Docker daemon socket

**Type**: String

**Required**: No

**Default**: `unix:///var/run/docker.sock`

**Examples**:
```bash
# Unix socket (local)
DOCKER_HOST=unix:///var/run/docker.sock

# TCP (remote)
DOCKER_HOST=tcp://192.168.1.100:2375

# SSH (remote)
DOCKER_HOST=ssh://user@host
```

---

## Runtime Configuration

### ENV

**Description**: Environment mode

**Type**: String

**Required**: No

**Values**: `development`, `production`

**Default**: `production`

**Example**:
```bash
ENV=production
```

**Effects**:
- `development`: Verbose logging, hot-reload
- `production`: Optimized, minimal logging

---

### TZ

**Description**: Timezone

**Type**: String (IANA timezone)

**Required**: No

**Default**: `UTC`

**Example**:
```bash
TZ=America/New_York
```

**List timezones**: `timedatectl list-timezones`

---

### DATA_DIR

**Description**: Data directory path

**Type**: String (directory path)

**Required**: No

**Default**: `/data`

**Example**:
```bash
DATA_DIR=/var/lib/infrapilot
```

**Contents**:
- PostgreSQL data (if embedded)
- Redis data (if embedded)
- SSL certificates
- Nginx configurations
- Logs

---

## Feature Flags

### ENABLE_API_RATE_LIMITING

**Description**: Enable API rate limiting

**Type**: Boolean

**Required**: No

**Default**: `true`

**Example**:
```bash
ENABLE_API_RATE_LIMITING=false
```

---

### ENABLE_AUDIT_LOGS

**Description**: Enable audit logging

**Type**: Boolean

**Required**: No

**Default**: `true`

**Example**:
```bash
ENABLE_AUDIT_LOGS=true
```

---

### ENABLE_METRICS_EXPORT

**Description**: Enable Prometheus metrics export

**Type**: Boolean

**Required**: No

**Default**: `false` (future feature)

**Example**:
```bash
ENABLE_METRICS_EXPORT=true
```

---

### ENABLE_TELEMETRY

**Description**: Enable anonymous telemetry

**Type**: Boolean

**Required**: No

**Default**: `false`

**Example**:
```bash
ENABLE_TELEMETRY=true
```

**Data Collected** (anonymous):
- Installation ID (UUID)
- Version
- Container count
- Proxy count
- No personal data

---

## Configuration Validation

InfraPilot validates configuration on startup. Common errors:

### Missing JWT_SECRET

```
Error: JWT_SECRET environment variable is required
Solution: Set JWT_SECRET=$(openssl rand -base64 32)
```

### Invalid Database URL

```
Error: Failed to parse DATABASE_URL
Solution: Check URL format: postgres://user:pass@host:port/db
```

### Port Already in Use

```
Error: Failed to bind to port 80
Solution: Change HTTP_PORT=8080 or stop conflicting service
```

## Configuration Examples

### Minimal (Embedded Databases)

```bash
JWT_SECRET=$(openssl rand -base64 32)
```

### Production (External Databases)

```bash
# Required
JWT_SECRET=<secure-random-string>

# Databases
DATABASE_URL=postgres://infrapilot:password@db.example.com:5432/infrapilot?sslmode=require
REDIS_URL=redis://:password@redis.example.com:6379

# SSL
LETSENCRYPT_EMAIL=admin@example.com
LETSENCRYPT_STAGING=false

# Security
MFA_REQUIRED=true
PASSWORD_MIN_LENGTH=12
JWT_EXPIRY=12h

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
LOG_RETENTION_DAYS=90
```

### Development

```bash
# Required
JWT_SECRET=dev-secret-not-for-production

# Database
DATABASE_URL=postgres://infrapilot:infrapilot@localhost:5432/infrapilot?sslmode=disable
REDIS_URL=redis://localhost:6379

# Development
ENV=development
LOG_LEVEL=debug
LOG_FORMAT=text

# Ports
HTTP_PORT=8080
HTTPS_PORT=8443
```

### High Security

```bash
# Required
JWT_SECRET=<very-long-random-string-64-chars>

# External Databases with SSL
DATABASE_URL=postgres://infrapilot:password@db.example.com:5432/infrapilot?sslmode=verify-full
REDIS_URL=rediss://:password@redis.example.com:6380

# SSL
LETSENCRYPT_EMAIL=security@example.com
LETSENCRYPT_STAGING=false

# Security
MFA_REQUIRED=true
PASSWORD_MIN_LENGTH=16
MAX_LOGIN_ATTEMPTS=3
LOCKOUT_DURATION=1h
JWT_EXPIRY=4h
SESSION_TIMEOUT=30m

# CORS
ALLOWED_ORIGINS=https://infrapilot.example.com

# Logging
LOG_LEVEL=warn
LOG_RETENTION_DAYS=180
ENABLE_AUDIT_LOGS=true
```

## Configuration Best Practices

1. **Never commit secrets** to version control
2. **Use strong random values** for JWT_SECRET
3. **Rotate secrets periodically** (quarterly)
4. **Use external databases** in production
5. **Enable SSL** (LETSENCRYPT_STAGING=false)
6. **Restrict CORS** (set ALLOWED_ORIGINS)
7. **Enable MFA** (MFA_REQUIRED=true)
8. **Set appropriate log levels** (info for production)
9. **Configure log retention** based on compliance needs
10. **Use environment-specific configs** (dev vs prod)

## Configuration Management

### Using .env File

```bash
# Load .env file
docker compose --env-file .env up -d
```

### Using External Secrets Manager

**AWS Secrets Manager**:
```bash
export JWT_SECRET=$(aws secretsmanager get-secret-value --secret-id infrapilot/jwt-secret --query SecretString --output text)
```

**HashiCorp Vault**:
```bash
export JWT_SECRET=$(vault kv get -field=jwt_secret secret/infrapilot)
```

### Using Docker Secrets

```yaml
services:
  infrapilot:
    secrets:
      - jwt_secret
    environment:
      JWT_SECRET_FILE: /run/secrets/jwt_secret

secrets:
  jwt_secret:
    external: true
```

---

**Last Updated**: 2026-01-14

For questions about configuration, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or open an issue on GitHub.
