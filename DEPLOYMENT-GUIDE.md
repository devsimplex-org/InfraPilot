# InfraPilot Deployment Guide

This guide covers both deployment architectures: **Multi-Container (Production)** and **All-in-One (Legacy)**.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Production Deployment (Multi-Container)](#production-deployment-multi-container)
- [Legacy Deployment (All-in-One)](#legacy-deployment-all-in-one)
- [Building Images](#building-images)
- [Migration Guide](#migration-guide)

---

## Architecture Overview

### Production Architecture (Recommended)

```
┌─────────────────────────────────────────────────────────┐
│                  Production Stack                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  External Traffic                                        │
│       ↓                                                  │
│  ┌──────────┐          ┌──────────┐                    │
│  │  Nginx   │─────────▶│ Frontend │                    │
│  │  :80/443 │          │  :3000   │                    │
│  └──────────┘          └──────────┘                    │
│       │                      │                           │
│       └────────────┐         │                           │
│                    ↓         ↓                           │
│               ┌──────────┐                              │
│               │ Backend  │                              │
│               │ :8080/90 │                              │
│               └──────────┘                              │
│                    │                                     │
│       ┌────────────┼────────────┐                       │
│       ↓                          ↓                       │
│  ┌──────────┐              ┌──────────┐                │
│  │Postgres  │              │  Redis   │                │
│  │  :5432   │              │  :6379   │                │
│  └──────────┘              └──────────┘                │
│                                                          │
│  ┌──────────┐                                           │
│  │  Agent   │ ← Manages Docker & Nginx                 │
│  └──────────┘                                           │
│       │                                                  │
│       └─────▶ /var/run/docker.sock                     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Components:**
- **Nginx** (`nginx:stable-alpine`) - Reverse proxy
- **Frontend** (`devsimplex/infrapilot-frontend`) - Next.js dashboard
- **Backend** (`devsimplex/infrapilot-backend`) - API server
- **Postgres** (`postgres:16-alpine`) - Database
- **Redis** (`redis:7-alpine`) - Cache & sessions
- **Agent** (`devsimplex/infrapilot-agent`) - Controller

### Legacy Architecture (Convenience)

```
┌──────────────────────────────────┐
│     All-in-One Container         │
├──────────────────────────────────┤
│  ┌────────────────────────────┐  │
│  │  Supervisor (Process Mgr)  │  │
│  └────────────────────────────┘  │
│         │                         │
│    ┌────┼────┬────┬─────┬────┐   │
│    ↓    ↓    ↓    ↓     ↓    ↓   │
│  Nginx Front Back Pg  Redis Ag   │
│                                   │
└──────────────────────────────────┘
```

**Single Image:** `devsimplex/infrapilot:latest`

---

## Production Deployment (Multi-Container)

### Prerequisites

- Docker 24+
- Docker Compose v2+
- 2 CPU cores, 4GB RAM minimum
- Linux x86_64 or ARM64

### Quick Start

1. **Clone or download InfraPilot:**

```bash
git clone https://github.com/devsimplex-org/infrapilot.git
cd infrapilot
```

2. **Configure environment:**

```bash
cp .env.prod.example .env

# Generate secrets
echo "JWT_SECRET=$(openssl rand -base64 32)" >> .env
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)" >> .env
echo "REDIS_PASSWORD=$(openssl rand -base64 32)" >> .env

# Edit other settings
nano .env
```

**Required settings:**
```bash
JWT_SECRET=<generated>
POSTGRES_PASSWORD=<generated>
REDIS_PASSWORD=<generated>
LETSENCRYPT_EMAIL=admin@yourdomain.com
ALLOWED_ORIGINS=https://yourdomain.com
```

3. **Deploy:**

```bash
docker compose -f docker-compose.prod.yml up -d
```

4. **Verify:**

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f
```

5. **Access Dashboard:**

Open http://localhost (or your domain). Create admin account on first access.

### Using Pre-built Images

Pull from Docker Hub:

```bash
docker pull devsimplex/infrapilot-backend:latest
docker pull devsimplex/infrapilot-frontend:latest
docker pull devsimplex/infrapilot-agent:latest
```

Then run:

```bash
docker compose -f docker-compose.prod.yml up -d
```

### Configuration Options

#### Use External Database

```bash
# .env
DATABASE_URL=postgres://user:pass@external-host:5432/infrapilot?sslmode=require
```

Remove `postgres` service from `docker-compose.prod.yml`.

#### Use External Redis

```bash
# .env
REDIS_URL=redis://:password@external-host:6379
```

Remove `redis` service from `docker-compose.prod.yml`.

#### Custom Ports

```bash
# .env
HTTP_PORT=8080
HTTPS_PORT=8443
```

---

## Legacy Deployment (All-in-One)

For simple single-server setups, use the all-in-one image:

### Quick Start

```bash
docker run -d \
  --name infrapilot \
  -p 80:80 -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v infrapilot_data:/data \
  -e JWT_SECRET=$(openssl rand -base64 32) \
  devsimplex/infrapilot:latest
```

### Using Docker Compose

```bash
# Use the existing docker-compose.yml
docker compose up -d
```

### Limitations

- Harder to scale horizontally
- Single point of failure
- More resource usage in one container
- Embedded PostgreSQL and Redis

**Recommended only for:**
- Development/testing
- Personal projects
- Single-server deployments

---

## Building Images

### Build All Components

```bash
./scripts/build-and-publish.sh v1.0.0
```

This builds and pushes:
- `devsimplex/infrapilot-backend:v1.0.0`
- `devsimplex/infrapilot-frontend:v1.0.0`
- `devsimplex/infrapilot-agent:v1.0.0`
- `devsimplex/infrapilot:v1.0.0` (all-in-one)

### Build Individual Components

```bash
# Backend only
./scripts/build-and-publish.sh v1.0.0 --backend

# Frontend only
./scripts/build-and-publish.sh v1.0.0 --frontend

# Agent only
./scripts/build-and-publish.sh v1.0.0 --agent

# All-in-one only
./scripts/build-and-publish.sh v1.0.0 --all-in-one
```

### Local Build (No Push)

```bash
./scripts/build-and-publish.sh test --no-push
```

### Multi-Architecture Build

```bash
# Build for AMD64 and ARM64
./scripts/build-and-publish.sh v1.0.0 --platform linux/amd64,linux/arm64
```

---

## Migration Guide

### From All-in-One to Multi-Container

1. **Backup your data:**

```bash
# Backup database
docker exec infrapilot pg_dump -U infrapilot infrapilot > backup.sql

# Backup certs
docker cp infrapilot:/data/letsencrypt ./certs-backup
```

2. **Stop all-in-one container:**

```bash
docker compose down
# or
docker stop infrapilot
```

3. **Create production .env:**

```bash
cp .env.prod.example .env
# Copy JWT_SECRET from old .env
# Set POSTGRES_PASSWORD and REDIS_PASSWORD
nano .env
```

4. **Start multi-container stack:**

```bash
docker compose -f docker-compose.prod.yml up -d
```

5. **Restore database:**

```bash
cat backup.sql | docker exec -i infrapilot-postgres psql -U infrapilot infrapilot
```

6. **Restore certificates:**

```bash
docker cp ./certs-backup/. infrapilot-nginx:/etc/letsencrypt/
docker exec infrapilot-nginx nginx -s reload
```

### From Multi-Container to All-in-One

```bash
# Export data
docker exec infrapilot-postgres pg_dump -U infrapilot infrapilot > backup.sql

# Stop multi-container
docker compose -f docker-compose.prod.yml down

# Start all-in-one
docker compose up -d

# Import data
cat backup.sql | docker exec -i infrapilot psql -U infrapilot infrapilot
```

---

## Maintenance

### Updating

#### Multi-Container

```bash
# Pull latest images
docker compose -f docker-compose.prod.yml pull

# Restart
docker compose -f docker-compose.prod.yml up -d

# Clean old images
docker image prune -a
```

#### All-in-One

```bash
docker compose pull
docker compose up -d
docker image prune -a
```

### Backup

#### Multi-Container

```bash
# Database
docker exec infrapilot-postgres pg_dump -U infrapilot infrapilot > backup-$(date +%Y%m%d).sql

# SSL Certificates
docker cp infrapilot-nginx:/etc/letsencrypt ./certs-backup-$(date +%Y%m%d)
```

#### All-in-One

```bash
# Full data backup
docker cp infrapilot:/data ./data-backup-$(date +%Y%m%d)
```

### Logs

```bash
# Multi-container: specific service
docker compose -f docker-compose.prod.yml logs -f backend

# All-in-one: all logs
docker logs -f infrapilot
```

---

## Comparison

| Feature | Multi-Container | All-in-One |
|---------|----------------|------------|
| **Scalability** | ✅ Easy to scale | ❌ Single container |
| **High Availability** | ✅ Can use external DB | ⚠️ Limited |
| **Resource Efficiency** | ✅ Better isolation | ⚠️ More overhead |
| **Maintenance** | ✅ Update components separately | ⚠️ Update all at once |
| **Complexity** | ⚠️ More moving parts | ✅ Simple |
| **Production Ready** | ✅ Recommended | ⚠️ For small deployments |
| **Backup** | ⚠️ Multiple volumes | ✅ Single data directory |

## Recommendations

- **Production:** Use multi-container with external managed databases
- **Staging:** Use multi-container with containerized databases
- **Development:** Use `docker-compose.dev.yml` (already configured)
- **Personal/Hobby:** All-in-one is acceptable

---

## Support

- **Docs:** https://github.com/devsimplex-org/infrapilot/tree/main/docs
- **Issues:** https://github.com/devsimplex-org/infrapilot/issues
- **Deployment README:** `deployments/README.md`
