# Deployment Guide

This guide covers production deployment strategies for InfraPilot Community Edition.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Deploy](#quick-deploy)
- [Production Deployment](#production-deployment)
- [Using External Databases](#using-external-databases)
- [SSL/TLS Configuration](#ssltls-configuration)
- [Reverse Proxy Setup](#reverse-proxy-setup)
- [High Availability](#high-availability)
- [Backup and Restore](#backup-and-restore)
- [Monitoring](#monitoring)
- [Scaling](#scaling)
- [Security Hardening](#security-hardening)
- [Upgrading](#upgrading)

## Overview

InfraPilot runs as a single Docker container with all components bundled:
- Nginx (reverse proxy)
- Backend (Go API server)
- Agent (Docker controller)
- Frontend (Next.js)
- PostgreSQL (embedded or external)
- Redis (embedded or external)

## Prerequisites

### System Requirements

**Minimum**:
- 2 CPU cores
- 4 GB RAM
- 20 GB disk space
- Docker 24+

**Recommended**:
- 4 CPU cores
- 8 GB RAM
- 50 GB disk space
- Docker 24+

### Operating Systems

- **Linux**: Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS 8+
- **Architecture**: x86_64 (amd64), ARM64 (aarch64)

### Network Requirements

- **Ports**: 80 (HTTP), 443 (HTTPS)
- **Outbound**: Access to Docker Hub, Let's Encrypt (if using SSL)
- **Docker Socket**: Access to `/var/run/docker.sock`

## Quick Deploy

### Using Docker Run

```bash
# Generate JWT secret
export JWT_SECRET=$(openssl rand -base64 32)

# Run InfraPilot
docker run -d \
  --name infrapilot \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v infrapilot_data:/data \
  -e JWT_SECRET="${JWT_SECRET}" \
  devsimplex/infrapilot:latest
```

### Using Docker Compose (Recommended)

```bash
# Create directory
mkdir infrapilot && cd infrapilot

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
services:
  infrapilot:
    image: devsimplex/infrapilot:latest
    container_name: infrapilot
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      JWT_SECRET: ${JWT_SECRET:?Run: export JWT_SECRET=$(openssl rand -base64 32)}
    volumes:
      - infrapilot_data:/data
      - /var/run/docker.sock:/var/run/docker.sock:ro

volumes:
  infrapilot_data:
EOF

# Generate JWT secret and start
export JWT_SECRET=$(openssl rand -base64 32)
docker compose up -d
```

### Initial Setup

1. Open http://your-server-ip
2. Complete setup wizard
3. Create admin account
4. Configure domain (optional)
5. Set up SSL (optional)

## Production Deployment

### Complete Docker Compose Configuration

Create `docker-compose.yml`:

```yaml
services:
  infrapilot:
    image: devsimplex/infrapilot:latest
    container_name: infrapilot
    restart: unless-stopped

    # Ports
    ports:
      - "80:80"
      - "443:443"

    # Environment
    environment:
      # Required
      JWT_SECRET: ${JWT_SECRET}

      # Database (optional - uses embedded if not set)
      DATABASE_URL: ${DATABASE_URL:-}
      REDIS_URL: ${REDIS_URL:-}

      # Embedded database passwords
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-infrapilot}
      REDIS_PASSWORD: ${REDIS_PASSWORD:-infrapilot}

      # SSL Configuration
      LETSENCRYPT_EMAIL: ${LETSENCRYPT_EMAIL:-}
      LETSENCRYPT_STAGING: ${LETSENCRYPT_STAGING:-true}

      # Ports (if custom)
      HTTP_PORT: ${HTTP_PORT:-80}
      HTTPS_PORT: ${HTTPS_PORT:-443}

      # Proxy Mode
      PROXY_MODE: ${PROXY_MODE:-managed}

      # Logging
      LOG_LEVEL: ${LOG_LEVEL:-info}

    # Volumes
    volumes:
      - infrapilot_data:/data
      - /var/run/docker.sock:/var/run/docker.sock:ro

    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

    # Security
    security_opt:
      - no-new-privileges:true

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 4G
        reservations:
          cpus: '2'
          memory: 2G

volumes:
  infrapilot_data:
    driver: local
```

### Environment File

Create `.env`:

```bash
# Required
JWT_SECRET=<generate-with-openssl-rand-base64-32>

# Optional: External Databases
#DATABASE_URL=postgres://user:pass@postgres-host:5432/infrapilot
#REDIS_URL=redis://:password@redis-host:6379

# Embedded database passwords (if not using external)
POSTGRES_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>

# SSL Configuration
LETSENCRYPT_EMAIL=admin@yourdomain.com
LETSENCRYPT_STAGING=false

# Proxy Mode
PROXY_MODE=managed

# Logging
LOG_LEVEL=info
```

### Start Production Deployment

```bash
# Load environment
source .env

# Start
docker compose up -d

# View logs
docker compose logs -f

# Check status
docker compose ps
```

## Using External Databases

For production deployments, external databases are recommended for better performance and reliability.

### PostgreSQL Setup

**1. Create Database**:

```sql
CREATE DATABASE infrapilot;
CREATE USER infrapilot WITH ENCRYPTED PASSWORD 'secure-password';
GRANT ALL PRIVILEGES ON DATABASE infrapilot TO infrapilot;
```

**2. Configure Connection**:

```bash
DATABASE_URL=postgres://infrapilot:secure-password@postgres-host:5432/infrapilot?sslmode=require
```

**3. Update docker-compose.yml**:

```yaml
services:
  infrapilot:
    environment:
      DATABASE_URL: ${DATABASE_URL}
```

### Redis Setup

**1. Configure Redis**:

```bash
# redis.conf
requirepass secure-redis-password
maxmemory 2gb
maxmemory-policy allkeys-lru
```

**2. Set Connection String**:

```bash
REDIS_URL=redis://:secure-redis-password@redis-host:6379
```

### Full External Setup Example

```yaml
services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: infrapilot
      POSTGRES_USER: infrapilot
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U infrapilot"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  infrapilot:
    image: devsimplex/infrapilot:latest
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - "80:80"
      - "443:443"
    environment:
      JWT_SECRET: ${JWT_SECRET}
      DATABASE_URL: postgres://infrapilot:${POSTGRES_PASSWORD}@postgres:5432/infrapilot
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379
    volumes:
      - infrapilot_data:/data
      - /var/run/docker.sock:/var/run/docker.sock:ro

volumes:
  postgres_data:
  redis_data:
  infrapilot_data:
```

## SSL/TLS Configuration

### Automatic SSL (Let's Encrypt)

InfraPilot includes built-in Let's Encrypt support:

**1. Configure Email**:

```bash
LETSENCRYPT_EMAIL=admin@yourdomain.com
LETSENCRYPT_STAGING=false
```

**2. Add Proxy Host**:

- Go to Proxies → Add Proxy Host
- Enter your domain
- Enable SSL
- Click "Request Certificate"

**3. Automatic Renewal**:

Certificates renew automatically 30 days before expiry.

### Manual SSL Certificates

**1. Place Certificates**:

```bash
# Copy to host
mkdir -p /path/to/ssl/yourdomain.com
cp fullchain.pem /path/to/ssl/yourdomain.com/
cp privkey.pem /path/to/ssl/yourdomain.com/
```

**2. Mount Volume**:

```yaml
volumes:
  - /path/to/ssl:/data/ssl:ro
```

**3. Configure Proxy Host**:

- Certificate Path: `/data/ssl/yourdomain.com/fullchain.pem`
- Key Path: `/data/ssl/yourdomain.com/privkey.pem`

### Wildcard Certificates

Use DNS-01 challenge for wildcard certificates:

**1. Start Challenge**:
- Go to SSL → Request Certificate
- Domain: `*.yourdomain.com`
- Challenge: DNS-01

**2. Add DNS Record**:
- Record: `_acme-challenge.yourdomain.com`
- Type: TXT
- Value: (provided by InfraPilot)

**3. Complete Challenge**:
- Wait for DNS propagation (5-10 minutes)
- Click "Complete Challenge"

## Reverse Proxy Setup

### Using External Reverse Proxy

If you have an existing reverse proxy (Caddy, Traefik, etc.):

**1. Set Proxy Mode**:

```bash
PROXY_MODE=external
```

**2. Don't Expose Ports 80/443**:

```yaml
ports:
  - "127.0.0.1:3000:3000"  # Frontend
  - "127.0.0.1:8080:8080"  # Backend API
```

**3. Configure Your Reverse Proxy**:

**Caddy**:
```caddyfile
infrapilot.example.com {
    reverse_proxy localhost:3000

    handle /api/* {
        reverse_proxy localhost:8080
    }
}
```

**Nginx**:
```nginx
server {
    listen 443 ssl http2;
    server_name infrapilot.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## High Availability

For high availability, use external databases with replication:

### PostgreSQL HA

**Using Patroni + etcd**:

```yaml
services:
  etcd:
    image: quay.io/coreos/etcd:latest
    # etcd configuration...

  patroni1:
    image: patroni/patroni:latest
    # Patroni primary...

  patroni2:
    image: patroni/patroni:latest
    # Patroni replica...

  infrapilot:
    environment:
      DATABASE_URL: postgres://infrapilot:pass@patroni1:5432/infrapilot
```

### Redis HA

**Using Redis Sentinel**:

```yaml
services:
  redis-master:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}

  redis-replica:
    image: redis:7-alpine
    command: redis-server --replicaof redis-master 6379 --requirepass ${REDIS_PASSWORD}

  redis-sentinel:
    image: redis:7-alpine
    command: redis-sentinel /sentinel.conf
```

## Backup and Restore

### Backup Strategy

**1. Volume Backup**:

```bash
# Stop container
docker compose stop infrapilot

# Backup volume
docker run --rm \
  -v infrapilot_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/infrapilot-backup-$(date +%Y%m%d).tar.gz /data

# Start container
docker compose start infrapilot
```

**2. Database Backup** (if using external):

```bash
# PostgreSQL
pg_dump -h postgres-host -U infrapilot infrapilot > backup.sql

# Or with docker
docker exec postgres pg_dump -U infrapilot infrapilot > backup.sql
```

**3. Automated Backups**:

```bash
# Add to crontab
0 2 * * * /path/to/backup-script.sh
```

**backup-script.sh**:
```bash
#!/bin/bash
BACKUP_DIR=/backups
DATE=$(date +%Y%m%d)

# Backup database
docker exec postgres pg_dump -U infrapilot infrapilot | gzip > $BACKUP_DIR/db-$DATE.sql.gz

# Backup volume
docker run --rm \
  -v infrapilot_data:/data \
  -v $BACKUP_DIR:/backup \
  alpine tar czf /backup/data-$DATE.tar.gz /data

# Keep last 30 days
find $BACKUP_DIR -name "*.gz" -mtime +30 -delete
```

### Restore

**1. Restore Volume**:

```bash
# Stop container
docker compose stop infrapilot

# Restore
docker run --rm \
  -v infrapilot_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/infrapilot-backup-20260114.tar.gz -C /

# Start container
docker compose start infrapilot
```

**2. Restore Database**:

```bash
# PostgreSQL
psql -h postgres-host -U infrapilot infrapilot < backup.sql

# Or with docker
docker exec -i postgres psql -U infrapilot infrapilot < backup.sql
```

## Monitoring

### Health Checks

**Container Health**:
```bash
docker compose ps
docker inspect infrapilot | jq '.[0].State.Health'
```

**API Health**:
```bash
curl http://localhost/health
```

### Metrics Collection

**Using Prometheus** (future feature):

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
```

**prometheus.yml**:
```yaml
scrape_configs:
  - job_name: 'infrapilot'
    static_configs:
      - targets: ['infrapilot:9090']
```

### Log Aggregation

**Using Loki**:

```yaml
services:
  loki:
    image: grafana/loki:latest
    volumes:
      - loki_data:/loki

  promtail:
    image: grafana/promtail:latest
    volumes:
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./promtail.yml:/etc/promtail/config.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
```

## Scaling

### Vertical Scaling

Increase container resources:

```yaml
deploy:
  resources:
    limits:
      cpus: '8'
      memory: 16G
```

### Horizontal Scaling

**Community Edition**: Single-node only

**Enterprise Edition**: Multi-node clustering with:
- Multiple agent nodes
- Shared external databases
- Load balancer

## Security Hardening

### 1. Firewall Configuration

```bash
# UFW
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# iptables
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

### 2. Docker Socket Security

Run with read-only Docker socket:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

### 3. Strong Secrets

```bash
# Generate strong JWT secret
JWT_SECRET=$(openssl rand -base64 48)

# Strong database passwords
POSTGRES_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
```

### 4. Enable MFA

- Enable MFA for all admin accounts
- Enforce MFA via settings

### 5. Regular Updates

```bash
# Update image
docker pull devsimplex/infrapilot:latest
docker compose up -d
```

### 6. Audit Logs

- Review audit logs regularly
- Set up alerts for suspicious activity

### 7. Network Isolation

```yaml
networks:
  infrapilot_net:
    driver: bridge
    internal: true
```

## Upgrading

### Upgrade Process

**1. Backup**:
```bash
./backup-script.sh
```

**2. Pull Latest Image**:
```bash
docker pull devsimplex/infrapilot:latest
```

**3. Stop Container**:
```bash
docker compose stop infrapilot
```

**4. Update and Restart**:
```bash
docker compose up -d
```

**5. Verify**:
```bash
docker compose logs -f infrapilot
curl http://localhost/health
```

### Rollback

If upgrade fails:

```bash
# Stop current version
docker compose stop infrapilot

# Use specific version
docker compose -f docker-compose.yml \
  -e IMAGE_TAG=v1.0.0 \
  up -d infrapilot
```

### Zero-Downtime Upgrades

Not supported in Community Edition. Use Enterprise Edition for:
- Blue-green deployments
- Rolling updates
- Canary deployments

## Production Checklist

Before going live:

- [ ] Set strong `JWT_SECRET`
- [ ] Use external databases
- [ ] Configure SSL/TLS
- [ ] Set up automated backups
- [ ] Configure monitoring
- [ ] Set up log aggregation
- [ ] Enable MFA for admins
- [ ] Configure firewall
- [ ] Set resource limits
- [ ] Test backup/restore
- [ ] Document configuration
- [ ] Set up alerting
- [ ] Review security settings

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues and solutions.

---

**Last Updated**: 2026-01-14
