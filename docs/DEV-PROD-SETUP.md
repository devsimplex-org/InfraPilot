# InfraPilot Development & Production Setup

This document describes the development and production environment setup for InfraPilot.

## Architecture Overview

InfraPilot runs as an "all-in-one" container that includes:
- **PostgreSQL 17** - Primary database with TimescaleDB extension
- **Redis** - Session cache and pub/sub
- **Nginx** - Reverse proxy and SSL termination
- **Backend** - Go API server (port 8080)
- **Frontend** - Next.js application (port 3000)
- **Agent** - Embedded agent for nginx management

## Directory Structure

```
/home/administrator/
├── infrapilot-ee/              # Source code repository
│   ├── backend/                # Go backend
│   ├── frontend/               # Next.js frontend
│   ├── agent/                  # Go agent
│   ├── scripts/                # Build and deployment scripts
│   └── deployments/            # Docker configs
│
└── dx-core-ops/
    └── infra/
        ├── docker-compose.infrapilot.yml   # Production compose file
        ├── data/                           # Persistent data
        └── .env                            # Production environment
```

## Development Environment

### Starting Development

```bash
cd /home/administrator/infrapilot-ee
./scripts/dev.sh up
```

This starts:
- `infrapilot-dev-postgres` - PostgreSQL database (timescale/timescaledb:latest-pg16)
- `infrapilot-dev-redis` - Redis cache
- `infrapilot-dev-backend` - Backend with hot reload
- `infrapilot-dev-frontend` - Frontend with hot reload
- `infrapilot-dev-agent` - Agent
- `infrapilot-nginx` - Shared nginx proxy

### Development URLs
- Frontend: http://localhost:3000
- Backend API: http://localhost:8080
- PostgreSQL: localhost:5432

### Stopping Development

```bash
./scripts/dev.sh down
```

## Production Environment

### Building & Publishing

```bash
cd /home/administrator/infrapilot-ee
./scripts/build-and-publish.sh v1.0.0 --all-in-one
```

This builds and pushes to `ghcr.io/tybali/infrapilot:v1.0.0` and `ghcr.io/tybali/infrapilot:latest`.

For local build only (no push):
```bash
./scripts/build-and-publish.sh v1.0.0 --all-in-one --no-push
```

### Deploying to Production

```bash
cd /home/administrator/dx-core-ops/infra

# Recreate container with new image
docker compose --env-file .env -f docker-compose.infrapilot.yml up -d --no-deps --force-recreate infrapilot

# Connect to dev network (required for proxies pointing to dev containers)
docker network connect infrapilot-ee_infrapilot-dev infrapilot
```

### Production URLs
- Dashboard: https://infra.devsimplex.net
- API: https://infra.devsimplex.net/api/

## Data Persistence

Production data is stored in Docker volumes mapped to `/data`:

| Path | Contents |
|------|----------|
| `/data/postgres` | PostgreSQL 17 data files |
| `/data/redis` | Redis persistence |
| `/data/nginx/conf.d/` | Nginx proxy configs and htpasswd files |
| `/data/nginx/certs/` | SSL certificates |
| `/data/letsencrypt/` | Let's Encrypt certificates |

## Basic Authentication

System proxies can have HTTP Basic Auth enabled:
- Htpasswd files stored at: `/data/nginx/conf.d/.htpasswd_{domain}`
- API routes (`/api/*`) bypass basic auth (use JWT instead)
- Frontend routes require basic auth when enabled

### Creating htpasswd manually

```bash
docker exec infrapilot htpasswd -cb /data/nginx/conf.d/.htpasswd_domain_name username password
docker exec infrapilot nginx -s reload
```

## Database

### PostgreSQL 17 + TimescaleDB

The production container uses PostgreSQL 17 with TimescaleDB extension for:
- Time-series nginx log analytics
- Hypertables for efficient log storage
- Materialized views for dashboard metrics

### Migrations

Migrations run automatically on startup from embedded SQL files.
- Up migrations: `*.up.sql` - Applied automatically
- Down migrations: `*.down.sql` - Manual rollback only

Migration files location: `backend/internal/db/migrations/`

### Manual migration

```bash
# Check current state
docker exec infrapilot su-exec postgres psql -h /run/postgresql -U postgres -d infrapilot -c "SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 10;"

# Run a specific migration
docker exec infrapilot su-exec postgres psql -h /run/postgresql -U postgres -d infrapilot -f /app/backend/migrations/044_example.up.sql
```

### Database Backup & Restore

```bash
# Backup
docker exec infrapilot su-exec postgres pg_dump -h /run/postgresql -U postgres -d infrapilot -F c -f /tmp/backup.dump
docker cp infrapilot:/tmp/backup.dump ./infrapilot_backup.dump

# Restore
docker cp ./infrapilot_backup.dump infrapilot:/tmp/backup.dump
docker exec infrapilot su-exec postgres pg_restore -h /run/postgresql -U postgres -d infrapilot --clean --if-exists --no-owner /tmp/backup.dump
# Fix permissions after restore
docker exec infrapilot su-exec postgres psql -h /run/postgresql -U postgres -d infrapilot -c "GRANT ALL ON ALL TABLES IN SCHEMA public TO infrapilot; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO infrapilot;"
```

## Networking

### Docker Networks

| Network | Purpose |
|---------|---------|
| `infrapilot-ee_infrapilot-dev` | Development containers |
| `infrapilot` | Production container |

### Cross-Environment Access

Production container must be connected to dev network to proxy requests to dev containers:
```bash
docker network connect infrapilot-ee_infrapilot-dev infrapilot
```

**Important:** This must be done after each container restart/recreate.

## Logs & Debugging

```bash
# All container logs
docker logs infrapilot

# Backend logs only
docker exec infrapilot cat /var/log/supervisor/backend.log
docker exec infrapilot cat /var/log/supervisor/backend-error.log

# Nginx logs
docker exec infrapilot tail -f /var/log/nginx/error.log

# Check service status
docker exec infrapilot cat /var/log/supervisor/supervisord.log
```

## Common Operations

### Restart a service

```bash
docker restart infrapilot
# Then reconnect to dev network
docker network connect infrapilot-ee_infrapilot-dev infrapilot
```

### Database access

```bash
docker exec -it infrapilot su-exec postgres psql -h /run/postgresql -U postgres -d infrapilot
```

### Nginx config test

```bash
docker exec infrapilot nginx -t
docker exec infrapilot nginx -s reload
```

## Troubleshooting

### Container won't start
Check logs: `docker logs infrapilot`

### 502 Bad Gateway
1. Check if backend is running:
   ```bash
   docker exec infrapilot curl -s http://127.0.0.1:8080/health
   ```
2. Check backend error logs:
   ```bash
   docker exec infrapilot cat /var/log/supervisor/backend-error.log | tail -20
   ```

### Nginx keeps restarting
Check for missing upstreams (dev containers not running):
```bash
docker exec infrapilot cat /var/log/supervisor/nginx-error.log | tail -20
```
If errors about `host not found in upstream`, connect to dev network:
```bash
docker network connect infrapilot-ee_infrapilot-dev infrapilot
```

### Database permission errors
After restore, fix permissions:
```bash
docker exec infrapilot su-exec postgres psql -h /run/postgresql -U postgres -d infrapilot -c "GRANT ALL ON ALL TABLES IN SCHEMA public TO infrapilot; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO infrapilot;"
```

### TimescaleDB not loading
Check if shared_preload_libraries is set:
```bash
docker exec infrapilot cat /data/postgres/postgresql.conf | grep shared_preload
```
Should show: `shared_preload_libraries = 'timescaledb'`
