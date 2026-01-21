# InfraPilot Development & Production Setup

This document describes the development and production environment setup for InfraPilot.

## Architecture Overview

InfraPilot runs as an "all-in-one" container that includes:
- **PostgreSQL** - Primary database
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
        ├── docker-compose.infra.yml   # Production compose file
        └── .env                       # Production environment
```

## Development Environment

### Starting Development

```bash
cd /home/administrator/infrapilot-ee
./scripts/dev.sh up
```

This starts:
- `infrapilot-dev-postgres` - PostgreSQL database
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

### Deploying to Production

```bash
cd /home/administrator/dx-core-ops/infra

# Pull latest image
docker compose --env-file .env -f docker-compose.infra.yml pull infrapilot

# Recreate container
docker compose --env-file .env -f docker-compose.infra.yml up -d --no-deps --force-recreate infrapilot

# Connect to development network (if needed for cross-container access)
docker network connect infrapilot-ee_infrapilot-dev infrapilot
```

### Production URLs
- Dashboard: https://infra.devsimplex.net (with basic auth)
- API: https://infra.devsimplex.net/api/

## Data Persistence

Production data is stored in Docker volumes mapped to `/data`:

| Path | Contents |
|------|----------|
| `/data/postgres` | PostgreSQL data files |
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

## Database Migrations

Migrations run automatically on startup from embedded SQL files.
- Up migrations: `*.up.sql` - Applied automatically
- Down migrations: `*.down.sql` - Manual rollback only

Migration files location: `backend/internal/db/migrations/`

### Manual migration

```bash
# Check current state
docker exec infrapilot psql -U postgres -d infrapilot -c "SELECT * FROM schema_migrations ORDER BY version DESC LIMIT 10;"

# Run a specific migration
docker exec infrapilot psql -U postgres -d infrapilot -f /app/backend/migrations/035_example.up.sql
```

## Networking

### Docker Networks

| Network | Purpose |
|---------|---------|
| `infrapilot-ee_infrapilot-dev` | Development containers |
| `dx-core-ops_default` | Production orchestration |

### Cross-Environment Access

To allow production container to reach dev containers:
```bash
docker network connect infrapilot-ee_infrapilot-dev infrapilot
```

## Logs & Debugging

```bash
# All container logs
docker logs infrapilot

# Backend logs only
docker exec infrapilot supervisorctl tail -f backend

# Nginx logs
docker exec infrapilot tail -f /var/log/nginx/error.log

# PostgreSQL logs
docker exec infrapilot tail -f /data/postgres/pg_log/postgresql.log
```

## Common Operations

### Restart a service

```bash
docker exec infrapilot supervisorctl restart backend
docker exec infrapilot supervisorctl restart frontend
docker exec infrapilot supervisorctl restart nginx
```

### Database access

```bash
docker exec -it infrapilot psql -U postgres -d infrapilot
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
Backend or frontend isn't running:
```bash
docker exec infrapilot supervisorctl status
```

### Basic auth not working
1. Check htpasswd file exists: `docker exec infrapilot ls -la /data/nginx/conf.d/.htpasswd*`
2. Check nginx config has auth_basic directive
3. Reload nginx: `docker exec infrapilot nginx -s reload`

### Database connection issues
Check PostgreSQL is running:
```bash
docker exec infrapilot pg_isready -U postgres
```
