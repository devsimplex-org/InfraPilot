# Production-Grade Nginx Log Analytics System

## Overview
Implement a persistent nginx log collection and analytics system using TimescaleDB for time-series storage, extending the existing agent log streamer, and creating a frontend analytics dashboard.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Nginx         │────▶│   Agent         │────▶│   Backend       │
│   access.log    │     │   Collector     │     │   Ingestion     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                              500 entries           COPY bulk insert
                              5s flush              │
                                                    ▼
                        ┌─────────────────────────────────────────┐
                        │         TimescaleDB Hypertable          │
                        │         nginx_access_logs               │
                        │         (auto-partitioned by day)       │
                        └─────────────────────────────────────────┘
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
                ┌───────────────┐                   ┌───────────────┐
                │ Continuous    │                   │ Continuous    │
                │ Aggregate 1m  │                   │ Aggregate 1h  │
                │ (30s refresh) │                   │ (hourly)      │
                └───────────────┘                   └───────────────┘
                        │
                        ▼
                ┌─────────────────┐
                │   Frontend      │
                │   Analytics     │
                │   (Recharts)    │
                └─────────────────┘
```

---

## Implementation Plan

### Phase 1: Database Schema (TimescaleDB)

**File:** `backend/internal/db/migrations/044_nginx_analytics_timescale.up.sql`

1. Enable TimescaleDB extension
2. Create `nginx_access_logs` hypertable with parsed fields:
   - `time`, `org_id`, `agent_id`
   - `client_ip`, `method`, `path`, `query_string`, `protocol`
   - `status_code`, `response_bytes`, `response_time`
   - `host`, `referer`, `user_agent`, `upstream`
3. Create continuous aggregates:
   - `nginx_stats_1m` - 30s refresh for real-time dashboards
   - `nginx_stats_1h` - hourly for historical views
   - `nginx_stats_daily` - daily for long-term trends
   - `nginx_top_paths_1h` - top endpoints by request count
4. Add compression policy (after 7 days)
5. Add retention policy (90 days default)

**Key Metrics in Aggregates:**
- Request counts by status code group (2xx, 3xx, 4xx, 5xx)
- Total bytes transferred
- Avg/P95/P99 response times
- Unique visitor counts

---

### Phase 2: Agent Nginx Log Collector

**New Files:**
- `agent/internal/logstreamer/nginx_parser.go`
- `agent/internal/logstreamer/nginx_collector.go`

**Features:**
1. Parse nginx combined log format with regex
2. Extract structured fields (IP, method, path, status, bytes, user-agent, etc.)
3. Watch `/var/log/nginx/access.log` with fsnotify
4. Buffer 500 entries or flush every 5 seconds
5. POST to `/api/v1/logs/nginx/ingest`

**Modify:** `agent/cmd/agent/main.go` - Start nginx collector alongside container log streamer

---

### Phase 3: Backend API Endpoints

**New File:** `backend/internal/api/nginx_analytics_handlers.go`

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/logs/nginx/ingest` | POST | Bulk log ingestion (uses COPY for speed) |
| `/api/v1/traffic/analytics` | GET | Time-series metrics (1m/1h/1d intervals) |
| `/api/v1/traffic/analytics/summary` | GET | 24h summary stats |
| `/api/v1/traffic/analytics/top-paths` | GET | Top N paths by requests |
| `/api/v1/traffic/analytics/status-codes` | GET | Status code distribution |

**Modify:** `backend/internal/api/handler.go` - Register routes

---

### Phase 4: Frontend Analytics Dashboard

**New File:** `frontend/app/(dashboard)/traffic/analytics/page.tsx`

**Features:**
- Time range selector (1h, 6h, 24h, 7d)
- Summary stats (StatCard grid): Total Requests, Error Rate, Avg Latency, P95, Unique Visitors
- Request rate chart (stacked area by status code)
- Response time chart (avg + P95 line chart)
- Status code pie chart
- Top paths table with request count, latency, bandwidth, errors
- Auto-refresh toggle (30s interval)

**Components Used:**
- Recharts: `AreaChart`, `LineChart`, `PieChart`
- Existing: `StatCard`, `MetricsGrid`, `Card`, `Badge`

**Modify:** `frontend/app/(dashboard)/traffic/layout.tsx` - Add "Analytics" nav item

---

### Phase 5: Docker Integration

**Modify:** `Dockerfile`
```dockerfile
# Add to runtime dependencies
RUN apk add --no-cache timescaledb
```

**Modify:** `deployments/docker-entrypoint.sh`
```bash
# After PostgreSQL init, enable TimescaleDB
echo "shared_preload_libraries = 'timescaledb'" >> /data/postgres/postgresql.conf
psql -U postgres -d infrapilot -c "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"
```

**Modify:** Nginx config template - Use extended log format with `$request_time`

---

## Files to Create/Modify

### New Files
| File | Purpose |
|------|---------|
| `backend/internal/db/migrations/044_nginx_analytics_timescale.up.sql` | TimescaleDB schema |
| `backend/internal/db/migrations/044_nginx_analytics_timescale.down.sql` | Rollback migration |
| `agent/internal/logstreamer/nginx_parser.go` | Log line parser |
| `agent/internal/logstreamer/nginx_collector.go` | File watcher + buffer |
| `backend/internal/api/nginx_analytics_handlers.go` | API handlers |
| `frontend/app/(dashboard)/traffic/analytics/page.tsx` | Analytics dashboard |

### Modify Files
| File | Changes |
|------|---------|
| `agent/cmd/agent/main.go` | Start nginx collector |
| `backend/internal/api/handler.go` | Register analytics routes |
| `frontend/app/(dashboard)/traffic/layout.tsx` | Add Analytics nav link |
| `frontend/lib/api.ts` | Add analytics API functions |
| `Dockerfile` | Add timescaledb package |
| `deployments/docker-entrypoint.sh` | Enable TimescaleDB extension |
| `backend/internal/api/traffic_compiler.go` | Extended nginx log format |

---

## Verification Plan

1. **Database**: Run migration, verify hypertable created with `\d+ nginx_access_logs`
2. **Agent**: Check logs for "Starting nginx log collector", verify batches sent
3. **Backend**: Test endpoints with curl:
   ```bash
   curl -X POST /api/v1/logs/nginx/ingest -d '{"agent_id":"...", "entries":[...]}'
   curl /api/v1/traffic/analytics?interval=1h&hours=24
   curl /api/v1/traffic/analytics/summary
   ```
4. **Frontend**: Navigate to /traffic/analytics, verify charts render
5. **E2E**: Generate traffic, wait 30s for aggregate refresh, verify data appears

---

## Performance Expectations

- **Ingestion**: 10,000+ logs/second with COPY bulk insert
- **Query**: <100ms for dashboard queries (continuous aggregates)
- **Storage**: ~90% compression after 7 days
- **Retention**: 90 days (configurable per org)
