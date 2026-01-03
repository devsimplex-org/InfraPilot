# EPIC-04: Dynamic Docker Network Attachment for Nginx Upstreams

**Epic ID:** INFRA-EDGE-004
**Status:** Complete
**Completed:** 2026-01-01

---

## Goal

Enable InfraPilot to proxy traffic to Docker containers in different networks by dynamically attaching the Nginx container to those networks at runtime via Docker API (NetworkConnect).

## Problem Statement

When using Docker containers as proxy upstream targets, nginx needs to be on the same Docker network as the target container to resolve its DNS name. Previously, users had to manually configure network attachments or use IP addresses.

## Solution

Implemented automatic network detection and attachment with user confirmation:
1. Detect which network(s) a target container is connected to
2. Check if nginx is already on that network
3. If not, prompt user with a warning modal to attach nginx to the network
4. Attach nginx dynamically using Docker's NetworkConnect API
5. Track attachments in database for audit and management

---

## Implementation Summary

| Layer | Files Changed | Status |
|-------|---------------|--------|
| Agent Docker Client | `agent/internal/docker/client.go` | Complete |
| Agent Command Handler | `agent/cmd/agent/main.go` | Complete |
| gRPC Protocol | `proto/agent/v1/agent.proto` | Complete |
| Database Migration | `backend/internal/db/migrations/002_network_attachments.sql` | Complete |
| Backend API | `backend/internal/api/networks_handlers.go` | Complete |
| Backend Routes | `backend/internal/api/handler.go` | Complete |
| Frontend API | `frontend/lib/api.ts` | Complete |
| Frontend UI | `frontend/app/(dashboard)/proxies/page.tsx` | Complete |

---

## Features Implemented

### Agent Docker Client Extensions

**New Types:**
- `NetworkInfo` - Docker network metadata
- `ContainerNetworkInfo` - Container's network membership with IP
- `NetworkAttachResult` - Result of network attach operation

**New Methods:**
- `ListNetworks(ctx)` - List all bridge networks (filters out host/none/overlay)
- `InspectNetwork(ctx, networkID)` - Get network details
- `GetContainerNetworks(ctx, containerID)` - Get container's networks
- `ConnectNetwork(ctx, networkID, containerID)` - Attach container to network
- `DisconnectNetwork(ctx, networkID, containerID)` - Detach container from network
- `IsNetworkSafe(ctx, networkID)` - Validate network is safe to attach
- `IsContainerOnNetwork(ctx, containerID, networkID)` - Check connection status

### gRPC Protocol

**NetworkCommand Actions:**
- `ACTION_LIST_NETWORKS` - List available networks
- `ACTION_GET_CONTAINER_NETWORKS` - Get container's networks
- `ACTION_CHECK_NGINX_NETWORK` - Check if nginx is on a network
- `ACTION_ATTACH_NGINX_NETWORK` - Attach nginx to network
- `ACTION_DETACH_NGINX_NETWORK` - Detach nginx from network

### Backend API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/agents/:id/networks` | List Docker networks |
| GET | `/agents/:id/networks/attachments` | List networks attached by InfraPilot |
| POST | `/agents/:id/networks/attach` | Attach nginx to network |
| POST | `/agents/:id/networks/detach` | Detach nginx from network |
| GET | `/agents/:id/containers/:cid/networks` | Get container's networks |
| GET | `/agents/:id/networks/:nid/check-nginx` | Check if nginx is on network |

### Database Schema

```sql
CREATE TABLE nginx_network_attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    network_id      VARCHAR(64) NOT NULL,
    network_name    VARCHAR(255) NOT NULL,
    attached_at     TIMESTAMPTZ DEFAULT NOW(),
    attached_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    status          VARCHAR(20) DEFAULT 'attached'
                    CHECK (status IN ('attached', 'detached', 'error')),
    error_message   TEXT,
    UNIQUE(agent_id, network_id)
);
```

### Frontend UI

1. **Upstream Mode Toggle** - Switch between "Manual URL" and "Container" modes
2. **Container Selector** - Dropdown of running containers
3. **Port Input** - Internal container port
4. **Network Status Indicator** - Shows if nginx is connected (green) or not (yellow warning)
5. **Network Warning Modal** - Confirmation dialog with "Attach Nginx to Network" button

---

## Safety Guardrails

### Blocked Networks
- `host` network - Security risk, bypasses container isolation
- `none` network - No networking, cannot be attached
- `overlay` networks - Swarm mode, not supported
- Non-local scope networks

### Allowed Networks
- `bridge` driver networks
- `scope=local` networks
- User-explicitly-selected networks only

### Validation Flow
```go
func (c *Client) IsNetworkSafe(ctx context.Context, networkID string) (bool, string) {
    net, err := c.cli.NetworkInspect(ctx, networkID, network.InspectOptions{})
    if err != nil {
        return false, "network not found"
    }
    if net.Name == "host" || net.Name == "none" {
        return false, fmt.Sprintf("cannot attach to %s network", net.Name)
    }
    if net.Driver == "overlay" {
        return false, "overlay networks not supported"
    }
    if net.Scope != "local" {
        return false, "only local scope networks are supported"
    }
    return true, ""
}
```

---

## User Flow

```
1. User creates proxy, selects "Container" mode
2. User picks container from dropdown (e.g., "my-app")
3. User enters internal port (e.g., "3000")
4. System checks: Is nginx on the same network as my-app?
   - YES: Green indicator, proceed normally
   - NO: Yellow warning indicator
5. User clicks "Create"
6. If not connected: Network Warning Modal appears
   - Shows network name and ID
   - "Attach Nginx to Network" button
7. User confirms attachment
8. Agent executes docker network connect
9. Database records attachment with audit trail
10. Proxy config generated with container DNS name
11. Nginx reloaded, traffic flows
```

---

## Testing Notes

### Manual Testing
1. Create a container on a custom bridge network
2. Try to create a proxy targeting that container
3. Verify warning modal appears
4. Confirm attachment and verify proxy works

### Verification Commands
```bash
# List networks
docker network ls

# Check nginx connections
docker network inspect <network_name> | jq '.Containers'

# Check container networks
docker inspect <container_id> | jq '.[0].NetworkSettings.Networks'
```

---

## Future Enhancements

- [ ] Bulk network attachment UI
- [ ] Network attachment cleanup on proxy deletion
- [ ] Network topology visualization
- [ ] Automatic network detection improvements
- [ ] Support for multiple container networks
