# Epic 03: Docker Operations

**Status:** 🔲 Not Started
**Phase:** 3
**Priority:** High

---

## Overview

Enable users to view, manage, and interact with Docker containers running on agents.

---

## User Stories

### US-3.1: List Containers
**As a** user
**I want** to see all containers on an agent
**So that** I know what's running

**Acceptance Criteria:**
- [ ] Table with name, image, status, CPU, RAM
- [ ] Color-coded status badges
- [ ] Stack grouping (docker-compose)
- [ ] Auto-refresh every 10s
- [ ] Filter by status/stack

### US-3.2: Container Details
**As a** user
**I want** to view container details
**So that** I can see its configuration

**Acceptance Criteria:**
- [ ] Container name, ID, image
- [ ] Port mappings
- [ ] Environment variables (masked)
- [ ] Volume mounts
- [ ] Network info
- [ ] Resource usage chart

### US-3.3: Start/Stop/Restart Container
**As an** operator
**I want** to control container lifecycle
**So that** I can manage services

**Acceptance Criteria:**
- [ ] Start button (for stopped)
- [ ] Stop button (for running)
- [ ] Restart button (always)
- [ ] Confirmation for stop
- [ ] Action logged in audit

### US-3.4: View Container Logs
**As a** user
**I want** to view container logs
**So that** I can debug issues

**Acceptance Criteria:**
- [ ] Last 100 lines by default
- [ ] Load more button
- [ ] Real-time streaming toggle
- [ ] Timestamp display
- [ ] Log level highlighting

### US-3.5: Container Exec Shell
**As an** operator
**I want** to open a shell in a container
**So that** I can run commands

**Acceptance Criteria:**
- [ ] Terminal emulator (xterm.js)
- [ ] Shell selection (sh/bash)
- [ ] Resize support
- [ ] Session timeout
- [ ] Commands logged in audit

### US-3.6: Stack View
**As a** user
**I want** to see containers grouped by stack
**So that** I understand service composition

**Acceptance Criteria:**
- [ ] Group by docker-compose project
- [ ] Expand/collapse groups
- [ ] Stack-level actions (restart all)

---

## Technical Tasks

### Backend
- [ ] Implement container list handler (from DB sync)
- [ ] Implement container detail handler
- [ ] Implement start/stop/restart handlers
- [ ] Implement log retrieval (paginated)
- [ ] WebSocket handler for log streaming
- [ ] WebSocket handler for exec

### Agent
- [ ] Sync container state on heartbeat
- [ ] Handle start/stop/restart commands
- [ ] Stream container logs via gRPC
- [ ] Handle exec sessions

### Frontend
- [ ] Create ContainersPage component
- [ ] Create ContainerCard component
- [ ] Create LogViewer component
- [ ] Create Terminal component (xterm.js)
- [ ] Add WebSocket connection manager

---

## Definition of Done

- [ ] Containers list shows real data from agent
- [ ] Can start/stop/restart containers
- [ ] Logs display correctly
- [ ] Exec terminal works
- [ ] All actions logged
