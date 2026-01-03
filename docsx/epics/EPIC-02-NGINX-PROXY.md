# Epic 02: Nginx Proxy Management

**Status:** 🔲 Not Started
**Phase:** 2
**Priority:** Critical

---

## Overview

Enable users to create and manage Nginx reverse proxy configurations through the dashboard, with automatic SSL certificate provisioning.

---

## User Stories

### US-2.1: Create Proxy Host
**As an** operator
**I want** to create a reverse proxy configuration
**So that** I can route traffic to my containers

**Acceptance Criteria:**
- [ ] Form to enter domain and upstream target
- [ ] Validation of domain format
- [ ] Upstream can be container:port or IP:port
- [ ] Config saved to database
- [ ] Config pushed to agent
- [ ] Nginx reloaded on agent

### US-2.2: List Proxy Hosts
**As a** user
**I want** to see all proxy hosts for an agent
**So that** I know what's configured

**Acceptance Criteria:**
- [ ] Table showing domain, upstream, SSL status
- [ ] Status indicator (active/error)
- [ ] SSL expiry date shown
- [ ] Filter by status
- [ ] Sort by domain/created date

### US-2.3: Edit Proxy Host
**As an** operator
**I want** to modify a proxy configuration
**So that** I can update upstreams or settings

**Acceptance Criteria:**
- [ ] Edit form pre-filled with current values
- [ ] Can change upstream target
- [ ] Can toggle SSL settings
- [ ] Changes pushed to agent
- [ ] Nginx reloaded

### US-2.4: Delete Proxy Host
**As an** operator
**I want** to remove a proxy configuration
**So that** traffic is no longer routed

**Acceptance Criteria:**
- [ ] Confirmation dialog
- [ ] Config file removed from agent
- [ ] Nginx reloaded
- [ ] Database record deleted

### US-2.5: Request SSL Certificate
**As an** operator
**I want** to enable SSL for a domain
**So that** traffic is encrypted

**Acceptance Criteria:**
- [ ] Button to request SSL
- [ ] Let's Encrypt integration (certbot or acme.sh)
- [ ] Certificate stored on agent
- [ ] Nginx config updated for HTTPS
- [ ] Auto-renewal scheduled
- [ ] SSL expiry tracked in database

### US-2.6: View Nginx Config
**As a** user
**I want** to see the generated nginx config
**So that** I can verify it's correct

**Acceptance Criteria:**
- [ ] Modal showing raw nginx config
- [ ] Syntax highlighting
- [ ] Read-only view

### US-2.7: Configure Security Headers
**As an** operator
**I want** to set security headers
**So that** my sites are more secure

**Acceptance Criteria:**
- [ ] HSTS toggle and max-age
- [ ] X-Frame-Options dropdown
- [ ] X-Content-Type-Options toggle
- [ ] CSP text input
- [ ] Headers applied to nginx config

---

## Technical Tasks

### Backend
- [ ] Implement proxy CRUD handlers
- [ ] Create nginx config generator
- [ ] Add gRPC commands for nginx operations
- [ ] Integrate with Let's Encrypt
- [ ] Add SSL certificate tracking

### Agent
- [ ] Handle nginx config write commands
- [ ] Implement nginx -t (test config)
- [ ] Implement nginx -s reload
- [ ] Report config status to backend
- [ ] Handle SSL cert requests

### Frontend
- [ ] Create ProxyHostsPage component
- [ ] Create ProxyForm component
- [ ] Create ConfigPreviewModal
- [ ] Create SecurityHeadersForm
- [ ] Add proxy API calls to lib/api.ts

---

## API Endpoints

```
POST   /api/v1/agents/:id/proxies
GET    /api/v1/agents/:id/proxies
GET    /api/v1/agents/:id/proxies/:pid
PUT    /api/v1/agents/:id/proxies/:pid
DELETE /api/v1/agents/:id/proxies/:pid
POST   /api/v1/agents/:id/proxies/:pid/ssl
GET    /api/v1/agents/:id/proxies/:pid/config
POST   /api/v1/agents/:id/proxies/:pid/test
```

---

## Definition of Done

- [ ] Can create a proxy host from dashboard
- [ ] Nginx config generated correctly
- [ ] Agent receives and applies config
- [ ] Nginx reloads successfully
- [ ] SSL certificates can be requested
- [ ] All CRUD operations work end-to-end
