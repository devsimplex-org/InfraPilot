# Epic 01: Foundation

**Status:** ✅ Complete
**Phase:** 1
**Priority:** Critical

---

## Overview

Set up the core infrastructure for InfraPilot including project structure, database schema, authentication, and basic UI shell.

---

## User Stories

### US-1.1: Project Setup ✅
**As a** developer
**I want** a well-organized monorepo structure
**So that** I can work on backend, agent, and frontend independently

**Acceptance Criteria:**
- [x] Go backend with internal package structure
- [x] Go agent with internal package structure
- [x] Next.js frontend with App Router
- [x] Shared proto definitions
- [x] Docker Compose for local dev
- [x] Dev scripts for common tasks

### US-1.2: Database Schema ✅
**As a** developer
**I want** a complete database schema
**So that** all entities are properly modeled

**Acceptance Criteria:**
- [x] Organizations table (multi-tenancy ready)
- [x] Users table with MFA support
- [x] Agents table with enrollment tokens
- [x] Proxy hosts and related tables
- [x] Containers table
- [x] Alert channels and rules
- [x] Audit logs
- [x] All indexes and constraints

### US-1.3: Authentication ✅
**As a** user
**I want** to log in securely
**So that** my account is protected

**Acceptance Criteria:**
- [x] JWT-based authentication
- [x] Password hashing (bcrypt)
- [x] Refresh token support
- [x] MFA skeleton (TOTP)
- [x] RBAC middleware

### US-1.4: API Scaffold ✅
**As a** developer
**I want** all API routes defined
**So that** I can implement them incrementally

**Acceptance Criteria:**
- [x] All auth endpoints
- [x] All agent endpoints
- [x] All proxy endpoints
- [x] All container endpoints
- [x] All alert endpoints
- [x] Stub implementations return 501

### US-1.5: Frontend Shell ✅
**As a** user
**I want** a dashboard UI
**So that** I can navigate the application

**Acceptance Criteria:**
- [x] Login page
- [x] Dashboard layout with sidebar
- [x] Overview page
- [x] Agents list page
- [x] Navigation between pages
- [x] Auth state management

---

## Technical Tasks

- [x] Initialize Go modules for backend and agent
- [x] Set up Gin router with middleware
- [x] Configure PostgreSQL connection pool
- [x] Write database migration SQL
- [x] Implement JWT service
- [x] Create API handlers structure
- [x] Set up Next.js with Tailwind
- [x] Create React Query provider
- [x] Build API client library
- [x] Create Zustand auth store
- [x] Add godotenv for .env loading
- [x] Configure Air for hot reload

---

## Definition of Done

- [x] Backend starts and connects to PostgreSQL
- [x] All routes registered (visible in logs)
- [x] Frontend builds and runs
- [x] Login page renders
- [x] Dashboard accessible
- [x] Hot reload working
