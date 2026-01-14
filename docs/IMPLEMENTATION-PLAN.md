# Complete DevSecOps Implementation Plan

This document provides a comprehensive implementation plan for transforming InfraPilot into a DevSecOps-first platform, including all epics from the roadmap plus load balancing.

## Table of Contents

- [Overview](#overview)
- [Phase 1: Foundations](#phase-1-foundations)
- [Phase 2: Supply Chain Security](#phase-2-supply-chain-security)
- [Phase 3: Policy Engine](#phase-3-policy-engine)
- [Phase 4: CI/CD Integration](#phase-4-cicd-integration)
- [Phase 5: Runtime Security](#phase-5-runtime-security)
- [Phase 6: Load Balancing](#phase-6-load-balancing)
- [Phase 7: Observability](#phase-7-observability)
- [Phase 8: Hardening & Research](#phase-8-hardening--research)
- [Database Migrations Summary](#database-migrations-summary)
- [API Endpoints Summary](#api-endpoints-summary)
- [File Changes Summary](#file-changes-summary)

---

## Overview

### Goals

Transform InfraPilot from an infrastructure control plane into a **DevSecOps-first platform** that satisfies all four pillars:

| Pillar | Description | Implementation |
|--------|-------------|----------------|
| **Security Gates** | Security gates deployments | Policy engine blocks vulnerable images |
| **Traceability** | Code → Image → Runtime | Deployment entity with full provenance |
| **Automation** | Automatic enforcement | OPA policies, automated scanning |
| **Auditability** | Reversible operations | Unified timeline, audit logs |

### Design Principles

- Follow existing handler patterns (Gin + pgx)
- Use existing gRPC command infrastructure
- Maintain org-level isolation
- Atomic nginx config updates
- Non-breaking changes to existing functionality

---

## Phase 1: Foundations

**Epic 0: DevSecOps Foundations**

**Objective**: Redefine core domain from "containers" to "secure deployments"

### 1.1 Database Migration: `010_deployments.up.sql`

```sql
-- Deployment status enum
CREATE TYPE deployment_status AS ENUM (
    'pending',
    'scanning',
    'policy_check',
    'deploying',
    'running',
    'failed',
    'rolled_back',
    'stopped'
);

-- Policy decision enum
CREATE TYPE policy_decision AS ENUM ('allow', 'warn', 'deny');

-- Core deployments table
CREATE TABLE deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Service identification
    service_name VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),

    -- Image information
    image_registry VARCHAR(255),
    image_repository VARCHAR(255) NOT NULL,
    image_tag VARCHAR(255),
    image_digest VARCHAR(255),

    -- Provenance (traceability)
    git_repo VARCHAR(500),
    git_branch VARCHAR(255),
    git_commit VARCHAR(64),
    ci_provider VARCHAR(50),
    ci_pipeline_id VARCHAR(255),
    ci_build_url VARCHAR(500),

    -- Security references
    scan_result_id UUID,
    sbom_id UUID,
    policy_decision policy_decision NOT NULL DEFAULT 'allow',
    policy_reason TEXT,

    -- Status
    status deployment_status NOT NULL DEFAULT 'pending',
    status_message TEXT,

    -- Container mapping
    container_id VARCHAR(64),
    container_name VARCHAR(255),
    proxy_host_id UUID REFERENCES proxy_hosts(id),

    -- Relationships
    replaces_deployment_id UUID REFERENCES deployments(id),
    rollback_of_deployment_id UUID REFERENCES deployments(id),

    -- Audit
    deployed_by UUID REFERENCES users(id),
    deployed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_deployments_org ON deployments(org_id);
CREATE INDEX idx_deployments_agent ON deployments(agent_id);
CREATE INDEX idx_deployments_service ON deployments(service_name, environment);
CREATE INDEX idx_deployments_image ON deployments(image_digest);
CREATE INDEX idx_deployments_git ON deployments(git_repo, git_commit);
CREATE INDEX idx_deployments_status ON deployments(status);
CREATE INDEX idx_deployments_created ON deployments(created_at DESC);

-- Link containers to deployments
ALTER TABLE containers ADD COLUMN IF NOT EXISTS deployment_id UUID REFERENCES deployments(id);
CREATE INDEX IF NOT EXISTS idx_containers_deployment ON containers(deployment_id);
```

### 1.2 Deployment Handlers: `backend/internal/api/deployment_handlers.go`

```go
package api

import (
    "fmt"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

// ==================== Types ====================

type DeploymentStatus string
type PolicyDecision string

const (
    StatusPending     DeploymentStatus = "pending"
    StatusScanning    DeploymentStatus = "scanning"
    StatusPolicyCheck DeploymentStatus = "policy_check"
    StatusDeploying   DeploymentStatus = "deploying"
    StatusRunning     DeploymentStatus = "running"
    StatusFailed      DeploymentStatus = "failed"
    StatusRolledBack  DeploymentStatus = "rolled_back"
    StatusStopped     DeploymentStatus = "stopped"

    DecisionAllow PolicyDecision = "allow"
    DecisionWarn  PolicyDecision = "warn"
    DecisionDeny  PolicyDecision = "deny"
)

type CreateDeploymentRequest struct {
    ServiceName     string `json:"service_name" binding:"required"`
    Environment     string `json:"environment" binding:"required,oneof=dev staging prod"`
    ImageRepository string `json:"image_repository" binding:"required"`
    ImageTag        string `json:"image_tag"`
    ImageDigest     string `json:"image_digest"`
    GitRepo         string `json:"git_repo"`
    GitBranch       string `json:"git_branch"`
    GitCommit       string `json:"git_commit"`
    CIProvider      string `json:"ci_provider"`
    CIPipelineID    string `json:"ci_pipeline_id"`
}

// ==================== List Deployments ====================

func (h *Handler) listDeployments(c *gin.Context) {
    orgID := c.GetString("org_id")
    agentID := c.Param("id")
    service := c.Query("service")
    environment := c.Query("environment")
    status := c.Query("status")

    query := `
        SELECT id, service_name, environment, image_repository, image_tag,
               image_digest, git_repo, git_branch, git_commit,
               ci_provider, ci_pipeline_id, scan_result_id, sbom_id,
               policy_decision, status, status_message, container_id,
               deployed_by, deployed_at, created_at
        FROM deployments
        WHERE org_id = $1 AND agent_id = $2
    `
    args := []interface{}{orgID, agentID}
    argIdx := 3

    if service != "" {
        query += fmt.Sprintf(" AND service_name = $%d", argIdx)
        args = append(args, service)
        argIdx++
    }
    if environment != "" {
        query += fmt.Sprintf(" AND environment = $%d", argIdx)
        args = append(args, environment)
        argIdx++
    }
    if status != "" {
        query += fmt.Sprintf(" AND status = $%d", argIdx)
        args = append(args, status)
        argIdx++
    }

    query += " ORDER BY created_at DESC LIMIT 100"

    rows, err := h.db.Query(c, query, args...)
    if err != nil {
        h.logger.Error("Failed to list deployments", zap.Error(err))
        c.JSON(500, gin.H{"error": "Failed to list deployments"})
        return
    }
    defer rows.Close()

    var deployments []gin.H
    for rows.Next() {
        var d struct {
            ID              uuid.UUID
            ServiceName     string
            Environment     string
            ImageRepository string
            ImageTag        *string
            ImageDigest     *string
            GitRepo         *string
            GitBranch       *string
            GitCommit       *string
            CIProvider      *string
            CIPipelineID    *string
            ScanResultID    *uuid.UUID
            SBOMID          *uuid.UUID
            PolicyDecision  string
            Status          string
            StatusMessage   *string
            ContainerID     *string
            DeployedBy      *uuid.UUID
            DeployedAt      *time.Time
            CreatedAt       time.Time
        }
        if err := rows.Scan(&d.ID, &d.ServiceName, &d.Environment,
            &d.ImageRepository, &d.ImageTag, &d.ImageDigest,
            &d.GitRepo, &d.GitBranch, &d.GitCommit,
            &d.CIProvider, &d.CIPipelineID, &d.ScanResultID, &d.SBOMID,
            &d.PolicyDecision, &d.Status, &d.StatusMessage, &d.ContainerID,
            &d.DeployedBy, &d.DeployedAt, &d.CreatedAt); err != nil {
            continue
        }
        deployments = append(deployments, gin.H{
            "id":               d.ID,
            "service_name":     d.ServiceName,
            "environment":      d.Environment,
            "image_repository": d.ImageRepository,
            "image_tag":        d.ImageTag,
            "image_digest":     d.ImageDigest,
            "git_repo":         d.GitRepo,
            "git_branch":       d.GitBranch,
            "git_commit":       d.GitCommit,
            "ci_provider":      d.CIProvider,
            "ci_pipeline_id":   d.CIPipelineID,
            "scan_result_id":   d.ScanResultID,
            "sbom_id":          d.SBOMID,
            "policy_decision":  d.PolicyDecision,
            "status":           d.Status,
            "status_message":   d.StatusMessage,
            "container_id":     d.ContainerID,
            "deployed_by":      d.DeployedBy,
            "deployed_at":      d.DeployedAt,
            "created_at":       d.CreatedAt,
        })
    }

    c.JSON(200, gin.H{"deployments": deployments})
}

// ==================== Create Deployment ====================

func (h *Handler) createDeployment(c *gin.Context) {
    orgID := c.GetString("org_id")
    userID := c.GetString("user_id")
    agentID := c.Param("id")

    var req CreateDeploymentRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    var deploymentID uuid.UUID
    err := h.db.QueryRow(c, `
        INSERT INTO deployments (org_id, agent_id, service_name, environment,
            image_repository, image_tag, image_digest,
            git_repo, git_branch, git_commit,
            ci_provider, ci_pipeline_id, deployed_by, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending')
        RETURNING id
    `, orgID, agentID, req.ServiceName, req.Environment,
        req.ImageRepository, nullString(req.ImageTag), nullString(req.ImageDigest),
        nullString(req.GitRepo), nullString(req.GitBranch), nullString(req.GitCommit),
        nullString(req.CIProvider), nullString(req.CIPipelineID), userID,
    ).Scan(&deploymentID)

    if err != nil {
        h.logger.Error("Failed to create deployment", zap.Error(err))
        c.JSON(500, gin.H{"error": "Failed to create deployment"})
        return
    }

    // Trigger deployment pipeline asynchronously
    go h.runDeploymentPipeline(orgID, deploymentID.String())

    c.JSON(201, gin.H{
        "id":      deploymentID,
        "status":  "pending",
        "message": "Deployment created, pipeline started",
    })
}

// ==================== Rollback Deployment ====================

func (h *Handler) rollbackDeployment(c *gin.Context) {
    orgID := c.GetString("org_id")
    userID := c.GetString("user_id")
    agentID := c.Param("id")
    deploymentID := c.Param("did")

    // Get deployment to rollback
    var serviceName, environment, imageRepo string
    var prevDeploymentID *uuid.UUID
    err := h.db.QueryRow(c, `
        SELECT service_name, environment, image_repository, replaces_deployment_id
        FROM deployments WHERE id = $1 AND org_id = $2 AND agent_id = $3
    `, deploymentID, orgID, agentID).Scan(&serviceName, &environment, &imageRepo, &prevDeploymentID)

    if err != nil {
        c.JSON(404, gin.H{"error": "Deployment not found"})
        return
    }

    if prevDeploymentID == nil {
        c.JSON(400, gin.H{"error": "No previous deployment to rollback to"})
        return
    }

    // Create rollback deployment
    var newDeploymentID uuid.UUID
    err = h.db.QueryRow(c, `
        INSERT INTO deployments (org_id, agent_id, service_name, environment,
            image_repository, image_tag, image_digest, rollback_of_deployment_id,
            deployed_by, status)
        SELECT org_id, agent_id, service_name, environment,
               image_repository, image_tag, image_digest, $1,
               $2, 'pending'
        FROM deployments WHERE id = $3
        RETURNING id
    `, deploymentID, userID, prevDeploymentID).Scan(&newDeploymentID)

    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to create rollback"})
        return
    }

    // Mark current as rolled back
    h.db.Exec(c, `UPDATE deployments SET status = 'rolled_back' WHERE id = $1`, deploymentID)

    go h.runDeploymentPipeline(orgID, newDeploymentID.String())

    c.JSON(200, gin.H{
        "id":      newDeploymentID,
        "message": "Rollback initiated",
    })
}

// ==================== Deployment Pipeline ====================

func (h *Handler) runDeploymentPipeline(orgID, deploymentID string) {
    ctx := context.Background()

    // Step 1: Scan image
    h.updateDeploymentStatus(ctx, deploymentID, "scanning", "Scanning image for vulnerabilities")
    scanResult, err := h.scanDeploymentImage(ctx, deploymentID)
    if err != nil {
        h.updateDeploymentStatus(ctx, deploymentID, "failed", "Scan failed: "+err.Error())
        return
    }

    // Step 2: Generate SBOM
    sbomID, _ := h.generateDeploymentSBOM(ctx, deploymentID)

    // Step 3: Evaluate policies
    h.updateDeploymentStatus(ctx, deploymentID, "policy_check", "Evaluating security policies")
    decision, reason := h.evaluateDeploymentPolicies(ctx, deploymentID, scanResult)

    h.db.Exec(ctx, `
        UPDATE deployments SET scan_result_id = $1, sbom_id = $2,
            policy_decision = $3, policy_reason = $4
        WHERE id = $5
    `, scanResult.ID, sbomID, decision, reason, deploymentID)

    if decision == "deny" {
        h.updateDeploymentStatus(ctx, deploymentID, "failed", "Blocked by policy: "+reason)
        return
    }

    // Step 4: Deploy container
    h.updateDeploymentStatus(ctx, deploymentID, "deploying", "Starting container")
    containerID, err := h.deployContainer(ctx, deploymentID)
    if err != nil {
        h.updateDeploymentStatus(ctx, deploymentID, "failed", "Deploy failed: "+err.Error())
        return
    }

    // Step 5: Mark as running
    h.db.Exec(ctx, `
        UPDATE deployments SET container_id = $1, status = 'running',
            deployed_at = NOW() WHERE id = $2
    `, containerID, deploymentID)
}

func (h *Handler) updateDeploymentStatus(ctx context.Context, id, status, message string) {
    h.db.Exec(ctx, `
        UPDATE deployments SET status = $1, status_message = $2, updated_at = NOW()
        WHERE id = $3
    `, status, message, id)
}
```

### 1.3 Routes for Deployments

Add to `backend/internal/api/handler.go` in `RegisterRoutes()`:

```go
// Deployments (Epic 0)
agents.GET("/:id/deployments", h.listDeployments)
agents.POST("/:id/deployments", h.RequireModifyContainers(), h.createDeployment)
agents.GET("/:id/deployments/:did", h.getDeployment)
agents.POST("/:id/deployments/:did/rollback", h.RequireModifyContainers(), h.rollbackDeployment)

// Services view
protected.GET("/services", h.listServices)
protected.GET("/services/:name/deployments", h.listServiceDeployments)
protected.GET("/services/:name/current", h.getCurrentDeployment)
```

---

## Phase 2: Supply Chain Security

**Epic 1: Supply Chain Security**

**Objective**: No image runs unless scanned, attested, and policy-approved

### 2.1 Database Migration: `011_supply_chain.up.sql`

```sql
-- Severity level enum
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'unknown');

-- Scan results table
CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Image
    image_digest VARCHAR(255) NOT NULL,
    image_repository VARCHAR(255) NOT NULL,
    image_tag VARCHAR(255),

    -- Summary counts
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    unknown_count INTEGER NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,
    fixable_count INTEGER NOT NULL DEFAULT 0,

    -- Scanner info
    scanner_name VARCHAR(50) NOT NULL DEFAULT 'trivy',
    scanner_version VARCHAR(50),
    scan_duration_ms INTEGER,

    -- Raw output
    raw_output JSONB,

    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Individual vulnerabilities
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,

    -- CVE info
    cve_id VARCHAR(50) NOT NULL,
    severity severity_level NOT NULL,

    -- Package info
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100),
    package_type VARCHAR(50),

    -- Fix info
    fixed_version VARCHAR(100),
    fix_available BOOLEAN NOT NULL DEFAULT FALSE,

    -- Details
    title VARCHAR(500),
    description TEXT,
    references JSONB,

    -- CVSS
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(100),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- SBOM table
CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Image
    image_digest VARCHAR(255) NOT NULL,
    image_repository VARCHAR(255) NOT NULL,

    -- SBOM format
    format VARCHAR(20) NOT NULL CHECK (format IN ('cyclonedx', 'spdx')),
    spec_version VARCHAR(20) NOT NULL,

    -- Package counts
    total_packages INTEGER NOT NULL DEFAULT 0,
    os_packages INTEGER NOT NULL DEFAULT 0,
    library_packages INTEGER NOT NULL DEFAULT 0,

    -- Raw SBOM
    sbom_json JSONB NOT NULL,

    -- Generator
    generator_name VARCHAR(50) NOT NULL DEFAULT 'syft',
    generator_version VARCHAR(50),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add foreign keys to deployments
ALTER TABLE deployments
    ADD CONSTRAINT fk_deployments_scan FOREIGN KEY (scan_result_id) REFERENCES scan_results(id),
    ADD CONSTRAINT fk_deployments_sbom FOREIGN KEY (sbom_id) REFERENCES sboms(id);

-- Indexes
CREATE INDEX idx_scan_results_org ON scan_results(org_id);
CREATE INDEX idx_scan_results_image ON scan_results(image_digest);
CREATE INDEX idx_scan_results_created ON scan_results(created_at DESC);
CREATE INDEX idx_vulnerabilities_scan ON vulnerabilities(scan_result_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_sboms_org ON sboms(org_id);
CREATE INDEX idx_sboms_image ON sboms(image_digest);
```

### 2.2 Scanner Service: `backend/internal/scanner/service.go`

```go
package scanner

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "time"

    "go.uber.org/zap"
)

type ScanResult struct {
    ID              string          `json:"id"`
    ImageDigest     string          `json:"image_digest"`
    ImageRepository string          `json:"image_repository"`
    CriticalCount   int             `json:"critical_count"`
    HighCount       int             `json:"high_count"`
    MediumCount     int             `json:"medium_count"`
    LowCount        int             `json:"low_count"`
    TotalCount      int             `json:"total_count"`
    FixableCount    int             `json:"fixable_count"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
    ScanDuration    time.Duration   `json:"scan_duration"`
    RawOutput       json.RawMessage `json:"raw_output"`
}

type Vulnerability struct {
    CVEID          string  `json:"cve_id"`
    Severity       string  `json:"severity"`
    PackageName    string  `json:"package_name"`
    PackageVersion string  `json:"package_version"`
    PackageType    string  `json:"package_type"`
    FixedVersion   string  `json:"fixed_version,omitempty"`
    FixAvailable   bool    `json:"fix_available"`
    Title          string  `json:"title"`
    Description    string  `json:"description"`
    CVSSScore      float64 `json:"cvss_score,omitempty"`
}

type Scanner struct {
    trivyPath string
    syftPath  string
    logger    *zap.Logger
}

func NewScanner(logger *zap.Logger) *Scanner {
    return &Scanner{
        trivyPath: "trivy",
        syftPath:  "syft",
        logger:    logger,
    }
}

func (s *Scanner) ScanImage(ctx context.Context, imageRef string) (*ScanResult, error) {
    start := time.Now()

    // Run Trivy
    cmd := exec.CommandContext(ctx, s.trivyPath,
        "image",
        "--format", "json",
        "--quiet",
        "--timeout", "10m",
        imageRef,
    )

    output, err := cmd.Output()
    if err != nil {
        s.logger.Error("Trivy scan failed", zap.Error(err), zap.String("image", imageRef))
        return nil, fmt.Errorf("scan failed: %w", err)
    }

    // Parse Trivy output
    var trivyResult TrivyOutput
    if err := json.Unmarshal(output, &trivyResult); err != nil {
        return nil, fmt.Errorf("parse failed: %w", err)
    }

    result := s.convertTrivyResult(trivyResult, imageRef)
    result.ScanDuration = time.Since(start)
    result.RawOutput = output

    return result, nil
}

type TrivyOutput struct {
    Results []TrivyTarget `json:"Results"`
}

type TrivyTarget struct {
    Target          string            `json:"Target"`
    Vulnerabilities []TrivyVuln       `json:"Vulnerabilities"`
}

type TrivyVuln struct {
    VulnerabilityID  string  `json:"VulnerabilityID"`
    PkgName          string  `json:"PkgName"`
    InstalledVersion string  `json:"InstalledVersion"`
    FixedVersion     string  `json:"FixedVersion"`
    Severity         string  `json:"Severity"`
    Title            string  `json:"Title"`
    Description      string  `json:"Description"`
    CVSS             map[string]struct {
        V3Score float64 `json:"V3Score"`
    } `json:"CVSS"`
}

func (s *Scanner) convertTrivyResult(trivy TrivyOutput, imageRef string) *ScanResult {
    result := &ScanResult{
        ImageRepository: imageRef,
    }

    for _, target := range trivy.Results {
        for _, vuln := range target.Vulnerabilities {
            v := Vulnerability{
                CVEID:          vuln.VulnerabilityID,
                Severity:       vuln.Severity,
                PackageName:    vuln.PkgName,
                PackageVersion: vuln.InstalledVersion,
                FixedVersion:   vuln.FixedVersion,
                FixAvailable:   vuln.FixedVersion != "",
                Title:          vuln.Title,
                Description:    vuln.Description,
            }

            // Get CVSS score
            if nvd, ok := vuln.CVSS["nvd"]; ok {
                v.CVSSScore = nvd.V3Score
            }

            result.Vulnerabilities = append(result.Vulnerabilities, v)
            result.TotalCount++

            switch vuln.Severity {
            case "CRITICAL":
                result.CriticalCount++
            case "HIGH":
                result.HighCount++
            case "MEDIUM":
                result.MediumCount++
            case "LOW":
                result.LowCount++
            }

            if v.FixAvailable {
                result.FixableCount++
            }
        }
    }

    return result
}

// GenerateSBOM creates a CycloneDX SBOM for an image
func (s *Scanner) GenerateSBOM(ctx context.Context, imageRef string) (*SBOM, error) {
    cmd := exec.CommandContext(ctx, s.syftPath,
        imageRef,
        "-o", "cyclonedx-json",
        "--quiet",
    )

    output, err := cmd.Output()
    if err != nil {
        return nil, fmt.Errorf("SBOM generation failed: %w", err)
    }

    var sbom SBOM
    if err := json.Unmarshal(output, &sbom.Raw); err != nil {
        return nil, err
    }

    sbom.Format = "cyclonedx"
    sbom.ImageRepository = imageRef
    s.countPackages(&sbom)

    return &sbom, nil
}

type SBOM struct {
    Format          string          `json:"format"`
    SpecVersion     string          `json:"spec_version"`
    ImageRepository string          `json:"image_repository"`
    ImageDigest     string          `json:"image_digest"`
    TotalPackages   int             `json:"total_packages"`
    OSPackages      int             `json:"os_packages"`
    LibraryPackages int             `json:"library_packages"`
    Raw             json.RawMessage `json:"raw"`
}

func (s *Scanner) countPackages(sbom *SBOM) {
    var data struct {
        Components []struct {
            Type string `json:"type"`
        } `json:"components"`
    }
    json.Unmarshal(sbom.Raw, &data)

    sbom.TotalPackages = len(data.Components)
    for _, c := range data.Components {
        if c.Type == "operating-system" {
            sbom.OSPackages++
        } else {
            sbom.LibraryPackages++
        }
    }
}
```

### 2.3 Scan Handlers: `backend/internal/api/scan_handlers.go`

```go
package api

import (
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "go.uber.org/zap"
)

type ScanRequest struct {
    Image       string `json:"image" binding:"required"`
    ImageDigest string `json:"image_digest"`
}

func (h *Handler) triggerScan(c *gin.Context) {
    orgID := c.GetString("org_id")

    var req ScanRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Scan image
    result, err := h.scanner.ScanImage(c, req.Image)
    if err != nil {
        c.JSON(500, gin.H{"error": "Scan failed: " + err.Error()})
        return
    }

    // Store result
    var scanID uuid.UUID
    err = h.db.QueryRow(c, `
        INSERT INTO scan_results (org_id, image_digest, image_repository, image_tag,
            critical_count, high_count, medium_count, low_count, total_count, fixable_count,
            scan_duration_ms, raw_output)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        RETURNING id
    `, orgID, req.ImageDigest, req.Image, "",
        result.CriticalCount, result.HighCount, result.MediumCount, result.LowCount,
        result.TotalCount, result.FixableCount,
        result.ScanDuration.Milliseconds(), result.RawOutput,
    ).Scan(&scanID)

    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to store scan"})
        return
    }

    // Store vulnerabilities
    for _, v := range result.Vulnerabilities {
        h.db.Exec(c, `
            INSERT INTO vulnerabilities (scan_result_id, cve_id, severity,
                package_name, package_version, fixed_version, fix_available,
                title, description, cvss_v3_score)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `, scanID, v.CVEID, v.Severity, v.PackageName, v.PackageVersion,
            v.FixedVersion, v.FixAvailable, v.Title, v.Description, v.CVSSScore)
    }

    c.JSON(200, gin.H{
        "id":       scanID,
        "critical": result.CriticalCount,
        "high":     result.HighCount,
        "medium":   result.MediumCount,
        "low":      result.LowCount,
        "total":    result.TotalCount,
        "fixable":  result.FixableCount,
    })
}

func (h *Handler) listScans(c *gin.Context) {
    orgID := c.GetString("org_id")

    rows, err := h.db.Query(c, `
        SELECT id, image_repository, image_tag, image_digest,
               critical_count, high_count, medium_count, low_count,
               total_count, fixable_count, scanned_at
        FROM scan_results
        WHERE org_id = $1
        ORDER BY scanned_at DESC
        LIMIT 100
    `, orgID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to list scans"})
        return
    }
    defer rows.Close()

    var scans []gin.H
    for rows.Next() {
        var s struct {
            ID              uuid.UUID
            ImageRepository string
            ImageTag        *string
            ImageDigest     *string
            Critical        int
            High            int
            Medium          int
            Low             int
            Total           int
            Fixable         int
            ScannedAt       time.Time
        }
        rows.Scan(&s.ID, &s.ImageRepository, &s.ImageTag, &s.ImageDigest,
            &s.Critical, &s.High, &s.Medium, &s.Low, &s.Total, &s.Fixable, &s.ScannedAt)
        scans = append(scans, gin.H{
            "id":         s.ID,
            "image":      s.ImageRepository,
            "tag":        s.ImageTag,
            "digest":     s.ImageDigest,
            "critical":   s.Critical,
            "high":       s.High,
            "medium":     s.Medium,
            "low":        s.Low,
            "total":      s.Total,
            "fixable":    s.Fixable,
            "scanned_at": s.ScannedAt,
        })
    }

    c.JSON(200, gin.H{"scans": scans})
}

func (h *Handler) getScanVulnerabilities(c *gin.Context) {
    scanID := c.Param("sid")
    severity := c.Query("severity")

    query := `
        SELECT id, cve_id, severity, package_name, package_version,
               fixed_version, fix_available, title, cvss_v3_score
        FROM vulnerabilities
        WHERE scan_result_id = $1
    `
    args := []interface{}{scanID}

    if severity != "" {
        query += " AND severity = $2"
        args = append(args, severity)
    }
    query += " ORDER BY cvss_v3_score DESC NULLS LAST"

    rows, err := h.db.Query(c, query, args...)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to list vulnerabilities"})
        return
    }
    defer rows.Close()

    var vulns []gin.H
    for rows.Next() {
        var v struct {
            ID             uuid.UUID
            CVEID          string
            Severity       string
            PackageName    string
            PackageVersion *string
            FixedVersion   *string
            FixAvailable   bool
            Title          *string
            CVSSScore      *float64
        }
        rows.Scan(&v.ID, &v.CVEID, &v.Severity, &v.PackageName,
            &v.PackageVersion, &v.FixedVersion, &v.FixAvailable, &v.Title, &v.CVSSScore)
        vulns = append(vulns, gin.H{
            "id":              v.ID,
            "cve_id":          v.CVEID,
            "severity":        v.Severity,
            "package_name":    v.PackageName,
            "package_version": v.PackageVersion,
            "fixed_version":   v.FixedVersion,
            "fix_available":   v.FixAvailable,
            "title":           v.Title,
            "cvss_score":      v.CVSSScore,
        })
    }

    c.JSON(200, gin.H{"vulnerabilities": vulns})
}
```

---

## Phase 3: Policy Engine

**Epic 2: Policy-as-Code**

**Objective**: Security decisions are automatic, versioned, and auditable

### 3.1 Database Migration: `012_policies.up.sql`

```sql
-- Policies table
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Policy identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Rego code
    rego_code TEXT NOT NULL,

    -- Scope
    environments TEXT[] NOT NULL DEFAULT '{}',
    services TEXT[] NOT NULL DEFAULT '{}',

    -- Enforcement
    enforcement VARCHAR(20) NOT NULL DEFAULT 'enforce'
        CHECK (enforcement IN ('enforce', 'warn', 'disabled')),

    -- Versioning
    version INTEGER NOT NULL DEFAULT 1,

    -- Audit
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(org_id, name)
);

-- Policy decisions log
CREATE TABLE policy_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,

    -- Decision
    decision policy_decision NOT NULL,
    reason TEXT,

    -- Input/Output
    input_data JSONB,
    output_data JSONB,

    -- Timing
    evaluation_time_ms INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_policies_org ON policies(org_id);
CREATE INDEX idx_policies_name ON policies(org_id, name);
CREATE INDEX idx_policy_decisions_deployment ON policy_decisions(deployment_id);
CREATE INDEX idx_policy_decisions_policy ON policy_decisions(policy_id);
```

### 3.2 Default Policies

Create `backend/internal/policy/defaults/` directory with these Rego files:

**`no_latest_tag.rego`**:
```rego
package infrapilot.security

deny[msg] {
    input.image.tag == "latest"
    input.environment == "prod"
    msg := "Using 'latest' tag is forbidden in production"
}

deny[msg] {
    input.image.tag == ""
    msg := "Image tag is required"
}
```

**`no_critical_vulns.rego`**:
```rego
package infrapilot.security

deny[msg] {
    input.environment == "prod"
    input.scan.critical > 0
    msg := sprintf("Critical vulnerabilities detected: %d", [input.scan.critical])
}

warn[msg] {
    input.environment == "staging"
    input.scan.critical > 0
    msg := sprintf("Critical vulnerabilities in staging: %d", [input.scan.critical])
}
```

**`require_digest.rego`**:
```rego
package infrapilot.security

deny[msg] {
    input.environment == "prod"
    input.image.digest == ""
    msg := "Image digest required for production"
}
```

**`no_privileged.rego`**:
```rego
package infrapilot.security

deny[msg] {
    input.container.privileged == true
    msg := "Privileged containers are not allowed"
}

deny[msg] {
    some port in input.container.ports
    port.private_port == 2375
    msg := "Docker API port exposure is forbidden"
}
```

### 3.3 Policy Engine: `backend/internal/policy/engine.go`

```go
package policy

import (
    "context"
    "embed"
    "fmt"
    "strings"
    "time"

    "github.com/open-policy-agent/opa/rego"
    "go.uber.org/zap"
)

//go:embed defaults/*.rego
var defaultPolicies embed.FS

type PolicyDecision string

const (
    DecisionAllow PolicyDecision = "allow"
    DecisionWarn  PolicyDecision = "warn"
    DecisionDeny  PolicyDecision = "deny"
)

type PolicyInput struct {
    Environment string     `json:"environment"`
    Service     string     `json:"service"`
    Image       ImageInfo  `json:"image"`
    Scan        ScanInfo   `json:"scan"`
    Container   ContainerInfo `json:"container,omitempty"`
}

type ImageInfo struct {
    Repository string `json:"repository"`
    Tag        string `json:"tag"`
    Digest     string `json:"digest"`
}

type ScanInfo struct {
    Critical int `json:"critical"`
    High     int `json:"high"`
    Medium   int `json:"medium"`
    Low      int `json:"low"`
    Total    int `json:"total"`
}

type ContainerInfo struct {
    Privileged bool        `json:"privileged"`
    User       string      `json:"user"`
    Ports      []PortInfo  `json:"ports"`
}

type PortInfo struct {
    PrivatePort int `json:"private_port"`
    PublicPort  int `json:"public_port"`
}

type PolicyResult struct {
    Decision       PolicyDecision `json:"decision"`
    Denies         []string       `json:"denies,omitempty"`
    Warnings       []string       `json:"warnings,omitempty"`
    EvaluationTime time.Duration  `json:"evaluation_time"`
}

type Engine struct {
    query  *rego.PreparedEvalQuery
    logger *zap.Logger
}

func NewEngine(logger *zap.Logger, customPolicies []string) (*Engine, error) {
    // Load default policies
    policies := []func(*rego.Rego){}

    entries, _ := defaultPolicies.ReadDir("defaults")
    for _, entry := range entries {
        if strings.HasSuffix(entry.Name(), ".rego") {
            content, _ := defaultPolicies.ReadFile("defaults/" + entry.Name())
            policies = append(policies, rego.Module(entry.Name(), string(content)))
        }
    }

    // Add custom policies
    for i, p := range customPolicies {
        policies = append(policies, rego.Module(fmt.Sprintf("custom_%d.rego", i), p))
    }

    // Prepare query
    opts := append(policies,
        rego.Query("data.infrapilot.security"),
    )

    query, err := rego.New(opts...).PrepareForEval(context.Background())
    if err != nil {
        return nil, fmt.Errorf("failed to prepare policy engine: %w", err)
    }

    return &Engine{query: query, logger: logger}, nil
}

func (e *Engine) Evaluate(ctx context.Context, input PolicyInput) (*PolicyResult, error) {
    start := time.Now()

    results, err := e.query.Eval(ctx, rego.EvalInput(input))
    if err != nil {
        return nil, fmt.Errorf("policy evaluation failed: %w", err)
    }

    result := &PolicyResult{
        Decision:       DecisionAllow,
        EvaluationTime: time.Since(start),
    }

    if len(results) == 0 {
        return result, nil
    }

    // Extract denies
    if denies, ok := results[0].Expressions[0].Value.(map[string]interface{})["deny"]; ok {
        if denyList, ok := denies.([]interface{}); ok {
            for _, d := range denyList {
                result.Denies = append(result.Denies, fmt.Sprint(d))
            }
        }
    }

    // Extract warnings
    if warns, ok := results[0].Expressions[0].Value.(map[string]interface{})["warn"]; ok {
        if warnList, ok := warns.([]interface{}); ok {
            for _, w := range warnList {
                result.Warnings = append(result.Warnings, fmt.Sprint(w))
            }
        }
    }

    // Determine decision
    if len(result.Denies) > 0 {
        result.Decision = DecisionDeny
    } else if len(result.Warnings) > 0 {
        result.Decision = DecisionWarn
    }

    return result, nil
}
```

### 3.4 Policy Handlers: `backend/internal/api/policy_handlers.go`

```go
package api

import (
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

type CreatePolicyRequest struct {
    Name         string   `json:"name" binding:"required"`
    Description  string   `json:"description"`
    RegoCode     string   `json:"rego_code" binding:"required"`
    Environments []string `json:"environments"`
    Services     []string `json:"services"`
    Enforcement  string   `json:"enforcement" binding:"oneof=enforce warn disabled"`
}

func (h *Handler) listPolicies(c *gin.Context) {
    orgID := c.GetString("org_id")

    rows, err := h.db.Query(c, `
        SELECT id, name, description, enforcement, environments, services,
               version, created_at, updated_at
        FROM policies
        WHERE org_id = $1
        ORDER BY name
    `, orgID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to list policies"})
        return
    }
    defer rows.Close()

    var policies []gin.H
    for rows.Next() {
        var p struct {
            ID           uuid.UUID
            Name         string
            Description  *string
            Enforcement  string
            Environments []string
            Services     []string
            Version      int
            CreatedAt    time.Time
            UpdatedAt    time.Time
        }
        rows.Scan(&p.ID, &p.Name, &p.Description, &p.Enforcement,
            &p.Environments, &p.Services, &p.Version, &p.CreatedAt, &p.UpdatedAt)
        policies = append(policies, gin.H{
            "id":           p.ID,
            "name":         p.Name,
            "description":  p.Description,
            "enforcement":  p.Enforcement,
            "environments": p.Environments,
            "services":     p.Services,
            "version":      p.Version,
            "created_at":   p.CreatedAt,
            "updated_at":   p.UpdatedAt,
        })
    }

    c.JSON(200, gin.H{"policies": policies})
}

func (h *Handler) createPolicy(c *gin.Context) {
    orgID := c.GetString("org_id")
    userID := c.GetString("user_id")

    var req CreatePolicyRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    if req.Enforcement == "" {
        req.Enforcement = "enforce"
    }

    var policyID uuid.UUID
    err := h.db.QueryRow(c, `
        INSERT INTO policies (org_id, name, description, rego_code,
            environments, services, enforcement, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
    `, orgID, req.Name, req.Description, req.RegoCode,
        req.Environments, req.Services, req.Enforcement, userID,
    ).Scan(&policyID)

    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to create policy"})
        return
    }

    // Reload policy engine
    h.reloadPolicyEngine(c)

    c.JSON(201, gin.H{"id": policyID, "message": "Policy created"})
}

func (h *Handler) testPolicy(c *gin.Context) {
    var req struct {
        RegoCode string                 `json:"rego_code" binding:"required"`
        Input    map[string]interface{} `json:"input" binding:"required"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    // Create temporary engine with this policy
    engine, err := policy.NewEngine(h.logger, []string{req.RegoCode})
    if err != nil {
        c.JSON(400, gin.H{"error": "Invalid policy: " + err.Error()})
        return
    }

    // Evaluate
    result, err := engine.Evaluate(c, req.Input)
    if err != nil {
        c.JSON(500, gin.H{"error": "Evaluation failed: " + err.Error()})
        return
    }

    c.JSON(200, gin.H{
        "decision":        result.Decision,
        "denies":          result.Denies,
        "warnings":        result.Warnings,
        "evaluation_time": result.EvaluationTime.String(),
    })
}
```

---

## Phase 4: CI/CD Integration

**Epic 4: Dev Integration**

**Objective**: Close the Dev → Sec → Ops loop

### 4.1 Database Migration: `013_ci_integration.up.sql`

```sql
-- CI Webhooks configuration
CREATE TABLE ci_webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Webhook identity
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL CHECK (provider IN ('github', 'gitlab', 'bitbucket', 'generic')),

    -- Security
    secret_token VARCHAR(255) NOT NULL,

    -- Filtering
    repositories TEXT[] DEFAULT '{}',
    branches TEXT[] DEFAULT '{}',
    events TEXT[] DEFAULT '{}',

    -- Settings
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    auto_deploy BOOLEAN NOT NULL DEFAULT FALSE,
    target_agent_id UUID REFERENCES agents(id),
    target_environment VARCHAR(50) DEFAULT 'staging',

    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- CI Events
CREATE TABLE ci_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    webhook_id UUID REFERENCES ci_webhooks(id) ON DELETE SET NULL,

    -- Provider info
    provider VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    delivery_id VARCHAR(255),

    -- Repository
    repo_owner VARCHAR(255) NOT NULL,
    repo_name VARCHAR(255) NOT NULL,
    repo_full_name VARCHAR(500) NOT NULL,
    repo_url VARCHAR(500),

    -- Commit/Branch
    git_ref VARCHAR(255),
    branch VARCHAR(255),
    commit_sha VARCHAR(64),
    commit_message TEXT,
    commit_author VARCHAR(255),

    -- Pipeline
    pipeline_id VARCHAR(255),
    pipeline_name VARCHAR(255),
    pipeline_status VARCHAR(50),
    pipeline_url VARCHAR(500),

    -- Artifacts
    image_repository VARCHAR(255),
    image_tag VARCHAR(255),
    image_digest VARCHAR(255),

    -- Raw
    raw_payload JSONB,
    headers JSONB,

    -- Processing
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    processed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_ci_webhooks_org ON ci_webhooks(org_id);
CREATE INDEX idx_ci_events_org ON ci_events(org_id);
CREATE INDEX idx_ci_events_repo ON ci_events(repo_full_name);
CREATE INDEX idx_ci_events_commit ON ci_events(commit_sha);
CREATE INDEX idx_ci_events_created ON ci_events(created_at DESC);
```

### 4.2 CI Handlers: `backend/internal/api/ci_handlers.go`

```go
package api

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

// ==================== Webhook Configuration ====================

func (h *Handler) listWebhooks(c *gin.Context) {
    orgID := c.GetString("org_id")

    rows, err := h.db.Query(c, `
        SELECT id, name, provider, repositories, branches, events,
               enabled, auto_deploy, target_agent_id, target_environment,
               created_at
        FROM ci_webhooks
        WHERE org_id = $1
        ORDER BY created_at DESC
    `, orgID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to list webhooks"})
        return
    }
    defer rows.Close()

    var webhooks []gin.H
    for rows.Next() {
        var w struct {
            ID                uuid.UUID
            Name              string
            Provider          string
            Repositories      []string
            Branches          []string
            Events            []string
            Enabled           bool
            AutoDeploy        bool
            TargetAgentID     *uuid.UUID
            TargetEnvironment *string
            CreatedAt         time.Time
        }
        rows.Scan(&w.ID, &w.Name, &w.Provider, &w.Repositories,
            &w.Branches, &w.Events, &w.Enabled, &w.AutoDeploy,
            &w.TargetAgentID, &w.TargetEnvironment, &w.CreatedAt)
        webhooks = append(webhooks, gin.H{
            "id":                 w.ID,
            "name":               w.Name,
            "provider":           w.Provider,
            "repositories":       w.Repositories,
            "branches":           w.Branches,
            "events":             w.Events,
            "enabled":            w.Enabled,
            "auto_deploy":        w.AutoDeploy,
            "target_agent_id":    w.TargetAgentID,
            "target_environment": w.TargetEnvironment,
            "created_at":         w.CreatedAt,
        })
    }

    c.JSON(200, gin.H{"webhooks": webhooks})
}

func (h *Handler) createWebhook(c *gin.Context) {
    orgID := c.GetString("org_id")
    userID := c.GetString("user_id")

    var req struct {
        Name              string   `json:"name" binding:"required"`
        Provider          string   `json:"provider" binding:"required,oneof=github gitlab bitbucket generic"`
        Repositories      []string `json:"repositories"`
        Branches          []string `json:"branches"`
        Events            []string `json:"events"`
        AutoDeploy        bool     `json:"auto_deploy"`
        TargetAgentID     string   `json:"target_agent_id"`
        TargetEnvironment string   `json:"target_environment"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    secret := uuid.New().String()

    var webhookID uuid.UUID
    err := h.db.QueryRow(c, `
        INSERT INTO ci_webhooks (org_id, name, provider, secret_token,
            repositories, branches, events, auto_deploy,
            target_agent_id, target_environment, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
    `, orgID, req.Name, req.Provider, secret, req.Repositories,
        req.Branches, req.Events, req.AutoDeploy,
        nullUUID(req.TargetAgentID), nullString(req.TargetEnvironment), userID,
    ).Scan(&webhookID)

    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to create webhook"})
        return
    }

    webhookURL := "/api/v1/webhooks/" + req.Provider + "/" + webhookID.String()

    c.JSON(201, gin.H{
        "id":          webhookID,
        "webhook_url": webhookURL,
        "secret":      secret,
        "message":     "Configure this URL in your " + req.Provider + " settings",
    })
}

// ==================== GitHub Webhook Handler ====================

func (h *Handler) handleGitHubWebhook(c *gin.Context) {
    webhookID := c.Param("webhook_id")

    body, _ := io.ReadAll(c.Request.Body)

    // Get webhook config
    var orgID uuid.UUID
    var secret string
    var enabled, autoDeploy bool
    var targetAgentID *uuid.UUID
    var targetEnv *string

    err := h.db.QueryRow(c, `
        SELECT org_id, secret_token, enabled, auto_deploy,
               target_agent_id, target_environment
        FROM ci_webhooks WHERE id = $1
    `, webhookID).Scan(&orgID, &secret, &enabled, &autoDeploy,
        &targetAgentID, &targetEnv)

    if err != nil {
        c.JSON(404, gin.H{"error": "Webhook not found"})
        return
    }

    if !enabled {
        c.JSON(200, gin.H{"status": "webhook disabled"})
        return
    }

    // Verify signature
    signature := c.GetHeader("X-Hub-Signature-256")
    if !verifyGitHubSignature(body, signature, secret) {
        c.JSON(401, gin.H{"error": "Invalid signature"})
        return
    }

    // Parse event
    eventType := c.GetHeader("X-GitHub-Event")
    deliveryID := c.GetHeader("X-GitHub-Delivery")

    var payload map[string]interface{}
    json.Unmarshal(body, &payload)

    // Store event
    event := parseGitHubEvent(eventType, payload)
    var eventID uuid.UUID
    h.db.QueryRow(c, `
        INSERT INTO ci_events (org_id, webhook_id, provider, event_type, delivery_id,
            repo_owner, repo_name, repo_full_name, repo_url,
            git_ref, branch, commit_sha, commit_message, commit_author,
            pipeline_id, pipeline_name, pipeline_status, pipeline_url,
            image_repository, image_tag, raw_payload, headers)
        VALUES ($1, $2, 'github', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                $14, $15, $16, $17, $18, $19, $20, $21)
        RETURNING id
    `, orgID, webhookID, eventType, deliveryID,
        event.RepoOwner, event.RepoName, event.RepoFullName, event.RepoURL,
        event.GitRef, event.Branch, event.CommitSHA, event.CommitMessage, event.CommitAuthor,
        event.PipelineID, event.PipelineName, event.PipelineStatus, event.PipelineURL,
        event.ImageRepo, event.ImageTag, payload,
        map[string]string{"X-GitHub-Event": eventType, "X-GitHub-Delivery": deliveryID},
    ).Scan(&eventID)

    // Auto-deploy if configured
    if autoDeploy && eventType == "workflow_run" && event.PipelineStatus == "success" {
        go h.triggerAutoDeploy(orgID, eventID, targetAgentID, targetEnv, event)
    }

    c.JSON(200, gin.H{"status": "received", "event_id": eventID})
}

func verifyGitHubSignature(body []byte, signature, secret string) bool {
    if signature == "" || secret == "" {
        return false
    }
    signature = strings.TrimPrefix(signature, "sha256=")
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(body)
    expected := hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(signature))
}

// ==================== Deployment Gate API ====================

func (h *Handler) checkDeploymentGate(c *gin.Context) {
    orgID := c.GetString("org_id")

    var req struct {
        Image       string `json:"image" binding:"required"`
        ImageDigest string `json:"image_digest"`
        Environment string `json:"environment" binding:"required"`
        Service     string `json:"service" binding:"required"`
        CommitSHA   string `json:"commit_sha"`
        AgentID     string `json:"agent_id"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    start := time.Now()

    // Scan image first
    scanResult, _ := h.scanner.ScanImage(c, req.Image)

    // Build policy input
    input := policy.PolicyInput{
        Environment: req.Environment,
        Service:     req.Service,
        Image: policy.ImageInfo{
            Repository: req.Image,
            Tag:        parseImageTag(req.Image),
            Digest:     req.ImageDigest,
        },
    }

    if scanResult != nil {
        input.Scan = policy.ScanInfo{
            Critical: scanResult.CriticalCount,
            High:     scanResult.HighCount,
            Medium:   scanResult.MediumCount,
            Low:      scanResult.LowCount,
            Total:    scanResult.TotalCount,
        }
    }

    // Evaluate policies
    result, err := h.policyEngine.Evaluate(c, input)
    if err != nil {
        c.JSON(500, gin.H{"error": "Policy evaluation failed"})
        return
    }

    evalTime := time.Since(start).Milliseconds()

    // Create deployment record if allowed
    var deploymentID *uuid.UUID
    if result.Decision != policy.DecisionDeny && req.AgentID != "" {
        var depID uuid.UUID
        h.db.QueryRow(c, `
            INSERT INTO deployments (org_id, agent_id, service_name, environment,
                image_repository, image_tag, image_digest, git_commit,
                policy_decision, policy_reason, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')
            RETURNING id
        `, orgID, req.AgentID, req.Service, req.Environment,
            parseImageRepo(req.Image), parseImageTag(req.Image),
            req.ImageDigest, req.CommitSHA,
            result.Decision, strings.Join(result.Denies, "; "),
        ).Scan(&depID)
        deploymentID = &depID
    }

    c.JSON(200, gin.H{
        "decision":       result.Decision,
        "denies":         result.Denies,
        "warnings":       result.Warnings,
        "scan":           input.Scan,
        "evaluation_ms":  evalTime,
        "deployment_id":  deploymentID,
    })
}
```

---

## Phase 5: Runtime Security

**Epic 3: Runtime Security**

**Objective**: Detect security drift after deployment

### 5.1 Database Migration: `014_runtime_security.up.sql`

```sql
-- Drift type enum
CREATE TYPE drift_type AS ENUM (
    'image_changed',
    'port_added',
    'port_removed',
    'privilege_escalation',
    'config_modified',
    'container_restarted',
    'resource_exceeded',
    'network_changed'
);

-- Drift severity enum
CREATE TYPE drift_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

-- Drift events table
CREATE TABLE drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    deployment_id UUID REFERENCES deployments(id),
    container_id VARCHAR(64),

    -- Drift info
    drift_type drift_type NOT NULL,
    severity drift_severity NOT NULL,

    -- Details
    description TEXT NOT NULL,
    expected_state JSONB,
    actual_state JSONB,

    -- Resolution
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id),
    resolution_notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_drift_events_org ON drift_events(org_id);
CREATE INDEX idx_drift_events_agent ON drift_events(agent_id);
CREATE INDEX idx_drift_events_deployment ON drift_events(deployment_id);
CREATE INDEX idx_drift_events_type ON drift_events(drift_type);
CREATE INDEX idx_drift_events_severity ON drift_events(severity);
CREATE INDEX idx_drift_events_resolved ON drift_events(resolved);
CREATE INDEX idx_drift_events_created ON drift_events(created_at DESC);
```

### 5.2 Drift Detector: `agent/internal/drift/detector.go`

```go
package drift

import (
    "context"
    "time"

    "github.com/docker/docker/api/types"
    "github.com/docker/docker/client"
    "go.uber.org/zap"
)

type DriftType string
type Severity string

const (
    DriftImageChanged       DriftType = "image_changed"
    DriftPortAdded          DriftType = "port_added"
    DriftPrivilegeEscalation DriftType = "privilege_escalation"
    DriftConfigModified     DriftType = "config_modified"
    DriftContainerRestarted DriftType = "container_restarted"

    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

type DriftEvent struct {
    Type          DriftType              `json:"type"`
    Severity      Severity               `json:"severity"`
    ContainerID   string                 `json:"container_id"`
    DeploymentID  string                 `json:"deployment_id,omitempty"`
    Description   string                 `json:"description"`
    ExpectedState map[string]interface{} `json:"expected_state,omitempty"`
    ActualState   map[string]interface{} `json:"actual_state,omitempty"`
}

type Detector struct {
    docker     *client.Client
    logger     *zap.Logger
    interval   time.Duration
    eventsChan chan<- DriftEvent
    expected   map[string]ContainerState
}

type ContainerState struct {
    ImageDigest  string
    Ports        []string
    Privileged   bool
    RestartCount int
}

func NewDetector(docker *client.Client, logger *zap.Logger, eventsChan chan<- DriftEvent) *Detector {
    return &Detector{
        docker:     docker,
        logger:     logger,
        interval:   30 * time.Second,
        eventsChan: eventsChan,
        expected:   make(map[string]ContainerState),
    }
}

func (d *Detector) Start(ctx context.Context) {
    ticker := time.NewTicker(d.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            d.checkForDrift(ctx)
        }
    }
}

func (d *Detector) checkForDrift(ctx context.Context) {
    containers, err := d.docker.ContainerList(ctx, types.ContainerListOptions{})
    if err != nil {
        d.logger.Error("Failed to list containers", zap.Error(err))
        return
    }

    for _, container := range containers {
        d.checkImageDrift(ctx, container)
        d.checkPrivilegeDrift(ctx, container)
        d.checkRestartDrift(ctx, container)
    }
}

func (d *Detector) checkImageDrift(ctx context.Context, container types.Container) {
    expected, exists := d.expected[container.ID]
    if !exists {
        return
    }

    inspect, err := d.docker.ContainerInspect(ctx, container.ID)
    if err != nil {
        return
    }

    actualDigest := inspect.Image
    if expected.ImageDigest != "" && expected.ImageDigest != actualDigest {
        d.eventsChan <- DriftEvent{
            Type:        DriftImageChanged,
            Severity:    SeverityCritical,
            ContainerID: container.ID,
            Description: "Container image changed without deployment",
            ExpectedState: map[string]interface{}{
                "image_digest": expected.ImageDigest,
            },
            ActualState: map[string]interface{}{
                "image_digest": actualDigest,
            },
        }
    }
}

func (d *Detector) checkPrivilegeDrift(ctx context.Context, container types.Container) {
    expected, exists := d.expected[container.ID]
    if !exists {
        return
    }

    inspect, err := d.docker.ContainerInspect(ctx, container.ID)
    if err != nil {
        return
    }

    if inspect.HostConfig.Privileged && !expected.Privileged {
        d.eventsChan <- DriftEvent{
            Type:        DriftPrivilegeEscalation,
            Severity:    SeverityCritical,
            ContainerID: container.ID,
            Description: "Container gained privileged mode",
            ExpectedState: map[string]interface{}{
                "privileged": false,
            },
            ActualState: map[string]interface{}{
                "privileged": true,
            },
        }
    }
}

func (d *Detector) checkRestartDrift(ctx context.Context, container types.Container) {
    expected, exists := d.expected[container.ID]
    if !exists {
        return
    }

    inspect, err := d.docker.ContainerInspect(ctx, container.ID)
    if err != nil {
        return
    }

    if inspect.RestartCount > expected.RestartCount+3 {
        d.eventsChan <- DriftEvent{
            Type:        DriftContainerRestarted,
            Severity:    SeverityMedium,
            ContainerID: container.ID,
            Description: "Container crash loop detected",
            ExpectedState: map[string]interface{}{
                "restart_count": expected.RestartCount,
            },
            ActualState: map[string]interface{}{
                "restart_count": inspect.RestartCount,
            },
        }
    }
}

func (d *Detector) RegisterDeployment(containerID, deploymentID, imageDigest string, privileged bool) {
    d.expected[containerID] = ContainerState{
        ImageDigest:  imageDigest,
        Privileged:   privileged,
        RestartCount: 0,
    }
}
```

---

## Phase 6: Load Balancing

**Additional Feature: Load Balancing**

**Objective**: Support multiple upstream targets with health checks

### 6.1 Database Migration: `015_load_balancing.up.sql`

```sql
-- Upstream pools
CREATE TABLE upstream_pools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Pool identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Load balancing method
    lb_method VARCHAR(50) NOT NULL DEFAULT 'round_robin'
        CHECK (lb_method IN ('round_robin', 'least_conn', 'ip_hash', 'random', 'weighted')),

    -- Health check settings
    health_check_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    health_check_interval INTEGER NOT NULL DEFAULT 30,
    health_check_timeout INTEGER NOT NULL DEFAULT 5,
    health_check_path VARCHAR(255) DEFAULT '/',
    health_check_expected_status INTEGER DEFAULT 200,

    -- Sticky sessions
    sticky_sessions BOOLEAN NOT NULL DEFAULT FALSE,
    sticky_cookie_name VARCHAR(100) DEFAULT 'SERVERID',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(agent_id, name)
);

-- Upstream targets
CREATE TABLE upstream_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_id UUID NOT NULL REFERENCES upstream_pools(id) ON DELETE CASCADE,

    -- Target address
    target_type VARCHAR(20) NOT NULL DEFAULT 'host'
        CHECK (target_type IN ('host', 'container', 'service')),
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,

    -- Container reference
    container_id VARCHAR(64),
    container_name VARCHAR(255),

    -- Weight and priority
    weight INTEGER NOT NULL DEFAULT 1 CHECK (weight >= 1 AND weight <= 100),
    priority INTEGER NOT NULL DEFAULT 1,

    -- State
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_backup BOOLEAN NOT NULL DEFAULT FALSE,
    is_down BOOLEAN NOT NULL DEFAULT FALSE,

    -- Health status
    health_status VARCHAR(20) NOT NULL DEFAULT 'unknown'
        CHECK (health_status IN ('healthy', 'unhealthy', 'unknown')),
    last_health_check TIMESTAMP WITH TIME ZONE,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Link proxy hosts to pools
ALTER TABLE proxy_hosts
    ADD COLUMN IF NOT EXISTS upstream_pool_id UUID REFERENCES upstream_pools(id),
    ADD COLUMN IF NOT EXISTS upstream_mode VARCHAR(20) DEFAULT 'single'
        CHECK (upstream_mode IN ('single', 'pool'));

-- Indexes
CREATE INDEX idx_upstream_pools_org ON upstream_pools(org_id);
CREATE INDEX idx_upstream_pools_agent ON upstream_pools(agent_id);
CREATE INDEX idx_upstream_targets_pool ON upstream_targets(pool_id);
CREATE INDEX idx_upstream_targets_health ON upstream_targets(health_status);
```

### 6.2 Load Balancing Handlers: `backend/internal/api/loadbalancing_handlers.go`

```go
package api

import (
    "fmt"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

func (h *Handler) listUpstreamPools(c *gin.Context) {
    orgID := c.GetString("org_id")
    agentID := c.Param("id")

    rows, err := h.db.Query(c, `
        SELECT p.id, p.name, p.description, p.lb_method,
               p.health_check_enabled, p.sticky_sessions,
               COUNT(t.id) as target_count,
               COUNT(t.id) FILTER (WHERE t.health_status = 'healthy') as healthy_count
        FROM upstream_pools p
        LEFT JOIN upstream_targets t ON t.pool_id = p.id
        WHERE p.org_id = $1 AND p.agent_id = $2
        GROUP BY p.id
        ORDER BY p.name
    `, orgID, agentID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to list pools"})
        return
    }
    defer rows.Close()

    var pools []gin.H
    for rows.Next() {
        var p struct {
            ID                 uuid.UUID
            Name               string
            Description        *string
            LBMethod           string
            HealthCheckEnabled bool
            StickySessions     bool
            TargetCount        int
            HealthyCount       int
        }
        rows.Scan(&p.ID, &p.Name, &p.Description, &p.LBMethod,
            &p.HealthCheckEnabled, &p.StickySessions, &p.TargetCount, &p.HealthyCount)
        pools = append(pools, gin.H{
            "id":                   p.ID,
            "name":                 p.Name,
            "description":          p.Description,
            "lb_method":            p.LBMethod,
            "health_check_enabled": p.HealthCheckEnabled,
            "sticky_sessions":      p.StickySessions,
            "target_count":         p.TargetCount,
            "healthy_count":        p.HealthyCount,
        })
    }

    c.JSON(200, gin.H{"pools": pools})
}

func (h *Handler) createUpstreamPool(c *gin.Context) {
    orgID := c.GetString("org_id")
    agentID := c.Param("id")

    var req struct {
        Name               string `json:"name" binding:"required"`
        Description        string `json:"description"`
        LBMethod           string `json:"lb_method"`
        HealthCheckEnabled bool   `json:"health_check_enabled"`
        HealthCheckPath    string `json:"health_check_path"`
        StickySessions     bool   `json:"sticky_sessions"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    if req.LBMethod == "" {
        req.LBMethod = "round_robin"
    }
    if req.HealthCheckPath == "" {
        req.HealthCheckPath = "/"
    }

    var poolID uuid.UUID
    err := h.db.QueryRow(c, `
        INSERT INTO upstream_pools (org_id, agent_id, name, description, lb_method,
            health_check_enabled, health_check_path, sticky_sessions)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
    `, orgID, agentID, req.Name, req.Description, req.LBMethod,
        req.HealthCheckEnabled, req.HealthCheckPath, req.StickySessions,
    ).Scan(&poolID)

    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to create pool"})
        return
    }

    c.JSON(201, gin.H{"id": poolID, "message": "Pool created"})
}

func (h *Handler) addUpstreamTarget(c *gin.Context) {
    poolID := c.Param("pool_id")

    var req struct {
        TargetType string `json:"target_type"`
        Host       string `json:"host" binding:"required"`
        Port       int    `json:"port" binding:"required"`
        Weight     int    `json:"weight"`
        IsBackup   bool   `json:"is_backup"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    if req.TargetType == "" {
        req.TargetType = "host"
    }
    if req.Weight == 0 {
        req.Weight = 1
    }

    var targetID uuid.UUID
    err := h.db.QueryRow(c, `
        INSERT INTO upstream_targets (pool_id, target_type, host, port, weight, is_backup)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
    `, poolID, req.TargetType, req.Host, req.Port, req.Weight, req.IsBackup,
    ).Scan(&targetID)

    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to add target"})
        return
    }

    // Regenerate nginx config
    h.regeneratePoolConfig(c, poolID)

    c.JSON(201, gin.H{"id": targetID, "message": "Target added"})
}

func (h *Handler) regeneratePoolConfig(c *gin.Context, poolID string) {
    // Get pool and targets
    var pool struct {
        AgentID        uuid.UUID
        Name           string
        LBMethod       string
        StickySessions bool
        StickyCookie   string
    }
    h.db.QueryRow(c, `
        SELECT agent_id, name, lb_method, sticky_sessions, sticky_cookie_name
        FROM upstream_pools WHERE id = $1
    `, poolID).Scan(&pool.AgentID, &pool.Name, &pool.LBMethod,
        &pool.StickySessions, &pool.StickyCookie)

    rows, _ := h.db.Query(c, `
        SELECT host, port, weight, is_backup
        FROM upstream_targets
        WHERE pool_id = $1 AND enabled = TRUE AND is_down = FALSE
        ORDER BY priority, weight DESC
    `, poolID)
    defer rows.Close()

    // Generate nginx upstream config
    config := fmt.Sprintf("upstream %s {\n", pool.Name)

    switch pool.LBMethod {
    case "least_conn":
        config += "    least_conn;\n"
    case "ip_hash":
        config += "    ip_hash;\n"
    }

    if pool.StickySessions {
        config += fmt.Sprintf("    sticky cookie %s expires=1h path=/;\n", pool.StickyCookie)
    }

    for rows.Next() {
        var t struct {
            Host     string
            Port     int
            Weight   int
            IsBackup bool
        }
        rows.Scan(&t.Host, &t.Port, &t.Weight, &t.IsBackup)

        server := fmt.Sprintf("    server %s:%d", t.Host, t.Port)
        if t.Weight > 1 {
            server += fmt.Sprintf(" weight=%d", t.Weight)
        }
        if t.IsBackup {
            server += " backup"
        }
        config += server + ";\n"
    }

    config += "}\n"

    // Send to agent via gRPC
    h.dispatchUpstreamConfig(pool.AgentID, pool.Name, config)
}
```

### 6.3 Health Checker: `agent/internal/healthcheck/checker.go`

```go
package healthcheck

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "go.uber.org/zap"
)

type Target struct {
    ID       string
    Host     string
    Port     int
    Path     string
    Expected int
    Timeout  time.Duration
}

type Result struct {
    TargetID     string
    Success      bool
    StatusCode   int
    ResponseTime time.Duration
    Error        string
}

type Checker struct {
    client   *http.Client
    logger   *zap.Logger
    interval time.Duration
}

func NewChecker(logger *zap.Logger) *Checker {
    return &Checker{
        client: &http.Client{
            Timeout: 10 * time.Second,
        },
        logger:   logger,
        interval: 30 * time.Second,
    }
}

func (c *Checker) Check(ctx context.Context, target Target) Result {
    start := time.Now()
    result := Result{TargetID: target.ID}

    url := fmt.Sprintf("http://%s:%d%s", target.Host, target.Port, target.Path)

    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    req.Header.Set("User-Agent", "InfraPilot-HealthCheck/1.0")

    resp, err := c.client.Do(req)
    result.ResponseTime = time.Since(start)

    if err != nil {
        result.Error = err.Error()
        return result
    }
    defer resp.Body.Close()

    result.StatusCode = resp.StatusCode
    result.Success = resp.StatusCode == target.Expected

    return result
}

func (c *Checker) Start(ctx context.Context, targets []Target, resultChan chan<- Result) {
    ticker := time.NewTicker(c.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            for _, target := range targets {
                go func(t Target) {
                    result := c.Check(ctx, t)
                    select {
                    case resultChan <- result:
                    case <-ctx.Done():
                    }
                }(target)
            }
        }
    }
}
```

---

## Phase 7: Observability

**Epic 5: DevSecOps Observability**

**Objective**: Make DevSecOps visible, explainable, and measurable

### 7.1 Database Migration: `016_observability.up.sql`

```sql
-- Timeline event types
CREATE TYPE timeline_event_type AS ENUM (
    'ci_push',
    'ci_build',
    'scan_started',
    'scan_completed',
    'policy_evaluated',
    'deployment_started',
    'deployment_completed',
    'deployment_failed',
    'drift_detected',
    'anomaly_detected',
    'alert_triggered',
    'rollback_initiated',
    'config_changed'
);

-- Unified timeline
CREATE TABLE timeline_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Type
    event_type timeline_event_type NOT NULL,

    -- Relationships
    deployment_id UUID REFERENCES deployments(id),
    service_name VARCHAR(255),

    -- Event data
    title VARCHAR(500) NOT NULL,
    description TEXT,
    metadata JSONB,

    -- Severity
    severity VARCHAR(20),

    -- Actor
    actor_type VARCHAR(20),
    actor_id UUID,
    actor_name VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security posture snapshots
CREATE TABLE security_posture (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Scores
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    vulnerability_score INTEGER NOT NULL,
    policy_score INTEGER NOT NULL,
    drift_score INTEGER NOT NULL,

    -- Counts
    total_deployments INTEGER NOT NULL DEFAULT 0,
    blocked_deployments INTEGER NOT NULL DEFAULT 0,
    total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
    critical_vulnerabilities INTEGER NOT NULL DEFAULT 0,
    unresolved_drift_events INTEGER NOT NULL DEFAULT 0,

    -- Calculated at
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_timeline_org ON timeline_events(org_id);
CREATE INDEX idx_timeline_deployment ON timeline_events(deployment_id);
CREATE INDEX idx_timeline_service ON timeline_events(service_name);
CREATE INDEX idx_timeline_created ON timeline_events(created_at DESC);
CREATE INDEX idx_security_posture_org ON security_posture(org_id);
CREATE INDEX idx_security_posture_calculated ON security_posture(calculated_at DESC);
```

### 7.2 Dashboard Handlers: `backend/internal/api/dashboard_handlers.go`

```go
package api

import (
    "github.com/gin-gonic/gin"
)

func (h *Handler) getSecurityPosture(c *gin.Context) {
    orgID := c.GetString("org_id")

    // Get latest posture or calculate
    var posture struct {
        RiskScore       int
        VulnScore       int
        PolicyScore     int
        DriftScore      int
        TotalDeploys    int
        BlockedDeploys  int
        TotalVulns      int
        CriticalVulns   int
        UnresolvedDrift int
    }

    err := h.db.QueryRow(c, `
        SELECT risk_score, vulnerability_score, policy_score, drift_score,
               total_deployments, blocked_deployments,
               total_vulnerabilities, critical_vulnerabilities,
               unresolved_drift_events
        FROM security_posture
        WHERE org_id = $1
        ORDER BY calculated_at DESC
        LIMIT 1
    `, orgID).Scan(&posture.RiskScore, &posture.VulnScore, &posture.PolicyScore,
        &posture.DriftScore, &posture.TotalDeploys, &posture.BlockedDeploys,
        &posture.TotalVulns, &posture.CriticalVulns, &posture.UnresolvedDrift)

    if err != nil {
        // Calculate on-the-fly
        posture = h.calculateSecurityPosture(c, orgID)
    }

    c.JSON(200, gin.H{
        "risk_score":              posture.RiskScore,
        "vulnerability_score":     posture.VulnScore,
        "policy_score":            posture.PolicyScore,
        "drift_score":             posture.DriftScore,
        "total_deployments":       posture.TotalDeploys,
        "blocked_deployments":     posture.BlockedDeploys,
        "block_rate":              float64(posture.BlockedDeploys) / float64(max(posture.TotalDeploys, 1)) * 100,
        "total_vulnerabilities":   posture.TotalVulns,
        "critical_vulnerabilities": posture.CriticalVulns,
        "unresolved_drift":        posture.UnresolvedDrift,
    })
}

func (h *Handler) getTimeline(c *gin.Context) {
    orgID := c.GetString("org_id")
    service := c.Query("service")
    eventType := c.Query("type")
    limit := 50

    query := `
        SELECT id, event_type, deployment_id, service_name,
               title, description, metadata, severity,
               actor_type, actor_name, created_at
        FROM timeline_events
        WHERE org_id = $1
    `
    args := []interface{}{orgID}
    argIdx := 2

    if service != "" {
        query += fmt.Sprintf(" AND service_name = $%d", argIdx)
        args = append(args, service)
        argIdx++
    }
    if eventType != "" {
        query += fmt.Sprintf(" AND event_type = $%d", argIdx)
        args = append(args, eventType)
        argIdx++
    }

    query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argIdx)
    args = append(args, limit)

    rows, err := h.db.Query(c, query, args...)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to get timeline"})
        return
    }
    defer rows.Close()

    var events []gin.H
    for rows.Next() {
        var e struct {
            ID           uuid.UUID
            EventType    string
            DeploymentID *uuid.UUID
            ServiceName  *string
            Title        string
            Description  *string
            Metadata     map[string]interface{}
            Severity     *string
            ActorType    *string
            ActorName    *string
            CreatedAt    time.Time
        }
        rows.Scan(&e.ID, &e.EventType, &e.DeploymentID, &e.ServiceName,
            &e.Title, &e.Description, &e.Metadata, &e.Severity,
            &e.ActorType, &e.ActorName, &e.CreatedAt)
        events = append(events, gin.H{
            "id":            e.ID,
            "event_type":    e.EventType,
            "deployment_id": e.DeploymentID,
            "service_name":  e.ServiceName,
            "title":         e.Title,
            "description":   e.Description,
            "metadata":      e.Metadata,
            "severity":      e.Severity,
            "actor_type":    e.ActorType,
            "actor_name":    e.ActorName,
            "created_at":    e.CreatedAt,
        })
    }

    c.JSON(200, gin.H{"events": events})
}

func (h *Handler) getVulnerabilityStats(c *gin.Context) {
    orgID := c.GetString("org_id")
    days := 30

    rows, err := h.db.Query(c, `
        SELECT DATE(scanned_at) as date,
               SUM(critical_count) as critical,
               SUM(high_count) as high,
               SUM(medium_count) as medium,
               SUM(low_count) as low
        FROM scan_results
        WHERE org_id = $1 AND scanned_at > NOW() - INTERVAL '30 days'
        GROUP BY DATE(scanned_at)
        ORDER BY date
    `, orgID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to get stats"})
        return
    }
    defer rows.Close()

    var stats []gin.H
    for rows.Next() {
        var s struct {
            Date     time.Time
            Critical int
            High     int
            Medium   int
            Low      int
        }
        rows.Scan(&s.Date, &s.Critical, &s.High, &s.Medium, &s.Low)
        stats = append(stats, gin.H{
            "date":     s.Date.Format("2006-01-02"),
            "critical": s.Critical,
            "high":     s.High,
            "medium":   s.Medium,
            "low":      s.Low,
        })
    }

    c.JSON(200, gin.H{"stats": stats, "days": days})
}
```

---

## Phase 8: Hardening & Research

**Epic 6 & 7: Hardening and Research Readiness**

### 8.1 Prometheus Metrics: `backend/internal/metrics/metrics.go`

```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    DeploymentsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "infrapilot_deployments_total",
            Help: "Total number of deployments",
        },
        []string{"environment", "decision", "service"},
    )

    ScanDuration = promauto.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "infrapilot_scan_duration_seconds",
            Help:    "Image scan duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
    )

    PolicyEvalDuration = promauto.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "infrapilot_policy_eval_duration_seconds",
            Help:    "Policy evaluation duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
    )

    VulnerabilitiesDetected = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "infrapilot_vulnerabilities",
            Help: "Detected vulnerabilities by severity",
        },
        []string{"severity"},
    )

    DriftEventsTotal = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "infrapilot_drift_events_total",
            Help: "Total drift events detected",
        },
    )

    PolicyBlocksTotal = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "infrapilot_policy_blocks_total",
            Help: "Total deployments blocked by policy",
        },
    )

    ActiveDeployments = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "infrapilot_active_deployments",
            Help: "Currently active deployments",
        },
        []string{"environment", "service"},
    )
)

func RecordDeployment(env, decision, service string) {
    DeploymentsTotal.WithLabelValues(env, decision, service).Inc()
    if decision == "deny" {
        PolicyBlocksTotal.Inc()
    }
}

func RecordScan(duration float64, critical, high, medium, low int) {
    ScanDuration.Observe(duration)
    VulnerabilitiesDetected.WithLabelValues("critical").Set(float64(critical))
    VulnerabilitiesDetected.WithLabelValues("high").Set(float64(high))
    VulnerabilitiesDetected.WithLabelValues("medium").Set(float64(medium))
    VulnerabilitiesDetected.WithLabelValues("low").Set(float64(low))
}
```

### 8.2 Secure Defaults Configuration

```go
// backend/internal/config/secure_defaults.go

package config

var SecureDefaults = map[string]interface{}{
    // Authentication
    "auth.mfa_required_for_admins": true,
    "auth.password_min_length":     12,
    "auth.session_timeout_minutes": 30,
    "auth.max_login_attempts":      5,
    "auth.lockout_duration_minutes": 15,

    // TLS
    "tls.min_version":           "1.2",
    "tls.require_everywhere":    true,
    "tls.hsts_enabled":          true,
    "tls.hsts_max_age":          31536000,

    // Container Security
    "containers.allow_privileged":     false,
    "containers.allow_host_network":   false,
    "containers.allow_host_pid":       false,
    "containers.block_docker_socket":  true,

    // Deployment Security
    "deployments.require_scan":        true,
    "deployments.block_critical":      true,
    "deployments.require_digest_prod": true,
    "deployments.block_latest_prod":   true,
}
```

---

## Database Migrations Summary

| Migration | Phase | Description |
|-----------|-------|-------------|
| `010_deployments.up.sql` | 1 | Deployment entity, status enums |
| `011_supply_chain.up.sql` | 2 | Scan results, vulnerabilities, SBOMs |
| `012_policies.up.sql` | 3 | Policies, policy decisions |
| `013_ci_integration.up.sql` | 4 | CI webhooks, CI events |
| `014_runtime_security.up.sql` | 5 | Drift events |
| `015_load_balancing.up.sql` | 6 | Upstream pools, targets |
| `016_observability.up.sql` | 7 | Timeline, security posture |

---

## API Endpoints Summary

### Deployments (Phase 1)
```
GET    /api/v1/agents/:id/deployments
POST   /api/v1/agents/:id/deployments
GET    /api/v1/agents/:id/deployments/:did
POST   /api/v1/agents/:id/deployments/:did/rollback
GET    /api/v1/services
GET    /api/v1/services/:name/current
```

### Supply Chain (Phase 2)
```
POST   /api/v1/scans
GET    /api/v1/scans
GET    /api/v1/scans/:id
GET    /api/v1/scans/:id/vulnerabilities
GET    /api/v1/sboms
GET    /api/v1/sboms/:id
GET    /api/v1/sboms/:id/download
```

### Policies (Phase 3)
```
GET    /api/v1/policies
POST   /api/v1/policies
GET    /api/v1/policies/:id
PUT    /api/v1/policies/:id
DELETE /api/v1/policies/:id
POST   /api/v1/policies/test
GET    /api/v1/policies/:id/decisions
```

### CI/CD Integration (Phase 4)
```
GET    /api/v1/ci/webhooks
POST   /api/v1/ci/webhooks
GET    /api/v1/ci/events
POST   /api/v1/webhooks/github/:id
POST   /api/v1/webhooks/gitlab/:id
POST   /api/v1/gate/check
```

### Runtime Security (Phase 5)
```
GET    /api/v1/drift-events
GET    /api/v1/drift-events/:id
POST   /api/v1/drift-events/:id/resolve
```

### Load Balancing (Phase 6)
```
GET    /api/v1/agents/:id/pools
POST   /api/v1/agents/:id/pools
GET    /api/v1/agents/:id/pools/:pid
DELETE /api/v1/agents/:id/pools/:pid
GET    /api/v1/agents/:id/pools/:pid/targets
POST   /api/v1/agents/:id/pools/:pid/targets
DELETE /api/v1/agents/:id/pools/:pid/targets/:tid
POST   /api/v1/agents/:id/pools/:pid/targets/:tid/down
GET    /api/v1/agents/:id/pools/:pid/health
```

### Observability (Phase 7)
```
GET    /api/v1/dashboard/security-posture
GET    /api/v1/dashboard/vulnerabilities
GET    /api/v1/dashboard/deployments
GET    /api/v1/dashboard/risk-score
GET    /api/v1/timeline
```

---

## File Changes Summary

### New Files

| File | Description |
|------|-------------|
| `backend/internal/db/migrations/010_deployments.up.sql` | Deployment tables |
| `backend/internal/db/migrations/011_supply_chain.up.sql` | Scan/SBOM tables |
| `backend/internal/db/migrations/012_policies.up.sql` | Policy tables |
| `backend/internal/db/migrations/013_ci_integration.up.sql` | CI tables |
| `backend/internal/db/migrations/014_runtime_security.up.sql` | Drift tables |
| `backend/internal/db/migrations/015_load_balancing.up.sql` | LB tables |
| `backend/internal/db/migrations/016_observability.up.sql` | Timeline tables |
| `backend/internal/api/deployment_handlers.go` | Deployment CRUD |
| `backend/internal/api/scan_handlers.go` | Scan endpoints |
| `backend/internal/api/policy_handlers.go` | Policy CRUD |
| `backend/internal/api/ci_handlers.go` | CI/CD handlers |
| `backend/internal/api/drift_handlers.go` | Drift endpoints |
| `backend/internal/api/loadbalancing_handlers.go` | LB handlers |
| `backend/internal/api/dashboard_handlers.go` | Dashboard endpoints |
| `backend/internal/scanner/service.go` | Trivy/Syft integration |
| `backend/internal/policy/engine.go` | OPA policy engine |
| `backend/internal/policy/defaults/*.rego` | Default policies |
| `backend/internal/metrics/metrics.go` | Prometheus metrics |
| `agent/internal/drift/detector.go` | Drift detection |
| `agent/internal/healthcheck/checker.go` | Health checks |

### Modified Files

| File | Changes |
|------|---------|
| `backend/internal/api/handler.go` | Register all new routes |
| `backend/cmd/backend/main.go` | Initialize scanner, policy engine |
| `agent/cmd/agent/main.go` | Add drift detector, health checker |

---

## Implementation Timeline

| Phase | Focus | Epics |
|-------|-------|-------|
| **Phase 1** | Foundations | Epic 0: Deployment entity |
| **Phase 2** | Supply Chain | Epic 1: Scanning, SBOM |
| **Phase 3** | Policy Engine | Epic 2: OPA integration |
| **Phase 4** | CI/CD | Epic 4: GitHub webhooks, gate API |
| **Phase 5** | Runtime Security | Epic 3: Drift detection |
| **Phase 6** | Load Balancing | Load balancing feature |
| **Phase 7** | Observability | Epic 5: Dashboard, timeline |
| **Phase 8** | Hardening | Epic 6 & 7: Metrics, secure defaults |

---

## Success Criteria

InfraPilot is **DevSecOps-complete** when:

- [ ] Vulnerable images cannot deploy (blocked by policy)
- [ ] Every runtime artifact is traceable to source code
- [ ] Policies block, not just warn
- [ ] Drift is detected automatically
- [ ] Humans only approve exceptions
- [ ] Metrics prove security improvement
- [ ] Load balancing with health checks works

---

**Last Updated**: 2026-01-14
**Status**: Complete Implementation Plan
