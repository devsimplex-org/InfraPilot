package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

// PolicyEngine handles policy evaluation with OPA
type PolicyEngine struct {
	logger     *zap.Logger
	opaPath    string
	policyPath string
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(logger *zap.Logger, policyPath string) *PolicyEngine {
	return &PolicyEngine{
		logger:     logger,
		opaPath:    "opa",
		policyPath: policyPath,
	}
}

// PolicyInput represents the input data for policy evaluation
type PolicyInput struct {
	Deployment     DeploymentInfo     `json:"deployment"`
	ScanResult     ScanResultInfo     `json:"scan_result"`
	Vulnerabilities []VulnerabilityInfo `json:"vulnerabilities"`
}

type DeploymentInfo struct {
	ServiceName  string `json:"service_name"`
	Environment  string `json:"environment"`
	ImageRepo    string `json:"image_repository"`
	ImageTag     string `json:"image_tag"`
	ImageDigest  string `json:"image_digest"`
	GitBranch    string `json:"git_branch"`
	GitCommit    string `json:"git_commit"`
}

type ScanResultInfo struct {
	TotalCount    int `json:"total_count"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	FixableCount  int `json:"fixable_count"`
}

type VulnerabilityInfo struct {
	CVEID       string  `json:"cve_id"`
	Severity    string  `json:"severity"`
	PackageName string  `json:"package_name"`
	CVSSScore   float64 `json:"cvss_score"`
	FixAvailable bool   `json:"fix_available"`
}

// PolicyResult represents the result of policy evaluation
type PolicyResult struct {
	Decision string   `json:"decision"` // "allow", "warn", "deny"
	Reason   string   `json:"reason"`
	Warnings []string `json:"warnings,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

// EvaluatePolicy evaluates a deployment against the policy
func (e *PolicyEngine) EvaluatePolicy(ctx context.Context, input PolicyInput) (*PolicyResult, error) {
	e.logger.Debug("Evaluating policy",
		zap.String("service", input.Deployment.ServiceName),
		zap.String("environment", input.Deployment.Environment),
		zap.Int("total_vulns", input.ScanResult.TotalCount),
	)

	// Marshal input to JSON
	inputJSON, err := json.Marshal(map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	// Check if OPA is installed
	if err := e.checkOPAInstalled(ctx); err != nil {
		e.logger.Warn("OPA not available, using default policy", zap.Error(err))
		return e.defaultPolicy(input), nil
	}

	// Run OPA eval
	cmd := exec.CommandContext(ctx, e.opaPath,
		"eval",
		"--data", e.policyPath,
		"--input", "-",
		"--format", "pretty",
		"data.deployment.policy.decision",
	)
	cmd.Stdin = strings.NewReader(string(inputJSON))

	output, err := cmd.CombinedOutput()
	if err != nil {
		e.logger.Warn("OPA evaluation failed, using default policy",
			zap.Error(err),
			zap.String("output", string(output)),
		)
		return e.defaultPolicy(input), nil
	}

	// Parse OPA output
	var result PolicyResult
	if err := json.Unmarshal(output, &result); err != nil {
		// If parsing fails, try to extract decision from pretty output
		return e.parseOPAOutput(string(output), input), nil
	}

	e.logger.Info("Policy evaluated",
		zap.String("decision", result.Decision),
		zap.String("reason", result.Reason),
	)

	return &result, nil
}

// parseOPAOutput parses OPA pretty-printed output
func (e *PolicyEngine) parseOPAOutput(output string, input PolicyInput) *PolicyResult {
	// Try to extract decision from output
	if strings.Contains(output, "allow") {
		return &PolicyResult{
			Decision: "allow",
			Reason:   "No critical security issues found",
		}
	}
	if strings.Contains(output, "deny") {
		return &PolicyResult{
			Decision: "deny",
			Reason:   fmt.Sprintf("Security policy violation: %d critical, %d high vulnerabilities",
				input.ScanResult.CriticalCount, input.ScanResult.HighCount),
		}
	}
	// Default to warn
	return &PolicyResult{
		Decision: "warn",
		Reason:   "Policy evaluation incomplete",
		Warnings: []string{"OPA output parsing failed"},
	}
}

// defaultPolicy returns a default policy decision when OPA is not available
func (e *PolicyEngine) defaultPolicy(input PolicyInput) *PolicyResult {
	// Production environment: strict policy
	if input.Deployment.Environment == "prod" {
		if input.ScanResult.CriticalCount > 0 {
			return &PolicyResult{
				Decision: "warn",
				Reason: fmt.Sprintf(
					"Production deployment warning: %d critical vulnerabilities found",
					input.ScanResult.CriticalCount,
				),
				Warnings: []string{
					fmt.Sprintf("%d critical vulnerabilities detected — review recommended", input.ScanResult.CriticalCount),
				},
			}
		}
		if input.ScanResult.HighCount > 5 {
			return &PolicyResult{
				Decision: "warn",
				Reason: fmt.Sprintf(
					"Production deployment warning: %d high-severity vulnerabilities found (threshold: 5)",
					input.ScanResult.HighCount,
				),
				Warnings: []string{
					"High number of high-severity vulnerabilities",
					"Consider upgrading dependencies before deploying",
				},
			}
		}
	}

	// Staging environment: moderate policy
	if input.Deployment.Environment == "staging" {
		if input.ScanResult.CriticalCount > 3 {
			return &PolicyResult{
				Decision: "deny",
				Reason: fmt.Sprintf(
					"Staging deployment blocked: %d critical vulnerabilities found (threshold: 3)",
					input.ScanResult.CriticalCount,
				),
			}
		}
		if input.ScanResult.CriticalCount > 0 || input.ScanResult.HighCount > 10 {
			return &PolicyResult{
				Decision: "warn",
				Reason: "Staging deployment contains vulnerabilities",
				Warnings: []string{
					fmt.Sprintf("%d critical, %d high vulnerabilities found",
						input.ScanResult.CriticalCount, input.ScanResult.HighCount),
				},
			}
		}
	}

	// Dev environment: permissive policy (allow but warn)
	if input.ScanResult.CriticalCount > 10 {
		return &PolicyResult{
			Decision: "warn",
			Reason: fmt.Sprintf(
				"Development deployment warning: %d critical vulnerabilities found",
				input.ScanResult.CriticalCount,
			),
			Warnings: []string{"High number of critical vulnerabilities"},
		}
	}

	// Default: allow
	return &PolicyResult{
		Decision: "allow",
		Reason: fmt.Sprintf(
			"Security scan passed: %d total vulnerabilities (%d critical, %d high)",
			input.ScanResult.TotalCount,
			input.ScanResult.CriticalCount,
			input.ScanResult.HighCount,
		),
	}
}

// checkOPAInstalled verifies OPA is available
func (e *PolicyEngine) checkOPAInstalled(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, e.opaPath, "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("opa command not found or not executable")
	}
	return nil
}
