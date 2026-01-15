"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Lock,
  Unlock,
  Activity,
} from "lucide-react";
import { api, SecurityCheck, PolicyViolation } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { Table } from "@/components/ui/Table";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { SeverityBadge, Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

export default function PlatformSecurityPage() {
  const [selectedViolation, setSelectedViolation] = useState<PolicyViolation | null>(null);

  const queryClient = useQueryClient();

  // Queries
  const { data: postureData, isLoading: isLoadingPosture } = useQuery({
    queryKey: ["securityPosture"],
    queryFn: () => api.getSecurityPosture(),
    refetchInterval: 60000, // Refresh every minute
  });

  const { data: checkData, isLoading: isLoadingChecks, refetch: refetchChecks } = useQuery({
    queryKey: ["securitySelfCheck"],
    queryFn: () => api.runSecuritySelfCheck(),
  });

  const { data: violationsData, isLoading: isLoadingViolations } = useQuery({
    queryKey: ["policyViolations"],
    queryFn: () => api.listPolicyViolations(),
  });

  const { data: violationSummaryData } = useQuery({
    queryKey: ["violationSummary"],
    queryFn: () => api.getViolationSummary(),
  });

  // Mutations
  const acknowledgeViolationMutation = useMutation({
    mutationFn: ({ violationId, notes }: { violationId: string; notes: string }) =>
      api.acknowledgeViolation(violationId, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policyViolations"] });
      queryClient.invalidateQueries({ queryKey: ["violationSummary"] });
      setSelectedViolation(null);
    },
  });

  const posture = postureData;
  const checks = checkData?.checks || [];
  const checkSummary = checkData?.summary;
  const violations = violationsData?.violations || [];
  const violationSummaries = violationSummaryData?.summaries || [];

  // Overall status
  const getOverallStatus = () => {
    const criticalFailures = checkSummary?.critical_failures || posture?.critical_failures || 0;
    const failedChecks = checkSummary?.failed_checks || posture?.failed_checks || 0;
    const warningChecks = checkSummary?.warning_checks || posture?.warning_checks || 0;

    if (criticalFailures > 0) return "critical";
    if (failedChecks > 0) return "degraded";
    if (warningChecks > 0) return "warning";
    return "healthy";
  };

  const overallStatus = getOverallStatus();

  // Map severity to SeverityLevel type
  const mapSeverity = (severity: string) => {
    const normalized = severity.toLowerCase();
    if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") {
      return normalized as "critical" | "high" | "medium" | "low";
    }
    return "medium";
  };

  // Loading state
  if (isLoadingPosture || isLoadingChecks) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Platform Security"
          description="InfraPilot security posture, self-protection policies, and threat detection"
          breadcrumbs={
            <Breadcrumb
              items={[
                { label: "Platform", href: "/" },
                { label: "Platform Security", current: true },
              ]}
            />
          }
        />
        <div className="flex justify-center py-12">
          <Spinner size="lg" label="Loading security data..." />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Section 1: Page Header with Breadcrumb */}
      <PageHeader
        title="Platform Security"
        description="InfraPilot security posture, self-protection policies, and threat detection"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Platform", href: "/" },
              { label: "Platform Security", current: true },
            ]}
          />
        }
        action={
          <div className="flex items-center gap-3">
            <StatusIndicator status={overallStatus} pulse size="sm" />
            <button
              onClick={() => refetchChecks()}
              className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
              Run Self-Check
            </button>
          </div>
        }
      />

      {/* Section 2: Key Security Metrics */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Security Score"
          value={`${checkSummary?.passed_checks || posture?.passed_checks || 0}/${(checkSummary?.passed_checks || posture?.passed_checks || 0) + (checkSummary?.failed_checks || posture?.failed_checks || 0)}`}
          description="Passed security checks"
          icon={ShieldCheck}
          iconColor={overallStatus === "healthy" ? "text-green-600 dark:text-green-400" : "text-orange-600 dark:text-orange-400"}
          trend={overallStatus === "healthy" ? "up" : "down"}
          trendValue={overallStatus === "healthy" ? "Excellent" : "Needs attention"}
        />

        <StatCard
          label="Failed Checks"
          value={checkSummary?.failed_checks || posture?.failed_checks || 0}
          description="Security checks failed"
          icon={XCircle}
          iconColor="text-red-600 dark:text-red-400"
          valueColor={(checkSummary?.failed_checks || posture?.failed_checks || 0) > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
        />

        <StatCard
          label="Critical Issues"
          value={checkSummary?.critical_failures || posture?.critical_failures || 0}
          description="Require immediate attention"
          icon={AlertTriangle}
          iconColor="text-orange-600 dark:text-orange-400"
          valueColor={(checkSummary?.critical_failures || posture?.critical_failures || 0) > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
        />

        <StatCard
          label="Warnings"
          value={checkSummary?.warning_checks || posture?.warning_checks || 0}
          description="Advisory notices"
          icon={Activity}
          iconColor="text-yellow-600 dark:text-yellow-400"
        />
      </MetricsGrid>

      {/* Section 3: Security Recommendations & Checks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Recommendations Card */}
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Security Recommendations
            </h3>
          </Card.Header>
          <Card.Body>
            {checks.length === 0 ? (
              <EmptyState
                icon={Activity}
                title="No checks available"
                description="Run a security self-check to see recommendations"
                size="sm"
              />
            ) : (
              <div className="space-y-3">
                {checks
                  .filter((check) => check.status === "fail" || check.status === "warning")
                  .slice(0, 5)
                  .map((check, index) => (
                    <div
                      key={index}
                      className="flex items-start gap-3 p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                    >
                      {check.status === "fail" && check.severity === "critical" ? (
                        <XCircle className="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                      ) : check.status === "fail" ? (
                        <XCircle className="h-5 w-5 text-orange-600 dark:text-orange-400 flex-shrink-0 mt-0.5" />
                      ) : (
                        <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900 dark:text-white">
                          {check.check_name}
                        </p>
                        {check.recommendation && (
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                            {check.recommendation}
                          </p>
                        )}
                        <div className="mt-2">
                          <SeverityBadge severity={mapSeverity(check.severity)} size="sm" />
                        </div>
                      </div>
                    </div>
                  ))}
                {checks.filter((c) => c.status === "fail" || c.status === "warning").length > 5 && (
                  <p className="text-xs text-gray-500 dark:text-gray-400 text-center mt-3">
                    +{checks.filter((c) => c.status === "fail" || c.status === "warning").length - 5} more recommendations
                  </p>
                )}
              </div>
            )}
          </Card.Body>
        </Card>

        {/* Recent Violations Card */}
        <Card>
          <Card.Header
            action={
              violationSummaries.length > 0 && (
                <span className="text-xs text-gray-500 dark:text-gray-400">Last 24 hours</span>
              )
            }
          >
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Policy Violations
            </h3>
          </Card.Header>
          <Card.Body>
            {violationSummaries.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No violations"
                description="All self-protection policies are being followed"
                size="sm"
                iconClassName="text-green-500 dark:text-green-400"
              />
            ) : (
              <div className="space-y-3">
                {violationSummaries.slice(0, 5).map((summary) => (
                  <div
                    key={summary.violation_type}
                    className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <ShieldAlert className={`h-5 w-5 flex-shrink-0 ${
                        summary.max_severity === "critical" ? "text-red-600 dark:text-red-400" :
                        summary.max_severity === "high" ? "text-orange-600 dark:text-orange-400" :
                        "text-yellow-600 dark:text-yellow-400"
                      }`} />
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                          {summary.violation_type.replace(/_/g, " ").toUpperCase()}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {summary.unique_users} user{summary.unique_users !== 1 ? "s" : ""}
                        </p>
                      </div>
                    </div>
                    <div className="text-right flex-shrink-0">
                      <p className="text-sm font-semibold text-gray-900 dark:text-white">
                        {summary.violation_count}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        {summary.blocked_count} blocked
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card.Body>
        </Card>
      </div>

      {/* Section 4: Security Findings Table */}
      <Card>
        <Card.Header
          action={
            <button
              onClick={() => refetchChecks()}
              className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          }
        >
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Security Checks
            </h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              Platform hardening and self-protection validation
            </p>
          </div>
        </Card.Header>
        <Card.Body className="p-0">
          <Table
            columns={[
              {
                key: "status",
                header: "Status",
                width: "80px",
                align: "center",
                render: (value: string, row: SecurityCheck) => (
                  row.status === "pass" ? (
                    <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400" />
                  ) : row.status === "fail" && row.severity === "critical" ? (
                    <XCircle className="h-5 w-5 text-red-600 dark:text-red-400" />
                  ) : row.status === "fail" ? (
                    <XCircle className="h-5 w-5 text-orange-600 dark:text-orange-400" />
                  ) : (
                    <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                  )
                ),
              },
              {
                key: "check_name",
                header: "Check",
                sortable: true,
                render: (value: string) => (
                  <div className="text-sm font-medium text-gray-900 dark:text-white">
                    {value}
                  </div>
                ),
              },
              {
                key: "severity",
                header: "Severity",
                width: "120px",
                sortable: true,
                render: (value: string) => (
                  <SeverityBadge severity={mapSeverity(value)} size="sm" />
                ),
              },
              {
                key: "message",
                header: "Message",
                render: (value: string) => (
                  <div className="text-sm text-gray-600 dark:text-gray-400 max-w-md">
                    {value}
                  </div>
                ),
              },
              {
                key: "recommendation",
                header: "Recommendation",
                render: (value: string) => (
                  value ? (
                    <div className="text-xs text-gray-500 dark:text-gray-400 max-w-xs">
                      {value}
                    </div>
                  ) : (
                    <span className="text-xs text-gray-400">-</span>
                  )
                ),
              },
            ]}
            data={checks}
            keyExtractor={(row, index) => `${row.check_name}-${index}`}
            loading={isLoadingChecks}
            emptyState={
              <EmptyState
                icon={Activity}
                title="No security checks"
                description="Run a security self-check to see results"
                size="md"
              />
            }
            hoverable
          />
        </Card.Body>
      </Card>

      {/* Violations Detail Section */}
      {violations.length > 0 && (
        <Card>
          <Card.Header>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Detailed Policy Violations
            </h3>
          </Card.Header>
          <Card.Body className="p-0">
            <Table
              columns={[
                {
                  key: "blocked",
                  header: "Status",
                  width: "100px",
                  align: "center",
                  render: (value: boolean) => (
                    value ? (
                      <Badge
                        variant="default"
                        icon={Lock}
                        size="sm"
                        className="bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300"
                      >
                        Blocked
                      </Badge>
                    ) : (
                      <Badge
                        variant="default"
                        icon={Unlock}
                        size="sm"
                        className="bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300"
                      >
                        Allowed
                      </Badge>
                    )
                  ),
                },
                {
                  key: "violation_type",
                  header: "Violation Type",
                  sortable: true,
                  render: (value: string) => (
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {value.replace(/_/g, " ")}
                    </div>
                  ),
                },
                {
                  key: "severity",
                  header: "Severity",
                  width: "120px",
                  sortable: true,
                  render: (value: string) => (
                    <SeverityBadge severity={mapSeverity(value)} size="sm" />
                  ),
                },
                {
                  key: "user_email",
                  header: "User",
                  render: (value: string) => (
                    <div className="text-sm text-gray-600 dark:text-gray-400">
                      {value || "Unknown"}
                    </div>
                  ),
                },
                {
                  key: "created_at",
                  header: "Timestamp",
                  sortable: true,
                  render: (value: string) => (
                    <div className="text-xs text-gray-500 dark:text-gray-400">
                      {new Date(value).toLocaleString()}
                    </div>
                  ),
                },
                {
                  key: "acknowledged",
                  header: "Acknowledged",
                  width: "120px",
                  align: "center",
                  render: (value: boolean) => (
                    value ? (
                      <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400" />
                    ) : (
                      <span className="text-xs text-gray-400">-</span>
                    )
                  ),
                },
              ]}
              data={violations}
              keyExtractor={(row) => row.id}
              loading={isLoadingViolations}
              emptyState={
                <EmptyState
                  icon={ShieldCheck}
                  title="No violations"
                  description="All self-protection policies are being followed"
                  size="md"
                />
              }
              onRowClick={(row) => setSelectedViolation(row)}
              hoverable
            />
          </Card.Body>
        </Card>
      )}

      {/* Violation Detail Modal/Panel */}
      {selectedViolation && (
        <div className="fixed inset-0 bg-gray-900/50 dark:bg-gray-950/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <Card className="max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <Card.Header>
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedViolation.violation_type.replace(/_/g, " ")}
                </h3>
                <button
                  onClick={() => setSelectedViolation(null)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  <XCircle className="h-5 w-5" />
                </button>
              </div>
            </Card.Header>
            <Card.Body>
              <div className="space-y-6">
                {/* Status */}
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Status</h4>
                  <div className="flex items-center gap-4">
                    {selectedViolation.blocked ? (
                      <Badge
                        variant="default"
                        icon={Lock}
                        size="md"
                        className="bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300"
                      >
                        Blocked
                      </Badge>
                    ) : (
                      <Badge
                        variant="default"
                        icon={Unlock}
                        size="md"
                        className="bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300"
                      >
                        Allowed
                      </Badge>
                    )}
                    <SeverityBadge severity={mapSeverity(selectedViolation.severity)} size="md" />
                  </div>
                </div>

                {/* Description */}
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Description</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">{selectedViolation.description}</p>
                </div>

                {/* Attempted Action */}
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Attempted Action</h4>
                  <p className="text-sm font-mono bg-gray-50 dark:bg-gray-900 rounded p-2 text-gray-900 dark:text-white">
                    {selectedViolation.attempted_action}
                  </p>
                </div>

                {/* Policy Rule */}
                {selectedViolation.policy_rule && (
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Policy Rule</h4>
                    <p className="text-xs font-mono bg-gray-50 dark:bg-gray-900 rounded p-2 text-gray-600 dark:text-gray-400">
                      {selectedViolation.policy_rule}
                    </p>
                  </div>
                )}

                {/* User Info */}
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">User Information</h4>
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 space-y-2 text-sm">
                    {selectedViolation.user_email && (
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Email:</span>
                        <span className="font-medium text-gray-900 dark:text-white">{selectedViolation.user_email}</span>
                      </div>
                    )}
                    {selectedViolation.ip_address && (
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">IP Address:</span>
                        <span className="font-mono text-xs text-gray-900 dark:text-white">{selectedViolation.ip_address}</span>
                      </div>
                    )}
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Timestamp:</span>
                      <span className="font-medium text-gray-900 dark:text-white">
                        {new Date(selectedViolation.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Acknowledge Button */}
                {!selectedViolation.acknowledged && (
                  <div>
                    <button
                      onClick={() => {
                        const notes = prompt("Add notes (optional):");
                        if (notes !== null) {
                          acknowledgeViolationMutation.mutate({
                            violationId: selectedViolation.id,
                            notes: notes || "Acknowledged",
                          });
                        }
                      }}
                      className="w-full px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors"
                    >
                      Acknowledge Violation
                    </button>
                  </div>
                )}

                {/* Acknowledged Info */}
                {selectedViolation.acknowledged && (
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Acknowledged</h4>
                    <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-3">
                      <p className="text-sm text-green-700 dark:text-green-300 flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4" />
                        Acknowledged on {selectedViolation.acknowledged_at && new Date(selectedViolation.acknowledged_at).toLocaleString()}
                      </p>
                      {selectedViolation.notes && (
                        <p className="text-xs text-green-600 dark:text-green-400 mt-1">
                          Notes: {selectedViolation.notes}
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </Card.Body>
          </Card>
        </div>
      )}
    </div>
  );
}
