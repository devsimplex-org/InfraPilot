"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  RefreshCw,
  Settings,
  Activity,
  Lock,
  Unlock,
  Eye,
  EyeOff,
} from "lucide-react";
import { PageLayout, ListCard, DetailPanel, EmptyState } from "@/components/ui/page-layout";
import { api, SecurityCheck, PolicyViolation, SecurityPosture, ViolationSummary } from "@/lib/api";

type PageTab = "overview" | "checks" | "violations";

export default function PlatformSecurityPage() {
  const [pageTab, setPageTab] = useState<PageTab>("overview");
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

  // Overall status badge
  const getStatusBadge = (status: string) => {
    const badges = {
      healthy: { icon: ShieldCheck, color: "bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300", label: "Healthy" },
      degraded: { icon: ShieldAlert, color: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300", label: "Degraded" },
      warning: { icon: AlertTriangle, color: "bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300", label: "Warning" },
      critical: { icon: ShieldX, color: "bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300", label: "Critical" },
    };

    const badge = badges[status as keyof typeof badges] || badges.degraded;

    return (
      <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg ${badge.color}`}>
        <badge.icon className="h-5 w-5" />
        <span className="font-semibold">{badge.label}</span>
      </div>
    );
  };

  // Check status icon
  const getCheckStatusIcon = (status: string, severity?: string) => {
    if (status === "pass") return <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400" />;
    if (status === "fail" && severity === "critical") return <XCircle className="h-5 w-5 text-red-600 dark:text-red-400" />;
    if (status === "fail") return <XCircle className="h-5 w-5 text-orange-600 dark:text-orange-400" />;
    if (status === "warning") return <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />;
    return <Info className="h-5 w-5 text-blue-600 dark:text-blue-400" />;
  };

  // Severity color
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "text-red-600 dark:text-red-400";
      case "high": return "text-orange-600 dark:text-orange-400";
      case "medium": return "text-yellow-600 dark:text-yellow-400";
      case "low": return "text-blue-600 dark:text-blue-400";
      default: return "text-gray-600 dark:text-gray-400";
    }
  };

  return (
    <PageLayout
      title="Platform Security"
      description="InfraPilot security posture, self-protection policies, and threat detection"
      icon={Shield}
      tabs={[
        { id: "overview", label: "Security Posture", icon: ShieldCheck },
        { id: "checks", label: "Security Checks", icon: Activity },
        { id: "violations", label: "Policy Violations", icon: ShieldAlert },
      ]}
      activeTab={pageTab}
      onTabChange={(tab) => setPageTab(tab as PageTab)}
    >
      {pageTab === "overview" && (
        <div className="space-y-6">
          {/* Overall Status */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Platform Security Status</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Overall security posture and hardening status
                </p>
              </div>
              <button
                onClick={() => refetchChecks()}
                className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
              >
                <RefreshCw className="h-4 w-4" />
                Run Self-Check
              </button>
            </div>

            {isLoadingPosture || isLoadingChecks ? (
              <div className="py-12 text-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Status Badge */}
                <div className="flex justify-center">
                  {getStatusBadge(checkSummary?.overall_status || posture?.overall_status || "healthy")}
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 text-center">
                    <div className="flex items-center justify-center mb-2">
                      <CheckCircle2 className="h-6 w-6 text-green-600 dark:text-green-400" />
                    </div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {checkSummary?.passed_checks || posture?.passed_checks || 0}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Passed</p>
                  </div>

                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 text-center">
                    <div className="flex items-center justify-center mb-2">
                      <XCircle className="h-6 w-6 text-red-600 dark:text-red-400" />
                    </div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {checkSummary?.failed_checks || posture?.failed_checks || 0}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Failed</p>
                  </div>

                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 text-center">
                    <div className="flex items-center justify-center mb-2">
                      <AlertTriangle className="h-6 w-6 text-orange-600 dark:text-orange-400" />
                    </div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {checkSummary?.critical_failures || posture?.critical_failures || 0}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Critical</p>
                  </div>

                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 text-center">
                    <div className="flex items-center justify-center mb-2">
                      <AlertTriangle className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
                    </div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {checkSummary?.warning_checks || posture?.warning_checks || 0}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Warnings</p>
                  </div>
                </div>

                {/* Key Security Metrics */}
                <div>
                  <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                    Self-Protection Status
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {checks.slice(0, 6).map((check) => (
                      <div
                        key={check.check_name}
                        className="flex items-center gap-3 bg-gray-50 dark:bg-gray-900 rounded-lg p-3"
                      >
                        {getCheckStatusIcon(check.status, check.severity)}
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                            {check.check_name}
                          </p>
                          <p className={`text-xs ${getSeverityColor(check.severity)} truncate`}>
                            {check.message}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Recent Violations */}
                {violationSummaries.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                      Recent Violations (Last 24h)
                    </h3>
                    <div className="space-y-2">
                      {violationSummaries.slice(0, 5).map((summary) => (
                        <div
                          key={summary.violation_type}
                          className="flex items-center justify-between bg-gray-50 dark:bg-gray-900 rounded-lg p-3"
                        >
                          <div className="flex items-center gap-3">
                            <ShieldAlert className={`h-5 w-5 ${getSeverityColor(summary.max_severity)}`} />
                            <div>
                              <p className="text-sm font-medium text-gray-900 dark:text-white">
                                {summary.violation_type.replace(/_/g, " ").toUpperCase()}
                              </p>
                              <p className="text-xs text-gray-500 dark:text-gray-400">
                                {summary.unique_users} user{summary.unique_users !== 1 ? "s" : ""}
                              </p>
                            </div>
                          </div>
                          <div className="text-right">
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
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {pageTab === "checks" && (
        <div className="space-y-6">
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Security Checks</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  Platform hardening and self-protection validation
                </p>
              </div>
              <button
                onClick={() => refetchChecks()}
                className="inline-flex items-center gap-2 px-3 py-2 text-sm bg-primary-600 text-white rounded-lg hover:bg-primary-700"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>
            </div>

            <div className="overflow-x-auto">
              {isLoadingChecks ? (
                <div className="p-12 text-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
                </div>
              ) : checks.length === 0 ? (
                <div className="p-12">
                  <EmptyState
                    icon={Activity}
                    title="No checks available"
                    description="Run a security self-check to see results"
                  />
                </div>
              ) : (
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-900">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Check
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Severity
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Message
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Recommendation
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {checks.map((check, index) => (
                      <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                        <td className="px-6 py-4 whitespace-nowrap">
                          {getCheckStatusIcon(check.status, check.severity)}
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm font-medium text-gray-900 dark:text-white">
                            {check.check_name}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`text-xs font-semibold uppercase ${getSeverityColor(check.severity)}`}>
                            {check.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm text-gray-600 dark:text-gray-400 max-w-md">
                            {check.message}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          {check.recommendation && (
                            <div className="text-xs text-gray-500 dark:text-gray-400 max-w-xs">
                              {check.recommendation}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {pageTab === "violations" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Violations List */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-2 mb-3">
                <ShieldAlert className="h-5 w-5 text-gray-500" />
                <h3 className="font-semibold text-gray-900 dark:text-white">Policy Violations</h3>
              </div>

              {isLoadingViolations ? (
                <div className="py-12 text-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
                </div>
              ) : violations.length === 0 ? (
                <EmptyState
                  icon={ShieldCheck}
                  title="No violations"
                  description="All self-protection policies are being followed"
                />
              ) : (
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {violations.map((violation) => (
                    <ListCard
                      key={violation.id}
                      selected={selectedViolation?.id === violation.id}
                      onClick={() => setSelectedViolation(violation)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            {violation.blocked ? (
                              <Lock className="h-4 w-4 text-red-600 dark:text-red-400" />
                            ) : (
                              <Unlock className="h-4 w-4 text-orange-600 dark:text-orange-400" />
                            )}
                            <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                              {violation.violation_type.replace(/_/g, " ")}
                            </p>
                          </div>
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate">
                            {violation.user_email || "Unknown user"}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={`text-xs font-semibold uppercase ${getSeverityColor(violation.severity)}`}>
                              {violation.severity}
                            </span>
                            {violation.acknowledged && (
                              <span className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs text-gray-600 dark:text-gray-400">
                                Acknowledged
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                        {new Date(violation.created_at).toLocaleString()}
                      </div>
                    </ListCard>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Violation Detail */}
          <div className="lg:col-span-2">
            {!selectedViolation ? (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12">
                <EmptyState
                  icon={ShieldAlert}
                  title="Select a violation"
                  description="Choose a violation from the list to view details"
                />
              </div>
            ) : (
              <DetailPanel title={selectedViolation.violation_type.replace(/_/g, " ")}>
                <div className="space-y-6">
                  {/* Status */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Status</h4>
                    <div className="flex items-center gap-4">
                      <span className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg text-sm font-medium ${
                        selectedViolation.blocked
                          ? "bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300"
                          : "bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300"
                      }`}>
                        {selectedViolation.blocked ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />}
                        {selectedViolation.blocked ? "Blocked" : "Allowed"}
                      </span>
                      <span className={`text-xs font-semibold uppercase ${getSeverityColor(selectedViolation.severity)}`}>
                        {selectedViolation.severity} Severity
                      </span>
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
                        className="w-full px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
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
                        <p className="text-sm text-green-700 dark:text-green-300">
                          ✓ Acknowledged on {selectedViolation.acknowledged_at && new Date(selectedViolation.acknowledged_at).toLocaleString()}
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
              </DetailPanel>
            )}
          </div>
        </div>
      )}
    </PageLayout>
  );
}
