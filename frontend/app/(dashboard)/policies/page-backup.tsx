"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  FileCode,
  CheckCircle,
  AlertTriangle,
  XCircle,
  TrendingUp,
  Clock,
  Eye,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  PageLayout,
  ListCard,
  EmptyState,
  Button,
  Tabs,
} from "@/components/ui/page-layout";
import {
  DetailPanel,
  DetailSection,
  DetailRow,
} from "@/components/ui/detail-panel";

type PolicyTab = "overview" | "files" | "decisions";

interface PolicyFile {
  name: string;
  path: string;
  content: string;
  size: number;
  modified_at: string;
  is_default: boolean;
  description: string;
}

interface PolicyDecision {
  id: string;
  deployment_id: string;
  service_name: string;
  environment: string;
  decision: "allow" | "warn" | "deny";
  reason: string;
  critical_count: number;
  high_count: number;
  total_vulns: number;
  evaluated_at: string;
}

interface PolicyStats {
  period: string;
  total: number;
  allow: number;
  warn: number;
  deny: number;
  allow_percentage: number;
  warn_percentage: number;
  deny_percentage: number;
}

export default function PoliciesPage() {
  const [activeTab, setActiveTab] = useState<PolicyTab>("overview");
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyFile | null>(null);
  const [selectedDecision, setSelectedDecision] = useState<PolicyDecision | null>(null);

  // Fetch policy files
  const { data: policyFiles } = useQuery({
    queryKey: ["policies"],
    queryFn: () => api.fetchAPI<PolicyFile[]>("/policies"),
  });

  // Fetch policy statistics
  const { data: stats } = useQuery({
    queryKey: ["policy-stats"],
    queryFn: () => api.fetchAPI<PolicyStats>("/policies/decisions/stats"),
  });

  // Fetch recent policy decisions
  const { data: recentDecisions } = useQuery({
    queryKey: ["policy-decisions"],
    queryFn: () => api.fetchAPI<PolicyDecision[]>("/policies/decisions/recent?limit=50"),
    enabled: activeTab === "decisions",
  });

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case "allow":
        return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400";
      case "warn":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
      case "deny":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
      default:
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400";
    }
  };

  const getDecisionIcon = (decision: string) => {
    switch (decision) {
      case "allow":
        return CheckCircle;
      case "warn":
        return AlertTriangle;
      case "deny":
        return XCircle;
      default:
        return Shield;
    }
  };

  return (
    <PageLayout
      title="Security Policies"
      description="Manage deployment security policies and review policy decisions"
      panel={
        (selectedPolicy || selectedDecision) && (
          <DetailPanel
            open={!!(selectedPolicy || selectedDecision)}
            onClose={() => {
              setSelectedPolicy(null);
              setSelectedDecision(null);
            }}
            title={selectedPolicy ? selectedPolicy.name : selectedDecision?.service_name}
            subtitle={selectedPolicy ? "Policy File" : selectedDecision?.environment}
          >
            {selectedPolicy && (
              <>
                <DetailSection title="Policy Information">
                  <DetailRow label="File" value={selectedPolicy.name} />
                  <DetailRow label="Size" value={`${(selectedPolicy.size / 1024).toFixed(2)} KB`} />
                  <DetailRow
                    label="Modified"
                    value={new Date(selectedPolicy.modified_at).toLocaleString()}
                  />
                  <DetailRow
                    label="Type"
                    value={selectedPolicy.is_default ? "Default Policy" : "Custom Policy"}
                  />
                </DetailSection>

                <DetailSection title="Policy Content">
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 max-h-96 overflow-auto">
                    <pre className="text-xs font-mono text-gray-800 dark:text-gray-200 whitespace-pre-wrap">
                      {selectedPolicy.content}
                    </pre>
                  </div>
                </DetailSection>
              </>
            )}

            {selectedDecision && (
              <>
                <DetailSection title="Decision Details">
                  <DetailRow label="Service" value={selectedDecision.service_name} />
                  <DetailRow label="Environment" value={selectedDecision.environment} />
                  <DetailRow
                    label="Decision"
                    value={
                      <span className={cn("px-2 py-0.5 text-xs font-medium rounded-full capitalize", getDecisionColor(selectedDecision.decision))}>
                        {selectedDecision.decision}
                      </span>
                    }
                  />
                  <DetailRow
                    label="Evaluated"
                    value={new Date(selectedDecision.evaluated_at).toLocaleString()}
                  />
                </DetailSection>

                <DetailSection title="Security Scan">
                  <DetailRow label="Total Vulnerabilities" value={selectedDecision.total_vulns} />
                  <DetailRow
                    label="Critical"
                    value={
                      <span className="text-red-600 dark:text-red-400 font-semibold">
                        {selectedDecision.critical_count}
                      </span>
                    }
                  />
                  <DetailRow
                    label="High"
                    value={
                      <span className="text-orange-600 dark:text-orange-400 font-semibold">
                        {selectedDecision.high_count}
                      </span>
                    }
                  />
                </DetailSection>

                <DetailSection title="Policy Reason">
                  <div className="text-sm text-gray-700 dark:text-gray-300 p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                    {selectedDecision.reason}
                  </div>
                </DetailSection>
              </>
            )}
          </DetailPanel>
        )
      }
      panelOpen={!!(selectedPolicy || selectedDecision)}
    >
      <Tabs
        tabs={[
          { id: "overview", label: "Overview" },
          { id: "files", label: "Policy Files", count: policyFiles?.length },
          { id: "decisions", label: "Recent Decisions", count: recentDecisions?.length },
        ]}
        activeTab={activeTab}
        onChange={(id) => setActiveTab(id as PolicyTab)}
      />

      <div className="mt-6">
        {/* Overview Tab */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {/* Statistics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Total Decisions</p>
                    <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                      {stats?.total || 0}
                    </p>
                  </div>
                  <TrendingUp className="w-8 h-8 text-primary-500" />
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">Last 30 days</p>
              </div>

              <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Allowed</p>
                    <p className="text-2xl font-semibold text-green-600 dark:text-green-400 mt-1">
                      {stats?.allow || 0}
                    </p>
                  </div>
                  <CheckCircle className="w-8 h-8 text-green-500" />
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                  {stats?.allow_percentage.toFixed(1)}% of total
                </p>
              </div>

              <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Warnings</p>
                    <p className="text-2xl font-semibold text-yellow-600 dark:text-yellow-400 mt-1">
                      {stats?.warn || 0}
                    </p>
                  </div>
                  <AlertTriangle className="w-8 h-8 text-yellow-500" />
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                  {stats?.warn_percentage.toFixed(1)}% of total
                </p>
              </div>

              <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">Denied</p>
                    <p className="text-2xl font-semibold text-red-600 dark:text-red-400 mt-1">
                      {stats?.deny || 0}
                    </p>
                  </div>
                  <XCircle className="w-8 h-8 text-red-500" />
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                  {stats?.deny_percentage.toFixed(1)}% of total
                </p>
              </div>
            </div>

            {/* Policy Overview */}
            <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Active Security Policies
              </h3>
              <div className="space-y-3">
                <div className="flex items-start gap-3 text-sm">
                  <Shield className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">Production Environment</p>
                    <p className="text-gray-600 dark:text-gray-400 text-xs mt-0.5">
                      Zero tolerance: Block any critical vulnerabilities, deny &gt;5 high-severity vulnerabilities
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3 text-sm">
                  <Shield className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">Staging Environment</p>
                    <p className="text-gray-600 dark:text-gray-400 text-xs mt-0.5">
                      Moderate policy: Block &gt;3 critical vulnerabilities, warn on any critical issues
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3 text-sm">
                  <Shield className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">Development Environment</p>
                    <p className="text-gray-600 dark:text-gray-400 text-xs mt-0.5">
                      Permissive policy: Allow with warnings, block only extreme cases (&gt;10 critical)
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Policy Files Tab */}
        {activeTab === "files" && (
          <div className="space-y-4">
            {policyFiles && policyFiles.length > 0 ? (
              policyFiles.map((policy) => (
                <ListCard
                  key={policy.name}
                  selected={selectedPolicy?.name === policy.name}
                  onClick={() => setSelectedPolicy(policy)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <FileCode className="w-5 h-5 text-gray-400" />
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                            {policy.name}
                          </h3>
                          {policy.is_default && (
                            <span className="px-2 py-0.5 text-xs bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 rounded-full">
                              Default
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                          {policy.description}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {(policy.size / 1024).toFixed(2)} KB
                        </p>
                        <p className="text-xs text-gray-400 dark:text-gray-500">
                          {new Date(policy.modified_at).toLocaleDateString()}
                        </p>
                      </div>
                      <Eye className="w-4 h-4 text-gray-400" />
                    </div>
                  </div>
                </ListCard>
              ))
            ) : (
              <EmptyState
                icon={FileCode}
                title="No Policy Files"
                description="No policy files found."
              />
            )}
          </div>
        )}

        {/* Recent Decisions Tab */}
        {activeTab === "decisions" && (
          <div className="space-y-4">
            {recentDecisions && recentDecisions.length > 0 ? (
              recentDecisions.map((decision) => {
                const DecisionIcon = getDecisionIcon(decision.decision);
                return (
                  <ListCard
                    key={decision.id}
                    selected={selectedDecision?.id === decision.id}
                    onClick={() => setSelectedDecision(decision)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <DecisionIcon className={cn("w-5 h-5",
                          decision.decision === "allow" && "text-green-500",
                          decision.decision === "warn" && "text-yellow-500",
                          decision.decision === "deny" && "text-red-500"
                        )} />
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                              {decision.service_name}
                            </h3>
                            <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-800 rounded">
                              {decision.environment}
                            </span>
                          </div>
                          <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-1">
                            {decision.reason}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right text-xs">
                          <p className="text-gray-900 dark:text-white">
                            {decision.total_vulns} vulns
                          </p>
                          <p className="text-gray-500 dark:text-gray-400">
                            {decision.critical_count} critical, {decision.high_count} high
                          </p>
                        </div>
                        <span className={cn("px-2 py-0.5 text-xs font-medium rounded-full capitalize", getDecisionColor(decision.decision))}>
                          {decision.decision}
                        </span>
                      </div>
                    </div>
                  </ListCard>
                );
              })
            ) : (
              <EmptyState
                icon={Clock}
                title="No Policy Decisions"
                description="No policy decisions have been made yet."
              />
            )}
          </div>
        )}
      </div>
    </PageLayout>
  );
}
