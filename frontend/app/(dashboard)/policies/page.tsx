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
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table, type Column } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { Badge } from "@/components/ui/Badge";
import { FilterPanel, type FilterGroup } from "@/components/ui/FilterPanel";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { Card } from "@/components/ui/Card";

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
  const [policyTypeFilter, setPolicyTypeFilter] = useState<string[]>([]);
  const [decisionFilter, setDecisionFilter] = useState<string[]>([]);

  // Fetch policy files
  const { data: policyFiles, isLoading: policiesLoading } = useQuery({
    queryKey: ["policies"],
    queryFn: () => api.fetchAPI<PolicyFile[]>("/policies"),
  });

  // Fetch policy statistics
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["policy-stats"],
    queryFn: () => api.fetchAPI<PolicyStats>("/policies/decisions/stats"),
  });

  // Fetch recent policy decisions
  const { data: recentDecisions, isLoading: decisionsLoading } = useQuery({
    queryKey: ["policy-decisions"],
    queryFn: () => api.fetchAPI<PolicyDecision[]>("/policies/decisions/recent?limit=50"),
    enabled: activeTab === "decisions",
  });

  // Filter policies by type
  const filteredPolicies = policyFiles?.filter((policy) => {
    if (policyTypeFilter.length === 0) return true;
    if (policyTypeFilter.includes("default") && policy.is_default) return true;
    if (policyTypeFilter.includes("custom") && !policy.is_default) return true;
    return false;
  });

  // Filter decisions by decision type
  const filteredDecisions = recentDecisions?.filter((decision) => {
    if (decisionFilter.length === 0) return true;
    return decisionFilter.includes(decision.decision);
  });

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case "allow":
        return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 border-green-200 dark:border-green-800";
      case "warn":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800";
      case "deny":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 border-red-200 dark:border-red-800";
      default:
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400 border-gray-200 dark:border-gray-700";
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

  // Policy files table columns
  const policyColumns: Column<PolicyFile>[] = [
    {
      key: "name",
      header: "Policy Name",
      sortable: true,
      render: (value, policy) => (
        <div className="flex items-center gap-3">
          <FileCode className="w-5 h-5 text-gray-400 flex-shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {policy.name}
              </p>
              {policy.is_default && (
                <Badge variant="default" size="sm">
                  Default
                </Badge>
              )}
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 truncate mt-0.5">
              {policy.description}
            </p>
          </div>
        </div>
      ),
    },
    {
      key: "size",
      header: "Size",
      sortable: true,
      align: "right",
      render: (value, policy) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {(policy.size / 1024).toFixed(2)} KB
        </span>
      ),
    },
    {
      key: "modified_at",
      header: "Modified",
      sortable: true,
      render: (value, policy) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {new Date(policy.modified_at).toLocaleDateString()}
        </span>
      ),
    },
  ];

  // Policy decisions table columns
  const decisionColumns: Column<PolicyDecision>[] = [
    {
      key: "service_name",
      header: "Service",
      sortable: true,
      render: (value, decision) => {
        const DecisionIcon = getDecisionIcon(decision.decision);
        return (
          <div className="flex items-center gap-3">
            <DecisionIcon
              className={cn(
                "w-5 h-5 flex-shrink-0",
                decision.decision === "allow" && "text-green-500",
                decision.decision === "warn" && "text-yellow-500",
                decision.decision === "deny" && "text-red-500"
              )}
            />
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                  {decision.service_name}
                </p>
                <Badge variant="default" size="sm">
                  {decision.environment}
                </Badge>
              </div>
              <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-1">
                {decision.reason}
              </p>
            </div>
          </div>
        );
      },
    },
    {
      key: "total_vulns",
      header: "Vulnerabilities",
      sortable: true,
      align: "right",
      render: (value, decision) => (
        <div className="text-right text-xs">
          <p className="text-gray-900 dark:text-white">{decision.total_vulns} vulns</p>
          <p className="text-gray-500 dark:text-gray-400">
            {decision.critical_count} critical, {decision.high_count} high
          </p>
        </div>
      ),
    },
    {
      key: "decision",
      header: "Decision",
      sortable: true,
      align: "center",
      render: (value, decision) => (
        <Badge className={cn("capitalize border", getDecisionColor(decision.decision))} size="sm">
          {decision.decision}
        </Badge>
      ),
    },
    {
      key: "evaluated_at",
      header: "Evaluated",
      sortable: true,
      render: (value, decision) => (
        <span className="text-sm text-gray-600 dark:text-gray-400">
          {new Date(decision.evaluated_at).toLocaleDateString()}
        </span>
      ),
    },
  ];

  // Policy type filters
  const policyTypeFilters: FilterGroup[] = [
    {
      id: "type",
      label: "Policy Type",
      type: "checkbox",
      options: [
        { label: "Default Policies", value: "default", count: policyFiles?.filter((p) => p.is_default).length },
        { label: "Custom Policies", value: "custom", count: policyFiles?.filter((p) => !p.is_default).length },
      ],
      value: policyTypeFilter,
      onChange: (value) => setPolicyTypeFilter(value as string[]),
    },
  ];

  // Decision filters
  const decisionFilters: FilterGroup[] = [
    {
      id: "decision",
      label: "Decision Type",
      type: "checkbox",
      options: [
        { label: "Allowed", value: "allow", count: recentDecisions?.filter((d) => d.decision === "allow").length },
        { label: "Warnings", value: "warn", count: recentDecisions?.filter((d) => d.decision === "warn").length },
        { label: "Denied", value: "deny", count: recentDecisions?.filter((d) => d.decision === "deny").length },
      ],
      value: decisionFilter,
      onChange: (value) => setDecisionFilter(value as string[]),
    },
  ];

  return (
    <>
      <div className="space-y-6">
        {/* Section 1: Page Header */}
        <PageHeader
          title="Security Policies"
          description="Manage deployment security policies and review policy decisions across all environments"
          breadcrumbs={
            <Breadcrumb
              items={[{ label: "Build", href: "/build" }, { label: "Policies" }]}
            />
          }
        />

        {/* Section 2: Tabs */}
        <div className="border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex gap-6">
            {[
              { id: "overview", label: "Overview" },
              { id: "files", label: "Policy Files", count: policyFiles?.length },
              { id: "decisions", label: "Recent Decisions", count: recentDecisions?.length },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as PolicyTab)}
                className={cn(
                  "py-3 px-1 border-b-2 font-medium text-sm transition-colors",
                  activeTab === tab.id
                    ? "border-primary-500 text-primary-600 dark:text-primary-400"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
                )}
              >
                {tab.label}
                {tab.count !== undefined && (
                  <span
                    className={cn(
                      "ml-2 px-2 py-0.5 text-xs rounded-full",
                      activeTab === tab.id
                        ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400"
                        : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
                    )}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        {/* Section 3: Main Content */}
        <div>
          {/* Overview Tab */}
          {activeTab === "overview" && (
            <div className="space-y-6">
              {/* Statistics Cards */}
              {statsLoading ? (
                <div className="flex justify-center py-12">
                  <Spinner size="lg" label="Loading statistics..." />
                </div>
              ) : stats ? (
                <MetricsGrid columns={4}>
                  <StatCard
                    label="Total Decisions"
                    value={stats.total}
                    description="Last 30 days"
                    icon={TrendingUp}
                    iconColor="text-primary-600"
                  />
                  <StatCard
                    label="Allowed"
                    value={stats.allow}
                    description={`${stats.allow_percentage.toFixed(1)}% of total`}
                    icon={CheckCircle}
                    iconColor="text-green-600"
                    valueColor="text-green-600 dark:text-green-400"
                  />
                  <StatCard
                    label="Warnings"
                    value={stats.warn}
                    description={`${stats.warn_percentage.toFixed(1)}% of total`}
                    icon={AlertTriangle}
                    iconColor="text-yellow-600"
                    valueColor="text-yellow-600 dark:text-yellow-400"
                  />
                  <StatCard
                    label="Denied"
                    value={stats.deny}
                    description={`${stats.deny_percentage.toFixed(1)}% of total`}
                    icon={XCircle}
                    iconColor="text-red-600"
                    valueColor="text-red-600 dark:text-red-400"
                  />
                </MetricsGrid>
              ) : null}

              {/* Active Policies Overview */}
              <Card>
                <Card.Header>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    Active Security Policies
                  </h3>
                </Card.Header>
                <Card.Body>
                  <div className="space-y-4">
                    <div className="flex items-start gap-3">
                      <Shield className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">
                          Production Environment
                        </p>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
                          Zero tolerance: Block any critical vulnerabilities, deny &gt;5 high-severity vulnerabilities
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <Shield className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">
                          Staging Environment
                        </p>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
                          Moderate policy: Block &gt;3 critical vulnerabilities, warn on any critical issues
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <Shield className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-medium text-gray-900 dark:text-white">
                          Development Environment
                        </p>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
                          Permissive policy: Allow with warnings, block only extreme cases (&gt;10 critical)
                        </p>
                      </div>
                    </div>
                  </div>
                </Card.Body>
              </Card>
            </div>
          )}

          {/* Policy Files Tab */}
          {activeTab === "files" && (
            <div className="space-y-4">
              {/* Section 4: Filter Panel */}
              {policyFiles && policyFiles.length > 0 && (
                <FilterPanel
                  filters={policyTypeFilters}
                  onReset={() => setPolicyTypeFilter([])}
                />
              )}

              {/* Policy Files Table */}
              {policiesLoading ? (
                <div className="flex justify-center py-12">
                  <Spinner size="lg" label="Loading policies..." />
                </div>
              ) : (
                <Card>
                  <Card.Body className="p-0">
                    <Table
                      columns={policyColumns}
                      data={filteredPolicies || []}
                      keyExtractor={(policy) => policy.name}
                      onRowClick={(policy) => setSelectedPolicy(policy)}
                      loading={policiesLoading}
                      emptyState={
                        <EmptyState
                          icon={FileCode}
                          title="No policies configured"
                          description={
                            policyTypeFilter.length > 0
                              ? "No policies match your filters."
                              : "No policy files found."
                          }
                          size="sm"
                        />
                      }
                      hoverable
                    />
                  </Card.Body>
                </Card>
              )}
            </div>
          )}

          {/* Recent Decisions Tab */}
          {activeTab === "decisions" && (
            <div className="space-y-4">
              {/* Section 4: Filter Panel */}
              {recentDecisions && recentDecisions.length > 0 && (
                <FilterPanel
                  filters={decisionFilters}
                  onReset={() => setDecisionFilter([])}
                />
              )}

              {/* Decisions Table */}
              {decisionsLoading ? (
                <div className="flex justify-center py-12">
                  <Spinner size="lg" label="Loading decisions..." />
                </div>
              ) : (
                <Card>
                  <Card.Body className="p-0">
                    <Table
                      columns={decisionColumns}
                      data={filteredDecisions || []}
                      keyExtractor={(decision) => decision.id}
                      onRowClick={(decision) => setSelectedDecision(decision)}
                      loading={decisionsLoading}
                      emptyState={
                        <EmptyState
                          icon={Clock}
                          title="No policy decisions"
                          description={
                            decisionFilter.length > 0
                              ? "No decisions match your filters."
                              : "No policy decisions have been made yet."
                          }
                          size="sm"
                        />
                      }
                      hoverable
                    />
                  </Card.Body>
                </Card>
              )}
            </div>
          )}
        </div>
      </div>

      {/* SlideOver for Policy Details */}
      <SlideOver
        isOpen={!!selectedPolicy}
        onClose={() => setSelectedPolicy(null)}
        size="lg"
      >
        {selectedPolicy && (
          <>
            <SlideOver.Header onClose={() => setSelectedPolicy(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedPolicy.name}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  Policy File
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Policy Information */}
                <Card>
                  <Card.Header>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                      Policy Information
                    </h3>
                  </Card.Header>
                  <Card.Body className="space-y-3">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-gray-500 dark:text-gray-400 mb-1">File</p>
                        <p className="font-medium text-gray-900 dark:text-white">
                          {selectedPolicy.name}
                        </p>
                      </div>
                      <div>
                        <p className="text-gray-500 dark:text-gray-400 mb-1">Size</p>
                        <p className="font-medium text-gray-900 dark:text-white">
                          {(selectedPolicy.size / 1024).toFixed(2)} KB
                        </p>
                      </div>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Modified</p>
                      <p className="text-sm text-gray-900 dark:text-white">
                        {new Date(selectedPolicy.modified_at).toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Type</p>
                      <Badge variant="default">
                        {selectedPolicy.is_default ? "Default Policy" : "Custom Policy"}
                      </Badge>
                    </div>
                    {selectedPolicy.description && (
                      <div>
                        <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Description</p>
                        <p className="text-sm text-gray-900 dark:text-white">
                          {selectedPolicy.description}
                        </p>
                      </div>
                    )}
                  </Card.Body>
                </Card>

                {/* Policy Content */}
                <Card>
                  <Card.Header>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                      Policy Content
                    </h3>
                  </Card.Header>
                  <Card.Body>
                    <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 max-h-96 overflow-auto">
                      <pre className="text-xs font-mono text-gray-800 dark:text-gray-200 whitespace-pre-wrap">
                        {selectedPolicy.content}
                      </pre>
                    </div>
                  </Card.Body>
                </Card>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>

      {/* SlideOver for Decision Details */}
      <SlideOver
        isOpen={!!selectedDecision}
        onClose={() => setSelectedDecision(null)}
        size="lg"
      >
        {selectedDecision && (
          <>
            <SlideOver.Header onClose={() => setSelectedDecision(null)}>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  {selectedDecision.service_name}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  {selectedDecision.environment}
                </p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              <div className="space-y-6">
                {/* Decision Details */}
                <Card>
                  <Card.Header>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                      Decision Details
                    </h3>
                  </Card.Header>
                  <Card.Body className="space-y-3">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-gray-500 dark:text-gray-400 mb-1">Service</p>
                        <p className="font-medium text-gray-900 dark:text-white">
                          {selectedDecision.service_name}
                        </p>
                      </div>
                      <div>
                        <p className="text-gray-500 dark:text-gray-400 mb-1">Environment</p>
                        <Badge variant="default">{selectedDecision.environment}</Badge>
                      </div>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Decision</p>
                      <Badge
                        className={cn("capitalize border", getDecisionColor(selectedDecision.decision))}
                      >
                        {selectedDecision.decision}
                      </Badge>
                    </div>
                    <div>
                      <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Evaluated</p>
                      <p className="text-sm text-gray-900 dark:text-white">
                        {new Date(selectedDecision.evaluated_at).toLocaleString()}
                      </p>
                    </div>
                  </Card.Body>
                </Card>

                {/* Security Scan */}
                <Card>
                  <Card.Header>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                      Security Scan
                    </h3>
                  </Card.Header>
                  <Card.Body className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        Total Vulnerabilities
                      </span>
                      <span className="text-lg font-semibold text-gray-900 dark:text-white">
                        {selectedDecision.total_vulns}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">Critical</span>
                      <span className="text-lg font-semibold text-red-600 dark:text-red-400">
                        {selectedDecision.critical_count}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-500 dark:text-gray-400">High</span>
                      <span className="text-lg font-semibold text-orange-600 dark:text-orange-400">
                        {selectedDecision.high_count}
                      </span>
                    </div>
                  </Card.Body>
                </Card>

                {/* Policy Reason */}
                <Card>
                  <Card.Header>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
                      Policy Reason
                    </h3>
                  </Card.Header>
                  <Card.Body>
                    <p className="text-sm text-gray-700 dark:text-gray-300">
                      {selectedDecision.reason}
                    </p>
                  </Card.Body>
                </Card>
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>
    </>
  );
}
