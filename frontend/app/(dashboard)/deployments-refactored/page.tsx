"use client";

import { useState, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Package,
  Shield,
  AlertTriangle,
  CheckCircle,
  GitBranch,
  FileCode,
  ExternalLink,
  RefreshCw,
  Download,
  Container,
  Clock,
} from "lucide-react";
import { api, Deployment, ScanResult, Vulnerability, SBOM } from "@/lib/api";
import { PageHeader } from "@/components/ui/PageHeader";
import { Table, type Column } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { Card } from "@/components/ui/Card";
import { Badge, SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { FilterPanel, type FilterGroup } from "@/components/ui/FilterPanel";
import { cn } from "@/lib/utils";

type PanelTab = "overview" | "scan" | "vulnerabilities" | "sbom";

export default function DeploymentsPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedDeployment, setSelectedDeployment] = useState<Deployment | null>(null);
  const [panelTab, setPanelTab] = useState<PanelTab>("overview");
  const [vulnerabilitySeverityFilter, setVulnerabilitySeverityFilter] = useState<string[]>([]);

  // Fetch agents
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });

  // Fetch deployments for selected agent
  const { data: deployments, isLoading } = useQuery({
    queryKey: ["deployments", selectedAgent],
    queryFn: () =>
      selectedAgent ? api.getDeployments(selectedAgent) : Promise.resolve([]),
    enabled: !!selectedAgent,
    refetchInterval: 10000,
  });

  // Fetch scan results for selected deployment
  const { data: scanResult } = useQuery({
    queryKey: ["scanResult", selectedDeployment?.scan_result_id],
    queryFn: () =>
      selectedDeployment?.scan_result_id
        ? api.getScanDetails(selectedDeployment.scan_result_id)
        : Promise.resolve(null),
    enabled: !!selectedDeployment?.scan_result_id && (panelTab === "scan" || panelTab === "vulnerabilities"),
  });

  // Fetch vulnerabilities for scan
  const { data: vulnerabilities } = useQuery({
    queryKey: ["vulnerabilities", selectedDeployment?.scan_result_id, vulnerabilitySeverityFilter],
    queryFn: () =>
      selectedDeployment?.scan_result_id
        ? api.getScanVulnerabilities(selectedDeployment.scan_result_id, {
            severity: vulnerabilitySeverityFilter[0],
          })
        : Promise.resolve([]),
    enabled: !!selectedDeployment?.scan_result_id && panelTab === "vulnerabilities",
  });

  // Fetch SBOM for selected deployment
  const { data: sboms } = useQuery({
    queryKey: ["sboms", selectedDeployment?.sbom_id],
    queryFn: () => (selectedDeployment?.sbom_id ? api.listSBOMs() : Promise.resolve([])),
    enabled: !!selectedDeployment?.sbom_id && panelTab === "sbom",
  });

  const activeAgents = agents?.filter((a) => a.status === "active") || [];

  // Auto-select first active agent
  useEffect(() => {
    if (!selectedAgent && activeAgents.length > 0) {
      setSelectedAgent(activeAgents[0].id);
    }
  }, [activeAgents, selectedAgent]);

  const getDeploymentStatus = (status: Deployment["status"]): "healthy" | "warning" | "degraded" | "critical" => {
    switch (status) {
      case "running":
        return "healthy";
      case "failed":
        return "critical";
      case "scanning":
      case "policy_check":
      case "deploying":
        return "warning";
      case "rolled_back":
        return "degraded";
      default:
        return "degraded";
    }
  };

  const getPolicyDecisionStatus = (decision?: "allow" | "warn" | "deny"): "healthy" | "warning" | "critical" | undefined => {
    if (!decision) return undefined;
    switch (decision) {
      case "allow":
        return "healthy";
      case "warn":
        return "warning";
      case "deny":
        return "critical";
    }
  };

  // Table columns
  const columns: Column<Deployment>[] = [
    {
      key: "service_name",
      header: "Service",
      sortable: true,
      render: (deployment) => (
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-gray-400 flex-shrink-0" />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {deployment.service_name}
              </p>
              <Badge variant="default" size="sm">
                {deployment.environment}
              </Badge>
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate mt-0.5">
              {deployment.image_repository}
              {deployment.image_tag && `:${deployment.image_tag}`}
            </p>
          </div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      sortable: true,
      render: (deployment) => (
        <div className="space-y-1">
          <StatusIndicator
            status={getDeploymentStatus(deployment.status)}
            label={deployment.status}
            size="sm"
            pulse={deployment.status === "running"}
          />
          {deployment.policy_decision && (
            <StatusIndicator
              status={getPolicyDecisionStatus(deployment.policy_decision)!}
              label={deployment.policy_decision === "allow" ? "Allowed" : deployment.policy_decision === "warn" ? "Warning" : "Blocked"}
              size="sm"
            />
          )}
        </div>
      ),
    },
    {
      key: "git_commit",
      header: "Git",
      render: (deployment) =>
        deployment.git_commit ? (
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-gray-400" />
            <span className="text-xs text-gray-600 dark:text-gray-400 font-mono">
              {deployment.git_commit.substring(0, 8)}
            </span>
          </div>
        ) : (
          <span className="text-xs text-gray-400">—</span>
        ),
    },
    {
      key: "deployed_at",
      header: "Deployed",
      sortable: true,
      render: (deployment) =>
        deployment.deployed_at ? (
          <span className="text-xs text-gray-600 dark:text-gray-400">
            {new Date(deployment.deployed_at).toLocaleDateString()}
          </span>
        ) : (
          <span className="text-xs text-gray-400">—</span>
        ),
    },
  ];

  // Vulnerability filters
  const vulnerabilityFilters: FilterGroup[] = [
    {
      id: "severity",
      label: "Severity",
      type: "checkbox",
      options: [
        { label: "Critical", value: "CRITICAL" },
        { label: "High", value: "HIGH" },
        { label: "Medium", value: "MEDIUM" },
        { label: "Low", value: "LOW" },
      ],
      value: vulnerabilitySeverityFilter,
      onChange: (value) => setVulnerabilitySeverityFilter(value as string[]),
    },
  ];

  // Loading state
  if (!selectedAgent && activeAgents.length === 0 && !isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Deployments"
          description="Manage and monitor deployments with security scanning"
          breadcrumbs={<Breadcrumb items={[{ label: "Deploy", href: "/deploy" }, { label: "Deployments" }]} />}
        />
        <EmptyState
          icon={Package}
          title="No active agents"
          description="Connect your first agent to start monitoring deployments"
          action={
            <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors">
              Connect Agent
            </button>
          }
        />
      </div>
    );
  }

  return (
    <>
      <div className="space-y-6">
        {/* Page Header */}
        <PageHeader
          title="Deployments"
          description="Manage and monitor deployments with security scanning across all environments"
          breadcrumbs={<Breadcrumb items={[{ label: "Deploy", href: "/deploy" }, { label: "Deployments" }]} />}
          action={
            <div className="flex items-center gap-3">
              {activeAgents.length > 1 && (
                <select
                  value={selectedAgent || ""}
                  onChange={(e) => {
                    setSelectedAgent(e.target.value);
                    setSelectedDeployment(null);
                  }}
                  className="rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-4 py-2 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                >
                  {activeAgents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.name}
                    </option>
                  ))}
                </select>
              )}
              <button
                onClick={() =>
                  queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] })
                }
                className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
              >
                <RefreshCw className="w-4 h-4" />
                Refresh
              </button>
            </div>
          }
        />

        {/* Deployments Table */}
        <Card>
          <Card.Body className="p-0">
            <Table
              columns={columns}
              data={deployments || []}
              keyExtractor={(deployment) => deployment.id}
              onRowClick={(deployment) => setSelectedDeployment(deployment)}
              loading={isLoading}
              emptyState={
                <EmptyState
                  icon={Package}
                  title="No deployments"
                  description="No deployments found for this agent"
                  size="sm"
                />
              }
              hoverable
            />
          </Card.Body>
        </Card>
      </div>

      {/* Detail SlideOver */}
      <SlideOver
        isOpen={!!selectedDeployment}
        onClose={() => setSelectedDeployment(null)}
        size="lg"
      >
        {selectedDeployment && (
          <>
            <SlideOver.Header onClose={() => setSelectedDeployment(null)} showCloseButton>
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedDeployment.service_name}</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400">{selectedDeployment.environment}</p>
              </div>
            </SlideOver.Header>

            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex items-center gap-1 p-1 bg-gray-100 dark:bg-gray-800 rounded-lg mb-6">
                {[
                  { id: "overview", label: "Overview" },
                  { id: "scan", label: "Scan Results", count: scanResult?.total },
                  { id: "vulnerabilities", label: "Vulnerabilities", count: vulnerabilities?.length },
                  { id: "sbom", label: "SBOM" },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setPanelTab(tab.id as PanelTab)}
                    className={cn(
                      "flex-1 px-3 py-2 text-sm font-medium rounded-md transition-colors",
                      panelTab === tab.id
                        ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm"
                        : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
                    )}
                  >
                    {tab.label}
                    {tab.count !== undefined && (
                      <span
                        className={cn(
                          "ml-2 px-1.5 py-0.5 text-xs rounded-full",
                          panelTab === tab.id
                            ? "bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400"
                            : "bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400"
                        )}
                      >
                        {tab.count}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              {/* Tab Content */}
              <div className="space-y-6">
                {/* Overview Tab */}
                {panelTab === "overview" && (
                  <>
                    {/* Quick Actions */}
                    {selectedDeployment.sbom_id && (
                      <Card>
                        <Card.Header>
                          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Quick Actions</h3>
                        </Card.Header>
                        <Card.Body className="space-y-2">
                          <button
                            onClick={() => api.downloadSBOM(selectedDeployment.sbom_id!)}
                            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
                          >
                            <Download className="w-4 h-4" />
                            Download SBOM
                          </button>
                          {selectedDeployment.scan_result_id && (
                            <button
                              onClick={() => setPanelTab("scan")}
                              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-white rounded-lg transition-colors text-sm font-medium"
                            >
                              <Shield className="w-4 h-4" />
                              View Scan Results
                            </button>
                          )}
                        </Card.Body>
                      </Card>
                    )}

                    {/* Deployment Info */}
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Deployment Info</h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 mb-1">Service</p>
                            <p className="font-medium text-gray-900 dark:text-white">{selectedDeployment.service_name}</p>
                          </div>
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 mb-1">Environment</p>
                            <Badge variant="default">{selectedDeployment.environment}</Badge>
                          </div>
                        </div>
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Status</p>
                          <StatusIndicator
                            status={getDeploymentStatus(selectedDeployment.status)}
                            label={selectedDeployment.status}
                            pulse={selectedDeployment.status === "running"}
                          />
                        </div>
                        {selectedDeployment.status_message && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Message</p>
                            <p className="text-sm text-gray-900 dark:text-white">{selectedDeployment.status_message}</p>
                          </div>
                        )}
                        {selectedDeployment.policy_decision && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Policy</p>
                            <StatusIndicator
                              status={getPolicyDecisionStatus(selectedDeployment.policy_decision)!}
                              label={selectedDeployment.policy_decision === "allow" ? "Allowed" : selectedDeployment.policy_decision === "warn" ? "Warning" : "Blocked"}
                            />
                          </div>
                        )}
                        {selectedDeployment.policy_reason && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Policy Reason</p>
                            <p className="text-sm text-gray-900 dark:text-white">{selectedDeployment.policy_reason}</p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>

                    {/* Image Info */}
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                          <Container className="w-4 h-4" />
                          Image
                        </h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Repository</p>
                          <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                            {selectedDeployment.image_repository}
                          </p>
                        </div>
                        {selectedDeployment.image_tag && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Tag</p>
                            <p className="text-sm font-mono text-gray-900 dark:text-white">{selectedDeployment.image_tag}</p>
                          </div>
                        )}
                        {selectedDeployment.image_digest && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Digest</p>
                            <p className="text-xs font-mono text-gray-900 dark:text-white break-all">
                              {selectedDeployment.image_digest.substring(0, 20)}...
                            </p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>

                    {/* Git Info */}
                    {(selectedDeployment.git_repo || selectedDeployment.git_commit) && (
                      <Card>
                        <Card.Header>
                          <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                            <GitBranch className="w-4 h-4" />
                            Git Info
                          </h3>
                        </Card.Header>
                        <Card.Body className="space-y-3">
                          {selectedDeployment.git_repo && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Repository</p>
                              <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                                {selectedDeployment.git_repo}
                              </p>
                            </div>
                          )}
                          <div className="grid grid-cols-2 gap-4">
                            {selectedDeployment.git_branch && (
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Branch</p>
                                <p className="text-sm font-mono text-gray-900 dark:text-white">
                                  {selectedDeployment.git_branch}
                                </p>
                              </div>
                            )}
                            {selectedDeployment.git_commit && (
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Commit</p>
                                <p className="text-sm font-mono text-gray-900 dark:text-white">
                                  {selectedDeployment.git_commit.substring(0, 8)}
                                </p>
                              </div>
                            )}
                          </div>
                        </Card.Body>
                      </Card>
                    )}

                    {/* CI/CD Info */}
                    {(selectedDeployment.ci_provider || selectedDeployment.ci_pipeline_id) && (
                      <Card>
                        <Card.Header>
                          <h3 className="text-sm font-semibold text-gray-900 dark:text-white">CI/CD</h3>
                        </Card.Header>
                        <Card.Body className="space-y-3">
                          {selectedDeployment.ci_provider && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Provider</p>
                              <p className="text-sm text-gray-900 dark:text-white">{selectedDeployment.ci_provider}</p>
                            </div>
                          )}
                          {selectedDeployment.ci_pipeline_id && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Pipeline ID</p>
                              <p className="text-sm font-mono text-gray-900 dark:text-white">
                                {selectedDeployment.ci_pipeline_id}
                              </p>
                            </div>
                          )}
                          {selectedDeployment.ci_build_url && (
                            <a
                              href={selectedDeployment.ci_build_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400"
                            >
                              View Build
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          )}
                        </Card.Body>
                      </Card>
                    )}

                    {/* Metadata */}
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                          <Clock className="w-4 h-4" />
                          Metadata
                        </h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Created</p>
                          <p className="text-sm text-gray-900 dark:text-white">
                            {new Date(selectedDeployment.created_at).toLocaleString()}
                          </p>
                        </div>
                        {selectedDeployment.deployed_at && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Deployed</p>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {new Date(selectedDeployment.deployed_at).toLocaleString()}
                            </p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>
                  </>
                )}

                {/* Scan Tab */}
                {panelTab === "scan" && scanResult && (
                  <>
                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Scan Summary</h3>
                      </Card.Header>
                      <Card.Body className="space-y-3">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 mb-1">Scanner</p>
                            <p className="text-gray-900 dark:text-white">{scanResult.scanner_name}</p>
                          </div>
                          {scanResult.scanner_version && (
                            <div>
                              <p className="text-gray-500 dark:text-gray-400 mb-1">Version</p>
                              <p className="text-gray-900 dark:text-white">{scanResult.scanner_version}</p>
                            </div>
                          )}
                        </div>
                        <div>
                          <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Scanned</p>
                          <p className="text-sm text-gray-900 dark:text-white">
                            {new Date(scanResult.scanned_at).toLocaleString()}
                          </p>
                        </div>
                        {scanResult.scan_duration_ms && (
                          <div>
                            <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Duration</p>
                            <p className="text-sm text-gray-900 dark:text-white">
                              {(scanResult.scan_duration_ms / 1000).toFixed(2)}s
                            </p>
                          </div>
                        )}
                      </Card.Body>
                    </Card>

                    <Card>
                      <Card.Header>
                        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Vulnerability Distribution</h3>
                      </Card.Header>
                      <Card.Body className="space-y-4">
                        {/* Severity Bars */}
                        <div className="space-y-3">
                          {scanResult.critical > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">Critical</span>
                                <span className="text-sm font-semibold text-red-600 dark:text-red-400">
                                  {scanResult.critical}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-red-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.critical / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                          {scanResult.high > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">High</span>
                                <span className="text-sm font-semibold text-orange-600 dark:text-orange-400">
                                  {scanResult.high}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-orange-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.high / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                          {scanResult.medium > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">Medium</span>
                                <span className="text-sm font-semibold text-yellow-600 dark:text-yellow-400">
                                  {scanResult.medium}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-yellow-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.medium / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                          {scanResult.low > 0 && (
                            <div>
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-sm text-gray-700 dark:text-gray-300">Low</span>
                                <span className="text-sm font-semibold text-blue-600 dark:text-blue-400">
                                  {scanResult.low}
                                </span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-blue-500"
                                  style={{
                                    width: `${Math.max(5, (scanResult.low / scanResult.total) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          )}
                        </div>

                        {/* Summary Stats */}
                        <div className="grid grid-cols-2 gap-4 pt-3 border-t border-gray-200 dark:border-gray-700">
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Total</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-white">
                              {scanResult.total}
                            </p>
                          </div>
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Fixable</p>
                            <p className="text-lg font-semibold text-green-600 dark:text-green-400">
                              {scanResult.fixable}
                            </p>
                          </div>
                        </div>
                      </Card.Body>
                    </Card>

                    {scanResult.total === 0 && (
                      <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                        <div className="flex items-center gap-3">
                          <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0" />
                          <div>
                            <p className="text-sm font-medium text-green-900 dark:text-green-100">
                              No Vulnerabilities Found
                            </p>
                            <p className="text-xs text-green-700 dark:text-green-300 mt-0.5">
                              This image has passed security scanning with zero vulnerabilities.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}

                {panelTab === "scan" && !scanResult && (
                  <EmptyState
                    icon={Shield}
                    title="No Scan Results"
                    description="This deployment hasn't been scanned yet."
                    size="sm"
                  />
                )}

                {/* Vulnerabilities Tab */}
                {panelTab === "vulnerabilities" && (
                  <>
                    <FilterPanel
                      filters={vulnerabilityFilters}
                      onReset={() => setVulnerabilitySeverityFilter([])}
                    />

                    {vulnerabilities && vulnerabilities.length > 0 ? (
                      <div className="space-y-3">
                        {vulnerabilities.map((vuln) => (
                          <Card key={vuln.id}>
                            <Card.Body>
                              <div className="flex items-start justify-between mb-2">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white">
                                    {vuln.cve_id}
                                  </span>
                                  <SeverityBadge
                                    severity={vuln.severity.toLowerCase() as "critical" | "high" | "medium" | "low"}
                                    size="sm"
                                  />
                                  {vuln.cvss_score && (
                                    <span className="text-xs text-gray-600 dark:text-gray-400">
                                      CVSS: {vuln.cvss_score.toFixed(1)}
                                    </span>
                                  )}
                                </div>
                                {vuln.fix_available && (
                                  <Badge variant="status" status="healthy" size="sm">
                                    Fix Available
                                  </Badge>
                                )}
                              </div>

                              {vuln.title && (
                                <p className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                                  {vuln.title}
                                </p>
                              )}

                              <div className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                                <span className="font-semibold">{vuln.package_name}</span>
                                {vuln.package_version && <span> @ {vuln.package_version}</span>}
                                {vuln.fixed_version && (
                                  <span className="text-green-600 dark:text-green-400">
                                    {" "}→ {vuln.fixed_version}
                                  </span>
                                )}
                              </div>

                              {vuln.description && (
                                <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2">
                                  {vuln.description}
                                </p>
                              )}
                            </Card.Body>
                          </Card>
                        ))}
                      </div>
                    ) : (
                      <EmptyState
                        icon={CheckCircle}
                        title="No Vulnerabilities"
                        description={
                          vulnerabilitySeverityFilter.length > 0
                            ? "No vulnerabilities found for this filter."
                            : "No vulnerabilities found in this deployment."
                        }
                        size="sm"
                      />
                    )}
                  </>
                )}

                {/* SBOM Tab */}
                {panelTab === "sbom" && selectedDeployment.sbom_id && sboms && sboms.length > 0 && (
                  <>
                    {sboms
                      .filter((s) => s.id === selectedDeployment.sbom_id)
                      .map((sbom) => (
                        <div key={sbom.id} className="space-y-4">
                          <Card>
                            <Card.Header>
                              <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                                <FileCode className="w-4 h-4" />
                                SBOM Info
                              </h3>
                            </Card.Header>
                            <Card.Body className="space-y-3">
                              <div className="grid grid-cols-2 gap-4 text-sm">
                                <div>
                                  <p className="text-gray-500 dark:text-gray-400 mb-1">Format</p>
                                  <p className="text-gray-900 dark:text-white">{sbom.format.toUpperCase()}</p>
                                </div>
                                <div>
                                  <p className="text-gray-500 dark:text-gray-400 mb-1">Spec Version</p>
                                  <p className="text-gray-900 dark:text-white">{sbom.spec_version}</p>
                                </div>
                              </div>
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Generator</p>
                                <p className="text-sm text-gray-900 dark:text-white">
                                  {sbom.generator_name}
                                  {sbom.generator_version && ` ${sbom.generator_version}`}
                                </p>
                              </div>
                              <div>
                                <p className="text-gray-500 dark:text-gray-400 text-sm mb-1">Generated</p>
                                <p className="text-sm text-gray-900 dark:text-white">
                                  {new Date(sbom.created_at).toLocaleString()}
                                </p>
                              </div>
                            </Card.Body>
                          </Card>

                          <Card>
                            <Card.Header>
                              <h3 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                                <Package className="w-4 h-4" />
                                Package Summary
                              </h3>
                            </Card.Header>
                            <Card.Body className="space-y-3">
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-gray-500 dark:text-gray-400">Total Packages</span>
                                <span className="text-lg font-semibold text-gray-900 dark:text-white">
                                  {sbom.total_packages}
                                </span>
                              </div>
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-gray-500 dark:text-gray-400">OS Packages</span>
                                <span className="text-sm text-gray-900 dark:text-white">{sbom.os_packages}</span>
                              </div>
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-gray-500 dark:text-gray-400">Library Packages</span>
                                <span className="text-sm text-gray-900 dark:text-white">
                                  {sbom.library_packages}
                                </span>
                              </div>
                            </Card.Body>
                          </Card>

                          <button
                            onClick={() => api.downloadSBOM(sbom.id)}
                            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
                          >
                            <Download className="w-4 h-4" />
                            Download SBOM
                          </button>
                        </div>
                      ))}
                  </>
                )}

                {panelTab === "sbom" && !selectedDeployment.sbom_id && (
                  <EmptyState
                    icon={FileCode}
                    title="No SBOM"
                    description="No SBOM has been generated for this deployment."
                    size="sm"
                  />
                )}
              </div>
            </SlideOver.Body>
          </>
        )}
      </SlideOver>
    </>
  );
}
