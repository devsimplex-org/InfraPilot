"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Package,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  GitBranch,
  FileCode,
  ExternalLink,
  RefreshCw,
  Download,
  Eye,
  ChevronRight,
} from "lucide-react";
import { api, Deployment, ScanResult, Vulnerability, SBOM } from "@/lib/api";
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

type PanelTab = "overview" | "scan" | "vulnerabilities" | "sbom";

export default function DeploymentsPage() {
  const queryClient = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [selectedDeployment, setSelectedDeployment] = useState<Deployment | null>(null);
  const [panelTab, setPanelTab] = useState<PanelTab>("overview");
  const [vulnerabilitySeverityFilter, setVulnerabilitySeverityFilter] = useState<string | undefined>();

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
    refetchInterval: 10000, // Refresh every 10s to see scan progress
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
            severity: vulnerabilitySeverityFilter,
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

  const getStatusBadgeClass = (status: Deployment["status"]) => {
    switch (status) {
      case "running":
        return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400";
      case "failed":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
      case "scanning":
      case "policy_check":
      case "deploying":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
      case "pending":
        return "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400";
      case "rolled_back":
        return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400";
      case "stopped":
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400";
      default:
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400";
    }
  };

  const getPolicyDecisionBadge = (decision?: "allow" | "warn" | "deny") => {
    if (!decision) return null;

    const config = {
      allow: {
        className: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
        label: "Allowed"
      },
      warn: {
        className: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
        label: "Warning"
      },
      deny: {
        className: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
        label: "Blocked"
      },
    };

    const { className, label } = config[decision];
    return (
      <span className={cn("px-2 py-0.5 text-xs font-medium rounded-full", className)}>
        {label}
      </span>
    );
  };

  const getSeverityColor = (severity: Vulnerability["severity"]) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
      case "high":
        return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400";
      case "medium":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
      case "low":
        return "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400";
      default:
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400";
    }
  };

  return (
    <PageLayout
      title="Deployments"
      description="Manage and monitor deployments with security scanning"
      actions={
        <div className="flex gap-2">
          {activeAgents.length > 1 && (
            <select
              value={selectedAgent || ""}
              onChange={(e) => {
                setSelectedAgent(e.target.value);
                setSelectedDeployment(null);
              }}
              className="rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
            >
              {activeAgents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name}
                </option>
              ))}
            </select>
          )}
          <Button
            variant="secondary"
            onClick={() =>
              queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] })
            }
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
        </div>
      }
      panel={
        <DetailPanel
          open={!!selectedDeployment}
          onClose={() => setSelectedDeployment(null)}
          title={selectedDeployment?.service_name}
          subtitle={selectedDeployment?.environment}
        >
          {selectedDeployment && (
            <>
            <Tabs
              tabs={[
                { id: "overview", label: "Overview" },
                { id: "scan", label: "Scan Results", count: scanResult?.total_count },
                { id: "vulnerabilities", label: "Vulnerabilities", count: vulnerabilities?.length },
                { id: "sbom", label: "SBOM" },
              ]}
              activeTab={panelTab}
              onChange={(id) => setPanelTab(id as PanelTab)}
            />

            <div className="mt-4 space-y-6">
              {panelTab === "overview" && (
                <>
                  {/* Quick Actions */}
                  {selectedDeployment.sbom_id && (
                    <DetailSection title="Quick Actions">
                      <div className="grid grid-cols-1 gap-2">
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => api.downloadSBOM(selectedDeployment.sbom_id!)}
                        >
                          <Download className="w-4 h-4 mr-2" />
                          Download SBOM
                        </Button>
                        {selectedDeployment.scan_result_id && (
                          <Button
                            variant="secondary"
                            size="sm"
                            onClick={() => setPanelTab("scan")}
                          >
                            <Shield className="w-4 h-4 mr-2" />
                            View Scan Results
                          </Button>
                        )}
                      </div>
                    </DetailSection>
                  )}

                  <DetailSection title="Deployment Info">
                    <DetailRow label="Service" value={selectedDeployment.service_name} />
                    <DetailRow label="Environment" value={selectedDeployment.environment} />
                    <DetailRow
                      label="Status"
                      value={
                        <span className={cn(
                          "px-2 py-0.5 text-xs font-medium rounded-full capitalize",
                          getStatusBadgeClass(selectedDeployment.status)
                        )}>
                          {selectedDeployment.status}
                        </span>
                      }
                    />
                    {selectedDeployment.status_message && (
                      <DetailRow label="Message" value={selectedDeployment.status_message} />
                    )}
                    {selectedDeployment.policy_decision && (
                      <DetailRow
                        label="Policy"
                        value={getPolicyDecisionBadge(selectedDeployment.policy_decision)}
                      />
                    )}
                    {selectedDeployment.policy_reason && (
                      <DetailRow label="Policy Reason" value={selectedDeployment.policy_reason} />
                    )}
                  </DetailSection>

                  <DetailSection title="Image">
                    <DetailRow
                      label="Repository"
                      value={selectedDeployment.image_repository}
                      mono
                    />
                    {selectedDeployment.image_tag && (
                      <DetailRow label="Tag" value={selectedDeployment.image_tag} mono />
                    )}
                    {selectedDeployment.image_digest && (
                      <DetailRow
                        label="Digest"
                        value={selectedDeployment.image_digest.substring(0, 20) + "..."}
                        mono
                      />
                    )}
                  </DetailSection>

                  {(selectedDeployment.git_repo || selectedDeployment.git_commit) && (
                    <DetailSection title="Git Info">
                      {selectedDeployment.git_repo && (
                        <DetailRow label="Repository" value={selectedDeployment.git_repo} mono />
                      )}
                      {selectedDeployment.git_branch && (
                        <DetailRow label="Branch" value={selectedDeployment.git_branch} mono />
                      )}
                      {selectedDeployment.git_commit && (
                        <DetailRow
                          label="Commit"
                          value={selectedDeployment.git_commit.substring(0, 8)}
                          mono
                        />
                      )}
                    </DetailSection>
                  )}

                  {(selectedDeployment.ci_provider || selectedDeployment.ci_pipeline_id) && (
                    <DetailSection title="CI/CD">
                      {selectedDeployment.ci_provider && (
                        <DetailRow label="Provider" value={selectedDeployment.ci_provider} />
                      )}
                      {selectedDeployment.ci_pipeline_id && (
                        <DetailRow
                          label="Pipeline ID"
                          value={selectedDeployment.ci_pipeline_id}
                          mono
                        />
                      )}
                      {selectedDeployment.ci_build_url && (
                        <DetailRow
                          label="Build URL"
                          value={
                            <a
                              href={selectedDeployment.ci_build_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-primary-600 hover:text-primary-700 flex items-center gap-1"
                            >
                              View Build
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          }
                        />
                      )}
                    </DetailSection>
                  )}

                  <DetailSection title="Metadata">
                    <DetailRow
                      label="Created"
                      value={new Date(selectedDeployment.created_at).toLocaleString()}
                    />
                    {selectedDeployment.deployed_at && (
                      <DetailRow
                        label="Deployed"
                        value={new Date(selectedDeployment.deployed_at).toLocaleString()}
                      />
                    )}
                  </DetailSection>
                </>
              )}

              {panelTab === "scan" && scanResult && (
                <>
                  <DetailSection title="Scan Summary">
                    <DetailRow label="Scanner" value={scanResult.scanner_name} />
                    {scanResult.scanner_version && (
                      <DetailRow label="Version" value={scanResult.scanner_version} />
                    )}
                    <DetailRow
                      label="Scanned"
                      value={new Date(scanResult.scanned_at).toLocaleString()}
                    />
                    {scanResult.scan_duration_ms && (
                      <DetailRow
                        label="Duration"
                        value={`${(scanResult.scan_duration_ms / 1000).toFixed(2)}s`}
                      />
                    )}
                  </DetailSection>

                  <DetailSection title="Vulnerability Distribution">
                    <div className="space-y-3">
                      {/* Visual bars */}
                      <div className="space-y-2">
                        {scanResult.critical_count > 0 && (
                          <div>
                            <div className="flex items-center justify-between text-sm mb-1">
                              <span className="text-gray-700 dark:text-gray-300">Critical</span>
                              <span className="font-semibold text-red-600 dark:text-red-400">
                                {scanResult.critical_count}
                              </span>
                            </div>
                            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-red-500"
                                style={{
                                  width: `${Math.max(5, (scanResult.critical_count / scanResult.total_count) * 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        )}
                        {scanResult.high_count > 0 && (
                          <div>
                            <div className="flex items-center justify-between text-sm mb-1">
                              <span className="text-gray-700 dark:text-gray-300">High</span>
                              <span className="font-semibold text-orange-600 dark:text-orange-400">
                                {scanResult.high_count}
                              </span>
                            </div>
                            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-orange-500"
                                style={{
                                  width: `${Math.max(5, (scanResult.high_count / scanResult.total_count) * 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        )}
                        {scanResult.medium_count > 0 && (
                          <div>
                            <div className="flex items-center justify-between text-sm mb-1">
                              <span className="text-gray-700 dark:text-gray-300">Medium</span>
                              <span className="font-semibold text-yellow-600 dark:text-yellow-400">
                                {scanResult.medium_count}
                              </span>
                            </div>
                            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-yellow-500"
                                style={{
                                  width: `${Math.max(5, (scanResult.medium_count / scanResult.total_count) * 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        )}
                        {scanResult.low_count > 0 && (
                          <div>
                            <div className="flex items-center justify-between text-sm mb-1">
                              <span className="text-gray-700 dark:text-gray-300">Low</span>
                              <span className="font-semibold text-blue-600 dark:text-blue-400">
                                {scanResult.low_count}
                              </span>
                            </div>
                            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className="h-full bg-blue-500"
                                style={{
                                  width: `${Math.max(5, (scanResult.low_count / scanResult.total_count) * 100)}%`,
                                }}
                              />
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Summary stats */}
                      <div className="pt-3 border-t border-gray-200 dark:border-gray-700 grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">Total</p>
                          <p className="text-lg font-semibold text-gray-900 dark:text-white">
                            {scanResult.total_count}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500 dark:text-gray-400">Fixable</p>
                          <p className="text-lg font-semibold text-green-600 dark:text-green-400">
                            {scanResult.fixable_count}
                          </p>
                        </div>
                      </div>
                    </div>
                  </DetailSection>

                  {scanResult.total_count === 0 && (
                    <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                      <div className="flex items-center gap-3">
                        <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
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
                />
              )}

              {panelTab === "vulnerabilities" && (
                <>
                  <div className="flex gap-2 flex-wrap">
                    <Button
                      variant={vulnerabilitySeverityFilter === undefined ? "primary" : "secondary"}
                      size="sm"
                      onClick={() => setVulnerabilitySeverityFilter(undefined)}
                    >
                      All
                    </Button>
                    <Button
                      variant={vulnerabilitySeverityFilter === "CRITICAL" ? "primary" : "secondary"}
                      size="sm"
                      onClick={() => setVulnerabilitySeverityFilter("CRITICAL")}
                    >
                      Critical
                    </Button>
                    <Button
                      variant={vulnerabilitySeverityFilter === "HIGH" ? "primary" : "secondary"}
                      size="sm"
                      onClick={() => setVulnerabilitySeverityFilter("HIGH")}
                    >
                      High
                    </Button>
                    <Button
                      variant={vulnerabilitySeverityFilter === "MEDIUM" ? "primary" : "secondary"}
                      size="sm"
                      onClick={() => setVulnerabilitySeverityFilter("MEDIUM")}
                    >
                      Medium
                    </Button>
                    <Button
                      variant={vulnerabilitySeverityFilter === "LOW" ? "primary" : "secondary"}
                      size="sm"
                      onClick={() => setVulnerabilitySeverityFilter("LOW")}
                    >
                      Low
                    </Button>
                  </div>

                  {vulnerabilities && vulnerabilities.length > 0 ? (
                    <div className="space-y-3">
                      {vulnerabilities.map((vuln) => (
                        <div
                          key={vuln.id}
                          className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg"
                        >
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-sm font-semibold">
                                {vuln.cve_id}
                              </span>
                              <span
                                className={cn(
                                  "px-2 py-0.5 rounded text-xs font-medium uppercase",
                                  getSeverityColor(vuln.severity)
                                )}
                              >
                                {vuln.severity}
                              </span>
                              {vuln.cvss_score && (
                                <span className="text-xs text-gray-600 dark:text-gray-400">
                                  CVSS: {vuln.cvss_score.toFixed(1)}
                                </span>
                              )}
                            </div>
                            {vuln.fix_available && (
                              <span className="text-xs px-2 py-1 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded">
                                Fix Available
                              </span>
                            )}
                          </div>

                          {vuln.title && (
                            <p className="text-sm font-medium mb-1">{vuln.title}</p>
                          )}

                          <div className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                            <span className="font-semibold">{vuln.package_name}</span>
                            {vuln.package_version && <span> @ {vuln.package_version}</span>}
                            {vuln.fixed_version && (
                              <span className="text-green-600 dark:text-green-400">
                                {" "}
                                → {vuln.fixed_version}
                              </span>
                            )}
                          </div>

                          {vuln.description && (
                            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2">
                              {vuln.description}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <EmptyState
                      icon={CheckCircle}
                      title="No Vulnerabilities"
                      description="No vulnerabilities found for this filter."
                    />
                  )}
                </>
              )}

              {panelTab === "sbom" && selectedDeployment.sbom_id && sboms && sboms.length > 0 && (
                <>
                  {sboms
                    .filter((s) => s.id === selectedDeployment.sbom_id)
                    .map((sbom) => (
                      <div key={sbom.id}>
                        <DetailSection title="SBOM Info">
                          <DetailRow label="Format" value={sbom.format.toUpperCase()} />
                          <DetailRow label="Spec Version" value={sbom.spec_version} />
                          <DetailRow label="Generator" value={sbom.generator_name} />
                          {sbom.generator_version && (
                            <DetailRow label="Version" value={sbom.generator_version} />
                          )}
                          <DetailRow
                            label="Generated"
                            value={new Date(sbom.created_at).toLocaleString()}
                          />
                        </DetailSection>

                        <DetailSection title="Package Summary">
                          <DetailRow
                            label="Total Packages"
                            value={<span className="font-semibold">{sbom.total_packages}</span>}
                          />
                          <DetailRow label="OS Packages" value={sbom.os_packages} />
                          <DetailRow label="Library Packages" value={sbom.library_packages} />
                        </DetailSection>

                        <div className="mt-4">
                          <Button
                            variant="primary"
                            onClick={() => api.downloadSBOM(sbom.id)}
                            className="w-full"
                          >
                            <Download className="w-4 h-4 mr-2" />
                            Download SBOM
                          </Button>
                        </div>
                      </div>
                    ))}
                </>
              )}

              {panelTab === "sbom" && !selectedDeployment.sbom_id && (
                <EmptyState
                  icon={FileCode}
                  title="No SBOM"
                  description="No SBOM has been generated for this deployment."
                />
              )}
            </div>
            </>
          )}
        </DetailPanel>
      }
      panelOpen={!!selectedDeployment}
    >
      <div className="space-y-4">
        {isLoading && (
          <div className="text-center py-12 text-gray-500">Loading deployments...</div>
        )}

        {!isLoading && (!deployments || deployments.length === 0) && (
          <EmptyState
            icon={Package}
            title="No Deployments"
            description="No deployments found for this agent."
          />
        )}

        {deployments && deployments.length > 0 && (
          <>
            {deployments.map((deployment) => (
              <ListCard
                key={deployment.id}
                selected={selectedDeployment?.id === deployment.id}
                onClick={() => setSelectedDeployment(deployment)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <Shield className="w-5 h-5 text-gray-400 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="text-sm font-medium truncate">
                          {deployment.service_name}
                        </h3>
                        <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 rounded">
                          {deployment.environment}
                        </span>
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate">
                        {deployment.image_repository}
                        {deployment.image_tag && `:${deployment.image_tag}`}
                      </p>
                      {deployment.git_commit && (
                        <div className="flex items-center gap-1 mt-1">
                          <GitBranch className="w-3 h-3 text-gray-400" />
                          <span className="text-xs text-gray-500 font-mono">
                            {deployment.git_commit.substring(0, 8)}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-3 ml-4">
                    <div className="text-right">
                      <span className={cn(
                        "px-2 py-0.5 text-xs font-medium rounded-full capitalize",
                        getStatusBadgeClass(deployment.status)
                      )}>
                        {deployment.status}
                      </span>
                      {deployment.policy_decision && (
                        <div className="mt-1">{getPolicyDecisionBadge(deployment.policy_decision)}</div>
                      )}
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-400" />
                  </div>
                </div>
              </ListCard>
            ))}
          </>
        )}
      </div>
    </PageLayout>
  );
}
