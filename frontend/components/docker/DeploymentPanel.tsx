"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Package,
  Copy,
  Check,
  ExternalLink,
  RotateCcw,
  Trash2,
  Shield,
  GitBranch,
  Container,
  Clock,
  User,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { api, Deployment } from "@/lib/api";
import { useDocker } from "@/lib/docker-context";
import { Badge } from "@/components/ui/Badge";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { SlideOver } from "@/components/ui/SlideOver";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { RedeployWizard } from "@/components/RedeployWizard";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

export function DeploymentPanel() {
  const queryClient = useQueryClient();
  const { selectedAgent, deploymentPanelId, closeDeploymentPanel, openContainerPanel } = useDocker();

  // Local state
  const [tab, setTab] = useState<"details" | "policy" | "git">("details");
  const [copied, setCopied] = useState<string | null>(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showRedeployWizard, setShowRedeployWizard] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(["status"]));

  // Reset tab when panel opens
  useEffect(() => {
    if (deploymentPanelId) {
      setTab("details");
    }
  }, [deploymentPanelId]);

  // Fetch deployment details
  const { data: deployment, isLoading: deploymentLoading } = useQuery({
    queryKey: ["deployment-detail", selectedAgent, deploymentPanelId],
    queryFn: async () => {
      if (!selectedAgent || !deploymentPanelId) return null;
      const deployments = await api.getDeployments(selectedAgent);
      return deployments.find((d) => d.id === deploymentPanelId) || null;
    },
    enabled: !!selectedAgent && !!deploymentPanelId,
  });

  // Redeploy mutation
  const redeployMutation = useMutation({
    mutationFn: ({ pullLatest, skipScanning }: { pullLatest: boolean; skipScanning: boolean }) => {
      if (!selectedAgent || !deployment) throw new Error("No agent or deployment");
      return api.redeployDeployment(selectedAgent, deployment.id, pullLatest, skipScanning);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] });
      queryClient.invalidateQueries({ queryKey: ["deployment-detail", selectedAgent, deploymentPanelId] });
      setShowRedeployWizard(false);
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: () => {
      if (!selectedAgent || !deployment) throw new Error("No agent or deployment");
      return api.deleteDeployment(selectedAgent, deployment.id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["deployments", selectedAgent] });
      setShowDeleteModal(false);
      closeDeploymentPanel();
    },
  });

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const toggleSection = (section: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  };

  const getStatusLevel = (status: Deployment["status"]): "healthy" | "warning" | "degraded" | "critical" => {
    switch (status) {
      case "running": return "healthy";
      case "failed": return "critical";
      case "scanning":
      case "policy_check":
      case "deploying": return "warning";
      default: return "degraded";
    }
  };

  const getPolicyIcon = (decision?: "allow" | "warn" | "deny") => {
    switch (decision) {
      case "allow": return <CheckCircle className="h-5 w-5 text-green-500" />;
      case "warn": return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case "deny": return <XCircle className="h-5 w-5 text-red-500" />;
      default: return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return "—";
    return new Date(dateString).toLocaleString();
  };

  const isProtected = deployment?.status === "running";

  return (
    <>
      <SlideOver isOpen={!!deploymentPanelId} onClose={closeDeploymentPanel} size="lg">
        {deploymentLoading ? (
          <div className="flex items-center justify-center h-64">
            <Spinner.Logo size="lg" />
          </div>
        ) : deployment ? (
          <>
            <SlideOver.Header onClose={closeDeploymentPanel}>
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-gray-100 dark:bg-gray-800">
                  <Package className="h-5 w-5 text-gray-500" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {deployment.service_name || "Unnamed Deployment"}
                  </h2>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
                    {deployment.image_repository}:{deployment.image_tag || "latest"}
                  </p>
                </div>
              </div>
            </SlideOver.Header>
            <SlideOver.Body>
              {/* Tabs */}
              <div className="flex gap-2 mb-6 border-b border-gray-200 dark:border-gray-700">
                <button
                  onClick={() => setTab("details")}
                  className={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    tab === "details"
                      ? "border-primary-600 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                  )}
                >
                  Details
                </button>
                <button
                  onClick={() => setTab("policy")}
                  className={cn(
                    "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                    tab === "policy"
                      ? "border-primary-600 text-primary-600 dark:text-primary-400"
                      : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                  )}
                >
                  Policy
                </button>
                {(deployment.git_repo || deployment.ci_provider) && (
                  <button
                    onClick={() => setTab("git")}
                    className={cn(
                      "px-4 py-2 text-sm font-medium border-b-2 transition-colors",
                      tab === "git"
                        ? "border-primary-600 text-primary-600 dark:text-primary-400"
                        : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
                    )}
                  >
                    Source
                  </button>
                )}
              </div>

              {tab === "details" && (
                <div className="space-y-6">
                  {/* Actions */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Actions</h3>
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => setShowRedeployWizard(true)}
                        className="px-3 py-1.5 text-sm bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 rounded-lg hover:bg-blue-200 dark:hover:bg-blue-900/50"
                      >
                        <RotateCcw className="h-4 w-4 inline mr-1" />Redeploy
                      </button>
                      {deployment.container_id && (
                        <button
                          onClick={() => {
                            openContainerPanel(deployment.container_id!);
                            closeDeploymentPanel();
                          }}
                          className="px-3 py-1.5 text-sm bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400 rounded-lg hover:bg-green-200 dark:hover:bg-green-900/50"
                        >
                          <Container className="h-4 w-4 inline mr-1" />View Container
                        </button>
                      )}
                      <button
                        onClick={() => setShowDeleteModal(true)}
                        disabled={isProtected}
                        className="px-3 py-1.5 text-sm bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 rounded-lg hover:bg-red-200 dark:hover:bg-red-900/50 disabled:opacity-50"
                        title={isProtected ? "Stop container first" : undefined}
                      >
                        <Trash2 className="h-4 w-4 inline mr-1" />Delete
                      </button>
                    </div>
                  </div>

                  {/* Status Section */}
                  <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg overflow-hidden">
                    <button
                      onClick={() => toggleSection("status")}
                      className="w-full flex items-center justify-between p-4 hover:bg-gray-100 dark:hover:bg-gray-700/50"
                    >
                      <h4 className="text-sm font-semibold text-gray-900 dark:text-white flex items-center gap-2">
                        Status
                      </h4>
                      {expandedSections.has("status") ? (
                        <ChevronDown className="h-4 w-4 text-gray-500" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-gray-500" />
                      )}
                    </button>
                    {expandedSections.has("status") && (
                      <div className="px-4 pb-4 space-y-3">
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Status</span>
                          <StatusIndicator
                            status={getStatusLevel(deployment.status)}
                            label={deployment.status?.replace(/_/g, " ") || "unknown"}
                            pulse={deployment.status === "running" || deployment.status === "scanning"}
                          />
                        </div>
                        {deployment.status_message && (
                          <div className="flex justify-between">
                            <span className="text-sm text-gray-500 dark:text-gray-400">Message</span>
                            <span className="text-sm text-gray-900 dark:text-white max-w-[250px] text-right">
                              {deployment.status_message}
                            </span>
                          </div>
                        )}
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Environment</span>
                          <Badge size="sm">{deployment.environment || "—"}</Badge>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Deployment Info */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Deployment Info</h3>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Deployment ID</span>
                        <div className="flex items-center gap-1">
                          <code className="text-sm">{deployment.id.slice(0, 12)}</code>
                          <button
                            onClick={() => handleCopy(deployment.id, "deployment-id")}
                            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                          >
                            {copied === "deployment-id" ? (
                              <Check className="h-3 w-3 text-green-500" />
                            ) : (
                              <Copy className="h-3 w-3 text-gray-400" />
                            )}
                          </button>
                        </div>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Image</span>
                        <span className="text-sm text-gray-900 dark:text-white truncate max-w-[200px] font-mono">
                          {deployment.image_repository}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Tag</span>
                        <Badge size="sm" color="blue">{deployment.image_tag || "latest"}</Badge>
                      </div>
                      {deployment.image_digest && (
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Digest</span>
                          <div className="flex items-center gap-1">
                            <code className="text-xs text-gray-600 dark:text-gray-400">
                              {deployment.image_digest.slice(0, 20)}...
                            </code>
                            <button
                              onClick={() => handleCopy(deployment.image_digest!, "digest")}
                              className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                            >
                              {copied === "digest" ? (
                                <Check className="h-3 w-3 text-green-500" />
                              ) : (
                                <Copy className="h-3 w-3 text-gray-400" />
                              )}
                            </button>
                          </div>
                        </div>
                      )}
                      {deployment.container_name && (
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Container</span>
                          <div className="flex items-center gap-2">
                            <Container className="h-4 w-4 text-green-500" />
                            <span className="text-sm font-mono text-gray-900 dark:text-white">
                              {deployment.container_name}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Timestamps */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Timeline</h3>
                    <div className="space-y-3">
                      <div className="flex justify-between">
                        <span className="text-sm text-gray-500 dark:text-gray-400 flex items-center gap-1">
                          <Clock className="h-3 w-3" /> Created
                        </span>
                        <span className="text-sm text-gray-900 dark:text-white">{formatDate(deployment.created_at)}</span>
                      </div>
                      {deployment.deployed_at && (
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400 flex items-center gap-1">
                            <Clock className="h-3 w-3" /> Deployed
                          </span>
                          <span className="text-sm text-gray-900 dark:text-white">{formatDate(deployment.deployed_at)}</span>
                        </div>
                      )}
                      {deployment.deployed_by && (
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400 flex items-center gap-1">
                            <User className="h-3 w-3" /> Deployed By
                          </span>
                          <span className="text-sm text-gray-900 dark:text-white">{deployment.deployed_by}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {tab === "policy" && (
                <div className="space-y-6">
                  {/* Policy Decision */}
                  <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                    <div className="flex items-center gap-3 mb-4">
                      {getPolicyIcon(deployment.policy_decision)}
                      <div>
                        <h4 className="text-sm font-semibold text-gray-900 dark:text-white">
                          {deployment.policy_decision === "allow" && "Deployment Allowed"}
                          {deployment.policy_decision === "warn" && "Deployment Warning"}
                          {deployment.policy_decision === "deny" && "Deployment Blocked"}
                          {!deployment.policy_decision && "Policy Pending"}
                        </h4>
                        {deployment.policy_reason && (
                          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                            {deployment.policy_reason}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Security Scan */}
                  <div>
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Security Scan</h3>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-gray-500 dark:text-gray-400">Scan Status</span>
                        {deployment.scan_result_id ? (
                          <div className="flex items-center gap-1">
                            <Shield className="w-4 h-4 text-green-500" />
                            <span className="text-sm text-green-600 dark:text-green-400">Completed</span>
                          </div>
                        ) : deployment.status === "scanning" ? (
                          <div className="flex items-center gap-1">
                            <RotateCcw className="w-4 h-4 text-yellow-500 animate-spin" />
                            <span className="text-sm text-yellow-600 dark:text-yellow-400">Scanning...</span>
                          </div>
                        ) : (
                          <span className="text-sm text-gray-400">Not scanned</span>
                        )}
                      </div>
                      {deployment.scan_result_id && (
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Scan Result ID</span>
                          <code className="text-xs text-gray-600 dark:text-gray-400">
                            {deployment.scan_result_id.slice(0, 12)}...
                          </code>
                        </div>
                      )}
                      {deployment.sbom_id && (
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400">SBOM ID</span>
                          <code className="text-xs text-gray-600 dark:text-gray-400">
                            {deployment.sbom_id.slice(0, 12)}...
                          </code>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {tab === "git" && (
                <div className="space-y-6">
                  {/* Git Info */}
                  {deployment.git_repo && (
                    <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                        <GitBranch className="h-4 w-4" />
                        Git Source
                      </h4>
                      <div className="space-y-3">
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Repository</span>
                          <span className="text-sm text-gray-900 dark:text-white font-mono truncate max-w-[250px]">
                            {deployment.git_repo}
                          </span>
                        </div>
                        {deployment.git_branch && (
                          <div className="flex justify-between">
                            <span className="text-sm text-gray-500 dark:text-gray-400">Branch</span>
                            <Badge size="sm">{deployment.git_branch}</Badge>
                          </div>
                        )}
                        {deployment.git_commit && (
                          <div className="flex justify-between">
                            <span className="text-sm text-gray-500 dark:text-gray-400">Commit</span>
                            <div className="flex items-center gap-1">
                              <code className="text-sm">{deployment.git_commit.slice(0, 8)}</code>
                              <button
                                onClick={() => handleCopy(deployment.git_commit!, "commit")}
                                className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
                              >
                                {copied === "commit" ? (
                                  <Check className="h-3 w-3 text-green-500" />
                                ) : (
                                  <Copy className="h-3 w-3 text-gray-400" />
                                )}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* CI/CD Info */}
                  {deployment.ci_provider && (
                    <div className="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center gap-2">
                        <ExternalLink className="h-4 w-4" />
                        CI/CD Pipeline
                      </h4>
                      <div className="space-y-3">
                        <div className="flex justify-between">
                          <span className="text-sm text-gray-500 dark:text-gray-400">Provider</span>
                          <Badge size="sm">{deployment.ci_provider}</Badge>
                        </div>
                        {deployment.ci_pipeline_id && (
                          <div className="flex justify-between">
                            <span className="text-sm text-gray-500 dark:text-gray-400">Pipeline ID</span>
                            <code className="text-sm">{deployment.ci_pipeline_id}</code>
                          </div>
                        )}
                        {deployment.ci_build_url && (
                          <div className="flex justify-between">
                            <span className="text-sm text-gray-500 dark:text-gray-400">Build URL</span>
                            <a
                              href={deployment.ci_build_url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sm text-primary-600 dark:text-primary-400 hover:underline flex items-center gap-1"
                            >
                              View Build <ExternalLink className="h-3 w-3" />
                            </a>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </SlideOver.Body>
          </>
        ) : (
          <div className="flex items-center justify-center h-64 text-gray-500">
            <p className="text-sm">Deployment not found</p>
          </div>
        )}
      </SlideOver>

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteModal && !!deployment}
        onClose={() => setShowDeleteModal(false)}
        onConfirm={() => deleteMutation.mutate()}
        title="Delete Deployment"
        message={`Are you sure you want to delete the deployment for ${deployment?.service_name || "this service"}? This will only remove the deployment record, not the running container.`}
        confirmText="Delete Deployment"
        variant="danger"
        icon="delete"
        isLoading={deleteMutation.isPending}
      />

      {/* Redeploy Wizard */}
      <RedeployWizard
        isOpen={showRedeployWizard}
        deployment={deployment || null}
        onClose={() => setShowRedeployWizard(false)}
        onConfirm={(pullLatest, skipScanning) => {
          redeployMutation.mutate({ pullLatest, skipScanning });
        }}
        isLoading={redeployMutation.isPending}
      />
    </>
  );
}
