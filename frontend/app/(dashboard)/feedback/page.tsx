"use client";

import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  MessageSquare,
  Github,
  GitBranch,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Send,
  Settings,
  Shield,
  Package,
  Code,
  Activity,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { api, Feedback, VCSConfiguration } from "@/lib/api";
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

type PageTab = "feedback" | "configuration";

export default function FeedbackPage() {
  const queryClient = useQueryClient();
  const [pageTab, setPageTab] = useState<PageTab>("feedback");
  const [selectedFeedback, setSelectedFeedback] = useState<Feedback | null>(null);
  const [sourceTypeFilter, setSourceTypeFilter] = useState<string | undefined>();
  const [statusFilter, setStatusFilter] = useState<string | undefined>();

  // VCS Configuration state
  const [vcsProvider, setVcsProvider] = useState<"github" | "gitlab">("github");
  const [vcsEnabled, setVcsEnabled] = useState(false);
  const [vcsToken, setVcsToken] = useState("");
  const [vcsDefaultRepo, setVcsDefaultRepo] = useState("");
  const [vcsAutoCommentPR, setVcsAutoCommentPR] = useState(true);
  const [vcsAutoCommentCommit, setVcsAutoCommentCommit] = useState(false);

  // Fetch feedback list
  const { data: feedbackData, isLoading: loadingFeedback } = useQuery({
    queryKey: ["feedback", sourceTypeFilter, statusFilter],
    queryFn: () =>
      api.listFeedback({
        source_type: sourceTypeFilter,
        status: statusFilter,
      }),
    enabled: pageTab === "feedback",
    refetchInterval: 10000, // Refresh every 10s
  });

  // Fetch VCS configuration
  const { data: vcsConfig, isLoading: loadingVcsConfig } = useQuery({
    queryKey: ["vcsConfig", vcsProvider],
    queryFn: () => api.getVCSConfig(vcsProvider),
    enabled: pageTab === "configuration",
  });

  // Load VCS config into form when fetched
  useEffect(() => {
    if (vcsConfig) {
      setVcsEnabled(vcsConfig.enabled);
      setVcsDefaultRepo(vcsConfig.default_repo || "");
      setVcsAutoCommentPR(vcsConfig.auto_comment_on_pr);
      setVcsAutoCommentCommit(vcsConfig.auto_comment_on_commit);
    }
  }, [vcsConfig]);

  // Deliver feedback mutation
  const deliverFeedbackMutation = useMutation({
    mutationFn: (feedbackId: string) => api.deliverFeedback(feedbackId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feedback"] });
      setSelectedFeedback(null);
    },
  });

  // Save VCS configuration mutation
  const saveVcsConfigMutation = useMutation({
    mutationFn: (config: {
      provider: string;
      enabled: boolean;
      token?: string;
      default_repo?: string;
      auto_comment_on_pr: boolean;
      auto_comment_on_commit: boolean;
    }) => api.saveVCSConfig(config.provider, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vcsConfig"] });
      setVcsToken(""); // Clear token after save
    },
  });

  const feedbacks = feedbackData?.feedbacks || [];

  const handleDeliverFeedback = (feedbackId: string) => {
    if (confirm("Manually deliver this feedback to the VCS provider?")) {
      deliverFeedbackMutation.mutate(feedbackId);
    }
  };

  const handleSaveVcsConfig = () => {
    saveVcsConfigMutation.mutate({
      provider: vcsProvider,
      enabled: vcsEnabled,
      token: vcsToken || undefined,
      default_repo: vcsDefaultRepo || undefined,
      auto_comment_on_pr: vcsAutoCommentPR,
      auto_comment_on_commit: vcsAutoCommentCommit,
    });
  };

  const getStatusIcon = (status: Feedback["delivery_status"]) => {
    switch (status) {
      case "delivered":
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case "failed":
        return <XCircle className="h-4 w-4 text-red-600" />;
      case "pending":
        return <Clock className="h-4 w-4 text-yellow-600" />;
      case "skipped":
        return <AlertTriangle className="h-4 w-4 text-gray-600" />;
    }
  };

  const getStatusBadgeClass = (status: Feedback["delivery_status"]) => {
    switch (status) {
      case "delivered":
        return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400";
      case "failed":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
      case "pending":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
      case "skipped":
        return "bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-400";
    }
  };

  const getSourceTypeIcon = (sourceType: Feedback["source_type"]) => {
    switch (sourceType) {
      case "vulnerability":
        return <Shield className="h-4 w-4 text-red-600" />;
      case "policy_violation":
        return <AlertTriangle className="h-4 w-4 text-orange-600" />;
      case "sbom":
        return <Package className="h-4 w-4 text-blue-600" />;
      case "code_quality":
        return <Code className="h-4 w-4 text-purple-600" />;
      case "drift":
        return <Activity className="h-4 w-4 text-yellow-600" />;
    }
  };

  const getSourceTypeLabel = (sourceType: Feedback["source_type"]) => {
    switch (sourceType) {
      case "vulnerability":
        return "Vulnerability";
      case "policy_violation":
        return "Policy Violation";
      case "sbom":
        return "SBOM";
      case "code_quality":
        return "Code Quality";
      case "drift":
        return "Drift";
    }
  };

  return (
    <PageLayout
      title="Developer Feedback"
      subtitle="Shift-left security feedback delivered to PRs and commits"
      icon={<MessageSquare className="h-8 w-8" />}
    >
      <Tabs
        tabs={[
          { id: "feedback", label: "Feedback History", icon: MessageSquare },
          { id: "configuration", label: "VCS Configuration", icon: Settings },
        ]}
        activeTab={pageTab}
        onChange={(tab) => setPageTab(tab as PageTab)}
      />

      {pageTab === "feedback" && (
        <div className="flex flex-col lg:flex-row gap-6 h-full">
          {/* Feedback List */}
          <div className="lg:w-1/2">
            <div className="mb-4 flex gap-2">
              <select
                value={sourceTypeFilter || ""}
                onChange={(e) => setSourceTypeFilter(e.target.value || undefined)}
                className="rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
              >
                <option value="">All Types</option>
                <option value="vulnerability">Vulnerability</option>
                <option value="policy_violation">Policy Violation</option>
                <option value="sbom">SBOM</option>
                <option value="code_quality">Code Quality</option>
                <option value="drift">Drift</option>
              </select>

              <select
                value={statusFilter || ""}
                onChange={(e) => setStatusFilter(e.target.value || undefined)}
                className="rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2 text-sm"
              >
                <option value="">All Status</option>
                <option value="pending">Pending</option>
                <option value="delivered">Delivered</option>
                <option value="failed">Failed</option>
                <option value="skipped">Skipped</option>
              </select>
            </div>

            {loadingFeedback ? (
              <div className="flex items-center justify-center h-64">
                <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
              </div>
            ) : feedbacks.length === 0 ? (
              <EmptyState
                icon={MessageSquare}
                title="No feedback yet"
                description="Feedback will appear here when security findings are sent to developers"
              />
            ) : (
              <div className="space-y-2">
                {feedbacks.map((feedback) => (
                  <ListCard
                    key={feedback.id}
                    selected={selectedFeedback?.id === feedback.id}
                    onClick={() => setSelectedFeedback(feedback)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          {getSourceTypeIcon(feedback.source_type)}
                          <span className="font-medium text-sm truncate">
                            {feedback.title}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400">
                          <Github className="h-3 w-3" />
                          <span className="truncate">{feedback.repo_full_name}</span>
                          {feedback.pull_request_number && (
                            <>
                              <span>•</span>
                              <span>PR #{feedback.pull_request_number}</span>
                            </>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-1 ml-4">
                        <div className="flex items-center gap-1">
                          {getStatusIcon(feedback.delivery_status)}
                          <span
                            className={cn(
                              "px-2 py-0.5 text-xs font-medium rounded-full",
                              getStatusBadgeClass(feedback.delivery_status)
                            )}
                          >
                            {feedback.delivery_status}
                          </span>
                        </div>
                        <span className="text-xs text-gray-500">
                          {new Date(feedback.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </ListCard>
                ))}
              </div>
            )}
          </div>

          {/* Feedback Detail */}
          <div className="lg:w-1/2">
            {selectedFeedback ? (
              <DetailPanel
                title={selectedFeedback.title}
                onClose={() => setSelectedFeedback(null)}
              >
                <DetailSection title="Status">
                  <DetailRow label="Delivery Status">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(selectedFeedback.delivery_status)}
                      <span
                        className={cn(
                          "px-2 py-0.5 text-xs font-medium rounded-full",
                          getStatusBadgeClass(selectedFeedback.delivery_status)
                        )}
                      >
                        {selectedFeedback.delivery_status}
                      </span>
                    </div>
                  </DetailRow>
                  {selectedFeedback.delivered_at && (
                    <DetailRow label="Delivered At">
                      {new Date(selectedFeedback.delivered_at).toLocaleString()}
                    </DetailRow>
                  )}
                  {selectedFeedback.delivery_error && (
                    <DetailRow label="Error">
                      <span className="text-red-600 text-sm">
                        {selectedFeedback.delivery_error}
                      </span>
                    </DetailRow>
                  )}
                </DetailSection>

                <DetailSection title="Target">
                  <DetailRow label="Provider">
                    <div className="flex items-center gap-2">
                      {selectedFeedback.provider === "github" && (
                        <Github className="h-4 w-4" />
                      )}
                      <span className="capitalize">{selectedFeedback.provider}</span>
                    </div>
                  </DetailRow>
                  <DetailRow label="Repository">
                    {selectedFeedback.repo_full_name}
                  </DetailRow>
                  {selectedFeedback.pull_request_number && (
                    <DetailRow label="Pull Request">
                      <a
                        href={`https://github.com/${selectedFeedback.repo_full_name}/pull/${selectedFeedback.pull_request_number}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-blue-600 hover:underline"
                      >
                        #{selectedFeedback.pull_request_number}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </DetailRow>
                  )}
                  {selectedFeedback.commit_sha && (
                    <DetailRow label="Commit">
                      <code className="text-xs bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                        {selectedFeedback.commit_sha.substring(0, 7)}
                      </code>
                    </DetailRow>
                  )}
                  {selectedFeedback.branch_name && (
                    <DetailRow label="Branch">
                      <div className="flex items-center gap-1">
                        <GitBranch className="h-3 w-3" />
                        <span className="text-sm">{selectedFeedback.branch_name}</span>
                      </div>
                    </DetailRow>
                  )}
                </DetailSection>

                <DetailSection title="Content">
                  <DetailRow label="Source Type">
                    <div className="flex items-center gap-2">
                      {getSourceTypeIcon(selectedFeedback.source_type)}
                      <span>{getSourceTypeLabel(selectedFeedback.source_type)}</span>
                    </div>
                  </DetailRow>
                  {selectedFeedback.severity && (
                    <DetailRow label="Severity">
                      <span className="uppercase text-xs font-semibold">
                        {selectedFeedback.severity}
                      </span>
                    </DetailRow>
                  )}
                  <div className="border-t border-gray-200 dark:border-gray-700 my-4" />
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-medium text-sm mb-2">Message</h4>
                      <div className="prose prose-sm dark:prose-invert max-w-none bg-gray-50 dark:bg-gray-900 p-3 rounded-md">
                        <pre className="whitespace-pre-wrap text-xs">
                          {selectedFeedback.message}
                        </pre>
                      </div>
                    </div>
                    {selectedFeedback.remediation && (
                      <div>
                        <h4 className="font-medium text-sm mb-2">Remediation</h4>
                        <div className="prose prose-sm dark:prose-invert max-w-none bg-blue-50 dark:bg-blue-900/20 p-3 rounded-md">
                          <pre className="whitespace-pre-wrap text-xs">
                            {selectedFeedback.remediation}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                </DetailSection>

                <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                  <Button
                    onClick={() => handleDeliverFeedback(selectedFeedback.id)}
                    disabled={
                      deliverFeedbackMutation.isPending ||
                      selectedFeedback.delivery_status === "delivered"
                    }
                    className="w-full"
                  >
                    <Send className="h-4 w-4 mr-2" />
                    {deliverFeedbackMutation.isPending
                      ? "Delivering..."
                      : "Deliver Feedback"}
                  </Button>
                </div>
              </DetailPanel>
            ) : (
              <EmptyState
                icon={MessageSquare}
                title="Select a feedback"
                description="Click on a feedback entry to view details"
              />
            )}
          </div>
        </div>
      )}

      {pageTab === "configuration" && (
        <div className="max-w-2xl mx-auto">
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold mb-4">VCS Provider Configuration</h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
              Configure how InfraPilot delivers security feedback to your version control system.
            </p>

            <div className="space-y-6">
              {/* Provider Selection */}
              <div>
                <label className="block text-sm font-medium mb-2">Provider</label>
                <select
                  value={vcsProvider}
                  onChange={(e) => setVcsProvider(e.target.value as "github" | "gitlab")}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                >
                  <option value="github">GitHub</option>
                  <option value="gitlab">GitLab</option>
                </select>
              </div>

              {/* Enabled Toggle */}
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="vcs-enabled"
                  checked={vcsEnabled}
                  onChange={(e) => setVcsEnabled(e.target.checked)}
                  className="rounded"
                />
                <label htmlFor="vcs-enabled" className="text-sm font-medium">
                  Enable {vcsProvider.charAt(0).toUpperCase() + vcsProvider.slice(1)} integration
                </label>
              </div>

              {/* Access Token */}
              <div>
                <label className="block text-sm font-medium mb-2">
                  Access Token {vcsConfig && "(leave empty to keep existing)"}
                </label>
                <input
                  type="password"
                  value={vcsToken}
                  onChange={(e) => setVcsToken(e.target.value)}
                  placeholder={vcsProvider === "github" ? "ghp_xxxxxxxxxxxx" : "glpat-xxxxxxxxxxxx"}
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
                <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                  {vcsProvider === "github"
                    ? "Personal access token with repo and pull_request scopes"
                    : "Personal access token with api scope"}
                </p>
              </div>

              {/* Default Repository */}
              <div>
                <label className="block text-sm font-medium mb-2">
                  Default Repository (optional)
                </label>
                <input
                  type="text"
                  value={vcsDefaultRepo}
                  onChange={(e) => setVcsDefaultRepo(e.target.value)}
                  placeholder="owner/repository"
                  className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-2"
                />
              </div>

              {/* Auto-comment Options */}
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    id="auto-comment-pr"
                    checked={vcsAutoCommentPR}
                    onChange={(e) => setVcsAutoCommentPR(e.target.checked)}
                    className="rounded"
                  />
                  <label htmlFor="auto-comment-pr" className="text-sm">
                    Automatically comment on pull requests
                  </label>
                </div>

                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    id="auto-comment-commit"
                    checked={vcsAutoCommentCommit}
                    onChange={(e) => setVcsAutoCommentCommit(e.target.checked)}
                    className="rounded"
                  />
                  <label htmlFor="auto-comment-commit" className="text-sm">
                    Automatically comment on commits
                  </label>
                </div>
              </div>

              {/* Save Button */}
              <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                <Button
                  onClick={handleSaveVcsConfig}
                  disabled={saveVcsConfigMutation.isPending}
                  className="w-full"
                >
                  {saveVcsConfigMutation.isPending
                    ? "Saving..."
                    : "Save Configuration"}
                </Button>
              </div>

              {saveVcsConfigMutation.isSuccess && (
                <div className="p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-md">
                  <p className="text-sm text-green-800 dark:text-green-200">
                    Configuration saved successfully!
                  </p>
                </div>
              )}

              {saveVcsConfigMutation.isError && (
                <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                  <p className="text-sm text-red-800 dark:text-red-200">
                    Failed to save configuration. Please try again.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Information Panel */}
          <div className="mt-6 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800 p-6">
            <h4 className="font-semibold text-blue-900 dark:text-blue-200 mb-2">
              How it works
            </h4>
            <ul className="space-y-2 text-sm text-blue-800 dark:text-blue-300">
              <li className="flex items-start gap-2">
                <CheckCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <span>
                  When a deployment is scanned, vulnerabilities and policy violations are
                  detected
                </span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <span>
                  InfraPilot automatically generates developer-friendly feedback messages
                </span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <span>
                  Feedback is delivered as comments on pull requests or commits
                </span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <span>
                  Developers see actionable security guidance directly in their workflow
                </span>
              </li>
            </ul>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
