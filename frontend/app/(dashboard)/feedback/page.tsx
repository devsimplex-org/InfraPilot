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
} from "lucide-react";
import { api, Feedback, VCSConfiguration } from "@/lib/api";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { Card, CardHeader, CardBody } from "@/components/ui/Card";
import { Table } from "@/components/ui/Table";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { Timeline } from "@/components/ui/Timeline";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

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
        return <Shield className="h-4 w-4" />;
      case "policy_violation":
        return <AlertTriangle className="h-4 w-4" />;
      case "sbom":
        return <Package className="h-4 w-4" />;
      case "code_quality":
        return <Code className="h-4 w-4" />;
      case "drift":
        return <Activity className="h-4 w-4" />;
    }
  };

  const getSourceTypeLabel = (sourceType: Feedback["source_type"]) => {
    switch (sourceType) {
      case "vulnerability":
        return "Security";
      case "policy_violation":
        return "Policy";
      case "sbom":
        return "SBOM";
      case "code_quality":
        return "Quality";
      case "drift":
        return "Drift";
    }
  };

  const getFeedbackTypeBadgeColor = (sourceType: Feedback["source_type"]) => {
    switch (sourceType) {
      case "vulnerability":
        return "bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800";
      case "policy_violation":
        return "bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/30 dark:text-orange-400 dark:border-orange-800";
      case "code_quality":
        return "bg-purple-100 text-purple-700 border-purple-200 dark:bg-purple-900/30 dark:text-purple-400 dark:border-purple-800";
      default:
        return "bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:border-blue-800";
    }
  };

  const getSeverityLevel = (severity?: string): "critical" | "high" | "medium" | "low" | "info" => {
    if (!severity) return "info";
    const normalized = severity.toLowerCase();
    if (normalized === "critical") return "critical";
    if (normalized === "high") return "high";
    if (normalized === "medium") return "medium";
    if (normalized === "low") return "low";
    return "info";
  };

  // Table columns for feedback history
  const feedbackColumns = [
    {
      key: "source_type",
      header: "Type",
      width: "120px",
      render: (value: Feedback["source_type"]) => (
        <Badge className={getFeedbackTypeBadgeColor(value)} size="sm">
          {getSourceTypeLabel(value)}
        </Badge>
      ),
    },
    {
      key: "title",
      header: "Title",
      sortable: true,
      render: (value: string, row: Feedback) => (
        <div className="flex items-start gap-2">
          {getSourceTypeIcon(row.source_type)}
          <div className="min-w-0 flex-1">
            <div className="font-medium text-sm truncate">{value}</div>
            <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mt-1">
              <Github className="h-3 w-3" />
              <span className="truncate">{row.repo_full_name}</span>
              {row.pull_request_number && (
                <>
                  <span>•</span>
                  <span>PR #{row.pull_request_number}</span>
                </>
              )}
            </div>
          </div>
        </div>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      width: "100px",
      align: "center" as const,
      render: (value: string | undefined) =>
        value ? <SeverityBadge severity={getSeverityLevel(value)} size="sm" /> : null,
    },
    {
      key: "delivery_status",
      header: "Status",
      width: "120px",
      sortable: true,
      render: (value: Feedback["delivery_status"]) => (
        <div className="flex items-center gap-2">
          {getStatusIcon(value)}
          <span className={cn("text-xs font-medium capitalize", getStatusBadgeClass(value))}>
            {value}
          </span>
        </div>
      ),
    },
    {
      key: "created_at",
      header: "Created",
      width: "100px",
      sortable: true,
      render: (value: string) => (
        <span className="text-xs text-gray-500">
          {new Date(value).toLocaleDateString()}
        </span>
      ),
    },
  ];

  // Recent feedback timeline items (last 5)
  const recentFeedback = feedbacks.slice(0, 5);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Developer Feedback"
        description="Shift-left security feedback delivered to PRs and commits"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Build", href: "/" },
              { label: "Developer Feedback", current: true },
            ]}
          />
        }
      />

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setPageTab("feedback")}
            className={cn(
              "py-2 px-1 border-b-2 font-medium text-sm",
              pageTab === "feedback"
                ? "border-primary-600 text-primary-600 dark:border-primary-400 dark:text-primary-400"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            <div className="flex items-center gap-2">
              <MessageSquare className="h-4 w-4" />
              <span>Feedback History</span>
            </div>
          </button>
          <button
            onClick={() => setPageTab("configuration")}
            className={cn(
              "py-2 px-1 border-b-2 font-medium text-sm",
              pageTab === "configuration"
                ? "border-primary-600 text-primary-600 dark:border-primary-400 dark:text-primary-400"
                : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300"
            )}
          >
            <div className="flex items-center gap-2">
              <Settings className="h-4 w-4" />
              <span>VCS Configuration</span>
            </div>
          </button>
        </nav>
      </div>

      {/* Feedback Tab */}
      {pageTab === "feedback" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Feedback Card */}
          <Card>
            <CardHeader>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Recent Feedback
              </h3>
            </CardHeader>
            <CardBody>
              {loadingFeedback ? (
                <div className="flex items-center justify-center py-12">
                  <Spinner size="lg" label="Loading feedback..." />
                </div>
              ) : recentFeedback.length === 0 ? (
                <EmptyState
                  icon={MessageSquare}
                  title="No feedback yet"
                  description="Feedback will appear here when security findings are sent to developers"
                  size="sm"
                />
              ) : (
                <Timeline>
                  {recentFeedback.map((feedback, index) => (
                    <Timeline.Item
                      key={feedback.id}
                      icon={getSourceTypeIcon(feedback.source_type)}
                      title={feedback.title}
                      description={
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <Badge
                              className={getFeedbackTypeBadgeColor(feedback.source_type)}
                              size="sm"
                            >
                              {getSourceTypeLabel(feedback.source_type)}
                            </Badge>
                            {feedback.severity && (
                              <SeverityBadge severity={getSeverityLevel(feedback.severity)} size="sm" />
                            )}
                          </div>
                          <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                            <Github className="h-3 w-3" />
                            <span>{feedback.repo_full_name}</span>
                            {feedback.pull_request_number && (
                              <>
                                <span>•</span>
                                <span>PR #{feedback.pull_request_number}</span>
                              </>
                            )}
                          </div>
                        </div>
                      }
                      timestamp={new Date(feedback.created_at).toLocaleDateString()}
                      isLast={index === recentFeedback.length - 1}
                    />
                  ))}
                </Timeline>
              )}
            </CardBody>
          </Card>

          {/* Feedback Details Card */}
          <Card>
            <CardHeader>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Feedback Details
              </h3>
            </CardHeader>
            <CardBody>
              {selectedFeedback ? (
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                      {selectedFeedback.title}
                    </h4>
                    <div className="flex items-center gap-2 mb-4">
                      <Badge
                        className={getFeedbackTypeBadgeColor(selectedFeedback.source_type)}
                        size="sm"
                      >
                        {getSourceTypeLabel(selectedFeedback.source_type)}
                      </Badge>
                      {selectedFeedback.severity && (
                        <SeverityBadge severity={getSeverityLevel(selectedFeedback.severity)} size="sm" />
                      )}
                      <div className="flex items-center gap-1">
                        {getStatusIcon(selectedFeedback.delivery_status)}
                        <span
                          className={cn(
                            "text-xs font-medium capitalize",
                            getStatusBadgeClass(selectedFeedback.delivery_status)
                          )}
                        >
                          {selectedFeedback.delivery_status}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-500 dark:text-gray-400">Repository</span>
                      <span className="font-medium">{selectedFeedback.repo_full_name}</span>
                    </div>
                    {selectedFeedback.pull_request_number && (
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Pull Request</span>
                        <a
                          href={`https://github.com/${selectedFeedback.repo_full_name}/pull/${selectedFeedback.pull_request_number}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-1 text-blue-600 hover:underline font-medium"
                        >
                          #{selectedFeedback.pull_request_number}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    )}
                    {selectedFeedback.branch_name && (
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Branch</span>
                        <div className="flex items-center gap-1">
                          <GitBranch className="h-3 w-3" />
                          <span className="font-medium">{selectedFeedback.branch_name}</span>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                    <h5 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2">
                      Message
                    </h5>
                    <div className="bg-gray-50 dark:bg-gray-800 p-3 rounded-md text-xs">
                      <pre className="whitespace-pre-wrap">{selectedFeedback.message}</pre>
                    </div>
                  </div>

                  {selectedFeedback.remediation && (
                    <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                      <h5 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2">
                        Remediation
                      </h5>
                      <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-md text-xs">
                        <pre className="whitespace-pre-wrap">{selectedFeedback.remediation}</pre>
                      </div>
                    </div>
                  )}

                  <button
                    onClick={() => handleDeliverFeedback(selectedFeedback.id)}
                    disabled={
                      deliverFeedbackMutation.isPending ||
                      selectedFeedback.delivery_status === "delivered"
                    }
                    className={cn(
                      "w-full flex items-center justify-center gap-2 px-4 py-2 rounded-md font-medium text-sm",
                      "bg-primary-600 text-white hover:bg-primary-700",
                      "disabled:opacity-50 disabled:cursor-not-allowed",
                      "transition-colors"
                    )}
                  >
                    <Send className="h-4 w-4" />
                    {deliverFeedbackMutation.isPending ? "Delivering..." : "Deliver Feedback"}
                  </button>
                </div>
              ) : (
                <EmptyState
                  icon={MessageSquare}
                  title="Select a feedback"
                  description="Click on a feedback entry in the table below to view details"
                  size="sm"
                />
              )}
            </CardBody>
          </Card>

          {/* Feedback History Table */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader
                action={
                  <div className="flex gap-2">
                    <select
                      value={sourceTypeFilter || ""}
                      onChange={(e) => setSourceTypeFilter(e.target.value || undefined)}
                      className="rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm"
                    >
                      <option value="">All Types</option>
                      <option value="vulnerability">Security</option>
                      <option value="policy_violation">Policy</option>
                      <option value="sbom">SBOM</option>
                      <option value="code_quality">Quality</option>
                      <option value="drift">Drift</option>
                    </select>

                    <select
                      value={statusFilter || ""}
                      onChange={(e) => setStatusFilter(e.target.value || undefined)}
                      className="rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-3 py-1.5 text-sm"
                    >
                      <option value="">All Status</option>
                      <option value="pending">Pending</option>
                      <option value="delivered">Delivered</option>
                      <option value="failed">Failed</option>
                      <option value="skipped">Skipped</option>
                    </select>
                  </div>
                }
              >
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Feedback History
                </h3>
              </CardHeader>
              <div className="overflow-hidden">
                <Table
                  columns={feedbackColumns}
                  data={feedbacks}
                  keyExtractor={(row) => row.id}
                  onRowClick={(row) => setSelectedFeedback(row)}
                  loading={loadingFeedback}
                  emptyState={
                    <EmptyState
                      icon={MessageSquare}
                      title="No feedback yet"
                      description="Feedback will appear here when security findings are sent to developers"
                    />
                  }
                  rowClassName={(row) =>
                    selectedFeedback?.id === row.id
                      ? "bg-primary-50 dark:bg-primary-900/20"
                      : ""
                  }
                />
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* Configuration Tab */}
      {pageTab === "configuration" && (
        <div className="max-w-2xl mx-auto">
          <Card>
            <CardHeader>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                VCS Provider Configuration
              </h3>
            </CardHeader>
            <CardBody>
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
                    Enable {vcsProvider.charAt(0).toUpperCase() + vcsProvider.slice(1)}{" "}
                    integration
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
                    placeholder={
                      vcsProvider === "github" ? "ghp_xxxxxxxxxxxx" : "glpat-xxxxxxxxxxxx"
                    }
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
                  <button
                    onClick={handleSaveVcsConfig}
                    disabled={saveVcsConfigMutation.isPending}
                    className={cn(
                      "w-full px-4 py-2 rounded-md font-medium text-sm",
                      "bg-primary-600 text-white hover:bg-primary-700",
                      "disabled:opacity-50 disabled:cursor-not-allowed",
                      "transition-colors"
                    )}
                  >
                    {saveVcsConfigMutation.isPending ? "Saving..." : "Save Configuration"}
                  </button>
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
            </CardBody>
          </Card>

          {/* Information Panel */}
          <Card className="mt-6 bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
            <CardBody>
              <h4 className="font-semibold text-blue-900 dark:text-blue-200 mb-3">
                How it works
              </h4>
              <ul className="space-y-2 text-sm text-blue-800 dark:text-blue-300">
                <li className="flex items-start gap-2">
                  <CheckCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                  <span>
                    When a deployment is scanned, vulnerabilities and policy violations are detected
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
                  <span>Feedback is delivered as comments on pull requests or commits</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                  <span>
                    Developers see actionable security guidance directly in their workflow
                  </span>
                </li>
              </ul>
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}
