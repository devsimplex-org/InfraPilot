"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Code2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  TrendingUp,
  TrendingDown,
  Minus,
  Bug,
  Shield,
  Clock,
  FileCode,
  GitBranch,
  Plus,
  Trash2,
  Award,
  Target,
} from "lucide-react";
import { PageLayout, ListCard, DetailPanel, EmptyState } from "@/components/ui/page-layout";
import { api, CodeQualityResult, CodeQualityIssue, CodeQualityPolicy, QualityLeaderboard, ProjectQualitySummary } from "@/lib/api";

type PageTab = "overview" | "results" | "policies";

export default function CodeQualityPage() {
  const [pageTab, setPageTab] = useState<PageTab>("overview");
  const [selectedResult, setSelectedResult] = useState<CodeQualityResult | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<CodeQualityPolicy | null>(null);
  const [showCreatePolicyModal, setShowCreatePolicyModal] = useState(false);
  const [toolFilter, setToolFilter] = useState<string>("");
  const [qualityGateFilter, setQualityGateFilter] = useState<string>("");

  const queryClient = useQueryClient();

  // Queries
  const { data: leaderboardData, isLoading: isLoadingLeaderboard } = useQuery({
    queryKey: ["codeQualityLeaderboard"],
    queryFn: () => api.getCodeQualityLeaderboard(),
  });

  const { data: summariesData, isLoading: isLoadingSummaries } = useQuery({
    queryKey: ["projectQualitySummary"],
    queryFn: () => api.getProjectQualitySummary(),
  });

  const { data: resultsData, isLoading: isLoadingResults } = useQuery({
    queryKey: ["codeQualityResults", toolFilter, qualityGateFilter],
    queryFn: () => api.listCodeQualityResults({
      tool: toolFilter || undefined,
      quality_gate: qualityGateFilter || undefined,
      limit: 100,
    }),
  });

  const { data: issuesData } = useQuery({
    queryKey: ["codeQualityIssues", selectedResult?.id],
    queryFn: () => selectedResult ? api.getCodeQualityIssues(selectedResult.id) : Promise.resolve({ issues: [], count: 0 }),
    enabled: !!selectedResult,
  });

  const { data: policiesData, isLoading: isLoadingPolicies } = useQuery({
    queryKey: ["codeQualityPolicies"],
    queryFn: () => api.listCodeQualityPolicies(),
  });

  // Mutations
  const deletePolicyMutation = useMutation({
    mutationFn: (policyId: string) => api.deleteCodeQualityPolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["codeQualityPolicies"] });
      setSelectedPolicy(null);
    },
  });

  const leaderboard = leaderboardData?.leaderboard || [];
  const summaries = summariesData?.summaries || [];
  const results = resultsData?.results || [];
  const issues = issuesData?.issues || [];
  const policies = policiesData?.policies || [];

  // Stats calculations
  const topScore = leaderboard[0]?.quality_score || 0;
  const avgScore = leaderboard.length > 0
    ? Math.round(leaderboard.reduce((sum, item) => sum + item.quality_score, 0) / leaderboard.length)
    : 0;
  const highPerformers = leaderboard.filter(item => item.quality_score >= 80).length;

  // Severity color helper
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "text-red-600 dark:text-red-400";
      case "high": return "text-orange-600 dark:text-orange-400";
      case "medium": return "text-yellow-600 dark:text-yellow-400";
      case "low": return "text-blue-600 dark:text-blue-400";
      default: return "text-gray-600 dark:text-gray-400";
    }
  };

  // Quality score color helper
  const getQualityScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600 dark:text-green-400";
    if (score >= 60) return "text-yellow-600 dark:text-yellow-400";
    if (score >= 40) return "text-orange-600 dark:text-orange-400";
    return "text-red-600 dark:text-red-400";
  };

  // Quality gate badge helper
  const getQualityGateBadge = (gate?: string) => {
    if (!gate) return null;

    const badges = {
      pass: { icon: CheckCircle2, color: "bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300" },
      warn: { icon: AlertTriangle, color: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300" },
      fail: { icon: XCircle, color: "bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300" },
    };

    const badge = badges[gate as keyof typeof badges];
    if (!badge) return null;

    return (
      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium ${badge.color}`}>
        <badge.icon className="h-3 w-3" />
        {gate.toUpperCase()}
      </span>
    );
  };

  // Get rank medal
  const getRankMedal = (rank: number) => {
    if (rank === 1) return "🥇";
    if (rank === 2) return "🥈";
    if (rank === 3) return "🥉";
    return null;
  };

  return (
    <PageLayout
      title="Code Quality"
      description="Static analysis, code quality metrics, and SAST results"
      icon={Code2}
      tabs={[
        { id: "overview", label: "Overview", icon: Award },
        { id: "results", label: "Scan Results", icon: FileCode },
        { id: "policies", label: "Policies", icon: Shield },
      ]}
      activeTab={pageTab}
      onTabChange={(tab) => setPageTab(tab as PageTab)}
    >
      {pageTab === "overview" && (
        <div className="space-y-6">
          {/* Stats Overview */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Total Projects</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                    {leaderboard.length}
                  </p>
                </div>
                <div className="h-12 w-12 bg-blue-100 dark:bg-blue-900 rounded-lg flex items-center justify-center">
                  <Code2 className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Top Score</p>
                  <p className={`text-2xl font-bold mt-1 ${getQualityScoreColor(topScore)}`}>
                    {topScore}
                  </p>
                </div>
                <div className="h-12 w-12 bg-green-100 dark:bg-green-900 rounded-lg flex items-center justify-center">
                  <Award className="h-6 w-6 text-green-600 dark:text-green-400" />
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Average Score</p>
                  <p className={`text-2xl font-bold mt-1 ${getQualityScoreColor(avgScore)}`}>
                    {avgScore}
                  </p>
                </div>
                <div className="h-12 w-12 bg-yellow-100 dark:bg-yellow-900 rounded-lg flex items-center justify-center">
                  <Target className="h-6 w-6 text-yellow-600 dark:text-yellow-400" />
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">High Quality</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white mt-1">
                    {highPerformers}
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Score ≥ 80
                  </p>
                </div>
                <div className="h-12 w-12 bg-purple-100 dark:bg-purple-900 rounded-lg flex items-center justify-center">
                  <CheckCircle2 className="h-6 w-6 text-purple-600 dark:text-purple-400" />
                </div>
              </div>
            </div>
          </div>

          {/* Leaderboard */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Quality Leaderboard</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Projects ranked by quality score</p>
            </div>
            <div className="overflow-x-auto">
              {isLoadingLeaderboard ? (
                <div className="p-12 text-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
                </div>
              ) : leaderboard.length === 0 ? (
                <div className="p-12">
                  <EmptyState
                    icon={Code2}
                    title="No scan results yet"
                    description="Upload code quality results to see the leaderboard"
                  />
                </div>
              ) : (
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead className="bg-gray-50 dark:bg-gray-900">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Rank</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Project</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Tool</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Quality Score</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Coverage</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Issues</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Gate</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                    {leaderboard.map((item, index) => {
                      const rank = index + 1;
                      const medal = getRankMedal(rank);

                      return (
                        <tr key={item.project_key} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <div className="flex items-center gap-2">
                              {medal && <span className="text-xl">{medal}</span>}
                              <span className="font-medium text-gray-900 dark:text-white">{rank}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm font-medium text-gray-900 dark:text-white">
                              {item.project_name || item.project_key}
                            </div>
                            {item.project_name && (
                              <div className="text-xs text-gray-500 dark:text-gray-400">{item.project_key}</div>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded text-xs font-medium">
                              {item.tool}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className={`text-2xl font-bold ${getQualityScoreColor(item.quality_score)}`}>
                              {item.quality_score}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                            {item.coverage !== null && item.coverage !== undefined
                              ? `${item.coverage.toFixed(1)}%`
                              : "N/A"}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm">
                            <div className="flex items-center gap-2">
                              {item.critical_issues > 0 && (
                                <span className="px-2 py-1 bg-red-100 dark:bg-red-900 text-red-700 dark:text-red-300 rounded text-xs font-medium">
                                  {item.critical_issues} Critical
                                </span>
                              )}
                              {item.high_issues > 0 && (
                                <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900 text-orange-700 dark:text-orange-300 rounded text-xs font-medium">
                                  {item.high_issues} High
                                </span>
                              )}
                              {item.critical_issues === 0 && item.high_issues === 0 && (
                                <span className="text-gray-500 dark:text-gray-400">{item.total_issues} total</span>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            {getQualityGateBadge(item.quality_gate || undefined)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      )}

      {pageTab === "results" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Results List */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-2 mb-3">
                <FileCode className="h-5 w-5 text-gray-500" />
                <h3 className="font-semibold text-gray-900 dark:text-white">Scan Results</h3>
              </div>

              {/* Filters */}
              <div className="space-y-2 mb-4">
                <select
                  value={toolFilter}
                  onChange={(e) => setToolFilter(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
                >
                  <option value="">All Tools</option>
                  <option value="semgrep">Semgrep</option>
                  <option value="sonarqube">SonarQube</option>
                  <option value="eslint">ESLint</option>
                  <option value="golangci-lint">golangci-lint</option>
                  <option value="pylint">Pylint</option>
                </select>

                <select
                  value={qualityGateFilter}
                  onChange={(e) => setQualityGateFilter(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-white text-sm"
                >
                  <option value="">All Gates</option>
                  <option value="pass">Pass</option>
                  <option value="warn">Warn</option>
                  <option value="fail">Fail</option>
                </select>
              </div>

              {isLoadingResults ? (
                <div className="py-12 text-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
                </div>
              ) : results.length === 0 ? (
                <EmptyState
                  icon={FileCode}
                  title="No results"
                  description="No scan results match your filters"
                />
              ) : (
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {results.map((result) => (
                    <ListCard
                      key={result.id}
                      selected={selectedResult?.id === result.id}
                      onClick={() => setSelectedResult(result)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Code2 className="h-4 w-4 text-gray-400 flex-shrink-0" />
                            <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                              {result.project_name || result.project_key}
                            </p>
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs font-medium text-gray-700 dark:text-gray-300">
                              {result.tool}
                            </span>
                            {getQualityGateBadge(result.quality_gate || undefined)}
                          </div>
                          {result.commit_sha && (
                            <div className="flex items-center gap-1 mt-1">
                              <GitBranch className="h-3 w-3 text-gray-400" />
                              <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                                {result.commit_sha.substring(0, 7)}
                              </span>
                            </div>
                          )}
                        </div>
                        <div className="ml-2 flex-shrink-0 text-right">
                          {result.critical_issues > 0 && (
                            <span className="text-xs font-semibold text-red-600 dark:text-red-400">
                              {result.critical_issues} Critical
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                        {new Date(result.created_at).toLocaleDateString()} at{" "}
                        {new Date(result.created_at).toLocaleTimeString()}
                      </div>
                    </ListCard>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Result Detail */}
          <div className="lg:col-span-2">
            {!selectedResult ? (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12">
                <EmptyState
                  icon={FileCode}
                  title="Select a scan result"
                  description="Choose a scan result from the list to view details"
                />
              </div>
            ) : (
              <DetailPanel title={selectedResult.project_name || selectedResult.project_key}>
                <div className="space-y-6">
                  {/* Summary */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Scan Summary</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">Bugs</p>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedResult.bugs}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">Vulnerabilities</p>
                        <p className="text-lg font-semibold text-red-600 dark:text-red-400">{selectedResult.vulnerabilities}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">Code Smells</p>
                        <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedResult.code_smells}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500 dark:text-gray-400">Hotspots</p>
                        <p className="text-lg font-semibold text-orange-600 dark:text-orange-400">{selectedResult.security_hotspots}</p>
                      </div>
                    </div>
                  </div>

                  {/* Severity Breakdown */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Issues by Severity</h4>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                      <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3">
                        <p className="text-xs text-red-700 dark:text-red-400">Critical</p>
                        <p className="text-xl font-bold text-red-700 dark:text-red-400">{selectedResult.critical_issues}</p>
                      </div>
                      <div className="bg-orange-50 dark:bg-orange-900/20 rounded-lg p-3">
                        <p className="text-xs text-orange-700 dark:text-orange-400">High</p>
                        <p className="text-xl font-bold text-orange-700 dark:text-orange-400">{selectedResult.high_issues}</p>
                      </div>
                      <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-3">
                        <p className="text-xs text-yellow-700 dark:text-yellow-400">Medium</p>
                        <p className="text-xl font-bold text-yellow-700 dark:text-yellow-400">{selectedResult.medium_issues}</p>
                      </div>
                      <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3">
                        <p className="text-xs text-blue-700 dark:text-blue-400">Low</p>
                        <p className="text-xl font-bold text-blue-700 dark:text-blue-400">{selectedResult.low_issues}</p>
                      </div>
                      <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                        <p className="text-xs text-gray-700 dark:text-gray-400">Info</p>
                        <p className="text-xl font-bold text-gray-700 dark:text-gray-400">{selectedResult.info_issues}</p>
                      </div>
                    </div>
                  </div>

                  {/* Metrics */}
                  {(selectedResult.coverage !== null || selectedResult.complexity !== null || selectedResult.duplication !== null) && (
                    <div>
                      <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Quality Metrics</h4>
                      <div className="grid grid-cols-3 gap-4">
                        {selectedResult.coverage !== null && selectedResult.coverage !== undefined && (
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Code Coverage</p>
                            <div className="flex items-baseline gap-1">
                              <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedResult.coverage.toFixed(1)}</p>
                              <span className="text-sm text-gray-500">%</span>
                            </div>
                          </div>
                        )}
                        {selectedResult.complexity !== null && selectedResult.complexity !== undefined && (
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Complexity</p>
                            <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedResult.complexity.toFixed(1)}</p>
                          </div>
                        )}
                        {selectedResult.duplication !== null && selectedResult.duplication !== undefined && (
                          <div>
                            <p className="text-xs text-gray-500 dark:text-gray-400">Duplication</p>
                            <div className="flex items-baseline gap-1">
                              <p className="text-lg font-semibold text-gray-900 dark:text-white">{selectedResult.duplication.toFixed(1)}</p>
                              <span className="text-sm text-gray-500">%</span>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Metadata */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Scan Metadata</h4>
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Tool:</span>
                        <span className="font-medium text-gray-900 dark:text-white">{selectedResult.tool} {selectedResult.tool_version}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Project Key:</span>
                        <span className="font-mono text-xs text-gray-900 dark:text-white">{selectedResult.project_key}</span>
                      </div>
                      {selectedResult.commit_sha && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Commit:</span>
                          <span className="font-mono text-xs text-gray-900 dark:text-white">{selectedResult.commit_sha}</span>
                        </div>
                      )}
                      {selectedResult.git_branch && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Branch:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedResult.git_branch}</span>
                        </div>
                      )}
                      {selectedResult.lines_of_code && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Lines of Code:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedResult.lines_of_code.toLocaleString()}</span>
                        </div>
                      )}
                      {selectedResult.files_analyzed && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Files Analyzed:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedResult.files_analyzed}</span>
                        </div>
                      )}
                      {selectedResult.scan_duration_ms && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Scan Duration:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{(selectedResult.scan_duration_ms / 1000).toFixed(1)}s</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Issues */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                      Issues ({issues.length})
                    </h4>
                    {issues.length === 0 ? (
                      <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                        No detailed issues available
                      </div>
                    ) : (
                      <div className="space-y-2 max-h-[400px] overflow-y-auto">
                        {issues.map((issue) => (
                          <div
                            key={issue.id}
                            className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border border-gray-200 dark:border-gray-700"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className={`text-xs font-semibold uppercase ${getSeverityColor(issue.severity)}`}>
                                    {issue.severity}
                                  </span>
                                  <span className="text-xs text-gray-500 dark:text-gray-400">
                                    {issue.issue_type}
                                  </span>
                                </div>
                                <p className="text-sm font-medium text-gray-900 dark:text-white mt-1">
                                  {issue.message}
                                </p>
                                <div className="flex items-center gap-1 mt-1">
                                  <FileCode className="h-3 w-3 text-gray-400" />
                                  <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                                    {issue.file_path}
                                    {issue.start_line && `:${issue.start_line}`}
                                  </span>
                                </div>
                                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                  Rule: {issue.rule_id}
                                </p>
                              </div>
                              {issue.fix_available && (
                                <div className="flex-shrink-0">
                                  <span className="px-2 py-1 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded text-xs font-medium">
                                    Fix Available
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </DetailPanel>
            )}
          </div>
        </div>
      )}

      {pageTab === "policies" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Policies List */}
          <div className="lg:col-span-1 space-y-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-gray-500" />
                  <h3 className="font-semibold text-gray-900 dark:text-white">Quality Policies</h3>
                </div>
                <button
                  onClick={() => setShowCreatePolicyModal(true)}
                  className="p-2 text-primary-600 hover:bg-primary-50 dark:hover:bg-primary-900/20 rounded-lg"
                >
                  <Plus className="h-4 w-4" />
                </button>
              </div>

              {isLoadingPolicies ? (
                <div className="py-12 text-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
                </div>
              ) : policies.length === 0 ? (
                <EmptyState
                  icon={Shield}
                  title="No policies"
                  description="Create policies to enforce code quality gates"
                />
              ) : (
                <div className="space-y-2">
                  {policies.map((policy) => (
                    <ListCard
                      key={policy.id}
                      selected={selectedPolicy?.id === policy.id}
                      onClick={() => setSelectedPolicy(policy)}
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                            {policy.name}
                          </p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                              policy.enabled
                                ? "bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300"
                                : "bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300"
                            }`}>
                              {policy.enabled ? "Enabled" : "Disabled"}
                            </span>
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              {policy.enforcement}
                            </span>
                          </div>
                        </div>
                      </div>
                    </ListCard>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Policy Detail */}
          <div className="lg:col-span-2">
            {!selectedPolicy ? (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12">
                <EmptyState
                  icon={Shield}
                  title="Select a policy"
                  description="Choose a policy from the list to view details"
                />
              </div>
            ) : (
              <DetailPanel
                title={selectedPolicy.name}
                actions={
                  <button
                    onClick={() => {
                      if (confirm("Are you sure you want to delete this policy?")) {
                        deletePolicyMutation.mutate(selectedPolicy.id);
                      }
                    }}
                    className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                }
              >
                <div className="space-y-6">
                  {selectedPolicy.description && (
                    <div>
                      <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Description</h4>
                      <p className="text-sm text-gray-600 dark:text-gray-400">{selectedPolicy.description}</p>
                    </div>
                  )}

                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Enforcement</h4>
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Mode:</span>
                        <span className="font-medium text-gray-900 dark:text-white capitalize">{selectedPolicy.enforcement}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Block Deployment:</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                          {selectedPolicy.block_deployment ? "Yes" : "No"}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-500 dark:text-gray-400">Status:</span>
                        <span className={`font-medium ${selectedPolicy.enabled ? "text-green-600" : "text-gray-600"}`}>
                          {selectedPolicy.enabled ? "Enabled" : "Disabled"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Thresholds</h4>
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 space-y-2 text-sm">
                      {selectedPolicy.max_critical !== null && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Max Critical:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedPolicy.max_critical}</span>
                        </div>
                      )}
                      {selectedPolicy.max_high !== null && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Max High:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedPolicy.max_high}</span>
                        </div>
                      )}
                      {selectedPolicy.max_vulnerabilities !== null && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Max Vulnerabilities:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedPolicy.max_vulnerabilities}</span>
                        </div>
                      )}
                      {selectedPolicy.min_coverage !== null && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Min Coverage:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedPolicy.min_coverage}%</span>
                        </div>
                      )}
                      {selectedPolicy.max_complexity !== null && (
                        <div className="flex justify-between">
                          <span className="text-gray-500 dark:text-gray-400">Max Complexity:</span>
                          <span className="font-medium text-gray-900 dark:text-white">{selectedPolicy.max_complexity}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Scope</h4>
                    <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 space-y-3 text-sm">
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Environments:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {selectedPolicy.environments.length === 0 ? (
                            <span className="text-gray-600 dark:text-gray-400 italic">All</span>
                          ) : (
                            selectedPolicy.environments.map((env) => (
                              <span key={env} className="px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 rounded text-xs">
                                {env}
                              </span>
                            ))
                          )}
                        </div>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Projects:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {selectedPolicy.projects.length === 0 ? (
                            <span className="text-gray-600 dark:text-gray-400 italic">All</span>
                          ) : (
                            selectedPolicy.projects.map((proj) => (
                              <span key={proj} className="px-2 py-1 bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 rounded text-xs">
                                {proj}
                              </span>
                            ))
                          )}
                        </div>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400">Tools:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {selectedPolicy.tools.length === 0 ? (
                            <span className="text-gray-600 dark:text-gray-400 italic">All</span>
                          ) : (
                            selectedPolicy.tools.map((tool) => (
                              <span key={tool} className="px-2 py-1 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded text-xs">
                                {tool}
                              </span>
                            ))
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </DetailPanel>
            )}
          </div>
        </div>
      )}
    </PageLayout>
  );
}
