"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Code2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  FileCode,
  GitBranch,
  Award,
  Target,
  Bug,
  Shield,
} from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SeverityBadge } from "@/components/ui/Badge";
import { api, CodeQualityResult, CodeQualityIssue } from "@/lib/api";

type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export default function CodeQualityPage() {
  const [selectedResult, setSelectedResult] = useState<CodeQualityResult | null>(null);
  const [selectedIssue, setSelectedIssue] = useState<CodeQualityIssue | null>(null);
  const [showIssueSlideOver, setShowIssueSlideOver] = useState(false);

  // Filter states
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [filePathFilter, setFilePathFilter] = useState("");
  const [ruleTypeFilter, setRuleTypeFilter] = useState<string[]>([]);
  const [toolFilter, setToolFilter] = useState("");
  const [qualityGateFilter, setQualityGateFilter] = useState("");

  // Queries
  const { data: leaderboardData, isLoading: isLoadingLeaderboard } = useQuery({
    queryKey: ["codeQualityLeaderboard"],
    queryFn: () => api.getCodeQualityLeaderboard(),
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

  const leaderboard = leaderboardData?.leaderboard || [];
  const results = resultsData?.results || [];
  const issues = issuesData?.issues || [];

  // Calculate metrics
  const selectedResultData = selectedResult || results[0];
  const criticalIssues = selectedResultData?.critical_issues || 0;
  const codeCoverage = selectedResultData?.coverage || 0;
  const technicalDebt = selectedResultData?.code_smells || 0;
  // Calculate quality score from available metrics
  const qualityScore = selectedResultData ? (() => {
    // Base score starts at 100 and reduces based on issues
    let score = 100;
    score -= (selectedResultData.critical_issues || 0) * 10;
    score -= (selectedResultData.high_issues || 0) * 5;
    score -= (selectedResultData.medium_issues || 0) * 2;
    score -= (selectedResultData.low_issues || 0) * 1;
    // Factor in coverage if available
    if (selectedResultData.coverage !== undefined) {
      score = Math.round((score + selectedResultData.coverage) / 2);
    }
    return Math.max(0, Math.min(100, score));
  })() : 0;

  // Filter issues
  const filteredIssues = issues.filter((issue) => {
    const severityMatch = severityFilter.length === 0 || severityFilter.includes(issue.severity.toLowerCase());
    const fileMatch = filePathFilter === "" || issue.file_path.toLowerCase().includes(filePathFilter.toLowerCase());
    const ruleMatch = ruleTypeFilter.length === 0 || ruleTypeFilter.includes(issue.issue_type);
    return severityMatch && fileMatch && ruleMatch;
  });

  // Table columns
  const issueColumns = [
    {
      key: "severity",
      header: "Severity",
      sortable: true,
      width: "120px",
      render: (value: string) => (
        <SeverityBadge severity={value.toLowerCase() as SeverityLevel} size="sm" />
      ),
    },
    {
      key: "message",
      header: "Issue",
      sortable: true,
      render: (value: string, row: CodeQualityIssue) => (
        <div>
          <p className="text-sm font-medium text-gray-900 dark:text-white">{value}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            Rule: {row.rule_id}
          </p>
        </div>
      ),
    },
    {
      key: "file_path",
      header: "File Path",
      sortable: true,
      render: (value: string, row: CodeQualityIssue) => (
        <div className="flex items-center gap-1">
          <FileCode className="h-4 w-4 text-gray-400 flex-shrink-0" />
          <span className="text-xs font-mono text-gray-700 dark:text-gray-300 truncate">
            {value}{row.start_line ? `:${row.start_line}` : ""}
          </span>
        </div>
      ),
    },
    {
      key: "issue_type",
      header: "Type",
      sortable: true,
      width: "120px",
      render: (value: string) => (
        <span className="px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded text-xs font-medium text-gray-700 dark:text-gray-300">
          {value}
        </span>
      ),
    },
  ];

  // Filter configuration
  const filters = [
    {
      id: "severity",
      label: "Severity",
      type: "checkbox" as const,
      options: [
        { label: "Critical", value: "critical", count: issues.filter(i => i.severity.toLowerCase() === "critical").length },
        { label: "High", value: "high", count: issues.filter(i => i.severity.toLowerCase() === "high").length },
        { label: "Medium", value: "medium", count: issues.filter(i => i.severity.toLowerCase() === "medium").length },
        { label: "Low", value: "low", count: issues.filter(i => i.severity.toLowerCase() === "low").length },
        { label: "Info", value: "info", count: issues.filter(i => i.severity.toLowerCase() === "info").length },
      ],
      value: severityFilter,
      onChange: (value: string | string[]) => setSeverityFilter(value as string[]),
    },
    {
      id: "filePath",
      label: "File Path",
      type: "search" as const,
      value: filePathFilter,
      onChange: (value: string | string[]) => setFilePathFilter(value as string),
    },
    {
      id: "ruleType",
      label: "Rule Type",
      type: "checkbox" as const,
      options: Array.from(new Set(issues.map(i => i.issue_type))).map(type => ({
        label: type,
        value: type,
        count: issues.filter(i => i.issue_type === type).length,
      })),
      value: ruleTypeFilter,
      onChange: (value: string | string[]) => setRuleTypeFilter(value as string[]),
    },
  ];

  const handleResetFilters = () => {
    setSeverityFilter([]);
    setFilePathFilter("");
    setRuleTypeFilter([]);
  };

  const handleIssueClick = (issue: CodeQualityIssue) => {
    setSelectedIssue(issue);
    setShowIssueSlideOver(true);
  };

  // Get quality score color
  const getQualityScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600 dark:text-green-400";
    if (score >= 60) return "text-yellow-600 dark:text-yellow-400";
    if (score >= 40) return "text-orange-600 dark:text-orange-400";
    return "text-red-600 dark:text-red-400";
  };

  const calculateQualityScore = (result: CodeQualityResult) => {
    let score = 100;
    score -= (result.critical_issues || 0) * 10;
    score -= (result.high_issues || 0) * 5;
    score -= (result.medium_issues || 0) * 2;
    score -= (result.low_issues || 0) * 1;
    if (result.coverage !== undefined) {
      score = Math.round((score + result.coverage) / 2);
    }
    return Math.max(0, Math.min(100, score));
  };

  const getTotalIssues = (result: CodeQualityResult) => {
    return (result.critical_issues || 0) + (result.high_issues || 0) +
           (result.medium_issues || 0) + (result.low_issues || 0) + (result.info_issues || 0);
  };

  return (
    <div className="space-y-6">
      {/* Section 1: Header with Breadcrumb */}
      <PageHeader
        title="Code Quality"
        description="Static analysis, code quality metrics, and SAST findings"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Build", href: "/build" },
              { label: "Code Quality", current: true },
            ]}
          />
        }
      />

      {/* Section 2: Metrics Grid */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Critical Issues"
          value={criticalIssues}
          icon={AlertTriangle}
          iconColor="text-red-600"
          valueColor={criticalIssues > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}
          description={criticalIssues === 0 ? "Great work!" : "Requires attention"}
        />
        <StatCard
          label="Code Coverage"
          value={`${codeCoverage.toFixed(1)}%`}
          icon={Target}
          iconColor="text-blue-600"
          valueColor={getQualityScoreColor(codeCoverage)}
        />
        <StatCard
          label="Technical Debt"
          value={technicalDebt}
          icon={Bug}
          iconColor="text-orange-600"
          valueColor="text-gray-900 dark:text-white"
          description="Code smells detected"
        />
        <StatCard
          label="Quality Score"
          value={qualityScore}
          icon={Award}
          iconColor="text-purple-600"
          valueColor={getQualityScoreColor(qualityScore)}
        />
      </MetricsGrid>

      {/* Section 3: SAST Findings with Filters */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Filter Panel */}
        <div className="lg:col-span-1">
          <FilterPanel
            filters={filters}
            onReset={handleResetFilters}
          />
        </div>

        {/* Findings Table */}
        <div className="lg:col-span-3">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                SAST Findings ({filteredIssues.length})
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Security and quality issues detected in your codebase
              </p>
            </div>

            {isLoadingResults ? (
              <div className="p-12 flex justify-center">
                <Spinner size="lg" label="Loading findings..." />
              </div>
            ) : filteredIssues.length === 0 ? (
              <div className="p-12">
                <EmptyState
                  icon={CheckCircle2}
                  title="No issues found - great work!"
                  description={issues.length === 0
                    ? "Your code is clean and secure"
                    : "Try adjusting your filters to see more results"
                  }
                  size="md"
                />
              </div>
            ) : (
              <Table
                columns={issueColumns}
                data={filteredIssues}
                keyExtractor={(row) => row.id}
                onRowClick={handleIssueClick}
                hoverable
                containerClassName="rounded-b-lg"
              />
            )}
          </div>
        </div>
      </div>

      {/* Section 4: Scan Results Selection */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Scan Results
              </h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                View results from different scan runs
              </p>
            </div>
            <div className="flex gap-2">
              <select
                value={toolFilter}
                onChange={(e) => setToolFilter(e.target.value)}
                className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm"
              >
                <option value="">All Tools</option>
                <option value="semgrep">Semgrep</option>
                <option value="sonarqube">SonarQube</option>
                <option value="eslint">ESLint</option>
                <option value="golangci-lint">golangci-lint</option>
              </select>
              <select
                value={qualityGateFilter}
                onChange={(e) => setQualityGateFilter(e.target.value)}
                className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm"
              >
                <option value="">All Gates</option>
                <option value="pass">Pass</option>
                <option value="warn">Warn</option>
                <option value="fail">Fail</option>
              </select>
            </div>
          </div>
        </div>

        {isLoadingResults ? (
          <div className="p-12 flex justify-center">
            <Spinner size="lg" label="Loading scan results..." />
          </div>
        ) : results.length === 0 ? (
          <div className="p-12">
            <EmptyState
              icon={Code2}
              title="No scan results found"
              description="Run a code quality scan to see results here"
              size="md"
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-800/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Project
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Tool
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Quality Score
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Issues
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Gate
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Date
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
                {results.map((result) => (
                  <tr
                    key={result.id}
                    onClick={() => setSelectedResult(result)}
                    className={`cursor-pointer transition-colors hover:bg-gray-50 dark:hover:bg-gray-800/50 ${
                      selectedResult?.id === result.id ? "bg-primary-50 dark:bg-primary-900/20" : ""
                    }`}
                  >
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <Code2 className="h-4 w-4 text-gray-400 flex-shrink-0" />
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            {result.project_name || result.project_key}
                          </p>
                          {result.commit_sha && (
                            <div className="flex items-center gap-1 mt-1">
                              <GitBranch className="h-3 w-3 text-gray-400" />
                              <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                                {result.commit_sha.substring(0, 7)}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded text-xs font-medium text-gray-700 dark:text-gray-300">
                        {result.tool}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={`text-2xl font-bold ${getQualityScoreColor(calculateQualityScore(result))}`}>
                        {calculateQualityScore(result)}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2 flex-wrap">
                        {result.critical_issues > 0 && (
                          <div className="flex items-center gap-1">
                            <SeverityBadge severity="critical" size="sm" />
                            <span className="text-xs text-gray-600 dark:text-gray-300">{result.critical_issues}</span>
                          </div>
                        )}
                        {result.high_issues > 0 && (
                          <div className="flex items-center gap-1">
                            <SeverityBadge severity="high" size="sm" />
                            <span className="text-xs text-gray-600 dark:text-gray-300">{result.high_issues}</span>
                          </div>
                        )}
                        {result.critical_issues === 0 && result.high_issues === 0 && (
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            {getTotalIssues(result)} total
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {result.quality_gate === "pass" && (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300">
                          <CheckCircle2 className="h-3 w-3" />
                          PASS
                        </span>
                      )}
                      {result.quality_gate === "warn" && (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">
                          <AlertTriangle className="h-3 w-3" />
                          WARN
                        </span>
                      )}
                      {result.quality_gate === "fail" && (
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">
                          <XCircle className="h-3 w-3" />
                          FAIL
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                      {new Date(result.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Issue Details SlideOver */}
      <SlideOver
        isOpen={showIssueSlideOver}
        onClose={() => setShowIssueSlideOver(false)}
        size="lg"
      >
        <SlideOver.Header onClose={() => setShowIssueSlideOver(false)}>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Issue Details
          </h2>
        </SlideOver.Header>

        <SlideOver.Body>
          {selectedIssue && (
            <div className="space-y-6">
              {/* Severity and Type */}
              <div>
                <div className="flex items-center gap-2 mb-4">
                  <SeverityBadge severity={selectedIssue.severity.toLowerCase() as SeverityLevel} />
                  <span className="px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded text-xs font-medium text-gray-700 dark:text-gray-300">
                    {selectedIssue.issue_type}
                  </span>
                  {selectedIssue.fix_available && (
                    <span className="px-2 py-1 bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300 rounded text-xs font-medium">
                      Fix Available
                    </span>
                  )}
                </div>

                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                  {selectedIssue.message}
                </h3>
              </div>

              {/* Location */}
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                  Location
                </h4>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <FileCode className="h-4 w-4 text-gray-400" />
                    <span className="text-sm font-mono text-gray-900 dark:text-white">
                      {selectedIssue.file_path}
                    </span>
                  </div>
                  {selectedIssue.start_line && (
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Line {selectedIssue.start_line}
                      {selectedIssue.end_line && selectedIssue.end_line !== selectedIssue.start_line &&
                        ` - ${selectedIssue.end_line}`
                      }
                    </p>
                  )}
                </div>
              </div>

              {/* Rule Information */}
              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                  Rule Information
                </h4>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Rule ID:</span>
                    <span className="text-sm font-mono text-gray-900 dark:text-white">
                      {selectedIssue.rule_id}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Type:</span>
                    <span className="text-sm text-gray-900 dark:text-white">
                      {selectedIssue.issue_type}
                    </span>
                  </div>
                </div>
              </div>

              {/* Suggested Fix */}
              {selectedIssue.fix_suggestion && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">
                    Suggested Fix
                  </h4>
                  <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                    <p className="text-sm text-gray-900 dark:text-white">
                      {selectedIssue.fix_suggestion}
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}
        </SlideOver.Body>

        <SlideOver.Footer>
          <button
            onClick={() => setShowIssueSlideOver(false)}
            className="px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            Close
          </button>
        </SlideOver.Footer>
      </SlideOver>
    </div>
  );
}
