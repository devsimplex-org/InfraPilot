"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  FileCode,
  Code2,
  GitBranch,
} from "lucide-react";
import { api, CodeQualityResult, CodeQualityIssue } from "@/lib/api";
import { Table } from "@/components/ui/Table";
import { SlideOver } from "@/components/ui/SlideOver";
import { FilterPanel } from "@/components/ui/FilterPanel";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SeverityBadge } from "@/components/ui/Badge";

type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export default function CodeQualityIssuesPage() {
  const [selectedResult, setSelectedResult] = useState<CodeQualityResult | null>(null);
  const [selectedIssue, setSelectedIssue] = useState<CodeQualityIssue | null>(null);
  const [showIssueSlideOver, setShowIssueSlideOver] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [filePathFilter, setFilePathFilter] = useState("");
  const [ruleTypeFilter, setRuleTypeFilter] = useState<string[]>([]);
  const [toolFilter, setToolFilter] = useState("");

  const { data: resultsData, isLoading: isLoadingResults } = useQuery({
    queryKey: ["codeQualityResults", toolFilter],
    queryFn: () => api.listCodeQualityResults({ tool: toolFilter || undefined, limit: 100 }),
  });

  const { data: issuesData, isLoading: isLoadingIssues } = useQuery({
    queryKey: ["codeQualityIssues", selectedResult?.id],
    queryFn: () =>
      selectedResult
        ? api.getCodeQualityIssues(selectedResult.id)
        : Promise.resolve({ issues: [], count: 0 }),
    enabled: !!selectedResult,
  });

  const results = resultsData?.results || [];
  const activeResult = selectedResult || results[0];
  const issues = issuesData?.issues || [];

  const filteredIssues = issues.filter((issue) => {
    const severityMatch =
      severityFilter.length === 0 || severityFilter.includes(issue.severity.toLowerCase());
    const fileMatch =
      filePathFilter === "" || issue.file_path.toLowerCase().includes(filePathFilter.toLowerCase());
    const ruleMatch = ruleTypeFilter.length === 0 || ruleTypeFilter.includes(issue.issue_type);
    return severityMatch && fileMatch && ruleMatch;
  });

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
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">Rule: {row.rule_id}</p>
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

  const filters = [
    {
      id: "scan",
      label: "Scan Result",
      type: "radio" as const,
      value: activeResult?.id || "",
      onChange: (value: string | string[]) => {
        const result = results.find((r) => r.id === value);
        setSelectedResult(result || null);
      },
      options: results.map((r) => ({
        label: r.project_name || r.project_key || r.id.substring(0, 8),
        value: r.id,
      })),
    },
    {
      id: "severity",
      label: "Severity",
      type: "checkbox" as const,
      options: [
        { label: "Critical", value: "critical", count: issues.filter((i) => i.severity.toLowerCase() === "critical").length },
        { label: "High", value: "high", count: issues.filter((i) => i.severity.toLowerCase() === "high").length },
        { label: "Medium", value: "medium", count: issues.filter((i) => i.severity.toLowerCase() === "medium").length },
        { label: "Low", value: "low", count: issues.filter((i) => i.severity.toLowerCase() === "low").length },
        { label: "Info", value: "info", count: issues.filter((i) => i.severity.toLowerCase() === "info").length },
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
      options: Array.from(new Set(issues.map((i) => i.issue_type))).map((type) => ({
        label: type,
        value: type,
        count: issues.filter((i) => i.issue_type === type).length,
      })),
      value: ruleTypeFilter,
      onChange: (value: string | string[]) => setRuleTypeFilter(value as string[]),
    },
  ];

  return (
    <>
      <div className="flex gap-6">
        <div className="w-64 flex-shrink-0">
          <FilterPanel
            filters={filters}
            onReset={() => {
              setSeverityFilter([]);
              setFilePathFilter("");
              setRuleTypeFilter([]);
            }}
          />
        </div>

        <div className="flex-1 min-w-0">
          <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  SAST Findings ({filteredIssues.length})
                </h3>
                {activeResult && (
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                    {activeResult.project_name || activeResult.project_key} &mdash; {activeResult.tool}
                  </p>
                )}
              </div>
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
            </div>

            {isLoadingResults || isLoadingIssues ? (
              <div className="p-12 flex justify-center">
                <Spinner size="lg" label="Loading findings..." />
              </div>
            ) : !activeResult ? (
              <div className="p-12">
                <EmptyState
                  icon={Code2}
                  title="No scan results found"
                  description="Run a code quality scan to see findings here"
                  size="md"
                />
              </div>
            ) : filteredIssues.length === 0 ? (
              <div className="p-12">
                <EmptyState
                  icon={CheckCircle2}
                  title="No issues found"
                  description={
                    issues.length === 0
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
                onRowClick={(issue) => {
                  setSelectedIssue(issue);
                  setShowIssueSlideOver(true);
                }}
                hoverable
                containerClassName="rounded-b-lg"
              />
            )}
          </div>
        </div>
      </div>

      <SlideOver isOpen={showIssueSlideOver} onClose={() => setShowIssueSlideOver(false)} size="lg">
        <SlideOver.Header onClose={() => setShowIssueSlideOver(false)}>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Issue Details</h2>
        </SlideOver.Header>
        <SlideOver.Body>
          {selectedIssue && (
            <div className="space-y-6">
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

              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Location</h4>
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
                        ` - ${selectedIssue.end_line}`}
                    </p>
                  )}
                </div>
              </div>

              <div>
                <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Rule Information</h4>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Rule ID:</span>
                    <span className="text-sm font-mono text-gray-900 dark:text-white">{selectedIssue.rule_id}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-600 dark:text-gray-400">Type:</span>
                    <span className="text-sm text-gray-900 dark:text-white">{selectedIssue.issue_type}</span>
                  </div>
                </div>
              </div>

              {selectedIssue.fix_suggestion && (
                <div>
                  <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Suggested Fix</h4>
                  <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                    <p className="text-sm text-gray-900 dark:text-white">{selectedIssue.fix_suggestion}</p>
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
    </>
  );
}
