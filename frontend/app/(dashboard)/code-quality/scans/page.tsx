"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Code2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  GitBranch,
} from "lucide-react";
import { api, CodeQualityResult } from "@/lib/api";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";
import { SeverityBadge } from "@/components/ui/Badge";

export default function CodeQualityScansPage() {
  const [toolFilter, setToolFilter] = useState("");
  const [qualityGateFilter, setQualityGateFilter] = useState("");
  const [selectedResult, setSelectedResult] = useState<CodeQualityResult | null>(null);

  const { data: resultsData, isLoading } = useQuery({
    queryKey: ["codeQualityResults", toolFilter, qualityGateFilter],
    queryFn: () =>
      api.listCodeQualityResults({
        tool: toolFilter || undefined,
        quality_gate: qualityGateFilter || undefined,
        limit: 100,
      }),
  });

  const results = resultsData?.results || [];

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

  const getTotalIssues = (result: CodeQualityResult) =>
    (result.critical_issues || 0) +
    (result.high_issues || 0) +
    (result.medium_issues || 0) +
    (result.low_issues || 0) +
    (result.info_issues || 0);

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-lg">
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Scan Results</h3>
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

      {isLoading ? (
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
                {["Project", "Tool", "Quality Score", "Issues", "Gate", "Date"].map((h) => (
                  <th
                    key={h}
                    className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider"
                  >
                    {h}
                  </th>
                ))}
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
                        <CheckCircle2 className="h-3 w-3" />PASS
                      </span>
                    )}
                    {result.quality_gate === "warn" && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300">
                        <AlertTriangle className="h-3 w-3" />WARN
                      </span>
                    )}
                    {result.quality_gate === "fail" && (
                      <span className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">
                        <XCircle className="h-3 w-3" />FAIL
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
  );
}
