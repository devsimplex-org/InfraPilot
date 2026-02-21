"use client";

import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Target, Bug, Award } from "lucide-react";
import { api } from "@/lib/api";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";

export default function CodeQualityOverviewPage() {
  const { data: resultsData } = useQuery({
    queryKey: ["codeQualityResults"],
    queryFn: () => api.listCodeQualityResults({ limit: 100 }),
  });

  const results = resultsData?.results || [];
  const latestResult = results[0];

  const criticalIssues = latestResult?.critical_issues || 0;
  const codeCoverage = latestResult?.coverage || 0;
  const technicalDebt = latestResult?.code_smells || 0;
  const qualityScore = latestResult
    ? (() => {
        let score = 100;
        score -= (latestResult.critical_issues || 0) * 10;
        score -= (latestResult.high_issues || 0) * 5;
        score -= (latestResult.medium_issues || 0) * 2;
        score -= (latestResult.low_issues || 0) * 1;
        if (latestResult.coverage !== undefined) {
          score = Math.round((score + latestResult.coverage) / 2);
        }
        return Math.max(0, Math.min(100, score));
      })()
    : 0;

  const getQualityScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600 dark:text-green-400";
    if (score >= 60) return "text-yellow-600 dark:text-yellow-400";
    if (score >= 40) return "text-orange-600 dark:text-orange-400";
    return "text-red-600 dark:text-red-400";
  };

  return (
    <MetricsGrid columns={4}>
      <StatCard
        label="Critical Issues"
        value={criticalIssues}
        icon={AlertTriangle}
        iconColor="text-red-600"
        valueColor={
          criticalIssues > 0
            ? "text-red-600 dark:text-red-400"
            : "text-green-600 dark:text-green-400"
        }
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
  );
}
