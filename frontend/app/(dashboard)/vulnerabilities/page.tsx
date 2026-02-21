"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import {
  Shield,
  AlertCircle,
  Server,
  Ban,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";
import { api } from "@/lib/api";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Spinner } from "@/components/ui/Spinner";
import { EmptyState } from "@/components/ui/EmptyState";

interface CVESummary {
  cve_id: string;
  severity: string;
  cvss_v3_score: number | null;
  description: string;
  affected_packages: string[];
  running_count: number;
  blocked_count: number;
  first_seen: string;
  last_seen: string;
}

export default function VulnerabilitiesOverviewPage() {
  const router = useRouter();

  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.fetchAPI<any[]>("/agents"),
  });

  const defaultAgent = agents?.[0];

  const { data: cveData, isLoading } = useQuery({
    queryKey: ["cves", defaultAgent?.id, "all"],
    queryFn: () =>
      api.fetchAPI<{ cves: CVESummary[]; count: number }>(
        `/agents/${defaultAgent?.id}/cves?severity=all`
      ),
    enabled: !!defaultAgent?.id,
  });

  const allCVEs = cveData?.cves || [];

  const stats = {
    total:    allCVEs.length,
    critical: allCVEs.filter((c) => c.severity === "critical").length,
    high:     allCVEs.filter((c) => c.severity === "high").length,
    medium:   allCVEs.filter((c) => c.severity === "medium").length,
    low:      allCVEs.filter((c) => c.severity === "low").length,
    running:  allCVEs.reduce((sum, cve) => sum + cve.running_count, 0),
    blocked:  allCVEs.reduce((sum, cve) => sum + cve.blocked_count, 0),
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading vulnerability data..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Key Metrics */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Total CVEs"
          value={stats.total}
          icon={Shield}
          iconColor="text-primary-600"
        />
        <StatCard
          label="Critical + High"
          value={stats.critical + stats.high}
          description={`${stats.critical} critical, ${stats.high} high`}
          icon={AlertCircle}
          iconColor="text-red-600"
          valueColor="text-red-600 dark:text-red-400"
        />
        <StatCard
          label="Running Deployments"
          value={stats.running}
          description="Affected deployments"
          icon={Server}
          iconColor="text-orange-600"
          valueColor="text-orange-600 dark:text-orange-400"
        />
        <StatCard
          label="Blocked by Policy"
          value={stats.blocked}
          description="Prevented deployments"
          icon={Ban}
          iconColor="text-green-600"
          valueColor="text-green-600 dark:text-green-400"
        />
      </MetricsGrid>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Severity Breakdown</h2>
          {stats.total > 0 ? (
            <div className="space-y-3">
              {[
                { label: "Critical", count: stats.critical, color: "bg-red-500" },
                { label: "High",     count: stats.high,     color: "bg-orange-500" },
                { label: "Medium",   count: stats.medium,   color: "bg-yellow-500" },
                { label: "Low",      count: stats.low,      color: "bg-blue-500" },
              ].map(({ label, count, color }) => (
                <div key={label} className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${color}`} />
                  <span className="text-sm text-gray-700 dark:text-gray-300 flex-1">{label}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 bg-gray-100 dark:bg-gray-800 rounded-full h-1.5">
                      <div
                        className={`h-1.5 rounded-full ${color}`}
                        style={{ width: `${stats.total > 0 ? (count / stats.total) * 100 : 0}%` }}
                      />
                    </div>
                    <span className="text-sm font-medium text-gray-900 dark:text-white w-6 text-right">
                      {count}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-400">No vulnerability data available</p>
          )}
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Security Summary</h2>
          <div className="space-y-4">
            <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-800/50">
              {stats.critical > 0 ? (
                <AlertTriangle className="h-5 w-5 text-red-500 flex-shrink-0" />
              ) : (
                <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
              )}
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  {stats.critical > 0
                    ? `${stats.critical} critical CVE${stats.critical > 1 ? "s" : ""} require immediate attention`
                    : "No critical CVEs detected"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-800/50">
              {stats.running > 0 ? (
                <AlertTriangle className="h-5 w-5 text-orange-500 flex-shrink-0" />
              ) : (
                <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
              )}
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  {stats.running > 0
                    ? `${stats.running} deployment${stats.running > 1 ? "s" : ""} running vulnerable images`
                    : "No deployments running vulnerable images"}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 dark:bg-gray-800/50">
              <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  {stats.blocked > 0
                    ? `${stats.blocked} deployment${stats.blocked > 1 ? "s" : ""} blocked by security policy`
                    : "No deployments blocked by policy"}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Link */}
      {stats.total > 0 && (
        <div className="flex justify-end">
          <button
            onClick={() => router.push("/vulnerabilities/cves")}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors text-sm font-medium"
          >
            View All CVEs ({stats.total})
          </button>
        </div>
      )}
    </div>
  );
}
