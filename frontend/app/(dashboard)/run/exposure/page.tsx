"use client";

import { useQuery } from "@tanstack/react-query";
import { Globe, Unlock, AlertTriangle, ExternalLink } from "lucide-react";
import { api } from "@/lib/api";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Spinner } from "@/components/ui/Spinner";
import { cn } from "@/lib/utils";

export default function ExposureOverviewPage() {
  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ["exposure-summary"],
    queryFn: () => api.getExposureSummary(),
  });

  const { data: tlsPosture, isLoading: tlsLoading } = useQuery({
    queryKey: ["tls-posture"],
    queryFn: () => api.getTLSPosture(),
  });

  const getRiskColor = (score: number) => {
    if (score >= 70) return "text-red-600 dark:text-red-400";
    if (score >= 40) return "text-yellow-600 dark:text-yellow-400";
    return "text-green-600 dark:text-green-400";
  };

  if (summaryLoading || tlsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading exposure data..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <MetricsGrid columns={4}>
        <StatCard
          label="Total Endpoints"
          value={summary?.total_endpoints || 0}
          icon={Globe}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Public Endpoints"
          value={summary?.public_endpoints || 0}
          icon={ExternalLink}
          iconColor="text-red-600"
          valueColor="text-red-600 dark:text-red-400"
        />
        <StatCard
          label="Unauthenticated Public"
          value={summary?.unauthenticated_public || 0}
          icon={Unlock}
          iconColor="text-orange-600"
          valueColor="text-orange-600 dark:text-orange-400"
        />
        <StatCard
          label="High Risk Endpoints"
          value={summary?.high_risk_endpoints || 0}
          icon={AlertTriangle}
          iconColor="text-red-600"
          valueColor="text-red-600 dark:text-red-400"
        />
      </MetricsGrid>

      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">TLS/SSL Health</h2>
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: "Valid Certs", value: tlsPosture?.valid_certs || 0, color: "text-green-600" },
            { label: "Invalid Certs", value: tlsPosture?.invalid_certs || 0, color: "text-red-600" },
            { label: "Expiring Soon", value: tlsPosture?.expiring_warning || 0, color: "text-yellow-600" },
            { label: "Critical Expiry", value: tlsPosture?.expiring_critical || 0, color: "text-red-600" },
          ].map(({ label, value, color }) => (
            <div key={label} className="text-center p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className={`text-2xl font-bold ${color}`}>{value}</div>
              <div className="text-sm text-gray-500">{label}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Exposure by Type</h2>
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-red-500"></div>
            <span className="text-sm text-gray-700 dark:text-gray-300">
              Public: {summary?.public_endpoints || 0}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-blue-500"></div>
            <span className="text-sm text-gray-700 dark:text-gray-300">
              Internal: {summary?.internal_endpoints || 0}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded bg-green-500"></div>
            <span className="text-sm text-gray-700 dark:text-gray-300">
              Active: {summary?.active_endpoints || 0}
            </span>
          </div>
        </div>
        <div className="mt-4">
          <div className="text-sm text-gray-500 dark:text-gray-400">
            Average Risk Score:{" "}
            <span className={cn("font-medium", getRiskColor(summary?.avg_risk_score || 0))}>
              {summary?.avg_risk_score || 0}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
