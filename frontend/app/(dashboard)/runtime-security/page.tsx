"use client";

import { useQuery } from "@tanstack/react-query";
import {
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  Activity,
  FileWarning,
  Container,
} from "lucide-react";
import { api } from "@/lib/api";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { StatusIndicator } from "@/components/ui/StatusIndicator";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

export default function RuntimeSecurityPage() {
  const { data: posture, isLoading } = useQuery({
    queryKey: ["runtime-security-posture"],
    queryFn: () => api.getRuntimeSecurityPosture(),
  });

  const formatTimestamp = (ts: string) => new Date(ts).toLocaleString();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size="lg" label="Loading security posture..." />
      </div>
    );
  }

  if (!posture) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No runtime security data available"
        description="Start monitoring your containers to see runtime security insights"
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Overall Status */}
      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Overall Status</h2>
        <StatusIndicator status={posture.overall_status as any} size="lg" pulse />
      </div>

      {/* Metrics */}
      <MetricsGrid columns={4}>
        <StatCard
          label="Drift Events (24h)"
          value={posture.drift_events_last_24h}
          icon={Activity}
          iconColor="text-blue-600"
        />
        <StatCard
          label="Anomalies (24h)"
          value={posture.anomalies_last_24h}
          icon={AlertTriangle}
          iconColor="text-yellow-600"
        />
        <StatCard
          label="Unresolved Drift"
          value={posture.unresolved_drift}
          icon={FileWarning}
          iconColor="text-orange-600"
          valueColor="text-orange-600 dark:text-orange-400"
        />
        <StatCard
          label="Critical Issues"
          value={posture.critical_drift + posture.critical_anomalies}
          icon={ShieldX}
          iconColor="text-red-600"
          valueColor="text-red-600 dark:text-red-400"
        />
      </MetricsGrid>

      {/* Drift by Type + Anomaly by Type */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Drift by Type (24h)</h2>
          {Object.keys(posture.drift_by_type).length > 0 ? (
            <div className="space-y-3">
              {Object.entries(posture.drift_by_type).map(([type, count]) => (
                <div key={type} className="flex items-center justify-between">
                  <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
                    {type.replace(/_/g, " ")}
                  </span>
                  <span className="text-sm font-medium text-gray-900 dark:text-white">{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-400">No drift detected in the last 24 hours</p>
          )}
        </div>

        <div className="bg-white dark:bg-gray-900 rounded-lg p-6 border border-gray-200 dark:border-gray-800">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Anomalies by Type (24h)</h2>
          {Object.keys(posture.anomaly_by_type).length > 0 ? (
            <div className="space-y-3">
              {Object.entries(posture.anomaly_by_type).map(([type, count]) => (
                <div key={type} className="flex items-center justify-between">
                  <span className="text-sm text-gray-700 dark:text-gray-300 capitalize">
                    {type.replace(/_/g, " ")}
                  </span>
                  <span className="text-sm font-medium text-gray-900 dark:text-white">{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-400">No anomalies detected in the last 24 hours</p>
          )}
        </div>
      </div>

      {/* Top Affected Containers */}
      {posture.top_affected_containers.length > 0 && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-800">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Top Affected Containers (7 days)
            </h2>
          </div>
          <Table
            columns={[
              {
                key: "container_name",
                header: "Container",
                render: (value: string) => (
                  <div className="flex items-center gap-2">
                    <Container className="h-4 w-4 text-gray-400" />
                    <span className="text-sm text-gray-900 dark:text-white font-medium">{value}</span>
                  </div>
                ),
              },
              {
                key: "total_drift",
                header: "Total Drift",
                render: (value: number) => (
                  <span className="text-sm text-gray-700 dark:text-gray-300">{value}</span>
                ),
              },
              {
                key: "unresolved_drift",
                header: "Unresolved",
                render: (value: number) => (
                  <span className="text-sm font-medium text-orange-600 dark:text-orange-400">{value}</span>
                ),
              },
              {
                key: "last_drift_at",
                header: "Last Drift",
                render: (value: string) => (
                  <span className="text-sm text-gray-500 dark:text-gray-400">{formatTimestamp(value)}</span>
                ),
              },
            ]}
            data={posture.top_affected_containers}
            keyExtractor={(row) => row.deployment_id}
          />
        </div>
      )}
    </div>
  );
}
