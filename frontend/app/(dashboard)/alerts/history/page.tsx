"use client";

import { useQuery } from "@tanstack/react-query";
import { Bell, AlertTriangle, Check, History, Clock } from "lucide-react";
import { api } from "@/lib/api";
import { formatRelativeTime, cn } from "@/lib/utils";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Card } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { Spinner } from "@/components/ui/Spinner";

export default function AlertHistoryPage() {
  const { data: history, isLoading } = useQuery({
    queryKey: ["alertHistory"],
    queryFn: () => api.getAlertHistory(50),
  });

  const activeAlerts   = history?.filter((h) => !h.resolved_at).length || 0;
  const criticalAlerts = history?.filter((h) => !h.resolved_at && h.severity === "critical").length || 0;
  const resolvedAlerts = history?.filter((h) => h.resolved_at).length || 0;
  const totalAlerts    = history?.length || 0;

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400 border-red-200 dark:border-red-800";
      case "warning":
        return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800";
      case "info":
        return "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 border-blue-200 dark:border-blue-800";
      default:
        return "bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-400 border-gray-200 dark:border-gray-700";
    }
  };

  return (
    <div className="space-y-6">
      <MetricsGrid columns={4}>
        <StatCard label="Active Alerts"  value={activeAlerts}   icon={Bell}          iconColor="text-yellow-600" />
        <StatCard label="Critical"        value={criticalAlerts} icon={AlertTriangle}  iconColor="text-red-600" />
        <StatCard label="Resolved"        value={resolvedAlerts} icon={Check}          iconColor="text-green-600" />
        <StatCard label="Total Alerts"    value={totalAlerts}    icon={History}        iconColor="text-blue-600" />
      </MetricsGrid>

      <Card>
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <Spinner size="lg" />
          </div>
        ) : history && history.length > 0 ? (
          <div className="divide-y divide-gray-100 dark:divide-gray-800">
            {history.map((entry) => (
              <div
                key={entry.id}
                className="flex items-center gap-4 p-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
              >
                <div
                  className={cn(
                    "p-2 rounded-lg",
                    entry.resolved_at
                      ? "bg-green-100 dark:bg-green-900/30"
                      : "bg-red-100 dark:bg-red-900/30"
                  )}
                >
                  {entry.resolved_at ? (
                    <Check className="h-4 w-4 text-green-600 dark:text-green-400" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-900 dark:text-white font-medium">{entry.message}</span>
                    <span
                      className={cn(
                        "text-xs px-2 py-0.5 rounded border",
                        getSeverityColor(entry.severity)
                      )}
                    >
                      {entry.severity}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-500 mt-1">
                    {entry.rule_name && <span>Rule: {entry.rule_name}</span>}
                    {entry.agent_name && <span>Agent: {entry.agent_name}</span>}
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatRelativeTime(entry.triggered_at)}
                    </span>
                    {entry.resolved_at && (
                      <span className="text-green-600 dark:text-green-400">
                        Resolved {formatRelativeTime(entry.resolved_at)}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-12">
            <EmptyState
              icon={History}
              title="No alert history"
              description="Triggered alerts will appear here"
            />
          </div>
        )}
      </Card>
    </div>
  );
}
